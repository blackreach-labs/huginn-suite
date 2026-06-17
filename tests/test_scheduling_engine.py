"""Tests for the SchedulingEngine and CronParser modules."""

import json
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from app.core.scheduling_engine import CronParser, SchedulingEngine
from app.core.database_pool import DatabaseConnectionPool


# ---------------------------------------------------------------------------
# Schema for the master index database (test helper)
# ---------------------------------------------------------------------------

MASTER_INDEX_SCHEMA = """
CREATE TABLE IF NOT EXISTS engagements (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    client_name TEXT NOT NULL,
    engagement_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft',
    start_date TEXT,
    end_date TEXT,
    db_path TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scheduled_scans (
    id TEXT PRIMARY KEY,
    engagement_id TEXT,
    name TEXT NOT NULL,
    scan_config TEXT NOT NULL,
    target_list TEXT NOT NULL,
    recurrence_pattern TEXT NOT NULL,
    next_execution TEXT NOT NULL,
    last_execution TEXT,
    status TEXT DEFAULT 'active',
    failure_count INTEGER DEFAULT 0,
    last_failure_reason TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);
"""


@pytest.fixture
def master_db_path(tmp_path):
    """Create a temporary master index database with schema."""
    db_path = str(tmp_path / "huginn_master_index.db")
    conn = sqlite3.connect(db_path)
    conn.executescript(MASTER_INDEX_SCHEMA)
    conn.close()
    return db_path


@pytest.fixture
def master_pool(master_db_path):
    """Create a DatabaseConnectionPool for the master DB."""
    pool = DatabaseConnectionPool(master_db_path, pool_size=2)
    yield pool
    pool.close_all()


@pytest.fixture
def engine(master_pool, qtbot):
    """Create a SchedulingEngine instance for testing."""
    eng = SchedulingEngine(master_pool)
    yield eng
    eng.stop()


# ===========================================================================
# CronParser Tests
# ===========================================================================


class TestCronParser:
    """Tests for the CronParser utility class."""

    def test_normalize_named_daily(self):
        result = CronParser.normalize_pattern("daily")
        assert result == "0 0 * * *"

    def test_normalize_named_weekly(self):
        result = CronParser.normalize_pattern("weekly")
        assert result == "0 0 * * 0"

    def test_normalize_named_monthly(self):
        result = CronParser.normalize_pattern("monthly")
        assert result == "0 0 1 * *"

    def test_normalize_named_once_returns_none(self):
        result = CronParser.normalize_pattern("once")
        assert result is None

    def test_normalize_case_insensitive(self):
        assert CronParser.normalize_pattern("DAILY") == "0 0 * * *"
        assert CronParser.normalize_pattern("Weekly") == "0 0 * * 0"

    def test_normalize_custom_cron_passthrough(self):
        expr = "30 2 * * 0"
        result = CronParser.normalize_pattern(expr)
        assert result == expr

    def test_normalize_invalid_field_count_raises(self):
        with pytest.raises(ValueError, match="expected 5 fields"):
            CronParser.normalize_pattern("30 2 *")

    def test_normalize_too_many_fields_raises(self):
        with pytest.raises(ValueError, match="expected 5 fields"):
            CronParser.normalize_pattern("30 2 * * * *")

    def test_parse_field_wildcard(self):
        result = CronParser._parse_field("*", 0, 59)
        assert result == list(range(0, 60))

    def test_parse_field_single_value(self):
        result = CronParser._parse_field("5", 0, 59)
        assert result == [5]

    def test_parse_field_list(self):
        result = CronParser._parse_field("1,3,5", 0, 59)
        assert result == [1, 3, 5]

    def test_parse_field_range(self):
        result = CronParser._parse_field("1-5", 0, 59)
        assert result == [1, 2, 3, 4, 5]

    def test_parse_field_step(self):
        result = CronParser._parse_field("*/15", 0, 59)
        assert result == [0, 15, 30, 45]

    def test_parse_field_range_with_step(self):
        result = CronParser._parse_field("0-10/3", 0, 59)
        assert result == [0, 3, 6, 9]

    def test_compute_next_every_minute(self):
        base = datetime(2024, 6, 15, 10, 30, 0)
        result = CronParser.compute_next("* * * * *", base)
        assert result == datetime(2024, 6, 15, 10, 31, 0)

    def test_compute_next_daily_midnight(self):
        # "0 0 * * *" = every day at midnight
        base = datetime(2024, 6, 15, 10, 30, 0)
        result = CronParser.compute_next("0 0 * * *", base)
        assert result == datetime(2024, 6, 16, 0, 0, 0)

    def test_compute_next_specific_time(self):
        # "30 14 * * *" = every day at 14:30
        base = datetime(2024, 6, 15, 10, 0, 0)
        result = CronParser.compute_next("30 14 * * *", base)
        assert result == datetime(2024, 6, 15, 14, 30, 0)

    def test_compute_next_specific_time_already_passed(self):
        # "30 14 * * *" = every day at 14:30, but it's already 15:00
        base = datetime(2024, 6, 15, 15, 0, 0)
        result = CronParser.compute_next("30 14 * * *", base)
        assert result == datetime(2024, 6, 16, 14, 30, 0)

    def test_compute_next_monthly_first_day(self):
        # "0 0 1 * *" = first of every month
        base = datetime(2024, 6, 15, 10, 0, 0)
        result = CronParser.compute_next("0 0 1 * *", base)
        assert result == datetime(2024, 7, 1, 0, 0, 0)

    def test_compute_next_specific_month(self):
        # "0 0 1 3 *" = March 1st at midnight
        base = datetime(2024, 1, 15, 10, 0, 0)
        result = CronParser.compute_next("0 0 1 3 *", base)
        assert result == datetime(2024, 3, 1, 0, 0, 0)

    def test_compute_next_day_of_week_monday(self):
        # "0 9 * * 0" = every Monday at 9:00 (0=Monday in Python weekday)
        # June 15, 2024 is a Saturday (weekday=5)
        base = datetime(2024, 6, 15, 10, 0, 0)
        result = CronParser.compute_next("0 9 * * 0", base)
        # Next Monday is June 17
        assert result == datetime(2024, 6, 17, 9, 0, 0)

    def test_compute_next_respects_day_of_month_overflow(self):
        # "0 0 31 * *" = 31st of every month
        # Start in June (30 days), should skip to July 31
        base = datetime(2024, 6, 15, 10, 0, 0)
        result = CronParser.compute_next("0 0 31 * *", base)
        assert result == datetime(2024, 7, 31, 0, 0, 0)

    def test_compute_next_invalid_expr_raises(self):
        with pytest.raises(ValueError):
            CronParser.compute_next("bad expr", datetime.now())


# ===========================================================================
# SchedulingEngine Tests
# ===========================================================================


class TestScheduleCreation:
    """Tests for creating schedules."""

    def test_create_schedule_returns_uuid(self, engine):
        sid = engine.create_schedule(
            name="Daily Scan",
            scan_config={"scan_type": "network"},
            target_list=["192.168.1.0/24"],
            recurrence="daily",
        )
        assert len(sid) == 36
        assert sid.count("-") == 4

    def test_create_schedule_stores_in_db(self, engine):
        sid = engine.create_schedule(
            name="Weekly Check",
            scan_config={"scan_type": "web"},
            target_list=["example.com"],
            recurrence="weekly",
            engagement_id="eng-123",
        )
        schedule = engine.get_schedule(sid)
        assert schedule is not None
        assert schedule["name"] == "Weekly Check"
        assert schedule["scan_config"] == {"scan_type": "web"}
        assert schedule["target_list"] == ["example.com"]
        assert schedule["recurrence_pattern"] == "weekly"
        assert schedule["status"] == "active"
        assert schedule["engagement_id"] == "eng-123"
        assert schedule["failure_count"] == 0

    def test_create_schedule_once_pattern(self, engine):
        sid = engine.create_schedule(
            name="One-time Scan",
            scan_config={},
            target_list=["10.0.0.1"],
            recurrence="once",
        )
        schedule = engine.get_schedule(sid)
        assert schedule["recurrence_pattern"] == "once"
        assert schedule["next_execution"] is not None

    def test_create_schedule_custom_cron(self, engine):
        sid = engine.create_schedule(
            name="Custom Cron",
            scan_config={"ports": "1-1024"},
            target_list=["10.0.0.0/8"],
            recurrence="30 2 * * 5",
        )
        schedule = engine.get_schedule(sid)
        assert schedule["recurrence_pattern"] == "30 2 * * 5"

    def test_create_schedule_invalid_pattern_raises(self, engine):
        with pytest.raises(ValueError):
            engine.create_schedule(
                name="Bad",
                scan_config={},
                target_list=[],
                recurrence="invalid cron",
            )

    def test_create_schedule_monthly(self, engine):
        sid = engine.create_schedule(
            name="Monthly Audit",
            scan_config={"full": True},
            target_list=["172.16.0.0/16"],
            recurrence="monthly",
        )
        schedule = engine.get_schedule(sid)
        assert schedule["recurrence_pattern"] == "monthly"


class TestComputeNextExecution:
    """Tests for next execution computation."""

    def test_once_returns_future_time(self, engine):
        now = datetime(2024, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        result = engine.compute_next_execution("once", now)
        assert result is not None
        assert result > now

    def test_daily_returns_next_midnight(self, engine):
        now = datetime(2024, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        result = engine.compute_next_execution("daily", now)
        assert result == datetime(2024, 6, 16, 0, 0, 0, tzinfo=timezone.utc)

    def test_weekly_returns_next_monday(self, engine):
        # June 15, 2024 is Saturday (weekday=5)
        now = datetime(2024, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        result = engine.compute_next_execution("weekly", now)
        # Next Monday is June 17 (weekday=0)
        assert result == datetime(2024, 6, 17, 0, 0, 0, tzinfo=timezone.utc)

    def test_monthly_returns_first_of_next_month(self, engine):
        now = datetime(2024, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        result = engine.compute_next_execution("monthly", now)
        assert result == datetime(2024, 7, 1, 0, 0, 0, tzinfo=timezone.utc)

    def test_custom_cron_expression(self, engine):
        now = datetime(2024, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        # Every hour at minute 0
        result = engine.compute_next_execution("0 * * * *", now)
        assert result == datetime(2024, 6, 15, 11, 0, 0, tzinfo=timezone.utc)


class TestDisableEnable:
    """Tests for disable/enable schedule operations."""

    def test_disable_schedule(self, engine):
        sid = engine.create_schedule(
            name="Disable Test",
            scan_config={},
            target_list=["10.0.0.1"],
            recurrence="daily",
        )
        result = engine.disable_schedule(sid)
        assert result is True

        schedule = engine.get_schedule(sid)
        assert schedule["status"] == "disabled"

    def test_disable_nonexistent_returns_false(self, engine):
        result = engine.disable_schedule("nonexistent-id")
        assert result is False

    def test_disable_already_disabled_returns_false(self, engine):
        sid = engine.create_schedule(
            name="Double Disable",
            scan_config={},
            target_list=["10.0.0.1"],
            recurrence="daily",
        )
        engine.disable_schedule(sid)
        result = engine.disable_schedule(sid)
        assert result is False

    def test_enable_schedule(self, engine):
        sid = engine.create_schedule(
            name="Enable Test",
            scan_config={},
            target_list=["10.0.0.1"],
            recurrence="daily",
        )
        engine.disable_schedule(sid)
        result = engine.enable_schedule(sid)
        assert result is True

        schedule = engine.get_schedule(sid)
        assert schedule["status"] == "active"
        assert schedule["next_execution"] is not None

    def test_enable_nonexistent_returns_false(self, engine):
        result = engine.enable_schedule("nonexistent-id")
        assert result is False

    def test_enable_active_schedule_returns_false(self, engine):
        sid = engine.create_schedule(
            name="Already Active",
            scan_config={},
            target_list=["10.0.0.1"],
            recurrence="daily",
        )
        # It's already active, not disabled
        result = engine.enable_schedule(sid)
        assert result is False


class TestCheckPending:
    """Tests for the pending scan check mechanism."""

    def test_check_pending_triggers_due_scan(self, engine, master_pool, qtbot):
        """A scan past its execution time should be triggered."""
        # Create a schedule with next_execution in the past
        past_time = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        now_iso = datetime.now(timezone.utc).isoformat()

        master_pool.execute_write(
            """INSERT INTO scheduled_scans
               (id, engagement_id, name, scan_config, target_list,
                recurrence_pattern, next_execution, status,
                failure_count, created_at, updated_at)
               VALUES (?, NULL, ?, ?, ?, ?, ?, 'active', 0, ?, ?)""",
            (
                "test-schedule-001",
                "Pending Test",
                json.dumps({"type": "quick"}),
                json.dumps(["10.0.0.1"]),
                "daily",
                past_time,
                now_iso,
                now_iso,
            ),
        )

        # Connect a mock scan controller
        mock_controller = MagicMock()
        engine.scan_controller = mock_controller

        # Capture signals
        with qtbot.waitSignal(engine.scan_triggered, timeout=5000) as blocker:
            engine._check_pending()

        assert blocker.args == ["test-schedule-001"]
        mock_controller.start.assert_called_once()

    def test_check_pending_does_not_trigger_future_scan(self, engine, master_pool):
        """A scan with future execution time should not trigger."""
        future_time = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        now_iso = datetime.now(timezone.utc).isoformat()

        master_pool.execute_write(
            """INSERT INTO scheduled_scans
               (id, engagement_id, name, scan_config, target_list,
                recurrence_pattern, next_execution, status,
                failure_count, created_at, updated_at)
               VALUES (?, NULL, ?, ?, ?, ?, ?, 'active', 0, ?, ?)""",
            (
                "test-future-001",
                "Future Test",
                json.dumps({}),
                json.dumps(["10.0.0.1"]),
                "daily",
                future_time,
                now_iso,
                now_iso,
            ),
        )

        mock_controller = MagicMock()
        engine.scan_controller = mock_controller

        engine._check_pending()

        mock_controller.start.assert_not_called()

    def test_check_pending_does_not_trigger_disabled_scan(self, engine, master_pool):
        """A disabled scan should not trigger even if past due."""
        past_time = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        now_iso = datetime.now(timezone.utc).isoformat()

        master_pool.execute_write(
            """INSERT INTO scheduled_scans
               (id, engagement_id, name, scan_config, target_list,
                recurrence_pattern, next_execution, status,
                failure_count, created_at, updated_at)
               VALUES (?, NULL, ?, ?, ?, ?, ?, 'disabled', 0, ?, ?)""",
            (
                "test-disabled-001",
                "Disabled Test",
                json.dumps({}),
                json.dumps(["10.0.0.1"]),
                "daily",
                past_time,
                now_iso,
                now_iso,
            ),
        )

        mock_controller = MagicMock()
        engine.scan_controller = mock_controller

        engine._check_pending()

        mock_controller.start.assert_not_called()

    def test_check_pending_completes_once_schedule(self, engine, master_pool, qtbot):
        """A one-time schedule should be marked completed after execution."""
        past_time = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        now_iso = datetime.now(timezone.utc).isoformat()

        master_pool.execute_write(
            """INSERT INTO scheduled_scans
               (id, engagement_id, name, scan_config, target_list,
                recurrence_pattern, next_execution, status,
                failure_count, created_at, updated_at)
               VALUES (?, NULL, ?, ?, ?, ?, ?, 'active', 0, ?, ?)""",
            (
                "test-once-001",
                "One-time Test",
                json.dumps({}),
                json.dumps(["10.0.0.1"]),
                "once",
                past_time,
                now_iso,
                now_iso,
            ),
        )

        mock_controller = MagicMock()
        engine.scan_controller = mock_controller

        engine._check_pending()

        schedule = engine.get_schedule("test-once-001")
        assert schedule["status"] == "completed"


class TestHandleFailure:
    """Tests for failure handling."""

    def test_failure_increments_counter(self, engine, master_pool, qtbot):
        """Failure should increment the failure_count and log reason."""
        past_time = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        now_iso = datetime.now(timezone.utc).isoformat()

        master_pool.execute_write(
            """INSERT INTO scheduled_scans
               (id, engagement_id, name, scan_config, target_list,
                recurrence_pattern, next_execution, status,
                failure_count, created_at, updated_at)
               VALUES (?, NULL, ?, ?, ?, ?, ?, 'active', 0, ?, ?)""",
            (
                "test-fail-001",
                "Fail Test",
                json.dumps({}),
                json.dumps(["10.0.0.1"]),
                "daily",
                past_time,
                now_iso,
                now_iso,
            ),
        )

        # No scan controller connected — will raise RuntimeError
        with qtbot.waitSignal(engine.scan_failed, timeout=5000) as blocker:
            engine._check_pending()

        assert blocker.args[0] == "test-fail-001"
        assert "No scan controller" in blocker.args[1]

        schedule = engine.get_schedule("test-fail-001")
        assert schedule["failure_count"] == 1
        assert "No scan controller" in schedule["last_failure_reason"]

    def test_failure_updates_next_execution(self, engine, master_pool):
        """After failure, next_execution should be updated to next interval."""
        past_time = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        now_iso = datetime.now(timezone.utc).isoformat()

        master_pool.execute_write(
            """INSERT INTO scheduled_scans
               (id, engagement_id, name, scan_config, target_list,
                recurrence_pattern, next_execution, status,
                failure_count, created_at, updated_at)
               VALUES (?, NULL, ?, ?, ?, ?, ?, 'active', 0, ?, ?)""",
            (
                "test-fail-next-001",
                "Fail Next Test",
                json.dumps({}),
                json.dumps(["10.0.0.1"]),
                "daily",
                past_time,
                now_iso,
                now_iso,
            ),
        )

        engine._check_pending()

        schedule = engine.get_schedule("test-fail-next-001")
        # next_execution should be updated to a future time
        next_exec = datetime.fromisoformat(schedule["next_execution"])
        # Make comparison tz-aware
        now_aware = datetime.now(timezone.utc) - timedelta(minutes=1)
        # Strip tzinfo if next_exec is naive, or keep both aware
        if next_exec.tzinfo is None:
            assert next_exec > now_aware.replace(tzinfo=None)
        else:
            assert next_exec > now_aware


class TestListAndDelete:
    """Tests for listing and deleting schedules."""

    def test_list_schedules_all(self, engine):
        engine.create_schedule("S1", {}, ["t1"], "daily")
        engine.create_schedule("S2", {}, ["t2"], "weekly")

        schedules = engine.list_schedules()
        assert len(schedules) == 2

    def test_list_schedules_with_filter(self, engine):
        sid = engine.create_schedule("S1", {}, ["t1"], "daily")
        engine.create_schedule("S2", {}, ["t2"], "weekly")
        engine.disable_schedule(sid)

        active = engine.list_schedules(status_filter="active")
        assert len(active) == 1
        assert active[0]["name"] == "S2"

        disabled = engine.list_schedules(status_filter="disabled")
        assert len(disabled) == 1
        assert disabled[0]["name"] == "S1"

    def test_delete_schedule(self, engine):
        sid = engine.create_schedule("Delete Me", {}, ["t1"], "daily")
        result = engine.delete_schedule(sid)
        assert result is True
        assert engine.get_schedule(sid) is None

    def test_delete_nonexistent_returns_false(self, engine):
        result = engine.delete_schedule("no-such-id")
        assert result is False

    def test_get_nonexistent_schedule_returns_none(self, engine):
        assert engine.get_schedule("no-such-id") is None


class TestSignals:
    """Tests for signal emissions."""

    def test_scan_triggered_signal(self, engine, master_pool, qtbot):
        """scan_triggered should be emitted when a due scan is found."""
        past_time = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        now_iso = datetime.now(timezone.utc).isoformat()

        master_pool.execute_write(
            """INSERT INTO scheduled_scans
               (id, engagement_id, name, scan_config, target_list,
                recurrence_pattern, next_execution, status,
                failure_count, created_at, updated_at)
               VALUES (?, NULL, ?, ?, ?, ?, ?, 'active', 0, ?, ?)""",
            (
                "signal-test-001",
                "Signal Test",
                json.dumps({}),
                json.dumps(["10.0.0.1"]),
                "daily",
                past_time,
                now_iso,
                now_iso,
            ),
        )

        mock_controller = MagicMock()
        engine.scan_controller = mock_controller

        with qtbot.waitSignal(engine.scan_triggered, timeout=5000):
            engine._check_pending()

    def test_scan_completed_signal(self, engine, master_pool, qtbot):
        """scan_completed should be emitted on successful execution."""
        past_time = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        now_iso = datetime.now(timezone.utc).isoformat()

        master_pool.execute_write(
            """INSERT INTO scheduled_scans
               (id, engagement_id, name, scan_config, target_list,
                recurrence_pattern, next_execution, status,
                failure_count, created_at, updated_at)
               VALUES (?, NULL, ?, ?, ?, ?, ?, 'active', 0, ?, ?)""",
            (
                "signal-complete-001",
                "Complete Signal",
                json.dumps({}),
                json.dumps(["10.0.0.1"]),
                "daily",
                past_time,
                now_iso,
                now_iso,
            ),
        )

        mock_controller = MagicMock()
        engine.scan_controller = mock_controller

        with qtbot.waitSignal(engine.scan_completed, timeout=5000) as blocker:
            engine._check_pending()

        assert blocker.args[0] == "signal-complete-001"
        assert blocker.args[1] == {"status": "success"}

    def test_scan_failed_signal(self, engine, master_pool, qtbot):
        """scan_failed should be emitted when execution fails."""
        past_time = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        now_iso = datetime.now(timezone.utc).isoformat()

        master_pool.execute_write(
            """INSERT INTO scheduled_scans
               (id, engagement_id, name, scan_config, target_list,
                recurrence_pattern, next_execution, status,
                failure_count, created_at, updated_at)
               VALUES (?, NULL, ?, ?, ?, ?, ?, 'active', 0, ?, ?)""",
            (
                "signal-fail-001",
                "Fail Signal",
                json.dumps({}),
                json.dumps(["10.0.0.1"]),
                "daily",
                past_time,
                now_iso,
                now_iso,
            ),
        )

        # No scan controller = failure
        with qtbot.waitSignal(engine.scan_failed, timeout=5000) as blocker:
            engine._check_pending()

        assert blocker.args[0] == "signal-fail-001"
        assert "No scan controller" in blocker.args[1]
