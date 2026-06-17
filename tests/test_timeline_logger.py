# tests/test_timeline_logger.py
"""Tests for the timeline logger engine."""

import json
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock

import pytest
from PyQt6.QtCore import QObject, pyqtSignal

from app.core.engagement_database import EngagementDatabase
from app.core.timeline_logger import (
    TimelineLogger,
    VALID_ACTION_TYPES,
)


@pytest.fixture
def engagement_db(tmp_path):
    """Create a temporary engagement database for testing."""
    db_path = str(tmp_path / "test_engagement.db")
    db = EngagementDatabase(db_path)
    db.connect()
    db.create_schema()
    yield db
    db.close()


@pytest.fixture
def timeline_logger(engagement_db):
    """Create a TimelineLogger with a connected database."""
    tl = TimelineLogger()
    tl.set_database(engagement_db)
    return tl


class TestTimelineLoggerSetup:
    """Tests for database configuration."""

    def test_no_database_raises(self):
        """Operations should raise RuntimeError if no database is set."""
        tl = TimelineLogger()
        with pytest.raises(RuntimeError, match="No database set"):
            tl.log_event("manual", "test description")

    def test_set_database(self, engagement_db):
        """set_database should configure the internal database reference."""
        tl = TimelineLogger()
        assert tl.database is None
        tl.set_database(engagement_db)
        assert tl.database is engagement_db

    def test_get_timeline_no_database_raises(self):
        """get_timeline should raise RuntimeError if no database is set."""
        tl = TimelineLogger()
        with pytest.raises(RuntimeError, match="No database set"):
            tl.get_timeline()


class TestLogEvent:
    """Tests for log_event() core method."""

    def test_log_basic_event(self, timeline_logger):
        """Log a simple event and verify it returns the correct structure."""
        entry = timeline_logger.log_event(
            action_type="manual",
            description="Test entry",
            actor="tester",
        )
        assert entry["id"] is not None
        assert entry["action_type"] == "manual"
        assert entry["description"] == "Test entry"
        assert entry["actor"] == "tester"
        assert entry["timestamp"] is not None

    def test_log_event_with_all_fields(self, timeline_logger):
        """Log an event with all optional fields populated."""
        ts = "2024-06-15T10:30:00+00:00"
        metadata = {"key": "value", "count": 42}
        entry = timeline_logger.log_event(
            action_type="finding_discovered",
            description="SQL Injection found",
            actor="scanner",
            affected_entity_type="finding",
            affected_entity_id=7,
            metadata=metadata,
            timestamp=ts,
        )
        assert entry["action_type"] == "finding_discovered"
        assert entry["affected_entity_type"] == "finding"
        assert entry["affected_entity_id"] == 7
        assert entry["metadata"] == metadata
        assert entry["timestamp"] == ts

    def test_log_event_invalid_action_type(self, timeline_logger):
        """Invalid action_type should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid action_type"):
            timeline_logger.log_event(
                action_type="invalid_type",
                description="should fail",
            )

    def test_log_event_auto_timestamp(self, timeline_logger):
        """Event should get an auto-generated UTC timestamp if none provided."""
        before = datetime.now(timezone.utc).isoformat()
        entry = timeline_logger.log_event("manual", "auto ts test")
        after = datetime.now(timezone.utc).isoformat()
        assert before <= entry["timestamp"] <= after

    def test_log_event_emits_signal(self, timeline_logger):
        """Logging an event should emit the event_logged signal."""
        received = []
        timeline_logger.event_logged.connect(lambda e: received.append(e))
        timeline_logger.log_event("manual", "signal test")
        assert len(received) == 1
        assert received[0]["description"] == "signal test"

    def test_all_valid_action_types_accepted(self, timeline_logger):
        """All defined action types should be accepted without error."""
        for action_type in VALID_ACTION_TYPES:
            entry = timeline_logger.log_event(action_type, f"test {action_type}")
            assert entry["action_type"] == action_type

    def test_metadata_none_stored_as_null(self, timeline_logger):
        """When metadata is None, it should be stored and retrieved as None."""
        entry = timeline_logger.log_event("manual", "no metadata")
        entries = timeline_logger.get_timeline()
        assert entries[0]["metadata"] is None


class TestSignalHandlers:
    """Tests for the signal handler methods."""

    def test_log_scan_start(self, timeline_logger):
        """log_scan_start should create a scan_start entry."""
        entry = timeline_logger.log_scan_start(
            scan_type="port_scan",
            target="192.168.1.1",
            actor="user1",
        )
        assert entry["action_type"] == "scan_start"
        assert "port_scan" in entry["description"]
        assert "192.168.1.1" in entry["description"]
        assert entry["metadata"]["scan_type"] == "port_scan"
        assert entry["metadata"]["target"] == "192.168.1.1"

    def test_log_scan_complete(self, timeline_logger):
        """log_scan_complete should create a scan_complete entry."""
        entry = timeline_logger.log_scan_complete(
            scan_type="vuln_scan",
            target="10.0.0.1",
            results_summary="3 vulnerabilities found",
            actor="system",
        )
        assert entry["action_type"] == "scan_complete"
        assert "vuln_scan" in entry["description"]
        assert "3 vulnerabilities found" in entry["description"]
        assert entry["metadata"]["results_summary"] == "3 vulnerabilities found"

    def test_log_scan_complete_no_summary(self, timeline_logger):
        """log_scan_complete without results_summary should still work."""
        entry = timeline_logger.log_scan_complete(
            scan_type="port_scan",
            target="10.0.0.2",
        )
        assert entry["action_type"] == "scan_complete"
        assert "results_summary" not in entry["metadata"]

    def test_log_finding_discovered(self, timeline_logger):
        """log_finding_discovered should create a finding_discovered entry."""
        entry = timeline_logger.log_finding_discovered(
            finding_id=42,
            title="XSS in Login",
            severity="high",
            actor="web_scanner",
        )
        assert entry["action_type"] == "finding_discovered"
        assert entry["affected_entity_type"] == "finding"
        assert entry["affected_entity_id"] == 42
        assert "HIGH" in entry["description"]
        assert "XSS in Login" in entry["description"]

    def test_log_state_transition(self, timeline_logger):
        """log_state_transition should create a state_transition entry."""
        entry = timeline_logger.log_state_transition(
            engagement_id="eng-123",
            old_state="draft",
            new_state="scoping",
            actor="admin",
        )
        assert entry["action_type"] == "state_transition"
        assert "draft" in entry["description"]
        assert "scoping" in entry["description"]
        assert entry["metadata"]["engagement_id"] == "eng-123"
        assert entry["metadata"]["old_state"] == "draft"
        assert entry["metadata"]["new_state"] == "scoping"

    def test_log_evidence_captured(self, timeline_logger):
        """log_evidence_captured should create an evidence_captured entry."""
        entry = timeline_logger.log_evidence_captured(
            evidence_id=10,
            evidence_type="screenshot",
            actor="tester",
        )
        assert entry["action_type"] == "evidence_captured"
        assert entry["affected_entity_type"] == "evidence"
        assert entry["affected_entity_id"] == 10
        assert "screenshot" in entry["description"]

    def test_log_evidence_captured_no_type(self, timeline_logger):
        """log_evidence_captured without evidence_type should use 'evidence'."""
        entry = timeline_logger.log_evidence_captured(evidence_id=5)
        assert "evidence" in entry["description"]


class TestManualEntry:
    """Tests for add_manual_entry()."""

    def test_add_manual_entry(self, timeline_logger):
        """add_manual_entry should create a manual action_type entry."""
        entry = timeline_logger.add_manual_entry(
            description="Started testing auth bypass",
            actor="pen_tester",
        )
        assert entry["action_type"] == "manual"
        assert entry["description"] == "Started testing auth bypass"
        assert entry["actor"] == "pen_tester"

    def test_add_manual_entry_custom_timestamp(self, timeline_logger):
        """add_manual_entry should accept a custom timestamp."""
        custom_ts = "2024-01-15T08:00:00+00:00"
        entry = timeline_logger.add_manual_entry(
            description="Retroactive note",
            timestamp=custom_ts,
        )
        assert entry["timestamp"] == custom_ts

    def test_add_manual_entry_with_metadata(self, timeline_logger):
        """add_manual_entry should store metadata."""
        entry = timeline_logger.add_manual_entry(
            description="Noted unusual behavior",
            metadata={"detail": "server returned 500 intermittently"},
        )
        assert entry["metadata"]["detail"] == "server returned 500 intermittently"


class TestGetTimeline:
    """Tests for get_timeline() with filtering."""

    def _seed_entries(self, timeline_logger):
        """Seed the timeline with multiple varied entries."""
        timeline_logger.log_event(
            "scan_start", "Port scan started",
            actor="scanner", affected_entity_type="target",
            timestamp="2024-06-01T09:00:00+00:00",
        )
        timeline_logger.log_event(
            "finding_discovered", "SQL Injection found",
            actor="scanner", affected_entity_type="finding",
            affected_entity_id=1,
            timestamp="2024-06-01T10:00:00+00:00",
        )
        timeline_logger.log_event(
            "manual", "Lunch break note",
            actor="tester",
            timestamp="2024-06-01T12:00:00+00:00",
        )
        timeline_logger.log_event(
            "state_transition", "Active to Reporting",
            actor="admin", affected_entity_type="engagement",
            timestamp="2024-06-02T09:00:00+00:00",
        )
        timeline_logger.log_event(
            "evidence_captured", "Screenshot captured",
            actor="tester", affected_entity_type="evidence",
            affected_entity_id=5,
            timestamp="2024-06-02T10:00:00+00:00",
        )

    def test_get_all_entries(self, timeline_logger):
        """get_timeline with no filters returns all entries in order."""
        self._seed_entries(timeline_logger)
        entries = timeline_logger.get_timeline()
        assert len(entries) == 5
        # Verify chronological order
        for i in range(len(entries) - 1):
            assert entries[i]["timestamp"] <= entries[i + 1]["timestamp"]

    def test_filter_by_action_type(self, timeline_logger):
        """Filtering by action_type returns only matching entries."""
        self._seed_entries(timeline_logger)
        entries = timeline_logger.get_timeline(action_type="manual")
        assert len(entries) == 1
        assert entries[0]["description"] == "Lunch break note"

    def test_filter_by_actor(self, timeline_logger):
        """Filtering by actor returns only entries from that actor."""
        self._seed_entries(timeline_logger)
        entries = timeline_logger.get_timeline(actor="scanner")
        assert len(entries) == 2
        for e in entries:
            assert e["actor"] == "scanner"

    def test_filter_by_date_from(self, timeline_logger):
        """Filtering by date_from returns entries at or after that time."""
        self._seed_entries(timeline_logger)
        entries = timeline_logger.get_timeline(
            date_from="2024-06-02T00:00:00+00:00"
        )
        assert len(entries) == 2
        for e in entries:
            assert e["timestamp"] >= "2024-06-02T00:00:00+00:00"

    def test_filter_by_date_to(self, timeline_logger):
        """Filtering by date_to returns entries at or before that time."""
        self._seed_entries(timeline_logger)
        entries = timeline_logger.get_timeline(
            date_to="2024-06-01T11:00:00+00:00"
        )
        assert len(entries) == 2
        for e in entries:
            assert e["timestamp"] <= "2024-06-01T11:00:00+00:00"

    def test_filter_by_date_range(self, timeline_logger):
        """Filtering by both date_from and date_to narrows to range."""
        self._seed_entries(timeline_logger)
        entries = timeline_logger.get_timeline(
            date_from="2024-06-01T09:30:00+00:00",
            date_to="2024-06-01T12:30:00+00:00",
        )
        assert len(entries) == 2
        assert entries[0]["action_type"] == "finding_discovered"
        assert entries[1]["action_type"] == "manual"

    def test_filter_by_affected_entity_type(self, timeline_logger):
        """Filtering by affected_entity_type returns matching entries."""
        self._seed_entries(timeline_logger)
        entries = timeline_logger.get_timeline(affected_entity_type="finding")
        assert len(entries) == 1
        assert entries[0]["affected_entity_type"] == "finding"

    def test_multiple_filters_combined(self, timeline_logger):
        """Multiple filters should be ANDed together."""
        self._seed_entries(timeline_logger)
        entries = timeline_logger.get_timeline(
            actor="tester",
            action_type="evidence_captured",
        )
        assert len(entries) == 1
        assert entries[0]["actor"] == "tester"
        assert entries[0]["action_type"] == "evidence_captured"

    def test_filter_no_results(self, timeline_logger):
        """Filters that match nothing should return empty list."""
        self._seed_entries(timeline_logger)
        entries = timeline_logger.get_timeline(actor="nonexistent_user")
        assert entries == []

    def test_invalid_action_type_filter_raises(self, timeline_logger):
        """Invalid action_type in filter should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid action_type filter"):
            timeline_logger.get_timeline(action_type="bogus")

    def test_empty_timeline(self, timeline_logger):
        """get_timeline on empty database returns empty list."""
        entries = timeline_logger.get_timeline()
        assert entries == []


class TestSignalConnections:
    """Tests for connect_to_* helper methods."""

    def test_connect_to_engagement_manager(self, timeline_logger):
        """connect_to_engagement_manager should connect to state_changed signal."""
        class MockEngagementManager(QObject):
            state_changed = pyqtSignal(str, str, str)

        mgr = MockEngagementManager()
        timeline_logger.connect_to_engagement_manager(mgr)

        # Emit the signal and verify a timeline entry is created
        mgr.state_changed.emit("eng-1", "active", "reporting")
        entries = timeline_logger.get_timeline(action_type="state_transition")
        assert len(entries) == 1
        assert entries[0]["metadata"]["old_state"] == "active"
        assert entries[0]["metadata"]["new_state"] == "reporting"

    def test_connect_to_evidence_manager(self, timeline_logger):
        """connect_to_evidence_manager should connect to evidence_stored signal."""
        class MockEvidenceManager(QObject):
            evidence_stored = pyqtSignal(int)

        mgr = MockEvidenceManager()
        timeline_logger.connect_to_evidence_manager(mgr)

        mgr.evidence_stored.emit(99)
        entries = timeline_logger.get_timeline(action_type="evidence_captured")
        assert len(entries) == 1
        assert entries[0]["affected_entity_id"] == 99

    def test_connect_to_scanner(self, timeline_logger):
        """connect_to_scanner should handle scanner signals gracefully."""
        class MockScanner(QObject):
            scan_started = pyqtSignal(str, str, str, dict)
            scan_completed = pyqtSignal(str, str, str, str, dict)

        scanner = MockScanner()
        # Should not raise even if signal signatures differ
        timeline_logger.connect_to_scanner(scanner)

    def test_connect_to_missing_signals(self, timeline_logger):
        """connect helpers should handle missing signals gracefully."""
        # Plain object without signals
        fake_manager = MagicMock()
        del fake_manager.state_changed  # Ensure attribute doesn't exist
        # Should not raise
        timeline_logger.connect_to_engagement_manager(fake_manager)
