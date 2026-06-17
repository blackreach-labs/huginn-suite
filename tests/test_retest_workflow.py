# tests/test_retest_workflow.py
"""Tests for the retest workflow engine module."""

import pytest
from unittest.mock import MagicMock

from app.core.engagement_database import EngagementDatabase
from app.core.retest_workflow import RetestWorkflow, VALID_RETEST_STATUSES


@pytest.fixture
def engagement_db(tmp_path):
    """Create a temporary engagement database for testing."""
    db_path = str(tmp_path / "engagement.db")
    db = EngagementDatabase(db_path)
    db.connect()
    db.create_schema()
    yield db
    db.close()


@pytest.fixture
def retest_workflow(engagement_db):
    """Create a RetestWorkflow instance attached to a test database."""
    rw = RetestWorkflow()
    rw.set_database(engagement_db)
    return rw


def _create_finding(db, title="Test Finding", severity="high", status="open"):
    """Helper to create a finding in the test database."""
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    return db.execute_write(
        """INSERT INTO findings (title, severity, description, impact, remediation, status, created_at, updated_at)
           VALUES (?, ?, 'desc', 'impact', 'fix it', ?, ?, ?)""",
        (title, severity, status, now, now),
    )


class TestRetestWorkflowSetup:
    """Tests for RetestWorkflow initialization and database attachment."""

    def test_set_database_attaches_db(self, engagement_db):
        """set_database() should attach the database."""
        rw = RetestWorkflow()
        assert rw.database is None

        rw.set_database(engagement_db)
        assert rw.database is engagement_db

    def test_set_database_requires_connected_db(self, tmp_path):
        """set_database() should raise if db is not connected."""
        db_path = str(tmp_path / "engagement.db")
        db = EngagementDatabase(db_path)

        rw = RetestWorkflow()
        with pytest.raises(RuntimeError, match="must be connected"):
            rw.set_database(db)

    def test_operations_require_database(self):
        """Operations should raise RuntimeError if no database is attached."""
        rw = RetestWorkflow()

        with pytest.raises(RuntimeError, match="No database attached"):
            rw.create_retest_cycle()

        with pytest.raises(RuntimeError, match="No database attached"):
            rw.get_findings_checklist(1)

        with pytest.raises(RuntimeError, match="No database attached"):
            rw.record_retest_result(1, 1, "fixed", "notes")

        with pytest.raises(RuntimeError, match="No database attached"):
            rw.get_metrics(1)

        with pytest.raises(RuntimeError, match="No database attached"):
            rw.complete_cycle(1)


class TestCreateRetestCycle:
    """Tests for creating retest cycles."""

    def test_create_cycle_returns_id(self, retest_workflow):
        """create_retest_cycle() should return a positive cycle ID."""
        cycle_id = retest_workflow.create_retest_cycle()
        assert cycle_id > 0

    def test_create_cycle_auto_increments_number(self, retest_workflow):
        """Successive cycles should have incrementing cycle numbers."""
        id1 = retest_workflow.create_retest_cycle()
        id2 = retest_workflow.create_retest_cycle()

        cycle1 = retest_workflow.get_cycle(id1)
        cycle2 = retest_workflow.get_cycle(id2)

        assert cycle1["cycle_number"] == 1
        assert cycle2["cycle_number"] == 2

    def test_create_cycle_with_notes(self, retest_workflow):
        """create_retest_cycle() should store provided notes."""
        cycle_id = retest_workflow.create_retest_cycle(notes="First retest round")
        cycle = retest_workflow.get_cycle(cycle_id)
        assert cycle["notes"] == "First retest round"

    def test_create_cycle_sets_in_progress_status(self, retest_workflow):
        """New cycles should have 'in_progress' status."""
        cycle_id = retest_workflow.create_retest_cycle()
        cycle = retest_workflow.get_cycle(cycle_id)
        assert cycle["status"] == "in_progress"

    def test_create_cycle_sets_start_date(self, retest_workflow):
        """New cycles should have a start_date set."""
        cycle_id = retest_workflow.create_retest_cycle()
        cycle = retest_workflow.get_cycle(cycle_id)
        assert cycle["start_date"] is not None

    def test_create_cycle_no_end_date(self, retest_workflow):
        """New cycles should have no end_date."""
        cycle_id = retest_workflow.create_retest_cycle()
        cycle = retest_workflow.get_cycle(cycle_id)
        assert cycle["end_date"] is None

    def test_create_cycle_emits_signal(self, retest_workflow):
        """create_retest_cycle() should emit cycle_created signal."""
        signal_received = []
        retest_workflow.cycle_created.connect(lambda cid: signal_received.append(cid))

        cycle_id = retest_workflow.create_retest_cycle()
        assert signal_received == [cycle_id]


class TestGetFindingsChecklist:
    """Tests for getting the findings checklist."""

    def test_checklist_with_no_findings(self, retest_workflow):
        """Checklist should be empty when no findings exist."""
        cycle_id = retest_workflow.create_retest_cycle()
        checklist = retest_workflow.get_findings_checklist(cycle_id)
        assert checklist == []

    def test_checklist_shows_all_findings(self, retest_workflow, engagement_db):
        """Checklist should contain all findings from the engagement."""
        _create_finding(engagement_db, "Finding A", "high")
        _create_finding(engagement_db, "Finding B", "medium")
        _create_finding(engagement_db, "Finding C", "low")

        cycle_id = retest_workflow.create_retest_cycle()
        checklist = retest_workflow.get_findings_checklist(cycle_id)

        assert len(checklist) == 3
        titles = [item["title"] for item in checklist]
        assert "Finding A" in titles
        assert "Finding B" in titles
        assert "Finding C" in titles

    def test_checklist_defaults_to_not_tested(self, retest_workflow, engagement_db):
        """Findings without results should show 'not_tested' status."""
        _create_finding(engagement_db, "Untested Finding")

        cycle_id = retest_workflow.create_retest_cycle()
        checklist = retest_workflow.get_findings_checklist(cycle_id)

        assert checklist[0]["retest_status"] == "not_tested"
        assert checklist[0]["retester_notes"] is None

    def test_checklist_shows_recorded_status(self, retest_workflow, engagement_db):
        """Findings with results should show their recorded retest status."""
        finding_id = _create_finding(engagement_db, "Tested Finding")
        cycle_id = retest_workflow.create_retest_cycle()

        retest_workflow.record_retest_result(cycle_id, finding_id, "fixed", "All good")
        checklist = retest_workflow.get_findings_checklist(cycle_id)

        assert checklist[0]["retest_status"] == "fixed"
        assert checklist[0]["retester_notes"] == "All good"

    def test_checklist_invalid_cycle_raises(self, retest_workflow):
        """get_findings_checklist() with invalid cycle ID should raise ValueError."""
        with pytest.raises(ValueError, match="does not exist"):
            retest_workflow.get_findings_checklist(999)


class TestRecordRetestResult:
    """Tests for recording retest results."""

    def test_record_result_returns_id(self, retest_workflow, engagement_db):
        """record_retest_result() should return a result ID."""
        finding_id = _create_finding(engagement_db)
        cycle_id = retest_workflow.create_retest_cycle()

        result_id = retest_workflow.record_retest_result(
            cycle_id, finding_id, "fixed", "Verified fix"
        )
        assert result_id > 0

    def test_record_all_valid_statuses(self, retest_workflow, engagement_db):
        """All valid statuses should be accepted."""
        cycle_id = retest_workflow.create_retest_cycle()

        for status in VALID_RETEST_STATUSES:
            finding_id = _create_finding(engagement_db, f"Finding {status}")
            result_id = retest_workflow.record_retest_result(
                cycle_id, finding_id, status, f"Notes for {status}"
            )
            assert result_id > 0

    def test_record_invalid_status_raises(self, retest_workflow, engagement_db):
        """Invalid status should raise ValueError."""
        finding_id = _create_finding(engagement_db)
        cycle_id = retest_workflow.create_retest_cycle()

        with pytest.raises(ValueError, match="Invalid retest status"):
            retest_workflow.record_retest_result(
                cycle_id, finding_id, "invalid_status", "notes"
            )

    def test_record_nonexistent_cycle_raises(self, retest_workflow, engagement_db):
        """Recording on a nonexistent cycle should raise ValueError."""
        finding_id = _create_finding(engagement_db)

        with pytest.raises(ValueError, match="does not exist"):
            retest_workflow.record_retest_result(999, finding_id, "fixed", "notes")

    def test_record_nonexistent_finding_raises(self, retest_workflow, engagement_db):
        """Recording for a nonexistent finding should raise ValueError."""
        cycle_id = retest_workflow.create_retest_cycle()

        with pytest.raises(ValueError, match="Finding with id .* does not exist"):
            retest_workflow.record_retest_result(cycle_id, 999, "fixed", "notes")

    def test_record_on_completed_cycle_raises(self, retest_workflow, engagement_db):
        """Recording on a completed cycle should raise ValueError."""
        finding_id = _create_finding(engagement_db)
        cycle_id = retest_workflow.create_retest_cycle()
        retest_workflow.complete_cycle(cycle_id)

        with pytest.raises(ValueError, match="completed cycle"):
            retest_workflow.record_retest_result(
                cycle_id, finding_id, "fixed", "notes"
            )

    def test_record_with_evidence_id(self, retest_workflow, engagement_db):
        """record_retest_result() should store the evidence_id."""
        from datetime import datetime, timezone
        import hashlib

        finding_id = _create_finding(engagement_db)
        cycle_id = retest_workflow.create_retest_cycle()

        # Create an actual evidence record to satisfy foreign key
        now = datetime.now(timezone.utc).isoformat()
        evidence_id = engagement_db.execute_write(
            """INSERT INTO evidence (evidence_type, title, sha256_hash, created_at)
               VALUES ('screenshot', 'test evidence', ?, ?)""",
            (hashlib.sha256(b"test").hexdigest(), now),
        )

        retest_workflow.record_retest_result(
            cycle_id, finding_id, "fixed", "With evidence", evidence_id=evidence_id
        )

        checklist = retest_workflow.get_findings_checklist(cycle_id)
        assert checklist[0]["evidence_id"] == evidence_id

    def test_record_upsert_updates_existing(self, retest_workflow, engagement_db):
        """Recording twice for same finding/cycle should update the result."""
        finding_id = _create_finding(engagement_db)
        cycle_id = retest_workflow.create_retest_cycle()

        retest_workflow.record_retest_result(
            cycle_id, finding_id, "not_fixed", "Still broken"
        )
        retest_workflow.record_retest_result(
            cycle_id, finding_id, "fixed", "Now fixed"
        )

        checklist = retest_workflow.get_findings_checklist(cycle_id)
        assert checklist[0]["retest_status"] == "fixed"
        assert checklist[0]["retester_notes"] == "Now fixed"

    def test_record_regressed_flags_finding(self, retest_workflow, engagement_db):
        """Recording 'regressed' should update finding status to 'regressed'."""
        finding_id = _create_finding(engagement_db, status="open")
        cycle_id = retest_workflow.create_retest_cycle()

        retest_workflow.record_retest_result(
            cycle_id, finding_id, "regressed", "Got worse"
        )

        # Check finding status was updated
        rows = engagement_db.execute_query(
            "SELECT status FROM findings WHERE id = ?", (finding_id,)
        )
        assert rows[0][0] == "regressed"

    def test_record_emits_signal(self, retest_workflow, engagement_db):
        """record_retest_result() should emit result_recorded signal."""
        finding_id = _create_finding(engagement_db)
        cycle_id = retest_workflow.create_retest_cycle()

        signal_received = []
        retest_workflow.result_recorded.connect(
            lambda cid, fid: signal_received.append((cid, fid))
        )

        retest_workflow.record_retest_result(
            cycle_id, finding_id, "fixed", "done"
        )
        assert signal_received == [(cycle_id, finding_id)]


class TestGetMetrics:
    """Tests for computing retest metrics."""

    def test_metrics_no_findings(self, retest_workflow):
        """Metrics with no findings should return all zeros."""
        cycle_id = retest_workflow.create_retest_cycle()
        metrics = retest_workflow.get_metrics(cycle_id)

        assert metrics["total_findings"] == 0
        assert metrics["findings_retested"] == 0
        assert metrics["findings_remaining"] == 0
        assert metrics["pass_rate"] == 0.0
        assert metrics["regressed_count"] == 0

    def test_metrics_all_not_tested(self, retest_workflow, engagement_db):
        """Metrics before any results should show all remaining."""
        _create_finding(engagement_db, "A")
        _create_finding(engagement_db, "B")
        _create_finding(engagement_db, "C")

        cycle_id = retest_workflow.create_retest_cycle()
        metrics = retest_workflow.get_metrics(cycle_id)

        assert metrics["total_findings"] == 3
        assert metrics["findings_retested"] == 0
        assert metrics["findings_remaining"] == 3
        assert metrics["pass_rate"] == 0.0

    def test_metrics_partial_completion(self, retest_workflow, engagement_db):
        """Metrics should reflect partial testing progress."""
        f1 = _create_finding(engagement_db, "Finding 1")
        f2 = _create_finding(engagement_db, "Finding 2")
        _create_finding(engagement_db, "Finding 3")

        cycle_id = retest_workflow.create_retest_cycle()
        retest_workflow.record_retest_result(cycle_id, f1, "fixed", "ok")
        retest_workflow.record_retest_result(cycle_id, f2, "not_fixed", "still broken")

        metrics = retest_workflow.get_metrics(cycle_id)

        assert metrics["total_findings"] == 3
        assert metrics["findings_retested"] == 2
        assert metrics["findings_remaining"] == 1
        assert metrics["pass_rate"] == 0.5  # 1 fixed out of 2 retested

    def test_metrics_pass_rate_all_fixed(self, retest_workflow, engagement_db):
        """Pass rate should be 1.0 when all retested findings are fixed."""
        f1 = _create_finding(engagement_db, "Finding 1")
        f2 = _create_finding(engagement_db, "Finding 2")

        cycle_id = retest_workflow.create_retest_cycle()
        retest_workflow.record_retest_result(cycle_id, f1, "fixed", "ok")
        retest_workflow.record_retest_result(cycle_id, f2, "fixed", "ok")

        metrics = retest_workflow.get_metrics(cycle_id)
        assert metrics["pass_rate"] == 1.0

    def test_metrics_regressed_count(self, retest_workflow, engagement_db):
        """Metrics should count regressed findings."""
        f1 = _create_finding(engagement_db, "Finding 1")
        f2 = _create_finding(engagement_db, "Finding 2")
        f3 = _create_finding(engagement_db, "Finding 3")

        cycle_id = retest_workflow.create_retest_cycle()
        retest_workflow.record_retest_result(cycle_id, f1, "fixed", "ok")
        retest_workflow.record_retest_result(cycle_id, f2, "regressed", "worse")
        retest_workflow.record_retest_result(cycle_id, f3, "regressed", "also worse")

        metrics = retest_workflow.get_metrics(cycle_id)
        assert metrics["regressed_count"] == 2

    def test_metrics_invariant_total_equals_retested_plus_remaining(
        self, retest_workflow, engagement_db
    ):
        """total_findings should always equal retested + remaining."""
        _create_finding(engagement_db, "A")
        _create_finding(engagement_db, "B")
        f3 = _create_finding(engagement_db, "C")

        cycle_id = retest_workflow.create_retest_cycle()
        retest_workflow.record_retest_result(cycle_id, f3, "fixed", "done")

        metrics = retest_workflow.get_metrics(cycle_id)
        assert metrics["total_findings"] == metrics["findings_retested"] + metrics["findings_remaining"]

    def test_metrics_invalid_cycle_raises(self, retest_workflow):
        """get_metrics() with invalid cycle should raise ValueError."""
        with pytest.raises(ValueError, match="does not exist"):
            retest_workflow.get_metrics(999)


class TestCompleteCycle:
    """Tests for completing retest cycles."""

    def test_complete_cycle_returns_summary(self, retest_workflow, engagement_db):
        """complete_cycle() should return a summary dict."""
        finding_id = _create_finding(engagement_db)
        cycle_id = retest_workflow.create_retest_cycle()
        retest_workflow.record_retest_result(cycle_id, finding_id, "fixed", "done")

        summary = retest_workflow.complete_cycle(cycle_id)

        assert summary["cycle_id"] == cycle_id
        assert summary["cycle_number"] == 1
        assert summary["start_date"] is not None
        assert summary["end_date"] is not None
        assert "metrics" in summary
        assert "regressed_findings" in summary

    def test_complete_cycle_sets_status_completed(self, retest_workflow):
        """complete_cycle() should set status to 'completed'."""
        cycle_id = retest_workflow.create_retest_cycle()
        retest_workflow.complete_cycle(cycle_id)

        cycle = retest_workflow.get_cycle(cycle_id)
        assert cycle["status"] == "completed"

    def test_complete_cycle_sets_end_date(self, retest_workflow):
        """complete_cycle() should set the end_date."""
        cycle_id = retest_workflow.create_retest_cycle()
        retest_workflow.complete_cycle(cycle_id)

        cycle = retest_workflow.get_cycle(cycle_id)
        assert cycle["end_date"] is not None

    def test_complete_already_completed_raises(self, retest_workflow):
        """Completing an already-completed cycle should raise ValueError."""
        cycle_id = retest_workflow.create_retest_cycle()
        retest_workflow.complete_cycle(cycle_id)

        with pytest.raises(ValueError, match="already completed"):
            retest_workflow.complete_cycle(cycle_id)

    def test_complete_nonexistent_cycle_raises(self, retest_workflow):
        """Completing a nonexistent cycle should raise ValueError."""
        with pytest.raises(ValueError, match="does not exist"):
            retest_workflow.complete_cycle(999)

    def test_complete_cycle_summary_includes_regressed(self, retest_workflow, engagement_db):
        """Summary should include regressed findings details."""
        f1 = _create_finding(engagement_db, "Regressed Finding", "critical")
        cycle_id = retest_workflow.create_retest_cycle()
        retest_workflow.record_retest_result(cycle_id, f1, "regressed", "Got worse")

        summary = retest_workflow.complete_cycle(cycle_id)

        assert len(summary["regressed_findings"]) == 1
        assert summary["regressed_findings"][0]["title"] == "Regressed Finding"
        assert summary["regressed_findings"][0]["severity"] == "critical"

    def test_complete_cycle_emits_signal(self, retest_workflow):
        """complete_cycle() should emit cycle_completed signal."""
        cycle_id = retest_workflow.create_retest_cycle()

        signal_received = []
        retest_workflow.cycle_completed.connect(lambda cid: signal_received.append(cid))

        retest_workflow.complete_cycle(cycle_id)
        assert signal_received == [cycle_id]


class TestMultipleCycles:
    """Tests for multiple retest cycles preserving history."""

    def test_multiple_cycles_have_different_numbers(self, retest_workflow):
        """Each cycle should get an incrementing cycle number."""
        id1 = retest_workflow.create_retest_cycle()
        id2 = retest_workflow.create_retest_cycle()
        id3 = retest_workflow.create_retest_cycle()

        cycles = retest_workflow.get_all_cycles()
        assert len(cycles) == 3
        assert cycles[0]["cycle_number"] == 1
        assert cycles[1]["cycle_number"] == 2
        assert cycles[2]["cycle_number"] == 3

    def test_cycle_results_independent(self, retest_workflow, engagement_db):
        """Results in one cycle should not affect another cycle's checklist."""
        finding_id = _create_finding(engagement_db, "Cross-cycle Finding")

        cycle1_id = retest_workflow.create_retest_cycle()
        cycle2_id = retest_workflow.create_retest_cycle()

        # Record in cycle 1 only
        retest_workflow.record_retest_result(
            cycle1_id, finding_id, "not_fixed", "Still broken"
        )

        # Cycle 2 should still show not_tested for the same finding
        checklist2 = retest_workflow.get_findings_checklist(cycle2_id)
        assert checklist2[0]["retest_status"] == "not_tested"

        # Cycle 1 should show the recorded result
        checklist1 = retest_workflow.get_findings_checklist(cycle1_id)
        assert checklist1[0]["retest_status"] == "not_fixed"

    def test_completed_cycle_results_preserved(self, retest_workflow, engagement_db):
        """Completing a cycle should not modify results in previous cycles."""
        finding_id = _create_finding(engagement_db, "Persistent Finding")

        cycle1_id = retest_workflow.create_retest_cycle()
        retest_workflow.record_retest_result(
            cycle1_id, finding_id, "not_fixed", "First attempt"
        )
        retest_workflow.complete_cycle(cycle1_id)

        # Create and complete a second cycle
        cycle2_id = retest_workflow.create_retest_cycle()
        retest_workflow.record_retest_result(
            cycle2_id, finding_id, "fixed", "Second attempt"
        )
        retest_workflow.complete_cycle(cycle2_id)

        # Verify cycle 1 results unchanged
        checklist1 = retest_workflow.get_findings_checklist(cycle1_id)
        assert checklist1[0]["retest_status"] == "not_fixed"
        assert checklist1[0]["retester_notes"] == "First attempt"

    def test_get_all_cycles_ordered(self, retest_workflow):
        """get_all_cycles() should return cycles in order."""
        retest_workflow.create_retest_cycle(notes="First")
        retest_workflow.create_retest_cycle(notes="Second")
        retest_workflow.create_retest_cycle(notes="Third")

        cycles = retest_workflow.get_all_cycles()
        assert [c["notes"] for c in cycles] == ["First", "Second", "Third"]

    def test_metrics_scoped_to_cycle(self, retest_workflow, engagement_db):
        """Metrics should only count results from the specified cycle."""
        f1 = _create_finding(engagement_db, "Finding 1")
        f2 = _create_finding(engagement_db, "Finding 2")

        cycle1_id = retest_workflow.create_retest_cycle()
        cycle2_id = retest_workflow.create_retest_cycle()

        retest_workflow.record_retest_result(cycle1_id, f1, "fixed", "ok")
        retest_workflow.record_retest_result(cycle1_id, f2, "fixed", "ok")
        retest_workflow.record_retest_result(cycle2_id, f1, "not_fixed", "nope")

        metrics1 = retest_workflow.get_metrics(cycle1_id)
        metrics2 = retest_workflow.get_metrics(cycle2_id)

        assert metrics1["findings_retested"] == 2
        assert metrics1["pass_rate"] == 1.0

        assert metrics2["findings_retested"] == 1
        assert metrics2["pass_rate"] == 0.0
