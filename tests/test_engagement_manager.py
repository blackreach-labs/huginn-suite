"""Tests for the EngagementManager lifecycle state machine and CRUD operations."""

import os
import tempfile
import shutil
from pathlib import Path

import pytest

from app.core.engagement_manager import (
    EngagementManager,
    EngagementState,
    VALID_TRANSITIONS,
)


@pytest.fixture
def tmp_resources(tmp_path):
    """Create a temporary resources directory for testing."""
    master_db = str(tmp_path / "huginn_master_index.db")
    return master_db


@pytest.fixture
def manager(tmp_resources):
    """Create an EngagementManager with a temp database."""
    mgr = EngagementManager(master_db_path=tmp_resources)
    yield mgr
    mgr.close()


class TestEngagementCreation:
    """Tests for engagement creation and listing."""

    def test_create_engagement_returns_uuid(self, manager):
        eid = manager.create_engagement(
            name="Test Engagement",
            client_name="Acme Corp",
            engagement_type="external",
            start_date="2024-01-01",
            end_date="2024-02-01",
        )
        assert eid is not None
        # UUID format check
        assert len(eid) == 36
        assert eid.count("-") == 4

    def test_create_engagement_creates_db_file(self, manager, tmp_resources):
        eid = manager.create_engagement(
            name="DB File Test",
            client_name="Client",
            engagement_type="internal",
        )
        base_dir = Path(tmp_resources).parent / "engagements" / eid
        db_file = base_dir / "engagement.db"
        assert db_file.exists()
        assert (base_dir / "evidence").exists()
        assert (base_dir / "documents").exists()

    def test_create_engagement_initial_state_is_draft(self, manager):
        eid = manager.create_engagement(
            name="State Test",
            client_name="Client",
            engagement_type="web",
        )
        state = manager.get_current_state(eid)
        assert state == EngagementState.DRAFT

    def test_create_multiple_engagements_unique_ids(self, manager):
        ids = set()
        for i in range(10):
            eid = manager.create_engagement(
                name=f"Engagement {i}",
                client_name="Client",
                engagement_type="external",
            )
            ids.add(eid)
        assert len(ids) == 10

    def test_get_engagement_returns_metadata(self, manager):
        eid = manager.create_engagement(
            name="Metadata Test",
            client_name="Meta Client",
            engagement_type="cloud",
            start_date="2024-03-01",
            end_date="2024-04-01",
        )
        eng = manager.get_engagement(eid)
        assert eng is not None
        assert eng["name"] == "Metadata Test"
        assert eng["client_name"] == "Meta Client"
        assert eng["engagement_type"] == "cloud"
        assert eng["status"] == "draft"
        assert eng["start_date"] == "2024-03-01"
        assert eng["end_date"] == "2024-04-01"

    def test_get_nonexistent_engagement_returns_none(self, manager):
        assert manager.get_engagement("nonexistent-id") is None


class TestEngagementListing:
    """Tests for listing and filtering engagements."""

    def test_list_all_engagements(self, manager):
        manager.create_engagement(name="Eng 1", client_name="C1", engagement_type="web")
        manager.create_engagement(name="Eng 2", client_name="C2", engagement_type="internal")
        results = manager.list_engagements()
        assert len(results) == 2

    def test_list_engagements_status_filter(self, manager):
        eid1 = manager.create_engagement(name="Draft Eng", client_name="C1", engagement_type="web")
        eid2 = manager.create_engagement(name="Active Eng", client_name="C2", engagement_type="web")

        # Transition eid2 to active
        manager.transition_state(eid2, EngagementState.SCOPING)
        manager.transition_state(eid2, EngagementState.ACTIVE)

        drafts = manager.list_engagements(status_filter="draft")
        actives = manager.list_engagements(status_filter="active")
        assert len(drafts) == 1
        assert drafts[0]["name"] == "Draft Eng"
        assert len(actives) == 1
        assert actives[0]["name"] == "Active Eng"

    def test_list_engagements_search(self, manager):
        manager.create_engagement(name="Alpha Project", client_name="Alpha Inc", engagement_type="web")
        manager.create_engagement(name="Beta Project", client_name="Beta Corp", engagement_type="internal")

        results = manager.list_engagements(search_query="Alpha")
        assert len(results) == 1
        assert results[0]["name"] == "Alpha Project"

        # Search by client name
        results = manager.list_engagements(search_query="Beta Corp")
        assert len(results) == 1
        assert results[0]["client_name"] == "Beta Corp"


class TestStateMachine:
    """Tests for the engagement state machine transitions."""

    def test_valid_transitions_from_draft(self, manager):
        eid = manager.create_engagement(name="SM Test", client_name="C", engagement_type="web")
        assert manager.transition_state(eid, EngagementState.SCOPING) is True
        assert manager.get_current_state(eid) == EngagementState.SCOPING

    def test_valid_full_lifecycle(self, manager):
        eid = manager.create_engagement(name="Lifecycle", client_name="C", engagement_type="web")

        # Draft -> Scoping -> Active -> Reporting -> Closed
        assert manager.transition_state(eid, EngagementState.SCOPING)
        assert manager.transition_state(eid, EngagementState.ACTIVE)
        assert manager.transition_state(eid, EngagementState.REPORTING)
        assert manager.transition_state(eid, EngagementState.CLOSED)
        assert manager.get_current_state(eid) == EngagementState.CLOSED

    def test_invalid_transition_rejected(self, manager):
        eid = manager.create_engagement(name="Invalid", client_name="C", engagement_type="web")

        # Draft cannot go directly to Active
        assert manager.transition_state(eid, EngagementState.ACTIVE) is False
        assert manager.get_current_state(eid) == EngagementState.DRAFT

    def test_closed_state_has_no_transitions(self, manager):
        eid = manager.create_engagement(name="Closed", client_name="C", engagement_type="web")
        manager.transition_state(eid, EngagementState.SCOPING)
        manager.transition_state(eid, EngagementState.ACTIVE)
        manager.transition_state(eid, EngagementState.REPORTING)
        manager.transition_state(eid, EngagementState.CLOSED)

        # Cannot transition from Closed to anything
        for state in EngagementState:
            assert manager.transition_state(eid, state) is False

    def test_active_to_paused_and_back(self, manager):
        eid = manager.create_engagement(name="Pause", client_name="C", engagement_type="web")
        manager.transition_state(eid, EngagementState.SCOPING)
        manager.transition_state(eid, EngagementState.ACTIVE)
        assert manager.transition_state(eid, EngagementState.PAUSED)
        assert manager.transition_state(eid, EngagementState.ACTIVE)
        assert manager.get_current_state(eid) == EngagementState.ACTIVE

    def test_active_to_retest_and_reporting(self, manager):
        eid = manager.create_engagement(name="Retest", client_name="C", engagement_type="web")
        manager.transition_state(eid, EngagementState.SCOPING)
        manager.transition_state(eid, EngagementState.ACTIVE)
        assert manager.transition_state(eid, EngagementState.RETEST)
        assert manager.transition_state(eid, EngagementState.REPORTING)
        assert manager.get_current_state(eid) == EngagementState.REPORTING

    def test_transition_records_history(self, manager):
        eid = manager.create_engagement(name="History", client_name="C", engagement_type="web")
        manager.transition_state(eid, EngagementState.SCOPING, actor="tester")
        manager.transition_state(eid, EngagementState.ACTIVE, actor="lead")

        history = manager.get_state_history(eid)
        assert len(history) == 2
        assert history[0]["from_state"] == "draft"
        assert history[0]["to_state"] == "scoping"
        assert history[0]["actor"] == "tester"
        assert history[1]["from_state"] == "scoping"
        assert history[1]["to_state"] == "active"
        assert history[1]["actor"] == "lead"

    def test_transition_nonexistent_engagement_fails(self, manager):
        assert manager.transition_state("fake-id", EngagementState.SCOPING) is False

    def test_all_valid_transitions_succeed(self, manager):
        """Verify every defined valid transition in the state machine works."""
        for from_state, to_states in VALID_TRANSITIONS.items():
            for to_state in to_states:
                eid = manager.create_engagement(
                    name=f"{from_state.value}->{to_state.value}",
                    client_name="C",
                    engagement_type="web",
                )
                # Walk to from_state
                self._walk_to_state(manager, eid, from_state)
                # Now attempt the transition
                result = manager.transition_state(eid, to_state)
                assert result is True, (
                    f"Transition {from_state.value} -> {to_state.value} should be valid"
                )

    @staticmethod
    def _walk_to_state(manager, eid, target_state):
        """Walk an engagement from DRAFT to target_state using known paths."""
        paths = {
            EngagementState.DRAFT: [],
            EngagementState.SCOPING: [EngagementState.SCOPING],
            EngagementState.ACTIVE: [EngagementState.SCOPING, EngagementState.ACTIVE],
            EngagementState.PAUSED: [EngagementState.SCOPING, EngagementState.ACTIVE, EngagementState.PAUSED],
            EngagementState.RETEST: [EngagementState.SCOPING, EngagementState.ACTIVE, EngagementState.RETEST],
            EngagementState.REPORTING: [
                EngagementState.SCOPING, EngagementState.ACTIVE, EngagementState.REPORTING
            ],
            EngagementState.CLOSED: [
                EngagementState.SCOPING, EngagementState.ACTIVE, EngagementState.REPORTING, EngagementState.CLOSED
            ],
        }
        for state in paths[target_state]:
            manager.transition_state(eid, state)


class TestOpenEngagement:
    """Tests for opening and connecting to engagement databases."""

    def test_open_engagement_success(self, manager):
        eid = manager.create_engagement(name="Open Test", client_name="C", engagement_type="web")
        assert manager.open_engagement(eid) is True
        assert manager.active_engagement_id == eid
        assert manager.active_db is not None

    def test_open_nonexistent_engagement_fails(self, manager):
        assert manager.open_engagement("nonexistent-id") is False
        assert manager.active_engagement_id is None

    def test_open_closes_previous_engagement(self, manager):
        eid1 = manager.create_engagement(name="First", client_name="C", engagement_type="web")
        eid2 = manager.create_engagement(name="Second", client_name="C", engagement_type="web")

        manager.open_engagement(eid1)
        assert manager.active_engagement_id == eid1

        manager.open_engagement(eid2)
        assert manager.active_engagement_id == eid2


class TestDocumentCRUD:
    """Tests for document management in active engagement."""

    @pytest.fixture(autouse=True)
    def open_engagement(self, manager):
        eid = manager.create_engagement(name="Doc Test", client_name="C", engagement_type="web")
        manager.open_engagement(eid)
        yield

    def test_add_and_get_document(self, manager):
        doc_id = manager.add_document(
            filename="scope.pdf",
            document_type="scope",
            content=b"fake pdf content",
            mime_type="application/pdf",
            metadata={"version": 1},
        )
        assert doc_id > 0

        docs = manager.get_documents()
        assert len(docs) == 1
        assert docs[0]["filename"] == "scope.pdf"
        assert docs[0]["document_type"] == "scope"
        assert docs[0]["metadata"] == {"version": 1}

    def test_get_document_content(self, manager):
        content = b"binary content here"
        doc_id = manager.add_document(
            filename="test.bin", document_type="other", content=content
        )
        retrieved = manager.get_document_content(doc_id)
        assert retrieved == content

    def test_filter_documents_by_type(self, manager):
        manager.add_document(filename="scope.pdf", document_type="scope", content=b"s")
        manager.add_document(filename="nda.pdf", document_type="nda", content=b"n")

        scope_docs = manager.get_documents(document_type="scope")
        assert len(scope_docs) == 1
        assert scope_docs[0]["filename"] == "scope.pdf"

    def test_delete_document(self, manager):
        doc_id = manager.add_document(filename="del.pdf", document_type="other", content=b"x")
        assert manager.delete_document(doc_id) is True
        assert len(manager.get_documents()) == 0


class TestContactCRUD:
    """Tests for client contact management."""

    @pytest.fixture(autouse=True)
    def open_engagement(self, manager):
        eid = manager.create_engagement(name="Contact Test", client_name="C", engagement_type="web")
        manager.open_engagement(eid)
        yield

    def test_add_and_list_contacts(self, manager):
        cid = manager.add_contact(
            name="John Doe",
            role="CTO",
            email="john@example.com",
            phone="555-0100",
            availability_window={"start": "09:00", "end": "17:00", "timezone": "UTC"},
        )
        assert cid > 0

        contacts = manager.get_contacts()
        assert len(contacts) == 1
        assert contacts[0]["name"] == "John Doe"
        assert contacts[0]["role"] == "CTO"
        assert contacts[0]["availability_window"]["timezone"] == "UTC"

    def test_update_contact(self, manager):
        cid = manager.add_contact(name="Jane", role="PM")
        manager.update_contact(cid, role="Director", email="jane@example.com")

        contacts = manager.get_contacts()
        assert contacts[0]["role"] == "Director"
        assert contacts[0]["email"] == "jane@example.com"

    def test_delete_contact(self, manager):
        cid = manager.add_contact(name="Delete Me")
        assert manager.delete_contact(cid) is True
        assert len(manager.get_contacts()) == 0


class TestRulesOfEngagement:
    """Tests for RoE management."""

    @pytest.fixture(autouse=True)
    def open_engagement(self, manager):
        eid = manager.create_engagement(name="RoE Test", client_name="C", engagement_type="web")
        manager.open_engagement(eid)
        yield

    def test_set_and_get_roe(self, manager):
        manager.set_rules_of_engagement(
            authorized_ip_ranges=["10.0.0.0/8", "192.168.1.0/24"],
            excluded_systems=["10.0.0.1"],
            testing_hours={"start": "08:00", "end": "18:00", "timezone": "EST", "days": ["Mon", "Tue"]},
            emergency_contacts=[{"name": "Security Team", "phone": "555-911"}],
            escalation_procedures="Contact SOC at x5555",
            custom_rules="No social engineering on executives",
        )

        roe = manager.get_rules_of_engagement()
        assert roe is not None
        assert "10.0.0.0/8" in roe["authorized_ip_ranges"]
        assert roe["excluded_systems"] == ["10.0.0.1"]
        assert roe["testing_hours"]["timezone"] == "EST"
        assert roe["emergency_contacts"][0]["name"] == "Security Team"
        assert "SOC" in roe["escalation_procedures"]
        assert "executives" in roe["custom_rules"]

    def test_update_roe_overwrites(self, manager):
        manager.set_rules_of_engagement(
            authorized_ip_ranges=["10.0.0.0/8"]
        )
        manager.set_rules_of_engagement(
            authorized_ip_ranges=["172.16.0.0/12"]
        )
        roe = manager.get_rules_of_engagement()
        assert roe["authorized_ip_ranges"] == ["172.16.0.0/12"]

    def test_get_roe_returns_none_when_not_set(self, manager):
        assert manager.get_rules_of_engagement() is None


class TestMilestoneCRUD:
    """Tests for milestone management."""

    @pytest.fixture(autouse=True)
    def open_engagement(self, manager):
        eid = manager.create_engagement(name="Milestone Test", client_name="C", engagement_type="web")
        manager.open_engagement(eid)
        yield

    def test_add_and_list_milestones(self, manager):
        mid = manager.add_milestone(
            name="Kickoff",
            milestone_type="planned_start",
            date="2024-01-15",
            notes="Initial kickoff meeting",
        )
        assert mid > 0

        milestones = manager.get_milestones()
        assert len(milestones) == 1
        assert milestones[0]["name"] == "Kickoff"
        assert milestones[0]["milestone_type"] == "planned_start"
        assert milestones[0]["date"] == "2024-01-15"

    def test_milestones_ordered_by_date(self, manager):
        manager.add_milestone(name="End", milestone_type="planned_end", date="2024-03-01")
        manager.add_milestone(name="Start", milestone_type="planned_start", date="2024-01-01")
        manager.add_milestone(name="Mid", milestone_type="checkpoint", date="2024-02-01")

        milestones = manager.get_milestones()
        dates = [m["date"] for m in milestones]
        assert dates == sorted(dates)

    def test_update_milestone(self, manager):
        mid = manager.add_milestone(name="Old Name", milestone_type="checkpoint", date="2024-01-01")
        manager.update_milestone(mid, name="New Name", date="2024-01-15")

        milestones = manager.get_milestones()
        assert milestones[0]["name"] == "New Name"
        assert milestones[0]["date"] == "2024-01-15"

    def test_delete_milestone(self, manager):
        mid = manager.add_milestone(name="Remove", milestone_type="checkpoint", date="2024-01-01")
        assert manager.delete_milestone(mid) is True
        assert len(manager.get_milestones()) == 0


class TestSignals:
    """Tests for PyQt6 signal emission."""

    def test_engagement_created_signal(self, manager, qtbot):
        with qtbot.waitSignal(manager.engagement_created, timeout=1000) as blocker:
            eid = manager.create_engagement(name="Signal", client_name="C", engagement_type="web")
        assert blocker.args == [eid]

    def test_engagement_opened_signal(self, manager, qtbot):
        eid = manager.create_engagement(name="Signal Open", client_name="C", engagement_type="web")
        with qtbot.waitSignal(manager.engagement_opened, timeout=1000) as blocker:
            manager.open_engagement(eid)
        assert blocker.args == [eid]

    def test_state_changed_signal(self, manager, qtbot):
        eid = manager.create_engagement(name="Signal State", client_name="C", engagement_type="web")
        with qtbot.waitSignal(manager.state_changed, timeout=1000) as blocker:
            manager.transition_state(eid, EngagementState.SCOPING)
        assert blocker.args == [eid, "draft", "scoping"]


class TestErrorHandling:
    """Tests for error scenarios."""

    def test_operations_without_open_engagement_raise(self, manager):
        with pytest.raises(RuntimeError, match="No engagement is currently open"):
            manager.add_document(filename="x", document_type="scope", content=b"x")

        with pytest.raises(RuntimeError, match="No engagement is currently open"):
            manager.get_contacts()

        with pytest.raises(RuntimeError, match="No engagement is currently open"):
            manager.get_rules_of_engagement()

        with pytest.raises(RuntimeError, match="No engagement is currently open"):
            manager.get_milestones()
