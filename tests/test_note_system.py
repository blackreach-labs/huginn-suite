# tests/test_note_system.py
"""Tests for the note-taking system module."""

import time
import pytest
from unittest.mock import MagicMock

from app.core.engagement_database import EngagementDatabase
from app.core.note_system import NoteSystem


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
def note_system(engagement_db):
    """Create a NoteSystem instance attached to a test database."""
    ns = NoteSystem()
    ns.set_database(engagement_db)
    return ns


class TestNoteSystemSetup:
    """Tests for NoteSystem initialization and database attachment."""

    def test_set_database_attaches_db(self, engagement_db):
        """set_database() should attach the database."""
        ns = NoteSystem()
        assert ns.database is None

        ns.set_database(engagement_db)
        assert ns.database is engagement_db

    def test_set_database_requires_connected_db(self, tmp_path):
        """set_database() should raise if db is not connected."""
        db_path = str(tmp_path / "engagement.db")
        db = EngagementDatabase(db_path)

        ns = NoteSystem()
        with pytest.raises(RuntimeError, match="must be connected"):
            ns.set_database(db)

    def test_set_database_creates_fts_table(self, engagement_db):
        """set_database() should create the notes_fts virtual table."""
        ns = NoteSystem()
        ns.set_database(engagement_db)

        tables = engagement_db.execute_query(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='notes_fts'"
        )
        assert len(tables) == 1
        assert tables[0][0] == "notes_fts"

    def test_operations_require_database(self):
        """Operations should raise RuntimeError if no database is attached."""
        ns = NoteSystem()

        with pytest.raises(RuntimeError, match="No database attached"):
            ns.create_note("target", 1, "content")

        with pytest.raises(RuntimeError, match="No database attached"):
            ns.get_notes_for_scope("target", 1)

        with pytest.raises(RuntimeError, match="No database attached"):
            ns.search_notes("query")


class TestNoteCreation:
    """Tests for creating notes."""

    def test_create_note_returns_id(self, note_system):
        """create_note() should return the note ID."""
        note_id = note_system.create_note("target", 1, "Test note content")
        assert isinstance(note_id, int)
        assert note_id > 0

    def test_create_note_stores_content(self, note_system):
        """Created note should be retrievable with correct content."""
        note_id = note_system.create_note(
            "target", 1, "# Hello\n\nThis is a **markdown** note.", "alice"
        )
        note = note_system.get_note(note_id)

        assert note["id"] == note_id
        assert note["scope_type"] == "target"
        assert note["scope_id"] == 1
        assert note["content"] == "# Hello\n\nThis is a **markdown** note."
        assert note["content_format"] == "markdown"
        assert note["author"] == "alice"
        assert note["pinned"] is False
        assert note["created_at"] is not None
        assert note["updated_at"] is not None

    def test_create_note_valid_scope_types(self, note_system):
        """Notes can be created for all valid scope types."""
        for scope_type in ("target", "service", "vulnerability"):
            note_id = note_system.create_note(scope_type, 1, f"Note for {scope_type}")
            note = note_system.get_note(note_id)
            assert note["scope_type"] == scope_type

    def test_create_note_invalid_scope_type_raises(self, note_system):
        """create_note() should raise ValueError for invalid scope type."""
        with pytest.raises(ValueError, match="Invalid scope_type"):
            note_system.create_note("invalid_scope", 1, "content")

    def test_create_note_empty_content_raises(self, note_system):
        """create_note() should raise ValueError for empty content."""
        with pytest.raises(ValueError, match="cannot be empty"):
            note_system.create_note("target", 1, "")

        with pytest.raises(ValueError, match="cannot be empty"):
            note_system.create_note("target", 1, "   ")

    def test_create_note_emits_signal(self, note_system):
        """create_note() should emit note_created signal."""
        handler = MagicMock()
        note_system.note_created.connect(handler)

        note_id = note_system.create_note("target", 1, "signal test")
        handler.assert_called_once_with(note_id)

    def test_create_note_defaults_markdown_format(self, note_system):
        """Notes default to markdown content_format."""
        note_id = note_system.create_note("target", 1, "content")
        note = note_system.get_note(note_id)
        assert note["content_format"] == "markdown"

    def test_create_note_supports_markdown_content(self, note_system):
        """Notes should preserve markdown formatting."""
        md_content = (
            "# Heading\n\n"
            "- **Bold** item\n"
            "- *Italic* item\n"
            "- `code inline`\n\n"
            "```python\nprint('hello')\n```\n\n"
            "[Link](https://example.com)"
        )
        note_id = note_system.create_note("target", 1, md_content)
        note = note_system.get_note(note_id)
        assert note["content"] == md_content


class TestNoteEditing:
    """Tests for editing notes with revision preservation."""

    def test_edit_note_updates_content(self, note_system):
        """edit_note() should update the note content."""
        note_id = note_system.create_note("target", 1, "Original content")
        note_system.edit_note(note_id, "Updated content")

        note = note_system.get_note(note_id)
        assert note["content"] == "Updated content"

    def test_edit_note_preserves_old_content_as_revision(self, note_system):
        """edit_note() should store old content in note_revisions."""
        note_id = note_system.create_note("target", 1, "Version 1")
        note_system.edit_note(note_id, "Version 2")

        revisions = note_system.get_revisions(note_id)
        assert len(revisions) == 1
        assert revisions[0]["content"] == "Version 1"
        assert revisions[0]["note_id"] == note_id
        assert revisions[0]["revised_at"] is not None

    def test_edit_note_multiple_revisions(self, note_system):
        """Multiple edits should create multiple revisions in order."""
        note_id = note_system.create_note("target", 1, "V1")
        note_system.edit_note(note_id, "V2")
        note_system.edit_note(note_id, "V3")
        note_system.edit_note(note_id, "V4")

        note = note_system.get_note(note_id)
        assert note["content"] == "V4"

        revisions = note_system.get_revisions(note_id)
        assert len(revisions) == 3
        assert revisions[0]["content"] == "V1"
        assert revisions[1]["content"] == "V2"
        assert revisions[2]["content"] == "V3"

    def test_edit_note_updates_timestamp(self, note_system):
        """edit_note() should update the updated_at timestamp."""
        note_id = note_system.create_note("target", 1, "Original")
        original_note = note_system.get_note(note_id)
        original_updated = original_note["updated_at"]

        # Small delay to ensure timestamp difference
        time.sleep(0.01)
        note_system.edit_note(note_id, "Edited")

        edited_note = note_system.get_note(note_id)
        assert edited_note["updated_at"] >= original_updated

    def test_edit_note_nonexistent_raises(self, note_system):
        """edit_note() should raise ValueError for non-existent note."""
        with pytest.raises(ValueError, match="does not exist"):
            note_system.edit_note(9999, "New content")

    def test_edit_note_empty_content_raises(self, note_system):
        """edit_note() should raise ValueError for empty content."""
        note_id = note_system.create_note("target", 1, "Original")
        with pytest.raises(ValueError, match="cannot be empty"):
            note_system.edit_note(note_id, "")

    def test_edit_note_emits_signal(self, note_system):
        """edit_note() should emit note_edited signal."""
        handler = MagicMock()
        note_system.note_edited.connect(handler)

        note_id = note_system.create_note("target", 1, "Original")
        note_system.edit_note(note_id, "Edited")

        handler.assert_called_once_with(note_id)


class TestNoteRetrieval:
    """Tests for retrieving notes with proper ordering."""

    def test_get_notes_for_scope_empty(self, note_system):
        """get_notes_for_scope() should return empty list when no notes."""
        notes = note_system.get_notes_for_scope("target", 999)
        assert notes == []

    def test_get_notes_for_scope_chronological_order(self, note_system):
        """Notes should be returned in chronological order (created_at ASC)."""
        id1 = note_system.create_note("target", 1, "First note")
        id2 = note_system.create_note("target", 1, "Second note")
        id3 = note_system.create_note("target", 1, "Third note")

        notes = note_system.get_notes_for_scope("target", 1)
        assert len(notes) == 3
        assert notes[0]["id"] == id1
        assert notes[1]["id"] == id2
        assert notes[2]["id"] == id3

    def test_get_notes_for_scope_pinned_first(self, note_system):
        """Pinned notes should appear before unpinned, each group chronological."""
        id1 = note_system.create_note("target", 1, "First (unpinned)")
        id2 = note_system.create_note("target", 1, "Second (will pin)")
        id3 = note_system.create_note("target", 1, "Third (unpinned)")

        note_system.pin_note(id2)

        notes = note_system.get_notes_for_scope("target", 1)
        assert len(notes) == 3
        # Pinned first
        assert notes[0]["id"] == id2
        assert notes[0]["pinned"] is True
        # Then chronological unpinned
        assert notes[1]["id"] == id1
        assert notes[1]["pinned"] is False
        assert notes[2]["id"] == id3
        assert notes[2]["pinned"] is False

    def test_get_notes_for_scope_filters_by_scope(self, note_system):
        """Only notes matching scope_type and scope_id should be returned."""
        note_system.create_note("target", 1, "Target 1 note")
        note_system.create_note("target", 2, "Target 2 note")
        note_system.create_note("service", 1, "Service 1 note")

        target1_notes = note_system.get_notes_for_scope("target", 1)
        assert len(target1_notes) == 1
        assert target1_notes[0]["content"] == "Target 1 note"

        service_notes = note_system.get_notes_for_scope("service", 1)
        assert len(service_notes) == 1
        assert service_notes[0]["content"] == "Service 1 note"

    def test_get_notes_for_scope_invalid_scope_raises(self, note_system):
        """get_notes_for_scope() should raise ValueError for invalid scope."""
        with pytest.raises(ValueError, match="Invalid scope_type"):
            note_system.get_notes_for_scope("invalid", 1)

    def test_get_note_nonexistent_returns_none(self, note_system):
        """get_note() should return None for non-existent ID."""
        assert note_system.get_note(9999) is None


class TestNoteSearch:
    """Tests for FTS5 full-text search."""

    def test_search_notes_finds_matching_content(self, note_system):
        """search_notes() should find notes containing the search term."""
        note_system.create_note("target", 1, "The server has a SQL injection vulnerability")
        note_system.create_note("target", 2, "SSH port is open on the target")
        note_system.create_note("service", 1, "Authentication bypass found")

        results = note_system.search_notes("SQL injection")
        assert len(results) == 1
        assert "SQL injection" in results[0]["content"]

    def test_search_notes_multiple_results(self, note_system):
        """search_notes() should return all matching notes."""
        note_system.create_note("target", 1, "Found open port 22 SSH")
        note_system.create_note("target", 2, "Port 80 is open HTTP")
        note_system.create_note("service", 1, "Closed for maintenance")

        results = note_system.search_notes("open")
        assert len(results) == 2

    def test_search_notes_no_results(self, note_system):
        """search_notes() should return empty list when nothing matches."""
        note_system.create_note("target", 1, "Hello world")
        results = note_system.search_notes("nonexistent_term_xyz")
        assert results == []

    def test_search_notes_empty_query_raises(self, note_system):
        """search_notes() should raise ValueError for empty query."""
        with pytest.raises(ValueError, match="cannot be empty"):
            note_system.search_notes("")

        with pytest.raises(ValueError, match="cannot be empty"):
            note_system.search_notes("   ")

    def test_search_notes_finds_edited_content(self, note_system):
        """search_notes() should find notes by their current (edited) content."""
        note_id = note_system.create_note("target", 1, "Original boring content")
        note_system.edit_note(note_id, "Updated with critical vulnerability info")

        results = note_system.search_notes("critical vulnerability")
        assert len(results) == 1
        assert results[0]["id"] == note_id

    def test_search_notes_does_not_find_old_revision_content(self, note_system):
        """search_notes() should NOT find notes by their old revision content."""
        note_id = note_system.create_note("target", 1, "uniquewordxyz in original")
        note_system.edit_note(note_id, "Completely different content now")

        results = note_system.search_notes("uniquewordxyz")
        assert len(results) == 0


class TestNotePinning:
    """Tests for pin/unpin functionality."""

    def test_pin_note(self, note_system):
        """pin_note() should set pinned to True."""
        note_id = note_system.create_note("target", 1, "Pin me")
        note_system.pin_note(note_id)

        note = note_system.get_note(note_id)
        assert note["pinned"] is True

    def test_unpin_note(self, note_system):
        """unpin_note() should set pinned to False."""
        note_id = note_system.create_note("target", 1, "Pin then unpin")
        note_system.pin_note(note_id)
        note_system.unpin_note(note_id)

        note = note_system.get_note(note_id)
        assert note["pinned"] is False

    def test_pin_nonexistent_note_raises(self, note_system):
        """pin_note() should raise ValueError for non-existent note."""
        with pytest.raises(ValueError, match="does not exist"):
            note_system.pin_note(9999)

    def test_unpin_nonexistent_note_raises(self, note_system):
        """unpin_note() should raise ValueError for non-existent note."""
        with pytest.raises(ValueError, match="does not exist"):
            note_system.unpin_note(9999)

    def test_pin_emits_signal_true(self, note_system):
        """pin_note() should emit note_pinned(id, True)."""
        handler = MagicMock()
        note_system.note_pinned.connect(handler)

        note_id = note_system.create_note("target", 1, "Pin signal test")
        note_system.pin_note(note_id)

        handler.assert_called_once_with(note_id, True)

    def test_unpin_emits_signal_false(self, note_system):
        """unpin_note() should emit note_pinned(id, False)."""
        handler = MagicMock()
        note_system.note_pinned.connect(handler)

        note_id = note_system.create_note("target", 1, "Unpin signal test")
        note_system.pin_note(note_id)
        handler.reset_mock()

        note_system.unpin_note(note_id)
        handler.assert_called_once_with(note_id, False)

    def test_multiple_pinned_notes_ordering(self, note_system):
        """Multiple pinned notes should appear in chronological order among themselves."""
        id1 = note_system.create_note("target", 1, "First")
        id2 = note_system.create_note("target", 1, "Second")
        id3 = note_system.create_note("target", 1, "Third")

        note_system.pin_note(id3)
        note_system.pin_note(id1)

        notes = note_system.get_notes_for_scope("target", 1)
        # Pinned notes first (id1 created before id3)
        assert notes[0]["id"] == id1
        assert notes[0]["pinned"] is True
        assert notes[1]["id"] == id3
        assert notes[1]["pinned"] is True
        # Then unpinned
        assert notes[2]["id"] == id2
        assert notes[2]["pinned"] is False


class TestNoteDelete:
    """Tests for note deletion."""

    def test_delete_note(self, note_system):
        """delete_note() should remove the note."""
        note_id = note_system.create_note("target", 1, "Delete me")
        note_system.delete_note(note_id)

        assert note_system.get_note(note_id) is None

    def test_delete_note_removes_revisions(self, note_system):
        """delete_note() should also remove associated revisions."""
        note_id = note_system.create_note("target", 1, "V1")
        note_system.edit_note(note_id, "V2")
        note_system.edit_note(note_id, "V3")

        note_system.delete_note(note_id)

        revisions = note_system.get_revisions(note_id)
        assert revisions == []

    def test_delete_nonexistent_note_raises(self, note_system):
        """delete_note() should raise ValueError for non-existent note."""
        with pytest.raises(ValueError, match="does not exist"):
            note_system.delete_note(9999)
