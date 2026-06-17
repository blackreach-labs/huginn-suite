# app/core/note_system.py
"""Inline note-taking system with scoped notes, revisions, and full-text search.

The NoteSystem supports per-target, per-service, and per-vulnerability notes
with timestamps, revision history, pinning, and FTS5 full-text search. Notes
use markdown content format by default and are stored in the per-engagement
database.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional

from PyQt6.QtCore import QObject, pyqtSignal

from app.core.engagement_database import EngagementDatabase
from app.core.logger import logger


# FTS5 virtual table for full-text note search
NOTES_FTS_SCHEMA = """
CREATE VIRTUAL TABLE IF NOT EXISTS notes_fts USING fts5(
    content,
    content=notes,
    content_rowid=id
);
"""

# Triggers to keep FTS index synchronized with notes table
NOTES_FTS_TRIGGERS = """
CREATE TRIGGER IF NOT EXISTS notes_ai AFTER INSERT ON notes BEGIN
    INSERT INTO notes_fts(rowid, content) VALUES (new.id, new.content);
END;

CREATE TRIGGER IF NOT EXISTS notes_ad AFTER DELETE ON notes BEGIN
    INSERT INTO notes_fts(notes_fts, rowid, content) VALUES ('delete', old.id, old.content);
END;

CREATE TRIGGER IF NOT EXISTS notes_au AFTER UPDATE ON notes BEGIN
    INSERT INTO notes_fts(notes_fts, rowid, content) VALUES ('delete', old.id, old.content);
    INSERT INTO notes_fts(rowid, content) VALUES (new.id, new.content);
END;
"""


class NoteSystem(QObject):
    """Scoped note-taking engine with revision tracking and full-text search.

    Notes can be attached at three scopes:
      - target: target-level observations
      - service: service-level observations
      - vulnerability: vulnerability-level observations

    Each note stores its content in markdown format, tracks creation and
    update timestamps, and preserves edit history as revisions. Notes can
    be pinned for priority display.

    Signals:
        note_created(int): Emitted with note ID when a note is created.
        note_edited(int): Emitted with note ID when a note is edited.
        note_pinned(int, bool): Emitted with note ID and pin state on pin/unpin.
    """

    note_created = pyqtSignal(int)
    note_edited = pyqtSignal(int)
    note_pinned = pyqtSignal(int, bool)

    VALID_SCOPE_TYPES = ("target", "service", "vulnerability")

    def __init__(self, parent=None):
        """Initialize the NoteSystem.

        Args:
            parent: Optional QObject parent.
        """
        super().__init__(parent)
        self._db: Optional[EngagementDatabase] = None

    @property
    def database(self) -> Optional[EngagementDatabase]:
        """The currently attached engagement database."""
        return self._db

    def set_database(self, db: EngagementDatabase) -> None:
        """Attach an engagement database and initialize FTS5 index.

        Creates the FTS5 virtual table and synchronization triggers if they
        don't already exist. Also rebuilds the FTS index to sync with any
        existing notes data.

        Args:
            db: An EngagementDatabase instance that is already connected
                with schema created.

        Raises:
            RuntimeError: If the database is not connected.
        """
        if not db.connected:
            raise RuntimeError("Database must be connected before attaching to NoteSystem.")

        self._db = db
        self._initialize_fts()
        logger.info("NoteSystem: database attached and FTS initialized.")

    def _initialize_fts(self) -> None:
        """Create FTS5 virtual table and triggers, then rebuild index."""
        with self._db.get_connection() as conn:
            # Create FTS virtual table
            conn.executescript(NOTES_FTS_SCHEMA)
            # Create synchronization triggers
            conn.executescript(NOTES_FTS_TRIGGERS)
            # Rebuild FTS index from existing notes data
            conn.execute("INSERT OR IGNORE INTO notes_fts(notes_fts) VALUES ('rebuild')")
            conn.commit()

    def _require_db(self) -> None:
        """Raise if no database is attached."""
        if self._db is None:
            raise RuntimeError("No database attached. Call set_database() first.")

    def create_note(
        self,
        scope_type: str,
        scope_id: int,
        content: str,
        author: Optional[str] = None,
        content_format: str = "markdown",
    ) -> int:
        """Create a new note attached to the given scope.

        Args:
            scope_type: One of 'target', 'service', 'vulnerability'.
            scope_id: The ID of the scoped entity.
            content: The note content (markdown by default).
            author: Optional author identifier.
            content_format: Content format, defaults to 'markdown'.

        Returns:
            The ID of the newly created note.

        Raises:
            RuntimeError: If no database is attached.
            ValueError: If scope_type is invalid or content is empty.
        """
        self._require_db()

        if scope_type not in self.VALID_SCOPE_TYPES:
            raise ValueError(
                f"Invalid scope_type '{scope_type}'. "
                f"Must be one of: {self.VALID_SCOPE_TYPES}"
            )

        if not content or not content.strip():
            raise ValueError("Note content cannot be empty.")

        now = datetime.now(timezone.utc).isoformat()

        note_id = self._db.execute_write(
            """INSERT INTO notes (scope_type, scope_id, content, content_format, author, pinned, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, 0, ?, ?)""",
            (scope_type, scope_id, content, content_format, author, now, now),
        )

        logger.debug(f"NoteSystem: created note {note_id} ({scope_type}/{scope_id})")
        self.note_created.emit(note_id)
        return note_id

    def edit_note(self, note_id: int, new_content: str) -> None:
        """Edit an existing note, preserving the old content as a revision.

        The previous content is saved to note_revisions before updating the
        note with the new content and updated timestamp.

        Args:
            note_id: The ID of the note to edit.
            new_content: The new content for the note.

        Raises:
            RuntimeError: If no database is attached.
            ValueError: If new_content is empty or note doesn't exist.
        """
        self._require_db()

        if not new_content or not new_content.strip():
            raise ValueError("Note content cannot be empty.")

        # Fetch the current content
        rows = self._db.execute_query(
            "SELECT content FROM notes WHERE id = ?", (note_id,)
        )
        if not rows:
            raise ValueError(f"Note with id {note_id} does not exist.")

        old_content = rows[0][0]
        now = datetime.now(timezone.utc).isoformat()

        # Preserve old content as a revision
        with self._db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO note_revisions (note_id, content, revised_at) VALUES (?, ?, ?)",
                (note_id, old_content, now),
            )
            # Update the note with new content
            cursor.execute(
                "UPDATE notes SET content = ?, updated_at = ? WHERE id = ?",
                (new_content, now, note_id),
            )
            conn.commit()

        logger.debug(f"NoteSystem: edited note {note_id}")
        self.note_edited.emit(note_id)

    def get_notes_for_scope(
        self, scope_type: str, scope_id: int
    ) -> List[Dict]:
        """Get all notes for a given scope, pinned first then chronological.

        Args:
            scope_type: One of 'target', 'service', 'vulnerability'.
            scope_id: The ID of the scoped entity.

        Returns:
            List of note dicts sorted: pinned notes first (chronological),
            then unpinned notes in chronological order.

        Raises:
            RuntimeError: If no database is attached.
            ValueError: If scope_type is invalid.
        """
        self._require_db()

        if scope_type not in self.VALID_SCOPE_TYPES:
            raise ValueError(
                f"Invalid scope_type '{scope_type}'. "
                f"Must be one of: {self.VALID_SCOPE_TYPES}"
            )

        rows = self._db.execute_query(
            """SELECT id, scope_type, scope_id, content, content_format, author, pinned, created_at, updated_at
               FROM notes
               WHERE scope_type = ? AND scope_id = ?
               ORDER BY pinned DESC, created_at ASC""",
            (scope_type, scope_id),
        )

        return [self._row_to_dict(row) for row in rows]

    def get_note(self, note_id: int) -> Optional[Dict]:
        """Get a single note by ID.

        Args:
            note_id: The note ID.

        Returns:
            Note dict or None if not found.
        """
        self._require_db()

        rows = self._db.execute_query(
            """SELECT id, scope_type, scope_id, content, content_format, author, pinned, created_at, updated_at
               FROM notes WHERE id = ?""",
            (note_id,),
        )

        if not rows:
            return None
        return self._row_to_dict(rows[0])

    def get_revisions(self, note_id: int) -> List[Dict]:
        """Get all revisions for a note, ordered by revision time.

        Args:
            note_id: The note ID.

        Returns:
            List of revision dicts with 'id', 'note_id', 'content', 'revised_at'.
        """
        self._require_db()

        rows = self._db.execute_query(
            """SELECT id, note_id, content, revised_at
               FROM note_revisions
               WHERE note_id = ?
               ORDER BY revised_at ASC""",
            (note_id,),
        )

        return [
            {
                "id": row[0],
                "note_id": row[1],
                "content": row[2],
                "revised_at": row[3],
            }
            for row in rows
        ]

    def search_notes(self, query: str) -> List[Dict]:
        """Search notes using FTS5 full-text search.

        Args:
            query: The search query string. Supports FTS5 syntax
                   (e.g., 'word1 AND word2', '"exact phrase"').

        Returns:
            List of matching note dicts ordered by relevance.

        Raises:
            RuntimeError: If no database is attached.
            ValueError: If query is empty.
        """
        self._require_db()

        if not query or not query.strip():
            raise ValueError("Search query cannot be empty.")

        rows = self._db.execute_query(
            """SELECT n.id, n.scope_type, n.scope_id, n.content, n.content_format,
                      n.author, n.pinned, n.created_at, n.updated_at
               FROM notes n
               JOIN notes_fts fts ON n.id = fts.rowid
               WHERE notes_fts MATCH ?
               ORDER BY rank""",
            (query.strip(),),
        )

        return [self._row_to_dict(row) for row in rows]

    def pin_note(self, note_id: int) -> None:
        """Pin a note for priority display at the top of its scope.

        Args:
            note_id: The note ID to pin.

        Raises:
            RuntimeError: If no database is attached.
            ValueError: If note doesn't exist.
        """
        self._require_db()
        self._set_pin_state(note_id, pinned=True)

    def unpin_note(self, note_id: int) -> None:
        """Unpin a note, returning it to normal chronological position.

        Args:
            note_id: The note ID to unpin.

        Raises:
            RuntimeError: If no database is attached.
            ValueError: If note doesn't exist.
        """
        self._require_db()
        self._set_pin_state(note_id, pinned=False)

    def _set_pin_state(self, note_id: int, pinned: bool) -> None:
        """Set the pin state for a note.

        Args:
            note_id: The note ID.
            pinned: True to pin, False to unpin.

        Raises:
            ValueError: If note doesn't exist.
        """
        rows = self._db.execute_query(
            "SELECT id FROM notes WHERE id = ?", (note_id,)
        )
        if not rows:
            raise ValueError(f"Note with id {note_id} does not exist.")

        now = datetime.now(timezone.utc).isoformat()
        self._db.execute_write(
            "UPDATE notes SET pinned = ?, updated_at = ? WHERE id = ?",
            (1 if pinned else 0, now, note_id),
        )

        logger.debug(f"NoteSystem: {'pinned' if pinned else 'unpinned'} note {note_id}")
        self.note_pinned.emit(note_id, pinned)

    def delete_note(self, note_id: int) -> None:
        """Delete a note and its revisions.

        Args:
            note_id: The note ID to delete.

        Raises:
            RuntimeError: If no database is attached.
            ValueError: If note doesn't exist.
        """
        self._require_db()

        rows = self._db.execute_query(
            "SELECT id FROM notes WHERE id = ?", (note_id,)
        )
        if not rows:
            raise ValueError(f"Note with id {note_id} does not exist.")

        with self._db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM note_revisions WHERE note_id = ?", (note_id,))
            cursor.execute("DELETE FROM notes WHERE id = ?", (note_id,))
            conn.commit()

        logger.debug(f"NoteSystem: deleted note {note_id}")

    @staticmethod
    def _row_to_dict(row: tuple) -> Dict:
        """Convert a notes query row to a dictionary.

        Expected column order: id, scope_type, scope_id, content,
        content_format, author, pinned, created_at, updated_at
        """
        return {
            "id": row[0],
            "scope_type": row[1],
            "scope_id": row[2],
            "content": row[3],
            "content_format": row[4],
            "author": row[5],
            "pinned": bool(row[6]),
            "created_at": row[7],
            "updated_at": row[8],
        }
