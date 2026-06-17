# app/core/engagement_manager.py
"""Engagement lifecycle management with state machine and DB isolation.

The EngagementManager is the central coordinator for engagement lifecycles.
It manages the master index database (tracking all engagements), creates
isolated per-engagement databases, enforces the state machine transitions,
and provides CRUD operations for engagement-scoped data (documents,
contacts, rules of engagement, milestones).
"""

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

from PyQt6.QtCore import QObject, pyqtSignal

from app.core.database_pool import DatabaseConnectionPool
from app.core.engagement_database import EngagementDatabase
from app.core.logger import logger


# ---------------------------------------------------------------------------
# State Machine
# ---------------------------------------------------------------------------

class EngagementState(Enum):
    """Engagement lifecycle states."""
    DRAFT = "draft"
    SCOPING = "scoping"
    ACTIVE = "active"
    PAUSED = "paused"
    RETEST = "retest"
    REPORTING = "reporting"
    CLOSED = "closed"


# Valid state transitions enforced by the state machine
VALID_TRANSITIONS: Dict[EngagementState, List[EngagementState]] = {
    EngagementState.DRAFT: [EngagementState.SCOPING],
    EngagementState.SCOPING: [EngagementState.ACTIVE],
    EngagementState.ACTIVE: [
        EngagementState.PAUSED,
        EngagementState.RETEST,
        EngagementState.REPORTING,
    ],
    EngagementState.PAUSED: [EngagementState.ACTIVE, EngagementState.CLOSED],
    EngagementState.RETEST: [EngagementState.REPORTING, EngagementState.ACTIVE],
    EngagementState.REPORTING: [EngagementState.CLOSED, EngagementState.RETEST],
    EngagementState.CLOSED: [],
}


# ---------------------------------------------------------------------------
# Master Index Schema
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

CREATE TABLE IF NOT EXISTS engagement_state_transitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL,
    from_state TEXT NOT NULL,
    to_state TEXT NOT NULL,
    transitioned_at TEXT NOT NULL,
    actor TEXT,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
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

CREATE INDEX IF NOT EXISTS idx_engagements_status ON engagements(status);
CREATE INDEX IF NOT EXISTS idx_engagements_client ON engagements(client_name);
CREATE INDEX IF NOT EXISTS idx_state_transitions_engagement ON engagement_state_transitions(engagement_id);
CREATE INDEX IF NOT EXISTS idx_scheduled_scans_engagement ON scheduled_scans(engagement_id);
CREATE INDEX IF NOT EXISTS idx_scheduled_scans_status ON scheduled_scans(status);
"""


# ---------------------------------------------------------------------------
# EngagementManager
# ---------------------------------------------------------------------------

class EngagementManager(QObject):
    """Manages engagement lifecycle, state machine, and database isolation.

    Signals:
        engagement_created(str): Emitted with the engagement_id when created.
        engagement_opened(str): Emitted with the engagement_id when opened.
        state_changed(str, str, str): Emitted with (engagement_id, old_state, new_state).
    """

    engagement_created = pyqtSignal(str)
    engagement_opened = pyqtSignal(str)
    state_changed = pyqtSignal(str, str, str)

    def __init__(self, master_db_path: Optional[str] = None):
        """Initialize the EngagementManager.

        Args:
            master_db_path: Path to the master index database. If None,
                defaults to resources/huginn_master_index.db relative to
                the project root.
        """
        super().__init__()

        if master_db_path is None:
            project_root = Path(__file__).resolve().parent.parent.parent
            master_db_path = str(project_root / "resources" / "huginn_master_index.db")

        self._master_db_path = master_db_path
        self._engagements_base: str = str(Path(master_db_path).parent / "engagements")

        # Ensure directories exist
        Path(self._master_db_path).parent.mkdir(parents=True, exist_ok=True)
        Path(self._engagements_base).mkdir(parents=True, exist_ok=True)

        # Initialize master index pool and schema
        self._master_pool = DatabaseConnectionPool(self._master_db_path, pool_size=5)
        self._init_master_schema()

        # Active engagement state
        self.active_engagement_id: Optional[str] = None
        self.active_db: Optional[EngagementDatabase] = None

    @property
    def master_db_path(self) -> str:
        """Path to the master index database."""
        return self._master_db_path

    # ------------------------------------------------------------------
    # Schema Initialization
    # ------------------------------------------------------------------

    def _init_master_schema(self) -> None:
        """Create master index tables if they don't exist."""
        try:
            with self._master_pool.get_connection() as conn:
                conn.executescript(MASTER_INDEX_SCHEMA)
                conn.commit()
            logger.info("Master index schema initialized.")
        except sqlite3.Error as e:
            logger.error(f"Failed to initialize master index schema: {e}")
            raise

    # ------------------------------------------------------------------
    # Engagement CRUD
    # ------------------------------------------------------------------

    def create_engagement(
        self,
        name: str,
        client_name: str,
        engagement_type: str,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
    ) -> str:
        """Create a new engagement with an isolated database.

        Args:
            name: Engagement name.
            client_name: Client organization name.
            engagement_type: Type (internal, external, web, mobile, physical, cloud).
            start_date: ISO date string for planned start.
            end_date: ISO date string for planned end.

        Returns:
            The generated engagement UUID.
        """
        engagement_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        # Relative DB path for portability
        relative_db_path = f"engagements/{engagement_id}/engagement.db"
        absolute_db_path = str(Path(self._engagements_base) / engagement_id / "engagement.db")

        # Create engagement directory structure
        eng_dir = Path(self._engagements_base) / engagement_id
        eng_dir.mkdir(parents=True, exist_ok=True)
        (eng_dir / "evidence").mkdir(exist_ok=True)
        (eng_dir / "documents").mkdir(exist_ok=True)

        # Create and initialize the engagement database
        eng_db = EngagementDatabase(absolute_db_path)
        eng_db.connect()
        eng_db.create_schema()
        eng_db.close()

        # Record in master index
        with self._master_pool.get_connection() as conn:
            conn.execute(
                """INSERT INTO engagements
                   (id, name, client_name, engagement_type, status,
                    start_date, end_date, db_path, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    engagement_id,
                    name,
                    client_name,
                    engagement_type,
                    EngagementState.DRAFT.value,
                    start_date,
                    end_date,
                    relative_db_path,
                    now,
                    now,
                ),
            )
            conn.commit()

        logger.info(f"Engagement created: {engagement_id} ({name})")
        self.engagement_created.emit(engagement_id)
        return engagement_id

    def open_engagement(self, engagement_id: str) -> bool:
        """Open an engagement and connect to its isolated database.

        Args:
            engagement_id: UUID of the engagement to open.

        Returns:
            True if successful, False otherwise.
        """
        # Close any currently open engagement
        if self.active_db is not None:
            self.active_db.close()
            self.active_db = None
            self.active_engagement_id = None

        # Look up engagement in master index
        rows = self._master_pool.execute_query(
            "SELECT db_path FROM engagements WHERE id = ?", (engagement_id,)
        )
        if not rows:
            logger.error(f"Engagement not found: {engagement_id}")
            return False

        relative_db_path = rows[0][0]
        absolute_db_path = str(Path(self._master_db_path).parent / relative_db_path)

        if not Path(absolute_db_path).exists():
            logger.error(f"Engagement database file not found: {absolute_db_path}")
            return False

        # Connect to the engagement database
        eng_db = EngagementDatabase(absolute_db_path)
        eng_db.connect()

        self.active_engagement_id = engagement_id
        self.active_db = eng_db

        logger.info(f"Engagement opened: {engagement_id}")
        self.engagement_opened.emit(engagement_id)
        return True

    def close_engagement(self) -> None:
        """Close the currently active engagement."""
        if self.active_db is not None:
            self.active_db.close()
            self.active_db = None
            self.active_engagement_id = None
            logger.info("Active engagement closed.")

    def get_engagement(self, engagement_id: str) -> Optional[Dict]:
        """Get engagement metadata from the master index.

        Returns:
            Dict with engagement metadata or None if not found.
        """
        rows = self._master_pool.execute_query(
            """SELECT id, name, client_name, engagement_type, status,
                      start_date, end_date, db_path, created_at, updated_at
               FROM engagements WHERE id = ?""",
            (engagement_id,),
        )
        if not rows:
            return None
        row = rows[0]
        return {
            "id": row[0],
            "name": row[1],
            "client_name": row[2],
            "engagement_type": row[3],
            "status": row[4],
            "start_date": row[5],
            "end_date": row[6],
            "db_path": row[7],
            "created_at": row[8],
            "updated_at": row[9],
        }

    def list_engagements(
        self,
        status_filter: Optional[str] = None,
        search_query: Optional[str] = None,
    ) -> List[Dict]:
        """List engagements from the master index with optional filtering.

        Args:
            status_filter: Filter by status value (e.g. 'active', 'draft').
            search_query: Search in name and client_name fields.

        Returns:
            List of engagement metadata dicts.
        """
        query = """SELECT id, name, client_name, engagement_type, status,
                          start_date, end_date, db_path, created_at, updated_at
                   FROM engagements WHERE 1=1"""
        params: list = []

        if status_filter:
            query += " AND status = ?"
            params.append(status_filter)

        if search_query:
            query += " AND (name LIKE ? OR client_name LIKE ?)"
            like_term = f"%{search_query}%"
            params.append(like_term)
            params.append(like_term)

        query += " ORDER BY updated_at DESC"

        rows = self._master_pool.execute_query(query, tuple(params))
        results = []
        for row in rows:
            results.append({
                "id": row[0],
                "name": row[1],
                "client_name": row[2],
                "engagement_type": row[3],
                "status": row[4],
                "start_date": row[5],
                "end_date": row[6],
                "db_path": row[7],
                "created_at": row[8],
                "updated_at": row[9],
            })
        return results

    # ------------------------------------------------------------------
    # State Machine
    # ------------------------------------------------------------------

    def get_current_state(self, engagement_id: str) -> Optional[EngagementState]:
        """Get the current state of an engagement.

        Returns:
            EngagementState or None if engagement not found.
        """
        rows = self._master_pool.execute_query(
            "SELECT status FROM engagements WHERE id = ?", (engagement_id,)
        )
        if not rows:
            return None
        try:
            return EngagementState(rows[0][0])
        except ValueError:
            return None

    def transition_state(
        self,
        engagement_id: str,
        new_state: EngagementState,
        actor: Optional[str] = None,
    ) -> bool:
        """Validate and apply a state transition.

        Args:
            engagement_id: UUID of the engagement.
            new_state: Target state.
            actor: Who triggered the transition (username, system, etc.).

        Returns:
            True if the transition was valid and applied, False otherwise.
        """
        current_state = self.get_current_state(engagement_id)
        if current_state is None:
            logger.error(f"Cannot transition state: engagement {engagement_id} not found.")
            return False

        # Validate transition
        allowed = VALID_TRANSITIONS.get(current_state, [])
        if new_state not in allowed:
            logger.warning(
                f"Invalid state transition for {engagement_id}: "
                f"{current_state.value} -> {new_state.value}. "
                f"Allowed: {[s.value for s in allowed]}"
            )
            return False

        now = datetime.now(timezone.utc).isoformat()

        with self._master_pool.get_connection() as conn:
            # Update engagement status
            conn.execute(
                "UPDATE engagements SET status = ?, updated_at = ? WHERE id = ?",
                (new_state.value, now, engagement_id),
            )
            # Record transition history
            conn.execute(
                """INSERT INTO engagement_state_transitions
                   (engagement_id, from_state, to_state, transitioned_at, actor)
                   VALUES (?, ?, ?, ?, ?)""",
                (engagement_id, current_state.value, new_state.value, now, actor),
            )
            conn.commit()

        logger.info(
            f"State transition: {engagement_id} "
            f"{current_state.value} -> {new_state.value}"
        )
        self.state_changed.emit(engagement_id, current_state.value, new_state.value)
        return True

    def get_state_history(self, engagement_id: str) -> List[Dict]:
        """Get the full state transition history for an engagement.

        Returns:
            List of transition records ordered chronologically.
        """
        rows = self._master_pool.execute_query(
            """SELECT from_state, to_state, transitioned_at, actor
               FROM engagement_state_transitions
               WHERE engagement_id = ?
               ORDER BY transitioned_at ASC""",
            (engagement_id,),
        )
        return [
            {
                "from_state": row[0],
                "to_state": row[1],
                "transitioned_at": row[2],
                "actor": row[3],
            }
            for row in rows
        ]


    # ------------------------------------------------------------------
    # Document CRUD (requires active engagement)
    # ------------------------------------------------------------------

    def _require_active_db(self) -> EngagementDatabase:
        """Ensure an engagement is open and return its database.

        Raises:
            RuntimeError: If no engagement is currently open.
        """
        if self.active_db is None:
            raise RuntimeError("No engagement is currently open.")
        return self.active_db

    def add_document(
        self,
        filename: str,
        document_type: str,
        content: bytes,
        mime_type: Optional[str] = None,
        metadata: Optional[Dict] = None,
    ) -> int:
        """Store a document in the active engagement.

        Args:
            filename: Original filename.
            document_type: Type (scope, roe, sow, nda, other).
            content: Raw file content as bytes.
            mime_type: MIME type string.
            metadata: Additional JSON-serializable metadata.

        Returns:
            The document row ID.
        """
        db = self._require_active_db()
        now = datetime.now(timezone.utc).isoformat()
        meta_json = json.dumps(metadata) if metadata else None

        row_id = db.execute_write(
            """INSERT INTO documents (filename, document_type, content, mime_type, upload_date, metadata)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (filename, document_type, content, mime_type, now, meta_json),
        )
        logger.debug(f"Document added: {filename} (type={document_type})")
        return row_id

    def get_documents(self, document_type: Optional[str] = None) -> List[Dict]:
        """List documents in the active engagement.

        Args:
            document_type: Optional filter by type.

        Returns:
            List of document metadata dicts (content excluded for efficiency).
        """
        db = self._require_active_db()
        query = "SELECT id, filename, document_type, mime_type, upload_date, metadata FROM documents"
        params: tuple = ()
        if document_type:
            query += " WHERE document_type = ?"
            params = (document_type,)
        query += " ORDER BY upload_date DESC"

        rows = db.execute_query(query, params)
        return [
            {
                "id": row[0],
                "filename": row[1],
                "document_type": row[2],
                "mime_type": row[3],
                "upload_date": row[4],
                "metadata": json.loads(row[5]) if row[5] else None,
            }
            for row in rows
        ]

    def get_document_content(self, document_id: int) -> Optional[bytes]:
        """Retrieve document content by ID.

        Returns:
            Raw document bytes or None if not found.
        """
        db = self._require_active_db()
        rows = db.execute_query(
            "SELECT content FROM documents WHERE id = ?", (document_id,)
        )
        return rows[0][0] if rows else None

    def delete_document(self, document_id: int) -> bool:
        """Delete a document from the active engagement.

        Returns:
            True if a row was deleted.
        """
        db = self._require_active_db()
        affected = db.execute_write("DELETE FROM documents WHERE id = ?", (document_id,))
        return affected > 0

    # ------------------------------------------------------------------
    # Client Contacts CRUD
    # ------------------------------------------------------------------

    def add_contact(
        self,
        name: str,
        role: Optional[str] = None,
        email: Optional[str] = None,
        phone: Optional[str] = None,
        availability_window: Optional[Dict] = None,
    ) -> int:
        """Add a client contact to the active engagement.

        Returns:
            The contact row ID.
        """
        db = self._require_active_db()
        now = datetime.now(timezone.utc).isoformat()
        avail_json = json.dumps(availability_window) if availability_window else None

        row_id = db.execute_write(
            """INSERT INTO client_contacts (name, role, email, phone, availability_window, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (name, role, email, phone, avail_json, now),
        )
        logger.debug(f"Contact added: {name} ({role})")
        return row_id

    def get_contacts(self) -> List[Dict]:
        """List all client contacts in the active engagement."""
        db = self._require_active_db()
        rows = db.execute_query(
            "SELECT id, name, role, email, phone, availability_window, created_at FROM client_contacts ORDER BY name"
        )
        return [
            {
                "id": row[0],
                "name": row[1],
                "role": row[2],
                "email": row[3],
                "phone": row[4],
                "availability_window": json.loads(row[5]) if row[5] else None,
                "created_at": row[6],
            }
            for row in rows
        ]

    def update_contact(self, contact_id: int, **fields) -> bool:
        """Update a client contact's fields.

        Supported fields: name, role, email, phone, availability_window.

        Returns:
            True if the contact was updated.
        """
        db = self._require_active_db()
        allowed_fields = {"name", "role", "email", "phone", "availability_window"}
        updates = []
        params = []
        for key, value in fields.items():
            if key not in allowed_fields:
                continue
            if key == "availability_window" and value is not None:
                value = json.dumps(value)
            updates.append(f"{key} = ?")
            params.append(value)

        if not updates:
            return False

        params.append(contact_id)
        query = f"UPDATE client_contacts SET {', '.join(updates)} WHERE id = ?"
        affected = db.execute_write(query, tuple(params))
        return affected > 0

    def delete_contact(self, contact_id: int) -> bool:
        """Delete a client contact.

        Returns:
            True if a row was deleted.
        """
        db = self._require_active_db()
        affected = db.execute_write("DELETE FROM client_contacts WHERE id = ?", (contact_id,))
        return affected > 0

    # ------------------------------------------------------------------
    # Rules of Engagement CRUD
    # ------------------------------------------------------------------

    def set_rules_of_engagement(
        self,
        authorized_ip_ranges: Optional[List[str]] = None,
        excluded_systems: Optional[List[str]] = None,
        testing_hours: Optional[Dict] = None,
        emergency_contacts: Optional[List[Dict]] = None,
        escalation_procedures: Optional[str] = None,
        custom_rules: Optional[str] = None,
    ) -> int:
        """Set or update rules of engagement for the active engagement.

        This creates a new RoE record (or updates existing). Only one
        active RoE record is expected per engagement.

        Returns:
            The RoE row ID.
        """
        db = self._require_active_db()
        now = datetime.now(timezone.utc).isoformat()

        # Check if RoE already exists
        existing = db.execute_query("SELECT id FROM rules_of_engagement LIMIT 1")

        ip_json = json.dumps(authorized_ip_ranges) if authorized_ip_ranges else None
        excluded_json = json.dumps(excluded_systems) if excluded_systems else None
        hours_json = json.dumps(testing_hours) if testing_hours else None
        contacts_json = json.dumps(emergency_contacts) if emergency_contacts else None

        if existing:
            roe_id = existing[0][0]
            db.execute_write(
                """UPDATE rules_of_engagement
                   SET authorized_ip_ranges = ?, excluded_systems = ?,
                       testing_hours = ?, emergency_contacts = ?,
                       escalation_procedures = ?, custom_rules = ?, updated_at = ?
                   WHERE id = ?""",
                (
                    ip_json, excluded_json, hours_json, contacts_json,
                    escalation_procedures, custom_rules, now, roe_id,
                ),
            )
            return roe_id
        else:
            row_id = db.execute_write(
                """INSERT INTO rules_of_engagement
                   (authorized_ip_ranges, excluded_systems, testing_hours,
                    emergency_contacts, escalation_procedures, custom_rules, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    ip_json, excluded_json, hours_json, contacts_json,
                    escalation_procedures, custom_rules, now,
                ),
            )
            return row_id

    def get_rules_of_engagement(self) -> Optional[Dict]:
        """Get the rules of engagement for the active engagement.

        Returns:
            Dict with RoE fields or None if not set.
        """
        db = self._require_active_db()
        rows = db.execute_query(
            """SELECT id, authorized_ip_ranges, excluded_systems, testing_hours,
                      emergency_contacts, escalation_procedures, custom_rules, updated_at
               FROM rules_of_engagement LIMIT 1"""
        )
        if not rows:
            return None
        row = rows[0]
        return {
            "id": row[0],
            "authorized_ip_ranges": json.loads(row[1]) if row[1] else None,
            "excluded_systems": json.loads(row[2]) if row[2] else None,
            "testing_hours": json.loads(row[3]) if row[3] else None,
            "emergency_contacts": json.loads(row[4]) if row[4] else None,
            "escalation_procedures": row[5],
            "custom_rules": row[6],
            "updated_at": row[7],
        }

    # ------------------------------------------------------------------
    # Milestones CRUD
    # ------------------------------------------------------------------

    def add_milestone(
        self,
        name: str,
        milestone_type: str,
        date: str,
        notes: Optional[str] = None,
    ) -> int:
        """Add a timeline milestone to the active engagement.

        Args:
            name: Milestone name.
            milestone_type: Type (planned_start, actual_start, planned_end, actual_end, checkpoint).
            date: ISO date string.
            notes: Optional notes.

        Returns:
            The milestone row ID.
        """
        db = self._require_active_db()
        row_id = db.execute_write(
            """INSERT INTO milestones (name, milestone_type, date, notes)
               VALUES (?, ?, ?, ?)""",
            (name, milestone_type, date, notes),
        )
        logger.debug(f"Milestone added: {name} ({milestone_type})")
        return row_id

    def get_milestones(self) -> List[Dict]:
        """List all milestones in the active engagement."""
        db = self._require_active_db()
        rows = db.execute_query(
            "SELECT id, name, milestone_type, date, notes FROM milestones ORDER BY date ASC"
        )
        return [
            {
                "id": row[0],
                "name": row[1],
                "milestone_type": row[2],
                "date": row[3],
                "notes": row[4],
            }
            for row in rows
        ]

    def update_milestone(self, milestone_id: int, **fields) -> bool:
        """Update a milestone's fields.

        Supported fields: name, milestone_type, date, notes.

        Returns:
            True if the milestone was updated.
        """
        db = self._require_active_db()
        allowed_fields = {"name", "milestone_type", "date", "notes"}
        updates = []
        params = []
        for key, value in fields.items():
            if key not in allowed_fields:
                continue
            updates.append(f"{key} = ?")
            params.append(value)

        if not updates:
            return False

        params.append(milestone_id)
        query = f"UPDATE milestones SET {', '.join(updates)} WHERE id = ?"
        affected = db.execute_write(query, tuple(params))
        return affected > 0

    def delete_milestone(self, milestone_id: int) -> bool:
        """Delete a milestone.

        Returns:
            True if a row was deleted.
        """
        db = self._require_active_db()
        affected = db.execute_write("DELETE FROM milestones WHERE id = ?", (milestone_id,))
        return affected > 0

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the manager, releasing all resources."""
        self.close_engagement()
        self._master_pool.close_all()
        logger.info("EngagementManager closed.")
