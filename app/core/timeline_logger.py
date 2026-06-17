# app/core/timeline_logger.py
"""Engagement timeline and activity logging engine.

Records chronological activity entries for all actions taken during an
engagement. Supports automatic logging via signal handlers (scan events,
finding discoveries, state transitions, evidence captures) and manual
entries for user notes. Provides filtered timeline retrieval by date range,
action type, actor, and affected entity.

Integrates with engagement_manager, evidence_manager, and scanner signals
via dedicated handler methods designed to be connected to pyqtSignals.
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from PyQt6.QtCore import QObject, pyqtSignal

from app.core.engagement_database import EngagementDatabase
from app.core.logger import logger


# Valid action types for timeline entries
VALID_ACTION_TYPES = frozenset([
    "scan_start",
    "scan_complete",
    "finding_discovered",
    "exploit_attempt",
    "state_transition",
    "evidence_captured",
    "note_added",
    "finding_modified",
    "manual",
])


class TimelineLogger(QObject):
    """Records and retrieves chronological activity log entries.

    Operates against a per-engagement SQLite database provided via
    set_database(). Each entry captures action_type, actor,
    affected_entity, description, optional metadata JSON, and timestamp.

    Signal handlers are provided to connect to other module signals
    (engagement_manager.state_changed, evidence_manager.evidence_stored, etc.)
    for automatic timeline population.

    Signals:
        event_logged(dict): Emitted after an event is successfully logged,
            containing the full entry dict including the assigned id.
    """

    event_logged = pyqtSignal(dict)

    def __init__(self, parent=None):
        """Initialize the TimelineLogger.

        Args:
            parent: Optional QObject parent.
        """
        super().__init__(parent)
        self._db: Optional[EngagementDatabase] = None

    @property
    def database(self) -> Optional[EngagementDatabase]:
        """The currently connected engagement database."""
        return self._db

    def set_database(self, db: EngagementDatabase) -> None:
        """Set the engagement database to operate against.

        Args:
            db: A connected EngagementDatabase instance.
        """
        self._db = db

    def _require_db(self) -> EngagementDatabase:
        """Return the active database or raise if not set.

        Returns:
            The active EngagementDatabase.

        Raises:
            RuntimeError: If no database has been set.
        """
        if self._db is None:
            raise RuntimeError("No database set. Call set_database() first.")
        return self._db

    # ------------------------------------------------------------------
    # Core logging method
    # ------------------------------------------------------------------

    def log_event(
        self,
        action_type: str,
        description: str,
        actor: Optional[str] = None,
        affected_entity_type: Optional[str] = None,
        affected_entity_id: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
        timestamp: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Record a timeline entry in the engagement database.

        Args:
            action_type: The type of action (must be in VALID_ACTION_TYPES).
            description: Human-readable description of the event.
            actor: Who or what performed the action (e.g., username, system).
            affected_entity_type: Type of affected entity (e.g., 'finding', 'target').
            affected_entity_id: ID of the affected entity.
            metadata: Optional JSON-serializable dict of extra context.
            timestamp: ISO 8601 timestamp string. Defaults to current UTC time.

        Returns:
            Dict containing the full logged entry including the assigned id.

        Raises:
            RuntimeError: If no database is set.
            ValueError: If action_type is not a valid type.
        """
        db = self._require_db()

        if action_type not in VALID_ACTION_TYPES:
            raise ValueError(
                f"Invalid action_type '{action_type}'. "
                f"Must be one of: {sorted(VALID_ACTION_TYPES)}"
            )

        if timestamp is None:
            timestamp = datetime.now(timezone.utc).isoformat()

        metadata_json = json.dumps(metadata) if metadata else None

        entry_id = db.execute_write(
            """INSERT INTO timeline_entries
               (action_type, actor, affected_entity_type, affected_entity_id,
                description, metadata, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                action_type,
                actor,
                affected_entity_type,
                affected_entity_id,
                description,
                metadata_json,
                timestamp,
            ),
        )

        entry = {
            "id": entry_id,
            "action_type": action_type,
            "actor": actor,
            "affected_entity_type": affected_entity_type,
            "affected_entity_id": affected_entity_id,
            "description": description,
            "metadata": metadata,
            "timestamp": timestamp,
        }

        self.event_logged.emit(entry)
        logger.debug(f"Timeline event logged: [{action_type}] {description}")
        return entry

    # ------------------------------------------------------------------
    # Signal handler methods (connect to other modules' signals)
    # ------------------------------------------------------------------

    def log_scan_start(
        self,
        scan_type: str,
        target: str,
        actor: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Log a scan start event.

        Designed to connect to scanner signals like:
            scanner.scan_started.connect(timeline_logger.log_scan_start)

        Args:
            scan_type: Type of scan (e.g., 'port_scan', 'vuln_scan').
            target: The scan target (IP, hostname, URL).
            actor: Who initiated the scan.
            metadata: Additional scan configuration data.

        Returns:
            The logged entry dict.
        """
        description = f"Scan started: {scan_type} against {target}"
        meta = metadata or {}
        meta.update({"scan_type": scan_type, "target": target})
        return self.log_event(
            action_type="scan_start",
            description=description,
            actor=actor,
            affected_entity_type="target",
            metadata=meta,
        )

    def log_scan_complete(
        self,
        scan_type: str,
        target: str,
        results_summary: Optional[str] = None,
        actor: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Log a scan completion event.

        Args:
            scan_type: Type of scan completed.
            target: The scan target.
            results_summary: Brief summary of results (e.g., '5 hosts found').
            actor: Who initiated the scan.
            metadata: Additional results data.

        Returns:
            The logged entry dict.
        """
        description = f"Scan completed: {scan_type} against {target}"
        if results_summary:
            description += f" — {results_summary}"
        meta = metadata or {}
        meta.update({"scan_type": scan_type, "target": target})
        if results_summary:
            meta["results_summary"] = results_summary
        return self.log_event(
            action_type="scan_complete",
            description=description,
            actor=actor,
            affected_entity_type="target",
            metadata=meta,
        )

    def log_finding_discovered(
        self,
        finding_id: int,
        title: str,
        severity: str,
        actor: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Log the discovery of a new finding.

        Args:
            finding_id: The ID of the discovered finding.
            title: Finding title.
            severity: Finding severity level.
            actor: Who/what discovered the finding.
            metadata: Additional finding context.

        Returns:
            The logged entry dict.
        """
        description = f"Finding discovered: [{severity.upper()}] {title}"
        meta = metadata or {}
        meta.update({"title": title, "severity": severity})
        return self.log_event(
            action_type="finding_discovered",
            description=description,
            actor=actor,
            affected_entity_type="finding",
            affected_entity_id=finding_id,
            metadata=meta,
        )

    def log_state_transition(
        self,
        engagement_id: str,
        old_state: str,
        new_state: str,
        actor: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Log an engagement state transition.

        Designed to connect to:
            engagement_manager.state_changed.connect(timeline_logger.log_state_transition)

        Args:
            engagement_id: The engagement that changed state.
            old_state: Previous state name.
            new_state: New state name.
            actor: Who triggered the transition.
            metadata: Additional context.

        Returns:
            The logged entry dict.
        """
        description = f"State transition: {old_state} → {new_state}"
        meta = metadata or {}
        meta.update({
            "engagement_id": engagement_id,
            "old_state": old_state,
            "new_state": new_state,
        })
        return self.log_event(
            action_type="state_transition",
            description=description,
            actor=actor,
            affected_entity_type="engagement",
            metadata=meta,
        )

    def log_evidence_captured(
        self,
        evidence_id: int,
        evidence_type: Optional[str] = None,
        actor: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Log an evidence capture event.

        Designed to connect to:
            evidence_manager.evidence_stored.connect(timeline_logger.log_evidence_captured)

        Args:
            evidence_id: The ID of the stored evidence.
            evidence_type: Type of evidence (screenshot, file, etc.).
            actor: Who captured the evidence.
            metadata: Additional context.

        Returns:
            The logged entry dict.
        """
        type_str = evidence_type or "evidence"
        description = f"Evidence captured: {type_str} (id={evidence_id})"
        meta = metadata or {}
        meta.update({"evidence_id": evidence_id})
        if evidence_type:
            meta["evidence_type"] = evidence_type
        return self.log_event(
            action_type="evidence_captured",
            description=description,
            actor=actor,
            affected_entity_type="evidence",
            affected_entity_id=evidence_id,
            metadata=meta,
        )

    # ------------------------------------------------------------------
    # Manual entry
    # ------------------------------------------------------------------

    def add_manual_entry(
        self,
        description: str,
        actor: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        timestamp: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Add a custom user note as a timeline entry.

        Allows users to insert free-form activity notes into the
        timeline with optional custom timestamps.

        Args:
            description: The manual note/entry text.
            actor: Who is adding the entry.
            metadata: Optional additional context.
            timestamp: Optional custom timestamp (ISO 8601). Defaults to now.

        Returns:
            The logged entry dict.
        """
        return self.log_event(
            action_type="manual",
            description=description,
            actor=actor,
            metadata=metadata,
            timestamp=timestamp,
        )

    # ------------------------------------------------------------------
    # Timeline retrieval and filtering
    # ------------------------------------------------------------------

    def get_timeline(
        self,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
        action_type: Optional[str] = None,
        actor: Optional[str] = None,
        affected_entity_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve timeline entries with optional filtering.

        All filters are ANDed together. Entries are returned in
        chronological order (oldest first).

        Args:
            date_from: ISO 8601 timestamp — only entries at or after this time.
            date_to: ISO 8601 timestamp — only entries at or before this time.
            action_type: Filter by action type.
            actor: Filter by actor name.
            affected_entity_type: Filter by entity type.

        Returns:
            List of timeline entry dicts ordered chronologically.

        Raises:
            RuntimeError: If no database is set.
            ValueError: If action_type filter is not a valid type.
        """
        db = self._require_db()

        if action_type is not None and action_type not in VALID_ACTION_TYPES:
            raise ValueError(
                f"Invalid action_type filter '{action_type}'. "
                f"Must be one of: {sorted(VALID_ACTION_TYPES)}"
            )

        query = "SELECT id, action_type, actor, affected_entity_type, affected_entity_id, description, metadata, timestamp FROM timeline_entries"
        conditions = []
        params: list = []

        if date_from is not None:
            conditions.append("timestamp >= ?")
            params.append(date_from)

        if date_to is not None:
            conditions.append("timestamp <= ?")
            params.append(date_to)

        if action_type is not None:
            conditions.append("action_type = ?")
            params.append(action_type)

        if actor is not None:
            conditions.append("actor = ?")
            params.append(actor)

        if affected_entity_type is not None:
            conditions.append("affected_entity_type = ?")
            params.append(affected_entity_type)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY timestamp ASC"

        rows = db.execute_query(query, tuple(params))

        entries = []
        for row in rows:
            entry = {
                "id": row[0],
                "action_type": row[1],
                "actor": row[2],
                "affected_entity_type": row[3],
                "affected_entity_id": row[4],
                "description": row[5],
                "metadata": json.loads(row[6]) if row[6] else None,
                "timestamp": row[7],
            }
            entries.append(entry)

        return entries

    # ------------------------------------------------------------------
    # Signal connection helpers
    # ------------------------------------------------------------------

    def connect_to_engagement_manager(self, engagement_manager) -> None:
        """Connect to engagement manager signals for automatic logging.

        Args:
            engagement_manager: An EngagementManager instance with
                state_changed(str, str, str) signal.
        """
        try:
            engagement_manager.state_changed.connect(self.log_state_transition)
            logger.info("TimelineLogger connected to EngagementManager signals")
        except AttributeError as e:
            logger.warning(
                f"Failed to connect to EngagementManager: {e}"
            )

    def connect_to_evidence_manager(self, evidence_manager) -> None:
        """Connect to evidence manager signals for automatic logging.

        Args:
            evidence_manager: An EvidenceManager instance with
                evidence_stored(int) signal.
        """
        try:
            evidence_manager.evidence_stored.connect(self.log_evidence_captured)
            logger.info("TimelineLogger connected to EvidenceManager signals")
        except AttributeError as e:
            logger.warning(
                f"Failed to connect to EvidenceManager: {e}"
            )

    def connect_to_scanner(self, scanner) -> None:
        """Connect to scanner signals for automatic logging.

        Expects the scanner to have scan_started and scan_completed signals.
        Falls back gracefully if signals are not present.

        Args:
            scanner: A scanner instance with optional scan_started/scan_completed signals.
        """
        try:
            if hasattr(scanner, "scan_started"):
                scanner.scan_started.connect(self.log_scan_start)
                logger.info("TimelineLogger connected to scanner.scan_started")
        except AttributeError as e:
            logger.warning(f"Failed to connect to scanner.scan_started: {e}")

        try:
            if hasattr(scanner, "scan_completed"):
                scanner.scan_completed.connect(self.log_scan_complete)
                logger.info("TimelineLogger connected to scanner.scan_completed")
        except AttributeError as e:
            logger.warning(f"Failed to connect to scanner.scan_completed: {e}")
