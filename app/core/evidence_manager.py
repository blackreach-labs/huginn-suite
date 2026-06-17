# app/core/evidence_manager.py
"""Database-backed evidence management engine for engagement system.

Handles evidence capture, storage with SHA-256 integrity hashing, zlib
compression for large files (>10MB), non-destructive annotations, and
bidirectional evidence-to-finding linkage.

Replaces the simpler in-memory evidence_collector.py with a full
database-backed implementation using the per-engagement EngagementDatabase.
"""

import hashlib
import json
import zlib
from datetime import datetime, timezone
from typing import Dict, List, Optional

from PyQt6.QtCore import QObject, pyqtSignal

from app.core.engagement_database import EngagementDatabase


# Valid evidence types
EVIDENCE_TYPES = frozenset([
    "screenshot",
    "text_snippet",
    "file",
    "http_pair",
    "terminal_output",
])

# Compression threshold: 10 MB
COMPRESSION_THRESHOLD = 10 * 1024 * 1024


class EvidenceManager(QObject):
    """Manages evidence storage, retrieval, annotation, and finding linkage.

    Operates against a per-engagement SQLite database provided via
    set_database(). All evidence is stored with SHA-256 integrity hashes,
    and files exceeding 10 MB are transparently compressed with zlib.

    Signals:
        evidence_stored(int): Emitted with evidence_id after successful store.
        evidence_linked(int, int): Emitted with (evidence_id, finding_id) after linkage.
    """

    evidence_stored = pyqtSignal(int)       # evidence_id
    evidence_linked = pyqtSignal(int, int)  # evidence_id, finding_id

    def __init__(self, parent=None):
        """Initialize the EvidenceManager.

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

    def store_evidence(
        self,
        evidence_type: str,
        data: bytes,
        title: str = "",
        source_context: str = "",
        tags: Optional[List[str]] = None,
        mime_type: str = "",
        target_id: Optional[int] = None,
    ) -> int:
        """Store evidence with SHA-256 hashing and optional compression.

        Data exceeding COMPRESSION_THRESHOLD (10 MB) is compressed with zlib
        before storage. The SHA-256 hash is computed on the *original*
        (uncompressed) data for integrity verification.

        Args:
            evidence_type: One of EVIDENCE_TYPES (screenshot, text_snippet,
                file, http_pair, terminal_output).
            data: Raw evidence bytes.
            title: Human-readable title for the evidence.
            source_context: Description of where/how evidence was captured.
            tags: Optional list of string tags for categorization.
            mime_type: MIME type of the evidence data.
            target_id: Optional target ID for categorization by target.

        Returns:
            The integer ID of the newly stored evidence record.

        Raises:
            ValueError: If evidence_type is not a recognized type.
            RuntimeError: If no database is set.
        """
        db = self._require_db()

        if evidence_type not in EVIDENCE_TYPES:
            raise ValueError(
                f"Invalid evidence_type '{evidence_type}'. "
                f"Must be one of: {sorted(EVIDENCE_TYPES)}"
            )

        # Compute SHA-256 on original data
        sha256_hash = hashlib.sha256(data).hexdigest()

        # Compress if above threshold
        compressed = 0
        store_data = data
        if len(data) > COMPRESSION_THRESHOLD:
            store_data = zlib.compress(data)
            compressed = 1

        # Serialize tags
        tags_json = json.dumps(tags) if tags else None

        # Timestamp
        created_at = datetime.now(timezone.utc).isoformat()

        evidence_id = db.execute_write(
            """INSERT INTO evidence
               (evidence_type, title, data, compressed, sha256_hash,
                mime_type, source_context, tags, target_id, annotations, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                evidence_type,
                title,
                store_data,
                compressed,
                sha256_hash,
                mime_type,
                source_context,
                tags_json,
                target_id,
                json.dumps([]),  # empty annotations list
                created_at,
            ),
        )

        self.evidence_stored.emit(evidence_id)
        return evidence_id

    def retrieve_evidence(self, evidence_id: int) -> bytes:
        """Retrieve evidence data, decompressing if needed.

        Args:
            evidence_id: The ID of the evidence record.

        Returns:
            The original (uncompressed) evidence bytes.

        Raises:
            ValueError: If the evidence_id does not exist.
            RuntimeError: If no database is set.
        """
        db = self._require_db()

        rows = db.execute_query(
            "SELECT data, compressed FROM evidence WHERE id = ?",
            (evidence_id,),
        )
        if not rows:
            raise ValueError(f"Evidence with id {evidence_id} not found.")

        data, compressed = rows[0]
        if compressed:
            data = zlib.decompress(data)
        return data

    def get_evidence_metadata(self, evidence_id: int) -> Dict:
        """Get metadata for an evidence record (without the blob data).

        Args:
            evidence_id: The ID of the evidence record.

        Returns:
            Dictionary with evidence metadata fields.

        Raises:
            ValueError: If the evidence_id does not exist.
            RuntimeError: If no database is set.
        """
        db = self._require_db()

        rows = db.execute_query(
            """SELECT id, evidence_type, title, compressed, sha256_hash,
                      mime_type, source_context, tags, target_id,
                      annotations, created_at
               FROM evidence WHERE id = ?""",
            (evidence_id,),
        )
        if not rows:
            raise ValueError(f"Evidence with id {evidence_id} not found.")

        row = rows[0]
        return {
            "id": row[0],
            "evidence_type": row[1],
            "title": row[2],
            "compressed": bool(row[3]),
            "sha256_hash": row[4],
            "mime_type": row[5],
            "source_context": row[6],
            "tags": json.loads(row[7]) if row[7] else [],
            "target_id": row[8],
            "annotations": json.loads(row[9]) if row[9] else [],
            "created_at": row[10],
        }

    def add_annotation(
        self,
        evidence_id: int,
        annotation_type: str,
        coordinates: Dict,
        properties: Optional[Dict] = None,
    ) -> None:
        """Add a non-destructive annotation to evidence.

        Annotations are stored as a JSON array in the annotations column.
        The original evidence data (BLOB) is never modified.

        Args:
            evidence_id: The ID of the evidence record.
            annotation_type: Type of annotation (e.g., rectangle, arrow,
                text_label, redaction).
            coordinates: Position/size dict (e.g., {x, y, width, height}).
            properties: Optional visual properties (color, text, thickness).

        Raises:
            ValueError: If the evidence_id does not exist.
            RuntimeError: If no database is set.
        """
        db = self._require_db()

        rows = db.execute_query(
            "SELECT annotations FROM evidence WHERE id = ?",
            (evidence_id,),
        )
        if not rows:
            raise ValueError(f"Evidence with id {evidence_id} not found.")

        existing = json.loads(rows[0][0]) if rows[0][0] else []

        annotation = {
            "annotation_type": annotation_type,
            "coordinates": coordinates,
            "properties": properties or {},
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        existing.append(annotation)

        db.execute_write(
            "UPDATE evidence SET annotations = ? WHERE id = ?",
            (json.dumps(existing), evidence_id),
        )

    def link_to_finding(self, evidence_id: int, finding_id: int) -> None:
        """Create a bidirectional link between evidence and a finding.

        Args:
            evidence_id: The ID of the evidence record.
            finding_id: The ID of the finding record.

        Raises:
            RuntimeError: If no database is set.
        """
        db = self._require_db()

        linked_at = datetime.now(timezone.utc).isoformat()

        db.execute_write(
            """INSERT OR IGNORE INTO evidence_finding_links
               (evidence_id, finding_id, linked_at)
               VALUES (?, ?, ?)""",
            (evidence_id, finding_id, linked_at),
        )

        self.evidence_linked.emit(evidence_id, finding_id)

    def unlink_from_finding(self, evidence_id: int, finding_id: int) -> None:
        """Remove the link between evidence and a finding.

        Args:
            evidence_id: The ID of the evidence record.
            finding_id: The ID of the finding record.

        Raises:
            RuntimeError: If no database is set.
        """
        db = self._require_db()

        db.execute_write(
            """DELETE FROM evidence_finding_links
               WHERE evidence_id = ? AND finding_id = ?""",
            (evidence_id, finding_id),
        )

    def get_evidence_for_finding(self, finding_id: int) -> List[Dict]:
        """Get all evidence linked to a specific finding.

        Args:
            finding_id: The ID of the finding.

        Returns:
            List of evidence metadata dicts (without blob data).

        Raises:
            RuntimeError: If no database is set.
        """
        db = self._require_db()

        rows = db.execute_query(
            """SELECT e.id, e.evidence_type, e.title, e.compressed,
                      e.sha256_hash, e.mime_type, e.source_context,
                      e.tags, e.target_id, e.annotations, e.created_at
               FROM evidence e
               JOIN evidence_finding_links efl ON e.id = efl.evidence_id
               WHERE efl.finding_id = ?
               ORDER BY e.created_at""",
            (finding_id,),
        )

        return [
            {
                "id": row[0],
                "evidence_type": row[1],
                "title": row[2],
                "compressed": bool(row[3]),
                "sha256_hash": row[4],
                "mime_type": row[5],
                "source_context": row[6],
                "tags": json.loads(row[7]) if row[7] else [],
                "target_id": row[8],
                "annotations": json.loads(row[9]) if row[9] else [],
                "created_at": row[10],
            }
            for row in rows
        ]

    def get_findings_for_evidence(self, evidence_id: int) -> List[Dict]:
        """Get all findings linked to a specific evidence item.

        Args:
            evidence_id: The ID of the evidence record.

        Returns:
            List of finding dicts with basic metadata.

        Raises:
            RuntimeError: If no database is set.
        """
        db = self._require_db()

        rows = db.execute_query(
            """SELECT f.id, f.title, f.severity, f.status, f.category,
                      f.created_at
               FROM findings f
               JOIN evidence_finding_links efl ON f.id = efl.finding_id
               WHERE efl.evidence_id = ?
               ORDER BY f.created_at""",
            (evidence_id,),
        )

        return [
            {
                "id": row[0],
                "title": row[1],
                "severity": row[2],
                "status": row[3],
                "category": row[4],
                "created_at": row[5],
            }
            for row in rows
        ]

    def on_finding_deleted(self, finding_id: int) -> None:
        """Handle finding deletion: unlink evidence but retain it.

        Removes all evidence_finding_links referencing the given finding_id.
        The evidence records themselves are preserved (orphaned, not deleted).

        Args:
            finding_id: The ID of the deleted finding.

        Raises:
            RuntimeError: If no database is set.
        """
        db = self._require_db()

        db.execute_write(
            "DELETE FROM evidence_finding_links WHERE finding_id = ?",
            (finding_id,),
        )

    def get_evidence_by_target(self, target_id: int) -> List[Dict]:
        """Get all evidence categorized under a specific target.

        Args:
            target_id: The target ID to filter by.

        Returns:
            List of evidence metadata dicts.

        Raises:
            RuntimeError: If no database is set.
        """
        db = self._require_db()

        rows = db.execute_query(
            """SELECT id, evidence_type, title, compressed, sha256_hash,
                      mime_type, source_context, tags, target_id,
                      annotations, created_at
               FROM evidence
               WHERE target_id = ?
               ORDER BY created_at""",
            (target_id,),
        )

        return [
            {
                "id": row[0],
                "evidence_type": row[1],
                "title": row[2],
                "compressed": bool(row[3]),
                "sha256_hash": row[4],
                "mime_type": row[5],
                "source_context": row[6],
                "tags": json.loads(row[7]) if row[7] else [],
                "target_id": row[8],
                "annotations": json.loads(row[9]) if row[9] else [],
                "created_at": row[10],
            }
            for row in rows
        ]

    def get_evidence_by_tag(self, tag: str) -> List[Dict]:
        """Get all evidence containing a specific tag.

        Args:
            tag: The tag string to search for.

        Returns:
            List of evidence metadata dicts matching the tag.

        Raises:
            RuntimeError: If no database is set.
        """
        db = self._require_db()

        # Use JSON-based search via LIKE pattern
        rows = db.execute_query(
            """SELECT id, evidence_type, title, compressed, sha256_hash,
                      mime_type, source_context, tags, target_id,
                      annotations, created_at
               FROM evidence
               WHERE tags LIKE ?
               ORDER BY created_at""",
            (f'%"{tag}"%',),
        )

        # Filter in Python for exact match within the JSON array
        results = []
        for row in rows:
            tags_list = json.loads(row[7]) if row[7] else []
            if tag in tags_list:
                results.append({
                    "id": row[0],
                    "evidence_type": row[1],
                    "title": row[2],
                    "compressed": bool(row[3]),
                    "sha256_hash": row[4],
                    "mime_type": row[5],
                    "source_context": row[6],
                    "tags": tags_list,
                    "target_id": row[8],
                    "annotations": json.loads(row[9]) if row[9] else [],
                    "created_at": row[10],
                })
        return results

    def verify_integrity(self, evidence_id: int) -> bool:
        """Verify evidence integrity by recomputing SHA-256 hash.

        Args:
            evidence_id: The ID of the evidence record.

        Returns:
            True if recomputed hash matches stored hash, False otherwise.

        Raises:
            ValueError: If the evidence_id does not exist.
            RuntimeError: If no database is set.
        """
        db = self._require_db()

        rows = db.execute_query(
            "SELECT data, compressed, sha256_hash FROM evidence WHERE id = ?",
            (evidence_id,),
        )
        if not rows:
            raise ValueError(f"Evidence with id {evidence_id} not found.")

        data, compressed, stored_hash = rows[0]
        if compressed:
            data = zlib.decompress(data)

        computed_hash = hashlib.sha256(data).hexdigest()
        return computed_hash == stored_hash
