"""Physical Security Assessment Tracking Engine.

Provides tracking of physical security assessment activities including:
- Physical access attempt logging with categorized methods
- Site map annotation on floor plan evidence
- Physical security control effectiveness ratings
- Assessment summary generation for report inclusion

Operates against a per-engagement EngagementDatabase via set_database().
"""

import json
from datetime import datetime, timezone
from typing import Dict, List, Optional

from PyQt6.QtCore import QObject, pyqtSignal


# Valid physical access attempt methods
VALID_METHODS = (
    "tailgating",
    "lock_bypass",
    "badge_cloning",
    "dumpster_diving",
    "social_engineering",
)

# Valid attempt outcomes
VALID_OUTCOMES = ("success", "failure", "partial")

# Valid annotation types for site maps
VALID_ANNOTATION_TYPES = ("entry_point", "camera", "access_control_zone")


class PhysicalSecurityEngine(QObject):
    """Engine for physical security assessment tracking.

    Tracks physical access attempts, site map annotations, and control
    effectiveness ratings. All data is persisted to the per-engagement
    database.

    Signals:
        attempt_logged(int): Emitted with attempt ID when a new attempt is logged.
        annotation_added(int): Emitted with annotation ID when a site annotation is added.
    """

    attempt_logged = pyqtSignal(dict)
    annotation_added = pyqtSignal(int)

    def __init__(self, parent: Optional[QObject] = None):
        """Initialize the Physical Security Engine.

        Args:
            parent: Optional QObject parent.
        """
        super().__init__(parent)
        self._db = None

    # ------------------------------------------------------------------
    # Database access
    # ------------------------------------------------------------------

    @property
    def database(self):
        """The current engagement database, or None."""
        return self._db

    def set_database(self, db) -> None:
        """Set the per-engagement database to operate against.

        Args:
            db: A connected EngagementDatabase instance.
        """
        self._db = db

    def _require_db(self):
        """Return the database or raise RuntimeError."""
        if self._db is None:
            raise RuntimeError("No database set. Call set_database() first.")
        return self._db

    # ------------------------------------------------------------------
    # Attempt Logging
    # ------------------------------------------------------------------

    def log_attempt(
        self,
        location: str,
        attempt_time: str,
        method: str,
        outcome: str,
        evidence_id: Optional[int] = None,
        notes: Optional[str] = None,
    ) -> int:
        """Log a physical access attempt.

        Args:
            location: The physical location of the attempt.
            attempt_time: ISO-format timestamp of the attempt.
            method: The method used (must be one of VALID_METHODS).
            outcome: The outcome (success, failure, partial).
            evidence_id: Optional ID of linked evidence record.
            notes: Optional notes about the attempt.

        Returns:
            The ID of the newly created attempt record.

        Raises:
            RuntimeError: If no database is set.
            ValueError: If method is not a valid category or outcome is invalid.
        """
        db = self._require_db()

        if method not in VALID_METHODS:
            raise ValueError(
                f"Invalid method '{method}'. Must be one of: {', '.join(VALID_METHODS)}"
            )

        if outcome not in VALID_OUTCOMES:
            raise ValueError(
                f"Invalid outcome '{outcome}'. Must be one of: {', '.join(VALID_OUTCOMES)}"
            )

        if not location or not location.strip():
            raise ValueError("Location must not be empty.")

        if not attempt_time or not attempt_time.strip():
            raise ValueError("Attempt time must not be empty.")

        attempt_id = db.execute_write(
            """
            INSERT INTO physical_attempts
                (location, attempt_time, method, outcome, evidence_id, notes)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (location.strip(), attempt_time.strip(), method, outcome, evidence_id, notes),
        )

        attempt_data = {
            "id": attempt_id,
            "location": location.strip(),
            "attempt_time": attempt_time.strip(),
            "method": method,
            "outcome": outcome,
            "evidence_id": evidence_id,
            "notes": notes,
        }
        self.attempt_logged.emit(attempt_data)
        return attempt_id

    def get_attempts(
        self,
        location: Optional[str] = None,
        method: Optional[str] = None,
    ) -> List[Dict]:
        """Retrieve physical access attempts with optional filtering.

        Args:
            location: Filter by location (case-insensitive partial match).
            method: Filter by method category.

        Returns:
            List of attempt dictionaries.
        """
        db = self._require_db()

        query = "SELECT id, location, attempt_time, method, outcome, evidence_id, notes FROM physical_attempts"
        conditions = []
        params: List = []

        if location:
            conditions.append("location LIKE ?")
            params.append(f"%{location}%")

        if method:
            if method not in VALID_METHODS:
                raise ValueError(
                    f"Invalid method '{method}'. Must be one of: {', '.join(VALID_METHODS)}"
                )
            conditions.append("method = ?")
            params.append(method)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY attempt_time DESC"

        rows = db.execute_query(query, tuple(params))
        return [
            {
                "id": row[0],
                "location": row[1],
                "attempt_time": row[2],
                "method": row[3],
                "outcome": row[4],
                "evidence_id": row[5],
                "notes": row[6],
            }
            for row in rows
        ]

    # ------------------------------------------------------------------
    # Site Annotations
    # ------------------------------------------------------------------

    def add_site_annotation(
        self,
        floor_plan_evidence_id: int,
        annotation_type: str,
        coordinates: Dict,
        label: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> int:
        """Add an annotation to a floor plan evidence image.

        Args:
            floor_plan_evidence_id: ID of the floor plan evidence record.
            annotation_type: Type of annotation (entry_point, camera, access_control_zone).
            coordinates: Dict with coordinate data (e.g., {x, y, width, height}).
            label: Optional label for the annotation.
            notes: Optional notes about the annotation.

        Returns:
            The ID of the newly created annotation record.

        Raises:
            RuntimeError: If no database is set.
            ValueError: If annotation_type is not valid or coordinates is empty.
        """
        db = self._require_db()

        if annotation_type not in VALID_ANNOTATION_TYPES:
            raise ValueError(
                f"Invalid annotation_type '{annotation_type}'. "
                f"Must be one of: {', '.join(VALID_ANNOTATION_TYPES)}"
            )

        if not coordinates or not isinstance(coordinates, dict):
            raise ValueError("Coordinates must be a non-empty dictionary.")

        coordinates_json = json.dumps(coordinates)

        annotation_id = db.execute_write(
            """
            INSERT INTO site_annotations
                (floor_plan_evidence_id, annotation_type, coordinates, label, notes)
            VALUES (?, ?, ?, ?, ?)
            """,
            (floor_plan_evidence_id, annotation_type, coordinates_json, label, notes),
        )

        self.annotation_added.emit(annotation_id)
        return annotation_id

    def get_annotations(
        self,
        floor_plan_evidence_id: Optional[int] = None,
    ) -> List[Dict]:
        """Retrieve site annotations, optionally filtered by floor plan.

        Args:
            floor_plan_evidence_id: Filter to specific floor plan evidence.

        Returns:
            List of annotation dictionaries.
        """
        db = self._require_db()

        query = (
            "SELECT id, floor_plan_evidence_id, annotation_type, coordinates, label, notes "
            "FROM site_annotations"
        )
        params: List = []

        if floor_plan_evidence_id is not None:
            query += " WHERE floor_plan_evidence_id = ?"
            params.append(floor_plan_evidence_id)

        query += " ORDER BY id"

        rows = db.execute_query(query, tuple(params))
        return [
            {
                "id": row[0],
                "floor_plan_evidence_id": row[1],
                "annotation_type": row[2],
                "coordinates": json.loads(row[3]) if row[3] else {},
                "label": row[4],
                "notes": row[5],
            }
            for row in rows
        ]

    # ------------------------------------------------------------------
    # Control Effectiveness Ratings
    # ------------------------------------------------------------------

    def rate_control(
        self,
        location: str,
        control_type: str,
        effectiveness_rating: int,
        notes: Optional[str] = None,
        assessed_at: Optional[str] = None,
    ) -> int:
        """Rate the effectiveness of a physical security control.

        Args:
            location: The location where the control is assessed.
            control_type: The type of control being rated (e.g., 'cctv', 'access_badge').
            effectiveness_rating: Rating from 1 (ineffective) to 5 (highly effective).
            notes: Optional notes about the rating.
            assessed_at: Optional ISO-format timestamp; defaults to current time.

        Returns:
            The ID of the newly created rating record.

        Raises:
            RuntimeError: If no database is set.
            ValueError: If rating is out of range or required fields are empty.
        """
        db = self._require_db()

        if not location or not location.strip():
            raise ValueError("Location must not be empty.")

        if not control_type or not control_type.strip():
            raise ValueError("Control type must not be empty.")

        if not isinstance(effectiveness_rating, int) or not (1 <= effectiveness_rating <= 5):
            raise ValueError(
                f"Effectiveness rating must be an integer between 1 and 5, got {effectiveness_rating}."
            )

        if assessed_at is None:
            assessed_at = datetime.now(timezone.utc).isoformat()

        rating_id = db.execute_write(
            """
            INSERT INTO physical_control_ratings
                (location, control_type, effectiveness_rating, notes, assessed_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (location.strip(), control_type.strip(), effectiveness_rating, notes, assessed_at),
        )

        return rating_id

    def get_ratings(
        self,
        location: Optional[str] = None,
        control_type: Optional[str] = None,
    ) -> List[Dict]:
        """Retrieve control effectiveness ratings with optional filtering.

        Args:
            location: Filter by location (case-insensitive partial match).
            control_type: Filter by control type.

        Returns:
            List of rating dictionaries.
        """
        db = self._require_db()

        query = (
            "SELECT id, location, control_type, effectiveness_rating, notes, assessed_at "
            "FROM physical_control_ratings"
        )
        conditions = []
        params: List = []

        if location:
            conditions.append("location LIKE ?")
            params.append(f"%{location}%")

        if control_type:
            conditions.append("control_type = ?")
            params.append(control_type)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY assessed_at DESC"

        rows = db.execute_query(query, tuple(params))
        return [
            {
                "id": row[0],
                "location": row[1],
                "control_type": row[2],
                "effectiveness_rating": row[3],
                "notes": row[4],
                "assessed_at": row[5],
            }
            for row in rows
        ]

    # ------------------------------------------------------------------
    # Summary Generation
    # ------------------------------------------------------------------

    def generate_summary(self) -> Dict:
        """Generate a physical assessment report section.

        Produces a summary containing:
        - Total attempts by method and outcome
        - Successful access points
        - Control effectiveness overview per location
        - Annotation counts per floor plan

        Returns:
            Dictionary with structured summary data for report inclusion.

        Raises:
            RuntimeError: If no database is set.
        """
        db = self._require_db()

        # Attempt statistics
        attempt_rows = db.execute_query(
            "SELECT method, outcome, COUNT(*) FROM physical_attempts GROUP BY method, outcome"
        )
        attempts_by_method: Dict[str, Dict[str, int]] = {}
        total_attempts = 0
        for method, outcome, count in attempt_rows:
            if method not in attempts_by_method:
                attempts_by_method[method] = {}
            attempts_by_method[method][outcome] = count
            total_attempts += count

        # Successful access points
        success_rows = db.execute_query(
            "SELECT location, method, attempt_time FROM physical_attempts WHERE outcome = 'success' ORDER BY attempt_time"
        )
        successful_access_points = [
            {"location": row[0], "method": row[1], "time": row[2]}
            for row in success_rows
        ]

        # Control ratings summary per location
        rating_rows = db.execute_query(
            """
            SELECT location, control_type, effectiveness_rating
            FROM physical_control_ratings
            ORDER BY location, control_type
            """
        )
        control_ratings: Dict[str, List[Dict]] = {}
        for loc, ctrl_type, rating in rating_rows:
            if loc not in control_ratings:
                control_ratings[loc] = []
            control_ratings[loc].append({
                "control_type": ctrl_type,
                "effectiveness_rating": rating,
            })

        # Average rating per location
        avg_rating_rows = db.execute_query(
            """
            SELECT location, AVG(effectiveness_rating) as avg_rating
            FROM physical_control_ratings
            GROUP BY location
            """
        )
        average_ratings = {row[0]: round(row[1], 2) for row in avg_rating_rows}

        # Annotation counts per floor plan
        annotation_rows = db.execute_query(
            """
            SELECT floor_plan_evidence_id, annotation_type, COUNT(*)
            FROM site_annotations
            GROUP BY floor_plan_evidence_id, annotation_type
            """
        )
        annotations_by_plan: Dict[int, Dict[str, int]] = {}
        for plan_id, ann_type, count in annotation_rows:
            if plan_id not in annotations_by_plan:
                annotations_by_plan[plan_id] = {}
            annotations_by_plan[plan_id][ann_type] = count

        return {
            "total_attempts": total_attempts,
            "attempts_by_method": attempts_by_method,
            "successful_access_points": successful_access_points,
            "control_ratings": control_ratings,
            "average_ratings_by_location": average_ratings,
            "annotations_by_floor_plan": annotations_by_plan,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
