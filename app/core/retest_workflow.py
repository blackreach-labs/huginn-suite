# app/core/retest_workflow.py
"""Retest and validation workflow engine.

Manages formal retest cycles for verifying client remediations. Supports
creating retest sessions linked to engagements, tracking finding retest
statuses, computing metrics, flagging regressions, and maintaining history
across multiple cycles.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional

from PyQt6.QtCore import QObject, pyqtSignal

from app.core.engagement_database import EngagementDatabase
from app.core.logger import logger


# Valid retest statuses for findings within a cycle
VALID_RETEST_STATUSES = (
    "not_tested",
    "fixed",
    "partially_fixed",
    "not_fixed",
    "regressed",
)


class RetestWorkflow(QObject):
    """Retest workflow engine for managing vulnerability retest cycles.

    Provides formal retest cycle management including creation of retest
    sessions, checklist presentation of findings with current status,
    result recording with evidence linking, metrics computation, and
    cycle completion with summary generation.

    Regressed findings are automatically flagged with elevated priority
    in retest reports. Multiple cycles per engagement are supported with
    full history preservation.

    Signals:
        cycle_created(int): Emitted with cycle ID when a new retest cycle is created.
        result_recorded(int, int): Emitted with (cycle_id, finding_id) when a result is recorded.
        cycle_completed(int): Emitted with cycle ID when a cycle is completed.
    """

    cycle_created = pyqtSignal(int)
    result_recorded = pyqtSignal(int, int)
    cycle_completed = pyqtSignal(int)

    def __init__(self, parent=None):
        """Initialize the RetestWorkflow.

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
        """Attach an engagement database for retest operations.

        Args:
            db: An EngagementDatabase instance that is already connected
                with schema created.

        Raises:
            RuntimeError: If the database is not connected.
        """
        if not db.connected:
            raise RuntimeError("Database must be connected before attaching to RetestWorkflow.")

        self._db = db
        logger.info("RetestWorkflow: database attached.")

    def _require_db(self) -> None:
        """Raise if no database is attached."""
        if self._db is None:
            raise RuntimeError("No database attached. Call set_database() first.")

    def create_retest_cycle(self, notes: Optional[str] = None) -> int:
        """Create a new retest cycle linked to the current engagement.

        The cycle_number is auto-incremented based on existing cycles in
        the engagement database.

        Args:
            notes: Optional notes describing the retest cycle purpose.

        Returns:
            The ID of the newly created retest cycle.

        Raises:
            RuntimeError: If no database is attached.
        """
        self._require_db()

        # Determine next cycle number
        rows = self._db.execute_query(
            "SELECT COALESCE(MAX(cycle_number), 0) FROM retest_cycles"
        )
        next_cycle_number = rows[0][0] + 1

        now = datetime.now(timezone.utc).isoformat()

        cycle_id = self._db.execute_write(
            """INSERT INTO retest_cycles (cycle_number, start_date, end_date, status, notes, created_at)
               VALUES (?, ?, NULL, 'in_progress', ?, ?)""",
            (next_cycle_number, now, notes, now),
        )

        logger.info(f"RetestWorkflow: created cycle {cycle_id} (number={next_cycle_number})")
        self.cycle_created.emit(cycle_id)
        return cycle_id

    def get_findings_checklist(self, cycle_id: int) -> List[Dict]:
        """Get all findings with their current retest status for a cycle.

        Returns a checklist of all findings in the engagement, each annotated
        with its retest status for the specified cycle. Findings without a
        recorded result in this cycle show as 'not_tested'.

        Args:
            cycle_id: The retest cycle ID.

        Returns:
            List of dicts with keys: finding_id, title, severity, status,
            retest_status, retester_notes, evidence_id, retested_at.

        Raises:
            RuntimeError: If no database is attached.
            ValueError: If cycle_id does not exist.
        """
        self._require_db()
        self._validate_cycle_exists(cycle_id)

        rows = self._db.execute_query(
            """SELECT f.id, f.title, f.severity, f.status,
                      r.retest_status, r.retester_notes, r.evidence_id, r.retested_at
               FROM findings f
               LEFT JOIN retest_results r ON f.id = r.finding_id AND r.cycle_id = ?
               ORDER BY f.id ASC""",
            (cycle_id,),
        )

        checklist = []
        for row in rows:
            checklist.append({
                "finding_id": row[0],
                "title": row[1],
                "severity": row[2],
                "status": row[3],
                "retest_status": row[4] if row[4] else "not_tested",
                "retester_notes": row[5],
                "evidence_id": row[6],
                "retested_at": row[7],
            })

        return checklist

    def record_retest_result(
        self,
        cycle_id: int,
        finding_id: int,
        status: str,
        notes: str,
        evidence_id: Optional[int] = None,
    ) -> int:
        """Record a retest result for a finding within a cycle.

        If a result already exists for this finding in this cycle, it is
        updated (upsert behavior). If the status is 'regressed', the finding
        is flagged with elevated priority.

        Args:
            cycle_id: The retest cycle ID.
            finding_id: The finding ID being retested.
            status: Retest status — one of: not_tested, fixed, partially_fixed,
                    not_fixed, regressed.
            notes: Retester notes describing the retest outcome.
            evidence_id: Optional ID of linked evidence.

        Returns:
            The ID of the retest result record.

        Raises:
            RuntimeError: If no database is attached.
            ValueError: If status is invalid, cycle doesn't exist, finding
                       doesn't exist, or cycle is already completed.
        """
        self._require_db()

        # Validate status
        if status not in VALID_RETEST_STATUSES:
            raise ValueError(
                f"Invalid retest status '{status}'. "
                f"Must be one of: {VALID_RETEST_STATUSES}"
            )

        # Validate cycle exists and is in progress
        cycle = self._get_cycle(cycle_id)
        if cycle is None:
            raise ValueError(f"Retest cycle with id {cycle_id} does not exist.")
        if cycle["status"] == "completed":
            raise ValueError(
                f"Cannot record results in completed cycle {cycle_id}."
            )

        # Validate finding exists
        finding_rows = self._db.execute_query(
            "SELECT id FROM findings WHERE id = ?", (finding_id,)
        )
        if not finding_rows:
            raise ValueError(f"Finding with id {finding_id} does not exist.")

        now = datetime.now(timezone.utc).isoformat()

        # Check for existing result (upsert)
        existing = self._db.execute_query(
            """SELECT id FROM retest_results
               WHERE cycle_id = ? AND finding_id = ?""",
            (cycle_id, finding_id),
        )

        if existing:
            # Update existing result
            result_id = existing[0][0]
            self._db.execute_write(
                """UPDATE retest_results
                   SET retest_status = ?, retester_notes = ?, evidence_id = ?, retested_at = ?
                   WHERE id = ?""",
                (status, notes, evidence_id, now, result_id),
            )
        else:
            # Insert new result
            result_id = self._db.execute_write(
                """INSERT INTO retest_results (cycle_id, finding_id, retest_status, retester_notes, evidence_id, retested_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (cycle_id, finding_id, status, notes, evidence_id, now),
            )

        # Flag regressed findings with elevated priority
        if status == "regressed":
            self._flag_regressed_finding(finding_id)

        logger.debug(
            f"RetestWorkflow: recorded result for finding {finding_id} "
            f"in cycle {cycle_id}: {status}"
        )
        self.result_recorded.emit(cycle_id, finding_id)
        return result_id

    def get_metrics(self, cycle_id: int) -> Dict:
        """Compute retest metrics for a cycle.

        Returns:
            Dict with keys:
              - total_findings: Total findings in the engagement
              - findings_retested: Number of findings with a recorded result
              - findings_remaining: Number of findings not yet retested
              - pass_rate: Ratio of 'fixed' results to total retested (0.0-1.0)
              - regressed_count: Number of findings marked as regressed

        Raises:
            RuntimeError: If no database is attached.
            ValueError: If cycle_id does not exist.
        """
        self._require_db()
        self._validate_cycle_exists(cycle_id)

        # Total findings in the engagement
        total_rows = self._db.execute_query(
            "SELECT COUNT(*) FROM findings"
        )
        total_findings = total_rows[0][0]

        # Results for this cycle
        results_rows = self._db.execute_query(
            """SELECT retest_status FROM retest_results
               WHERE cycle_id = ?""",
            (cycle_id,),
        )

        findings_retested = len(results_rows)
        findings_remaining = total_findings - findings_retested

        # Count fixed and regressed
        fixed_count = sum(1 for row in results_rows if row[0] == "fixed")
        regressed_count = sum(1 for row in results_rows if row[0] == "regressed")

        # Pass rate = fixed / retested (avoid division by zero)
        pass_rate = fixed_count / findings_retested if findings_retested > 0 else 0.0

        return {
            "total_findings": total_findings,
            "findings_retested": findings_retested,
            "findings_remaining": findings_remaining,
            "pass_rate": pass_rate,
            "regressed_count": regressed_count,
        }

    def complete_cycle(self, cycle_id: int) -> Dict:
        """Complete a retest cycle and generate a summary.

        Sets the cycle status to 'completed' and records the end date.
        Generates a summary comparing original findings to retest outcomes.

        Args:
            cycle_id: The retest cycle ID to complete.

        Returns:
            A summary dict with keys: cycle_id, cycle_number, start_date,
            end_date, metrics, regressed_findings.

        Raises:
            RuntimeError: If no database is attached.
            ValueError: If cycle doesn't exist or is already completed.
        """
        self._require_db()

        cycle = self._get_cycle(cycle_id)
        if cycle is None:
            raise ValueError(f"Retest cycle with id {cycle_id} does not exist.")
        if cycle["status"] == "completed":
            raise ValueError(f"Retest cycle {cycle_id} is already completed.")

        now = datetime.now(timezone.utc).isoformat()

        # Mark cycle as completed
        self._db.execute_write(
            """UPDATE retest_cycles SET status = 'completed', end_date = ?
               WHERE id = ?""",
            (now, cycle_id),
        )

        # Compute metrics
        metrics = self.get_metrics(cycle_id)

        # Get regressed findings details
        regressed_findings = self._get_regressed_findings(cycle_id)

        summary = {
            "cycle_id": cycle_id,
            "cycle_number": cycle["cycle_number"],
            "start_date": cycle["start_date"],
            "end_date": now,
            "metrics": metrics,
            "regressed_findings": regressed_findings,
        }

        logger.info(f"RetestWorkflow: completed cycle {cycle_id}")
        self.cycle_completed.emit(cycle_id)
        return summary

    def get_cycle(self, cycle_id: int) -> Optional[Dict]:
        """Get a single retest cycle by ID.

        Args:
            cycle_id: The cycle ID.

        Returns:
            Cycle dict or None if not found.
        """
        self._require_db()
        return self._get_cycle(cycle_id)

    def get_all_cycles(self) -> List[Dict]:
        """Get all retest cycles for the engagement, ordered by cycle number.

        Returns:
            List of cycle dicts.

        Raises:
            RuntimeError: If no database is attached.
        """
        self._require_db()

        rows = self._db.execute_query(
            """SELECT id, cycle_number, start_date, end_date, status, notes, created_at
               FROM retest_cycles
               ORDER BY cycle_number ASC"""
        )

        return [self._cycle_row_to_dict(row) for row in rows]

    def _get_cycle(self, cycle_id: int) -> Optional[Dict]:
        """Internal method to fetch a cycle by ID."""
        rows = self._db.execute_query(
            """SELECT id, cycle_number, start_date, end_date, status, notes, created_at
               FROM retest_cycles WHERE id = ?""",
            (cycle_id,),
        )
        if not rows:
            return None
        return self._cycle_row_to_dict(rows[0])

    def _validate_cycle_exists(self, cycle_id: int) -> None:
        """Raise ValueError if the cycle does not exist."""
        if self._get_cycle(cycle_id) is None:
            raise ValueError(f"Retest cycle with id {cycle_id} does not exist.")

    def _flag_regressed_finding(self, finding_id: int) -> None:
        """Flag a finding as regressed with elevated priority.

        Updates the finding's status to indicate regression, which gives
        it elevated priority in reports.
        """
        self._db.execute_write(
            """UPDATE findings SET status = 'regressed', updated_at = ?
               WHERE id = ?""",
            (datetime.now(timezone.utc).isoformat(), finding_id),
        )
        logger.info(f"RetestWorkflow: flagged finding {finding_id} as regressed (elevated priority)")

    def _get_regressed_findings(self, cycle_id: int) -> List[Dict]:
        """Get details of all regressed findings in a cycle."""
        rows = self._db.execute_query(
            """SELECT f.id, f.title, f.severity, r.retester_notes, r.retested_at
               FROM retest_results r
               JOIN findings f ON r.finding_id = f.id
               WHERE r.cycle_id = ? AND r.retest_status = 'regressed'
               ORDER BY f.id ASC""",
            (cycle_id,),
        )

        return [
            {
                "finding_id": row[0],
                "title": row[1],
                "severity": row[2],
                "retester_notes": row[3],
                "retested_at": row[4],
            }
            for row in rows
        ]

    @staticmethod
    def _cycle_row_to_dict(row: tuple) -> Dict:
        """Convert a retest_cycles row to a dictionary.

        Expected column order: id, cycle_number, start_date, end_date, status,
        notes, created_at.
        """
        return {
            "id": row[0],
            "cycle_number": row[1],
            "start_date": row[2],
            "end_date": row[3],
            "status": row[4],
            "notes": row[5],
            "created_at": row[6],
        }
