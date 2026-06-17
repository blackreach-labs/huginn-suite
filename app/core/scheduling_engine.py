# app/core/scheduling_engine.py
"""Scheduling engine for recurring and one-time scans.

Manages scheduled scan configurations stored in the master index database,
computes next execution times from recurrence patterns (once, daily, weekly,
monthly, custom 5-field cron), and triggers scans via the existing scan
controller when they become due.
"""

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from PyQt6.QtCore import QObject, QTimer, pyqtSignal

from app.core.database_pool import DatabaseConnectionPool
from app.core.logger import logger


class CronParser:
    """Simple 5-field cron expression parser.

    Supports fields: minute hour day_of_month month day_of_week
    Each field supports:
      - '*' (any)
      - specific values: '5', '10'
      - lists: '1,3,5'
      - ranges: '1-5'
      - step values: '*/5', '1-10/2'

    Also supports named shortcuts: 'once', 'daily', 'weekly', 'monthly'.
    """

    NAMED_PATTERNS = {
        "once": None,  # One-time, no recurrence
        "daily": "0 0 * * *",  # Every day at midnight
        "weekly": "0 0 * * 0",  # Every Monday at midnight (0=Monday)
        "monthly": "0 0 1 * *",  # First of every month at midnight
    }

    @classmethod
    def normalize_pattern(cls, pattern: str) -> Optional[str]:
        """Convert named patterns to cron expressions.

        Returns None for 'once' (no recurrence), otherwise returns
        the 5-field cron expression.
        """
        pattern = pattern.strip().lower()
        if pattern in cls.NAMED_PATTERNS:
            return cls.NAMED_PATTERNS[pattern]
        # Validate it looks like a 5-field cron
        fields = pattern.split()
        if len(fields) != 5:
            raise ValueError(
                f"Invalid cron expression '{pattern}': expected 5 fields "
                f"(minute hour day month dow), got {len(fields)}"
            )
        return pattern

    @classmethod
    def _parse_field(cls, field: str, min_val: int, max_val: int) -> List[int]:
        """Parse a single cron field into a list of matching values."""
        values = set()

        for part in field.split(","):
            part = part.strip()
            if "/" in part:
                range_part, step_str = part.split("/", 1)
                step = int(step_str)
                if range_part == "*":
                    start, end = min_val, max_val
                elif "-" in range_part:
                    start, end = (int(x) for x in range_part.split("-", 1))
                else:
                    start = int(range_part)
                    end = max_val
                for v in range(start, end + 1, step):
                    if min_val <= v <= max_val:
                        values.add(v)
            elif part == "*":
                values.update(range(min_val, max_val + 1))
            elif "-" in part:
                start, end = (int(x) for x in part.split("-", 1))
                for v in range(start, end + 1):
                    if min_val <= v <= max_val:
                        values.add(v)
            else:
                v = int(part)
                if min_val <= v <= max_val:
                    values.add(v)

        return sorted(values)

    @classmethod
    def compute_next(cls, cron_expr: str, from_time: datetime) -> Optional[datetime]:
        """Compute the next execution time after from_time for a cron expression.

        Args:
            cron_expr: A 5-field cron expression (minute hour dom month dow).
            from_time: The reference time to compute the next execution after.

        Returns:
            The next matching datetime, or None if no match found within 1 year.
        """
        fields = cron_expr.split()
        if len(fields) != 5:
            raise ValueError(f"Invalid cron expression: '{cron_expr}'")

        minutes = cls._parse_field(fields[0], 0, 59)
        hours = cls._parse_field(fields[1], 0, 23)
        days_of_month = cls._parse_field(fields[2], 1, 31)
        months = cls._parse_field(fields[3], 1, 12)
        days_of_week = cls._parse_field(fields[4], 0, 6)  # 0=Monday ... 6=Sunday

        if not minutes or not hours or not days_of_month or not months or not days_of_week:
            return None

        # Start searching from the next minute after from_time
        candidate = from_time.replace(second=0, microsecond=0) + timedelta(minutes=1)
        max_time = from_time + timedelta(days=366)

        while candidate < max_time:
            if candidate.month not in months:
                # Jump to start of next month
                if candidate.month == 12:
                    candidate = candidate.replace(
                        year=candidate.year + 1, month=1, day=1, hour=0, minute=0
                    )
                else:
                    candidate = candidate.replace(
                        month=candidate.month + 1, day=1, hour=0, minute=0
                    )
                continue

            if candidate.day not in days_of_month:
                candidate = candidate.replace(hour=0, minute=0) + timedelta(days=1)
                continue

            # Python weekday: 0=Monday, 6=Sunday (matches our cron convention)
            if candidate.weekday() not in days_of_week:
                candidate = candidate.replace(hour=0, minute=0) + timedelta(days=1)
                continue

            if candidate.hour not in hours:
                candidate = candidate.replace(minute=0) + timedelta(hours=1)
                continue

            if candidate.minute not in minutes:
                candidate += timedelta(minutes=1)
                continue

            return candidate

        return None


class SchedulingEngine(QObject):
    """Engine for managing and executing scheduled/recurring scans.

    Stores schedule configurations in the master index database's
    scheduled_scans table. Uses a QTimer to check for pending scans
    every 60 seconds and emits signals when scans are triggered,
    completed, or failed.

    Signals:
        scan_triggered(schedule_id): Emitted when a scheduled scan is initiated.
        scan_completed(schedule_id, results): Emitted when a scan finishes successfully.
        scan_failed(schedule_id, error): Emitted when a scan fails.
    """

    scan_triggered = pyqtSignal(str)  # schedule_id
    scan_completed = pyqtSignal(str, dict)  # schedule_id, results
    scan_failed = pyqtSignal(str, str)  # schedule_id, error

    def __init__(self, master_db_pool: DatabaseConnectionPool, parent=None):
        """Initialize the scheduling engine.

        Args:
            master_db_pool: Connection pool for the master index database.
            parent: Optional QObject parent.
        """
        super().__init__(parent)
        self.master_db_pool = master_db_pool
        self._scan_controller = None

        # Timer to check for pending scans every 60 seconds
        self.check_timer = QTimer(self)
        self.check_timer.timeout.connect(self._check_pending)
        self.check_timer.start(60000)

    @property
    def scan_controller(self):
        """Get the connected scan controller."""
        return self._scan_controller

    @scan_controller.setter
    def scan_controller(self, controller):
        """Set and connect the scan controller for execution."""
        self._scan_controller = controller

    def create_schedule(
        self,
        name: str,
        scan_config: Dict,
        target_list: List[str],
        recurrence: str,
        engagement_id: Optional[str] = None,
    ) -> str:
        """Create a new scheduled scan.

        Args:
            name: Human-readable name for the schedule.
            scan_config: JSON-serializable scan configuration dict.
            target_list: List of target strings (IPs, hostnames, URLs).
            recurrence: Recurrence pattern ('once', 'daily', 'weekly',
                        'monthly', or a 5-field cron expression).
            engagement_id: Optional engagement to associate results with.

        Returns:
            The unique schedule_id (UUID string).

        Raises:
            ValueError: If the recurrence pattern is invalid.
        """
        # Validate and normalize recurrence pattern
        cron_expr = CronParser.normalize_pattern(recurrence)

        schedule_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()

        # Compute next execution time
        next_execution = self.compute_next_execution(recurrence, now)
        next_exec_iso = next_execution.isoformat() if next_execution else now_iso

        self.master_db_pool.execute_write(
            """INSERT INTO scheduled_scans
               (id, engagement_id, name, scan_config, target_list,
                recurrence_pattern, next_execution, last_execution,
                status, failure_count, last_failure_reason,
                created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 'active', 0, NULL, ?, ?)""",
            (
                schedule_id,
                engagement_id,
                name,
                json.dumps(scan_config),
                json.dumps(target_list),
                recurrence,
                next_exec_iso,
                now_iso,
                now_iso,
            ),
        )

        logger.info(
            f"Created schedule '{name}' (id={schedule_id}), "
            f"next execution: {next_exec_iso}"
        )
        return schedule_id

    def compute_next_execution(
        self, recurrence: str, from_time: Optional[datetime] = None
    ) -> Optional[datetime]:
        """Compute the next execution time for a recurrence pattern.

        Args:
            recurrence: Recurrence pattern string.
            from_time: Reference time (defaults to now UTC).

        Returns:
            The next execution datetime, or None for one-time schedules
            that have already executed.
        """
        if from_time is None:
            from_time = datetime.now(timezone.utc)

        recurrence_lower = recurrence.strip().lower()

        if recurrence_lower == "once":
            # For one-time schedules, next execution is 1 minute from now
            return from_time + timedelta(minutes=1)

        # Normalize named patterns to cron expressions
        cron_expr = CronParser.normalize_pattern(recurrence)
        if cron_expr is None:
            return None

        return CronParser.compute_next(cron_expr, from_time)

    def _check_pending(self) -> None:
        """Check for scheduled scans that are due and trigger them.

        Called by the QTimer every 60 seconds. Queries the master DB for
        active schedules whose next_execution time has passed.
        """
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()

        try:
            pending = self.master_db_pool.execute_query(
                """SELECT id, engagement_id, name, scan_config, target_list,
                          recurrence_pattern, next_execution
                   FROM scheduled_scans
                   WHERE status = 'active' AND next_execution <= ?""",
                (now_iso,),
            )
        except Exception as e:
            logger.error(f"SchedulingEngine: failed to query pending scans: {e}")
            return

        for row in pending:
            schedule_id = row[0]
            engagement_id = row[1]
            name = row[2]
            scan_config = json.loads(row[3]) if row[3] else {}
            target_list = json.loads(row[4]) if row[4] else []
            recurrence = row[5]

            logger.info(f"Triggering scheduled scan '{name}' (id={schedule_id})")
            self.scan_triggered.emit(schedule_id)

            try:
                self._execute_scan(schedule_id, scan_config, target_list, engagement_id)

                # Update last_execution and compute next execution
                recurrence_lower = recurrence.strip().lower()
                if recurrence_lower == "once":
                    # One-time scan: mark as completed
                    self.master_db_pool.execute_write(
                        """UPDATE scheduled_scans
                           SET last_execution = ?, status = 'completed',
                               updated_at = ?
                           WHERE id = ?""",
                        (now_iso, now_iso, schedule_id),
                    )
                else:
                    next_exec = self.compute_next_execution(recurrence, now)
                    next_exec_iso = next_exec.isoformat() if next_exec else now_iso
                    self.master_db_pool.execute_write(
                        """UPDATE scheduled_scans
                           SET last_execution = ?, next_execution = ?,
                               failure_count = 0, updated_at = ?
                           WHERE id = ?""",
                        (now_iso, next_exec_iso, now_iso, schedule_id),
                    )

                self.scan_completed.emit(schedule_id, {"status": "success"})

            except Exception as e:
                self._handle_failure(schedule_id, str(e), recurrence, now)

    def _execute_scan(
        self,
        schedule_id: str,
        scan_config: Dict,
        target_list: List[str],
        engagement_id: Optional[str],
    ) -> None:
        """Execute a scan using the connected scan controller.

        Args:
            schedule_id: The schedule identifier.
            scan_config: Scan configuration parameters.
            target_list: List of targets.
            engagement_id: Optional engagement for result storage.

        Raises:
            RuntimeError: If no scan controller is connected.
        """
        if self._scan_controller is None:
            raise RuntimeError("No scan controller connected to scheduling engine")

        # The scan controller start method initiates the scan
        self._scan_controller.start()
        logger.info(
            f"Scan execution started for schedule {schedule_id} "
            f"with {len(target_list)} targets"
        )

    def _handle_failure(
        self, schedule_id: str, reason: str, recurrence: str, now: datetime
    ) -> None:
        """Handle a scan execution failure.

        Increments the failure counter, logs the reason, and updates
        the next execution time for recurring schedules.

        Args:
            schedule_id: The schedule that failed.
            reason: Human-readable failure reason.
            recurrence: The recurrence pattern (to compute next execution).
            now: Current timestamp.
        """
        now_iso = now.isoformat()
        logger.error(f"Scheduled scan {schedule_id} failed: {reason}")

        # Compute next execution for retry
        recurrence_lower = recurrence.strip().lower()
        if recurrence_lower == "once":
            # One-time scans that fail stay active for next check interval
            self.master_db_pool.execute_write(
                """UPDATE scheduled_scans
                   SET failure_count = failure_count + 1,
                       last_failure_reason = ?,
                       next_execution = ?,
                       updated_at = ?
                   WHERE id = ?""",
                (reason, (now + timedelta(minutes=5)).isoformat(), now_iso, schedule_id),
            )
        else:
            next_exec = self.compute_next_execution(recurrence, now)
            next_exec_iso = next_exec.isoformat() if next_exec else now_iso
            self.master_db_pool.execute_write(
                """UPDATE scheduled_scans
                   SET failure_count = failure_count + 1,
                       last_failure_reason = ?,
                       next_execution = ?,
                       updated_at = ?
                   WHERE id = ?""",
                (reason, next_exec_iso, now_iso, schedule_id),
            )

        self.scan_failed.emit(schedule_id, reason)

    def disable_schedule(self, schedule_id: str) -> bool:
        """Disable a scheduled scan without deleting its configuration.

        Args:
            schedule_id: The schedule to disable.

        Returns:
            True if the schedule was found and disabled, False otherwise.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        rows = self.master_db_pool.execute_write(
            """UPDATE scheduled_scans
               SET status = 'disabled', updated_at = ?
               WHERE id = ? AND status = 'active'""",
            (now_iso, schedule_id),
        )
        if rows:
            logger.info(f"Disabled schedule {schedule_id}")
            return True
        return False

    def enable_schedule(self, schedule_id: str) -> bool:
        """Re-enable a previously disabled schedule.

        Recomputes the next execution time from the current moment.

        Args:
            schedule_id: The schedule to re-enable.

        Returns:
            True if the schedule was found and re-enabled, False otherwise.
        """
        # Fetch recurrence to recompute next execution
        results = self.master_db_pool.execute_query(
            """SELECT recurrence_pattern FROM scheduled_scans
               WHERE id = ? AND status = 'disabled'""",
            (schedule_id,),
        )
        if not results:
            return False

        recurrence = results[0][0]
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        next_exec = self.compute_next_execution(recurrence, now)
        next_exec_iso = next_exec.isoformat() if next_exec else now_iso

        self.master_db_pool.execute_write(
            """UPDATE scheduled_scans
               SET status = 'active', next_execution = ?, updated_at = ?
               WHERE id = ?""",
            (next_exec_iso, now_iso, schedule_id),
        )
        logger.info(f"Re-enabled schedule {schedule_id}, next execution: {next_exec_iso}")
        return True

    def get_schedule(self, schedule_id: str) -> Optional[Dict]:
        """Retrieve a schedule by ID.

        Returns:
            Dictionary with schedule fields, or None if not found.
        """
        results = self.master_db_pool.execute_query(
            """SELECT id, engagement_id, name, scan_config, target_list,
                      recurrence_pattern, next_execution, last_execution,
                      status, failure_count, last_failure_reason,
                      created_at, updated_at
               FROM scheduled_scans WHERE id = ?""",
            (schedule_id,),
        )
        if not results:
            return None

        row = results[0]
        return {
            "id": row[0],
            "engagement_id": row[1],
            "name": row[2],
            "scan_config": json.loads(row[3]) if row[3] else {},
            "target_list": json.loads(row[4]) if row[4] else [],
            "recurrence_pattern": row[5],
            "next_execution": row[6],
            "last_execution": row[7],
            "status": row[8],
            "failure_count": row[9],
            "last_failure_reason": row[10],
            "created_at": row[11],
            "updated_at": row[12],
        }

    def list_schedules(self, status_filter: Optional[str] = None) -> List[Dict]:
        """List all schedules, optionally filtered by status.

        Args:
            status_filter: If provided, only return schedules with this status.

        Returns:
            List of schedule dictionaries.
        """
        if status_filter:
            results = self.master_db_pool.execute_query(
                """SELECT id, engagement_id, name, scan_config, target_list,
                          recurrence_pattern, next_execution, last_execution,
                          status, failure_count, last_failure_reason,
                          created_at, updated_at
                   FROM scheduled_scans WHERE status = ?""",
                (status_filter,),
            )
        else:
            results = self.master_db_pool.execute_query(
                """SELECT id, engagement_id, name, scan_config, target_list,
                          recurrence_pattern, next_execution, last_execution,
                          status, failure_count, last_failure_reason,
                          created_at, updated_at
                   FROM scheduled_scans"""
            )

        schedules = []
        for row in results:
            schedules.append({
                "id": row[0],
                "engagement_id": row[1],
                "name": row[2],
                "scan_config": json.loads(row[3]) if row[3] else {},
                "target_list": json.loads(row[4]) if row[4] else [],
                "recurrence_pattern": row[5],
                "next_execution": row[6],
                "last_execution": row[7],
                "status": row[8],
                "failure_count": row[9],
                "last_failure_reason": row[10],
                "created_at": row[11],
                "updated_at": row[12],
            })
        return schedules

    def delete_schedule(self, schedule_id: str) -> bool:
        """Permanently delete a schedule.

        Args:
            schedule_id: The schedule to delete.

        Returns:
            True if deleted, False if not found.
        """
        rows = self.master_db_pool.execute_write(
            "DELETE FROM scheduled_scans WHERE id = ?",
            (schedule_id,),
        )
        if rows:
            logger.info(f"Deleted schedule {schedule_id}")
            return True
        return False

    def stop(self) -> None:
        """Stop the scheduling engine timer."""
        self.check_timer.stop()
        logger.info("SchedulingEngine stopped")
