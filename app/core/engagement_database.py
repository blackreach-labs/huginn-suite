# app/core/engagement_database.py
"""Per-engagement isolated SQLite database module.

Each engagement gets its own database file stored under
resources/engagements/{engagement_id}/engagement.db. This module handles
schema creation, connection management, and lifecycle operations for
individual engagement databases.
"""

import sqlite3
import threading
from pathlib import Path
from contextlib import contextmanager
from queue import Queue, Empty
from typing import Optional

from app.core.logger import logger


# Complete per-engagement database schema
ENGAGEMENT_DB_SCHEMA = """
-- Engagement metadata (key-value store for flexible config)
CREATE TABLE IF NOT EXISTS engagement_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Rules of Engagement
CREATE TABLE IF NOT EXISTS rules_of_engagement (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    authorized_ip_ranges TEXT,
    excluded_systems TEXT,
    testing_hours TEXT,
    emergency_contacts TEXT,
    escalation_procedures TEXT,
    custom_rules TEXT,
    updated_at TEXT NOT NULL
);

-- Client contacts
CREATE TABLE IF NOT EXISTS client_contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    role TEXT,
    email TEXT,
    phone TEXT,
    availability_window TEXT,
    created_at TEXT NOT NULL
);

-- Documents (scoping docs, RoE, SoW, NDA, etc.)
CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    document_type TEXT NOT NULL,
    content BLOB NOT NULL,
    mime_type TEXT,
    upload_date TEXT NOT NULL,
    metadata TEXT
);

-- Timeline milestones
CREATE TABLE IF NOT EXISTS milestones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    milestone_type TEXT NOT NULL,
    date TEXT NOT NULL,
    notes TEXT
);

-- Findings (engagement-specific)
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT,
    impact TEXT,
    remediation TEXT,
    cvss_score REAL,
    cvss_vector TEXT,
    cwe_id TEXT,
    category TEXT,
    status TEXT DEFAULT 'open',
    template_id TEXT,
    target_id INTEGER,
    service_id INTEGER,
    attack_technique_ids TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Evidence storage
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_type TEXT NOT NULL,
    title TEXT,
    data BLOB,
    compressed INTEGER DEFAULT 0,
    sha256_hash TEXT NOT NULL,
    mime_type TEXT,
    source_context TEXT,
    tags TEXT,
    target_id INTEGER,
    annotations TEXT,
    created_at TEXT NOT NULL
);

-- Evidence-Finding linkage (many-to-many)
CREATE TABLE IF NOT EXISTS evidence_finding_links (
    evidence_id INTEGER NOT NULL,
    finding_id INTEGER NOT NULL,
    linked_at TEXT NOT NULL,
    PRIMARY KEY (evidence_id, finding_id),
    FOREIGN KEY (evidence_id) REFERENCES evidence(id),
    FOREIGN KEY (finding_id) REFERENCES findings(id)
);

-- Notes
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scope_type TEXT NOT NULL,
    scope_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    content_format TEXT DEFAULT 'markdown',
    author TEXT,
    pinned INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Note revisions
CREATE TABLE IF NOT EXISTS note_revisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    note_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    revised_at TEXT NOT NULL,
    FOREIGN KEY (note_id) REFERENCES notes(id)
);

-- ATT&CK mappings
CREATE TABLE IF NOT EXISTS attack_mappings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL,
    technique_id TEXT NOT NULL,
    tactic TEXT NOT NULL,
    procedure_description TEXT,
    status TEXT DEFAULT 'tested',
    FOREIGN KEY (finding_id) REFERENCES findings(id)
);

-- Retest cycles
CREATE TABLE IF NOT EXISTS retest_cycles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cycle_number INTEGER NOT NULL,
    start_date TEXT NOT NULL,
    end_date TEXT,
    status TEXT DEFAULT 'in_progress',
    notes TEXT,
    created_at TEXT NOT NULL
);

-- Retest results
CREATE TABLE IF NOT EXISTS retest_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cycle_id INTEGER NOT NULL,
    finding_id INTEGER NOT NULL,
    retest_status TEXT NOT NULL,
    retester_notes TEXT,
    evidence_id INTEGER,
    retested_at TEXT NOT NULL,
    FOREIGN KEY (cycle_id) REFERENCES retest_cycles(id),
    FOREIGN KEY (finding_id) REFERENCES findings(id),
    FOREIGN KEY (evidence_id) REFERENCES evidence(id)
);

-- Timeline / Activity Log
CREATE TABLE IF NOT EXISTS timeline_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action_type TEXT NOT NULL,
    actor TEXT,
    affected_entity_type TEXT,
    affected_entity_id INTEGER,
    description TEXT NOT NULL,
    metadata TEXT,
    timestamp TEXT NOT NULL
);

-- Physical security attempts
CREATE TABLE IF NOT EXISTS physical_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    location TEXT NOT NULL,
    attempt_time TEXT NOT NULL,
    method TEXT NOT NULL,
    outcome TEXT NOT NULL,
    evidence_id INTEGER,
    notes TEXT,
    FOREIGN KEY (evidence_id) REFERENCES evidence(id)
);

-- Physical site annotations
CREATE TABLE IF NOT EXISTS site_annotations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    floor_plan_evidence_id INTEGER NOT NULL,
    annotation_type TEXT NOT NULL,
    coordinates TEXT NOT NULL,
    label TEXT,
    notes TEXT,
    FOREIGN KEY (floor_plan_evidence_id) REFERENCES evidence(id)
);

-- Physical security control ratings
CREATE TABLE IF NOT EXISTS physical_control_ratings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    location TEXT NOT NULL,
    control_type TEXT NOT NULL,
    effectiveness_rating INTEGER NOT NULL,
    notes TEXT,
    assessed_at TEXT NOT NULL
);
"""

# Indexes for query performance
ENGAGEMENT_DB_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target_id);
CREATE INDEX IF NOT EXISTS idx_evidence_type ON evidence(evidence_type);
CREATE INDEX IF NOT EXISTS idx_evidence_target ON evidence(target_id);
CREATE INDEX IF NOT EXISTS idx_evidence_finding_links_evidence ON evidence_finding_links(evidence_id);
CREATE INDEX IF NOT EXISTS idx_evidence_finding_links_finding ON evidence_finding_links(finding_id);
CREATE INDEX IF NOT EXISTS idx_notes_scope ON notes(scope_type, scope_id);
CREATE INDEX IF NOT EXISTS idx_notes_pinned ON notes(pinned);
CREATE INDEX IF NOT EXISTS idx_note_revisions_note ON note_revisions(note_id);
CREATE INDEX IF NOT EXISTS idx_attack_mappings_finding ON attack_mappings(finding_id);
CREATE INDEX IF NOT EXISTS idx_attack_mappings_technique ON attack_mappings(technique_id);
CREATE INDEX IF NOT EXISTS idx_retest_results_cycle ON retest_results(cycle_id);
CREATE INDEX IF NOT EXISTS idx_retest_results_finding ON retest_results(finding_id);
CREATE INDEX IF NOT EXISTS idx_timeline_action ON timeline_entries(action_type);
CREATE INDEX IF NOT EXISTS idx_timeline_timestamp ON timeline_entries(timestamp);
CREATE INDEX IF NOT EXISTS idx_physical_attempts_method ON physical_attempts(method);
CREATE INDEX IF NOT EXISTS idx_documents_type ON documents(document_type);
"""


class EngagementDatabase:
    """Manages a per-engagement isolated SQLite database.

    Each engagement has its own database file containing all engagement-specific
    data (findings, evidence, notes, etc.). This class handles schema creation,
    connection pooling via a thread-safe queue, and WAL mode for concurrent
    read/write support.

    Usage:
        db = EngagementDatabase(db_path)
        db.connect()
        db.create_schema()
        # ... use db ...
        db.close()
    """

    def __init__(self, db_path: str, pool_size: int = 5, timeout: int = 30):
        """Initialize the engagement database.

        Args:
            db_path: Path to the SQLite database file.
            pool_size: Number of connections to maintain in the pool.
            timeout: Connection timeout in seconds.
        """
        self.db_path = db_path
        self.pool_size = pool_size
        self.timeout = timeout
        self._pool: Queue = Queue(maxsize=pool_size)
        self._lock = threading.Lock()
        self._connected = False

    @property
    def connected(self) -> bool:
        """Whether the database connection pool is active."""
        return self._connected

    def connect(self) -> None:
        """Initialize the connection pool and enable WAL mode.

        Creates the database file's parent directories if they don't exist,
        then initializes a pool of SQLite connections with WAL journal mode
        and performance pragmas.

        Raises:
            sqlite3.Error: If the database cannot be opened or configured.
        """
        if self._connected:
            logger.debug(f"EngagementDatabase already connected: {self.db_path}")
            return

        # Ensure parent directory exists
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)

        try:
            for _ in range(self.pool_size):
                conn = self._create_connection()
                self._pool.put(conn)

            self._connected = True
            logger.info(f"EngagementDatabase connected: {self.db_path} (pool_size={self.pool_size})")
        except sqlite3.Error as e:
            logger.error(f"Failed to connect EngagementDatabase at {self.db_path}: {e}")
            raise

    def _create_connection(self) -> sqlite3.Connection:
        """Create a single configured SQLite connection.

        Returns:
            A sqlite3.Connection with WAL mode and performance pragmas enabled.
        """
        conn = sqlite3.connect(
            self.db_path,
            check_same_thread=False,
            timeout=self.timeout
        )
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA cache_size=10000")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def create_schema(self) -> None:
        """Create all tables and indexes for the engagement database.

        This is idempotent — safe to call on an existing database with
        CREATE TABLE IF NOT EXISTS semantics.

        Raises:
            RuntimeError: If the database is not connected.
            sqlite3.Error: If schema creation fails.
        """
        if not self._connected:
            raise RuntimeError("Database not connected. Call connect() first.")

        try:
            with self.get_connection() as conn:
                conn.executescript(ENGAGEMENT_DB_SCHEMA)
                conn.executescript(ENGAGEMENT_DB_INDEXES)
                conn.commit()
            logger.info(f"EngagementDatabase schema created: {self.db_path}")
        except sqlite3.Error as e:
            logger.error(f"Failed to create schema for {self.db_path}: {e}")
            raise

    @contextmanager
    def get_connection(self):
        """Get a connection from the pool (context manager).

        Yields a connection that is automatically returned to the pool when
        the context exits. If the pool is exhausted, creates a temporary
        connection that is closed after use.

        Yields:
            sqlite3.Connection: A database connection.

        Raises:
            RuntimeError: If the database is not connected.
        """
        if not self._connected:
            raise RuntimeError("Database not connected. Call connect() first.")

        conn = None
        from_pool = False
        try:
            conn = self._pool.get(timeout=5)
            from_pool = True
            yield conn
        except Empty:
            # Pool exhausted — create a temporary connection
            logger.debug(f"EngagementDatabase pool exhausted, creating temp connection: {self.db_path}")
            conn = self._create_connection()
            yield conn
        finally:
            if conn:
                if from_pool:
                    try:
                        self._pool.put_nowait(conn)
                    except Exception:
                        conn.close()
                else:
                    conn.close()

    def execute_query(self, query: str, params: tuple = ()) -> list:
        """Execute a read query and return all results.

        Args:
            query: SQL query string.
            params: Query parameters.

        Returns:
            List of rows as tuples.
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor.fetchall()

    def execute_write(self, query: str, params: tuple = ()) -> int:
        """Execute a write query and commit.

        Args:
            query: SQL statement (INSERT, UPDATE, DELETE).
            params: Query parameters.

        Returns:
            The lastrowid for INSERTs or rowcount for UPDATE/DELETE.
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            return cursor.lastrowid if cursor.lastrowid else cursor.rowcount

    def execute_many(self, query: str, params_list: list) -> int:
        """Execute a batch write operation.

        Args:
            query: SQL statement template.
            params_list: List of parameter tuples.

        Returns:
            Number of rows affected.
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.executemany(query, params_list)
            conn.commit()
            return cursor.rowcount

    def close(self) -> None:
        """Close all connections in the pool and mark as disconnected.

        Safe to call multiple times.
        """
        if not self._connected:
            return

        closed_count = 0
        while not self._pool.empty():
            try:
                conn = self._pool.get_nowait()
                conn.close()
                closed_count += 1
            except Empty:
                break

        self._connected = False
        logger.info(f"EngagementDatabase closed: {self.db_path} ({closed_count} connections)")
