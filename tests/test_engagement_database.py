# tests/test_engagement_database.py
"""Tests for the engagement database module."""

import tempfile
import os
import sqlite3
import pytest
from pathlib import Path

from app.core.engagement_database import (
    EngagementDatabase,
    ENGAGEMENT_DB_SCHEMA,
    ENGAGEMENT_DB_INDEXES,
)


REQUIRED_TABLES = [
    "engagement_meta",
    "rules_of_engagement",
    "client_contacts",
    "documents",
    "milestones",
    "findings",
    "evidence",
    "evidence_finding_links",
    "notes",
    "note_revisions",
    "attack_mappings",
    "retest_cycles",
    "retest_results",
    "timeline_entries",
    "physical_attempts",
    "site_annotations",
    "physical_control_ratings",
]


@pytest.fixture
def tmp_db(tmp_path):
    """Create a temporary engagement database for testing."""
    db_path = str(tmp_path / "engagement.db")
    db = EngagementDatabase(db_path)
    db.connect()
    db.create_schema()
    yield db
    db.close()


class TestEngagementDatabaseSchema:
    """Tests verifying the schema contains all required tables."""

    def test_schema_contains_all_required_tables(self):
        """All 17 per-engagement tables must appear in the schema string."""
        for table in REQUIRED_TABLES:
            assert table in ENGAGEMENT_DB_SCHEMA, f"Missing table: {table}"

    def test_schema_table_count(self):
        """Schema should define exactly 17 tables."""
        count = ENGAGEMENT_DB_SCHEMA.count("CREATE TABLE IF NOT EXISTS")
        assert count == 17


class TestEngagementDatabaseConnection:
    """Tests for connect/close lifecycle."""

    def test_connect_creates_directory_and_file(self, tmp_path):
        """connect() should create parent dirs and the db file."""
        db_path = str(tmp_path / "nested" / "dir" / "engagement.db")
        db = EngagementDatabase(db_path)

        assert not db.connected
        db.connect()

        assert db.connected
        assert os.path.exists(db_path)
        db.close()

    def test_connect_idempotent(self, tmp_db):
        """Calling connect() when already connected is a no-op."""
        tmp_db.connect()  # second call
        assert tmp_db.connected

    def test_close_marks_disconnected(self, tmp_path):
        """close() should mark database as not connected."""
        db_path = str(tmp_path / "engagement.db")
        db = EngagementDatabase(db_path)
        db.connect()
        assert db.connected

        db.close()
        assert not db.connected

    def test_close_idempotent(self, tmp_path):
        """Calling close() multiple times should not raise."""
        db_path = str(tmp_path / "engagement.db")
        db = EngagementDatabase(db_path)
        db.connect()
        db.close()
        db.close()  # should not raise

    def test_wal_mode_enabled(self, tmp_db):
        """WAL journal mode must be active on all pool connections."""
        result = tmp_db.execute_query("PRAGMA journal_mode")
        assert result[0][0] == "wal"

    def test_foreign_keys_enabled(self, tmp_db):
        """Foreign key enforcement must be active."""
        result = tmp_db.execute_query("PRAGMA foreign_keys")
        assert result[0][0] == 1


class TestEngagementDatabaseSchemaCreation:
    """Tests verifying create_schema() produces all expected objects."""

    def test_all_tables_created(self, tmp_db):
        """All required tables should exist after create_schema()."""
        tables = tmp_db.execute_query(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        table_names = [t[0] for t in tables]
        for table in REQUIRED_TABLES:
            assert table in table_names, f"Table {table} not created"

    def test_indexes_created(self, tmp_db):
        """Performance indexes should be created."""
        indexes = tmp_db.execute_query(
            "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'"
        )
        assert len(indexes) >= 15  # We define 17 indexes

    def test_create_schema_idempotent(self, tmp_db):
        """Calling create_schema() twice should not raise."""
        tmp_db.create_schema()  # second call should be fine

    def test_create_schema_requires_connection(self, tmp_path):
        """create_schema() should raise RuntimeError if not connected."""
        db_path = str(tmp_path / "engagement.db")
        db = EngagementDatabase(db_path)

        with pytest.raises(RuntimeError, match="not connected"):
            db.create_schema()


class TestEngagementDatabaseOperations:
    """Tests for read/write operations."""

    def test_execute_write_and_query(self, tmp_db):
        """Basic write followed by read should round-trip correctly."""
        tmp_db.execute_write(
            "INSERT INTO engagement_meta (key, value) VALUES (?, ?)",
            ("name", "Test Engagement"),
        )
        result = tmp_db.execute_query(
            "SELECT value FROM engagement_meta WHERE key = ?", ("name",)
        )
        assert result[0][0] == "Test Engagement"

    def test_execute_many(self, tmp_db):
        """Batch insert should work correctly."""
        contacts = [
            ("Alice", "Lead", "alice@test.com", "555-0001", None, "2024-01-01T00:00:00"),
            ("Bob", "Support", "bob@test.com", "555-0002", None, "2024-01-01T00:00:00"),
        ]
        tmp_db.execute_many(
            "INSERT INTO client_contacts (name, role, email, phone, availability_window, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            contacts,
        )
        result = tmp_db.execute_query("SELECT COUNT(*) FROM client_contacts")
        assert result[0][0] == 2

    def test_get_connection_context_manager(self, tmp_db):
        """get_connection() should yield a usable connection."""
        with tmp_db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            assert cursor.fetchone()[0] == 1

    def test_operations_require_connection(self, tmp_path):
        """Operations should raise RuntimeError if not connected."""
        db_path = str(tmp_path / "engagement.db")
        db = EngagementDatabase(db_path)

        with pytest.raises(RuntimeError, match="not connected"):
            db.execute_query("SELECT 1")

        with pytest.raises(RuntimeError, match="not connected"):
            db.execute_write("INSERT INTO engagement_meta VALUES (?, ?)", ("k", "v"))

    def test_foreign_key_enforcement(self, tmp_db):
        """Foreign keys should be enforced (e.g., evidence_finding_links)."""
        # Insert a valid finding first
        tmp_db.execute_write(
            "INSERT INTO findings (title, severity, created_at, updated_at) "
            "VALUES (?, ?, ?, ?)",
            ("Test Finding", "high", "2024-01-01", "2024-01-01"),
        )
        # Try to link to non-existent evidence — should fail
        with pytest.raises(sqlite3.IntegrityError):
            tmp_db.execute_write(
                "INSERT INTO evidence_finding_links (evidence_id, finding_id, linked_at) "
                "VALUES (?, ?, ?)",
                (999, 1, "2024-01-01"),
            )
