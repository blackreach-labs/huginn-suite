# tests/test_evidence_manager.py
"""Tests for the evidence manager engine."""

import hashlib
import json
import zlib
import pytest

from app.core.engagement_database import EngagementDatabase
from app.core.evidence_manager import (
    EvidenceManager,
    EVIDENCE_TYPES,
    COMPRESSION_THRESHOLD,
)


@pytest.fixture
def engagement_db(tmp_path):
    """Create a temporary engagement database for testing."""
    db_path = str(tmp_path / "test_engagement.db")
    db = EngagementDatabase(db_path)
    db.connect()
    db.create_schema()
    yield db
    db.close()


@pytest.fixture
def evidence_manager(engagement_db):
    """Create an EvidenceManager with a connected database."""
    mgr = EvidenceManager()
    mgr.set_database(engagement_db)
    return mgr


@pytest.fixture
def sample_finding(engagement_db):
    """Insert a sample finding and return its ID."""
    finding_id = engagement_db.execute_write(
        """INSERT INTO findings (title, severity, created_at, updated_at)
           VALUES (?, ?, ?, ?)""",
        ("SQL Injection", "high", "2024-01-01T00:00:00", "2024-01-01T00:00:00"),
    )
    return finding_id


def _make_large_data(size: int = COMPRESSION_THRESHOLD + 1024) -> bytes:
    """Create test data larger than the compression threshold."""
    return b"A" * size


class TestEvidenceManagerSetup:
    """Tests for database configuration."""

    def test_no_database_raises(self):
        """Operations should raise RuntimeError if no database is set."""
        mgr = EvidenceManager()
        with pytest.raises(RuntimeError, match="No database set"):
            mgr.store_evidence("screenshot", b"data")

    def test_set_database(self, engagement_db):
        """set_database should configure the internal database reference."""
        mgr = EvidenceManager()
        assert mgr.database is None
        mgr.set_database(engagement_db)
        assert mgr.database is engagement_db


class TestStoreEvidence:
    """Tests for store_evidence()."""

    def test_store_basic_screenshot(self, evidence_manager):
        """Store a screenshot and verify it returns an ID."""
        data = b"PNG_IMAGE_DATA_BYTES"
        eid = evidence_manager.store_evidence(
            evidence_type="screenshot",
            data=data,
            title="Login Page",
            source_context="Browser capture",
            tags=["login", "auth"],
            mime_type="image/png",
        )
        assert isinstance(eid, int)
        assert eid > 0

    def test_store_all_evidence_types(self, evidence_manager):
        """All valid evidence types should store successfully."""
        for etype in EVIDENCE_TYPES:
            eid = evidence_manager.store_evidence(
                evidence_type=etype,
                data=b"test data",
                title=f"Test {etype}",
            )
            assert eid > 0

    def test_store_invalid_type_raises(self, evidence_manager):
        """Invalid evidence_type should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid evidence_type"):
            evidence_manager.store_evidence("invalid_type", b"data")

    def test_store_computes_sha256(self, evidence_manager, engagement_db):
        """Stored evidence should have correct SHA-256 hash."""
        data = b"test integrity data"
        eid = evidence_manager.store_evidence("text_snippet", data)

        rows = engagement_db.execute_query(
            "SELECT sha256_hash FROM evidence WHERE id = ?", (eid,)
        )
        expected_hash = hashlib.sha256(data).hexdigest()
        assert rows[0][0] == expected_hash

    def test_store_small_data_uncompressed(self, evidence_manager, engagement_db):
        """Data under 10MB should be stored uncompressed."""
        data = b"small data"
        eid = evidence_manager.store_evidence("text_snippet", data)

        rows = engagement_db.execute_query(
            "SELECT compressed, data FROM evidence WHERE id = ?", (eid,)
        )
        assert rows[0][0] == 0  # not compressed
        assert rows[0][1] == data

    def test_store_large_data_compressed(self, evidence_manager, engagement_db):
        """Data over 10MB should be compressed with zlib."""
        data = _make_large_data()
        eid = evidence_manager.store_evidence("file", data)

        rows = engagement_db.execute_query(
            "SELECT compressed, data FROM evidence WHERE id = ?", (eid,)
        )
        assert rows[0][0] == 1  # compressed
        # The stored data should be compressed
        assert rows[0][1] != data
        # But decompresses to original
        assert zlib.decompress(rows[0][1]) == data

    def test_store_sha256_on_original_data(self, evidence_manager, engagement_db):
        """SHA-256 should be computed on original (uncompressed) data."""
        data = _make_large_data()
        eid = evidence_manager.store_evidence("file", data)

        rows = engagement_db.execute_query(
            "SELECT sha256_hash FROM evidence WHERE id = ?", (eid,)
        )
        expected_hash = hashlib.sha256(data).hexdigest()
        assert rows[0][0] == expected_hash

    def test_store_with_target_id(self, evidence_manager, engagement_db):
        """target_id should be stored for categorization."""
        eid = evidence_manager.store_evidence(
            "screenshot", b"img", target_id=42
        )
        rows = engagement_db.execute_query(
            "SELECT target_id FROM evidence WHERE id = ?", (eid,)
        )
        assert rows[0][0] == 42

    def test_store_tags_as_json(self, evidence_manager, engagement_db):
        """Tags should be stored as a JSON array."""
        tags = ["critical", "web", "auth"]
        eid = evidence_manager.store_evidence(
            "text_snippet", b"data", tags=tags
        )
        rows = engagement_db.execute_query(
            "SELECT tags FROM evidence WHERE id = ?", (eid,)
        )
        assert json.loads(rows[0][0]) == tags

    def test_store_emits_signal(self, evidence_manager, qtbot):
        """evidence_stored signal should be emitted with the new ID."""
        with qtbot.waitSignal(evidence_manager.evidence_stored, timeout=1000) as blocker:
            eid = evidence_manager.store_evidence("screenshot", b"img")
        assert blocker.args == [eid]


class TestRetrieveEvidence:
    """Tests for retrieve_evidence()."""

    def test_retrieve_uncompressed(self, evidence_manager):
        """Retrieve should return original data for small evidence."""
        data = b"test retrieve data"
        eid = evidence_manager.store_evidence("text_snippet", data)
        retrieved = evidence_manager.retrieve_evidence(eid)
        assert retrieved == data

    def test_retrieve_compressed(self, evidence_manager):
        """Retrieve should decompress data transparently for large evidence."""
        data = _make_large_data()
        eid = evidence_manager.store_evidence("file", data)
        retrieved = evidence_manager.retrieve_evidence(eid)
        assert retrieved == data

    def test_retrieve_nonexistent_raises(self, evidence_manager):
        """Retrieving a non-existent ID should raise ValueError."""
        with pytest.raises(ValueError, match="not found"):
            evidence_manager.retrieve_evidence(99999)


class TestAnnotations:
    """Tests for add_annotation()."""

    def test_add_annotation(self, evidence_manager):
        """Adding an annotation should persist it in the annotations field."""
        eid = evidence_manager.store_evidence("screenshot", b"img_data")

        evidence_manager.add_annotation(
            eid,
            annotation_type="rectangle",
            coordinates={"x": 10, "y": 20, "width": 100, "height": 50},
            properties={"color": "red", "thickness": 2},
        )

        meta = evidence_manager.get_evidence_metadata(eid)
        assert len(meta["annotations"]) == 1
        ann = meta["annotations"][0]
        assert ann["annotation_type"] == "rectangle"
        assert ann["coordinates"] == {"x": 10, "y": 20, "width": 100, "height": 50}
        assert ann["properties"]["color"] == "red"

    def test_multiple_annotations(self, evidence_manager):
        """Multiple annotations should accumulate without overwriting."""
        eid = evidence_manager.store_evidence("screenshot", b"img_data")

        evidence_manager.add_annotation(eid, "rectangle", {"x": 0, "y": 0, "width": 50, "height": 50})
        evidence_manager.add_annotation(eid, "arrow", {"x1": 10, "y1": 10, "x2": 90, "y2": 90})
        evidence_manager.add_annotation(eid, "text_label", {"x": 50, "y": 50}, {"text": "XSS here"})

        meta = evidence_manager.get_evidence_metadata(eid)
        assert len(meta["annotations"]) == 3

    def test_annotation_does_not_modify_data(self, evidence_manager):
        """Annotations must not modify the original evidence data."""
        original_data = b"ORIGINAL_IMAGE_BYTES_12345"
        eid = evidence_manager.store_evidence("screenshot", original_data)

        evidence_manager.add_annotation(eid, "rectangle", {"x": 0, "y": 0, "width": 10, "height": 10})
        evidence_manager.add_annotation(eid, "redaction", {"x": 5, "y": 5, "width": 20, "height": 20})

        retrieved = evidence_manager.retrieve_evidence(eid)
        assert retrieved == original_data

    def test_annotation_nonexistent_raises(self, evidence_manager):
        """Annotating non-existent evidence should raise ValueError."""
        with pytest.raises(ValueError, match="not found"):
            evidence_manager.add_annotation(99999, "rectangle", {"x": 0, "y": 0})


class TestFindingLinkage:
    """Tests for evidence-to-finding linking."""

    def test_link_to_finding(self, evidence_manager, sample_finding, engagement_db):
        """link_to_finding should create a link record."""
        eid = evidence_manager.store_evidence("screenshot", b"img")
        evidence_manager.link_to_finding(eid, sample_finding)

        rows = engagement_db.execute_query(
            "SELECT * FROM evidence_finding_links WHERE evidence_id = ? AND finding_id = ?",
            (eid, sample_finding),
        )
        assert len(rows) == 1

    def test_link_emits_signal(self, evidence_manager, sample_finding, qtbot):
        """evidence_linked signal should be emitted on successful link."""
        eid = evidence_manager.store_evidence("screenshot", b"img")
        with qtbot.waitSignal(evidence_manager.evidence_linked, timeout=1000) as blocker:
            evidence_manager.link_to_finding(eid, sample_finding)
        assert blocker.args == [eid, sample_finding]

    def test_link_idempotent(self, evidence_manager, sample_finding, engagement_db):
        """Linking the same pair twice should not raise or duplicate."""
        eid = evidence_manager.store_evidence("screenshot", b"img")
        evidence_manager.link_to_finding(eid, sample_finding)
        evidence_manager.link_to_finding(eid, sample_finding)  # second call

        rows = engagement_db.execute_query(
            "SELECT COUNT(*) FROM evidence_finding_links WHERE evidence_id = ? AND finding_id = ?",
            (eid, sample_finding),
        )
        assert rows[0][0] == 1

    def test_get_evidence_for_finding(self, evidence_manager, sample_finding):
        """Should return all evidence linked to a finding."""
        eid1 = evidence_manager.store_evidence("screenshot", b"img1", title="Screenshot 1")
        eid2 = evidence_manager.store_evidence("text_snippet", b"text", title="Snippet")
        evidence_manager.link_to_finding(eid1, sample_finding)
        evidence_manager.link_to_finding(eid2, sample_finding)

        evidence_list = evidence_manager.get_evidence_for_finding(sample_finding)
        assert len(evidence_list) == 2
        ids = {e["id"] for e in evidence_list}
        assert eid1 in ids
        assert eid2 in ids

    def test_get_findings_for_evidence(self, evidence_manager, engagement_db):
        """Should return all findings linked to evidence."""
        eid = evidence_manager.store_evidence("screenshot", b"img")

        # Create two findings
        fid1 = engagement_db.execute_write(
            "INSERT INTO findings (title, severity, created_at, updated_at) VALUES (?, ?, ?, ?)",
            ("Finding 1", "high", "2024-01-01", "2024-01-01"),
        )
        fid2 = engagement_db.execute_write(
            "INSERT INTO findings (title, severity, created_at, updated_at) VALUES (?, ?, ?, ?)",
            ("Finding 2", "medium", "2024-01-02", "2024-01-02"),
        )

        evidence_manager.link_to_finding(eid, fid1)
        evidence_manager.link_to_finding(eid, fid2)

        findings = evidence_manager.get_findings_for_evidence(eid)
        assert len(findings) == 2
        ids = {f["id"] for f in findings}
        assert fid1 in ids
        assert fid2 in ids

    def test_unlink_from_finding(self, evidence_manager, sample_finding, engagement_db):
        """unlink_from_finding should remove the link."""
        eid = evidence_manager.store_evidence("screenshot", b"img")
        evidence_manager.link_to_finding(eid, sample_finding)
        evidence_manager.unlink_from_finding(eid, sample_finding)

        rows = engagement_db.execute_query(
            "SELECT COUNT(*) FROM evidence_finding_links WHERE evidence_id = ? AND finding_id = ?",
            (eid, sample_finding),
        )
        assert rows[0][0] == 0


class TestFindingDeletion:
    """Tests for on_finding_deleted() behavior."""

    def test_finding_deleted_retains_evidence(self, evidence_manager, sample_finding, engagement_db):
        """Evidence should be retained after its finding is deleted."""
        data = b"important_evidence"
        eid = evidence_manager.store_evidence("screenshot", data)
        evidence_manager.link_to_finding(eid, sample_finding)

        # Delete finding links (simulating finding deletion)
        evidence_manager.on_finding_deleted(sample_finding)

        # Links should be gone
        links = engagement_db.execute_query(
            "SELECT COUNT(*) FROM evidence_finding_links WHERE finding_id = ?",
            (sample_finding,),
        )
        assert links[0][0] == 0

        # But evidence still exists and is retrievable
        retrieved = evidence_manager.retrieve_evidence(eid)
        assert retrieved == data

    def test_finding_deleted_multiple_evidence(self, evidence_manager, sample_finding, engagement_db):
        """All links for a deleted finding should be removed."""
        eid1 = evidence_manager.store_evidence("screenshot", b"img1")
        eid2 = evidence_manager.store_evidence("text_snippet", b"text")
        evidence_manager.link_to_finding(eid1, sample_finding)
        evidence_manager.link_to_finding(eid2, sample_finding)

        evidence_manager.on_finding_deleted(sample_finding)

        # Both evidence items still exist
        assert evidence_manager.retrieve_evidence(eid1) == b"img1"
        assert evidence_manager.retrieve_evidence(eid2) == b"text"

        # No links remain
        links = engagement_db.execute_query(
            "SELECT COUNT(*) FROM evidence_finding_links WHERE finding_id = ?",
            (sample_finding,),
        )
        assert links[0][0] == 0


class TestTaggingAndCategorization:
    """Tests for tagging and target-based categorization."""

    def test_get_evidence_by_target(self, evidence_manager):
        """Should filter evidence by target_id."""
        eid1 = evidence_manager.store_evidence("screenshot", b"img1", target_id=10)
        eid2 = evidence_manager.store_evidence("screenshot", b"img2", target_id=10)
        evidence_manager.store_evidence("screenshot", b"img3", target_id=20)

        results = evidence_manager.get_evidence_by_target(10)
        assert len(results) == 2
        ids = {r["id"] for r in results}
        assert eid1 in ids
        assert eid2 in ids

    def test_get_evidence_by_tag(self, evidence_manager):
        """Should filter evidence by tag."""
        eid1 = evidence_manager.store_evidence("screenshot", b"img1", tags=["web", "auth"])
        eid2 = evidence_manager.store_evidence("text_snippet", b"txt", tags=["web", "sqli"])
        evidence_manager.store_evidence("file", b"file", tags=["network"])

        results = evidence_manager.get_evidence_by_tag("web")
        assert len(results) == 2
        ids = {r["id"] for r in results}
        assert eid1 in ids
        assert eid2 in ids


class TestIntegrityVerification:
    """Tests for verify_integrity()."""

    def test_integrity_valid(self, evidence_manager):
        """Integrity check should pass for unmodified evidence."""
        data = b"pristine evidence data"
        eid = evidence_manager.store_evidence("text_snippet", data)
        assert evidence_manager.verify_integrity(eid) is True

    def test_integrity_valid_compressed(self, evidence_manager):
        """Integrity check should pass for compressed evidence."""
        data = _make_large_data()
        eid = evidence_manager.store_evidence("file", data)
        assert evidence_manager.verify_integrity(eid) is True

    def test_integrity_nonexistent_raises(self, evidence_manager):
        """Verifying non-existent evidence should raise."""
        with pytest.raises(ValueError, match="not found"):
            evidence_manager.verify_integrity(99999)


class TestGetMetadata:
    """Tests for get_evidence_metadata()."""

    def test_metadata_fields(self, evidence_manager):
        """Metadata should contain all expected fields."""
        eid = evidence_manager.store_evidence(
            "http_pair",
            b"request\nresponse",
            title="Login Request",
            source_context="Burp Proxy",
            tags=["auth", "session"],
            mime_type="text/plain",
            target_id=5,
        )

        meta = evidence_manager.get_evidence_metadata(eid)
        assert meta["id"] == eid
        assert meta["evidence_type"] == "http_pair"
        assert meta["title"] == "Login Request"
        assert meta["sha256_hash"] == hashlib.sha256(b"request\nresponse").hexdigest()
        assert meta["mime_type"] == "text/plain"
        assert meta["source_context"] == "Burp Proxy"
        assert meta["tags"] == ["auth", "session"]
        assert meta["target_id"] == 5
        assert meta["annotations"] == []
        assert meta["compressed"] is False

    def test_metadata_nonexistent_raises(self, evidence_manager):
        """Getting metadata for non-existent ID should raise."""
        with pytest.raises(ValueError, match="not found"):
            evidence_manager.get_evidence_metadata(99999)
