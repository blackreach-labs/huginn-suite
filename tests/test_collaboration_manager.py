# tests/test_collaboration_manager.py
"""Tests for the collaboration manager engine."""

import hashlib
import io
import json
import os
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.core.collaboration_manager import CollaborationManager, HUGINN_VERSION
from app.core.engagement_database import EngagementDatabase
from app.core.engagement_manager import EngagementManager


@pytest.fixture
def tmp_engagement(tmp_path):
    """Create a temporary engagement directory with DB, evidence, and documents."""
    eng_id = "test-engagement-001"
    eng_dir = tmp_path / "engagements" / eng_id
    eng_dir.mkdir(parents=True)

    # Create engagement database
    db_path = eng_dir / "engagement.db"
    db = EngagementDatabase(str(db_path))
    db.connect()
    db.create_schema()

    # Insert a sample finding
    db.execute_write(
        """INSERT INTO findings (title, severity, description, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?)""",
        ("SQL Injection", "high", "Found SQLi in login", "2024-01-01", "2024-01-01"),
    )
    db.close()

    # Create evidence directory with files
    evidence_dir = eng_dir / "evidence"
    evidence_dir.mkdir()
    (evidence_dir / "1").write_bytes(b"screenshot_data_001")
    (evidence_dir / "2").write_bytes(b"screenshot_data_002")
    (evidence_dir / "3").write_bytes(b"screenshot_data_003")

    # Create documents directory with files
    documents_dir = eng_dir / "documents"
    documents_dir.mkdir()
    (documents_dir / "scope.pdf").write_bytes(b"PDF_SCOPE_DOC_DATA")
    (documents_dir / "roe.docx").write_bytes(b"ROE_DOCUMENT_DATA")

    return {
        "id": eng_id,
        "path": eng_dir,
        "db_path": db_path,
        "evidence_dir": evidence_dir,
        "documents_dir": documents_dir,
    }


@pytest.fixture
def engagement_manager(tmp_path):
    """Create a real EngagementManager with a temp master DB."""
    master_db = str(tmp_path / "resources" / "huginn_master_index.db")
    mgr = EngagementManager(master_db_path=master_db)
    return mgr


@pytest.fixture
def collab_manager(engagement_manager):
    """Create a CollaborationManager with an engagement manager."""
    mgr = CollaborationManager(engagement_manager=engagement_manager)
    return mgr


@pytest.fixture
def collab_manager_no_em():
    """Create a CollaborationManager without an engagement manager."""
    return CollaborationManager()


class TestKeyDerivation:
    """Tests for _derive_key()."""

    def test_derive_key_returns_32_bytes(self, collab_manager):
        """Key derivation should produce a 32-byte key."""
        salt = os.urandom(16)
        key = collab_manager._derive_key("test_passphrase", salt)
        assert len(key) == 32

    def test_derive_key_deterministic(self, collab_manager):
        """Same passphrase + salt should produce the same key."""
        salt = b"\x00" * 16
        key1 = collab_manager._derive_key("password123", salt)
        key2 = collab_manager._derive_key("password123", salt)
        assert key1 == key2

    def test_derive_key_different_salt(self, collab_manager):
        """Different salts should produce different keys."""
        key1 = collab_manager._derive_key("password", b"\x00" * 16)
        key2 = collab_manager._derive_key("password", b"\x01" * 16)
        assert key1 != key2

    def test_derive_key_different_passphrase(self, collab_manager):
        """Different passphrases should produce different keys."""
        salt = b"\x00" * 16
        key1 = collab_manager._derive_key("password_a", salt)
        key2 = collab_manager._derive_key("password_b", salt)
        assert key1 != key2


class TestManifest:
    """Tests for manifest creation and validation."""

    def test_create_manifest_structure(self, collab_manager, tmp_path):
        """Manifest should contain required metadata fields."""
        # Create a test file
        test_file = tmp_path / "test.db"
        test_file.write_bytes(b"database_content")

        files = [("engagement.db", str(test_file))]
        manifest = collab_manager._create_manifest(files, "eng-123")

        assert manifest["huginn_version"] == HUGINN_VERSION
        assert "export_date" in manifest
        assert manifest["source_engagement_id"] == "eng-123"
        assert manifest["file_count"] == 1
        assert len(manifest["files"]) == 1
        assert manifest["files"][0]["path"] == "engagement.db"
        assert manifest["files"][0]["sha256"] == hashlib.sha256(b"database_content").hexdigest()
        assert manifest["files"][0]["size"] == len(b"database_content")

    def test_create_manifest_multiple_files(self, collab_manager, tmp_path):
        """Manifest should include entries for all exported files."""
        f1 = tmp_path / "a.txt"
        f2 = tmp_path / "b.txt"
        f1.write_bytes(b"aaa")
        f2.write_bytes(b"bbb")

        files = [("a.txt", str(f1)), ("b.txt", str(f2))]
        manifest = collab_manager._create_manifest(files, "eng-456")

        assert manifest["file_count"] == 2
        paths = [entry["path"] for entry in manifest["files"]]
        assert "a.txt" in paths
        assert "b.txt" in paths

    def test_create_manifest_selective_export_metadata(self, collab_manager, tmp_path):
        """Manifest should record selective export parameters."""
        f = tmp_path / "db.sqlite"
        f.write_bytes(b"data")

        manifest = collab_manager._create_manifest(
            [("db.sqlite", str(f))],
            "eng-789",
            selected_findings=[1, 2, 3],
            selected_evidence=[10, 20],
        )

        assert manifest["selective_export"]["findings"] == [1, 2, 3]
        assert manifest["selective_export"]["evidence"] == [10, 20]

    def test_validate_manifest_valid(self, collab_manager, tmp_path):
        """Validation should pass when all checksums match."""
        content_a = b"file_a_content"
        content_b = b"file_b_content"

        # Create a ZIP with matching contents
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("a.txt", content_a)
            zf.writestr("b.txt", content_b)

        manifest = {
            "files": [
                {"path": "a.txt", "sha256": hashlib.sha256(content_a).hexdigest(), "size": len(content_a)},
                {"path": "b.txt", "sha256": hashlib.sha256(content_b).hexdigest(), "size": len(content_b)},
            ]
        }

        zip_buffer.seek(0)
        with zipfile.ZipFile(zip_buffer, "r") as zf:
            assert collab_manager._validate_manifest(manifest, zf) is True

    def test_validate_manifest_checksum_mismatch(self, collab_manager):
        """Validation should fail on checksum mismatch."""
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("a.txt", b"actual_content")

        manifest = {
            "files": [
                {"path": "a.txt", "sha256": "0000000000000000000000000000000000000000000000000000000000000000", "size": 14},
            ]
        }

        zip_buffer.seek(0)
        with zipfile.ZipFile(zip_buffer, "r") as zf:
            assert collab_manager._validate_manifest(manifest, zf) is False

    def test_validate_manifest_missing_file(self, collab_manager):
        """Validation should fail if a manifest file is missing from the archive."""
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("a.txt", b"content")

        manifest = {
            "files": [
                {"path": "a.txt", "sha256": hashlib.sha256(b"content").hexdigest(), "size": 7},
                {"path": "b.txt", "sha256": "abc123", "size": 5},
            ]
        }

        zip_buffer.seek(0)
        with zipfile.ZipFile(zip_buffer, "r") as zf:
            assert collab_manager._validate_manifest(manifest, zf) is False

    def test_validate_manifest_empty_files(self, collab_manager):
        """Validation should fail if manifest has no file entries."""
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("dummy.txt", b"x")

        manifest = {"files": []}

        zip_buffer.seek(0)
        with zipfile.ZipFile(zip_buffer, "r") as zf:
            assert collab_manager._validate_manifest(manifest, zf) is False


class TestExportEngagement:
    """Tests for export_engagement()."""

    def test_export_creates_file(self, collab_manager, tmp_engagement, tmp_path):
        """Export should create an encrypted file at the output path."""
        output = str(tmp_path / "output" / "test.huginn")
        result = collab_manager.export_engagement(
            engagement_id=tmp_engagement["id"],
            passphrase="test_password",
            output_path=output,
            engagement_base_path=str(tmp_engagement["path"]),
        )
        assert result is True
        assert Path(output).exists()
        assert Path(output).stat().st_size > 0

    def test_export_file_structure(self, collab_manager, tmp_engagement, tmp_path):
        """Exported file should contain salt (16) + nonce (12) + ciphertext."""
        output = str(tmp_path / "export.huginn")
        collab_manager.export_engagement(
            engagement_id=tmp_engagement["id"],
            passphrase="password",
            output_path=output,
            engagement_base_path=str(tmp_engagement["path"]),
        )

        data = Path(output).read_bytes()
        # Minimum: 16 (salt) + 12 (nonce) + some ciphertext
        assert len(data) > 28

    def test_export_nonexistent_engagement(self, collab_manager, tmp_path):
        """Export should return False if engagement directory doesn't exist."""
        output = str(tmp_path / "fail.huginn")
        result = collab_manager.export_engagement(
            engagement_id="nonexistent",
            passphrase="password",
            output_path=output,
            engagement_base_path=str(tmp_path / "nonexistent"),
        )
        assert result is False

    def test_export_emits_progress(self, collab_manager, tmp_engagement, tmp_path, qtbot):
        """Export should emit progress signals."""
        output = str(tmp_path / "progress.huginn")
        progress_values = []

        def on_progress(current, total):
            progress_values.append((current, total))

        collab_manager.export_progress.connect(on_progress)

        collab_manager.export_engagement(
            engagement_id=tmp_engagement["id"],
            passphrase="password",
            output_path=output,
            engagement_base_path=str(tmp_engagement["path"]),
        )

        assert len(progress_values) > 0
        # Last progress should be complete
        last = progress_values[-1]
        assert last[0] == last[1]

    def test_export_selective_evidence(self, collab_manager, tmp_engagement, tmp_path):
        """Selective export should only include chosen evidence files."""
        output = str(tmp_path / "selective.huginn")
        collab_manager.export_engagement(
            engagement_id=tmp_engagement["id"],
            passphrase="password",
            output_path=output,
            engagement_base_path=str(tmp_engagement["path"]),
            selected_evidence=[1],  # Only include evidence file "1"
        )

        # Decrypt and check contents
        data = Path(output).read_bytes()
        salt = data[:16]
        nonce = data[16:28]
        ciphertext = data[28:]

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        key = collab_manager._derive_key("password", salt)
        aesgcm = AESGCM(key)
        zip_data = aesgcm.decrypt(nonce, ciphertext, None)

        with zipfile.ZipFile(io.BytesIO(zip_data), "r") as zf:
            names = zf.namelist()
            evidence_files = [n for n in names if n.startswith("evidence/")]
            assert "evidence/1" in evidence_files
            assert "evidence/2" not in evidence_files
            assert "evidence/3" not in evidence_files


class TestImportEngagement:
    """Tests for import_engagement()."""

    def _create_test_package(self, collab_manager, tmp_engagement, tmp_path, passphrase="test_pass"):
        """Helper to create an encrypted package for import tests."""
        output = str(tmp_path / "package.huginn")
        collab_manager.export_engagement(
            engagement_id=tmp_engagement["id"],
            passphrase=passphrase,
            output_path=output,
            engagement_base_path=str(tmp_engagement["path"]),
        )
        return output

    def test_import_round_trip(self, collab_manager, tmp_engagement, tmp_path):
        """Export then import should produce a new valid engagement."""
        package_path = self._create_test_package(
            collab_manager, tmp_engagement, tmp_path
        )
        import_dir = tmp_path / "import_base"
        import_dir.mkdir()

        new_id = collab_manager.import_engagement(
            package_path=package_path,
            passphrase="test_pass",
            engagements_base_path=str(import_dir),
        )

        assert new_id is not None
        assert new_id != tmp_engagement["id"]  # New ID assigned

        # Verify files were extracted
        new_eng_dir = import_dir / new_id
        assert (new_eng_dir / "engagement.db").exists()
        assert (new_eng_dir / "evidence").exists()
        assert (new_eng_dir / "documents").exists()

    def test_import_preserves_db_content(self, collab_manager, tmp_engagement, tmp_path):
        """Imported engagement DB should have the same data as the original."""
        package_path = self._create_test_package(
            collab_manager, tmp_engagement, tmp_path
        )
        import_dir = tmp_path / "import_base"
        import_dir.mkdir()

        new_id = collab_manager.import_engagement(
            package_path=package_path,
            passphrase="test_pass",
            engagements_base_path=str(import_dir),
        )

        # Open imported DB and verify finding exists
        imported_db_path = str(import_dir / new_id / "engagement.db")
        db = EngagementDatabase(imported_db_path)
        db.connect()
        findings = db.execute_query("SELECT title, severity FROM findings")
        db.close()

        assert len(findings) == 1
        assert findings[0][0] == "SQL Injection"
        assert findings[0][1] == "high"

    def test_import_preserves_evidence_files(self, collab_manager, tmp_engagement, tmp_path):
        """Imported evidence files should match the originals."""
        package_path = self._create_test_package(
            collab_manager, tmp_engagement, tmp_path
        )
        import_dir = tmp_path / "import_base"
        import_dir.mkdir()

        new_id = collab_manager.import_engagement(
            package_path=package_path,
            passphrase="test_pass",
            engagements_base_path=str(import_dir),
        )

        # Verify evidence content
        ev1 = (import_dir / new_id / "evidence" / "1").read_bytes()
        assert ev1 == b"screenshot_data_001"

    def test_import_wrong_passphrase_rejected(self, collab_manager, tmp_engagement, tmp_path):
        """Wrong passphrase should return None immediately."""
        package_path = self._create_test_package(
            collab_manager, tmp_engagement, tmp_path, passphrase="correct"
        )
        import_dir = tmp_path / "import_base"
        import_dir.mkdir()

        result = collab_manager.import_engagement(
            package_path=package_path,
            passphrase="wrong_passphrase",
            engagements_base_path=str(import_dir),
        )

        assert result is None
        # Verify no partial extraction occurred
        entries = list(import_dir.iterdir())
        assert len(entries) == 0

    def test_import_assigns_new_id(self, collab_manager, tmp_engagement, tmp_path):
        """Each import should get a unique engagement ID."""
        package_path = self._create_test_package(
            collab_manager, tmp_engagement, tmp_path
        )
        import_dir = tmp_path / "import_base"
        import_dir.mkdir()

        id1 = collab_manager.import_engagement(
            package_path=package_path,
            passphrase="test_pass",
            engagements_base_path=str(import_dir),
        )
        id2 = collab_manager.import_engagement(
            package_path=package_path,
            passphrase="test_pass",
            engagements_base_path=str(import_dir),
        )

        assert id1 is not None
        assert id2 is not None
        assert id1 != id2

    def test_import_emits_progress(self, collab_manager, tmp_engagement, tmp_path, qtbot):
        """Import should emit progress signals."""
        package_path = self._create_test_package(
            collab_manager, tmp_engagement, tmp_path
        )
        import_dir = tmp_path / "import_base"
        import_dir.mkdir()

        progress_values = []

        def on_progress(current, total):
            progress_values.append((current, total))

        collab_manager.import_progress.connect(on_progress)

        collab_manager.import_engagement(
            package_path=package_path,
            passphrase="test_pass",
            engagements_base_path=str(import_dir),
        )

        assert len(progress_values) > 0
        last = progress_values[-1]
        assert last[0] == last[1]

    def test_import_invalid_file(self, collab_manager, tmp_path):
        """Import of a non-package file should return None."""
        bad_file = tmp_path / "not_a_package.huginn"
        bad_file.write_bytes(b"this is not encrypted data")

        import_dir = tmp_path / "import_base"
        import_dir.mkdir()

        result = collab_manager.import_engagement(
            package_path=str(bad_file),
            passphrase="anything",
            engagements_base_path=str(import_dir),
        )
        assert result is None

    def test_import_registers_in_master_index(
        self, collab_manager, tmp_engagement, tmp_path
    ):
        """Import with engagement_manager should register in master index."""
        package_path = self._create_test_package(
            collab_manager, tmp_engagement, tmp_path
        )
        import_dir = tmp_path / "import_base"
        import_dir.mkdir()

        new_id = collab_manager.import_engagement(
            package_path=package_path,
            passphrase="test_pass",
            engagements_base_path=str(import_dir),
        )

        assert new_id is not None
        # Verify it's in the master index
        engagement = collab_manager.engagement_manager.get_engagement(new_id)
        assert engagement is not None
        assert engagement["id"] == new_id
        assert engagement["status"] == "draft"


class TestSelectiveExport:
    """Tests for selective export with finding/evidence filtering."""

    def test_full_export_includes_all(self, collab_manager, tmp_engagement, tmp_path):
        """Full export (no selection) should include all files."""
        output = str(tmp_path / "full.huginn")
        collab_manager.export_engagement(
            engagement_id=tmp_engagement["id"],
            passphrase="pass",
            output_path=output,
            engagement_base_path=str(tmp_engagement["path"]),
        )

        # Decrypt and check
        data = Path(output).read_bytes()
        key = collab_manager._derive_key("pass", data[:16])
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        aesgcm = AESGCM(key)
        zip_data = aesgcm.decrypt(data[16:28], data[28:], None)

        with zipfile.ZipFile(io.BytesIO(zip_data), "r") as zf:
            names = zf.namelist()
            assert "engagement.db" in names
            assert "manifest.json" in names
            assert "evidence/1" in names
            assert "evidence/2" in names
            assert "evidence/3" in names
            assert "documents/scope.pdf" in names
            assert "documents/roe.docx" in names

    def test_selective_evidence_excludes_unselected(
        self, collab_manager, tmp_engagement, tmp_path
    ):
        """Selective export should exclude non-selected evidence."""
        output = str(tmp_path / "selective.huginn")
        collab_manager.export_engagement(
            engagement_id=tmp_engagement["id"],
            passphrase="pass",
            output_path=output,
            engagement_base_path=str(tmp_engagement["path"]),
            selected_evidence=[2, 3],
        )

        data = Path(output).read_bytes()
        key = collab_manager._derive_key("pass", data[:16])
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        aesgcm = AESGCM(key)
        zip_data = aesgcm.decrypt(data[16:28], data[28:], None)

        with zipfile.ZipFile(io.BytesIO(zip_data), "r") as zf:
            names = zf.namelist()
            evidence_files = [n for n in names if n.startswith("evidence/")]
            assert "evidence/2" in evidence_files
            assert "evidence/3" in evidence_files
            assert "evidence/1" not in evidence_files
            # DB and documents should still be present
            assert "engagement.db" in names
            assert "documents/scope.pdf" in names


class TestManifestIntegrity:
    """Tests for end-to-end manifest integrity validation."""

    def test_manifest_checksums_match_files(self, collab_manager, tmp_engagement, tmp_path):
        """All manifest checksums should match actual file contents."""
        output = str(tmp_path / "integrity.huginn")
        collab_manager.export_engagement(
            engagement_id=tmp_engagement["id"],
            passphrase="check_pass",
            output_path=output,
            engagement_base_path=str(tmp_engagement["path"]),
        )

        # Decrypt the package
        data = Path(output).read_bytes()
        key = collab_manager._derive_key("check_pass", data[:16])
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        aesgcm = AESGCM(key)
        zip_data = aesgcm.decrypt(data[16:28], data[28:], None)

        with zipfile.ZipFile(io.BytesIO(zip_data), "r") as zf:
            manifest = json.loads(zf.read("manifest.json"))

            # Verify each file's checksum
            for entry in manifest["files"]:
                file_data = zf.read(entry["path"])
                actual_hash = hashlib.sha256(file_data).hexdigest()
                assert actual_hash == entry["sha256"], (
                    f"Checksum mismatch for {entry['path']}"
                )

    def test_import_rejects_corrupted_package(self, collab_manager, tmp_engagement, tmp_path):
        """Import should fail if package data is corrupted."""
        output = str(tmp_path / "corrupt.huginn")
        collab_manager.export_engagement(
            engagement_id=tmp_engagement["id"],
            passphrase="pass",
            output_path=output,
            engagement_base_path=str(tmp_engagement["path"]),
        )

        # Corrupt the ciphertext
        data = bytearray(Path(output).read_bytes())
        if len(data) > 50:
            data[40] ^= 0xFF  # Flip a byte in the ciphertext
        Path(output).write_bytes(bytes(data))

        import_dir = tmp_path / "import_base"
        import_dir.mkdir()

        result = collab_manager.import_engagement(
            package_path=output,
            passphrase="pass",
            engagements_base_path=str(import_dir),
        )
        assert result is None
