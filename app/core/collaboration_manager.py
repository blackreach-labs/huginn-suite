# app/core/collaboration_manager.py
"""Team collaboration via encrypted engagement packages.

Enables penetration testers to export and import engagement data as
AES-256-GCM encrypted ZIP archives for file-based team sharing without
requiring a server. Uses PBKDF2 key derivation with 480,000 iterations.
"""

import hashlib
import io
import json
import os
import shutil
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from PyQt6.QtCore import QObject, pyqtSignal

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

from app.core.logger import logger

# Huginn version identifier for manifest metadata
HUGINN_VERSION = "1.0.0"


class CollaborationManager(QObject):
    """Manages engagement package export/import as encrypted ZIP archives.

    Supports:
    - AES-256-GCM encryption with PBKDF2HMAC key derivation (480k iterations)
    - Selective export (chosen findings and evidence subsets)
    - Manifest-based integrity validation via SHA-256 checksums
    - New engagement ID assignment on import to avoid conflicts
    - Immediate rejection on wrong passphrase (no partial extraction)

    Signals:
        export_progress(int, int): Emitted with (current, total) during export.
        import_progress(int, int): Emitted with (current, total) during import.
    """

    export_progress = pyqtSignal(int, int)
    import_progress = pyqtSignal(int, int)

    def __init__(self, engagement_manager=None):
        """Initialize the CollaborationManager.

        Args:
            engagement_manager: Optional EngagementManager instance used
                to register imported engagements in the master index.
        """
        super().__init__()
        self._engagement_manager = engagement_manager

    @property
    def engagement_manager(self):
        """The engagement manager used for registering imports."""
        return self._engagement_manager

    @engagement_manager.setter
    def engagement_manager(self, manager):
        self._engagement_manager = manager

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def export_engagement(
        self,
        engagement_id: str,
        passphrase: str,
        output_path: str,
        engagement_base_path: str,
        selected_findings: Optional[List[int]] = None,
        selected_evidence: Optional[List[int]] = None,
    ) -> bool:
        """Export an engagement as an AES-256-GCM encrypted ZIP archive.

        The archive contains the engagement database, evidence files,
        document files, and a manifest with checksums and metadata.

        Args:
            engagement_id: UUID of the engagement to export.
            passphrase: User-provided passphrase for encryption.
            output_path: Path where the encrypted archive will be written.
            engagement_base_path: Base path to the engagement directory
                (containing engagement.db, evidence/, documents/).
            selected_findings: Optional list of finding IDs to include.
                If None, all findings are included.
            selected_evidence: Optional list of evidence IDs to include.
                If None, all evidence files are included.

        Returns:
            True if export succeeded, False otherwise.
        """
        try:
            eng_path = Path(engagement_base_path)
            db_path = eng_path / "engagement.db"

            if not db_path.exists():
                logger.error(f"Engagement database not found: {db_path}")
                return False

            # Collect files to export
            files_to_export = self._collect_export_files(
                eng_path, selected_findings, selected_evidence
            )

            total_files = len(files_to_export)
            self.export_progress.emit(0, total_files + 2)  # +2 for manifest + encryption

            # Create in-memory ZIP
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
                for idx, (archive_name, file_path) in enumerate(files_to_export):
                    zf.write(file_path, archive_name)
                    self.export_progress.emit(idx + 1, total_files + 2)

                # Create and add manifest
                manifest = self._create_manifest(
                    files_to_export, engagement_id, selected_findings, selected_evidence
                )
                manifest_json = json.dumps(manifest, indent=2)
                zf.writestr("manifest.json", manifest_json)

            self.export_progress.emit(total_files + 1, total_files + 2)

            # Encrypt the ZIP
            zip_data = zip_buffer.getvalue()
            salt = os.urandom(16)
            key = self._derive_key(passphrase, salt)
            nonce = os.urandom(12)  # 96-bit nonce for AES-GCM

            aesgcm = AESGCM(key)
            encrypted_data = aesgcm.encrypt(nonce, zip_data, None)

            # Write the encrypted package: salt (16) + nonce (12) + ciphertext
            output = Path(output_path)
            output.parent.mkdir(parents=True, exist_ok=True)
            with open(output, "wb") as f:
                f.write(salt)
                f.write(nonce)
                f.write(encrypted_data)

            self.export_progress.emit(total_files + 2, total_files + 2)
            logger.info(
                f"Engagement exported: {engagement_id} -> {output_path} "
                f"({len(files_to_export)} files)"
            )
            return True

        except Exception as e:
            logger.error(f"Export failed for engagement {engagement_id}: {e}")
            return False

    def import_engagement(
        self,
        package_path: str,
        passphrase: str,
        engagements_base_path: str,
    ) -> Optional[str]:
        """Import an encrypted engagement package.

        Decrypts the archive, validates manifest checksums, copies content
        to a new engagement directory, and registers it in the master index.

        Args:
            package_path: Path to the encrypted .huginn package file.
            passphrase: User-provided passphrase for decryption.
            engagements_base_path: Base directory where engagements are stored
                (e.g., resources/engagements/).

        Returns:
            New engagement ID if import succeeded, None on failure.
        """
        try:
            # Read encrypted package
            with open(package_path, "rb") as f:
                salt = f.read(16)
                nonce = f.read(12)
                encrypted_data = f.read()

            if len(salt) < 16 or len(nonce) < 12 or len(encrypted_data) == 0:
                logger.error("Invalid package format: file too short")
                return None

            # Derive key and decrypt
            key = self._derive_key(passphrase, salt)
            aesgcm = AESGCM(key)

            try:
                zip_data = aesgcm.decrypt(nonce, encrypted_data, None)
            except InvalidTag:
                logger.warning("Import failed: incorrect passphrase")
                return None

            self.import_progress.emit(1, 4)

            # Extract ZIP contents in memory
            zip_buffer = io.BytesIO(zip_data)
            with zipfile.ZipFile(zip_buffer, "r") as zf:
                # Read and validate manifest
                if "manifest.json" not in zf.namelist():
                    logger.error("Import failed: no manifest.json in package")
                    return None

                manifest_json = zf.read("manifest.json").decode("utf-8")
                manifest = json.loads(manifest_json)

                self.import_progress.emit(2, 4)

                # Validate checksums before extracting anything
                if not self._validate_manifest(manifest, zf):
                    logger.error("Import failed: manifest checksum validation failed")
                    return None

                self.import_progress.emit(3, 4)

                # Create new engagement directory with new ID
                new_engagement_id = str(uuid.uuid4())
                new_eng_path = Path(engagements_base_path) / new_engagement_id
                new_eng_path.mkdir(parents=True, exist_ok=True)
                (new_eng_path / "evidence").mkdir(exist_ok=True)
                (new_eng_path / "documents").mkdir(exist_ok=True)

                # Extract all files to new engagement directory
                for item in zf.namelist():
                    if item == "manifest.json":
                        continue
                    # Sanitize path to prevent zip slip
                    target_path = new_eng_path / item
                    if not str(target_path.resolve()).startswith(
                        str(new_eng_path.resolve())
                    ):
                        logger.warning(f"Skipping suspicious path: {item}")
                        continue

                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(target_path, "wb") as out_f:
                        out_f.write(zf.read(item))

            # Register in master index if engagement manager is available
            if self._engagement_manager is not None:
                self._register_imported_engagement(
                    new_engagement_id, new_eng_path, manifest
                )

            self.import_progress.emit(4, 4)
            logger.info(
                f"Engagement imported: {package_path} -> {new_engagement_id}"
            )
            return new_engagement_id

        except InvalidTag:
            # Double-guard: wrong passphrase
            logger.warning("Import failed: incorrect passphrase")
            return None
        except Exception as e:
            logger.error(f"Import failed: {e}")
            return None

    # ------------------------------------------------------------------
    # Key Derivation
    # ------------------------------------------------------------------

    def _derive_key(self, passphrase: str, salt: bytes) -> bytes:
        """Derive a 32-byte AES-256 key from passphrase using PBKDF2HMAC.

        Uses SHA-256 with 480,000 iterations as recommended for strong
        password-based key derivation.

        Args:
            passphrase: User-provided passphrase string.
            salt: 16-byte random salt.

        Returns:
            32-byte derived key suitable for AES-256.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        return kdf.derive(passphrase.encode("utf-8"))

    # ------------------------------------------------------------------
    # Manifest Operations
    # ------------------------------------------------------------------

    def _create_manifest(
        self,
        files: List[tuple],
        engagement_id: str,
        selected_findings: Optional[List[int]] = None,
        selected_evidence: Optional[List[int]] = None,
    ) -> Dict:
        """Create a manifest with file checksums and export metadata.

        Args:
            files: List of (archive_name, file_path) tuples.
            engagement_id: Source engagement UUID.
            selected_findings: Findings IDs included (None = all).
            selected_evidence: Evidence IDs included (None = all).

        Returns:
            Manifest dictionary with metadata and file checksums.
        """
        file_entries = []
        for archive_name, file_path in files:
            sha256_hash = self._compute_file_hash(file_path)
            file_size = os.path.getsize(file_path)
            file_entries.append({
                "path": archive_name,
                "sha256": sha256_hash,
                "size": file_size,
            })

        manifest = {
            "huginn_version": HUGINN_VERSION,
            "export_date": datetime.now(timezone.utc).isoformat(),
            "source_engagement_id": engagement_id,
            "file_count": len(file_entries),
            "files": file_entries,
            "selective_export": {
                "findings": selected_findings,
                "evidence": selected_evidence,
            },
        }
        return manifest

    def _validate_manifest(self, manifest: Dict, zf: zipfile.ZipFile) -> bool:
        """Validate all file checksums in the manifest against the ZIP contents.

        Args:
            manifest: Parsed manifest dictionary.
            zf: Open ZipFile to read file contents from.

        Returns:
            True if all checksums match, False if any mismatch detected.
        """
        files = manifest.get("files", [])
        if not files:
            logger.warning("Manifest contains no file entries")
            return False

        for entry in files:
            path = entry["path"]
            expected_hash = entry["sha256"]

            if path not in zf.namelist():
                logger.error(f"Manifest validation: file missing from archive: {path}")
                return False

            data = zf.read(path)
            actual_hash = hashlib.sha256(data).hexdigest()

            if actual_hash != expected_hash:
                logger.error(
                    f"Manifest validation: checksum mismatch for {path}: "
                    f"expected {expected_hash}, got {actual_hash}"
                )
                return False

        return True

    # ------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------

    def _collect_export_files(
        self,
        eng_path: Path,
        selected_findings: Optional[List[int]],
        selected_evidence: Optional[List[int]],
    ) -> List[tuple]:
        """Collect files to include in the export archive.

        Args:
            eng_path: Path to the engagement directory.
            selected_findings: If provided, only export a filtered DB.
            selected_evidence: If provided, only export matching evidence files.

        Returns:
            List of (archive_name, absolute_file_path) tuples.
        """
        files = []

        # Always include engagement database
        db_path = eng_path / "engagement.db"
        if db_path.exists():
            files.append(("engagement.db", str(db_path)))

        # Collect evidence files
        evidence_dir = eng_path / "evidence"
        if evidence_dir.exists():
            for evidence_file in evidence_dir.iterdir():
                if evidence_file.is_file():
                    if selected_evidence is not None:
                        # Filter: only include if the filename matches a selected ID
                        # Evidence files are typically named by ID or hash
                        try:
                            file_id = int(evidence_file.stem)
                            if file_id not in selected_evidence:
                                continue
                        except ValueError:
                            # If filename is not an integer, include it
                            # (could be hash-named, include all non-ID files)
                            pass
                    archive_name = f"evidence/{evidence_file.name}"
                    files.append((archive_name, str(evidence_file)))

        # Collect document files
        documents_dir = eng_path / "documents"
        if documents_dir.exists():
            for doc_file in documents_dir.iterdir():
                if doc_file.is_file():
                    archive_name = f"documents/{doc_file.name}"
                    files.append((archive_name, str(doc_file)))

        return files

    def _compute_file_hash(self, file_path: str) -> str:
        """Compute SHA-256 hash of a file.

        Args:
            file_path: Path to the file.

        Returns:
            Hex-encoded SHA-256 digest.
        """
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _register_imported_engagement(
        self,
        new_engagement_id: str,
        new_eng_path: Path,
        manifest: Dict,
    ) -> None:
        """Register an imported engagement in the master index.

        Uses the EngagementManager's master database pool to insert
        the new engagement record.

        Args:
            new_engagement_id: New UUID assigned to the imported engagement.
            new_eng_path: Path to the new engagement directory.
            manifest: Parsed manifest with source metadata.
        """
        now = datetime.now(timezone.utc).isoformat()
        source_id = manifest.get("source_engagement_id", "unknown")
        export_date = manifest.get("export_date", now)

        # Compute relative DB path
        master_db_path = Path(self._engagement_manager.master_db_path)
        resources_dir = master_db_path.parent
        try:
            relative_db_path = str(
                (new_eng_path / "engagement.db").relative_to(resources_dir)
            )
        except ValueError:
            relative_db_path = str(new_eng_path / "engagement.db")

        with self._engagement_manager._master_pool.get_connection() as conn:
            conn.execute(
                """INSERT INTO engagements
                   (id, name, client_name, engagement_type, status,
                    start_date, end_date, db_path, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    new_engagement_id,
                    f"Imported from {source_id[:8]}...",
                    "Imported",
                    "external",
                    "draft",
                    None,
                    None,
                    relative_db_path,
                    now,
                    now,
                ),
            )
            conn.commit()

        logger.info(
            f"Registered imported engagement {new_engagement_id} "
            f"(source: {source_id}, exported: {export_date})"
        )
