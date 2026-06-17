"""SHA256 integrity verification for downloaded update archives."""

import hashlib
import re
from pathlib import Path


class IntegrityError(Exception):
    """Hash mismatch or checksum file parse error."""

    pass


class ChecksumFormatError(IntegrityError):
    """Checksum file doesn't contain a valid SHA256 hex string."""

    pass


# Standard sha256sum output: 64 hex chars, two spaces, filename
_CHECKSUM_PATTERN = re.compile(r"^([0-9a-fA-F]{64})  (.+)$")


class IntegrityVerifier:
    """Verifies downloaded files against SHA256 checksums."""

    def verify(self, archive_path: Path, checksum_path: Path) -> bool:
        """Verify archive integrity against checksum file.

        Checksum file format: <64-char-hex>  <filename>
        (standard sha256sum output: hex digest, two spaces, filename)

        Args:
            archive_path: Path to the downloaded archive file.
            checksum_path: Path to the SHA256 checksum file.

        Raises:
            ChecksumFormatError: Can't extract valid SHA256 from checksum file.
            IntegrityError: Hash mismatch between computed and expected.

        Returns:
            True if verification succeeds.
        """
        expected_hash = self._read_expected_hash(checksum_path)
        computed_hash = self._compute_sha256(archive_path)

        if computed_hash.lower() != expected_hash.lower():
            raise IntegrityError(
                f"SHA256 mismatch: expected {expected_hash}, got {computed_hash}"
            )

        return True

    def _read_expected_hash(self, checksum_path: Path) -> str:
        """Read and parse the checksum file to extract the expected hash.

        Args:
            checksum_path: Path to the checksum file.

        Raises:
            ChecksumFormatError: If the file doesn't match expected format.

        Returns:
            The 64-character hex hash string.
        """
        content = checksum_path.read_text(encoding="utf-8").strip()
        match = _CHECKSUM_PATTERN.match(content)

        if not match:
            raise ChecksumFormatError(
                f"Checksum file does not match expected format "
                f"'<64-hex-chars>  <filename>': {checksum_path}"
            )

        return match.group(1)

    def _compute_sha256(self, file_path: Path) -> str:
        """Compute SHA256 hash of a file.

        Args:
            file_path: Path to the file to hash.

        Returns:
            Lowercase hex digest string.
        """
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                sha256.update(chunk)
        return sha256.hexdigest()
