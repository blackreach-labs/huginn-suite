"""Recursive SSH key scanner for filesystem enumeration."""

import logging
from pathlib import Path
from typing import List, Optional, Union

from .parser import SSHKeyParser
from .models import SSHKeyInfo
from .exceptions import SSHParserError, InvalidKeyError

logger = logging.getLogger(__name__)

# Common SSH private key filename patterns
DEFAULT_KEY_PATTERNS = [
    "id_*",
    "*.pem",
    "*.key",
    "*.id",
    "*.ppk",
    "*_key",
    "*_rsa",
    "*_dsa",
    "*_ecdsa",
    "*_ed25519",
    "*identity*",
]

# Files to always skip
SKIP_EXTENSIONS = {".pub", ".log", ".txt", ".md", ".json", ".yaml", ".yml", ".xml"}


class ScanResult:
    """Result from scanning a single file."""

    def __init__(self, filepath: Path, info: Optional[SSHKeyInfo] = None, error: Optional[str] = None):
        self.filepath = filepath
        self.info = info
        self.error = error

    @property
    def success(self) -> bool:
        return self.info is not None

    def to_dict(self) -> dict:
        """Structured output with module tags for Huginn integration."""
        base = {
            "module": "ssh_parser",
            "file": str(self.filepath),
        }

        if self.info:
            severity = _assess_severity(self.info)
            base.update({
                "severity": severity,
                "artifact": "encrypted_key" if self.info.is_encrypted else "unencrypted_key",
                "data": self.info.to_dict(),
            })
        else:
            base.update({
                "severity": "info",
                "artifact": "parse_error",
                "error": self.error,
            })

        return base


class SSHKeyScanner:
    """
    Recursively scans a directory tree for SSH private keys and parses them.

    Usage:
        scanner = SSHKeyScanner()
        results = scanner.scan("/target/home")
        for r in results:
            print(r.to_dict())
    """

    def __init__(self, patterns: Optional[List[str]] = None):
        """
        Args:
            patterns: Glob patterns for key file discovery.
                      Defaults to common SSH key naming conventions.
        """
        self._parser = SSHKeyParser()
        self._patterns = patterns or DEFAULT_KEY_PATTERNS

    def scan(self, path: Union[str, Path], recursive: bool = True) -> List[ScanResult]:
        """
        Scan a directory for SSH private keys.

        Args:
            path: Root directory to scan.
            recursive: Whether to recurse into subdirectories.

        Returns:
            List of ScanResult objects for each discovered key file.
        """
        root = Path(path)
        results = []

        if not root.exists():
            logger.warning(f"Scan path does not exist: {root}")
            return results

        if root.is_file():
            # Single file mode
            return [self._scan_file(root)]

        # Discover candidate files
        candidates = self._discover_files(root, recursive)
        logger.info(f"Discovered {len(candidates)} candidate key files in {root}")

        for filepath in sorted(candidates):
            result = self._scan_file(filepath)
            results.append(result)

        return results

    def scan_file(self, filepath: Union[str, Path]) -> ScanResult:
        """Scan a single file. Public wrapper around internal method."""
        return self._scan_file(Path(filepath))

    def _scan_file(self, filepath: Path) -> ScanResult:
        """Parse a single file and wrap the result."""
        try:
            info = self._parser.parse_file(filepath)
            return ScanResult(filepath=filepath, info=info)
        except (SSHParserError, InvalidKeyError) as e:
            return ScanResult(filepath=filepath, error=str(e))
        except Exception as e:
            return ScanResult(filepath=filepath, error=f"Unexpected error: {e}")

    def _discover_files(self, root: Path, recursive: bool) -> List[Path]:
        """Find candidate SSH key files using glob patterns + content sniffing."""
        candidates = set()

        # Pass 1: glob-based pattern matching
        for pattern in self._patterns:
            if recursive:
                glob_pattern = f"**/{pattern}"
            else:
                glob_pattern = pattern

            try:
                for match in root.glob(glob_pattern):
                    if match.is_file() and self._should_include(match):
                        candidates.add(match)
            except PermissionError:
                logger.debug(f"Permission denied scanning with pattern: {pattern}")
            except OSError as e:
                logger.debug(f"OS error during glob ({pattern}): {e}")

        # Pass 2: content sniff files that have no extension or uncommon extensions
        # This catches keys with arbitrary names like "facts.id", "mykey", etc.
        try:
            iter_files = root.rglob("*") if recursive else root.iterdir()
            for filepath in iter_files:
                if filepath in candidates:
                    continue
                if not filepath.is_file():
                    continue
                if not self._should_include(filepath):
                    continue
                # Only sniff small files with no extension or uncommon extensions
                if filepath.suffix.lower() in SKIP_EXTENSIONS:
                    continue
                if self._sniff_ssh_key(filepath):
                    candidates.add(filepath)
        except PermissionError:
            logger.debug("Permission denied during content sniff pass")
        except OSError as e:
            logger.debug(f"OS error during content sniff: {e}")

        return list(candidates)

    def _sniff_ssh_key(self, filepath: Path) -> bool:
        """Quick content check: read first line to see if it looks like an SSH key."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                first_line = f.readline(256)
            return (
                "BEGIN OPENSSH PRIVATE KEY" in first_line
                or "BEGIN RSA PRIVATE KEY" in first_line
                or "BEGIN DSA PRIVATE KEY" in first_line
                or "BEGIN EC PRIVATE KEY" in first_line
                or "BEGIN ENCRYPTED PRIVATE KEY" in first_line
            )
        except Exception:
            return False

        return list(candidates)

    def _should_include(self, filepath: Path) -> bool:
        """Filter out files that are clearly not SSH keys."""
        # Skip public keys and known non-key extensions
        if filepath.suffix.lower() in SKIP_EXTENSIONS:
            return False

        # Skip files that are too large (likely not keys)
        try:
            if filepath.stat().st_size > 1_000_000:
                return False
            if filepath.stat().st_size == 0:
                return False
        except OSError:
            return False

        return True


def _assess_severity(info: SSHKeyInfo) -> str:
    """
    Assess the security severity of a discovered key.

    Returns:
        Severity string: critical, high, medium, low, info
    """
    if not info.is_encrypted:
        return "critical"  # Unencrypted private key — immediate risk

    # Encrypted but with weak parameters
    if info.cipher and info.cipher.lower() in ("des-ede3-cbc", "des-cbc", "rc4"):
        return "high"

    if info.kdf == "md5":
        return "medium"  # Legacy PEM key derivation is weak

    if info.rounds and info.rounds < 16:
        return "medium"  # Very low bcrypt rounds

    return "low"  # Encrypted with reasonable parameters
