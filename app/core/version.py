"""Version management utilities for Huginn.

Provides version reading, parsing, and comparison against the canonical
VERSION file at the project root.
"""

import re
from pathlib import Path

# Regex for validating semantic version format: MAJOR.MINOR.PATCH
VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")

# Path to the VERSION file at project root (parent of app/, which is parent of core/)
VERSION_FILE = Path(__file__).parent.parent.parent / "VERSION"


class VersionError(Exception):
    """Raised when VERSION file is missing or malformed."""
    pass


def get_version() -> str:
    """Read and validate the version from the VERSION file.

    Returns:
        The version string (e.g., "8.0.0")

    Raises:
        VersionError: If VERSION file is missing or doesn't match MAJOR.MINOR.PATCH
    """
    if not VERSION_FILE.exists():
        raise VersionError(
            f"VERSION file not found at {VERSION_FILE}. "
            "The application cannot determine its current version."
        )

    try:
        content = VERSION_FILE.read_text(encoding="utf-8").strip()
    except OSError as e:
        raise VersionError(f"Failed to read VERSION file: {e}") from e

    if not VERSION_PATTERN.match(content):
        raise VersionError(
            f"VERSION file contains malformed version: '{content}'. "
            "Expected format: MAJOR.MINOR.PATCH (e.g., '8.0.0')"
        )

    return content


def parse_version(version_str: str) -> tuple[int, int, int]:
    """Parse a semantic version string into (major, minor, patch).

    Strips leading 'v' prefix if present.

    Args:
        version_str: A version string like "8.0.0" or "v8.0.0"

    Returns:
        A tuple of (major, minor, patch) integers

    Raises:
        ValueError: If string doesn't match semantic version format
    """
    cleaned = version_str.strip()

    # Strip leading 'v' or 'V' prefix
    if cleaned.startswith(("v", "V")):
        cleaned = cleaned[1:]

    if not VERSION_PATTERN.match(cleaned):
        raise ValueError(
            f"Invalid version format: '{version_str}'. "
            "Expected format: [v]MAJOR.MINOR.PATCH (e.g., 'v8.0.0' or '8.0.0')"
        )

    parts = cleaned.split(".")
    return (int(parts[0]), int(parts[1]), int(parts[2]))


def compare_versions(current: str, remote: str) -> int:
    """Compare two version strings.

    Both strings may optionally have a leading 'v' prefix.

    Args:
        current: The current installed version
        remote: The remote/available version

    Returns:
        -1 if current < remote (update available)
         0 if current == remote
         1 if current > remote
    """
    current_tuple = parse_version(current)
    remote_tuple = parse_version(remote)

    if current_tuple < remote_tuple:
        return -1
    elif current_tuple == remote_tuple:
        return 0
    else:
        return 1
