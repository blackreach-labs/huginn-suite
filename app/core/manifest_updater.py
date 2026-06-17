"""Manifest-based file-level updater for Huginn.

Fetches a remote manifest from CloudFront CDN, compares SHA256 hashes
of individual files against local copies, downloads only changed/missing
files, then performs an automatic hot-reload via os.execv().

Infrastructure:
    - CDN endpoint: https://updates.blackreachlabs.com
    - Manifest path: /dist/manifest.json
    - Source files:  /src/<relative_path>

Dependencies: Standard library only (urllib.request, json, hashlib, pathlib, os, sys).
"""

import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, Optional


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CDN_BASE_URL = "https://updates.blackreachlabs.com"
MANIFEST_URL = f"{CDN_BASE_URL}/dist/manifest.json"
SOURCE_PREFIX = f"{CDN_BASE_URL}/src"
REQUEST_TIMEOUT = 30  # seconds for manifest fetch
DOWNLOAD_TIMEOUT = 60  # seconds per file download

# Local manifest stores the currently installed version + file state
LOCAL_MANIFEST_NAME = ".update_manifest.json"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class UpdateError(Exception):
    """Base exception for update failures."""
    pass


class ManifestFetchError(UpdateError):
    """Failed to retrieve the remote manifest."""
    pass


class FileDownloadError(UpdateError):
    """Failed to download one or more files."""
    pass


class IntegrityError(UpdateError):
    """Downloaded file does not match expected hash."""
    pass


# ---------------------------------------------------------------------------
# ManifestUpdater
# ---------------------------------------------------------------------------

class ManifestUpdater:
    """Individual file auto-update system using S3/CloudFront CDN.

    Usage:
        updater = ManifestUpdater(app_root)
        result = updater.check_for_updates(license_key=None)
        if result.has_update:
            updater.apply_updates(result, progress_callback=...)
            # apply_updates triggers os.execv — does not return
    """

    def __init__(self, app_root: Optional[Path] = None):
        """Initialize the updater.

        Args:
            app_root: The project root directory (where main.py lives).
                      Defaults to the parent of app/core/.
        """
        if app_root is None:
            app_root = Path(__file__).resolve().parent.parent.parent
        self.app_root = app_root
        self._local_manifest_path = self.app_root / LOCAL_MANIFEST_NAME

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_local_version(self) -> str:
        """Read the locally installed version from the local manifest.

        Returns:
            The version string, or "0.0.0" if no local manifest exists.
        """
        manifest = self._read_local_manifest()
        return manifest.get("installed_version", "0.0.0")

    def check_for_updates(
        self,
        license_key: Optional[str] = None,
    ) -> "UpdateCheckResult":
        """Check the CDN for available file updates.

        Fetches the remote manifest and compares each file's SHA256 hash
        against the local copy on disk.

        Args:
            license_key: Optional license key for future authenticated
                         update provisioning. Currently passed as a query
                         parameter for forward-compatibility.

        Returns:
            An UpdateCheckResult describing available changes.

        Raises:
            ManifestFetchError: If the remote manifest cannot be retrieved.
        """
        remote_manifest = self._fetch_remote_manifest(license_key)

        remote_version = remote_manifest.get("latest_version", "0.0.0")
        local_version = self.get_local_version()
        release_notes = remote_manifest.get("release_notes", "")
        files_to_update: list[dict] = []

        for file_entry in remote_manifest.get("files", []):
            rel_path = file_entry["path"]
            remote_hash = file_entry["sha256"]

            local_file = self.app_root / rel_path
            if local_file.exists():
                local_hash = self._compute_sha256(local_file)
                if local_hash == remote_hash.lower():
                    continue  # File is up to date

            # File is missing or hash differs
            files_to_update.append(file_entry)

        has_update = len(files_to_update) > 0

        return UpdateCheckResult(
            has_update=has_update,
            local_version=local_version,
            remote_version=remote_version,
            release_notes=release_notes,
            files_to_update=files_to_update,
            remote_manifest=remote_manifest,
        )

    def apply_updates(
        self,
        check_result: "UpdateCheckResult",
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> None:
        """Download changed files and restart the application.

        Args:
            check_result: The result from check_for_updates().
            progress_callback: Called with (files_done, files_total, current_file)
                               after each file is downloaded.

        Raises:
            FileDownloadError: If a file cannot be downloaded.
            IntegrityError: If a downloaded file's hash doesn't match.

        Note:
            On success this method calls os.execv() and does NOT return.
        """
        files = check_result.files_to_update
        total = len(files)

        for idx, file_entry in enumerate(files):
            rel_path = file_entry["path"]
            expected_hash = file_entry["sha256"].lower()
            download_url = file_entry["url"]

            if progress_callback is not None:
                progress_callback(idx, total, rel_path)

            # Download the file content
            content = self._download_file(download_url, rel_path)

            # Verify integrity before writing to disk
            actual_hash = hashlib.sha256(content).hexdigest()
            if actual_hash != expected_hash:
                raise IntegrityError(
                    f"Hash mismatch for '{rel_path}': "
                    f"expected {expected_hash}, got {actual_hash}"
                )

            # Write to disk — create parent directories as needed
            target_path = self.app_root / rel_path
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.write_bytes(content)

        # Final progress tick
        if progress_callback is not None:
            progress_callback(total, total, "")

        # Persist the new version locally
        self._write_local_manifest(check_result.remote_manifest)

        # Hot-reload: replace the running process with a fresh interpreter
        self._restart_application()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _fetch_remote_manifest(self, license_key: Optional[str] = None) -> dict:
        """Fetch and parse the remote manifest.json from CDN.

        Args:
            license_key: If provided, appended as a query param for future
                         license-gated update provisioning.

        Returns:
            Parsed manifest dictionary.

        Raises:
            ManifestFetchError: On network/HTTP failures.
        """
        url = MANIFEST_URL
        if license_key:
            url = f"{url}?license_key={urllib.request.quote(license_key)}"

        request = urllib.request.Request(
            url,
            headers={"User-Agent": "Huginn-Updater"},
        )

        try:
            with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
                data = response.read().decode("utf-8")
                return json.loads(data)
        except urllib.error.HTTPError as e:
            raise ManifestFetchError(
                f"Failed to fetch manifest: HTTP {e.code} {e.reason}"
            ) from e
        except urllib.error.URLError as e:
            raise ManifestFetchError(
                f"Failed to connect to update server: {e.reason}"
            ) from e
        except (OSError, json.JSONDecodeError) as e:
            raise ManifestFetchError(
                f"Error retrieving manifest: {e}"
            ) from e

    def _download_file(self, url: str, rel_path: str) -> bytes:
        """Download a single file from the CDN.

        Args:
            url: The full download URL.
            rel_path: Relative path (used in error messages).

        Returns:
            Raw bytes of the downloaded file.

        Raises:
            FileDownloadError: On any download failure.
        """
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "Huginn-Updater"},
        )

        try:
            with urllib.request.urlopen(request, timeout=DOWNLOAD_TIMEOUT) as response:
                return response.read()
        except urllib.error.HTTPError as e:
            raise FileDownloadError(
                f"Failed to download '{rel_path}': HTTP {e.code} {e.reason}"
            ) from e
        except urllib.error.URLError as e:
            raise FileDownloadError(
                f"Failed to download '{rel_path}': {e.reason}"
            ) from e
        except OSError as e:
            raise FileDownloadError(
                f"Network error downloading '{rel_path}': {e}"
            ) from e

    def _compute_sha256(self, file_path: Path) -> str:
        """Compute the SHA256 hex digest of a local file.

        Returns:
            Lowercase hex string.
        """
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                sha256.update(chunk)
        return sha256.hexdigest()

    def _read_local_manifest(self) -> dict:
        """Read the local manifest file (version tracking).

        Returns:
            Parsed dict, or empty dict if file doesn't exist.
        """
        if not self._local_manifest_path.exists():
            return {}
        try:
            content = self._local_manifest_path.read_text(encoding="utf-8")
            return json.loads(content)
        except (OSError, json.JSONDecodeError):
            return {}

    def _write_local_manifest(self, remote_manifest: dict) -> None:
        """Persist the remote manifest as the local installed state.

        Stores the full manifest so we have a record of installed file
        hashes and the current version.
        """
        local_data = {
            "installed_version": remote_manifest.get("latest_version", "0.0.0"),
            "release_date": remote_manifest.get("release_date", ""),
            "files": remote_manifest.get("files", []),
        }
        self._local_manifest_path.write_text(
            json.dumps(local_data, indent=2),
            encoding="utf-8",
        )

    def _restart_application(self) -> None:
        """Hot-reload the application via os.execv().

        Replaces the current process entirely, discarding old in-memory
        module state and reloading all updated source files.
        """
        python = sys.executable
        os.execv(python, [python] + sys.argv)


# ---------------------------------------------------------------------------
# UpdateCheckResult
# ---------------------------------------------------------------------------

class UpdateCheckResult:
    """Result of a check_for_updates() call."""

    def __init__(
        self,
        has_update: bool,
        local_version: str,
        remote_version: str,
        release_notes: str,
        files_to_update: list[dict],
        remote_manifest: dict,
    ):
        self.has_update = has_update
        self.local_version = local_version
        self.remote_version = remote_version
        self.release_notes = release_notes
        self.files_to_update = files_to_update
        self.remote_manifest = remote_manifest

    @property
    def update_count(self) -> int:
        """Number of files that need updating."""
        return len(self.files_to_update)
