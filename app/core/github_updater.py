"""GitHub Release checker and downloader for Huginn.

Queries the GitHub Releases API for the latest release and determines
whether an update is available by comparing against the current version.
Downloads release assets with progress reporting.
"""

import json
import urllib.request
import urllib.error
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from app.core.version import get_version, parse_version, compare_versions


@dataclass
class ReleaseInfo:
    """Parsed GitHub release information."""

    version: str  # Semantic version (no 'v' prefix)
    zip_url: str  # Download URL for the zip archive
    checksum_url: str  # Download URL for the .sha256 file
    release_notes: str  # Release body/description


class UpdateCheckError(Exception):
    """Base error for update check failures."""

    pass


class NetworkError(UpdateCheckError):
    """Connection failed or network unreachable."""

    pass


class TimeoutError(UpdateCheckError):
    """Request exceeded the configured timeout."""

    pass


class AssetNotFoundError(UpdateCheckError):
    """Release is missing expected assets (zip or checksum)."""

    pass


class VersionFormatError(UpdateCheckError):
    """Release tag is not a valid semantic version."""

    pass


class DownloadError(UpdateCheckError):
    """Base error for download failures."""

    pass


class HttpError(DownloadError):
    """HTTP error during download (non-2xx response)."""

    def __init__(self, message: str, status_code: int):
        super().__init__(message)
        self.status_code = status_code


class GitHubReleaseChecker:
    """Queries GitHub Releases API for the latest release."""

    GITHUB_API_URL = "https://api.github.com/repos/{owner}/{repo}/releases/latest"
    REQUEST_TIMEOUT = 30  # seconds

    def __init__(self, owner: str, repo: str):
        self.owner = owner
        self.repo = repo
        self._api_url = self.GITHUB_API_URL.format(owner=owner, repo=repo)

    def check_for_update(self) -> Optional[ReleaseInfo]:
        """Check GitHub for a newer release than the current version.

        Returns:
            ReleaseInfo if an update is available, None otherwise.

        Raises:
            NetworkError: Connection failed or network unreachable
            TimeoutError: Request exceeded 30s
            AssetNotFoundError: Release missing zip or checksum
            VersionFormatError: Tag not valid semver
        """
        response_data = self._fetch_latest_release()
        release_info = self._parse_release(response_data)

        current_version = get_version()
        if compare_versions(current_version, release_info.version) < 0:
            return release_info

        return None

    def _fetch_latest_release(self) -> dict:
        """Send HTTP GET to the GitHub Releases API.

        Returns:
            Parsed JSON response as a dictionary.

        Raises:
            NetworkError: Connection failed or network unreachable
            TimeoutError: Request exceeded 30s timeout
        """
        request = urllib.request.Request(
            self._api_url,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "Huginn-Updater",
            },
        )

        try:
            with urllib.request.urlopen(
                request, timeout=self.REQUEST_TIMEOUT
            ) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raise NetworkError(
                f"GitHub API returned HTTP error {e.code}: {e.reason}"
            ) from e
        except urllib.error.URLError as e:
            if isinstance(e.reason, OSError) and "timed out" in str(e.reason):
                raise TimeoutError(
                    "Request to GitHub API timed out after "
                    f"{self.REQUEST_TIMEOUT} seconds"
                ) from e
            raise NetworkError(
                f"Failed to connect to GitHub API: {e.reason}"
            ) from e
        except OSError as e:
            if "timed out" in str(e):
                raise TimeoutError(
                    "Request to GitHub API timed out after "
                    f"{self.REQUEST_TIMEOUT} seconds"
                ) from e
            raise NetworkError(
                f"Network error while contacting GitHub API: {e}"
            ) from e

    def _parse_release(self, data: dict) -> ReleaseInfo:
        """Parse the GitHub API response into a ReleaseInfo.

        Args:
            data: The JSON response from the GitHub Releases API.

        Returns:
            A populated ReleaseInfo dataclass.

        Raises:
            VersionFormatError: Tag not valid semver
            AssetNotFoundError: Release missing zip or checksum asset
        """
        tag_name = data.get("tag_name", "")
        release_notes = data.get("body", "") or ""
        assets = data.get("assets", [])

        # Strip 'v' prefix and validate semver
        version = tag_name.lstrip("v") if tag_name.startswith("v") else tag_name
        try:
            parse_version(version)
        except ValueError as e:
            raise VersionFormatError(
                f"Release tag '{tag_name}' is not a valid semantic version: {e}"
            ) from e

        # Find expected assets
        zip_name = f"huginn-{version}.zip"
        checksum_name = f"huginn-{version}.zip.sha256"

        zip_url = None
        checksum_url = None

        for asset in assets:
            name = asset.get("name", "")
            url = asset.get("browser_download_url", "")
            if name == zip_name:
                zip_url = url
            elif name == checksum_name:
                checksum_url = url

        if not zip_url:
            raise AssetNotFoundError(
                f"Release is missing the expected zip archive: '{zip_name}'"
            )
        if not checksum_url:
            raise AssetNotFoundError(
                f"Release is missing the expected checksum file: '{checksum_name}'"
            )

        return ReleaseInfo(
            version=version,
            zip_url=zip_url,
            checksum_url=checksum_url,
            release_notes=release_notes,
        )


class ReleaseDownloader:
    """Downloads release assets with progress reporting."""

    DOWNLOAD_TIMEOUT = 300  # seconds
    CHUNK_SIZE = 8192  # bytes

    def download(
        self,
        url: str,
        destination: Path,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> Path:
        """Download a file with progress reporting.

        Streams the download in chunks, calling progress_callback after each
        chunk with (bytes_received, total_bytes). If the server does not
        provide a Content-Length header, total_bytes is reported as 0.

        Args:
            url: The download URL.
            destination: Local file path to save to.
            progress_callback: Called with (bytes_received, total_bytes).

        Returns:
            The destination Path on success.

        Raises:
            NetworkError: Download failed due to a network issue.
            HttpError: Server returned a non-2xx HTTP status.
            TimeoutError: Download exceeded 300 seconds.
        """
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "Huginn-Updater"},
        )

        try:
            response = urllib.request.urlopen(
                request, timeout=self.DOWNLOAD_TIMEOUT
            )
        except urllib.error.HTTPError as e:
            self._cleanup(destination)
            raise HttpError(
                f"Download failed with HTTP error {e.code}: {e.reason}",
                status_code=e.code,
            ) from e
        except urllib.error.URLError as e:
            self._cleanup(destination)
            if isinstance(e.reason, OSError) and "timed out" in str(e.reason):
                raise TimeoutError(
                    f"Download timed out after {self.DOWNLOAD_TIMEOUT} seconds"
                ) from e
            raise NetworkError(
                f"Failed to connect for download: {e.reason}"
            ) from e
        except OSError as e:
            self._cleanup(destination)
            if "timed out" in str(e):
                raise TimeoutError(
                    f"Download timed out after {self.DOWNLOAD_TIMEOUT} seconds"
                ) from e
            raise NetworkError(
                f"Network error during download: {e}"
            ) from e

        try:
            total_bytes = int(response.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            total_bytes = 0

        bytes_received = 0

        try:
            with open(destination, "wb") as f:
                while True:
                    try:
                        chunk = response.read(self.CHUNK_SIZE)
                    except OSError as e:
                        if "timed out" in str(e):
                            raise TimeoutError(
                                f"Download timed out after "
                                f"{self.DOWNLOAD_TIMEOUT} seconds"
                            ) from e
                        raise NetworkError(
                            f"Network error during download: {e}"
                        ) from e

                    if not chunk:
                        break

                    f.write(chunk)
                    bytes_received += len(chunk)

                    if progress_callback is not None:
                        progress_callback(bytes_received, total_bytes)
        except (NetworkError, TimeoutError):
            self._cleanup(destination)
            raise
        except OSError as e:
            self._cleanup(destination)
            raise NetworkError(
                f"Error writing download to disk: {e}"
            ) from e
        finally:
            response.close()

        return destination

    def _cleanup(self, destination: Path) -> None:
        """Remove partially downloaded file if it exists."""
        try:
            if destination.exists():
                destination.unlink()
        except OSError:
            pass
