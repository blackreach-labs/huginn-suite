"""Release packager for Huginn — creates artifacts for GitHub Releases.

Produces:
    dist/huginn-{version}.zip       — zip archive of the app/ directory
    dist/huginn-{version}.zip.sha256 — SHA256 checksum file

Reads the version from the VERSION file at the project root.
No RSA signing. No S3 uploads.
"""

import hashlib
import sys
import zipfile
from pathlib import Path


class ReleasePackager:
    """Creates release artifacts for GitHub Releases."""

    def __init__(self):
        self.app_root = Path(__file__).parent
        self.version = self._read_version()
        self.dist_dir = self.app_root / "dist"

    def _read_version(self) -> str:
        """Read and validate the version from the VERSION file.

        Returns:
            The version string (e.g., "8.0.0")

        Exits with non-zero status if VERSION is missing or invalid.
        """
        import re

        version_file = self.app_root / "VERSION"

        if not version_file.exists():
            print(f"Error: VERSION file not found at {version_file}", file=sys.stderr)
            sys.exit(1)

        try:
            content = version_file.read_text(encoding="utf-8").strip()
        except OSError as e:
            print(f"Error: Failed to read VERSION file: {e}", file=sys.stderr)
            sys.exit(1)

        if not re.match(r"^\d+\.\d+\.\d+$", content):
            print(
                f"Error: VERSION file contains malformed version: '{content}'. "
                "Expected format: MAJOR.MINOR.PATCH (e.g., '8.0.0')",
                file=sys.stderr,
            )
            sys.exit(1)

        return content

    def create_release(self) -> tuple[Path, Path]:
        """Create zip archive and SHA256 checksum file.

        Returns:
            Tuple of (zip_path, checksum_path) in dist/ directory

        Output files:
            dist/huginn-{version}.zip
            dist/huginn-{version}.zip.sha256
        """
        self.dist_dir.mkdir(parents=True, exist_ok=True)

        zip_name = f"huginn-{self.version}.zip"
        zip_path = self.dist_dir / zip_name
        checksum_path = self.dist_dir / f"{zip_name}.sha256"

        # Create zip archive of app/ directory
        self._create_zip(zip_path)

        # Compute SHA256 and write checksum file
        sha256_hex = self._compute_sha256(zip_path)
        checksum_path.write_text(f"{sha256_hex}  {zip_name}", encoding="utf-8")

        print(f"Release {self.version} packaged successfully:")
        print(f"  {zip_path}")
        print(f"  {checksum_path}")
        print(f"  SHA256: {sha256_hex}")

        return zip_path, checksum_path

    def _create_zip(self, zip_path: Path) -> None:
        """Create a zip archive of the app/ directory."""
        app_dir = self.app_root / "app"

        if not app_dir.exists():
            print(f"Error: app/ directory not found at {app_dir}", file=sys.stderr)
            sys.exit(1)

        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            for file_path in sorted(app_dir.rglob("*")):
                if file_path.is_file():
                    arcname = file_path.relative_to(self.app_root)
                    zipf.write(file_path, arcname)

    def _compute_sha256(self, file_path: Path) -> str:
        """Compute the SHA256 hex digest of a file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()


def main():
    """Entry point for release packaging."""
    packager = ReleasePackager()
    packager.create_release()


if __name__ == "__main__":
    main()
