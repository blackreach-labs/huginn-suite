#!/usr/bin/env python3
"""Manifest generator for Huginn's file-level update system.

Scans the project file tree, computes SHA256 hashes for each tracked file,
and produces a manifest.json ready to upload to S3.

Usage:
    python manifest_generator.py [--version X.Y.Z]

Output:
    dist/manifest.json

The generated manifest.json and all source files should be uploaded to
the S3 bucket with this structure:

    blackreach-labs-app-releases/
    ├── dist/
    │   └── manifest.json
    └── src/
        ├── main.py
        ├── app/
        │   └── ...
        └── ...

CloudFront serves these at:
    https://updates.blackreachlabs.com/dist/manifest.json
    https://updates.blackreachlabs.com/src/<path>
"""

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Base URL for file downloads (CloudFront CDN)
CDN_SOURCE_PREFIX = "https://updates.blackreachlabs.com/src"

# Project root is wherever this script lives
PROJECT_ROOT = Path(__file__).resolve().parent

# Directories and files to EXCLUDE from the manifest
EXCLUDE_DIRS = {
    ".git",
    ".kiro",
    ".pytest_cache",
    ".vscode",
    "__pycache__",
    "backup",
    "dist",
    "logs",
    "node_modules",
    "venv",
    ".env",
}

EXCLUDE_FILES = {
    ".gitignore",
    ".update_manifest.json",
    "manifest_generator.py",  # Don't update the generator itself via the updater
}

# Only include these extensions (empty set means include all)
INCLUDE_EXTENSIONS = {
    ".py",
    ".json",
    ".qss",
    ".txt",
    ".md",
    ".otf",
    ".ttf",
    ".png",
    ".jpg",
    ".svg",
    ".ico",
    ".db",
    ".lic",
}


def compute_sha256(file_path: Path) -> str:
    """Compute SHA256 hex digest of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()


def should_include(path: Path, rel_path: Path) -> bool:
    """Determine if a file should be included in the manifest."""
    # Skip excluded directories
    for part in rel_path.parts:
        if part in EXCLUDE_DIRS:
            return False

    # Skip excluded filenames
    if path.name in EXCLUDE_FILES:
        return False

    # Skip hidden files/dirs (starting with dot) except specific ones
    for part in rel_path.parts:
        if part.startswith(".") and part not in {".update_manifest.json"}:
            return False

    # Filter by extension if INCLUDE_EXTENSIONS is defined
    if INCLUDE_EXTENSIONS and path.suffix.lower() not in INCLUDE_EXTENSIONS:
        return False

    return True


def generate_manifest(version: str) -> dict:
    """Generate the manifest dictionary by scanning the project tree.

    Args:
        version: The version string for this release (e.g., "8.1.0").

    Returns:
        The manifest dictionary ready for JSON serialization.
    """
    files = []

    for file_path in sorted(PROJECT_ROOT.rglob("*")):
        if not file_path.is_file():
            continue

        rel_path = file_path.relative_to(PROJECT_ROOT)

        if not should_include(file_path, rel_path):
            continue

        # Use forward slashes for cross-platform compatibility
        rel_str = rel_path.as_posix()
        sha256 = compute_sha256(file_path)
        url = f"{CDN_SOURCE_PREFIX}/{rel_str}"

        files.append({
            "path": rel_str,
            "url": url,
            "sha256": sha256,
        })

    manifest = {
        "latest_version": version,
        "release_date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "files": files,
        "release_notes": "",
    }

    return manifest


def main():
    parser = argparse.ArgumentParser(
        description="Generate manifest.json for Huginn's update system."
    )
    parser.add_argument(
        "--version",
        required=True,
        help="Release version string (e.g., 8.1.0)",
    )
    parser.add_argument(
        "--notes",
        default="",
        help="Release notes text to include in the manifest",
    )
    args = parser.parse_args()

    # Validate version format
    parts = args.version.split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        print(f"Error: Invalid version format '{args.version}'. Use MAJOR.MINOR.PATCH", file=sys.stderr)
        sys.exit(1)

    print(f"Generating manifest for v{args.version}...")
    manifest = generate_manifest(args.version)

    if args.notes:
        manifest["release_notes"] = args.notes

    # Write to dist/
    dist_dir = PROJECT_ROOT / "dist"
    dist_dir.mkdir(exist_ok=True)
    output_path = dist_dir / "manifest.json"

    output_path.write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8",
    )

    print(f"Manifest written to: {output_path}")
    print(f"Total files tracked: {len(manifest['files'])}")
    print()
    print("Next steps:")
    print("  1. Upload dist/manifest.json to s3://blackreach-labs-app-releases/dist/manifest.json")
    print("  2. Upload all project source files to s3://blackreach-labs-app-releases/src/")
    print("     (maintaining the same directory structure)")
    print("  3. Invalidate CloudFront cache if needed:")
    print('     aws cloudfront create-invalidation --distribution-id <ID> --paths "/dist/manifest.json"')


if __name__ == "__main__":
    main()
