#!/usr/bin/env python3
"""Huginn Installer — Bootstrap a fresh installation from CloudFront CDN.

Downloads the complete application by fetching the remote manifest and
pulling every tracked file to the local installation directory.

Usage:
    python huginn_install.py [--dir PATH] [--license-key KEY]

Options:
    --dir PATH          Installation directory (default: ./huginn)
    --license-key KEY   License key to embed in the installation

Requirements:
    Python 3.10+ (standard library only, no pip packages needed)
"""

import argparse
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CDN_BASE_URL = "https://updates.blackreachlabs.com"
MANIFEST_URL = f"{CDN_BASE_URL}/dist/manifest.json"
REQUEST_TIMEOUT = 30
DOWNLOAD_TIMEOUT = 120
LOCAL_MANIFEST_NAME = ".update_manifest.json"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def fetch_manifest(license_key=None):
    """Fetch the remote manifest from CDN."""
    url = MANIFEST_URL
    if license_key:
        url = f"{url}?license_key={urllib.request.quote(license_key)}"

    request = urllib.request.Request(url, headers={"User-Agent": "Huginn-Installer"})

    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        print(f"\nError: Failed to fetch manifest — HTTP {e.code} {e.reason}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"\nError: Cannot connect to update server — {e.reason}", file=sys.stderr)
        sys.exit(1)
    except (OSError, json.JSONDecodeError) as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(1)


def download_file(url, dest_path):
    """Download a single file from CDN and write to disk.

    Returns the SHA256 hex digest of the downloaded content.
    """
    request = urllib.request.Request(url, headers={"User-Agent": "Huginn-Installer"})

    try:
        with urllib.request.urlopen(request, timeout=DOWNLOAD_TIMEOUT) as response:
            content = response.read()
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code} {e.reason}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"Connection failed: {e.reason}")
    except OSError as e:
        raise RuntimeError(str(e))

    dest_path.parent.mkdir(parents=True, exist_ok=True)
    dest_path.write_bytes(content)

    return hashlib.sha256(content).hexdigest()


def write_local_manifest(install_dir, remote_manifest):
    """Seed the local manifest so the updater knows the installed version."""
    local_data = {
        "installed_version": remote_manifest.get("latest_version", "0.0.0"),
        "release_date": remote_manifest.get("release_date", ""),
        "files": remote_manifest.get("files", []),
    }
    manifest_path = install_dir / LOCAL_MANIFEST_NAME
    manifest_path.write_text(json.dumps(local_data, indent=2), encoding="utf-8")


def print_progress(current, total, filename, bar_width=40):
    """Print a progress bar to the terminal."""
    fraction = current / total if total > 0 else 0
    filled = int(bar_width * fraction)
    bar = "#" * filled + "-" * (bar_width - filled)
    # Truncate long filenames
    display_name = filename if len(filename) <= 50 else "..." + filename[-47:]
    sys.stdout.write(f"\r  [{bar}] {current}/{total}  {display_name:<50}")
    sys.stdout.flush()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Install Huginn from CloudFront CDN.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--dir",
        default="./huginn",
        help="Installation directory (default: ./huginn)",
    )
    parser.add_argument(
        "--license-key",
        default=None,
        help="License key to embed in the installation",
    )
    args = parser.parse_args()

    install_dir = Path(args.dir).resolve()

    print("=" * 60)
    print("  Huginn Installer")
    print("=" * 60)
    print()
    print(f"  Install directory: {install_dir}")
    print(f"  Source:            {CDN_BASE_URL}")
    print()

    # Confirm if directory already exists and has files
    if install_dir.exists() and any(install_dir.iterdir()):
        response = input(f"  Directory '{install_dir}' is not empty. Continue? [y/N]: ")
        if response.lower() not in ("y", "yes"):
            print("  Installation cancelled.")
            sys.exit(0)

    install_dir.mkdir(parents=True, exist_ok=True)

    # Fetch manifest
    print("  Fetching manifest...")
    manifest = fetch_manifest(license_key=args.license_key)

    version = manifest.get("latest_version", "unknown")
    files = manifest.get("files", [])
    total = len(files)

    print(f"  Version: {version}")
    print(f"  Files to download: {total}")
    print()

    # Download all files
    failed = []
    for idx, file_entry in enumerate(files, start=1):
        rel_path = file_entry["path"]
        url = file_entry["url"]
        expected_hash = file_entry["sha256"].lower()

        dest_path = install_dir / rel_path
        print_progress(idx, total, rel_path)

        try:
            actual_hash = download_file(url, dest_path)
            if actual_hash != expected_hash:
                failed.append((rel_path, "Hash mismatch"))
        except RuntimeError as e:
            failed.append((rel_path, str(e)))

    # End progress line
    print()
    print()

    # Write local manifest
    write_local_manifest(install_dir, manifest)

    # Write license key if provided
    if args.license_key:
        license_path = install_dir / "huginn.lic"
        license_path.write_text(args.license_key, encoding="utf-8")
        print(f"  License key written to: {license_path}")

    # Summary
    if failed:
        print(f"  WARNING: {len(failed)} file(s) failed to download:")
        for path, reason in failed[:10]:
            print(f"    - {path}: {reason}")
        if len(failed) > 10:
            print(f"    ... and {len(failed) - 10} more")
        print()
        print("  Installation completed with errors.")
        print("  Run 'Check for Updates' from within the app to retry failed files.")
    else:
        print(f"  Installation complete! ({total} files)")

    print()
    print("  To run Huginn:")
    print(f"    cd {install_dir}")
    print(f"    pip install -r requirements.txt")
    print(f"    python main.py")
    print()


if __name__ == "__main__":
    main()
