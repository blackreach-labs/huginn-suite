# Implementation Plan: Update System Overhaul

## Overview

Replace the existing S3/CloudFront-based updater with a GitHub Releases-based system. Establish a single `VERSION` file as the canonical version source, implement manual-only update checking via the About dialog, add SHA256 integrity verification, backup/rollback installation, and remove all legacy update infrastructure.

## Tasks

- [x] 1. Create VERSION file and version management module
  - [x] 1.1 Create the `VERSION` file at the project root
    - Create `VERSION` file containing `8.0.0` as a single line, UTF-8 encoded, no trailing whitespace or newline
    - _Requirements: 1.1, 1.4_

  - [x] 1.2 Implement `app/core/version.py` module
    - Implement `VersionError` exception class
    - Implement `get_version()` function that reads from the `VERSION` file at project root, validates format against `^\d+\.\d+\.\d+$`, and raises `VersionError` if missing or malformed
    - Implement `parse_version(version_str)` that strips leading "v" prefix and returns `(major, minor, patch)` tuple, raising `ValueError` for invalid formats
    - Implement `compare_versions(current, remote)` returning -1, 0, or 1 based on numeric tuple comparison
    - _Requirements: 1.1, 1.2, 1.5, 3.1, 3.2, 3.3, 3.4_

  - [x]* 1.3 Write property tests for version module
    - **Property 1: Version Validation** — For any string, the parser accepts if and only if it matches `^\d+\.\d+\.\d+$` after optional "v" stripping
    - **Property 2: Prefix Stripping Idempotence** — Parsing "v1.2.3" and "1.2.3" produces the same tuple
    - **Property 3: Numeric Version Comparison** — compare_versions result is consistent with integer tuple ordering
    - **Validates: Requirements 1.1, 1.5, 2.2, 3.1, 3.2, 3.3, 3.4**

  - [x]* 1.4 Write unit tests for version module
    - Test valid version strings ("8.0.0", "0.1.0", "100.200.300")
    - Test invalid strings ("", "1.2", "1.2.3.4", "abc", "v", whitespace variants)
    - Test `get_version()` with missing file, malformed content
    - Test comparison edge cases (equal, less, greater across major/minor/patch)
    - _Requirements: 1.1, 1.2, 1.5, 3.2, 3.3, 3.4, 3.5_

- [x] 2. Implement GitHub Release checker
  - [x] 2.1 Implement `app/core/github_updater.py` — `GitHubReleaseChecker` class
    - Implement `ReleaseInfo` dataclass with `version`, `zip_url`, `checksum_url`, `release_notes` fields
    - Implement error hierarchy: `UpdateCheckError`, `NetworkError`, `TimeoutError`, `AssetNotFoundError`, `VersionFormatError`
    - Implement `GitHubReleaseChecker.__init__(owner, repo)` storing owner/repo and building API URL
    - Implement `check_for_update()` that sends HTTP GET to GitHub Releases API with 30s timeout, parses JSON response, strips "v" prefix from tag, validates semver, extracts zip and sha256 asset URLs, compares against current version via `version.py`, returns `ReleaseInfo` if update available or `None` if not
    - Handle HTTP errors (report status code), timeouts, network unreachable, missing assets, and unparseable tags with appropriate exceptions
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 3.1, 3.2, 3.3, 3.4, 3.5_

  - [x]* 2.2 Write property test for HTTP error code preservation
    - **Property 4: HTTP Error Code Preservation** — For any HTTP status 400–599, the error message contains that status code as a substring
    - **Validates: Requirements 2.4**

  - [x]* 2.3 Write unit tests for `GitHubReleaseChecker`
    - Test successful response with valid release (mock API)
    - Test response with missing zip asset
    - Test response with missing checksum asset
    - Test response with unparseable tag name
    - Test HTTP 404/500 error responses
    - Test request timeout
    - Test network unreachable
    - Test "no update available" when remote version <= current
    - _Requirements: 2.1–2.8, 3.3, 3.4_

- [x] 3. Implement release downloader
  - [x] 3.1 Implement `ReleaseDownloader` class in `app/core/github_updater.py`
    - Implement `download(url, destination, progress_callback)` method
    - Stream download with progress reporting (bytes_received, total_bytes from Content-Length)
    - Implement 300-second download timeout
    - On network error or HTTP error: delete partial files, raise appropriate exception
    - On timeout: cancel download, delete partial files, raise `TimeoutError`
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6_

  - [x]* 3.2 Write unit tests for `ReleaseDownloader`
    - Test successful download with progress callback invocations
    - Test download with no Content-Length header
    - Test network error mid-download (verify partial file cleanup)
    - Test HTTP error response (verify partial file cleanup)
    - Test timeout (verify partial file cleanup)
    - _Requirements: 4.1–4.6_

- [x] 4. Implement integrity verification
  - [x] 4.1 Implement `app/core/integrity_verifier.py`
    - Implement `IntegrityError` and `ChecksumFormatError` exceptions
    - Implement `IntegrityVerifier.verify(archive_path, checksum_path)` that:
      - Reads checksum file and extracts 64-char hex string (format: `<hex>  <filename>`)
      - Raises `ChecksumFormatError` if file doesn't match expected format
      - Computes SHA256 of entire archive file
      - Compares computed vs expected hash (case-insensitive)
      - Raises `IntegrityError` on mismatch
      - Returns `True` on success
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5_

  - [x]* 4.2 Write property tests for integrity verification
    - **Property 5: Integrity Round-Trip** — For any byte sequence, computing SHA256 and comparing against hashlib.sha256 always matches
    - **Property 6: Checksum Format Validation** — Any string not matching `<64-hex>  <filename>` raises `ChecksumFormatError`
    - **Validates: Requirements 5.1, 5.2, 5.4**

  - [x]* 4.3 Write unit tests for integrity verification
    - Test valid checksum file with matching hash
    - Test hash mismatch (correct format, wrong hash)
    - Test malformed checksum files (short hash, no spaces, no filename, empty)
    - Test case-insensitive comparison (uppercase vs lowercase hex)
    - _Requirements: 5.1–5.5_

- [x] 5. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 6. Implement update installer with backup and rollback
  - [x] 6.1 Implement `app/core/update_installer.py`
    - Implement `InstallationError` and `RollbackError` (with `backup_path` attribute) exceptions
    - Implement `UpdateInstaller.__init__(app_root)` setting paths for app dir and backup dir
    - Implement `install(archive_path, new_version)` that:
      - Creates backup of `app/` directory to backup location
      - Aborts with `InstallationError` if backup creation fails
      - Extracts release archive over the `app/` directory
      - Updates `VERSION` file to new version
      - Deletes backup directory on success
      - On failure after backup: restores `app/` from backup, restores `VERSION` file
      - Raises `InstallationError` if rollback succeeds
      - Raises `RollbackError` (with backup path) if rollback itself fails
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7, 7.1, 7.2, 7.3, 7.4_

  - [x]* 6.2 Write property test for rollback invariant
    - **Property 7: Rollback Invariant** — For any initial app directory state and VERSION content, if install fails after backup, rollback restores byte-for-byte identical state
    - **Validates: Requirements 7.1, 7.2**

  - [x]* 6.3 Write unit tests for update installer
    - Test successful installation (backup created, extracted, VERSION updated, backup deleted)
    - Test backup creation failure (aborts cleanly)
    - Test extraction failure (rollback restores app/ and VERSION)
    - Test VERSION update failure (rollback restores both)
    - Test rollback failure (RollbackError includes backup path)
    - _Requirements: 6.1–6.7, 7.1–7.4_

- [x] 7. Update About dialog UI
  - [x] 7.1 Implement `UpdateCheckWorker` and `UpdateInstallWorker` in `app/widgets/about_dialog.py`
    - Create `UpdateCheckWorker(QThread)` with signals: `update_available(object)`, `no_update()`, `error(str)`
    - Worker calls `GitHubReleaseChecker.check_for_update()` and emits appropriate signal
    - Create `UpdateInstallWorker(QThread)` with signals: `progress(int, int)`, `status(str)`, `finished(bool, str)`
    - Worker orchestrates: download zip + checksum → verify integrity → install → emit result
    - On any failure: clean up downloaded files, emit error via `finished(False, message)`
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 10.1_

  - [x] 7.2 Update About dialog UI controls and state management
    - Add "Check for Updates" button that starts `UpdateCheckWorker`
    - Add "Install Update" button (initially hidden) that starts `UpdateInstallWorker`
    - Show indeterminate progress during update check
    - Show new version number when update is available
    - Show "you're up to date" message when no update available
    - Show determinate progress bar during download (percentage from bytes_received/total_bytes)
    - Show status messages in update log `QTextEdit` during installation
    - Show error messages in update log area
    - Disable both buttons while any operation is in progress
    - Show restart prompt on successful installation
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 10.1, 10.2_

  - [x]* 7.3 Write unit tests for About dialog update UI
    - Test button states during check (disabled while running)
    - Test UI shows version number when update available
    - Test UI shows "up to date" when no update
    - Test error display in log area
    - Test progress bar visibility and values during download
    - _Requirements: 8.1–8.7_

- [x] 8. Implement release packager
  - [x] 8.1 Rewrite `release_packager.py` at project root
    - Read version from `VERSION` file (exit non-zero if missing/invalid)
    - Create `dist/` directory if it doesn't exist
    - Create zip archive of `app/` directory named `huginn-{version}.zip`
    - Compute SHA256 of the zip archive
    - Write checksum file `huginn-{version}.zip.sha256` with format: `<hex>  huginn-{version}.zip`
    - Remove all RSA signing logic and S3 upload references
    - Output both files to `dist/` directory
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 11.7_

  - [x]* 8.2 Write property test for release packaging
    - **Property 8: Release Packaging Correctness** — For any valid version and app directory contents, the packager produces correctly named zip and checksum file, and the checksum matches independent SHA256 computation
    - **Validates: Requirements 11.1, 11.2**

  - [x]* 8.3 Write unit tests for release packager
    - Test output filenames match `huginn-{version}.zip` and `huginn-{version}.zip.sha256`
    - Test checksum file content format matches `<hex>  <filename>`
    - Test checksum matches actual zip hash
    - Test failure when VERSION file missing
    - Test failure when VERSION file has invalid format
    - Test artifacts are written to `dist/` directory
    - _Requirements: 11.1–11.7_

- [x] 9. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 10. Remove legacy update infrastructure
  - [x] 10.1 Delete legacy update files
    - Delete `app/core/auto_updater.py`
    - Delete `app/core/temp_update_fix.py`
    - Delete `deploy_update.sh` from project root
    - _Requirements: 9.2, 9.3, 9.5_

  - [x] 10.2 Remove background auto-check logic from `app/core/update_manager.py`
    - Remove `start_auto_check`, `stop_auto_check`, and `_auto_check_loop` methods
    - Remove associated `threading.Event` and daemon thread code
    - Remove any S3/CloudFront URL references related to the update system
    - If the module has no remaining functionality after removal, delete the entire file
    - _Requirements: 9.1, 9.4, 10.2, 10.3, 10.4_

  - [x] 10.3 Clean up `main.py` references to legacy update system
    - Remove `_cleanup_update_manager()` function
    - Remove invocation of `_cleanup_update_manager()` from `cleanup_on_exit()`
    - Remove any imports of deleted modules (`auto_updater`, `temp_update_fix`, `update_manager` background logic)
    - _Requirements: 9.6_

  - [x] 10.4 Wire application startup to use new version module
    - Update `main.py` or application entry point to call `get_version()` at startup
    - If `VersionError` is raised, display error message and exit
    - Remove any version reads from `manifest.json` or `setup.py` in the startup path
    - _Requirements: 1.2, 1.5, 10.3_

- [x] 11. Integration wiring and final verification
  - [x] 11.1 Wire About dialog to use new update system components
    - Import and configure `GitHubReleaseChecker` with correct owner/repo values
    - Connect "Check for Updates" button to `UpdateCheckWorker`
    - Connect "Install Update" button to `UpdateInstallWorker`
    - Ensure no update checks occur at application startup or on any lifecycle event
    - _Requirements: 10.1, 10.2, 10.3, 10.4_

  - [x]* 11.2 Write smoke tests for legacy code removal
    - Assert `app/core/auto_updater.py` does not exist
    - Assert `app/core/temp_update_fix.py` does not exist
    - Assert `deploy_update.sh` does not exist
    - Assert no CloudFront/S3 URLs in update-related modules
    - Assert no background threading for update checks
    - Assert `main.py` has no `_cleanup_update_manager` reference
    - _Requirements: 9.1–9.6, 10.2, 10.3_

  - [x]* 11.3 Write integration tests for full update flow
    - Test full check → download → verify → install → restart prompt flow (mocked GitHub API)
    - Test full rollback flow (check → download → verify → install fails → rollback → original state)
    - Test network failure at each stage produces correct error messages
    - _Requirements: 2.1–2.8, 4.1–4.6, 5.1–5.5, 6.1–6.7, 7.1–7.4, 8.1–8.7_

- [x] 12. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- Unit tests validate specific examples and edge cases
- The design uses Python with PyQt6 for UI and Hypothesis for property-based testing
- All new core modules go in `app/core/`; the about dialog is at `app/widgets/about_dialog.py`
- The release packager remains at the project root as `release_packager.py`

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "1.2"] },
    { "id": 1, "tasks": ["1.3", "1.4", "2.1"] },
    { "id": 2, "tasks": ["2.2", "2.3", "3.1", "4.1"] },
    { "id": 3, "tasks": ["3.2", "4.2", "4.3"] },
    { "id": 4, "tasks": ["6.1", "8.1"] },
    { "id": 5, "tasks": ["6.2", "6.3", "8.2", "8.3"] },
    { "id": 6, "tasks": ["7.1"] },
    { "id": 7, "tasks": ["7.2", "7.3"] },
    { "id": 8, "tasks": ["10.1", "10.2", "10.3"] },
    { "id": 9, "tasks": ["10.4", "11.1"] },
    { "id": 10, "tasks": ["11.2", "11.3"] }
  ]
}
```
