# Requirements Document

## Introduction

This document defines the requirements for overhauling the Huginn application's update system. The current S3/CloudFront-based updater (with RSA signature verification) will be replaced with a GitHub Releases-based system. The new system supports only manual "Check for Updates" triggered from the About dialog — no background auto-update functionality. The overhaul also resolves the existing version inconsistency (auto_updater.py: 1.3.1, manifest.json: 1.3.3, setup.py: 8.0.0) by establishing a single source of truth for the application version.

## Glossary

- **Updater**: The core module responsible for querying GitHub Releases, comparing versions, downloading release assets, verifying integrity, and installing updates
- **About_Dialog**: The PyQt6 dialog accessible via Help > About that contains the "Check for Updates" and "Install Update" UI controls
- **GitHub_Releases_API**: The GitHub REST API endpoint (`https://api.github.com/repos/{owner}/{repo}/releases/latest`) used to query available releases
- **Release_Asset**: A file attached to a GitHub Release (e.g., the application zip archive and its SHA256 checksum file)
- **Version_File**: A single `VERSION` file at the project root that serves as the canonical source of the application's current version
- **Semantic_Version**: A version string following the `MAJOR.MINOR.PATCH` format (e.g., `8.0.0`)
- **Integrity_Checksum**: A SHA256 hash used to verify that a downloaded file has not been corrupted or tampered with
- **Backup_Directory**: A temporary copy of the current application files created before an update is applied, enabling rollback
- **Release_Packager**: The script that creates release archives and metadata for publishing to GitHub Releases

## Requirements

### Requirement 1: Single Source of Truth for Version

**User Story:** As a developer, I want a single canonical version definition, so that there are no version inconsistencies across the codebase.

#### Acceptance Criteria

1. THE Version_File SHALL contain the application version as a single Semantic_Version string in the format MAJOR.MINOR.PATCH (e.g., "8.0.0") with no leading or trailing whitespace, encoded as UTF-8, and containing no other content
2. WHEN the application starts, THE Updater SHALL read the current version exclusively from the Version_File
3. WHEN a release is packaged, THE Release_Packager SHALL read the version from the Version_File
4. THE Version_File SHALL be located at the project root as a plain text file named `VERSION`
5. IF the Version_File is missing or contains a string that does not match the MAJOR.MINOR.PATCH format, THEN THE System SHALL fail to start and provide an error message indicating that the version file is missing or malformed

### Requirement 2: Query GitHub Releases for Latest Version

**User Story:** As a user, I want the application to check GitHub for the latest release, so that I know when a newer version is available.

#### Acceptance Criteria

1. WHEN the user clicks "Check for Updates", THE Updater SHALL send an HTTP GET request to the GitHub_Releases_API for the latest release
2. WHEN the GitHub_Releases_API returns a successful response, THE Updater SHALL strip any leading "v" prefix from the release tag and extract it as the available Semantic_Version
3. WHEN the GitHub_Releases_API returns a successful response, THE Updater SHALL extract the Release_Asset download URLs for the zip archive and checksum file
4. IF the GitHub_Releases_API returns an HTTP error status, THEN THE Updater SHALL report an error message indicating the HTTP status code to the About_Dialog
5. IF the GitHub_Releases_API request times out after 30 seconds, THEN THE Updater SHALL report a timeout error to the About_Dialog
6. IF the network is unreachable, THEN THE Updater SHALL report a connectivity error to the About_Dialog
7. IF the release response does not contain the expected Release_Assets (zip archive or checksum file), THEN THE Updater SHALL report an error indicating the release assets are missing
8. IF the release tag cannot be parsed as a valid Semantic_Version after prefix stripping, THEN THE Updater SHALL report an error indicating the version format is unrecognized

### Requirement 3: Version Comparison

**User Story:** As a user, I want the updater to determine whether the available release is newer than my current version, so that I only see relevant update notifications.

#### Acceptance Criteria

1. WHEN a release version is retrieved from GitHub, THE Updater SHALL strip any leading "v" prefix from the release tag before comparison
2. WHEN a release version is retrieved from GitHub, THE Updater SHALL compare it against the current version by comparing MAJOR, MINOR, and PATCH components numerically in that precedence order
3. WHEN the remote version is greater than the current version, THE Updater SHALL report that an update is available including the remote version number
4. WHEN the remote version is equal to or less than the current version, THE Updater SHALL report that no update is available
5. IF the release tag cannot be parsed as a valid Semantic_Version after prefix stripping, THEN THE Updater SHALL report an error indicating the version format is unrecognized and treat the check as failed

### Requirement 4: Download Release Assets

**User Story:** As a user, I want to download the update from GitHub, so that I can install the latest version.

#### Acceptance Criteria

1. WHEN the user clicks "Install Update", THE Updater SHALL download the release zip archive from the Release_Asset URL
2. WHEN the user clicks "Install Update", THE Updater SHALL download the SHA256 checksum file from the Release_Asset URL
3. WHILE downloading, THE Updater SHALL report download progress to the About_Dialog as bytes received and total bytes expected (when the server provides a Content-Length header)
4. IF the download fails due to a network error, THEN THE Updater SHALL delete any partially downloaded files, report the failure to the About_Dialog, and abort the installation
5. IF the download fails due to an HTTP error, THEN THE Updater SHALL delete any partially downloaded files, report the HTTP status to the About_Dialog, and abort the installation
6. IF a download does not complete within 300 seconds, THEN THE Updater SHALL cancel the download, delete any partially downloaded files, report a timeout error to the About_Dialog, and abort the installation

### Requirement 5: Integrity Verification

**User Story:** As a user, I want downloaded updates to be verified for integrity, so that corrupted or tampered files are not installed.

#### Acceptance Criteria

1. WHEN a release archive has been downloaded, THE Updater SHALL compute the SHA256 hash of the entire downloaded file
2. WHEN the computed hash is available, THE Updater SHALL compare it against the expected hash extracted from the downloaded checksum file using case-insensitive hexadecimal string comparison
3. IF the computed hash does not match the expected hash, THEN THE Updater SHALL delete the downloaded archive and checksum file, abort the installation, and report an integrity verification failure to the About_Dialog
4. IF the checksum file cannot be parsed to extract a valid SHA256 hex string (64 hexadecimal characters), THEN THE Updater SHALL abort the installation and report a checksum file format error to the About_Dialog
5. WHEN the hash verification succeeds, THE Updater SHALL mark the archive as verified and proceed to the installation phase

### Requirement 6: Install Update with Backup

**User Story:** As a user, I want updates installed safely with a backup of the current version, so that I can recover if something goes wrong.

#### Acceptance Criteria

1. WHEN installation begins, THE Updater SHALL create a Backup_Directory containing a copy of the current `app` directory
2. IF backup creation fails, THEN THE Updater SHALL abort the installation and report the failure to the About_Dialog
3. WHEN the backup is created, THE Updater SHALL extract the release archive over the current installation directory
4. WHEN extraction completes successfully, THE Updater SHALL update the Version_File to the new version
5. WHEN installation succeeds, THE Updater SHALL display a restart prompt in the About_Dialog informing the user to restart the application
6. IF extraction fails, THEN THE Updater SHALL restore the Backup_Directory to the `app` directory and report the failure to the About_Dialog
7. WHEN installation succeeds, THE Updater SHALL delete the Backup_Directory to reclaim disk space

### Requirement 7: Rollback on Installation Failure

**User Story:** As a user, I want the application to automatically roll back a failed update, so that my installation remains usable.

#### Acceptance Criteria

1. IF any step after backup creation fails (archive extraction or Version_File update), THEN THE Updater SHALL remove the contents of the `app` directory and restore all files from the Backup_Directory to the `app` directory
2. IF the Version_File was modified before the failure occurred, THEN THE Updater SHALL restore the Version_File to its pre-update content as part of the rollback
3. WHEN rollback completes successfully, THE Updater SHALL report to the About_Dialog that the rollback was successful and the previous version is restored
4. IF rollback itself fails, THEN THE Updater SHALL report the error to the About_Dialog and display the Backup_Directory file path so the user can perform manual recovery

### Requirement 8: UI Feedback in About Dialog

**User Story:** As a user, I want clear visual feedback during the update process, so that I understand what is happening at each stage.

#### Acceptance Criteria

1. WHEN an update check is in progress, THE About_Dialog SHALL display an indeterminate progress indicator
2. WHEN an update is available, THE About_Dialog SHALL display the new version number and make the "Install Update" button visible
3. WHEN no update is available, THE About_Dialog SHALL display a message confirming the current version is the latest
4. WHILE a download is in progress, THE About_Dialog SHALL display a determinate progress bar showing download percentage
5. WHILE installation is in progress, THE About_Dialog SHALL display status messages in the update log area
6. WHEN an error occurs, THE About_Dialog SHALL display the error message in the update log area
7. WHILE an update check or installation is in progress, THE About_Dialog SHALL disable the "Check for Updates" and "Install Update" buttons to prevent concurrent operations

### Requirement 9: Remove Legacy S3/CloudFront Update Infrastructure

**User Story:** As a developer, I want the old S3/CloudFront update code removed, so that the codebase has no dead code or confusing legacy paths.

#### Acceptance Criteria

1. THE Updater SHALL not contain any references to CloudFront URLs or S3 bucket identifiers used for update distribution (this does not apply to CloudFront or S3 references in pentest tooling, wordlists, or documentation unrelated to the update system)
2. THE codebase SHALL not contain the `auto_updater.py` module in `app/core/`
3. THE codebase SHALL not contain the `temp_update_fix.py` module in `app/core/`
4. THE codebase SHALL not contain the `update_manager.py` background auto-check threading logic, specifically the `start_auto_check`, `stop_auto_check`, and `_auto_check_loop` methods and their associated `threading.Event` and daemon thread
5. THE codebase SHALL not contain the `deploy_update.sh` script at the project root
6. THE `main.py` cleanup logic SHALL not contain the `_cleanup_update_manager()` function or its invocation in `cleanup_on_exit()`

### Requirement 10: No Background Auto-Update

**User Story:** As a user, I want updates to only occur when I explicitly request them, so that my workflow is not interrupted.

#### Acceptance Criteria

1. THE Updater SHALL initiate update checks only when the user clicks the "Check for Updates" button in the About_Dialog
2. THE Updater SHALL not run background threads, timers, scheduled tasks, or event-driven triggers for periodic or automatic update checking
3. WHEN the application starts, THE application SHALL not send any network requests to the GitHub_Releases_API or any other update-related endpoint
4. THE Updater SHALL not initiate update checks in response to external signals, push notifications, or application lifecycle events other than the user clicking "Check for Updates"

### Requirement 11: Release Packaging for GitHub Releases

**User Story:** As a developer, I want a packaging script that produces release artifacts suitable for GitHub Releases, so that I can publish updates easily.

#### Acceptance Criteria

1. WHEN a release is created, THE Release_Packager SHALL produce a zip archive containing the `app` directory, named using the pattern `huginn-{version}.zip` where `{version}` is the Semantic_Version read from the Version_File
2. WHEN a release is created, THE Release_Packager SHALL produce a checksum file named `huginn-{version}.zip.sha256` containing the SHA256 hex digest followed by two spaces and the archive filename
3. WHEN a release is created, THE Release_Packager SHALL read the version from the Version_File and include it in the output filenames
4. THE Release_Packager SHALL not require RSA private keys or produce RSA signatures
5. THE Release_Packager SHALL not reference S3 upload instructions in its output
6. IF the Version_File is missing or does not contain a valid Semantic_Version string, THEN THE Release_Packager SHALL exit with a non-zero status and print an error message indicating the version could not be read
7. WHEN packaging completes successfully, THE Release_Packager SHALL write all output artifacts to a `dist` directory relative to the project root
