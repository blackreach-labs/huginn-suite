"""Update installer with backup and rollback support.

Handles safe update installation by creating a backup of the current app/
directory before extracting the new release archive. If any step fails after
backup creation, the installer restores the original state from the backup.
"""

import shutil
import zipfile
from pathlib import Path


class InstallationError(Exception):
    """Installation failed but rollback succeeded."""
    pass


class RollbackError(Exception):
    """Rollback itself failed — includes backup path for manual recovery."""

    def __init__(self, message: str, backup_path: Path):
        super().__init__(message)
        self.backup_path = backup_path


class UpdateInstaller:
    """Handles safe update installation with backup and rollback."""

    def __init__(self, app_root: Path):
        self.app_root = app_root
        self.app_dir = app_root / "app"
        self.backup_dir = app_root / "backup"
        self.version_file = app_root / "VERSION"

    def install(self, archive_path: Path, new_version: str) -> None:
        """Install update with backup/rollback.

        Steps:
            1. Create backup of app/ directory
            2. Extract archive over app/
            3. Update VERSION file
            4. Delete backup on success

        On failure after step 1:
            - Restore app/ from backup
            - Restore VERSION file

        Raises:
            InstallationError: Install failed but rollback succeeded
            RollbackError: Rollback itself failed (includes backup_path)
        """
        # Read the current VERSION content before any changes
        original_version: str | None = None
        if self.version_file.exists():
            original_version = self.version_file.read_text(encoding="utf-8")

        # Step 1: Create backup of app/ directory
        try:
            if self.backup_dir.exists():
                shutil.rmtree(self.backup_dir)
            shutil.copytree(self.app_dir, self.backup_dir)
        except OSError as e:
            raise InstallationError(
                f"Failed to create backup of app/ directory: {e}"
            ) from e

        # Steps 2 & 3: Extract archive and update VERSION (with rollback on failure)
        try:
            # Step 2: Extract release archive over the app/ directory
            with zipfile.ZipFile(archive_path, "r") as zf:
                zf.extractall(self.app_dir)

            # Step 3: Update VERSION file to new version
            self.version_file.write_text(new_version, encoding="utf-8")

        except Exception as e:
            # Installation failed — attempt rollback
            install_error_msg = str(e)
            self._rollback(original_version, install_error_msg)
            # _rollback raises either InstallationError or RollbackError
            # so we should never reach here, but just in case:
            raise InstallationError(
                f"Installation failed: {install_error_msg}"
            ) from e

        # Step 4: Delete backup on success
        try:
            shutil.rmtree(self.backup_dir)
        except OSError:
            # Non-critical — backup cleanup failure doesn't affect the update
            pass

    def _rollback(self, original_version: str | None, install_error_msg: str) -> None:
        """Restore app/ from backup and VERSION file content.

        Always raises either InstallationError or RollbackError.
        """
        try:
            # Remove the corrupted/partial app/ directory
            if self.app_dir.exists():
                shutil.rmtree(self.app_dir)

            # Restore app/ from backup
            shutil.copytree(self.backup_dir, self.app_dir)

            # Restore VERSION file content
            if original_version is not None:
                self.version_file.write_text(original_version, encoding="utf-8")

            # Rollback succeeded — clean up backup
            shutil.rmtree(self.backup_dir)

        except Exception as rollback_err:
            raise RollbackError(
                f"Installation failed ({install_error_msg}) and rollback also "
                f"failed ({rollback_err}). Manual recovery needed from backup.",
                backup_path=self.backup_dir,
            ) from rollback_err

        # Rollback succeeded
        raise InstallationError(
            f"Installation failed: {install_error_msg}. "
            "Rollback succeeded — previous version restored."
        )
