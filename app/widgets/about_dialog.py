"""About dialog with integrated manifest-based update system."""

from pathlib import Path

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QTextEdit, QProgressBar,
)
from PyQt6.QtCore import QThread, pyqtSignal, Qt
from PyQt6.QtGui import QFont

from ..core.manifest_updater import (
    ManifestUpdater,
    UpdateCheckResult,
    UpdateError,
    ManifestFetchError,
    FileDownloadError,
    IntegrityError,
)

import socket
import psutil


class UpdateCheckWorker(QThread):
    """Background thread for checking the CDN manifest for updates."""

    update_available = pyqtSignal(object)  # UpdateCheckResult
    no_update = pyqtSignal(str)  # current version string
    error = pyqtSignal(str)

    def __init__(self, license_key=None, parent=None):
        super().__init__(parent)
        self.license_key = license_key

    def run(self):
        try:
            updater = ManifestUpdater()
            result = updater.check_for_updates(license_key=self.license_key)
            if result.has_update:
                self.update_available.emit(result)
            else:
                self.no_update.emit(result.local_version)
        except Exception as e:
            self.error.emit(str(e))


class UpdateInstallWorker(QThread):
    """Background thread for downloading and applying file updates."""

    progress = pyqtSignal(int, int, str)  # files_done, files_total, current_file
    status = pyqtSignal(str)
    finished = pyqtSignal(bool, str)  # success, message

    def __init__(self, check_result: UpdateCheckResult, parent=None):
        super().__init__(parent)
        self.check_result = check_result

    def run(self):
        try:
            self.status.emit("Downloading updated files...")
            updater = ManifestUpdater()
            # apply_updates calls os.execv on success — this thread won't
            # continue past that point. The signal below is for error paths.
            updater.apply_updates(
                self.check_result,
                progress_callback=self._on_progress,
            )
            # If we somehow get here (shouldn't with os.execv), signal success
            self.finished.emit(True, "Update applied. Restarting...")
        except Exception as e:
            self.finished.emit(False, str(e))

    def _on_progress(self, files_done: int, files_total: int, current_file: str):
        self.progress.emit(files_done, files_total, current_file)
        if current_file:
            self.status.emit(f"Updating: {current_file}")


class AboutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("About Huginn")
        self.setFixedSize(650, 750)
        self._pending_result: UpdateCheckResult | None = None
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()

        # Title
        title = QLabel("Huginn Advanced Security Framework")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setFont(QFont("Neuropol X", 16, QFont.Weight.Bold))
        layout.addWidget(title)

        # Version info
        updater = ManifestUpdater()
        current_version = updater.get_local_version()

        version_text = f"""
        <p><b>Version:</b> {current_version}</p>
        <p><b>Description:</b> Comprehensive cybersecurity toolkit with AI-powered vulnerability assessment</p>

        <p><b>Key Features:</b></p>
        <ul>
            <li>Neural Network Vulnerability Analysis</li>
            <li>Quantum-Inspired Fuzzing</li>
            <li>Autonomous Security Agent</li>
            <li>ML Vulnerability Prediction</li>
            <li>Advanced Exploitation</li>
            <li>Compliance Reporting</li>
            <li>OSINT Intelligence</li>
            <li>WAF Evasion</li>
        </ul>
        """

        version_label = QLabel(version_text)
        version_label.setWordWrap(True)
        layout.addWidget(version_label)

        # Network interfaces section
        network_info = self.get_network_interfaces()
        network_label = QLabel(f"<p><b>Network Interfaces:</b></p>{network_info}")
        network_label.setWordWrap(True)
        layout.addWidget(network_label)

        # Update section
        update_layout = QVBoxLayout()

        # Update status
        self.update_status = QLabel("Click 'Check for Updates' to check for new versions")
        update_layout.addWidget(self.update_status)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        update_layout.addWidget(self.progress_bar)

        # Update log
        self.update_log = QTextEdit()
        self.update_log.setReadOnly(True)
        self.update_log.setMaximumHeight(120)
        self.update_log.setVisible(False)
        update_layout.addWidget(self.update_log)

        # Buttons
        button_layout = QHBoxLayout()

        self.check_btn = QPushButton("Check for Updates")
        self.check_btn.clicked.connect(self.check_for_updates)
        button_layout.addWidget(self.check_btn)

        self.install_btn = QPushButton("Install Update")
        self.install_btn.setVisible(False)
        self.install_btn.clicked.connect(self.install_update)
        button_layout.addWidget(self.install_btn)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        button_layout.addWidget(close_btn)

        update_layout.addLayout(button_layout)
        layout.addLayout(update_layout)

        self.setLayout(layout)
        self.apply_styling()

    def get_network_interfaces(self):
        """Get network interface information."""
        try:
            interfaces = []
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        interfaces.append(f"<li><b>{interface}:</b> {addr.address}</li>")
            return "<ul>" + "".join(interfaces) + "</ul>" if interfaces else "<p>No network interfaces found</p>"
        except Exception:
            return "<p>Unable to retrieve network information</p>"

    def apply_styling(self):
        self.setStyleSheet("""
            QDialog {
                background-color: rgba(20, 30, 40, 240);
                color: #DCDCDC;
            }
            QLabel {
                color: #DCDCDC;
                padding: 5px;
            }
            QPushButton {
                background-color: rgba(100, 200, 255, 150);
                color: #000000;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(100, 200, 255, 200);
            }
            QPushButton:disabled {
                background-color: rgba(100, 100, 100, 100);
                color: #666666;
            }
            QTextEdit {
                background-color: rgba(40, 50, 60, 200);
                color: #DCDCDC;
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 4px;
            }
            QProgressBar {
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 4px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: rgba(100, 200, 255, 150);
                border-radius: 3px;
            }
        """)

    # ------------------------------------------------------------------
    # Update workflow
    # ------------------------------------------------------------------

    def check_for_updates(self):
        self.check_btn.setEnabled(False)
        self.install_btn.setEnabled(False)
        self.update_status.setText("Checking for updates...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate

        self.check_worker = UpdateCheckWorker()
        self.check_worker.update_available.connect(self.on_update_available)
        self.check_worker.no_update.connect(self.on_no_update)
        self.check_worker.error.connect(self.on_check_error)
        self.check_worker.start()

    def on_update_available(self, result: UpdateCheckResult):
        self.progress_bar.setVisible(False)
        self._pending_result = result
        self.update_status.setText(
            f"Update available: v{result.remote_version} "
            f"({result.update_count} file{'s' if result.update_count != 1 else ''} changed)"
        )
        self.install_btn.setVisible(True)
        self.install_btn.setEnabled(True)
        self.check_btn.setEnabled(True)

        # Show release notes if available
        if result.release_notes:
            self.update_log.setVisible(True)
            self.update_log.setPlainText(result.release_notes)

    def on_no_update(self, version: str):
        self.progress_bar.setVisible(False)
        self.update_status.setText(f"You're up to date! (v{version})")
        self.check_btn.setEnabled(True)
        self.install_btn.setEnabled(False)

    def on_check_error(self, error: str):
        self.progress_bar.setVisible(False)
        self.update_status.setText("Update check failed")
        self.update_log.setVisible(True)
        self.update_log.append(f"Error: {error}")
        self.check_btn.setEnabled(True)
        self.install_btn.setEnabled(False)

    def install_update(self):
        if self._pending_result is None:
            return

        self.install_btn.setEnabled(False)
        self.check_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, self._pending_result.update_count)
        self.progress_bar.setValue(0)
        self.update_log.setVisible(True)
        self.update_log.clear()
        self.update_status.setText("Installing update...")

        self.install_worker = UpdateInstallWorker(self._pending_result)
        self.install_worker.progress.connect(self.on_install_progress)
        self.install_worker.status.connect(self.on_install_status)
        self.install_worker.finished.connect(self.on_install_finished)
        self.install_worker.start()

    def on_install_progress(self, files_done: int, files_total: int, current_file: str):
        self.progress_bar.setValue(files_done)

    def on_install_status(self, message: str):
        self.update_log.append(message)

    def on_install_finished(self, success: bool, message: str):
        self.progress_bar.setVisible(False)
        if success:
            self.update_log.append(message)
            self.update_status.setText("Update complete. Application is restarting...")
        else:
            self.update_log.append(f"Error: {message}")
            self.update_status.setText("Update failed")
            self.check_btn.setEnabled(True)
            self.install_btn.setEnabled(True)
