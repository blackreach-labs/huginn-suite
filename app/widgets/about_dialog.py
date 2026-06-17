import tempfile
from pathlib import Path

from PyQt6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTextEdit, QProgressBar
from PyQt6.QtCore import QThread, pyqtSignal, Qt
from PyQt6.QtGui import QFont
from ..core.github_updater import GitHubReleaseChecker, ReleaseDownloader, ReleaseInfo
from ..core.integrity_verifier import IntegrityVerifier
from ..core.update_installer import UpdateInstaller
from ..core.version import get_version
import socket
import psutil

GITHUB_OWNER = "Cinnamon-Mug"
GITHUB_REPO = "huginn"


class UpdateCheckWorker(QThread):
    """Background thread for checking GitHub releases."""

    update_available = pyqtSignal(object)  # ReleaseInfo
    no_update = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, owner: str = GITHUB_OWNER, repo: str = GITHUB_REPO, parent=None):
        super().__init__(parent)
        self.owner = owner
        self.repo = repo

    def run(self):
        try:
            checker = GitHubReleaseChecker(self.owner, self.repo)
            release_info = checker.check_for_update()
            if release_info is not None:
                self.update_available.emit(release_info)
            else:
                self.no_update.emit()
        except Exception as e:
            self.error.emit(str(e))


class UpdateInstallWorker(QThread):
    """Background thread for downloading and installing updates."""

    progress = pyqtSignal(int, int)  # bytes_received, total_bytes
    status = pyqtSignal(str)  # status message
    finished = pyqtSignal(bool, str)  # success, message

    def __init__(self, release_info: ReleaseInfo, parent=None):
        super().__init__(parent)
        self.release_info = release_info

    def run(self):
        temp_dir = Path(tempfile.mkdtemp(prefix="huginn_update_"))
        zip_path = temp_dir / f"huginn-{self.release_info.version}.zip"
        checksum_path = temp_dir / f"huginn-{self.release_info.version}.zip.sha256"

        try:
            # Step 1: Download the zip archive
            self.status.emit("Downloading update archive...")
            downloader = ReleaseDownloader()
            downloader.download(
                self.release_info.zip_url,
                zip_path,
                progress_callback=self._on_progress,
            )

            # Step 2: Download the checksum file
            self.status.emit("Downloading checksum...")
            downloader.download(self.release_info.checksum_url, checksum_path)

            # Step 3: Verify integrity
            self.status.emit("Verifying integrity...")
            verifier = IntegrityVerifier()
            verifier.verify(zip_path, checksum_path)

            # Step 4: Install the update
            self.status.emit("Installing update...")
            app_root = Path(__file__).parent.parent.parent
            installer = UpdateInstaller(app_root)
            installer.install(zip_path, self.release_info.version)

            # Step 5: Clean up temp files on success
            self._cleanup_temp(temp_dir)

            self.finished.emit(True, "Update installed successfully. Please restart the application.")

        except Exception as e:
            # Clean up downloaded temp files on failure
            self._cleanup_temp(temp_dir)
            self.finished.emit(False, str(e))

    def _on_progress(self, bytes_received: int, total_bytes: int):
        self.progress.emit(bytes_received, total_bytes)

    def _cleanup_temp(self, temp_dir: Path):
        """Remove the temporary download directory and its contents."""
        try:
            import shutil
            if temp_dir.exists():
                shutil.rmtree(temp_dir)
        except OSError:
            pass

class AboutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("About Huginn")
        self.setFixedSize(650, 750)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Huginn Advanced Security Framework")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setFont(QFont("Neuropol X", 16, QFont.Weight.Bold))
        layout.addWidget(title)
        
        # Version info
        version_text = f"""
        <p><b>Version:</b> {get_version()}</p>
        <p><b>Description:</b> Comprehensive cybersecurity toolkit with AI-powered vulnerability assessment</p>
        
        <p><b>Key Features:</b></p>
        <ul>
            <li>🧠 Neural Network Vulnerability Analysis</li>
            <li>🔬 Quantum-Inspired Fuzzing</li>
            <li>🤖 Autonomous Security Agent</li>
            <li>📊 ML Vulnerability Prediction</li>
            <li>🎯 Advanced Exploitation</li>
            <li>📈 Compliance Reporting</li>
            <li>🔍 OSINT Intelligence</li>
            <li>🛡️ WAF Evasion</li>
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
        self.update_log.setMaximumHeight(100)
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
        """Get network interface information"""
        try:
            interfaces = []
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:  # IPv4
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
        
    def on_update_available(self, release_info):
        self.progress_bar.setVisible(False)
        self.update_status.setText(f"Update available: Version {release_info.version}")
        self.install_btn.setVisible(True)
        self.check_btn.setEnabled(True)
        self.install_btn.setEnabled(True)
        self.pending_release_info = release_info
        
    def on_no_update(self):
        self.progress_bar.setVisible(False)
        self.update_status.setText("You're up to date!")
        self.check_btn.setEnabled(True)
        self.install_btn.setEnabled(False)
        
    def on_check_error(self, error):
        self.progress_bar.setVisible(False)
        self.update_status.setText(f"Update check failed: {error}")
        self.update_log.setVisible(True)
        self.update_log.append(f"Error: {error}")
        self.check_btn.setEnabled(True)
        self.install_btn.setEnabled(False)
        
    def install_update(self):
        self.install_btn.setEnabled(False)
        self.check_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.update_log.setVisible(True)
        self.update_log.clear()
        
        self.install_worker = UpdateInstallWorker(self.pending_release_info)
        self.install_worker.progress.connect(self.on_download_progress)
        self.install_worker.status.connect(self.on_install_status)
        self.install_worker.finished.connect(self.on_install_finished)
        self.install_worker.start()
        
    def on_download_progress(self, bytes_received, total_bytes):
        self.progress_bar.setRange(0, 100)
        if total_bytes > 0:
            percentage = int(bytes_received * 100 / total_bytes)
            self.progress_bar.setValue(percentage)
        
    def on_install_status(self, message):
        self.update_log.append(message)
        
    def on_install_finished(self, success, message):
        self.progress_bar.setVisible(False)
        if success:
            self.update_log.append(message)
            self.update_status.setText("Update installed successfully. Please restart the application.")
        else:
            self.update_log.append(f"Error: {message}")
            self.update_status.setText("Update failed")
            self.check_btn.setEnabled(True)
            self.install_btn.setEnabled(True)