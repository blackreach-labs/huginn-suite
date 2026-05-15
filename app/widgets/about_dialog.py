from PyQt6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTextEdit, QProgressBar
from PyQt6.QtCore import QThread, pyqtSignal, Qt
from PyQt6.QtGui import QFont
from ..core.update_manager import update_manager
import socket
import psutil

class UpdateCheckWorker(QThread):
    update_found = pyqtSignal(dict)
    no_update = pyqtSignal()
    error = pyqtSignal(str)
    
    def run(self):
        try:
            manifest = update_manager.check_now()
            if manifest:
                self.update_found.emit(manifest)
            else:
                self.no_update.emit()
        except Exception as e:
            self.error.emit(str(e))

class UpdateInstallWorker(QThread):
    progress = pyqtSignal(str)
    finished = pyqtSignal(bool)
    
    def __init__(self, manifest):
        super().__init__()
        self.manifest = manifest
        
    def run(self):
        try:
            self.progress.emit("Downloading update...")
            success = update_manager.install_update(self.manifest)
            self.finished.emit(success)
        except Exception as e:
            self.progress.emit(f"Error: {e}")
            self.finished.emit(False)

class AboutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("About Huginn")
        self.setFixedSize(500, 650)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Huginn Advanced Security Framework")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        layout.addWidget(title)
        
        # Version info
        version_text = f"""
        <p><b>Version:</b> {update_manager.updater.current_version}</p>
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
        self.update_status.setText("Checking for updates...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate
        
        self.check_worker = UpdateCheckWorker()
        self.check_worker.update_found.connect(self.on_update_found)
        self.check_worker.no_update.connect(self.on_no_update)
        self.check_worker.error.connect(self.on_check_error)
        self.check_worker.start()
        
    def on_update_found(self, manifest):
        self.progress_bar.setVisible(False)
        self.update_status.setText(f"Update available: Version {manifest['version']}")
        self.install_btn.setVisible(True)
        self.check_btn.setEnabled(True)
        self.pending_manifest = manifest
        
    def on_no_update(self):
        self.progress_bar.setVisible(False)
        self.update_status.setText("You have the latest version")
        self.check_btn.setEnabled(True)
        
    def on_check_error(self, error):
        self.progress_bar.setVisible(False)
        self.update_status.setText(f"Update check failed: {error}")
        self.update_log.setVisible(True)
        self.update_log.setText(f"Error details: {error}")
        self.check_btn.setEnabled(True)
        
    def install_update(self):
        self.install_btn.setEnabled(False)
        self.check_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.update_log.setVisible(True)
        self.update_log.clear()
        
        self.install_worker = UpdateInstallWorker(self.pending_manifest)
        self.install_worker.progress.connect(self.on_install_progress)
        self.install_worker.finished.connect(self.on_install_finished)
        self.install_worker.start()
        
    def on_install_progress(self, message):
        self.update_log.append(message)
        
    def on_install_finished(self, success):
        self.progress_bar.setVisible(False)
        if success:
            self.update_log.append("Update completed! Application will restart.")
            self.update_status.setText("Update installed successfully")
            # Close dialog and restart will happen automatically
            self.accept()
        else:
            self.update_log.append("Update installation failed!")
            self.update_status.setText("Update failed")
            self.check_btn.setEnabled(True)
            self.install_btn.setEnabled(True)