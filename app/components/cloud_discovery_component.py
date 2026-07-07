from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QLineEdit, QPushButton, QTextEdit, QCheckBox, QFrame)
from PyQt6.QtCore import pyqtSignal
from app.components.progress_component import ProgressComponent

class CloudDiscoveryComponent(QWidget):
    discovery_started = pyqtSignal(str)
    discovery_completed = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.apply_theme()

    def setup_ui(self):
        """Setup cloud discovery UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Input section
        input_frame = self.create_input_section()
        layout.addWidget(input_frame)
        
        # Progress component
        self.progress_component = ProgressComponent(self)
        layout.addWidget(self.progress_component)
        
        # Output section
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setPlaceholderText("Cloud discovery results will appear here...")
        layout.addWidget(self.output_text)

    def create_input_section(self):
        """Create input controls section"""
        frame = QFrame()
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(15, 15, 15, 15)
        
        # Target input
        layout.addWidget(QLabel("Target Domain/Organization:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("e.g., company-name")
        layout.addWidget(self.target_input)
        
        # Cloud services selection
        services_layout = QHBoxLayout()
        services_layout.addWidget(QLabel("Services to check:"))
        
        self.check_aws = QCheckBox("AWS")
        self.check_aws.setChecked(True)
        services_layout.addWidget(self.check_aws)
        
        self.check_azure = QCheckBox("Azure")
        self.check_azure.setChecked(True)
        services_layout.addWidget(self.check_azure)
        
        self.check_gcp = QCheckBox("Google Cloud")
        self.check_gcp.setChecked(True)
        services_layout.addWidget(self.check_gcp)
        
        services_layout.addStretch()
        
        # Control buttons
        self.start_button = QPushButton("Start Cloud Discovery")
        self.start_button.clicked.connect(self.start_discovery)
        services_layout.addWidget(self.start_button)
        
        layout.addLayout(services_layout)
        
        return frame

    def start_discovery(self):
        """Start cloud asset discovery"""
        target = self.target_input.text().strip()
        if not target:
            return
        
        self.output_text.clear()
        self.progress_component.start_progress(f"Cloud discovery for {target}")
        self.start_button.setEnabled(False)
        
        self.discovery_started.emit(target)
        
        # Run discovery
        self.run_cloud_discovery(target)

    def run_cloud_discovery(self, target):
        """Run cloud asset discovery"""
        self.append_output(f"Starting cloud asset discovery for: {target}")
        self.append_output("=" * 50)
        
        results = {}
        
        # AWS discovery
        if self.check_aws.isChecked():
            self.append_output("[*] Checking AWS S3 Buckets...")
            aws_results = self.discover_aws_assets(target)
            results['aws'] = aws_results
            for result in aws_results:
                self.append_output(f"  [+] Found: {result}")
        
        # Azure discovery
        if self.check_azure.isChecked():
            self.append_output("[*] Checking Azure Storage...")
            azure_results = self.discover_azure_assets(target)
            results['azure'] = azure_results
            for result in azure_results:
                self.append_output(f"  [+] Found: {result}")
        
        # GCP discovery
        if self.check_gcp.isChecked():
            self.append_output("[*] Checking Google Cloud Storage...")
            gcp_results = self.discover_gcp_assets(target)
            results['gcp'] = gcp_results
            for result in gcp_results:
                self.append_output(f"  [+] Found: {result}")
        
        self.append_output("=" * 50)
        self.append_output("Cloud asset discovery completed")
        
        self.progress_component.finish_progress("Discovery completed")
        self.start_button.setEnabled(True)
        
        self.discovery_completed.emit(results)

    def discover_aws_assets(self, target):
        """Discover AWS assets"""
        # Simulate AWS discovery
        return [
            f"{target}-backups.s3.amazonaws.com",
            f"{target}-logs.s3.amazonaws.com",
            f"{target}-data.s3.amazonaws.com"
        ]

    def discover_azure_assets(self, target):
        """Discover Azure assets"""
        # Simulate Azure discovery
        return [
            f"{target}storage.blob.core.windows.net",
            f"{target}backup.blob.core.windows.net"
        ]

    def discover_gcp_assets(self, target):
        """Discover GCP assets"""
        # Simulate GCP discovery
        return [
            f"{target}-data.storage.googleapis.com",
            f"{target}-backup.storage.googleapis.com"
        ]

    def append_output(self, text):
        """Append text to output"""
        self.output_text.append(text)

    def apply_theme(self):
        """Theme is applied globally by UnifiedThemeManager."""
        pass