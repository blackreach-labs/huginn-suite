# app/widgets/cloud_assets_widget.py
import os
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QLineEdit, QComboBox, QTextEdit, QPushButton,
                            QCheckBox, QGroupBox, QListWidget, QSplitter)
from PyQt6.QtCore import Qt, pyqtSignal, QThreadPool
from app.core.cloud_enumeration import CloudEnumerationWorker
from app.core.logger import logger

class CloudAssetsWidget(QWidget):
    """Cloud Assets enumeration widget"""
    
    scan_completed = pyqtSignal(dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.current_worker = None
        self.is_scanning = False
        self.setup_ui()
        self.connect_signals()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Header removed to save space
        
        # Main content splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(splitter)
        
        # Left panel - Controls
        controls_widget = QWidget()
        controls_layout = QVBoxLayout(controls_widget)
        
        # Target input
        target_group = QGroupBox("Target Configuration")
        target_layout = QVBoxLayout(target_group)
        
        target_row = QHBoxLayout()
        target_row.addWidget(QLabel("Target:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("company, domain, or IP address")
        target_row.addWidget(self.target_input)
        target_layout.addLayout(target_row)
        
        controls_layout.addWidget(target_group)
        
        # Scan type selection
        scan_group = QGroupBox("Scan Configuration")
        scan_layout = QVBoxLayout(scan_group)
        
        scan_type_row = QHBoxLayout()
        scan_type_row.addWidget(QLabel("Scan Type:"))
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems([
            "S3 Bucket Enumeration",
            "Azure Blob Storage",
            "Cloud Metadata APIs",
            "Full Cloud Scan"
        ])
        scan_type_row.addWidget(self.scan_type_combo)
        scan_layout.addLayout(scan_type_row)
        
        # Wordlist selection
        wordlist_row = QHBoxLayout()
        wordlist_row.addWidget(QLabel("Wordlist:"))
        self.wordlist_combo = QComboBox()
        self.populate_wordlists()
        wordlist_row.addWidget(self.wordlist_combo)
        scan_layout.addLayout(wordlist_row)
        
        # Options
        self.check_permissions = QCheckBox("Check bucket permissions")
        self.check_permissions.setChecked(True)
        scan_layout.addWidget(self.check_permissions)
        
        self.enumerate_objects = QCheckBox("Enumerate objects (if accessible)")
        scan_layout.addWidget(self.enumerate_objects)
        
        controls_layout.addWidget(scan_group)
        
        # Custom wordlist
        custom_group = QGroupBox("Custom Keywords")
        custom_layout = QVBoxLayout(custom_group)
        
        self.custom_keywords = QTextEdit()
        self.custom_keywords.setMaximumHeight(100)
        self.custom_keywords.setPlaceholderText("Enter custom keywords (one per line)")
        custom_layout.addWidget(self.custom_keywords)
        
        controls_layout.addWidget(custom_group)
        
        # Control buttons
        button_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start Scan")
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        self.export_btn = QPushButton("Export Results")
        self.export_btn.setEnabled(False)
        
        button_layout.addWidget(self.start_btn)
        button_layout.addWidget(self.stop_btn)
        button_layout.addWidget(self.export_btn)
        controls_layout.addLayout(button_layout)
        
        controls_layout.addStretch()
        splitter.addWidget(controls_widget)
        
        # Right panel - Results
        results_widget = QWidget()
        results_layout = QVBoxLayout(results_widget)
        
        results_label = QLabel("Scan Results")
        results_label.setStyleSheet("font-weight: bold; color: #87CEEB;")
        results_layout.addWidget(results_label)
        
        # Results output
        self.results_output = QTextEdit()
        self.results_output.setReadOnly(True)
        self.results_output.setStyleSheet("""
            QTextEdit {
                background-color: #0A0A0A;
                color: #DCDCDC;
                border: 1px solid #333333;
                font-family: 'Courier New', monospace;
            }
        """)
        results_layout.addWidget(self.results_output)
        
        # Findings summary
        self.findings_list = QListWidget()
        self.findings_list.setMaximumHeight(150)
        results_layout.addWidget(QLabel("Key Findings:"))
        results_layout.addWidget(self.findings_list)
        
        splitter.addWidget(results_widget)
        splitter.setSizes([300, 500])
        
    def populate_wordlists(self):
        """Populate wordlist dropdown"""
        self.wordlist_combo.addItem("Default cloud keywords", None)
        
        # Look for cloud-specific wordlists
        wordlist_dir = os.path.join(os.path.dirname(__file__), "..", "..", "resources", "wordlists")
        if os.path.exists(wordlist_dir):
            for filename in os.listdir(wordlist_dir):
                if filename.endswith(".txt") and any(keyword in filename.lower() 
                    for keyword in ["cloud", "s3", "azure", "bucket"]):
                    self.wordlist_combo.addItem(filename, os.path.join(wordlist_dir, filename))
        
        # Add generic wordlists
        if os.path.exists(wordlist_dir):
            for filename in ["common.txt", "subdomains-top1000.txt"]:
                filepath = os.path.join(wordlist_dir, filename)
                if os.path.exists(filepath):
                    self.wordlist_combo.addItem(filename, filepath)
    
    def connect_signals(self):
        self.start_btn.clicked.connect(self.start_scan)
        self.stop_btn.clicked.connect(self.stop_scan)
        self.export_btn.clicked.connect(self.export_results)
        self.target_input.returnPressed.connect(self.start_scan)
        
    def start_scan(self):
        target = self.target_input.text().strip()
        if not target:
            self.append_output("<p style='color: #FF6B6B;'>Please enter a target</p>")
            return
            
        if self.is_scanning:
            return
            
        self.is_scanning = True
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.export_btn.setEnabled(False)
        
        # Clear previous results
        self.results_output.clear()
        self.findings_list.clear()
        
        # Get scan configuration
        scan_type_map = {
            "S3 Bucket Enumeration": "s3_buckets",
            "Azure Blob Storage": "azure_blobs", 
            "Cloud Metadata APIs": "metadata_apis",
            "Full Cloud Scan": "full_scan"
        }
        scan_type = scan_type_map[self.scan_type_combo.currentText()]
        
        # Get wordlist
        wordlist = self.get_wordlist()
        
        # Add custom keywords
        custom_keywords = [kw.strip() for kw in self.custom_keywords.toPlainText().split('\n') if kw.strip()]
        wordlist.extend(custom_keywords)
        
        self.append_output(f"<p style='color: #00BFFF;'>Starting {self.scan_type_combo.currentText()} for: {target}</p>")
        self.append_output(f"<p style='color: #DCDCDC;'>Using {len(wordlist)} keywords</p><br>")
        
        # Get stealth configuration from global settings
        try:
            from app.core.stealth_config import stealth_config
            proxy = stealth_config.get_proxy() if stealth_config.is_enabled() else None
            delay = stealth_config.get_delay() if stealth_config.is_enabled() else 0.5
            max_workers = stealth_config.get_max_workers() if stealth_config.is_enabled() else 10
        except ImportError:
            proxy = None
            delay = 0.5
            max_workers = 10
            
        # Create and start worker with global stealth settings
        self.current_worker = CloudEnumerationWorker(
            target, scan_type, wordlist, 
            proxy=proxy, delay=delay, max_workers=max_workers
        )
        self.current_worker.signals.output.connect(self.append_output)
        self.current_worker.signals.results_ready.connect(self.handle_results)
        self.current_worker.signals.finished.connect(self.scan_finished)
        self.current_worker.signals.error.connect(self.handle_error)
        
        QThreadPool.globalInstance().start(self.current_worker)
        
    def stop_scan(self):
        if self.current_worker:
            self.current_worker.is_running = False
        self.scan_finished()
        
    def scan_finished(self):
        self.is_scanning = False
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.export_btn.setEnabled(True)
        self.append_output("<p style='color: #00FF41;'>Scan completed</p>")
        
    def get_wordlist(self) -> list:
        """Get wordlist for enumeration"""
        wordlist_path = self.wordlist_combo.currentData()
        
        if wordlist_path and os.path.exists(wordlist_path):
            try:
                with open(wordlist_path, 'r') as f:
                    return [line.strip() for line in f if line.strip()]
            except Exception as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        
        # Default cloud keywords
        return [
            "backup", "backups", "data", "logs", "assets", "files", "uploads",
            "static", "dev", "prod", "staging", "test", "admin", "api",
            "storage", "archive", "temp", "tmp", "public", "private",
            "documents", "images", "media", "downloads", "exports"
        ]
    
    def append_output(self, text: str):
        """Append text to results output"""
        self.results_output.insertHtml(text + "<br>")
        self.results_output.verticalScrollBar().setValue(
            self.results_output.verticalScrollBar().maximum()
        )
        
    def handle_results(self, results: dict):
        """Handle scan results"""
        self.scan_results = results
        self.update_findings_summary(results)
        self.scan_completed.emit(results)
        
    def update_findings_summary(self, results: dict):
        """Update findings summary list"""
        self.findings_list.clear()
        
        if isinstance(results, dict):
            # Handle different result types
            if 's3' in results:
                s3_results = results['s3']
                if s3_results.get('buckets'):
                    self.findings_list.addItem(f"🪣 {len(s3_results['buckets'])} S3 buckets found")
                if s3_results.get('accessible'):
                    self.findings_list.addItem(f"⚠️ {len(s3_results['accessible'])} publicly accessible S3 buckets")
                    
            if 'azure' in results:
                azure_results = results['azure']
                if azure_results.get('containers'):
                    self.findings_list.addItem(f"📦 {len(azure_results['containers'])} Azure storage accounts found")
                if azure_results.get('accessible'):
                    self.findings_list.addItem(f"⚠️ {len(azure_results['accessible'])} accessible Azure containers")
                    
            if 'metadata' in results:
                metadata_results = results['metadata']
                if metadata_results.get('aws', {}).get('available'):
                    self.findings_list.addItem("☁️ AWS metadata API accessible")
                if metadata_results.get('azure', {}).get('available'):
                    self.findings_list.addItem("☁️ Azure metadata API accessible")
                if metadata_results.get('gcp', {}).get('available'):
                    self.findings_list.addItem("☁️ GCP metadata API accessible")
            
            # Handle single scan type results
            if 'buckets' in results:
                if results['buckets']:
                    self.findings_list.addItem(f"🪣 {len(results['buckets'])} S3 buckets found")
                if results.get('accessible'):
                    self.findings_list.addItem(f"⚠️ {len(results['accessible'])} publicly accessible buckets")
                    
            if 'containers' in results:
                if results['containers']:
                    self.findings_list.addItem(f"📦 {len(results['containers'])} Azure storage accounts found")
                if results.get('accessible'):
                    self.findings_list.addItem(f"⚠️ {len(results['accessible'])} accessible containers")
        
        if self.findings_list.count() == 0:
            self.findings_list.addItem("No cloud assets discovered")
            
    def handle_error(self, error_msg: str):
        """Handle scan errors"""
        self.append_output(f"<p style='color: #FF6B6B;'>Error: {error_msg}</p>")
        self.scan_finished()
        
    def export_results(self):
        """Export scan results"""
        if not hasattr(self, 'scan_results'):
            self.append_output("<p style='color: #FFAA00;'>No results to export</p>")
            return
            
        from PyQt6.QtWidgets import QFileDialog
        import json
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Cloud Assets Results", 
            f"cloud_assets_{self.target_input.text().strip()}.json",
            "JSON Files (*.json);;All Files (*)"
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump(self.scan_results, f, indent=2)
                self.append_output(f"<p style='color: #00FF41;'>Results exported to: {filename}</p>")
            except Exception as e:
                self.append_output(f"<p style='color: #FF6B6B;'>Export failed: {str(e)}</p>")