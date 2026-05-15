from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QLineEdit, QComboBox, QTextEdit,
                             QProgressBar, QTabWidget, QWidget, QFrame,
                             QCheckBox, QSpinBox, QGroupBox, QGridLayout,
                             QFileDialog, QMessageBox)
from PyQt6.QtCore import QThread, pyqtSignal, Qt, QTimer
from PyQt6.QtGui import QFont, QPixmap
import asyncio
import json
import os
from datetime import datetime

class HuginnScanWorker(QThread):
    """Worker thread for running Huginn scans"""
    
    progress_updated = pyqtSignal(str)
    scan_completed = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, target_url, profile, config=None):
        super().__init__()
        self.target_url = target_url
        self.profile = profile
        self.config = config or {}
        
    def run(self):
        """Run the scan in a separate thread"""
        try:
            from app.tools.huginn_vuln_scanner import HuginnVulnScanner
            
            self.progress_updated.emit("Initializing Huginn Scanner...")
            scanner = HuginnVulnScanner(self.target_url, profile=self.profile)
            
            if self.config.get('webhook_url'):
                scanner.webhook_notifier.set_webhook_url(self.config['webhook_url'])
            
            if self.config.get('custom_headers'):
                scanner.config_manager.config['custom_headers'] = self.config['custom_headers']
            
            # Apply concurrent limit to prevent hanging
            if self.config.get('max_concurrent'):
                scanner.max_concurrent = min(self.config['max_concurrent'], 50)  # Cap at 50
            
            self.progress_updated.emit(f"Starting {self.profile} scan of {self.target_url}")
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                results = loop.run_until_complete(scanner.scan())
                self.scan_completed.emit(results)
            finally:
                loop.close()
                
        except Exception as e:
            self.error_occurred.emit(str(e))

class HuginnScannerWidget(QWidget):
    """Advanced Huginn Scanner Interface Widget"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scan_worker = None
        self.scan_results = None
        
        self.setup_ui()
        self.apply_styles()
        
    def setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Main title removed - using only the button title to avoid duplication
        
        # Create tabs
        self.tab_widget = QTabWidget()
        
        config_tab = self.create_config_tab()
        self.tab_widget.addTab(config_tab, "⚙️ Configuration")
        self.tab_widget.setTabToolTip(0, "Configure scan target and advanced options")
        
        results_tab = self.create_results_tab()
        self.tab_widget.addTab(results_tab, "📊 Results")
        
        reports_tab = self.create_reports_tab()
        self.tab_widget.addTab(reports_tab, "📄 Reports")
        
        layout.addWidget(self.tab_widget)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        self.scan_button = QPushButton("🚀 Start Scan")
        self.scan_button.setMinimumHeight(50)
        self.scan_button.clicked.connect(self.start_scan)
        
        self.stop_button = QPushButton("⏹️ Stop Scan")
        self.stop_button.setMinimumHeight(50)
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_scan)
        
        self.back_button = QPushButton("⬅️ Back to Enumeration")
        self.back_button.setMinimumHeight(50)
        self.back_button.clicked.connect(self.go_back)
        
        button_layout.addWidget(self.scan_button)
        button_layout.addWidget(self.stop_button)
        button_layout.addStretch()
        button_layout.addWidget(self.back_button)
        
        layout.addLayout(button_layout)
        
    def go_back(self):
        """Navigate back to enumeration page"""
        if hasattr(self.parent(), 'navigate_signal'):
            self.parent().navigate_signal.emit('enumeration')
        elif hasattr(self.parent(), 'parent') and hasattr(self.parent().parent(), 'navigate_signal'):
            self.parent().parent().navigate_signal.emit('enumeration')
        
    def create_config_tab(self):
        """Create scan configuration tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Target Configuration
        target_group = QGroupBox("🎯 Target Configuration")
        target_layout = QGridLayout(target_group)
        
        target_layout.addWidget(QLabel("Target URL:"), 0, 0)
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("https://example.com")
        target_layout.addWidget(self.target_input, 0, 1)
        
        target_layout.addWidget(QLabel("Scan Profile:"), 1, 0)
        self.profile_combo = QComboBox()
        self.profile_combo.addItems(["light", "normal", "aggressive", "insane"])
        self.profile_combo.setCurrentText("light")
        target_layout.addWidget(self.profile_combo, 1, 1)
        
        layout.addWidget(target_group)
        
        # Advanced Configuration
        advanced_group = QGroupBox("🔧 Advanced Configuration")
        advanced_layout = QGridLayout(advanced_group)
        
        # Custom headers
        advanced_layout.addWidget(QLabel("Custom Headers:"), 0, 0)
        self.headers_input = QTextEdit()
        self.headers_input.setMaximumHeight(80)
        self.headers_input.setPlaceholderText('Authorization: Bearer token\nUser-Agent: Custom Scanner')
        advanced_layout.addWidget(self.headers_input, 0, 1)
        
        # Webhook URL
        advanced_layout.addWidget(QLabel("Webhook URL:"), 1, 0)
        self.webhook_input = QLineEdit()
        self.webhook_input.setPlaceholderText("https://hooks.slack.com/services/...")
        advanced_layout.addWidget(self.webhook_input, 1, 1)
        
        # Concurrent requests
        advanced_layout.addWidget(QLabel("Max Concurrent:"), 2, 0)
        self.concurrent_spin = QSpinBox()
        self.concurrent_spin.setRange(1, 200)
        self.concurrent_spin.setValue(20)
        advanced_layout.addWidget(self.concurrent_spin, 2, 1)
        
        layout.addWidget(advanced_group)
        
        # Feature Selection
        features_group = QGroupBox("🧠 AI & Advanced Features")
        features_layout = QGridLayout(features_group)
        
        self.neural_check = QCheckBox("Neural Network Analysis")
        features_layout.addWidget(self.neural_check, 0, 0)
        
        self.quantum_check = QCheckBox("Quantum Fuzzing")
        features_layout.addWidget(self.quantum_check, 0, 1)
        
        self.autonomous_check = QCheckBox("Autonomous Agent")
        features_layout.addWidget(self.autonomous_check, 1, 0)
        
        self.ml_check = QCheckBox("ML Vulnerability Prediction")
        features_layout.addWidget(self.ml_check, 1, 1)
        
        layout.addWidget(features_group)
        
        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("Ready to scan")
        layout.addWidget(self.status_label)
        
        layout.addStretch()
        return tab
        
    def create_results_tab(self):
        """Create results display tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        self.summary_label = QLabel("No scan results available")
        layout.addWidget(self.summary_label)
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(self.results_text)
        
        return tab
        
    def create_reports_tab(self):
        """Create reports generation tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        report_group = QGroupBox("📄 Report Generation")
        report_layout = QGridLayout(report_group)
        
        report_layout.addWidget(QLabel("Format:"), 0, 0)
        self.format_combo = QComboBox()
        self.format_combo.addItems(["html", "json", "executive", "owasp", "pci"])
        report_layout.addWidget(self.format_combo, 0, 1)
        
        self.generate_btn = QPushButton("📊 Generate Report")
        self.generate_btn.clicked.connect(self.generate_report)
        self.generate_btn.setEnabled(False)
        report_layout.addWidget(self.generate_btn, 1, 0)
        
        self.save_btn = QPushButton("💾 Save Report")
        self.save_btn.clicked.connect(self.save_report)
        self.save_btn.setEnabled(False)
        report_layout.addWidget(self.save_btn, 1, 1)
        
        layout.addWidget(report_group)
        
        self.report_preview = QTextEdit()
        self.report_preview.setReadOnly(True)
        layout.addWidget(self.report_preview)
        
        return tab
        
    def apply_styles(self):
        """Apply custom styles to the widget"""
        self.setStyleSheet("""
            QWidget {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, 
                    stop:0 rgba(10, 15, 25, 255), 
                    stop:1 rgba(25, 35, 50, 255));
                color: #DCDCDC;
            }
            QPushButton {
                background-color: rgba(20, 30, 40, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 8px;
                color: #DCDCDC;
                font-size: 12pt;
                font-weight: bold;
                padding: 10px;
            }
            QPushButton:hover {
                background-color: rgba(40, 60, 80, 200);
                border: 2px solid #64C8FF;
                color: #FFFFFF;
            }
        """)
        
    def start_scan(self):
        """Start the vulnerability scan"""
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Warning", "Please enter a target URL")
            return
            
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
            self.target_input.setText(target)
        
        # Prepare configuration
        config = {
            'webhook_url': self.webhook_input.text().strip() or None,
            'custom_headers': {},
            'max_concurrent': self.concurrent_spin.value()
        }
        
        # Parse custom headers
        headers_text = self.headers_input.toPlainText().strip()
        if headers_text:
            for line in headers_text.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    config['custom_headers'][key.strip()] = value.strip()
        
        profile = self.profile_combo.currentText()
        self.scan_worker = HuginnScanWorker(target, profile, config)
        self.scan_worker.progress_updated.connect(self.update_progress)
        self.scan_worker.scan_completed.connect(self.scan_finished)
        self.scan_worker.error_occurred.connect(self.scan_error)
        
        self.scan_worker.start()
        
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        
    def stop_scan(self):
        """Stop the current scan"""
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.terminate()
            self.scan_worker.wait()
        
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.status_label.setText("Scan stopped")
        
    def update_progress(self, message):
        """Update scan progress"""
        self.status_label.setText(message)
        
    def scan_finished(self, results):
        """Handle scan completion"""
        self.scan_results = results
        
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setVisible(False)
        
        vuln_count = len(results.get('vulnerabilities', []))
        self.summary_label.setText(f"Scan completed: {vuln_count} vulnerabilities found")
        self.status_label.setText("Scan completed successfully")
        
        self.display_results(results)
        self.generate_btn.setEnabled(True)
        self.tab_widget.setCurrentIndex(1)
        
    def scan_error(self, error_message):
        """Handle scan error"""
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.status_label.setText(f"Scan failed: {error_message}")
        
        QMessageBox.critical(self, "Scan Error", f"Scan failed:\n{error_message}")
        
    def display_results(self, results):
        """Display scan results in the results tab"""
        output = []
        
        output.append(f"Target: {results.get('target', 'Unknown')}")
        output.append(f"Total Vulnerabilities: {len(results.get('vulnerabilities', []))}")
        output.append("\n" + "="*50 + "\n")
        
        for i, vuln in enumerate(results.get('vulnerabilities', []), 1):
            output.append(f"{i}. {vuln.get('type', 'Unknown')} [{vuln.get('severity', 'Unknown')}]")
            output.append(f"   Description: {vuln.get('description', 'No description')}")
            output.append("")
        
        self.results_text.setPlainText("\n".join(output))
        
    def generate_report(self):
        """Generate report in selected format"""
        if not self.scan_results:
            QMessageBox.warning(self, "Warning", "No scan results available")
            return
        
        try:
            from app.tools.huginn_vuln_scanner import HuginnVulnScanner
            
            scanner = HuginnVulnScanner(self.scan_results['target'])
            scanner.results = self.scan_results
            
            format_type = self.format_combo.currentText()
            report_content = scanner.export_results(format_type)
            
            self.report_preview.setPlainText(report_content)
            self.save_btn.setEnabled(True)
            self.tab_widget.setCurrentIndex(2)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate report:\n{str(e)}")
            
    def save_report(self):
        """Save the generated report to file"""
        if not self.report_preview.toPlainText():
            QMessageBox.warning(self, "Warning", "No report content to save")
            return
        
        format_type = self.format_combo.currentText()
        file_extension = 'html' if format_type == 'html' else 'txt'
        
        filename, _ = QFileDialog.getSaveFileName(
            self, 
            "Save Report", 
            f"huginn_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{file_extension}",
            f"Report Files (*.{file_extension});;All Files (*)"
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.report_preview.toPlainText())
                
                QMessageBox.information(self, "Success", f"Report saved to:\n{filename}")
                
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save report:\n{str(e)}")