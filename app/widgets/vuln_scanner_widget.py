# app/widgets/vuln_scanner_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QPushButton, QLineEdit, QTextEdit, QProgressBar, 
                            QGroupBox, QComboBox, QTableWidget, QTableWidgetItem, QTabWidget)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from app.core.vuln_scanner import vuln_scanner
import json

class VulnScanWorker(QThread):
    """Worker thread for vulnerability scanning"""
    
    progress_update = pyqtSignal(str)
    scan_completed = pyqtSignal(dict)
    
    def __init__(self, target, scan_type):
        super().__init__()
        self.target = target
        self.scan_type = scan_type
    
    def run(self):
        """Execute vulnerability scan"""
        try:
            results = vuln_scanner.scan_vulnerabilities(
                self.target,
                self.scan_type,
                progress_callback=self.progress_update.emit
            )
            self.scan_completed.emit(results)
        except Exception as e:
            self.scan_completed.emit({'error': str(e)})

class VulnScannerWidget(QWidget):
    """Widget for vulnerability scanning"""
    
    scan_completed = pyqtSignal(dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Main group
        main_group = QGroupBox("🛡️ Vulnerability Scanner")
        main_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                color: #64C8FF;
                border: 2px solid #555;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)
        
        main_layout = QVBoxLayout(main_group)
        
        # Target and scan type
        config_layout = QHBoxLayout()
        
        config_layout.addWidget(QLabel("Target:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("example.com or 192.168.1.1")
        self.target_input.setStyleSheet("""
            QLineEdit {
                background-color: rgba(20, 30, 40, 180);
                border: 1px solid #555;
                border-radius: 4px;
                color: #DCDCDC;
                padding: 4px 8px;
                font-size: 10pt;
            }
            QLineEdit:focus {
                border: 2px solid #64C8FF;
            }
        """)
        
        config_layout.addWidget(self.target_input)
        
        config_layout.addWidget(QLabel("Type:"))
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(["HTTP", "SSL", "DNS", "Port"])
        self.scan_type_combo.setFixedWidth(100)
        
        config_layout.addWidget(self.scan_type_combo)
        
        # Scan button
        self.scan_button = QPushButton("🛡️ Start Scan")
        self.scan_button.clicked.connect(self.start_scan)
        self.scan_button.setStyleSheet("""
            QPushButton {
                background-color: rgba(255, 100, 100, 150);
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 16px;
                font-size: 11pt;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(255, 100, 100, 200);
            }
            QPushButton:disabled {
                background-color: rgba(60, 60, 60, 100);
                color: #888;
            }
        """)
        
        config_layout.addWidget(self.scan_button)
        
        # Progress section
        progress_layout = QVBoxLayout()
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #555;
                border-radius: 4px;
                text-align: center;
                color: white;
                font-weight: bold;
            }
            QProgressBar::chunk {
                background-color: rgba(255, 100, 100, 150);
                border-radius: 3px;
            }
        """)
        
        self.status_label = QLabel("Select target and scan type to begin vulnerability assessment")
        self.status_label.setStyleSheet("color: #888; font-size: 10pt; padding: 5px;")
        
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.status_label)
        
        # Results tabs
        self.results_tabs = QTabWidget()
        self.results_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #555;
                background-color: rgba(0, 0, 0, 100);
            }
            QTabBar::tab {
                background-color: rgba(50, 50, 50, 150);
                color: #DCDCDC;
                padding: 8px 12px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: rgba(255, 100, 100, 150);
                color: #000;
            }
        """)
        
        # Vulnerabilities tab
        self.vulns_table = QTableWidget()
        self.vulns_table.setColumnCount(5)
        self.vulns_table.setHorizontalHeaderLabels([
            "Type", "Severity", "Description", "Evidence", "URL"
        ])
        self.vulns_table.setStyleSheet("""
            QTableWidget {
                background-color: rgba(0, 0, 0, 150);
                border: 1px solid #555;
                border-radius: 4px;
                color: #DCDCDC;
                gridline-color: #555;
            }
            QHeaderView::section {
                background-color: rgba(255, 100, 100, 150);
                color: white;
                padding: 4px;
                border: none;
                font-weight: bold;
            }
        """)
        self.results_tabs.addTab(self.vulns_table, "🚨 Vulnerabilities")
        
        # Summary tab
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.summary_text.setStyleSheet("""
            QTextEdit {
                background-color: rgba(0, 0, 0, 150);
                border: 1px solid #555;
                border-radius: 4px;
                color: #DCDCDC;
                font-size: 10pt;
                padding: 8px;
                font-family: 'Courier New', monospace;
            }
        """)
        self.results_tabs.addTab(self.summary_text, "📊 Summary")
        
        # Raw data tab
        self.raw_data_text = QTextEdit()
        self.raw_data_text.setReadOnly(True)
        self.raw_data_text.setStyleSheet("""
            QTextEdit {
                background-color: rgba(0, 0, 0, 150);
                border: 1px solid #555;
                border-radius: 4px;
                color: #DCDCDC;
                font-size: 10pt;
                padding: 8px;
                font-family: 'Courier New', monospace;
            }
        """)
        self.results_tabs.addTab(self.raw_data_text, "📄 Raw Data")
        
        # Add to main layout
        main_layout.addLayout(config_layout)
        main_layout.addLayout(progress_layout)
        main_layout.addWidget(self.results_tabs)
        
        layout.addWidget(main_group)
        
    def start_scan(self):
        """Start vulnerability scan"""
        target = self.target_input.text().strip()
        if not target:
            self.status_label.setText("❌ Please enter a target")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
            return
        
        scan_type = self.scan_type_combo.currentText().lower()
        
        # Start worker thread
        self.worker = VulnScanWorker(target, scan_type)
        self.worker.progress_update.connect(self.on_progress_update)
        self.worker.scan_completed.connect(self.on_scan_completed)
        self.worker.start()
        
        # Update UI
        self.scan_button.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.clear_results()
        
        self.status_label.setText(f"🛡️ Scanning {scan_type.upper()} vulnerabilities...")
        self.status_label.setStyleSheet("color: #FF6600; font-size: 10pt; padding: 5px;")
    
    def on_progress_update(self, message):
        """Handle progress updates"""
        self.status_label.setText(message)
    
    def on_scan_completed(self, results):
        """Handle scan completion"""
        self.scan_button.setEnabled(True)
        self.progress_bar.setVisible(False)
        
        if 'error' in results:
            self.status_label.setText(f"❌ Error: {results['error']}")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
            return
        
        # Display results
        vulnerabilities = results.get('vulnerabilities', [])
        summary = results.get('summary', {})
        
        self.display_vulnerabilities(vulnerabilities)
        self.display_summary(summary, results.get('target', ''))
        self.display_raw_data(results)
        
        # Update status
        vuln_count = len(vulnerabilities)
        high_count = summary.get('severity_breakdown', {}).get('high', 0)
        
        if vuln_count == 0:
            self.status_label.setText("✅ No vulnerabilities found")
            self.status_label.setStyleSheet("color: #00AA00; font-size: 10pt; padding: 5px;")
        else:
            self.status_label.setText(f"🚨 Found {vuln_count} vulnerabilities ({high_count} high severity)")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
        
        # Emit completion signal
        self.scan_completed.emit(results)
    
    def display_vulnerabilities(self, vulnerabilities):
        """Display vulnerability findings"""
        self.vulns_table.setRowCount(len(vulnerabilities))
        
        for row, vuln in enumerate(vulnerabilities):
            # Type
            type_item = QTableWidgetItem(vuln.get('type', 'Unknown'))
            self.vulns_table.setItem(row, 0, type_item)
            
            # Severity
            severity = vuln.get('severity', 'low')
            severity_item = QTableWidgetItem(severity.upper())
            
            # Color code by severity
            if severity == 'high':
                severity_item.setForeground(Qt.GlobalColor.red)
            elif severity == 'medium':
                severity_item.setForeground(Qt.GlobalColor.yellow)
            else:
                severity_item.setForeground(Qt.GlobalColor.cyan)
            
            self.vulns_table.setItem(row, 1, severity_item)
            
            # Description
            desc = vuln.get('description', 'No description')
            if len(desc) > 40:
                desc = desc[:37] + "..."
            desc_item = QTableWidgetItem(desc)
            self.vulns_table.setItem(row, 2, desc_item)
            
            # Evidence
            evidence = vuln.get('evidence', 'No evidence')
            if len(evidence) > 30:
                evidence = evidence[:27] + "..."
            evidence_item = QTableWidgetItem(evidence)
            self.vulns_table.setItem(row, 3, evidence_item)
            
            # URL
            url = vuln.get('url', 'N/A')
            if len(url) > 30:
                url = url[:27] + "..."
            url_item = QTableWidgetItem(url)
            self.vulns_table.setItem(row, 4, url_item)
        
        self.vulns_table.resizeColumnsToContents()
    
    def display_summary(self, summary, target):
        """Display scan summary"""
        summary_text = f"Vulnerability Scan Summary\n"
        summary_text += "=" * 30 + "\n\n"
        
        summary_text += f"Target: {target}\n"
        summary_text += f"Scan Type: {self.scan_type_combo.currentText()}\n"
        summary_text += f"Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}\n\n"
        
        # Severity breakdown
        severity = summary.get('severity_breakdown', {})
        summary_text += "Severity Breakdown:\n"
        summary_text += "-" * 20 + "\n"
        summary_text += f"High: {severity.get('high', 0)}\n"
        summary_text += f"Medium: {severity.get('medium', 0)}\n"
        summary_text += f"Low: {severity.get('low', 0)}\n\n"
        
        # Vulnerability types
        vuln_types = summary.get('vulnerability_types', {})
        if vuln_types:
            summary_text += "Vulnerability Types:\n"
            summary_text += "-" * 20 + "\n"
            for vuln_type, count in vuln_types.items():
                summary_text += f"{vuln_type}: {count}\n"
        
        # Risk assessment
        high_count = severity.get('high', 0)
        medium_count = severity.get('medium', 0)
        
        summary_text += "\nRisk Assessment:\n"
        summary_text += "-" * 15 + "\n"
        
        if high_count > 0:
            summary_text += "🔴 HIGH RISK - Immediate attention required\n"
        elif medium_count > 0:
            summary_text += "🟡 MEDIUM RISK - Should be addressed\n"
        else:
            summary_text += "🟢 LOW RISK - Minimal security concerns\n"
        
        self.summary_text.setPlainText(summary_text)
    
    def display_raw_data(self, results):
        """Display raw scan data"""
        raw_text = json.dumps(results, indent=2, default=str)
        self.raw_data_text.setPlainText(raw_text)
    
    def clear_results(self):
        """Clear all result displays"""
        self.vulns_table.setRowCount(0)
        self.summary_text.clear()
        self.raw_data_text.clear()