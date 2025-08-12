# app/widgets/osint_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QPushButton, QLineEdit, QTextEdit, QProgressBar, 
                            QGroupBox, QCheckBox, QTabWidget, QTableWidget, QTableWidgetItem)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from app.core.osint_collector import osint_collector
import json

class OSINTWorker(QThread):
    """Worker thread for OSINT data collection"""
    
    progress_update = pyqtSignal(str)
    collection_completed = pyqtSignal(dict)
    
    def __init__(self, target, sources):
        super().__init__()
        self.target = target
        self.sources = sources
    
    def run(self):
        """Execute OSINT data collection"""
        try:
            results = osint_collector.gather_intelligence(
                self.target,
                self.sources,
                progress_callback=self.progress_update.emit
            )
            self.collection_completed.emit(results)
        except Exception as e:
            self.collection_completed.emit({'error': str(e)})

class OSINTWidget(QWidget):
    """Widget for OSINT data gathering"""
    
    collection_completed = pyqtSignal(dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Main group
        main_group = QGroupBox("🕵️ OSINT Data Gathering")
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
        
        # Target input
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target:"))
        
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
        
        target_layout.addWidget(self.target_input)
        
        # Source selection
        sources_layout = QVBoxLayout()
        sources_layout.addWidget(QLabel("OSINT Sources:"))
        
        sources_row1 = QHBoxLayout()
        self.shodan_cb = QCheckBox("Shodan")
        self.shodan_cb.setChecked(True)
        self.shodan_cb.setStyleSheet("color: #DCDCDC;")
        
        self.virustotal_cb = QCheckBox("VirusTotal")
        self.virustotal_cb.setChecked(True)
        self.virustotal_cb.setStyleSheet("color: #DCDCDC;")
        
        self.urlvoid_cb = QCheckBox("URLVoid")
        self.urlvoid_cb.setChecked(True)
        self.urlvoid_cb.setStyleSheet("color: #DCDCDC;")
        
        sources_row1.addWidget(self.shodan_cb)
        sources_row1.addWidget(self.virustotal_cb)
        sources_row1.addWidget(self.urlvoid_cb)
        sources_row1.addStretch()
        
        sources_row2 = QHBoxLayout()
        self.whois_cb = QCheckBox("WHOIS")
        self.whois_cb.setChecked(True)
        self.whois_cb.setStyleSheet("color: #DCDCDC;")
        
        self.dns_dumpster_cb = QCheckBox("DNS Dumpster")
        self.dns_dumpster_cb.setChecked(True)
        self.dns_dumpster_cb.setStyleSheet("color: #DCDCDC;")
        
        sources_row2.addWidget(self.whois_cb)
        sources_row2.addWidget(self.dns_dumpster_cb)
        sources_row2.addStretch()
        
        sources_layout.addLayout(sources_row1)
        sources_layout.addLayout(sources_row2)
        
        # Control buttons
        control_layout = QHBoxLayout()
        
        self.gather_button = QPushButton("🕵️ Gather Intelligence")
        self.gather_button.clicked.connect(self.start_collection)
        self.gather_button.setStyleSheet("""
            QPushButton {
                background-color: rgba(100, 255, 100, 150);
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 16px;
                font-size: 11pt;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(100, 255, 100, 200);
            }
            QPushButton:disabled {
                background-color: rgba(60, 60, 60, 100);
                color: #888;
            }
        """)
        
        control_layout.addWidget(self.gather_button)
        control_layout.addStretch()
        
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
                background-color: rgba(100, 200, 255, 150);
                border-radius: 3px;
            }
        """)
        
        self.status_label = QLabel("Select target and sources to gather intelligence")
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
                background-color: rgba(100, 200, 255, 150);
                color: #000;
            }
        """)
        
        # Summary tab
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.summary_text.setStyleSheet(self._get_text_style())
        self.results_tabs.addTab(self.summary_text, "📊 Summary")
        
        # Findings tab
        self.findings_table = QTableWidget()
        self.findings_table.setColumnCount(4)
        self.findings_table.setHorizontalHeaderLabels([
            "Type", "Source", "Data", "Severity"
        ])
        self.findings_table.setStyleSheet("""
            QTableWidget {
                background-color: rgba(0, 0, 0, 150);
                border: 1px solid #555;
                border-radius: 4px;
                color: #DCDCDC;
                gridline-color: #555;
            }
            QHeaderView::section {
                background-color: rgba(100, 200, 255, 150);
                color: white;
                padding: 4px;
                border: none;
                font-weight: bold;
            }
        """)
        self.results_tabs.addTab(self.findings_table, "🔍 Findings")
        
        # Raw data tab
        self.raw_data_text = QTextEdit()
        self.raw_data_text.setReadOnly(True)
        self.raw_data_text.setStyleSheet(self._get_text_style())
        self.results_tabs.addTab(self.raw_data_text, "📄 Raw Data")
        
        # Add to main layout
        main_layout.addLayout(target_layout)
        main_layout.addLayout(sources_layout)
        main_layout.addLayout(control_layout)
        main_layout.addLayout(progress_layout)
        main_layout.addWidget(self.results_tabs)
        
        layout.addWidget(main_group)
        
    def _get_text_style(self):
        return """
            QTextEdit {
                background-color: rgba(0, 0, 0, 150);
                border: 1px solid #555;
                border-radius: 4px;
                color: #DCDCDC;
                font-size: 10pt;
                padding: 8px;
                font-family: 'Courier New', monospace;
            }
        """
    
    def start_collection(self):
        """Start OSINT data collection"""
        target = self.target_input.text().strip()
        if not target:
            self.status_label.setText("❌ Please enter a target")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
            return
        
        # Get selected sources
        sources = []
        if self.shodan_cb.isChecked():
            sources.append('shodan')
        if self.virustotal_cb.isChecked():
            sources.append('virustotal')
        if self.urlvoid_cb.isChecked():
            sources.append('urlvoid')
        if self.whois_cb.isChecked():
            sources.append('whois')
        if self.dns_dumpster_cb.isChecked():
            sources.append('dns_dumpster')
        
        if not sources:
            self.status_label.setText("❌ Please select at least one source")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
            return
        
        # Start worker thread
        self.worker = OSINTWorker(target, sources)
        self.worker.progress_update.connect(self.on_progress_update)
        self.worker.collection_completed.connect(self.on_collection_completed)
        self.worker.start()
        
        # Update UI
        self.gather_button.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.clear_results()
        
        self.status_label.setText("🕵️ Gathering intelligence...")
        self.status_label.setStyleSheet("color: #64C8FF; font-size: 10pt; padding: 5px;")
    
    def on_progress_update(self, message):
        """Handle progress updates"""
        self.status_label.setText(message)
    
    def on_collection_completed(self, results):
        """Handle collection completion"""
        self.gather_button.setEnabled(True)
        self.progress_bar.setVisible(False)
        
        if 'error' in results:
            self.status_label.setText(f"❌ Error: {results['error']}")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
            return
        
        # Display results
        self.display_summary(results.get('summary', {}))
        self.display_findings(results.get('findings', []))
        self.display_raw_data(results)
        
        # Update status
        findings_count = len(results.get('findings', []))
        sources_count = results.get('summary', {}).get('successful_sources', 0)
        
        self.status_label.setText(f"✅ Collected {findings_count} findings from {sources_count} sources")
        self.status_label.setStyleSheet("color: #00AA00; font-size: 10pt; padding: 5px;")
        
        # Emit completion signal
        self.collection_completed.emit(results)
    
    def display_summary(self, summary):
        """Display collection summary"""
        summary_text = f"OSINT Intelligence Summary\n"
        summary_text += "=" * 30 + "\n\n"
        
        summary_text += f"Target: {self.target_input.text()}\n"
        summary_text += f"Sources Queried: {summary.get('sources_queried', 0)}\n"
        summary_text += f"Successful Sources: {summary.get('successful_sources', 0)}\n"
        summary_text += f"Total Findings: {summary.get('total_findings', 0)}\n\n"
        
        # Severity breakdown
        severity = summary.get('severity_breakdown', {})
        summary_text += "Findings by Severity:\n"
        summary_text += "-" * 20 + "\n"
        summary_text += f"High: {severity.get('high', 0)}\n"
        summary_text += f"Medium: {severity.get('medium', 0)}\n"
        summary_text += f"Low: {severity.get('low', 0)}\n"
        summary_text += f"Info: {severity.get('info', 0)}\n"
        
        self.summary_text.setPlainText(summary_text)
    
    def display_findings(self, findings):
        """Display intelligence findings"""
        self.findings_table.setRowCount(len(findings))
        
        for row, finding in enumerate(findings):
            # Type
            type_item = QTableWidgetItem(finding.get('type', 'unknown'))
            self.findings_table.setItem(row, 0, type_item)
            
            # Source
            source_item = QTableWidgetItem(finding.get('source', 'unknown'))
            self.findings_table.setItem(row, 1, source_item)
            
            # Data
            data = str(finding.get('data', ''))
            if len(data) > 50:
                data = data[:47] + "..."
            data_item = QTableWidgetItem(data)
            self.findings_table.setItem(row, 2, data_item)
            
            # Severity
            severity = finding.get('severity', 'info')
            severity_item = QTableWidgetItem(severity.upper())
            
            # Color code by severity
            if severity == 'high':
                severity_item.setForeground(Qt.GlobalColor.red)
            elif severity == 'medium':
                severity_item.setForeground(Qt.GlobalColor.yellow)
            elif severity == 'low':
                severity_item.setForeground(Qt.GlobalColor.cyan)
            else:
                severity_item.setForeground(Qt.GlobalColor.white)
            
            self.findings_table.setItem(row, 3, severity_item)
        
        self.findings_table.resizeColumnsToContents()
    
    def display_raw_data(self, results):
        """Display raw OSINT data"""
        raw_text = json.dumps(results, indent=2, default=str)
        self.raw_data_text.setPlainText(raw_text)
    
    def clear_results(self):
        """Clear all result displays"""
        self.summary_text.clear()
        self.findings_table.setRowCount(0)
        self.raw_data_text.clear()