# app/widgets/enhanced_reporting_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QComboBox, QPushButton, QTextEdit, QGroupBox,
                            QTableWidget, QTableWidgetItem, QHeaderView,
                            QTabWidget, QProgressBar, QFileDialog)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QFont
from app.core.enhanced_reporting import enhanced_reporting
from app.core.license_manager import license_manager
import json

class ReportGenerationWorker(QThread):
    """Worker thread for report generation"""
    report_completed = pyqtSignal(dict)
    
    def __init__(self, report_type, scan_data, framework=None):
        super().__init__()
        self.report_type = report_type
        self.scan_data = scan_data
        self.framework = framework
        
    def run(self):
        if self.report_type == 'executive':
            result = enhanced_reporting.generate_executive_summary(self.scan_data)
        elif self.report_type == 'technical':
            result = enhanced_reporting.generate_technical_report(self.scan_data)
        elif self.report_type == 'compliance':
            result = enhanced_reporting.generate_compliance_report(self.scan_data, self.framework)
        else:
            result = {'error': 'Unknown report type'}
            
        self.report_completed.emit(result)

class EnhancedReportingWidget(QWidget):
    """Enhanced reporting engine widget"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.report_worker = None
        self.current_report = {}
        self.setup_ui()
        self.connect_signals()
        self.check_license()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Header
        header = QLabel("Enhanced Reporting Engine")
        header.setStyleSheet("font-size: 16pt; font-weight: bold; color: #64C8FF;")
        layout.addWidget(header)
        
        # License warning
        self.license_warning = QLabel("⚠️ Enhanced Reporting requires Enterprise license")
        self.license_warning.setStyleSheet("color: #FF6B6B; font-weight: bold; padding: 10px;")
        layout.addWidget(self.license_warning)
        
        # Report Configuration
        config_group = QGroupBox("Report Configuration")
        config_layout = QVBoxLayout(config_group)
        
        # Report type selection
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Report Type:"))
        self.report_type = QComboBox()
        self.report_type.addItems([
            "Executive Summary",
            "Technical Assessment", 
            "Compliance Report"
        ])
        type_layout.addWidget(self.report_type)
        config_layout.addLayout(type_layout)
        
        # Compliance framework (for compliance reports)
        framework_layout = QHBoxLayout()
        framework_layout.addWidget(QLabel("Framework:"))
        self.compliance_framework = QComboBox()
        self.compliance_framework.addItems(["NIST", "ISO27001", "PCI-DSS"])
        self.compliance_framework.setEnabled(False)
        framework_layout.addWidget(self.compliance_framework)
        config_layout.addLayout(framework_layout)
        
        # Data source
        data_layout = QHBoxLayout()
        data_layout.addWidget(QLabel("Data Source:"))
        self.data_source_btn = QPushButton("Load Scan Results")
        self.data_source_label = QLabel("No data loaded")
        data_layout.addWidget(self.data_source_btn)
        data_layout.addWidget(self.data_source_label)
        config_layout.addLayout(data_layout)
        
        layout.addWidget(config_group)
        
        # Generation Controls
        control_layout = QHBoxLayout()
        self.generate_btn = QPushButton("Generate Report")
        self.generate_btn.setStyleSheet("background-color: #64C8FF; font-weight: bold;")
        self.export_btn = QPushButton("Export Report")
        self.export_btn.setEnabled(False)
        
        control_layout.addWidget(self.generate_btn)
        control_layout.addWidget(self.export_btn)
        layout.addLayout(control_layout)
        
        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Report Tabs
        self.report_tabs = QTabWidget()
        
        # Executive Summary Tab
        self.executive_tab = self.create_executive_tab()
        self.report_tabs.addTab(self.executive_tab, "Executive Summary")
        
        # Technical Details Tab
        self.technical_tab = self.create_technical_tab()
        self.report_tabs.addTab(self.technical_tab, "Technical Details")
        
        # Compliance Tab
        self.compliance_tab = self.create_compliance_tab()
        self.report_tabs.addTab(self.compliance_tab, "Compliance")
        
        layout.addWidget(self.report_tabs)
        
    def create_executive_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Risk Score Display
        risk_group = QGroupBox("Risk Assessment")
        risk_layout = QVBoxLayout(risk_group)
        
        self.risk_score_label = QLabel("Overall Risk Score: N/A")
        self.risk_score_label.setStyleSheet("font-size: 14pt; font-weight: bold;")
        risk_layout.addWidget(self.risk_score_label)
        
        # Risk breakdown table
        self.risk_breakdown_table = QTableWidget()
        self.risk_breakdown_table.setColumnCount(2)
        self.risk_breakdown_table.setHorizontalHeaderLabels(["Severity", "Count"])
        self.risk_breakdown_table.setMaximumHeight(150)
        risk_layout.addWidget(self.risk_breakdown_table)
        
        layout.addWidget(risk_group)
        
        # Key Findings
        findings_group = QGroupBox("Key Findings")
        findings_layout = QVBoxLayout(findings_group)
        
        self.findings_table = QTableWidget()
        self.findings_table.setColumnCount(3)
        self.findings_table.setHorizontalHeaderLabels(["Finding", "Severity", "Business Impact"])
        self.findings_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        findings_layout.addWidget(self.findings_table)
        
        layout.addWidget(findings_group)
        
        return widget
        
    def create_technical_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Vulnerability Categories
        vuln_group = QGroupBox("Vulnerability Analysis")
        vuln_layout = QVBoxLayout(vuln_group)
        
        self.vuln_categories_table = QTableWidget()
        self.vuln_categories_table.setColumnCount(2)
        self.vuln_categories_table.setHorizontalHeaderLabels(["Category", "Count"])
        vuln_layout.addWidget(self.vuln_categories_table)
        
        layout.addWidget(vuln_group)
        
        # Remediation Timeline
        timeline_group = QGroupBox("Remediation Timeline")
        timeline_layout = QVBoxLayout(timeline_group)
        
        self.timeline_text = QTextEdit()
        self.timeline_text.setMaximumHeight(200)
        self.timeline_text.setReadOnly(True)
        timeline_layout.addWidget(self.timeline_text)
        
        layout.addWidget(timeline_group)
        
        return widget
        
    def create_compliance_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Compliance Status
        status_group = QGroupBox("Compliance Status")
        status_layout = QVBoxLayout(status_group)
        
        self.compliance_table = QTableWidget()
        self.compliance_table.setColumnCount(3)
        self.compliance_table.setHorizontalHeaderLabels(["Framework", "Score", "Status"])
        status_layout.addWidget(self.compliance_table)
        
        layout.addWidget(status_group)
        
        # Recommendations
        rec_group = QGroupBox("Recommendations")
        rec_layout = QVBoxLayout(rec_group)
        
        self.recommendations_table = QTableWidget()
        self.recommendations_table.setColumnCount(4)
        self.recommendations_table.setHorizontalHeaderLabels(["Priority", "Recommendation", "Effort", "Timeline"])
        self.recommendations_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        rec_layout.addWidget(self.recommendations_table)
        
        layout.addWidget(rec_group)
        
        return widget
        
    def connect_signals(self):
        self.report_type.currentTextChanged.connect(self.on_report_type_changed)
        self.data_source_btn.clicked.connect(self.load_scan_data)
        self.generate_btn.clicked.connect(self.generate_report)
        self.export_btn.clicked.connect(self.export_report)
        enhanced_reporting.report_event.connect(self.handle_report_event)
        
    def check_license(self):
        if license_manager.is_feature_enabled('enhanced_reporting'):
            self.license_warning.hide()
            self.setEnabled(True)
        else:
            self.license_warning.show()
            self.setEnabled(False)
            
    def on_report_type_changed(self, report_type):
        self.compliance_framework.setEnabled(report_type == "Compliance Report")
        
    def load_scan_data(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Load Scan Results", "", "JSON Files (*.json);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    self.scan_data = json.load(f)
                self.data_source_label.setText(f"Loaded: {file_path.split('/')[-1]}")
                self.generate_btn.setEnabled(True)
            except Exception as e:
                self.data_source_label.setText(f"Error loading file: {str(e)}")
        else:
            # Use demo data if no file selected
            self.scan_data = self.get_demo_data()
            self.data_source_label.setText("Using demo data")
            self.generate_btn.setEnabled(True)
            
    def get_demo_data(self):
        """Generate demo scan data"""
        return {
            'organization': 'Demo Corporation',
            'period': '1 week',
            'targets': ['192.168.1.0/24', 'demo.company.com'],
            'vulnerabilities': [
                {
                    'type': 'SQL Injection',
                    'severity': 'Critical',
                    'url': 'https://demo.company.com/login',
                    'payload': "' OR 1=1--",
                    'evidence': 'Database error revealed'
                },
                {
                    'type': 'Cross-Site Scripting',
                    'severity': 'High',
                    'url': 'https://demo.company.com/search',
                    'payload': '<script>alert("XSS")</script>',
                    'evidence': 'Script executed in browser'
                },
                {
                    'type': 'Directory Traversal',
                    'severity': 'Medium',
                    'url': 'https://demo.company.com/files',
                    'payload': '../../../etc/passwd',
                    'evidence': 'System file accessed'
                }
            ]
        }
        
    def generate_report(self):
        if not license_manager.is_feature_enabled('enhanced_reporting'):
            return
            
        if not hasattr(self, 'scan_data'):
            self.load_scan_data()
            
        report_type_map = {
            "Executive Summary": "executive",
            "Technical Assessment": "technical",
            "Compliance Report": "compliance"
        }
        
        report_type = report_type_map[self.report_type.currentText()]
        framework = self.compliance_framework.currentText() if report_type == "compliance" else None
        
        # Start report generation
        self.generate_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate
        
        self.report_worker = ReportGenerationWorker(report_type, self.scan_data, framework)
        self.report_worker.report_completed.connect(self.handle_report_completed)
        self.report_worker.start()
        
    def handle_report_completed(self, report):
        self.generate_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        
        if 'error' in report:
            self.data_source_label.setText(f"Error: {report['error']}")
            return
            
        self.current_report = report
        self.export_btn.setEnabled(True)
        
        # Update UI based on report type
        if report.get('report_type') == 'Executive Summary':
            self.update_executive_summary(report)
        elif report.get('report_type') == 'Technical Assessment':
            self.update_technical_report(report)
        elif 'Compliance' in report.get('report_type', ''):
            self.update_compliance_report(report)
            
    def update_executive_summary(self, report):
        # Update risk score
        risk_score = report.get('overall_risk_score', 0)
        self.risk_score_label.setText(f"Overall Risk Score: {risk_score}/10")
        
        # Color code risk score
        if risk_score >= 7:
            color = "#FF0000"  # Red
        elif risk_score >= 4:
            color = "#FFA500"  # Orange
        else:
            color = "#00FF41"  # Green
            
        self.risk_score_label.setStyleSheet(f"font-size: 14pt; font-weight: bold; color: {color};")
        
        # Update risk breakdown
        risk_breakdown = report.get('risk_breakdown', {}).get('severity_distribution', {})
        self.risk_breakdown_table.setRowCount(len(risk_breakdown))
        
        for row, (severity, count) in enumerate(risk_breakdown.items()):
            self.risk_breakdown_table.setItem(row, 0, QTableWidgetItem(severity))
            count_item = QTableWidgetItem(str(count))
            
            # Color code severity
            if severity == 'Critical':
                count_item.setForeground(QColor("#FF0000"))
            elif severity == 'High':
                count_item.setForeground(QColor("#FF6B6B"))
            elif severity == 'Medium':
                count_item.setForeground(QColor("#FFA500"))
                
            self.risk_breakdown_table.setItem(row, 1, count_item)
            
        # Update key findings
        findings = report.get('key_findings', [])
        self.findings_table.setRowCount(len(findings))
        
        for row, finding in enumerate(findings):
            self.findings_table.setItem(row, 0, QTableWidgetItem(finding.get('title', '')))
            
            severity_item = QTableWidgetItem(finding.get('severity', ''))
            if finding.get('severity') == 'Critical':
                severity_item.setForeground(QColor("#FF0000"))
            elif finding.get('severity') == 'High':
                severity_item.setForeground(QColor("#FF6B6B"))
                
            self.findings_table.setItem(row, 1, severity_item)
            self.findings_table.setItem(row, 2, QTableWidgetItem(finding.get('business_risk', '')))
            
    def update_technical_report(self, report):
        # Update vulnerability categories
        categories = report.get('vulnerabilities', {})
        self.vuln_categories_table.setRowCount(len(categories))
        
        for row, (category, vulns) in enumerate(categories.items()):
            self.vuln_categories_table.setItem(row, 0, QTableWidgetItem(category))
            self.vuln_categories_table.setItem(row, 1, QTableWidgetItem(str(len(vulns))))
            
        # Update timeline
        timeline = report.get('timeline', {})
        timeline_text = ""
        for phase, activities in timeline.items():
            timeline_text += f"{phase.upper()}:\n"
            for activity in activities:
                timeline_text += f"  • {activity}\n"
            timeline_text += "\n"
            
        self.timeline_text.setPlainText(timeline_text)
        
    def update_compliance_report(self, report):
        # Update compliance status (single framework)
        framework = report.get('framework', 'Unknown')
        score = report.get('compliance_score', 0)
        
        self.compliance_table.setRowCount(1)
        self.compliance_table.setItem(0, 0, QTableWidgetItem(framework))
        self.compliance_table.setItem(0, 1, QTableWidgetItem(f"{score}%"))
        
        status = 'Compliant' if score >= 80 else 'Non-Compliant' if score < 60 else 'Partially Compliant'
        status_item = QTableWidgetItem(status)
        
        if status == 'Compliant':
            status_item.setForeground(QColor("#00FF41"))
        elif status == 'Non-Compliant':
            status_item.setForeground(QColor("#FF0000"))
        else:
            status_item.setForeground(QColor("#FFA500"))
            
        self.compliance_table.setItem(0, 2, status_item)
        
        # Update recommendations (use demo recommendations)
        recommendations = [
            {'priority': 'Critical', 'title': 'Patch Management', 'effort': 'Medium', 'timeline': '2 weeks'},
            {'priority': 'High', 'title': 'Access Controls', 'effort': 'High', 'timeline': '1 month'},
            {'priority': 'Medium', 'title': 'Security Training', 'effort': 'Low', 'timeline': '6 weeks'}
        ]
        
        self.recommendations_table.setRowCount(len(recommendations))
        
        for row, rec in enumerate(recommendations):
            priority_item = QTableWidgetItem(rec['priority'])
            if rec['priority'] == 'Critical':
                priority_item.setForeground(QColor("#FF0000"))
            elif rec['priority'] == 'High':
                priority_item.setForeground(QColor("#FF6B6B"))
                
            self.recommendations_table.setItem(row, 0, priority_item)
            self.recommendations_table.setItem(row, 1, QTableWidgetItem(rec['title']))
            self.recommendations_table.setItem(row, 2, QTableWidgetItem(rec['effort']))
            self.recommendations_table.setItem(row, 3, QTableWidgetItem(rec['timeline']))
            
    def export_report(self):
        if not self.current_report:
            return
            
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Report", f"report_{self.current_report.get('report_type', 'unknown')}.json",
            "JSON Files (*.json);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    json.dump(self.current_report, f, indent=2)
                self.data_source_label.setText(f"Report exported: {file_path.split('/')[-1]}")
            except Exception as e:
                self.data_source_label.setText(f"Export error: {str(e)}")
                
    def handle_report_event(self, event_type, message, data):
        if event_type == 'report_generated':
            self.data_source_label.setText(f"✅ {message}")