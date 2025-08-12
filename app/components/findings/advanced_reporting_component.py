# app/components/findings/advanced_reporting_component.py
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTextEdit, QComboBox, QCheckBox, QGroupBox
from PyQt6.QtCore import pyqtSignal

class AdvancedReportingComponent(QWidget):
    report_generated = pyqtSignal(str)
    status_updated = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Report configuration
        config_group = QGroupBox("Report Configuration")
        config_layout = QVBoxLayout(config_group)
        
        # Report type selection
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Report Type:"))
        self.report_type = QComboBox()
        self.report_type.addItems(["Executive Summary", "Technical Report", "Compliance Report", "Custom Report"])
        type_layout.addWidget(self.report_type)
        config_layout.addLayout(type_layout)
        
        # Report sections
        sections_layout = QHBoxLayout()
        sections_layout.addWidget(QLabel("Include Sections:"))
        self.include_findings = QCheckBox("Findings")
        self.include_findings.setChecked(True)
        self.include_recommendations = QCheckBox("Recommendations")
        self.include_recommendations.setChecked(True)
        self.include_appendix = QCheckBox("Technical Appendix")
        sections_layout.addWidget(self.include_findings)
        sections_layout.addWidget(self.include_recommendations)
        sections_layout.addWidget(self.include_appendix)
        config_layout.addLayout(sections_layout)
        
        layout.addWidget(config_group)
        
        # Generate button
        self.generate_btn = QPushButton("Generate Report")
        self.generate_btn.clicked.connect(self.generate_report)
        layout.addWidget(self.generate_btn)
        
        # Report preview
        preview_group = QGroupBox("Report Preview")
        preview_layout = QVBoxLayout(preview_group)
        
        self.preview_text = QTextEdit()
        self.preview_text.setReadOnly(True)
        self.show_default_preview()
        preview_layout.addWidget(self.preview_text)
        
        layout.addWidget(preview_group)

    def show_default_preview(self):
        self.preview_text.setHtml("""
        <div style='color: #64C8FF; font-size: 18pt; font-weight: bold; margin-bottom: 20px;'>Advanced Reporting Engine</div>
        <div style='color: #DCDCDC; font-size: 14pt; line-height: 150%;'>
        Generate comprehensive security assessment reports from your scan data.
        <br><br>
        <b>Available Report Types:</b>
        <ul>
        <li><b>Executive Summary:</b> High-level overview for management</li>
        <li><b>Technical Report:</b> Detailed findings for security teams</li>
        <li><b>Compliance Report:</b> Regulatory compliance assessment</li>
        <li><b>Custom Report:</b> Tailored report with selected sections</li>
        </ul>
        <br>
        Configure your report settings above and click "Generate Report" to create a professional assessment document.
        </div>
        """)

    def generate_report(self):
        report_type = self.report_type.currentText()
        self.status_updated.emit(f"Generating {report_type}...")
        
        # Simulate report generation
        report_content = f"""
        <div style='color: #64C8FF; font-size: 20pt; font-weight: bold; margin-bottom: 20px;'>{report_type}</div>
        <div style='color: #DCDCDC; font-size: 14pt; line-height: 150%;'>
        <b>Generated:</b> {self.get_current_timestamp()}
        <br><br>
        <b>Report Summary:</b>
        <ul>
        <li>Total Findings: 12</li>
        <li>Critical Issues: 3</li>
        <li>High Risk: 4</li>
        <li>Medium Risk: 5</li>
        </ul>
        <br>
        <b>Key Recommendations:</b>
        <ol>
        <li>Implement multi-factor authentication</li>
        <li>Update vulnerable software components</li>
        <li>Strengthen password policies</li>
        <li>Configure proper access controls</li>
        </ol>
        <br>
        <i>This is a preview. Full report would include detailed findings, evidence, and remediation steps.</i>
        </div>
        """
        
        self.preview_text.setHtml(report_content)
        self.report_generated.emit(report_type)
        self.status_updated.emit(f"{report_type} generated successfully")

    def get_current_timestamp(self):
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")