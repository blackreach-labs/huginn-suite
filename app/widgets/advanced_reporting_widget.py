# app/widgets/advanced_reporting_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QFrame, QComboBox, QTextEdit)
from PyQt6.QtCore import pyqtSignal

class AdvancedReportingWidget(QWidget):
    """Advanced reporting with compliance features"""
    
    status_updated = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Header
        header = QLabel("📈 Advanced Reporting & Compliance")
        layout.addWidget(header)
        
        # Export section
        export_frame = QFrame()
        export_layout = QVBoxLayout(export_frame)
        
        # Export buttons
        button_layout = QHBoxLayout()
        
        export_json_btn = QPushButton("📊 Export JSON")
        export_json_btn.clicked.connect(lambda: self.export_findings("json"))
        button_layout.addWidget(export_json_btn)
        
        export_html_btn = QPushButton("🌐 Export HTML")
        export_html_btn.clicked.connect(lambda: self.export_findings("html"))
        button_layout.addWidget(export_html_btn)
        
        export_pdf_btn = QPushButton("📄 Export PDF")
        export_pdf_btn.clicked.connect(lambda: self.export_findings("pdf"))
        button_layout.addWidget(export_pdf_btn)
        
        # Compliance reporting
        compliance_btn = QPushButton("📈 Compliance Report")
        compliance_btn.clicked.connect(self.generate_compliance_report)
        button_layout.addWidget(compliance_btn)
        
        export_layout.addLayout(button_layout)
        
        # Compliance framework selection
        compliance_layout = QHBoxLayout()
        compliance_layout.addWidget(QLabel("Compliance Framework:"))
        
        self.compliance_combo = QComboBox()
        self.compliance_combo.addItems(["PCI DSS", "SOX", "HIPAA", "ISO 27001", "NIST", "GDPR"])
        compliance_layout.addWidget(self.compliance_combo)
        
        export_layout.addLayout(compliance_layout)
        layout.addWidget(export_frame)
        
        # Report preview
        preview_label = QLabel("📋 Report Preview")
        layout.addWidget(preview_label)
        
        self.report_preview = QTextEdit()
        self.report_preview.setReadOnly(True)
        self.report_preview.setPlainText("Report preview will appear here after generating compliance report...")
        layout.addWidget(self.report_preview)
        
    
    def export_findings(self, format_type):
        """Export findings in specified format"""
        self.status_updated.emit(f"Exporting findings as {format_type.upper()}")
        
    def generate_compliance_report(self):
        """Generate automated compliance report"""
        framework = self.compliance_combo.currentText()
        
        from app.core.compliance_reporter import ComplianceReporter
        
        reporter = ComplianceReporter()
        report = reporter.generate_report(framework)
        
        self.report_preview.setPlainText(report)
        self.status_updated.emit(f"📈 {framework} compliance report generated")