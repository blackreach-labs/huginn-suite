# app/components/findings/advanced_reporting_component.py
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QComboBox, QCheckBox, QGroupBox, QFileDialog,
    QSplitter, QFrame, QScrollArea
)
from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtGui import QFont


class AdvancedReportingComponent(QWidget):
    report_generated = pyqtSignal(str)
    status_updated = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.apply_theme()

    # ------------------------------------------------------------------ #
    #  UI construction                                                     #
    # ------------------------------------------------------------------ #

    def setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        # Header
        header = QLabel("📈 Advanced Reporting & Compliance")
        header.setStyleSheet(
            "font-size: 16pt; font-weight: bold; color: #64C8FF; padding: 6px 0;"
        )
        root.addWidget(header)

        # Main splitter: left config panel | right preview
        splitter = QSplitter(Qt.Orientation.Horizontal)

        splitter.addWidget(self._build_config_panel())
        splitter.addWidget(self._build_preview_panel())
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([320, 680])

        root.addWidget(splitter, 1)

    # ---- left panel --------------------------------------------------- #

    def _build_config_panel(self):
        panel = QFrame()
        panel.setFixedWidth(320)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 8, 0)
        layout.setSpacing(10)

        layout.addWidget(self._build_report_config_group())
        layout.addWidget(self._build_export_group())
        layout.addWidget(self._build_compliance_content_group())
        layout.addStretch()

        return panel

    def _build_report_config_group(self):
        group = QGroupBox("Report Configuration")
        layout = QVBoxLayout(group)

        # Report type
        layout.addWidget(QLabel("Report Type:"))
        self.report_type = QComboBox()
        self.report_type.addItems([
            "Executive Summary",
            "Technical Report",
            "Compliance Report",
            "Custom Report",
        ])
        layout.addWidget(self.report_type)

        # Compliance framework
        layout.addWidget(QLabel("Framework:"))
        self.compliance_combo = QComboBox()
        self.compliance_combo.addItems([
            "PCI DSS", "SOX", "HIPAA", "ISO 27001", "NIST", "GDPR"
        ])
        layout.addWidget(self.compliance_combo)

        # Section checkboxes
        layout.addWidget(QLabel("Include Sections:"))
        self.include_findings = QCheckBox("Findings")
        self.include_findings.setChecked(True)
        self.include_recommendations = QCheckBox("Recommendations")
        self.include_recommendations.setChecked(True)
        self.include_appendix = QCheckBox("Technical Appendix")
        layout.addWidget(self.include_findings)
        layout.addWidget(self.include_recommendations)
        layout.addWidget(self.include_appendix)

        # Generate button
        self.generate_btn = QPushButton("⚙️  Generate Report")
        self.generate_btn.setMinimumHeight(36)
        self.generate_btn.clicked.connect(self.generate_report)
        layout.addWidget(self.generate_btn)

        return group

    def _build_export_group(self):
        group = QGroupBox("Export")
        layout = QVBoxLayout(group)

        row = QHBoxLayout()
        for label, fmt in [("📊 JSON", "json"), ("🌐 HTML", "html"), ("📄 PDF", "pdf")]:
            btn = QPushButton(label)
            btn.clicked.connect(lambda checked, f=fmt: self.export_findings(f))
            row.addWidget(btn)
        layout.addLayout(row)

        compliance_btn = QPushButton("📈 Compliance Report")
        compliance_btn.setObjectName("compliance_btn")
        compliance_btn.setMinimumHeight(36)
        compliance_btn.clicked.connect(self.generate_compliance_report)
        layout.addWidget(compliance_btn)

        return group

    def _build_compliance_content_group(self):
        """Compliance & Ethics reference content (from ComplianceComponent)."""
        group = QGroupBox("Compliance & Ethics")
        layout = QVBoxLayout(group)

        buttons = [
            ("⚖️  Legal Guidelines",    self._show_legal_guidelines),
            ("🤝 Ethical Standards",    self._show_ethical_standards),
            ("🔒 Privacy Compliance",   self._show_privacy_compliance),
            ("🛡️  Data Protection",     self._show_data_protection),
            ("✅ Consent Management",   self._show_consent_management),
            ("📋 Audit Trail",          self._show_audit_trail),
            ("⚠️  Risk Assessment",     self._show_risk_assessment),
        ]

        for text, slot in buttons:
            btn = QPushButton(text)
            btn.setMinimumHeight(32)
            btn.clicked.connect(slot)
            layout.addWidget(btn)

        return group

    # ---- right panel -------------------------------------------------- #

    def _build_preview_panel(self):
        panel = QFrame()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(8, 0, 0, 0)

        lbl = QLabel("📋 Report Preview")
        lbl.setStyleSheet(
            "font-size: 13pt; font-weight: bold; color: #87CEEB; padding: 4px 0;"
        )
        layout.addWidget(lbl)

        self.preview_text = QTextEdit()
        self.preview_text.setReadOnly(True)
        self._show_default_preview()
        layout.addWidget(self.preview_text, 1)

        return panel

    # ------------------------------------------------------------------ #
    #  Report generation                                                   #
    # ------------------------------------------------------------------ #

    def _show_default_preview(self):
        self.preview_text.setHtml("""
        <div style='color:#64C8FF;font-size:18pt;font-weight:bold;margin-bottom:16px;'>
            Advanced Reporting Engine
        </div>
        <div style='color:#DCDCDC;font-size:13pt;line-height:160%;'>
            Generate comprehensive security assessment reports from your scan data.
            <br><br>
            <b>Available Report Types:</b>
            <ul>
                <li><b>Executive Summary</b> — High-level overview for management</li>
                <li><b>Technical Report</b> — Detailed findings for security teams</li>
                <li><b>Compliance Report</b> — Regulatory compliance assessment</li>
                <li><b>Custom Report</b> — Tailored report with selected sections</li>
            </ul>
            <br>
            Use the <b>Compliance &amp; Ethics</b> buttons on the left to view reference
            guidelines, or configure your report settings and click
            <b>Generate Report</b> to create a professional assessment document.
        </div>
        """)

    def generate_report(self):
        """Generate a report using the core AdvancedReportGenerator."""
        report_type = self.report_type.currentText()
        self.status_updated.emit(f"Generating {report_type}…")

        try:
            from app.core.advanced_reporting import report_generator

            type_map = {
                "Executive Summary": "executive",
                "Technical Report":  "technical",
                "Compliance Report": "compliance",
                "Custom Report":     "executive",
            }
            key = type_map.get(report_type, "executive")
            content = report_generator.generate_report(key)

            # Render plain-text report as preformatted HTML
            escaped = (
                content
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
            )
            self.preview_text.setHtml(
                f"<pre style='color:#DCDCDC;font-family:Consolas,monospace;"
                f"font-size:11pt;white-space:pre-wrap;'>{escaped}</pre>"
            )

        except Exception as e:
            self.preview_text.setPlainText(f"Error generating report: {e}")

        self.report_generated.emit(report_type)
        self.status_updated.emit(f"{report_type} generated successfully")

    def generate_compliance_report(self):
        """Generate a compliance report for the selected framework."""
        framework = self.compliance_combo.currentText()
        self.status_updated.emit(f"Generating {framework} compliance report…")

        try:
            from app.core.compliance_reporter import ComplianceReporter
            reporter = ComplianceReporter()
            report = reporter.generate_report(framework)
            self.preview_text.setPlainText(report)
        except Exception as e:
            # Fallback: generate via core engine
            try:
                from app.core.advanced_reporting import report_generator
                content = report_generator.generate_report("compliance")
                self.preview_text.setPlainText(
                    f"[{framework} Compliance Report]\n\n{content}"
                )
            except Exception as e2:
                self.preview_text.setPlainText(
                    f"Error generating compliance report: {e2}"
                )

        self.status_updated.emit(f"📈 {framework} compliance report generated")

    def export_findings(self, format_type: str):
        """Export the current report preview to a file."""
        ext_map = {"json": "JSON Files (*.json)", "html": "HTML Files (*.html)", "pdf": "PDF Files (*.pdf)"}
        path, _ = QFileDialog.getSaveFileName(
            self, f"Export as {format_type.upper()}",
            f"report.{format_type}", ext_map.get(format_type, "All Files (*)")
        )
        if not path:
            return

        self.status_updated.emit(f"Exporting findings as {format_type.upper()}…")
        try:
            from app.core.advanced_reporting import report_generator
            report_generator.generate_report("technical", output_path=path)
            self.status_updated.emit(f"✅ Exported to {path}")
        except Exception as e:
            self.status_updated.emit(f"Export failed: {e}")

    # ------------------------------------------------------------------ #
    #  Compliance & Ethics reference content                               #
    # ------------------------------------------------------------------ #

    def _show_compliance_content(self, title: str, html_body: str):
        self.preview_text.setHtml(
            f"<div style='color:#64C8FF;font-size:15pt;font-weight:bold;"
            f"padding:8px 0;'>{title}</div>{html_body}"
        )

    def _show_legal_guidelines(self):
        self._show_compliance_content("⚖️ Legal Guidelines for OSINT Activities", """
        <h3 style='color:#FFD93D;'>Legal Framework</h3>
        <p style='color:#DCDCDC;'>
        • <b>CFAA:</b> Prohibits unauthorized access to computer systems<br>
        • <b>DMCA:</b> Protects copyrighted digital content<br>
        • <b>ECPA:</b> Governs electronic communications interception<br>
        • <b>GDPR:</b> EU data protection and privacy regulation<br>
        • <b>CCPA:</b> California privacy rights legislation
        </p>
        <h3 style='color:#FFD93D;'>Permitted Activities</h3>
        <p style='color:#DCDCDC;'>
        • Public information gathering from openly accessible sources<br>
        • Social media analysis of public profiles and posts<br>
        • DNS and WHOIS lookups for publicly registered domains<br>
        • Certificate transparency log searches<br>
        • Search engine queries and cached content analysis
        </p>
        <h3 style='color:#FFD93D;'>Prohibited Activities</h3>
        <p style='color:#FF6B6B;'>
        • Unauthorized access to private systems or accounts<br>
        • Bypassing authentication mechanisms<br>
        • Social engineering or impersonation<br>
        • Harassment or stalking behaviors<br>
        • Violation of terms of service agreements
        </p>
        <h3 style='color:#FFD93D;'>Best Practices</h3>
        <p style='color:#DCDCDC;'>
        • Always obtain proper authorization before conducting OSINT<br>
        • Document the legal basis for your investigation<br>
        • Respect rate limits and terms of service<br>
        • Maintain detailed logs of all activities<br>
        • Consult legal counsel when in doubt
        </p>
        """)

    def _show_ethical_standards(self):
        self._show_compliance_content("🤝 Ethical Standards for OSINT Practitioners", """
        <h3 style='color:#FFD93D;'>Core Ethical Principles</h3>
        <p style='color:#DCDCDC;'>
        • <b>Respect for Privacy:</b> Honor individual privacy rights and expectations<br>
        • <b>Proportionality:</b> Use methods proportionate to the investigation's importance<br>
        • <b>Transparency:</b> Be open about your methods and intentions when possible<br>
        • <b>Accountability:</b> Take responsibility for your actions and their consequences<br>
        • <b>Non-maleficence:</b> Do no harm to individuals or organizations
        </p>
        <h3 style='color:#FFD93D;'>Professional Standards</h3>
        <p style='color:#DCDCDC;'>
        • Maintain professional competence and stay updated on legal changes<br>
        • Avoid conflicts of interest and disclose when they exist<br>
        • Protect the confidentiality of sensitive information<br>
        • Collaborate ethically with other professionals<br>
        • Report unethical behavior when encountered
        </p>
        <h3 style='color:#FFD93D;'>Data Handling Ethics</h3>
        <p style='color:#DCDCDC;'>
        • Collect only necessary information for legitimate purposes<br>
        • Secure and protect collected data appropriately<br>
        • Delete data when no longer needed<br>
        • Share information only with authorized parties<br>
        • Respect data subject rights and requests
        </p>
        """)

    def _show_privacy_compliance(self):
        self._show_compliance_content("🔒 Privacy Compliance Requirements", """
        <h3 style='color:#FFD93D;'>GDPR Compliance</h3>
        <p style='color:#DCDCDC;'>
        • Lawful basis for processing personal data<br>
        • Data subject rights (access, rectification, erasure)<br>
        • Privacy by design and by default<br>
        • Data protection impact assessments<br>
        • Breach notification requirements
        </p>
        <h3 style='color:#FFD93D;'>CCPA Compliance</h3>
        <p style='color:#DCDCDC;'>
        • Consumer right to know about data collection<br>
        • Right to delete personal information<br>
        • Right to opt-out of data sales<br>
        • Non-discrimination for exercising rights<br>
        • Reasonable security measures
        </p>
        <h3 style='color:#FFD93D;'>International Considerations</h3>
        <p style='color:#DCDCDC;'>
        • Cross-border data transfer restrictions<br>
        • Local data protection laws and regulations<br>
        • Sector-specific privacy requirements<br>
        • Cultural privacy expectations<br>
        • Diplomatic and political sensitivities
        </p>
        """)

    def _show_data_protection(self):
        self._show_compliance_content("🛡️ Data Protection Guidelines", """
        <h3 style='color:#FFD93D;'>Data Classification</h3>
        <p style='color:#DCDCDC;'>
        • <b>Public:</b> Openly available information with no restrictions<br>
        • <b>Internal:</b> Information for internal use within organization<br>
        • <b>Confidential:</b> Sensitive information requiring protection<br>
        • <b>Restricted:</b> Highly sensitive data with strict access controls
        </p>
        <h3 style='color:#FFD93D;'>Security Measures</h3>
        <p style='color:#DCDCDC;'>
        • Encryption of data at rest and in transit<br>
        • Access controls and authentication mechanisms<br>
        • Regular security assessments and audits<br>
        • Incident response and breach procedures<br>
        • Secure data disposal and destruction
        </p>
        <h3 style='color:#FFD93D;'>Retention Policies</h3>
        <p style='color:#DCDCDC;'>
        • Define retention periods for different data types<br>
        • Implement automated deletion procedures<br>
        • Document retention decisions and rationale<br>
        • Regular review and update of policies<br>
        • Legal hold procedures for litigation
        </p>
        """)

    def _show_consent_management(self):
        self._show_compliance_content("✅ Consent Management Framework", """
        <h3 style='color:#FFD93D;'>Consent Requirements</h3>
        <p style='color:#DCDCDC;'>
        • Freely given, specific, informed, and unambiguous<br>
        • Clear and plain language explanations<br>
        • Separate consent for different processing purposes<br>
        • Easy withdrawal mechanisms<br>
        • Documentation and proof of consent
        </p>
        <h3 style='color:#FFD93D;'>Alternative Legal Bases</h3>
        <p style='color:#DCDCDC;'>
        • Legitimate interests assessment<br>
        • Legal obligation compliance<br>
        • Vital interests protection<br>
        • Public task performance<br>
        • Contractual necessity
        </p>
        <h3 style='color:#FFD93D;'>Consent Management Tools</h3>
        <p style='color:#DCDCDC;'>
        • Consent capture and recording systems<br>
        • Preference management interfaces<br>
        • Withdrawal request processing<br>
        • Audit trails and compliance reporting<br>
        • Integration with data processing systems
        </p>
        """)

    def _show_audit_trail(self):
        self._show_compliance_content("📋 Audit Trail and Documentation", """
        <h3 style='color:#FFD93D;'>Required Documentation</h3>
        <p style='color:#DCDCDC;'>
        • Investigation authorization and scope<br>
        • Data sources and collection methods<br>
        • Processing activities and purposes<br>
        • Data sharing and disclosure records<br>
        • Retention and deletion activities
        </p>
        <h3 style='color:#FFD93D;'>Audit Log Elements</h3>
        <p style='color:#DCDCDC;'>
        • Timestamp and duration of activities<br>
        • User identification and authentication<br>
        • System and application access logs<br>
        • Data queries and search parameters<br>
        • Export and sharing activities
        </p>
        <h3 style='color:#FFD93D;'>Compliance Reporting</h3>
        <p style='color:#DCDCDC;'>
        • Regular compliance assessments<br>
        • Incident and breach reporting<br>
        • Data subject request handling<br>
        • Third-party audit preparation<br>
        • Regulatory inquiry responses
        </p>
        """)

    def _show_risk_assessment(self):
        self._show_compliance_content("⚠️ Risk Assessment Framework", """
        <h3 style='color:#FFD93D;'>Risk Categories</h3>
        <p style='color:#DCDCDC;'>
        • <b>Legal Risk:</b> Violation of laws and regulations<br>
        • <b>Ethical Risk:</b> Harm to individuals or reputation<br>
        • <b>Operational Risk:</b> Disruption to business operations<br>
        • <b>Technical Risk:</b> System security and data breaches<br>
        • <b>Reputational Risk:</b> Damage to organization image
        </p>
        <h3 style='color:#FFD93D;'>Risk Assessment Process</h3>
        <p style='color:#DCDCDC;'>
        • Identify potential risks and threats<br>
        • Assess likelihood and impact severity<br>
        • Evaluate existing controls and mitigations<br>
        • Calculate residual risk levels<br>
        • Develop risk treatment strategies
        </p>
        <h3 style='color:#FFD93D;'>Mitigation Strategies</h3>
        <p style='color:#DCDCDC;'>
        • Risk avoidance through policy restrictions<br>
        • Risk reduction via technical controls<br>
        • Risk transfer through insurance or contracts<br>
        • Risk acceptance with documented rationale<br>
        • Continuous monitoring and review
        </p>
        """)

    # ------------------------------------------------------------------ #
    #  Theme                                                               #
    # ------------------------------------------------------------------ #

    def apply_theme(self):
        self.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 80);
                border-radius: 8px;
                border: 1px solid rgba(100, 200, 255, 40);
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 6px;
                margin-top: 10px;
                color: #64C8FF;
                padding-top: 6px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            QPushButton {
                background-color: rgba(30, 40, 50, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 6px;
                color: #DCDCDC;
                font-weight: bold;
                padding: 6px 10px;
            }
            QPushButton:hover {
                background-color: rgba(50, 70, 90, 200);
                border: 2px solid #64C8FF;
            }
            QPushButton#compliance_btn {
                background-color: rgba(0, 180, 0, 120);
                border: 2px solid #00CC00;
                color: #FFFFFF;
            }
            QPushButton#compliance_btn:hover {
                background-color: rgba(0, 220, 0, 160);
            }
            QComboBox {
                background-color: rgba(30, 40, 50, 180);
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 4px;
                color: #DCDCDC;
                padding: 4px 8px;
            }
            QComboBox::drop-down { border: none; }
            QComboBox QAbstractItemView {
                background-color: rgba(30, 40, 50, 240);
                color: #DCDCDC;
                selection-background-color: rgba(100, 200, 255, 150);
            }
            QCheckBox { color: #DCDCDC; }
            QCheckBox::indicator {
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 3px;
                background-color: rgba(30, 40, 50, 150);
            }
            QCheckBox::indicator:checked {
                background-color: rgba(100, 200, 255, 200);
            }
            QTextEdit {
                background-color: rgba(0, 0, 0, 180);
                border: 1px solid rgba(100, 200, 255, 80);
                border-radius: 5px;
                color: #DCDCDC;
                font-family: 'Segoe UI', sans-serif;
            }
            QLabel { color: #DCDCDC; }
            QSplitter::handle {
                background-color: rgba(100, 200, 255, 40);
                width: 2px;
            }
        """)
