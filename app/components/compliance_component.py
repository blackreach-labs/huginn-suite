from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QTextEdit, QFrame, QGroupBox, QPushButton, QScrollArea)
from PyQt6.QtCore import pyqtSignal

class ComplianceComponent(QWidget):
    compliance_checked = pyqtSignal(str, str)
    compliance_completed = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.apply_theme()

    def setup_ui(self):
        """Setup compliance UI"""
        layout = QHBoxLayout(self)
        
        # Left panel - controls
        left_panel = self.create_controls_panel()
        layout.addWidget(left_panel)
        
        # Right panel - content
        right_panel = self.create_content_panel()
        layout.addWidget(right_panel, 2)

    def create_controls_panel(self):
        """Create controls panel"""
        panel = QFrame()
        panel.setFixedWidth(300)
        layout = QVBoxLayout(panel)
        
        # Compliance modules
        modules_group = QGroupBox("Compliance & Ethics")
        modules_layout = QVBoxLayout(modules_group)
        
        buttons = [
            ("Legal Guidelines", self.show_legal_guidelines),
            ("Ethical Standards", self.show_ethical_standards),
            ("Privacy Compliance", self.show_privacy_compliance),
            ("Data Protection", self.show_data_protection),
            ("Consent Management", self.show_consent_management),
            ("Audit Trail", self.show_audit_trail),
            ("Risk Assessment", self.show_risk_assessment)
        ]
        
        for text, method in buttons:
            btn = QPushButton(text)
            btn.clicked.connect(method)
            btn.setMinimumHeight(35)
            modules_layout.addWidget(btn)
        
        layout.addWidget(modules_group)
        layout.addStretch()
        
        return panel

    def create_content_panel(self):
        """Create content panel"""
        panel = QFrame()
        layout = QVBoxLayout(panel)
        
        # Scrollable content area
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        
        self.content_widget = QWidget()
        self.content_layout = QVBoxLayout(self.content_widget)
        
        # Default content
        self.show_legal_guidelines()
        
        scroll_area.setWidget(self.content_widget)
        layout.addWidget(scroll_area)
        
        return panel

    def clear_content(self):
        """Clear existing content"""
        for i in reversed(range(self.content_layout.count())):
            child = self.content_layout.itemAt(i).widget()
            if child:
                child.setParent(None)

    def show_legal_guidelines(self):
        """Show legal guidelines"""
        self.compliance_checked.emit("", "Legal Guidelines")
        self.clear_content()
        
        title = QLabel("⚖️ Legal Guidelines for OSINT Activities")
        title.setStyleSheet("color: #64C8FF; font-size: 16pt; font-weight: bold; padding: 10px;")
        self.content_layout.addWidget(title)
        
        content = QTextEdit()
        content.setReadOnly(True)
        content.setHtml("""
        <h3 style='color: #FFD93D;'>Legal Framework</h3>
        <p style='color: #DCDCDC;'>
        • <b>Computer Fraud and Abuse Act (CFAA):</b> Prohibits unauthorized access to computer systems<br>
        • <b>Digital Millennium Copyright Act (DMCA):</b> Protects copyrighted digital content<br>
        • <b>Electronic Communications Privacy Act (ECPA):</b> Governs electronic communications interception<br>
        • <b>General Data Protection Regulation (GDPR):</b> EU data protection and privacy regulation<br>
        • <b>California Consumer Privacy Act (CCPA):</b> California privacy rights legislation
        </p>
        
        <h3 style='color: #FFD93D;'>Permitted Activities</h3>
        <p style='color: #DCDCDC;'>
        • Public information gathering from openly accessible sources<br>
        • Social media analysis of public profiles and posts<br>
        • DNS and WHOIS lookups for publicly registered domains<br>
        • Certificate transparency log searches<br>
        • Search engine queries and cached content analysis
        </p>
        
        <h3 style='color: #FFD93D;'>Prohibited Activities</h3>
        <p style='color: #FF6B6B;'>
        • Unauthorized access to private systems or accounts<br>
        • Bypassing authentication mechanisms<br>
        • Social engineering or impersonation<br>
        • Harassment or stalking behaviors<br>
        • Violation of terms of service agreements
        </p>
        
        <h3 style='color: #FFD93D;'>Best Practices</h3>
        <p style='color: #DCDCDC;'>
        • Always obtain proper authorization before conducting OSINT<br>
        • Document the legal basis for your investigation<br>
        • Respect rate limits and terms of service<br>
        • Maintain detailed logs of all activities<br>
        • Consult legal counsel when in doubt
        </p>
        """)
        content.setMinimumHeight(400)
        self.content_layout.addWidget(content)
        
        self.compliance_completed.emit({"legal_guidelines": True})

    def show_ethical_standards(self):
        """Show ethical standards"""
        self.compliance_checked.emit("", "Ethical Standards")
        self.clear_content()
        
        title = QLabel("🤝 Ethical Standards for OSINT Practitioners")
        title.setStyleSheet("color: #64C8FF; font-size: 16pt; font-weight: bold; padding: 10px;")
        self.content_layout.addWidget(title)
        
        content = QTextEdit()
        content.setReadOnly(True)
        content.setHtml("""
        <h3 style='color: #FFD93D;'>Core Ethical Principles</h3>
        <p style='color: #DCDCDC;'>
        • <b>Respect for Privacy:</b> Honor individual privacy rights and expectations<br>
        • <b>Proportionality:</b> Use methods proportionate to the investigation's importance<br>
        • <b>Transparency:</b> Be open about your methods and intentions when possible<br>
        • <b>Accountability:</b> Take responsibility for your actions and their consequences<br>
        • <b>Non-maleficence:</b> Do no harm to individuals or organizations
        </p>
        
        <h3 style='color: #FFD93D;'>Professional Standards</h3>
        <p style='color: #DCDCDC;'>
        • Maintain professional competence and stay updated on legal changes<br>
        • Avoid conflicts of interest and disclose when they exist<br>
        • Protect the confidentiality of sensitive information<br>
        • Collaborate ethically with other professionals<br>
        • Report unethical behavior when encountered
        </p>
        
        <h3 style='color: #FFD93D;'>Data Handling Ethics</h3>
        <p style='color: #DCDCDC;'>
        • Collect only necessary information for legitimate purposes<br>
        • Secure and protect collected data appropriately<br>
        • Delete data when no longer needed<br>
        • Share information only with authorized parties<br>
        • Respect data subject rights and requests
        </p>
        """)
        content.setMinimumHeight(400)
        self.content_layout.addWidget(content)
        
        self.compliance_completed.emit({"ethical_standards": True})

    def show_privacy_compliance(self):
        """Show privacy compliance"""
        self.compliance_checked.emit("", "Privacy Compliance")
        self.clear_content()
        
        title = QLabel("🔒 Privacy Compliance Requirements")
        title.setStyleSheet("color: #64C8FF; font-size: 16pt; font-weight: bold; padding: 10px;")
        self.content_layout.addWidget(title)
        
        content = QTextEdit()
        content.setReadOnly(True)
        content.setHtml("""
        <h3 style='color: #FFD93D;'>GDPR Compliance</h3>
        <p style='color: #DCDCDC;'>
        • Lawful basis for processing personal data<br>
        • Data subject rights (access, rectification, erasure)<br>
        • Privacy by design and by default<br>
        • Data protection impact assessments<br>
        • Breach notification requirements
        </p>
        
        <h3 style='color: #FFD93D;'>CCPA Compliance</h3>
        <p style='color: #DCDCDC;'>
        • Consumer right to know about data collection<br>
        • Right to delete personal information<br>
        • Right to opt-out of data sales<br>
        • Non-discrimination for exercising rights<br>
        • Reasonable security measures
        </p>
        
        <h3 style='color: #FFD93D;'>International Considerations</h3>
        <p style='color: #DCDCDC;'>
        • Cross-border data transfer restrictions<br>
        • Local data protection laws and regulations<br>
        • Sector-specific privacy requirements<br>
        • Cultural privacy expectations<br>
        • Diplomatic and political sensitivities
        </p>
        """)
        content.setMinimumHeight(400)
        self.content_layout.addWidget(content)
        
        self.compliance_completed.emit({"privacy_compliance": True})

    def show_data_protection(self):
        """Show data protection guidelines"""
        self.compliance_checked.emit("", "Data Protection")
        self.clear_content()
        
        title = QLabel("🛡️ Data Protection Guidelines")
        title.setStyleSheet("color: #64C8FF; font-size: 16pt; font-weight: bold; padding: 10px;")
        self.content_layout.addWidget(title)
        
        content = QTextEdit()
        content.setReadOnly(True)
        content.setHtml("""
        <h3 style='color: #FFD93D;'>Data Classification</h3>
        <p style='color: #DCDCDC;'>
        • <b>Public:</b> Openly available information with no restrictions<br>
        • <b>Internal:</b> Information for internal use within organization<br>
        • <b>Confidential:</b> Sensitive information requiring protection<br>
        • <b>Restricted:</b> Highly sensitive data with strict access controls
        </p>
        
        <h3 style='color: #FFD93D;'>Security Measures</h3>
        <p style='color: #DCDCDC;'>
        • Encryption of data at rest and in transit<br>
        • Access controls and authentication mechanisms<br>
        • Regular security assessments and audits<br>
        • Incident response and breach procedures<br>
        • Secure data disposal and destruction
        </p>
        
        <h3 style='color: #FFD93D;'>Retention Policies</h3>
        <p style='color: #DCDCDC;'>
        • Define retention periods for different data types<br>
        • Implement automated deletion procedures<br>
        • Document retention decisions and rationale<br>
        • Regular review and update of policies<br>
        • Legal hold procedures for litigation
        </p>
        """)
        content.setMinimumHeight(400)
        self.content_layout.addWidget(content)
        
        self.compliance_completed.emit({"data_protection": True})

    def show_consent_management(self):
        """Show consent management"""
        self.compliance_checked.emit("", "Consent Management")
        self.clear_content()
        
        title = QLabel("✅ Consent Management Framework")
        title.setStyleSheet("color: #64C8FF; font-size: 16pt; font-weight: bold; padding: 10px;")
        self.content_layout.addWidget(title)
        
        content = QTextEdit()
        content.setReadOnly(True)
        content.setHtml("""
        <h3 style='color: #FFD93D;'>Consent Requirements</h3>
        <p style='color: #DCDCDC;'>
        • Freely given, specific, informed, and unambiguous<br>
        • Clear and plain language explanations<br>
        • Separate consent for different processing purposes<br>
        • Easy withdrawal mechanisms<br>
        • Documentation and proof of consent
        </p>
        
        <h3 style='color: #FFD93D;'>Alternative Legal Bases</h3>
        <p style='color: #DCDCDC;'>
        • Legitimate interests assessment<br>
        • Legal obligation compliance<br>
        • Vital interests protection<br>
        • Public task performance<br>
        • Contractual necessity
        </p>
        
        <h3 style='color: #FFD93D;'>Consent Management Tools</h3>
        <p style='color: #DCDCDC;'>
        • Consent capture and recording systems<br>
        • Preference management interfaces<br>
        • Withdrawal request processing<br>
        • Audit trails and compliance reporting<br>
        • Integration with data processing systems
        </p>
        """)
        content.setMinimumHeight(400)
        self.content_layout.addWidget(content)
        
        self.compliance_completed.emit({"consent_management": True})

    def show_audit_trail(self):
        """Show audit trail requirements"""
        self.compliance_checked.emit("", "Audit Trail")
        self.clear_content()
        
        title = QLabel("📋 Audit Trail and Documentation")
        title.setStyleSheet("color: #64C8FF; font-size: 16pt; font-weight: bold; padding: 10px;")
        self.content_layout.addWidget(title)
        
        content = QTextEdit()
        content.setReadOnly(True)
        content.setHtml("""
        <h3 style='color: #FFD93D;'>Required Documentation</h3>
        <p style='color: #DCDCDC;'>
        • Investigation authorization and scope<br>
        • Data sources and collection methods<br>
        • Processing activities and purposes<br>
        • Data sharing and disclosure records<br>
        • Retention and deletion activities
        </p>
        
        <h3 style='color: #FFD93D;'>Audit Log Elements</h3>
        <p style='color: #DCDCDC;'>
        • Timestamp and duration of activities<br>
        • User identification and authentication<br>
        • System and application access logs<br>
        • Data queries and search parameters<br>
        • Export and sharing activities
        </p>
        
        <h3 style='color: #FFD93D;'>Compliance Reporting</h3>
        <p style='color: #DCDCDC;'>
        • Regular compliance assessments<br>
        • Incident and breach reporting<br>
        • Data subject request handling<br>
        • Third-party audit preparation<br>
        • Regulatory inquiry responses
        </p>
        """)
        content.setMinimumHeight(400)
        self.content_layout.addWidget(content)
        
        self.compliance_completed.emit({"audit_trail": True})

    def show_risk_assessment(self):
        """Show risk assessment framework"""
        self.compliance_checked.emit("", "Risk Assessment")
        self.clear_content()
        
        title = QLabel("⚠️ Risk Assessment Framework")
        title.setStyleSheet("color: #64C8FF; font-size: 16pt; font-weight: bold; padding: 10px;")
        self.content_layout.addWidget(title)
        
        content = QTextEdit()
        content.setReadOnly(True)
        content.setHtml("""
        <h3 style='color: #FFD93D;'>Risk Categories</h3>
        <p style='color: #DCDCDC;'>
        • <b>Legal Risk:</b> Violation of laws and regulations<br>
        • <b>Ethical Risk:</b> Harm to individuals or reputation<br>
        • <b>Operational Risk:</b> Disruption to business operations<br>
        • <b>Technical Risk:</b> System security and data breaches<br>
        • <b>Reputational Risk:</b> Damage to organization image
        </p>
        
        <h3 style='color: #FFD93D;'>Risk Assessment Process</h3>
        <p style='color: #DCDCDC;'>
        • Identify potential risks and threats<br>
        • Assess likelihood and impact severity<br>
        • Evaluate existing controls and mitigations<br>
        • Calculate residual risk levels<br>
        • Develop risk treatment strategies
        </p>
        
        <h3 style='color: #FFD93D;'>Mitigation Strategies</h3>
        <p style='color: #DCDCDC;'>
        • Risk avoidance through policy restrictions<br>
        • Risk reduction via technical controls<br>
        • Risk transfer through insurance or contracts<br>
        • Risk acceptance with documented rationale<br>
        • Continuous monitoring and review
        </p>
        """)
        content.setMinimumHeight(400)
        self.content_layout.addWidget(content)
        
        self.compliance_completed.emit({"risk_assessment": True})

    def apply_theme(self):
        """Apply component theme"""
        self.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 100);
                border-radius: 10px;
                border: 1px solid rgba(100, 200, 255, 50);
            }
            QPushButton {
                background-color: rgba(30, 40, 50, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 8px;
                color: #DCDCDC;
                font-weight: bold;
                padding: 8px;
            }
            QPushButton:hover {
                background-color: rgba(50, 70, 90, 200);
                border: 2px solid #64C8FF;
            }
            QTextEdit {
                background-color: rgba(0, 0, 0, 200);
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                color: #DCDCDC;
                font-family: 'Segoe UI', sans-serif;
            }
            QLabel {
                color: #64C8FF;
                font-weight: bold;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                margin-top: 10px;
                color: #64C8FF;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
            QScrollArea {
                border: none;
                background-color: transparent;
            }
        """)