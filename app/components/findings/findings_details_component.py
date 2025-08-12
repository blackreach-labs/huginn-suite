# app/components/findings/findings_details_component.py
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QTextEdit

class FindingsDetailsComponent(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        self.info_panel = QTextEdit()
        self.info_panel.setReadOnly(True)
        self.show_default_content()
        layout.addWidget(self.info_panel)

    def show_default_content(self):
        self.info_panel.setHtml("""
        <div style='color: #64C8FF; font-size: 18pt; font-weight: bold; margin-bottom: 20px;'>Common Penetration Testing Findings</div>
        <div style='color: #DCDCDC; font-size: 14pt; line-height: 150%;'>
        This section covers the most frequently discovered vulnerabilities and misconfigurations during penetration tests.
        <br><br>
        <i>Select a category from the left to view detailed information and remediation guidance.</i>
        <br><br>
        <b>💡 Tip:</b> Use the "Advanced Reporting" tab to generate comprehensive reports from your scan data.
        </div>
        """)

    def show_finding_details(self, finding):
        details = self.get_finding_details(finding["id"])
        self.info_panel.setHtml(f"""
        <div style='color: #64C8FF; font-size: 20pt; font-weight: bold; margin-bottom: 15px;'>{finding["title"]}</div>
        <div style='color: #DCDCDC; font-size: 14pt; line-height: 150%;'>{details}</div>
        """)

    def show_hover_info(self, title, description):
        self.info_panel.setHtml(f"""
        <div style='color: #64C8FF; font-size: 22pt; font-weight: bold;'>{title}</div>
        <div style='color: #DCDCDC; font-size: 16pt;'>{description}</div>
        """)

    def get_finding_details(self, finding_id):
        details = {
            "default_pages": """
            <b>Description:</b> Default web pages and configurations that reveal system information.
            <br><br><b>Risk:</b> Information disclosure, system fingerprinting
            <br><br><b>Remediation:</b> Remove or customize default pages, configure custom error pages
            """,
            "historical_compromise": """
            <b>Description:</b> Previously compromised accounts and credentials still in use.
            <br><br><b>Risk:</b> Account takeover, lateral movement
            <br><br><b>Remediation:</b> Force password resets, implement multi-factor authentication
            """,
            "insufficient_auth": """
            <b>Description:</b> Weak or missing authentication controls.
            <br><br><b>Risk:</b> Unauthorized access, privilege escalation
            <br><br><b>Remediation:</b> Implement strong authentication, enforce password policies
            """,
            "sql_injection": """
            <b>Description:</b> Database query manipulation vulnerabilities.
            <br><br><b>Risk:</b> Data breach, system compromise
            <br><br><b>Remediation:</b> Use parameterized queries, input validation
            """,
            "weak_passwords": """
            <b>Description:</b> Inadequate password requirements and default credentials.
            <br><br><b>Risk:</b> Brute force attacks, credential stuffing
            <br><br><b>Remediation:</b> Enforce strong password policies, remove default accounts
            """
        }
        return details.get(finding_id, "Detailed information not available.")