# app/components/findings/findings_details_component.py
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QTextEdit
from app.core.html_utils import h

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
        # details comes from a hardcoded dict — safe as-is (contains trusted HTML)
        # finding["title"] comes from user-selected data — escape it
        self.info_panel.setHtml(f"""
        <div style='color: #64C8FF; font-size: 20pt; font-weight: bold; margin-bottom: 15px;'>{h(finding["title"])}</div>
        <div style='color: #DCDCDC; font-size: 14pt; line-height: 150%;'>{details}</div>
        """)

    def show_hover_info(self, title, description):
        self.info_panel.setHtml(f"""
        <div style='color: #64C8FF; font-size: 22pt; font-weight: bold;'>{h(title)}</div>
        <div style='color: #DCDCDC; font-size: 16pt;'>{h(description)}</div>
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
            """,
            "wireless_security": """
            <b>Description:</b> Vulnerabilities in WiFi and Bluetooth configurations discovered during wireless security scans.
            <br><br><b>Common Findings:</b>
            <ul>
            <li>WPA2 networks vulnerable to PMKID or handshake capture attacks</li>
            <li>Networks without Protected Management Frames (802.11w / PMF)</li>
            <li>WPA3 transition mode allowing downgrade attacks</li>
            <li>Evil Twin susceptibility (no 802.1X or certificate pinning)</li>
            <li>SSID Confusion (CVE-2023-52424) — multi-SSID environments</li>
            <li>Bluetooth devices in discoverable mode or using legacy pairing</li>
            </ul>
            <b>Risk:</b> Credential interception, man-in-the-middle, unauthorized network access, lateral movement
            <br><br><b>Remediation:</b>
            <ul>
            <li>Enable PMF (802.11w) on all access points</li>
            <li>Use WPA3-SAE where supported; disable transition mode</li>
            <li>Deploy 802.1X (EAP-TLS) with certificate validation for enterprise networks</li>
            <li>Implement wireless IDS/IPS to detect rogue APs and deauth floods</li>
            <li>Disable Bluetooth discoverability; use Secure Simple Pairing</li>
            <li>Rotate PSKs regularly; use unique per-SSID keys</li>
            </ul>
            <b>References:</b> NIST SP 800-153, CIS Wireless Benchmark, OWASP Wireless Testing Guide
            """
        }
        return details.get(finding_id, "Detailed information not available.")