"""Global Settings page"""

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, 
                            QFormLayout, QLineEdit, QPushButton, QLabel, 
                            QSpinBox, QCheckBox, QGroupBox, QMessageBox)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from shared.configuration.global_settings import global_settings
from app.core.logger import logger

class GlobalSettingsPage(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.load_settings()
    
    def init_ui(self):
        """Initialize the user interface"""
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Global Settings")
        title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # Tab widget
        self.tabs = QTabWidget()
        
        # API Keys tab
        self.create_api_keys_tab()
        
        # General Settings tab
        self.create_general_tab()
        
        # Proxy Settings tab
        self.create_proxy_tab()
        
        # DNS Settings tab
        self.create_dns_tab()
        
        layout.addWidget(self.tabs)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.save_btn = QPushButton("Save Settings")
        self.save_btn.clicked.connect(self.save_settings)
        
        self.reset_btn = QPushButton("Reset to Defaults")
        self.reset_btn.clicked.connect(self.reset_settings)
        
        button_layout.addStretch()
        button_layout.addWidget(self.save_btn)
        button_layout.addWidget(self.reset_btn)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
    
    def create_api_keys_tab(self):
        """Create API Keys tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Hash Cracking APIs
        hash_group = QGroupBox("Hash Cracking APIs")
        hash_layout = QFormLayout()
        
        self.hashes_com_key = QLineEdit()
        self.hashes_com_key.setPlaceholderText("Enter your hashes.com API key")
        hash_layout.addRow("Hashes.com API Key:", self.hashes_com_key)
        
        self.md5decrypt_email = QLineEdit()
        self.md5decrypt_email.setPlaceholderText("Enter your email for MD5Decrypt")
        hash_layout.addRow("MD5Decrypt Email:", self.md5decrypt_email)
        
        self.md5decrypt_key = QLineEdit()
        self.md5decrypt_key.setPlaceholderText("Enter your MD5Decrypt API key")
        hash_layout.addRow("MD5Decrypt API Key:", self.md5decrypt_key)
        
        hash_group.setLayout(hash_layout)
        layout.addWidget(hash_group)
        
        # OSINT & Intelligence APIs
        osint_group = QGroupBox("OSINT & Intelligence APIs")
        osint_layout = QFormLayout()
        
        self.shodan_key = QLineEdit()
        self.shodan_key.setPlaceholderText("Enter your Shodan API key")
        osint_layout.addRow("Shodan API Key:", self.shodan_key)
        
        self.virustotal_key = QLineEdit()
        self.virustotal_key.setPlaceholderText("Enter your VirusTotal API key")
        osint_layout.addRow("VirusTotal API Key:", self.virustotal_key)
        
        self.urlvoid_key = QLineEdit()
        self.urlvoid_key.setPlaceholderText("Enter your URLVoid API key")
        osint_layout.addRow("URLVoid API Key:", self.urlvoid_key)
        
        osint_group.setLayout(osint_layout)
        layout.addWidget(osint_group)
        
        # Professional Subdomain Enumeration APIs
        subdomain_group = QGroupBox("🔍 Professional Subdomain Enumeration APIs")
        subdomain_layout = QFormLayout()
        
        # Certificate Transparency
        cert_label = QLabel("Certificate Transparency:")
        cert_label.setStyleSheet("font-weight: bold; color: #64C8FF;")
        subdomain_layout.addRow(cert_label)
        
        self.certspotter_key = QLineEdit()
        self.certspotter_key.setPlaceholderText("CertSpotter API key (100/hour free, 1000/hour paid)")
        subdomain_layout.addRow("  CertSpotter:", self.certspotter_key)
        
        # Search & Intelligence
        search_label = QLabel("Search & Intelligence:")
        search_label.setStyleSheet("font-weight: bold; color: #64C8FF;")
        subdomain_layout.addRow(search_label)
        
        # Note: VirusTotal already exists above, so we'll reference it
        vt_note = QLabel("  VirusTotal: (configured above)")
        vt_note.setStyleSheet("color: #FFD93D; font-style: italic;")
        subdomain_layout.addRow(vt_note)
        
        self.censys_id = QLineEdit()
        self.censys_id.setPlaceholderText("Censys API ID (120/min free, 480/min paid)")
        subdomain_layout.addRow("  Censys API ID:", self.censys_id)
        
        self.censys_secret = QLineEdit()
        self.censys_secret.setPlaceholderText("Censys API Secret")
        self.censys_secret.setEchoMode(QLineEdit.EchoMode.Password)
        subdomain_layout.addRow("  Censys Secret:", self.censys_secret)
        
        self.securitytrails_key = QLineEdit()
        self.securitytrails_key.setPlaceholderText("SecurityTrails API key (50/month free, 2000/month paid)")
        subdomain_layout.addRow("  SecurityTrails:", self.securitytrails_key)
        
        # Threat Intelligence
        threat_label = QLabel("Threat Intelligence:")
        threat_label.setStyleSheet("font-weight: bold; color: #64C8FF;")
        subdomain_layout.addRow(threat_label)
        
        self.binaryedge_key = QLineEdit()
        self.binaryedge_key.setPlaceholderText("BinaryEdge API key (250/month free, 10000/month paid)")
        subdomain_layout.addRow("  BinaryEdge:", self.binaryedge_key)
        
        self.passivetotal_user = QLineEdit()
        self.passivetotal_user.setPlaceholderText("PassiveTotal username")
        subdomain_layout.addRow("  PassiveTotal User:", self.passivetotal_user)
        
        self.passivetotal_key = QLineEdit()
        self.passivetotal_key.setPlaceholderText("PassiveTotal API key (2000/month free, 10000/month paid)")
        self.passivetotal_key.setEchoMode(QLineEdit.EchoMode.Password)
        subdomain_layout.addRow("  PassiveTotal Key:", self.passivetotal_key)
        
        # DNS Intelligence
        dns_label = QLabel("DNS Intelligence:")
        dns_label.setStyleSheet("font-weight: bold; color: #64C8FF;")
        subdomain_layout.addRow(dns_label)
        
        self.dnsdb_key = QLineEdit()
        self.dnsdb_key.setPlaceholderText("Farsight DNSDB API key (paid service)")
        self.dnsdb_key.setEchoMode(QLineEdit.EchoMode.Password)
        subdomain_layout.addRow("  DNSDB (Farsight):", self.dnsdb_key)
        
        # Free sources note
        free_note = QLabel("📝 Free Sources (No API Key Required): crt.sh, Wayback Machine, URLScan.io")
        free_note.setStyleSheet("color: #00FF41; font-style: italic; margin-top: 10px;")
        subdomain_layout.addRow(free_note)
        
        # API registration links
        links_label = QLabel("🔗 API Registration Links:")
        links_label.setStyleSheet("font-weight: bold; color: #FFD93D; margin-top: 15px;")
        subdomain_layout.addRow(links_label)
        
        links_text = QLabel("""
        • CertSpotter: https://sslmate.com/certspotter/api/
        • VirusTotal: https://www.virustotal.com/gui/join-us
        • Censys: https://search.censys.io/register
        • SecurityTrails: https://securitytrails.com/corp/api
        • BinaryEdge: https://app.binaryedge.io/sign-up
        • PassiveTotal: https://community.riskiq.com/registration
        • DNSDB: https://www.farsightsecurity.com/dnsdb-community-edition/
        """)
        links_text.setStyleSheet("color: #DCDCDC; font-size: 9px; margin-left: 10px;")
        links_text.setWordWrap(True)
        subdomain_layout.addRow(links_text)
        
        subdomain_group.setLayout(subdomain_layout)
        layout.addWidget(subdomain_group)
        
        # Test API Keys button
        test_btn = QPushButton("🧪 Test API Keys")
        test_btn.clicked.connect(self.test_api_keys)
        test_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(0, 100, 200, 150);
                border: 2px solid rgba(0, 150, 255, 100);
                border-radius: 5px;
                color: white;
                font-weight: bold;
                padding: 8px;
            }
            QPushButton:hover {
                background-color: rgba(0, 150, 255, 200);
            }
        """)
        layout.addWidget(test_btn)
        
        layout.addStretch()
        tab.setLayout(layout)
        self.tabs.addTab(tab, "🔑 API Keys")
    
    def create_general_tab(self):
        """Create General Settings tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        general_group = QGroupBox("General Settings")
        general_layout = QFormLayout()
        
        self.default_timeout = QSpinBox()
        self.default_timeout.setRange(5, 300)
        self.default_timeout.setSuffix(" seconds")
        general_layout.addRow("Default Timeout:", self.default_timeout)
        
        self.max_threads = QSpinBox()
        self.max_threads.setRange(1, 200)
        general_layout.addRow("Max Threads:", self.max_threads)
        
        self.auto_save = QCheckBox("Automatically save scan results")
        general_layout.addRow("Auto Save:", self.auto_save)
        
        general_group.setLayout(general_layout)
        layout.addWidget(general_group)
        
        layout.addStretch()
        tab.setLayout(layout)
        self.tabs.addTab(tab, "General")
    
    def create_proxy_tab(self):
        """Create Proxy Settings tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        proxy_group = QGroupBox("Proxy Settings")
        proxy_layout = QFormLayout()
        
        self.proxy_enabled = QCheckBox("Enable proxy")
        proxy_layout.addRow("Proxy Enabled:", self.proxy_enabled)
        
        self.proxy_host = QLineEdit()
        self.proxy_host.setPlaceholderText("127.0.0.1")
        proxy_layout.addRow("Proxy Host:", self.proxy_host)
        
        self.proxy_port = QSpinBox()
        self.proxy_port.setRange(1, 65535)
        proxy_layout.addRow("Proxy Port:", self.proxy_port)
        
        self.proxy_username = QLineEdit()
        self.proxy_username.setPlaceholderText("Username (optional)")
        proxy_layout.addRow("Username:", self.proxy_username)
        
        self.proxy_password = QLineEdit()
        self.proxy_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.proxy_password.setPlaceholderText("Password (optional)")
        proxy_layout.addRow("Password:", self.proxy_password)
        
        proxy_group.setLayout(proxy_layout)
        layout.addWidget(proxy_group)
        
        layout.addStretch()
        tab.setLayout(layout)
        self.tabs.addTab(tab, "Proxy")
    
    def create_dns_tab(self):
        """Create DNS Settings tab"""
        try:
            from app.widgets.dns_settings_widget import DNSSettingsWidget
            dns_widget = DNSSettingsWidget()
            self.tabs.addTab(dns_widget, "DNS")
        except ImportError:
            # Fallback if DNS widget not available
            tab = QWidget()
            layout = QVBoxLayout()
            layout.addWidget(QLabel("DNS Settings widget not available"))
            tab.setLayout(layout)
            self.tabs.addTab(tab, "DNS")
    
    def load_settings(self):
        """Load settings from global settings"""
        # Hash Cracking API Keys
        self.hashes_com_key.setText(global_settings.get("api_keys.hashes_com", ""))
        self.md5decrypt_email.setText(global_settings.get("api_keys.md5decrypt_email", ""))
        self.md5decrypt_key.setText(global_settings.get("api_keys.md5decrypt_key", ""))
        
        # OSINT & Intelligence API Keys
        self.shodan_key.setText(global_settings.get("api_keys.shodan", ""))
        self.virustotal_key.setText(global_settings.get("api_keys.virustotal", ""))
        self.urlvoid_key.setText(global_settings.get("api_keys.urlvoid", ""))
        
        # Professional Subdomain Enumeration API Keys
        self.certspotter_key.setText(global_settings.get("api_keys.certspotter", ""))
        self.censys_id.setText(global_settings.get("api_keys.censys_id", ""))
        self.censys_secret.setText(global_settings.get("api_keys.censys_secret", ""))
        self.securitytrails_key.setText(global_settings.get("api_keys.securitytrails", ""))
        self.binaryedge_key.setText(global_settings.get("api_keys.binaryedge", ""))
        self.passivetotal_user.setText(global_settings.get("api_keys.passivetotal_user", ""))
        self.passivetotal_key.setText(global_settings.get("api_keys.passivetotal_key", ""))
        self.dnsdb_key.setText(global_settings.get("api_keys.dnsdb", ""))
        
        # General
        self.default_timeout.setValue(global_settings.get("general.default_timeout", 30))
        self.max_threads.setValue(global_settings.get("general.max_threads", 50))
        self.auto_save.setChecked(global_settings.get("general.auto_save", True))
        
        # Proxy
        self.proxy_enabled.setChecked(global_settings.get("proxy.enabled", False))
        self.proxy_host.setText(global_settings.get("proxy.host", ""))
        self.proxy_port.setValue(global_settings.get("proxy.port", 8080))
        self.proxy_username.setText(global_settings.get("proxy.username", ""))
        self.proxy_password.setText(global_settings.get("proxy.password", ""))
        
        # Load DNS settings if widget exists
        dns_tab = None
        for i in range(self.tabs.count()):
            if self.tabs.tabText(i) == "DNS":
                dns_tab = self.tabs.widget(i)
                break
        
        if dns_tab and hasattr(dns_tab, 'load_settings'):
            dns_tab.load_settings()
    
    def save_settings(self):
        """Save settings to global settings"""
        # Hash Cracking API Keys
        global_settings.set("api_keys.hashes_com", self.hashes_com_key.text())
        global_settings.set("api_keys.md5decrypt_email", self.md5decrypt_email.text())
        global_settings.set("api_keys.md5decrypt_key", self.md5decrypt_key.text())
        
        # OSINT & Intelligence API Keys
        global_settings.set("api_keys.shodan", self.shodan_key.text())
        global_settings.set("api_keys.virustotal", self.virustotal_key.text())
        global_settings.set("api_keys.urlvoid", self.urlvoid_key.text())
        
        # Professional Subdomain Enumeration API Keys
        global_settings.set("api_keys.certspotter", self.certspotter_key.text())
        global_settings.set("api_keys.censys_id", self.censys_id.text())
        global_settings.set("api_keys.censys_secret", self.censys_secret.text())
        global_settings.set("api_keys.securitytrails", self.securitytrails_key.text())
        global_settings.set("api_keys.binaryedge", self.binaryedge_key.text())
        global_settings.set("api_keys.passivetotal_user", self.passivetotal_user.text())
        global_settings.set("api_keys.passivetotal_key", self.passivetotal_key.text())
        global_settings.set("api_keys.dnsdb", self.dnsdb_key.text())
        
        # General
        global_settings.set("general.default_timeout", self.default_timeout.value())
        global_settings.set("general.max_threads", self.max_threads.value())
        global_settings.set("general.auto_save", self.auto_save.isChecked())
        
        # Proxy
        global_settings.set("proxy.enabled", self.proxy_enabled.isChecked())
        global_settings.set("proxy.host", self.proxy_host.text())
        global_settings.set("proxy.port", self.proxy_port.value())
        global_settings.set("proxy.username", self.proxy_username.text())
        global_settings.set("proxy.password", self.proxy_password.text())
        
        # Save DNS settings if widget exists
        dns_tab = None
        for i in range(self.tabs.count()):
            if self.tabs.tabText(i) == "DNS":
                dns_tab = self.tabs.widget(i)
                break
        
        if dns_tab and hasattr(dns_tab, 'save_settings'):
            dns_tab.save_settings()
        
        # Update the subdomain engine's API keys
        self._update_subdomain_engine_keys()
        
        QMessageBox.information(self, "Settings Saved", "Global settings have been saved successfully.")
    
    def reset_settings(self):
        """Reset settings to defaults"""
        reply = QMessageBox.question(self, "Reset Settings", 
                                   "Are you sure you want to reset all settings to defaults?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            # Reset to defaults by recreating the settings
            global_settings._settings = global_settings._get_default_settings()
            global_settings._save_settings()
            
            # Reset DNS settings if widget exists
            dns_tab = None
            for i in range(self.tabs.count()):
                if self.tabs.tabText(i) == "DNS":
                    dns_tab = self.tabs.widget(i)
                    break
            
            if dns_tab and hasattr(dns_tab, 'reset_settings'):
                dns_tab.reset_settings()
            
            self.load_settings()
            QMessageBox.information(self, "Settings Reset", "All settings have been reset to defaults.")
    
    def test_api_keys(self):
        """Test API keys functionality"""
        from PyQt6.QtWidgets import QProgressDialog
        from PyQt6.QtCore import QTimer
        
        # Create progress dialog
        progress = QProgressDialog("Testing API keys...", "Cancel", 0, 0, self)
        progress.setWindowTitle("API Key Testing")
        progress.setModal(True)
        progress.show()
        
        # Simulate testing (in a real implementation, you'd test each API)
        QTimer.singleShot(2000, lambda: self._show_api_test_results(progress))
    
    def _show_api_test_results(self, progress_dialog):
        """Show API key test results"""
        progress_dialog.close()
        
        # Get configured keys
        configured_keys = []
        if self.certspotter_key.text().strip():
            configured_keys.append("CertSpotter")
        if self.virustotal_key.text().strip():
            configured_keys.append("VirusTotal")
        if self.censys_id.text().strip() and self.censys_secret.text().strip():
            configured_keys.append("Censys")
        if self.securitytrails_key.text().strip():
            configured_keys.append("SecurityTrails")
        if self.binaryedge_key.text().strip():
            configured_keys.append("BinaryEdge")
        if self.passivetotal_user.text().strip() and self.passivetotal_key.text().strip():
            configured_keys.append("PassiveTotal")
        if self.dnsdb_key.text().strip():
            configured_keys.append("DNSDB")
        
        if configured_keys:
            message = f"Configured API Keys ({len(configured_keys)}):\n\n" + "\n".join([f"✅ {key}" for key in configured_keys])
            message += "\n\nNote: Actual API validation requires network testing."
        else:
            message = "No API keys configured.\n\nFree sources (crt.sh, Wayback Machine) will still work."
        
        QMessageBox.information(self, "API Key Test Results", message)
    
    def _update_subdomain_engine_keys(self):
        """Update the subdomain engine with new API keys"""
        try:
            from app.core.subdomain_engine import subdomain_engine
            
            # Create API keys dictionary
            api_keys = {}
            
            if self.certspotter_key.text().strip():
                api_keys['certspotter'] = self.certspotter_key.text().strip()
            
            if self.virustotal_key.text().strip():
                api_keys['virustotal'] = self.virustotal_key.text().strip()
            
            if self.censys_id.text().strip() and self.censys_secret.text().strip():
                api_keys['censys_id'] = self.censys_id.text().strip()
                api_keys['censys_secret'] = self.censys_secret.text().strip()
            
            if self.securitytrails_key.text().strip():
                api_keys['securitytrails'] = self.securitytrails_key.text().strip()
            
            if self.binaryedge_key.text().strip():
                api_keys['binaryedge'] = self.binaryedge_key.text().strip()
            
            if self.passivetotal_user.text().strip() and self.passivetotal_key.text().strip():
                api_keys['passivetotal_user'] = self.passivetotal_user.text().strip()
                api_keys['passivetotal_key'] = self.passivetotal_key.text().strip()
            
            if self.dnsdb_key.text().strip():
                api_keys['dnsdb'] = self.dnsdb_key.text().strip()
            
            # Update the engine's API keys
            subdomain_engine.api_keys = api_keys
            
        except ImportError as _exc:
            # Subdomain engine not available
            pass
            logger.debug("Suppressed exception", exc_info=True)
