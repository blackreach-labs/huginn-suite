"""Global Settings page"""

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, 
                            QFormLayout, QLineEdit, QPushButton, QLabel, 
                            QSpinBox, QCheckBox, QGroupBox, QMessageBox,
                            QScrollArea, QSizePolicy)
from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtGui import QFont, QDesktopServices
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
        title.setFont(QFont("Neuropol X", 16, QFont.Weight.Bold))
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
    
    def _make_api_field(self, placeholder, password=False, link=None):
        """Return a (QLineEdit, status_dot, row_widget) for a single API key field.

        The row widget contains the input, a coloured status dot, and an
        optional clickable registration link icon.
        """
        row = QWidget()
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(6)

        field = QLineEdit()
        field.setPlaceholderText(placeholder)
        if password:
            field.setEchoMode(QLineEdit.EchoMode.Password)

        # Status dot — grey when empty, green when filled
        dot = QLabel("●")
        dot.setFixedWidth(16)
        dot.setAlignment(Qt.AlignmentFlag.AlignCenter)
        dot.setStyleSheet("color: #555555; font-size: 14px;")

        def _update_dot(text, _dot=dot):
            _dot.setStyleSheet(
                "color: #00CC66; font-size: 14px;" if text.strip()
                else "color: #555555; font-size: 14px;"
            )

        field.textChanged.connect(_update_dot)

        row_layout.addWidget(field)
        row_layout.addWidget(dot)

        if link:
            link_btn = QPushButton("🔗")
            link_btn.setFixedWidth(28)
            link_btn.setToolTip(f"Register / get API key: {link}")
            link_btn.setStyleSheet(
                "QPushButton { background: transparent; border: none; color: #64C8FF; font-size: 13px; }"
                "QPushButton:hover { color: #FFFFFF; }"
            )
            link_btn.clicked.connect(lambda _, url=link: QDesktopServices.openUrl(QUrl(url)))
            row_layout.addWidget(link_btn)

        return field, dot, row

    def _section_label(self, text):
        """Return a styled section header label for use inside a QFormLayout."""
        lbl = QLabel(text)
        lbl.setStyleSheet("font-weight: bold; color: #64C8FF; margin-top: 6px;")
        return lbl

    def _make_scrollable(self, inner_widget):
        """Wrap a widget in a QScrollArea and return the scroll area."""
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setWidget(inner_widget)
        return scroll

    def create_api_keys_tab(self):
        """Create API Keys tab with nested sub-tabs and scroll areas."""

        # ── outer container ──────────────────────────────────────────────────
        outer = QWidget()
        outer_layout = QVBoxLayout(outer)
        outer_layout.setContentsMargins(8, 8, 8, 8)
        outer_layout.setSpacing(6)

        # ── configured-key summary bar ───────────────────────────────────────
        self._api_summary_label = QLabel("0 of 0 API keys configured")
        self._api_summary_label.setStyleSheet(
            "color: #FFD93D; font-style: italic; padding: 4px 0;"
        )
        outer_layout.addWidget(self._api_summary_label)

        # ── nested tab widget ────────────────────────────────────────────────
        api_tabs = QTabWidget()
        api_tabs.setDocumentMode(True)
        outer_layout.addWidget(api_tabs)

        # ── Tab 1: Hash Cracking ─────────────────────────────────────────────
        hash_inner = QWidget()
        hash_layout = QVBoxLayout(hash_inner)
        hash_layout.setContentsMargins(12, 12, 12, 12)

        hash_group = QGroupBox("Hash Cracking APIs")
        hash_form = QFormLayout()
        hash_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        hash_form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)

        self.hashes_com_key, _, _row = self._make_api_field(
            "hashes.com API key",
            link="https://hashes.com/en/api/info"
        )
        hash_form.addRow("Hashes.com:", _row)

        self.md5decrypt_email, _, _row = self._make_api_field("Email address for MD5Decrypt")
        hash_form.addRow("MD5Decrypt Email:", _row)

        self.md5decrypt_key, _, _row = self._make_api_field(
            "MD5Decrypt API key",
            link="https://md5decrypt.net/en/Api/"
        )
        hash_form.addRow("MD5Decrypt Key:", _row)

        hash_group.setLayout(hash_form)
        hash_layout.addWidget(hash_group)
        hash_layout.addStretch()

        api_tabs.addTab(self._make_scrollable(hash_inner), "🔓 Hash Cracking")

        # ── Tab 2: OSINT & Intelligence ──────────────────────────────────────
        osint_inner = QWidget()
        osint_layout = QVBoxLayout(osint_inner)
        osint_layout.setContentsMargins(12, 12, 12, 12)

        osint_group = QGroupBox("OSINT & Intelligence APIs")
        osint_form = QFormLayout()
        osint_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        osint_form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)

        self.shodan_key, _, _row = self._make_api_field(
            "Shodan API key",
            link="https://account.shodan.io/"
        )
        osint_form.addRow("Shodan:", _row)

        self.virustotal_key, _, _row = self._make_api_field(
            "VirusTotal API key — also used for subdomain enumeration",
            link="https://www.virustotal.com/gui/join-us"
        )
        osint_form.addRow("VirusTotal:", _row)

        self.urlvoid_key, _, _row = self._make_api_field(
            "URLVoid API key",
            link="https://www.urlvoid.com/api/"
        )
        osint_form.addRow("URLVoid:", _row)

        osint_group.setLayout(osint_form)
        osint_layout.addWidget(osint_group)
        osint_layout.addStretch()

        api_tabs.addTab(self._make_scrollable(osint_inner), "🕵️ OSINT")

        # ── Tab 3: Subdomain Enumeration ─────────────────────────────────────
        sub_inner = QWidget()
        sub_layout = QVBoxLayout(sub_inner)
        sub_layout.setContentsMargins(12, 12, 12, 12)
        sub_layout.setSpacing(10)

        free_note = QLabel(
            "📝  Free sources active by default (no key needed): "
            "crt.sh · Wayback Machine · URLScan.io"
        )
        free_note.setStyleSheet("color: #00CC66; font-style: italic;")
        free_note.setWordWrap(True)
        sub_layout.addWidget(free_note)

        # Certificate Transparency
        ct_group = QGroupBox("Certificate Transparency")
        ct_form = QFormLayout()
        ct_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        ct_form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)

        self.certspotter_key, _, _row = self._make_api_field(
            "CertSpotter key  (100 req/hr free · 1 000 req/hr paid)",
            link="https://sslmate.com/certspotter/api/"
        )
        ct_form.addRow("CertSpotter:", _row)
        ct_group.setLayout(ct_form)
        sub_layout.addWidget(ct_group)

        # Search & Intelligence
        si_group = QGroupBox("Search & Intelligence")
        si_form = QFormLayout()
        si_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        si_form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)

        si_form.addRow(self._section_label("VirusTotal key is shared with the OSINT tab above"))

        self.censys_id, _, _row = self._make_api_field(
            "Censys API ID  (120 req/min free · 480 req/min paid)",
            link="https://search.censys.io/register"
        )
        si_form.addRow("Censys ID:", _row)

        self.censys_secret, _, _row = self._make_api_field(
            "Censys API Secret", password=True
        )
        si_form.addRow("Censys Secret:", _row)

        self.securitytrails_key, _, _row = self._make_api_field(
            "SecurityTrails key  (50 req/month free · 2 000 req/month paid)",
            link="https://securitytrails.com/corp/api"
        )
        si_form.addRow("SecurityTrails:", _row)

        si_group.setLayout(si_form)
        sub_layout.addWidget(si_group)

        # Threat Intelligence
        ti_group = QGroupBox("Threat Intelligence")
        ti_form = QFormLayout()
        ti_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        ti_form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)

        self.binaryedge_key, _, _row = self._make_api_field(
            "BinaryEdge key  (250 req/month free · 10 000 req/month paid)",
            link="https://app.binaryedge.io/sign-up"
        )
        ti_form.addRow("BinaryEdge:", _row)

        self.passivetotal_user, _, _row = self._make_api_field("PassiveTotal username")
        ti_form.addRow("PassiveTotal User:", _row)

        self.passivetotal_key, _, _row = self._make_api_field(
            "PassiveTotal API key  (2 000 req/month free · 10 000 req/month paid)",
            password=True,
            link="https://community.riskiq.com/registration"
        )
        ti_form.addRow("PassiveTotal Key:", _row)

        ti_group.setLayout(ti_form)
        sub_layout.addWidget(ti_group)

        # DNS Intelligence
        dns_group = QGroupBox("DNS Intelligence")
        dns_form = QFormLayout()
        dns_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        dns_form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)

        self.dnsdb_key, _, _row = self._make_api_field(
            "Farsight DNSDB key  (paid service)",
            password=True,
            link="https://www.farsightsecurity.com/dnsdb-community-edition/"
        )
        dns_form.addRow("DNSDB (Farsight):", _row)

        dns_group.setLayout(dns_form)
        sub_layout.addWidget(dns_group)
        sub_layout.addStretch()

        api_tabs.addTab(self._make_scrollable(sub_inner), "🔍 Subdomain Enum")

        # ── status summary update hook ────────────────────────────────────────
        all_key_fields = [
            self.hashes_com_key, self.md5decrypt_key,
            self.shodan_key, self.virustotal_key, self.urlvoid_key,
            self.certspotter_key, self.censys_id, self.securitytrails_key,
            self.binaryedge_key, self.passivetotal_key, self.dnsdb_key,
        ]
        total = len(all_key_fields)

        def _refresh_summary(_text=None):
            configured = sum(1 for f in all_key_fields if f.text().strip())
            self._api_summary_label.setText(
                f"{configured} of {total} API keys configured"
            )

        for _f in all_key_fields:
            _f.textChanged.connect(_refresh_summary)

        _refresh_summary()

        self.tabs.addTab(outer, "🔑 API Keys")

    
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
        """Show a summary of which API keys are currently configured."""
        configured_keys = []
        checks = [
            ("Hashes.com",     self.hashes_com_key),
            ("MD5Decrypt",     self.md5decrypt_key),
            ("Shodan",         self.shodan_key),
            ("VirusTotal",     self.virustotal_key),
            ("URLVoid",        self.urlvoid_key),
            ("CertSpotter",    self.certspotter_key),
            ("Censys",         self.censys_id),
            ("SecurityTrails", self.securitytrails_key),
            ("BinaryEdge",     self.binaryedge_key),
            ("PassiveTotal",   self.passivetotal_key),
            ("DNSDB",          self.dnsdb_key),
        ]
        for name, field in checks:
            if field.text().strip():
                configured_keys.append(name)

        if configured_keys:
            message = (
                f"Configured API Keys ({len(configured_keys)} of {len(checks)}):\n\n"
                + "\n".join(f"✅ {k}" for k in configured_keys)
                + "\n\nNote: Actual API validation requires a live network test."
            )
        else:
            message = "No API keys configured.\n\nFree sources (crt.sh, Wayback Machine) will still work."

        QMessageBox.information(self, "API Key Status", message)
    
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
