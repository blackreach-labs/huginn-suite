"""Global Settings page"""

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, 
                            QFormLayout, QLineEdit, QPushButton, QLabel, 
                            QSpinBox, QCheckBox, QGroupBox, QMessageBox)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from shared.configuration.global_settings import global_settings

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
        
        # OSINT APIs
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
        
        layout.addStretch()
        tab.setLayout(layout)
        self.tabs.addTab(tab, "API Keys")
    
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
        # API Keys
        self.hashes_com_key.setText(global_settings.get("api_keys.hashes_com", ""))
        self.md5decrypt_email.setText(global_settings.get("api_keys.md5decrypt_email", ""))
        self.md5decrypt_key.setText(global_settings.get("api_keys.md5decrypt_key", ""))
        self.shodan_key.setText(global_settings.get("api_keys.shodan", ""))
        self.virustotal_key.setText(global_settings.get("api_keys.virustotal", ""))
        self.urlvoid_key.setText(global_settings.get("api_keys.urlvoid", ""))
        
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
        # API Keys
        global_settings.set("api_keys.hashes_com", self.hashes_com_key.text())
        global_settings.set("api_keys.md5decrypt_email", self.md5decrypt_email.text())
        global_settings.set("api_keys.md5decrypt_key", self.md5decrypt_key.text())
        global_settings.set("api_keys.shodan", self.shodan_key.text())
        global_settings.set("api_keys.virustotal", self.virustotal_key.text())
        global_settings.set("api_keys.urlvoid", self.urlvoid_key.text())
        
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