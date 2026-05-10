# app/widgets/stealth_widget.py
# NOTE: An improved version of this widget exists at
# app/widgets/stealth_widget_improved.py which has additional features.
# New code should use ImprovedStealthWidget from stealth_widget_improved.
# This file is kept for backward compatibility.
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QComboBox, QPushButton, QSpinBox, QCheckBox,
                            QGroupBox, QSlider, QLineEdit, QTextEdit, QTabWidget,
                            QSplitter, QFrame, QProgressBar, QGridLayout)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QPalette
from app.core.stealth_engine import stealth_engine
from app.core.license_manager import license_manager

class StealthWidget(QWidget):
    """Stealth mode configuration widget"""
    
    stealth_configured = pyqtSignal(dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.connect_signals()
        self.check_license()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Header
        header = QLabel("Stealth Mode Configuration")
        header.setStyleSheet("font-size: 16pt; font-weight: bold; color: #64C8FF;")
        layout.addWidget(header)
        
        # License warning
        self.license_warning = QLabel("⚠️ Stealth Mode requires Professional license")
        self.license_warning.setStyleSheet("color: #FF6B6B; font-weight: bold; padding: 10px;")
        layout.addWidget(self.license_warning)
        
        # Evasion Level
        evasion_group = QGroupBox("Evasion Level")
        evasion_layout = QVBoxLayout(evasion_group)
        
        self.evasion_combo = QComboBox()
        self.evasion_combo.addItems(["normal", "polite", "sneaky", "paranoid"])
        evasion_layout.addWidget(self.evasion_combo)
        
        # Descriptions
        descriptions = {
            "normal": "Standard timing (0.1-1s delay)",
            "polite": "Polite timing (1-3s delay)", 
            "sneaky": "Sneaky timing (2-8s delay)",
            "paranoid": "Paranoid timing (5-15s delay)"
        }
        
        self.description_label = QLabel(descriptions["normal"])
        evasion_layout.addWidget(self.description_label)
        
        layout.addWidget(evasion_group)
        
        # Decoy Configuration
        decoy_group = QGroupBox("Decoy IPs")
        decoy_layout = QVBoxLayout(decoy_group)
        
        self.enable_decoys = QCheckBox("Enable IP Decoys")
        decoy_layout.addWidget(self.enable_decoys)
        
        decoy_count_layout = QHBoxLayout()
        decoy_count_layout.addWidget(QLabel("Decoy Count:"))
        self.decoy_count = QSpinBox()
        self.decoy_count.setRange(1, 10)
        self.decoy_count.setValue(5)
        decoy_count_layout.addWidget(self.decoy_count)
        decoy_layout.addLayout(decoy_count_layout)
        
        self.decoy_input = QLineEdit()
        self.decoy_input.setPlaceholderText("Custom decoy IPs (comma-separated)")
        decoy_layout.addWidget(self.decoy_input)
        
        layout.addWidget(decoy_group)
        
        # Timing Controls
        timing_group = QGroupBox("Advanced Timing")
        timing_layout = QVBoxLayout(timing_group)
        
        # Scan delay
        delay_layout = QHBoxLayout()
        delay_layout.addWidget(QLabel("Scan Delay (ms):"))
        self.scan_delay = QSpinBox()
        self.scan_delay.setRange(0, 10000)
        self.scan_delay.setValue(1000)
        delay_layout.addWidget(self.scan_delay)
        timing_layout.addLayout(delay_layout)
        
        # Max retries
        retry_layout = QHBoxLayout()
        retry_layout.addWidget(QLabel("Max Retries:"))
        self.max_retries = QSpinBox()
        self.max_retries.setRange(1, 10)
        self.max_retries.setValue(2)
        retry_layout.addWidget(self.max_retries)
        timing_layout.addLayout(retry_layout)
        
        layout.addWidget(timing_group)
        
        # Fragmentation
        frag_group = QGroupBox("Packet Fragmentation")
        frag_layout = QVBoxLayout(frag_group)
        
        self.enable_frag = QCheckBox("Enable Packet Fragmentation")
        frag_layout.addWidget(self.enable_frag)
        
        mtu_layout = QHBoxLayout()
        mtu_layout.addWidget(QLabel("MTU Size:"))
        self.mtu_size = QSpinBox()
        self.mtu_size.setRange(8, 1500)
        self.mtu_size.setValue(24)
        mtu_layout.addWidget(self.mtu_size)
        frag_layout.addLayout(mtu_layout)
        
        layout.addWidget(frag_group)
        
        # Advanced Evasion Features
        advanced_group = QGroupBox("Advanced Evasion")
        advanced_layout = QVBoxLayout(advanced_group)
        
        # Dynamic Rate Limiting
        self.dynamic_rate = QCheckBox("Dynamic Rate Limiting")
        advanced_layout.addWidget(self.dynamic_rate)
        
        rate_layout = QHBoxLayout()
        rate_layout.addWidget(QLabel("Base Rate (req/s):"))
        self.base_rate = QSpinBox()
        self.base_rate.setRange(1, 100)
        self.base_rate.setValue(10)
        rate_layout.addWidget(self.base_rate)
        advanced_layout.addLayout(rate_layout)
        
        # Header Randomization
        self.randomize_headers = QCheckBox("Randomize User-Agent & Headers")
        advanced_layout.addWidget(self.randomize_headers)
        
        self.custom_agents = QLineEdit()
        self.custom_agents.setPlaceholderText("Custom User-Agents (comma-separated)")
        advanced_layout.addWidget(self.custom_agents)
        
        # Jitter Configuration
        self.enable_jitter = QCheckBox("Enable Request Jitter")
        advanced_layout.addWidget(self.enable_jitter)
        
        jitter_layout = QHBoxLayout()
        jitter_layout.addWidget(QLabel("Jitter Range (s):"))
        self.jitter_min = QSpinBox()
        self.jitter_min.setRange(0, 10)
        self.jitter_min.setValue(1)
        jitter_layout.addWidget(self.jitter_min)
        jitter_layout.addWidget(QLabel("to"))
        self.jitter_max = QSpinBox()
        self.jitter_max.setRange(1, 20)
        self.jitter_max.setValue(3)
        jitter_layout.addWidget(self.jitter_max)
        advanced_layout.addLayout(jitter_layout)
        
        # Proxy Rotation
        self.proxy_rotation = QCheckBox("Enable Proxy Rotation")
        advanced_layout.addWidget(self.proxy_rotation)
        
        self.proxy_list = QTextEdit()
        self.proxy_list.setMaximumHeight(60)
        self.proxy_list.setPlaceholderText("Proxy list (one per line): http://proxy:port")
        advanced_layout.addWidget(self.proxy_list)
        
        # VPN Integration
        self.vpn_rotation = QCheckBox("Enable VPN Rotation")
        advanced_layout.addWidget(self.vpn_rotation)
        
        vpn_layout = QHBoxLayout()
        self.vpn_browse = QPushButton("Browse VPN Configs")
        self.vpn_status = QLabel("No VPN configs selected")
        vpn_layout.addWidget(self.vpn_browse)
        vpn_layout.addWidget(self.vpn_status)
        advanced_layout.addLayout(vpn_layout)
        
        layout.addWidget(advanced_group)
        
        # Threat Profile Matching
        profile_group = QGroupBox("Threat Profile Matching")
        profile_layout = QVBoxLayout(profile_group)
        
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target Type:"))
        self.target_type_combo = QComboBox()
        self.target_type_combo.addItems([
            "Generic Target",
            "Cloudflare WAF", 
            "AWS CloudFront",
            "Akamai CDN",
            "IDS/IPS System"
        ])
        target_layout.addWidget(self.target_type_combo)
        profile_layout.addLayout(target_layout)
        
        # Risk Score Display
        risk_layout = QHBoxLayout()
        risk_layout.addWidget(QLabel("Detection Risk:"))
        self.risk_score_label = QLabel("50")
        self.risk_score_label.setStyleSheet("color: #FFAA00; font-weight: bold;")
        risk_layout.addWidget(self.risk_score_label)
        risk_layout.addWidget(QLabel("/100"))
        risk_layout.addStretch()
        profile_layout.addLayout(risk_layout)
        
        layout.addWidget(profile_group)
        
        # Evasion Plugins
        plugin_group = QGroupBox("Evasion Plugins")
        plugin_layout = QVBoxLayout(plugin_group)
        
        plugin_btn_layout = QHBoxLayout()
        self.load_plugins_btn = QPushButton("Load Plugins")
        self.plugin_status = QLabel("No plugins loaded")
        plugin_btn_layout.addWidget(self.load_plugins_btn)
        plugin_btn_layout.addWidget(self.plugin_status)
        plugin_layout.addLayout(plugin_btn_layout)
        
        layout.addWidget(plugin_group)
        
        # Control Buttons
        button_layout = QHBoxLayout()
        self.enable_btn = QPushButton("Enable Stealth Mode")
        self.disable_btn = QPushButton("Disable Stealth Mode")
        self.test_btn = QPushButton("Test Configuration")
        self.preview_btn = QPushButton("Traffic Preview")
        
        button_layout.addWidget(self.enable_btn)
        button_layout.addWidget(self.disable_btn)
        button_layout.addWidget(self.test_btn)
        button_layout.addWidget(self.preview_btn)
        layout.addLayout(button_layout)
        
        # Status
        self.status_text = QTextEdit()
        self.status_text.setMaximumHeight(100)
        self.status_text.setReadOnly(True)
        layout.addWidget(self.status_text)
        
    def connect_signals(self):
        self.evasion_combo.currentTextChanged.connect(self.update_description)
        self.enable_btn.clicked.connect(self.enable_stealth)
        self.disable_btn.clicked.connect(self.disable_stealth)
        self.test_btn.clicked.connect(self.test_configuration)
        self.preview_btn.clicked.connect(self.show_traffic_preview)
        self.vpn_browse.clicked.connect(self.browse_vpn_configs)
        self.target_type_combo.currentTextChanged.connect(self.update_threat_profile)
        self.load_plugins_btn.clicked.connect(self.load_evasion_plugins)
        stealth_engine.stealth_event.connect(self.handle_stealth_event)
        
        # Initialize state
        self.vpn_configs = []
        
        # Set tooltips for advanced features
        self.dynamic_rate.setToolTip("Automatically adjusts request rate based on target response")
        self.randomize_headers.setToolTip("Randomizes User-Agent and HTTP headers to avoid detection")
        self.enable_jitter.setToolTip("Adds random delays between requests to mimic human behavior")
        self.proxy_rotation.setToolTip("Rotates through proxy servers to mask source IP")
        self.vpn_rotation.setToolTip("Integrates with VPN Manager for IP address rotation")
        self.target_type_combo.setToolTip("Auto-tune stealth settings for specific target types")
        
        # Load plugins on startup
        self.load_evasion_plugins()
        
        # Update initial risk score
        self.update_risk_score()
        
    def check_license(self):
        if license_manager.is_feature_enabled('stealth_mode'):
            self.license_warning.hide()
            self.setEnabled(True)
        else:
            self.license_warning.show()
            self.setEnabled(False)
            
    def update_description(self, level):
        descriptions = {
            "normal": "Standard timing (0.1-1s delay) - Fast but detectable",
            "polite": "Polite timing (1-3s delay) - Balanced approach", 
            "sneaky": "Sneaky timing (2-8s delay) - Slower but stealthier",
            "paranoid": "Paranoid timing (5-15s delay) - Maximum stealth"
        }
        self.description_label.setText(descriptions.get(level, ""))
        
    def enable_stealth(self):
        if not license_manager.is_feature_enabled('stealth_mode'):
            self.status_text.append("❌ Stealth Mode requires Professional license")
            return
            
        config = self.get_configuration()
        stealth_engine.enable_stealth_mode(config['evasion_level'])
        
        # Configure decoys
        if config['enable_decoys']:
            if config['custom_decoys']:
                stealth_engine.decoy_ips = config['custom_decoys'].split(',')
            else:
                stealth_engine.generate_decoy_ips("192.168.1.1", config['decoy_count'])
        
        # Configure advanced features
        stealth_engine.configure_dynamic_rate(
            config['dynamic_rate'], 
            config['base_rate']
        )
        
        custom_agents = [ua.strip() for ua in config['custom_agents'].split(',') if ua.strip()]
        stealth_engine.configure_header_randomization(
            config['randomize_headers'],
            custom_agents
        )
        
        stealth_engine.configure_jitter(
            config['enable_jitter'],
            (config['jitter_min'], config['jitter_max'])
        )
        
        proxy_list = [p.strip() for p in config['proxy_list'].split('\n') if p.strip()]
        stealth_engine.configure_proxy_rotation(
            config['proxy_rotation'],
            proxy_list
        )
        
        if config['vpn_rotation'] and self.vpn_configs:
            stealth_engine.integrate_vpn_rotation(self.vpn_configs)
        
        # Update risk score
        self.update_risk_score()
                
        self.status_text.append("✅ Advanced Stealth Mode enabled")
        self.stealth_configured.emit(config)
        
    def disable_stealth(self):
        stealth_engine.stealth_enabled = False
        stealth_engine.decoy_ips = []
        self.status_text.append("🔓 Stealth Mode disabled")
        
    def test_configuration(self):
        config = self.get_configuration()
        self.status_text.append(f"🧪 Testing configuration: {config['evasion_level']} level")
        
        # Test timing with jitter
        delay = stealth_engine.get_timing_delay(config['evasion_level'])
        self.status_text.append(f"⏱️ Base timing delay: {delay:.2f}s")
        
        # Test decoys
        if config['enable_decoys']:
            self.status_text.append(f"🎭 Decoys: {config['decoy_count']} IPs")
        
        # Test dynamic rate limiting
        if config['dynamic_rate']:
            self.status_text.append(f"⚡ Dynamic rate: {config['base_rate']} req/s (adaptive)")
        
        # Test header randomization
        if config['randomize_headers']:
            headers = stealth_engine.get_random_headers()
            ua = headers.get('User-Agent', 'N/A')[:50] + '...'
            self.status_text.append(f"🎭 Random User-Agent: {ua}")
        
        # Test jitter
        if config['enable_jitter']:
            self.status_text.append(f"🌲 Jitter range: {config['jitter_min']}-{config['jitter_max']}s")
        
        # Test proxy rotation
        if config['proxy_rotation'] and config['proxy_list']:
            proxy_count = len([p for p in config['proxy_list'].split('\n') if p.strip()])
            self.status_text.append(f"🔄 Proxy pool: {proxy_count} proxies")
        
        # Test VPN integration
        if config['vpn_rotation'] and self.vpn_configs:
            self.status_text.append(f"🔐 VPN rotation: {len(self.vpn_configs)} configs")
        
        self.status_text.append("✅ Configuration test completed")
        
        # Update risk score after test
        self.update_risk_score()
            
    def get_configuration(self):
        return {
            'evasion_level': self.evasion_combo.currentText(),
            'enable_decoys': self.enable_decoys.isChecked(),
            'decoy_count': self.decoy_count.value(),
            'custom_decoys': self.decoy_input.text().strip(),
            'scan_delay': self.scan_delay.value(),
            'max_retries': self.max_retries.value(),
            'enable_fragmentation': self.enable_frag.isChecked(),
            'mtu_size': self.mtu_size.value(),
            'dynamic_rate': self.dynamic_rate.isChecked(),
            'base_rate': self.base_rate.value(),
            'randomize_headers': self.randomize_headers.isChecked(),
            'custom_agents': self.custom_agents.text().strip(),
            'enable_jitter': self.enable_jitter.isChecked(),
            'jitter_min': self.jitter_min.value(),
            'jitter_max': self.jitter_max.value(),
            'proxy_rotation': self.proxy_rotation.isChecked(),
            'proxy_list': self.proxy_list.toPlainText().strip(),
            'vpn_rotation': self.vpn_rotation.isChecked(),
            'target_type': self.target_type_combo.currentText()
        }
        
    def browse_vpn_configs(self):
        from PyQt6.QtWidgets import QFileDialog
        files, _ = QFileDialog.getOpenFileNames(
            self, "Select VPN Config Files", "", "OpenVPN Files (*.ovpn);;All Files (*)"
        )
        if files:
            self.vpn_configs = files
            self.vpn_status.setText(f"{len(files)} VPN configs selected")
    
    def update_threat_profile(self, target_type: str):
        """Update threat profile based on target type"""
        profile_map = {
            "Generic Target": "generic",
            "Cloudflare WAF": "cloudflare_waf",
            "AWS CloudFront": "aws_cloudfront", 
            "Akamai CDN": "akamai_cdn",
            "IDS/IPS System": "ids_ips"
        }
        
        profile_key = profile_map.get(target_type, "generic")
        stealth_engine.apply_threat_profile(profile_key)
        
        # Update UI based on profile
        if profile_key in stealth_engine.threat_profiles:
            profile = stealth_engine.threat_profiles[profile_key]
            self.base_rate.setValue(profile.get('rate', 10))
            self.enable_jitter.setChecked(profile.get('jitter', True))
            self.randomize_headers.setChecked(profile.get('headers', True))
        
        self.update_risk_score()
        self.status_text.append(f"🎯 Applied {target_type} threat profile")
    
    def update_risk_score(self):
        """Update detection risk score display"""
        score = stealth_engine.calculate_risk_score()
        self.risk_score_label.setText(str(score))
        
        # Color code the risk score
        if score < 30:
            color = "#00FF41"  # Green - Low risk
        elif score < 70:
            color = "#FFAA00"  # Orange - Medium risk
        else:
            color = "#FF6B6B"  # Red - High risk
        
        self.risk_score_label.setStyleSheet(f"color: {color}; font-weight: bold;")
    
    def show_traffic_preview(self):
        """Show traffic signature preview dialog"""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QTextEdit, QPushButton
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Traffic Signature Preview")
        dialog.setModal(True)
        dialog.resize(600, 400)
        
        layout = QVBoxLayout(dialog)
        
        preview_text = QTextEdit()
        preview_text.setReadOnly(True)
        preview_text.setStyleSheet("font-family: 'Courier New', monospace;")
        
        # Get traffic preview from stealth engine
        preview_data = stealth_engine.get_traffic_preview()
        
        preview_content = f"""TRAFFIC SIGNATURE PREVIEW
{'='*50}

User-Agent: {preview_data['user_agent']}

DNS Resolver: {preview_data['dns_resolver']}

TLS Fingerprint: {preview_data['tls_fingerprint']}

Rate Limiting: {preview_data['rate_limit']}

Jitter Range: {preview_data['jitter_range']}

Proxy Pool: {preview_data['proxy_count']} proxies

Detection Risk Score: {preview_data['risk_score']}/100

HTTP HEADERS:
{'-'*20}
"""
        
        for key, value in preview_data['headers'].items():
            preview_content += f"{key}: {value}\n"
        
        preview_text.setPlainText(preview_content)
        layout.addWidget(preview_text)
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.close)
        layout.addWidget(close_btn)
        
        dialog.exec()
    
    def load_evasion_plugins(self):
        """Load evasion plugins from plugins directory"""
        import os
        
        plugins_dir = os.path.join(os.path.dirname(__file__), "..", "..", "plugins", "evasion")
        
        # Create plugins directory if it doesn't exist
        os.makedirs(plugins_dir, exist_ok=True)
        
        # Load plugins
        stealth_engine.load_evasion_plugins(plugins_dir)
        
        # Update status
        plugin_count = len(stealth_engine.evasion_plugins)
        if plugin_count > 0:
            self.plugin_status.setText(f"{plugin_count} plugins loaded")
            self.plugin_status.setStyleSheet("color: #00FF41;")
        else:
            self.plugin_status.setText("No plugins found")
            self.plugin_status.setStyleSheet("color: #FFAA00;")
    
    def handle_stealth_event(self, event_type, message):
        icons = {
            'stealth_enabled': '🛡️',
            'rate_adjusted': '⚡',
            'vpn_rotated': '🔄',
            'vpn_error': '❌',
            'plugin_loaded': '🔌',
            'plugin_error': '⚠️'
        }
        icon = icons.get(event_type, '📡')
        self.status_text.append(f"{icon} {message}")
        
        # Update risk score when configuration changes
        if event_type in ['rate_adjusted', 'plugin_loaded']:
            self.update_risk_score()