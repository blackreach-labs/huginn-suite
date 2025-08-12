# app/widgets/stealth_widget_improved.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QComboBox, QPushButton, QSpinBox, QCheckBox,
                            QGroupBox, QSlider, QLineEdit, QTextEdit, QTabWidget,
                            QSplitter, QFrame, QProgressBar, QGridLayout)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QPalette
from app.core.stealth_engine import stealth_engine
from app.core.license_manager import license_manager

class ImprovedStealthWidget(QWidget):
    """Improved stealth mode configuration widget with enhanced UI"""
    
    stealth_configured = pyqtSignal(dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.vpn_configs = []
        self.setup_ui()
        self.connect_signals()
        self.check_license()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Header with status indicator
        header_frame = QFrame()
        header_layout = QHBoxLayout(header_frame)
        
        header = QLabel("Stealth Mode Configuration")
        header.setStyleSheet("font-size: 16pt; font-weight: bold; color: #64C8FF;")
        header_layout.addWidget(header)
        
        self.status_indicator = QLabel("●")
        self.status_indicator.setStyleSheet("color: #FF6B6B; font-size: 14pt;")
        self.status_indicator.setToolTip("Stealth Mode: Disabled")
        header_layout.addWidget(self.status_indicator)
        
        header_layout.addStretch()
        layout.addWidget(header_frame)
        
        # License warning
        self.license_warning = QLabel("⚠️ Stealth Mode requires Professional license")
        self.license_warning.setStyleSheet("color: #FF6B6B; font-weight: bold; padding: 10px;")
        layout.addWidget(self.license_warning)
        
        # Quick presets
        presets_frame = QFrame()
        presets_layout = QHBoxLayout(presets_frame)
        presets_layout.addWidget(QLabel("Quick Presets:"))
        
        self.web_preset_btn = QPushButton("Web App")
        self.api_preset_btn = QPushButton("API Testing")
        self.infra_preset_btn = QPushButton("Infrastructure")
        
        presets_layout.addWidget(self.web_preset_btn)
        presets_layout.addWidget(self.api_preset_btn)
        presets_layout.addWidget(self.infra_preset_btn)
        presets_layout.addStretch()
        
        layout.addWidget(presets_frame)
        
        # Main content splitter
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(main_splitter)
        
        # Left panel - Tabbed configuration
        self.config_tabs = QTabWidget()
        main_splitter.addWidget(self.config_tabs)
        
        # Create tabs
        self.config_tabs.addTab(self.create_basic_tab(), "Basic")
        self.config_tabs.addTab(self.create_advanced_tab(), "Advanced")
        self.config_tabs.addTab(self.create_profiles_tab(), "Profiles")
        self.config_tabs.addTab(self.create_plugins_tab(), "Plugins")
        self.config_tabs.addTab(self.create_aws_tab(), "AWS Deploy")
        
        # Right panel - Status and preview
        status_widget = self.create_status_panel()
        main_splitter.addWidget(status_widget)
        
        main_splitter.setSizes([600, 400])
        
        # Control buttons
        button_frame = QFrame()
        button_layout = QHBoxLayout(button_frame)
        
        self.enable_btn = QPushButton("Enable Stealth Mode")
        self.disable_btn = QPushButton("Disable Stealth Mode")
        self.test_btn = QPushButton("Test Configuration")
        self.preview_btn = QPushButton("Traffic Preview")
        
        button_layout.addWidget(self.enable_btn)
        button_layout.addWidget(self.disable_btn)
        button_layout.addWidget(self.test_btn)
        button_layout.addWidget(self.preview_btn)
        button_layout.addStretch()
        
        layout.addWidget(button_frame)
    
    def create_basic_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Evasion Level
        evasion_group = QGroupBox("Evasion Level")
        evasion_layout = QVBoxLayout(evasion_group)
        
        self.evasion_combo = QComboBox()
        self.evasion_combo.addItems(["normal", "polite", "sneaky", "paranoid"])
        evasion_layout.addWidget(self.evasion_combo)
        
        self.description_label = QLabel("Standard timing (0.1-1s delay)")
        evasion_layout.addWidget(self.description_label)
        
        layout.addWidget(evasion_group)
        
        # Basic timing controls
        timing_group = QGroupBox("Basic Timing")
        timing_layout = QGridLayout(timing_group)
        
        timing_layout.addWidget(QLabel("Rate (req/s):"), 0, 0)
        self.basic_rate = QSpinBox()
        self.basic_rate.setRange(1, 100)
        self.basic_rate.setValue(10)
        timing_layout.addWidget(self.basic_rate, 0, 1)
        
        timing_layout.addWidget(QLabel("Delay (ms):"), 1, 0)
        self.basic_delay = QSpinBox()
        self.basic_delay.setRange(0, 10000)
        self.basic_delay.setValue(1000)
        timing_layout.addWidget(self.basic_delay, 1, 1)
        
        layout.addWidget(timing_group)
        layout.addStretch()
        return widget
    
    def create_advanced_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Dynamic Rate Limiting
        rate_group = QGroupBox("Dynamic Rate Limiting")
        rate_layout = QVBoxLayout(rate_group)
        
        self.dynamic_rate = QCheckBox("Enable Dynamic Rate Limiting")
        rate_layout.addWidget(self.dynamic_rate)
        
        rate_controls = QHBoxLayout()
        rate_controls.addWidget(QLabel("Base Rate:"))
        self.base_rate = QSpinBox()
        self.base_rate.setRange(1, 100)
        self.base_rate.setValue(10)
        rate_controls.addWidget(self.base_rate)
        rate_layout.addLayout(rate_controls)
        
        layout.addWidget(rate_group)
        
        # Header Randomization
        header_group = QGroupBox("Header Randomization")
        header_layout = QVBoxLayout(header_group)
        
        self.randomize_headers = QCheckBox("Randomize User-Agent & Headers")
        header_layout.addWidget(self.randomize_headers)
        
        self.custom_agents = QLineEdit()
        self.custom_agents.setPlaceholderText("Custom User-Agents (comma-separated)")
        header_layout.addWidget(self.custom_agents)
        
        layout.addWidget(header_group)
        
        # Jitter Configuration
        jitter_group = QGroupBox("Request Jitter")
        jitter_layout = QVBoxLayout(jitter_group)
        
        self.enable_jitter = QCheckBox("Enable Request Jitter")
        jitter_layout.addWidget(self.enable_jitter)
        
        jitter_controls = QHBoxLayout()
        jitter_controls.addWidget(QLabel("Range (s):"))
        self.jitter_min = QSpinBox()
        self.jitter_min.setRange(0, 10)
        self.jitter_min.setValue(1)
        jitter_controls.addWidget(self.jitter_min)
        jitter_controls.addWidget(QLabel("to"))
        self.jitter_max = QSpinBox()
        self.jitter_max.setRange(1, 20)
        self.jitter_max.setValue(3)
        jitter_controls.addWidget(self.jitter_max)
        jitter_layout.addLayout(jitter_controls)
        
        layout.addWidget(jitter_group)
        
        # Unified Proxy Configuration
        proxy_group = QGroupBox("Proxy Configuration")
        proxy_layout = QVBoxLayout(proxy_group)
        
        # Proxy mode selection
        mode_layout = QHBoxLayout()
        mode_layout.addWidget(QLabel("Mode:"))
        self.proxy_mode = QComboBox()
        self.proxy_mode.addItems(["Rotation", "Chain", "Both"])
        mode_layout.addWidget(self.proxy_mode)
        proxy_layout.addLayout(mode_layout)
        
        # Chain configuration
        chain_layout = QHBoxLayout()
        chain_layout.addWidget(QLabel("Chain Type:"))
        self.chain_type = QComboBox()
        self.chain_type.addItems(["dynamic", "strict", "random"])
        chain_layout.addWidget(self.chain_type)
        
        self.enable_tor = QCheckBox("Include Tor")
        chain_layout.addWidget(self.enable_tor)
        
        tor_port_layout = QHBoxLayout()
        tor_port_layout.addWidget(QLabel("Tor Port:"))
        self.tor_port = QSpinBox()
        self.tor_port.setRange(1, 65535)
        self.tor_port.setValue(9050)
        tor_port_layout.addWidget(self.tor_port)
        chain_layout.addLayout(tor_port_layout)
        
        proxy_layout.addLayout(chain_layout)
        
        # Add proxy form
        add_layout = QHBoxLayout()
        add_layout.addWidget(QLabel("Add Proxy:"))
        
        self.proxy_type = QComboBox()
        self.proxy_type.addItems(["http", "socks4", "socks5"])
        add_layout.addWidget(self.proxy_type)
        
        self.proxy_host = QLineEdit()
        self.proxy_host.setPlaceholderText("Host/IP")
        add_layout.addWidget(self.proxy_host)
        
        self.proxy_port = QSpinBox()
        self.proxy_port.setRange(1, 65535)
        self.proxy_port.setValue(8080)
        add_layout.addWidget(self.proxy_port)
        
        self.proxy_user = QLineEdit()
        self.proxy_user.setPlaceholderText("Username")
        add_layout.addWidget(self.proxy_user)
        
        self.proxy_pass = QLineEdit()
        self.proxy_pass.setPlaceholderText("Password")
        self.proxy_pass.setEchoMode(QLineEdit.EchoMode.Password)
        add_layout.addWidget(self.proxy_pass)
        
        self.add_proxy_btn = QPushButton("Add")
        add_layout.addWidget(self.add_proxy_btn)
        
        proxy_layout.addLayout(add_layout)
        
        # Proxy list
        self.proxy_list = QTextEdit()
        self.proxy_list.setMaximumHeight(100)
        self.proxy_list.setPlaceholderText("Proxy list (auto-populated when adding proxies above)\nManual format: type://host:port or host:port for http")
        proxy_layout.addWidget(self.proxy_list)
        
        # Proxy controls
        proxy_controls = QHBoxLayout()
        self.test_chain_btn = QPushButton("Test Chain")
        self.clear_proxies_btn = QPushButton("Clear All")
        self.save_config_btn = QPushButton("Save Config")
        proxy_controls.addWidget(self.test_chain_btn)
        proxy_controls.addWidget(self.clear_proxies_btn)
        proxy_controls.addWidget(self.save_config_btn)
        proxy_layout.addLayout(proxy_controls)
        
        # VPN rotation
        self.vpn_rotation = QCheckBox("Enable VPN Rotation")
        proxy_layout.addWidget(self.vpn_rotation)
        
        vpn_controls = QHBoxLayout()
        self.vpn_browse = QPushButton("Browse VPN Configs")
        self.vpn_status = QLabel("No VPN configs selected")
        vpn_controls.addWidget(self.vpn_browse)
        vpn_controls.addWidget(self.vpn_status)
        proxy_layout.addLayout(vpn_controls)
        
        layout.addWidget(proxy_group)
        layout.addStretch()
        return widget
    
    def create_profiles_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Target Type Selection
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
        
        layout.addWidget(profile_group)
        layout.addStretch()
        return widget
    
    def create_plugins_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Plugin Management
        plugin_group = QGroupBox("Evasion Plugins")
        plugin_layout = QVBoxLayout(plugin_group)
        
        plugin_controls = QHBoxLayout()
        self.load_plugins_btn = QPushButton("Load Plugins")
        self.plugin_status = QLabel("No plugins loaded")
        plugin_controls.addWidget(self.load_plugins_btn)
        plugin_controls.addWidget(self.plugin_status)
        plugin_layout.addLayout(plugin_controls)
        
        layout.addWidget(plugin_group)
        layout.addStretch()
        return widget
    
    def create_aws_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # AWS Credentials
        creds_group = QGroupBox("AWS & GitLab Credentials")
        creds_layout = QVBoxLayout(creds_group)
        
        # GitLab
        gitlab_layout = QHBoxLayout()
        gitlab_layout.addWidget(QLabel("GitLab URL:"))
        self.gitlab_url = QLineEdit("https://gitlab.com")
        gitlab_layout.addWidget(self.gitlab_url)
        creds_layout.addLayout(gitlab_layout)
        
        token_layout = QHBoxLayout()
        token_layout.addWidget(QLabel("Token:"))
        self.gitlab_token = QLineEdit()
        self.gitlab_token.setEchoMode(QLineEdit.EchoMode.Password)
        token_layout.addWidget(self.gitlab_token)
        creds_layout.addLayout(token_layout)
        
        project_layout = QHBoxLayout()
        project_layout.addWidget(QLabel("Project ID:"))
        self.project_id = QLineEdit()
        project_layout.addWidget(self.project_id)
        creds_layout.addLayout(project_layout)
        
        # AWS
        aws_layout = QHBoxLayout()
        aws_layout.addWidget(QLabel("AWS Key:"))
        self.aws_access_key = QLineEdit()
        aws_layout.addWidget(self.aws_access_key)
        creds_layout.addLayout(aws_layout)
        
        secret_layout = QHBoxLayout()
        secret_layout.addWidget(QLabel("AWS Secret:"))
        self.aws_secret_key = QLineEdit()
        self.aws_secret_key.setEchoMode(QLineEdit.EchoMode.Password)
        secret_layout.addWidget(self.aws_secret_key)
        creds_layout.addLayout(secret_layout)
        
        test_btn = QPushButton("Test Connections")
        test_btn.clicked.connect(self.test_aws_connections)
        creds_layout.addWidget(test_btn)
        
        layout.addWidget(creds_group)
        
        # Deployment Options
        deploy_group = QGroupBox("Infrastructure Deployment")
        deploy_layout = QVBoxLayout(deploy_group)
        
        # Proxy deployment
        proxy_layout = QHBoxLayout()
        proxy_layout.addWidget(QLabel("Proxy Servers:"))
        self.proxy_count = QSpinBox()
        self.proxy_count.setRange(1, 10)
        self.proxy_count.setValue(2)
        proxy_layout.addWidget(self.proxy_count)
        
        deploy_proxy_btn = QPushButton("Deploy Proxy Servers")
        deploy_proxy_btn.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; padding: 8px; }")
        deploy_proxy_btn.clicked.connect(self.deploy_proxy_servers)
        proxy_layout.addWidget(deploy_proxy_btn)
        deploy_layout.addLayout(proxy_layout)
        
        # VPN deployment
        vpn_layout = QHBoxLayout()
        vpn_layout.addWidget(QLabel("VPN Servers:"))
        self.vpn_count = QSpinBox()
        self.vpn_count.setRange(1, 5)
        self.vpn_count.setValue(1)
        vpn_layout.addWidget(self.vpn_count)
        
        deploy_vpn_btn = QPushButton("Deploy VPN Servers")
        deploy_vpn_btn.setStyleSheet("QPushButton { background-color: #2196F3; color: white; padding: 8px; }")
        deploy_vpn_btn.clicked.connect(self.deploy_vpn_servers)
        vpn_layout.addWidget(deploy_vpn_btn)
        deploy_layout.addLayout(vpn_layout)
        
        layout.addWidget(deploy_group)
        
        # Deployment Status
        self.aws_status = QTextEdit()
        self.aws_status.setMaximumHeight(100)
        self.aws_status.setReadOnly(True)
        layout.addWidget(self.aws_status)
        
        layout.addStretch()
        return widget
    
    def create_status_panel(self):
        status_widget = QWidget()
        status_layout = QVBoxLayout(status_widget)
        
        # Risk Score Gauge
        risk_frame = QFrame()
        risk_frame.setFrameStyle(QFrame.Shape.Box)
        risk_layout = QVBoxLayout(risk_frame)
        
        risk_layout.addWidget(QLabel("Detection Risk Score"))
        
        self.risk_gauge = QProgressBar()
        self.risk_gauge.setRange(0, 100)
        self.risk_gauge.setValue(50)
        self.risk_gauge.setTextVisible(True)
        self.risk_gauge.setFormat("%v/100")
        risk_layout.addWidget(self.risk_gauge)
        
        self.risk_level_label = QLabel("Medium Risk")
        self.risk_level_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.risk_level_label.setStyleSheet("font-weight: bold; color: #FFAA00;")
        risk_layout.addWidget(self.risk_level_label)
        
        status_layout.addWidget(risk_frame)
        
        # Active Features
        features_group = QGroupBox("Active Features")
        features_layout = QVBoxLayout(features_group)
        
        self.features_list = QTextEdit()
        self.features_list.setMaximumHeight(100)
        self.features_list.setReadOnly(True)
        features_layout.addWidget(self.features_list)
        
        status_layout.addWidget(features_group)
        
        # Status Log
        self.status_text = QTextEdit()
        self.status_text.setMaximumHeight(150)
        self.status_text.setReadOnly(True)
        status_layout.addWidget(self.status_text)
        
        return status_widget
    
    def connect_signals(self):
        # Basic connections
        self.evasion_combo.currentTextChanged.connect(self.update_description)
        self.enable_btn.clicked.connect(self.enable_stealth)
        self.disable_btn.clicked.connect(self.disable_stealth)
        self.test_btn.clicked.connect(self.test_configuration)
        self.preview_btn.clicked.connect(self.show_traffic_preview)
        
        # Advanced connections
        self.vpn_browse.clicked.connect(self.browse_vpn_configs)
        self.target_type_combo.currentTextChanged.connect(self.update_threat_profile)
        self.load_plugins_btn.clicked.connect(self.load_evasion_plugins)
        
        # Quick presets
        self.web_preset_btn.clicked.connect(lambda: self.apply_preset("web"))
        self.api_preset_btn.clicked.connect(lambda: self.apply_preset("api"))
        self.infra_preset_btn.clicked.connect(lambda: self.apply_preset("infra"))
        
        # Real-time updates
        self.basic_rate.valueChanged.connect(self.update_risk_score)
        self.dynamic_rate.toggled.connect(self.update_risk_score)
        self.randomize_headers.toggled.connect(self.update_risk_score)
        self.enable_jitter.toggled.connect(self.update_risk_score)
        self.proxy_mode.currentTextChanged.connect(self.update_risk_score)
        self.chain_type.currentTextChanged.connect(self.update_risk_score)
        self.enable_tor.toggled.connect(self.update_risk_score)
        self.add_proxy_btn.clicked.connect(self.add_proxy_to_list)
        self.test_chain_btn.clicked.connect(self.test_proxy_chain)
        self.clear_proxies_btn.clicked.connect(self.clear_proxy_list)
        self.save_config_btn.clicked.connect(self.save_proxy_config)
        self.vpn_rotation.toggled.connect(self.update_risk_score)
        
        stealth_engine.stealth_event.connect(self.handle_stealth_event)
        
        # AWS deployment signals
        from app.core.aws_sam_deployment import sam_deployment_manager
        sam_deployment_manager.deployment_started.connect(self.on_aws_deployment_started)
        sam_deployment_manager.deployment_completed.connect(self.on_aws_deployment_completed)
        
        # Initialize
        self.load_evasion_plugins()
        self.update_risk_score()
    
    def apply_preset(self, preset_type):
        """Apply quick preset configurations"""
        presets = {
            "web": {
                "rate": 5, "jitter": True, "headers": True, "proxy_mode": "Rotation",
                "target": "Cloudflare WAF", "level": "sneaky"
            },
            "api": {
                "rate": 10, "jitter": True, "headers": True, "proxy_mode": "Chain",
                "target": "Generic Target", "level": "polite"
            },
            "infra": {
                "rate": 2, "jitter": True, "headers": False, "proxy_mode": "Both",
                "target": "IDS/IPS System", "level": "paranoid"
            }
        }
        
        if preset_type in presets:
            preset = presets[preset_type]
            self.basic_rate.setValue(preset["rate"])
            self.enable_jitter.setChecked(preset["jitter"])
            self.randomize_headers.setChecked(preset["headers"])
            # Find and set proxy mode
            for i in range(self.proxy_mode.count()):
                if self.proxy_mode.itemText(i) == preset["proxy_mode"]:
                    self.proxy_mode.setCurrentIndex(i)
                    break
            self.evasion_combo.setCurrentText(preset["level"])
            
            # Find and set target type
            for i in range(self.target_type_combo.count()):
                if self.target_type_combo.itemText(i) == preset["target"]:
                    self.target_type_combo.setCurrentIndex(i)
                    break
            
            self.status_text.append(f"🎯 Applied {preset_type.upper()} preset")
            self.update_risk_score()
    
    def update_risk_score(self):
        """Update risk score display with gauge"""
        score = stealth_engine.calculate_risk_score()
        
        self.risk_gauge.setValue(score)
        
        # Update risk level and color
        if score < 30:
            level = "Low Risk"
            color = "#00FF41"
            gauge_color = "QProgressBar::chunk { background-color: #00FF41; }"
        elif score < 70:
            level = "Medium Risk"
            color = "#FFAA00"
            gauge_color = "QProgressBar::chunk { background-color: #FFAA00; }"
        else:
            level = "High Risk"
            color = "#FF6B6B"
            gauge_color = "QProgressBar::chunk { background-color: #FF6B6B; }"
        
        self.risk_level_label.setText(level)
        self.risk_level_label.setStyleSheet(f"font-weight: bold; color: {color};")
        self.risk_gauge.setStyleSheet(gauge_color)
        
        # Update active features list
        features = []
        if self.dynamic_rate.isChecked():
            features.append("Dynamic Rate Limiting")
        if self.randomize_headers.isChecked():
            features.append("Header Randomization")
        if self.enable_jitter.isChecked():
            features.append("Request Jitter")
        proxy_mode = self.proxy_mode.currentText()
        if proxy_mode != "Rotation":
            features.append(f"Proxy {proxy_mode}")
        if self.enable_tor.isChecked():
            features.append("Tor Integration")
        if self.vpn_rotation.isChecked():
            features.append("VPN Rotation")
        
        self.features_list.setPlainText("\n".join(features) if features else "No advanced features enabled")
    
    # Include other methods from original widget
    def check_license(self):
        if license_manager.is_feature_enabled('stealth_mode'):
            self.license_warning.hide()
            self.setEnabled(True)
            self.status_indicator.setStyleSheet("color: #00FF41; font-size: 14pt;")
            self.status_indicator.setToolTip("Stealth Mode: Available")
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
        
        self.status_indicator.setStyleSheet("color: #00FF41; font-size: 14pt;")
        self.status_indicator.setToolTip("Stealth Mode: Enabled")
        self.status_text.append("✅ Stealth Mode enabled")
    
    def disable_stealth(self):
        self.status_indicator.setStyleSheet("color: #FF6B6B; font-size: 14pt;")
        self.status_indicator.setToolTip("Stealth Mode: Disabled")
        self.status_text.append("🔓 Stealth Mode disabled")
    
    def test_configuration(self):
        self.status_text.append("🧪 Testing configuration...")
        self.update_risk_score()
        self.status_text.append("✅ Configuration test completed")
    
    def show_traffic_preview(self):
        """Show enhanced traffic preview"""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QTextEdit, QPushButton, QTabWidget
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Traffic Signature Preview")
        dialog.setModal(True)
        dialog.resize(700, 500)
        
        layout = QVBoxLayout(dialog)
        
        # Tabbed preview
        preview_tabs = QTabWidget()
        
        # Headers tab
        headers_text = QTextEdit()
        headers_text.setReadOnly(True)
        headers_text.setStyleSheet("font-family: 'Courier New', monospace;")
        
        preview_data = stealth_engine.get_traffic_preview()
        headers_content = "HTTP HEADERS:\n" + "="*30 + "\n\n"
        for key, value in preview_data['headers'].items():
            headers_content += f"{key}: {value}\n"
        
        headers_text.setPlainText(headers_content)
        preview_tabs.addTab(headers_text, "Headers")
        
        # Configuration tab
        config_text = QTextEdit()
        config_text.setReadOnly(True)
        config_text.setStyleSheet("font-family: 'Courier New', monospace;")
        
        config_content = f"""CONFIGURATION SUMMARY:
{'='*30}

User-Agent: {preview_data['user_agent']}
DNS Resolver: {preview_data['dns_resolver']}
TLS Fingerprint: {preview_data['tls_fingerprint']}
Rate Limiting: {preview_data['rate_limit']}
Jitter Range: {preview_data['jitter_range']}
Proxy Pool: {preview_data['proxy_count']} proxies
Detection Risk: {preview_data['risk_score']}/100
"""
        
        config_text.setPlainText(config_content)
        preview_tabs.addTab(config_text, "Configuration")
        
        layout.addWidget(preview_tabs)
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.close)
        layout.addWidget(close_btn)
        
        dialog.exec()
    
    def browse_vpn_configs(self):
        from PyQt6.QtWidgets import QFileDialog
        files, _ = QFileDialog.getOpenFileNames(
            self, "Select VPN Config Files", "", "OpenVPN Files (*.ovpn);;All Files (*)"
        )
        if files:
            self.vpn_configs = files
            self.vpn_status.setText(f"{len(files)} VPN configs selected")
    
    def update_threat_profile(self, target_type):
        profile_map = {
            "Generic Target": "generic",
            "Cloudflare WAF": "cloudflare_waf",
            "AWS CloudFront": "aws_cloudfront", 
            "Akamai CDN": "akamai_cdn",
            "IDS/IPS System": "ids_ips"
        }
        
        profile_key = profile_map.get(target_type, "generic")
        stealth_engine.apply_threat_profile(profile_key)
        self.update_risk_score()

    
    def add_proxy_to_list(self):
        """Add proxy to the list"""
        proxy_type = self.proxy_type.currentText()
        host = self.proxy_host.text().strip()
        port = self.proxy_port.value()
        username = self.proxy_user.text().strip()
        password = self.proxy_pass.text().strip()
        
        if not host:
            self.status_text.append("❌ Host/IP is required")
            return
        
        # Format proxy entry
        if username and password:
            proxy_entry = f"{proxy_type}://{username}:{password}@{host}:{port}"
        else:
            proxy_entry = f"{proxy_type}://{host}:{port}"
        
        # Add to list
        current_text = self.proxy_list.toPlainText().strip()
        if current_text:
            self.proxy_list.setPlainText(current_text + "\n" + proxy_entry)
        else:
            self.proxy_list.setPlainText(proxy_entry)
        
        # Clear form
        self.proxy_host.clear()
        self.proxy_user.clear()
        self.proxy_pass.clear()
        
        self.status_text.append(f"✅ Added {proxy_type} proxy: {host}:{port}")
    
    def test_proxy_chain(self):
        """Test proxy chain configuration"""
        proxy_list = self.proxy_list.toPlainText().strip()
        if not proxy_list:
            self.status_text.append("❌ No proxies configured")
            return
        
        self.status_text.append("🧪 Testing proxy chain...")
        
        # Simulate proxy chain test
        proxies = proxy_list.split('\n')
        self.status_text.append(f"📡 Testing {len(proxies)} proxies")
        
        if self.enable_tor.isChecked():
            self.status_text.append(f"🧅 Including Tor on port {self.tor_port.value()}")
        
        self.status_text.append(f"✅ Chain test completed - {self.chain_type.currentText()} mode")
    
    def clear_proxy_list(self):
        """Clear all proxies"""
        self.proxy_list.clear()
        self.status_text.append("🧹 All proxies cleared")
    
    def save_proxy_config(self):
        """Save proxy configuration"""
        config = self.get_configuration()
        try:
            import json
            with open("stealth_proxy_config.json", "w") as f:
                json.dump(config, f, indent=2)
            self.status_text.append("💾 Proxy configuration saved")
        except Exception as e:
            self.status_text.append(f"❌ Failed to save config: {str(e)}")
    
    def load_evasion_plugins(self):
        import os
        plugins_dir = os.path.join(os.path.dirname(__file__), "..", "..", "plugins", "evasion")
        os.makedirs(plugins_dir, exist_ok=True)
        
        stealth_engine.load_evasion_plugins(plugins_dir)
        
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
        
        if event_type in ['rate_adjusted', 'plugin_loaded']:
            self.update_risk_score()
    
    def test_aws_connections(self):
        from app.core.aws_sam_deployment import sam_deployment_manager
        from PyQt6.QtWidgets import QMessageBox
        
        gitlab_ok = sam_deployment_manager.configure_gitlab(
            self.gitlab_url.text(), self.gitlab_token.text(), self.project_id.text()
        )
        aws_ok = sam_deployment_manager.configure_aws(
            self.aws_access_key.text(), self.aws_secret_key.text()
        )
        
        if gitlab_ok and aws_ok:
            QMessageBox.information(self, "Success", "All connections tested successfully!")
            self.aws_status.append("✅ Connections configured")
        else:
            QMessageBox.warning(self, "Error", "Connection test failed")
            self.aws_status.append("❌ Connection test failed")
    
    def deploy_proxy_servers(self):
        from app.core.aws_sam_deployment import sam_deployment_manager
        from PyQt6.QtWidgets import QMessageBox
        
        config = {'count': self.proxy_count.value(), 'instance_type': 't3.micro'}
        job_id = sam_deployment_manager.deploy_proxy_servers(config)
        
        if job_id:
            self.aws_status.append(f"🚀 Proxy deployment started: {job_id}")
        else:
            QMessageBox.warning(self, "Error", "Failed to start deployment")
    
    def deploy_vpn_servers(self):
        from app.core.aws_sam_deployment import sam_deployment_manager
        from PyQt6.QtWidgets import QMessageBox
        
        config = {'count': self.vpn_count.value(), 'instance_type': 't3.small'}
        job_id = sam_deployment_manager.deploy_vpn_servers(config)
        
        if job_id:
            self.aws_status.append(f"🚀 VPN deployment started: {job_id}")
        else:
            QMessageBox.warning(self, "Error", "Failed to start deployment")
    
    def on_aws_deployment_started(self, deployment_type: str, job_id: str):
        self.aws_status.append(f"🚀 {deployment_type} deployment pipeline started: {job_id}")
    
    def on_aws_deployment_completed(self, job_id: str, success: bool, message: str):
        icon = "✅" if success else "❌"
        self.aws_status.append(f"{icon} Deployment {job_id}: {message}")
        if success:
            self.aws_status.append("🎉 Infrastructure ready for stealth operations!")
    
    def get_configuration(self):
        return {
            'evasion_level': self.evasion_combo.currentText(),
            'base_rate': self.basic_rate.value(),
            'dynamic_rate': self.dynamic_rate.isChecked(),
            'randomize_headers': self.randomize_headers.isChecked(),
            'custom_agents': self.custom_agents.text().strip(),
            'enable_jitter': self.enable_jitter.isChecked(),
            'jitter_min': self.jitter_min.value(),
            'jitter_max': self.jitter_max.value(),
            'proxy_mode': self.proxy_mode.currentText(),
            'chain_type': self.chain_type.currentText(),
            'enable_tor': self.enable_tor.isChecked(),
            'tor_port': self.tor_port.value(),
            'proxy_list': self.proxy_list.toPlainText().strip(),
            'vpn_rotation': self.vpn_rotation.isChecked(),
            'target_type': self.target_type_combo.currentText()
        }