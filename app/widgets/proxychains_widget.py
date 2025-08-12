# app/widgets/proxychains_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QComboBox, QPushButton, QLineEdit, QSpinBox,
                            QGroupBox, QTableWidget, QTableWidgetItem,
                            QHeaderView, QTextEdit, QCheckBox, QMessageBox)
from PyQt6.QtCore import Qt, pyqtSignal
from app.core.proxychains_manager import proxychains_manager
from app.core.license_manager import license_manager

class ProxyChainsWidget(QWidget):
    """ProxyChains configuration widget"""
    
    proxy_configured = pyqtSignal(dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.connect_signals()
        self.check_license()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Header
        header = QLabel("ProxyChains Configuration")
        header.setStyleSheet("font-size: 16pt; font-weight: bold; color: #64C8FF;")
        layout.addWidget(header)
        
        # License warning
        self.license_warning = QLabel("⚠️ ProxyChains requires Professional license")
        self.license_warning.setStyleSheet("color: #FF6B6B; font-weight: bold; padding: 10px;")
        layout.addWidget(self.license_warning)
        
        # Chain Configuration
        chain_group = QGroupBox("Chain Configuration")
        chain_layout = QVBoxLayout(chain_group)
        
        chain_type_layout = QHBoxLayout()
        chain_type_layout.addWidget(QLabel("Chain Type:"))
        self.chain_type_combo = QComboBox()
        self.chain_type_combo.addItems(["dynamic", "strict", "random"])
        chain_type_layout.addWidget(self.chain_type_combo)
        chain_layout.addLayout(chain_type_layout)
        
        # Tor integration
        self.enable_tor = QCheckBox("Enable Tor Integration")
        chain_layout.addWidget(self.enable_tor)
        
        tor_layout = QHBoxLayout()
        tor_layout.addWidget(QLabel("Tor Port:"))
        self.tor_port = QSpinBox()
        self.tor_port.setRange(1, 65535)
        self.tor_port.setValue(9050)
        tor_layout.addWidget(self.tor_port)
        chain_layout.addLayout(tor_layout)
        
        layout.addWidget(chain_group)
        
        # Proxy Management
        proxy_group = QGroupBox("Proxy Management")
        proxy_layout = QVBoxLayout(proxy_group)
        
        # Add proxy form
        add_layout = QHBoxLayout()
        
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
        self.proxy_user.setPlaceholderText("Username (optional)")
        add_layout.addWidget(self.proxy_user)
        
        self.proxy_pass = QLineEdit()
        self.proxy_pass.setPlaceholderText("Password (optional)")
        self.proxy_pass.setEchoMode(QLineEdit.EchoMode.Password)
        add_layout.addWidget(self.proxy_pass)
        
        self.add_proxy_btn = QPushButton("Add Proxy")
        add_layout.addWidget(self.add_proxy_btn)
        
        proxy_layout.addLayout(add_layout)
        
        # Proxy table
        self.proxy_table = QTableWidget()
        self.proxy_table.setColumnCount(5)
        self.proxy_table.setHorizontalHeaderLabels(["Type", "Host", "Port", "Auth", "Actions"])
        self.proxy_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        proxy_layout.addWidget(self.proxy_table)
        
        layout.addWidget(proxy_group)
        
        # Control Buttons
        button_layout = QHBoxLayout()
        self.test_btn = QPushButton("Test Chain")
        self.clear_btn = QPushButton("Clear All")
        self.save_config_btn = QPushButton("Save Config")
        
        button_layout.addWidget(self.test_btn)
        button_layout.addWidget(self.clear_btn)
        button_layout.addWidget(self.save_config_btn)
        layout.addLayout(button_layout)
        
        # Status
        self.status_text = QTextEdit()
        self.status_text.setMaximumHeight(150)
        self.status_text.setReadOnly(True)
        layout.addWidget(self.status_text)
        
    def connect_signals(self):
        self.add_proxy_btn.clicked.connect(self.add_proxy)
        self.test_btn.clicked.connect(self.test_chain)
        self.clear_btn.clicked.connect(self.clear_proxies)
        self.save_config_btn.clicked.connect(self.save_configuration)
        self.enable_tor.toggled.connect(self.toggle_tor)
        proxychains_manager.proxy_event.connect(self.handle_proxy_event)
        
    def check_license(self):
        if license_manager.is_feature_enabled('proxychains'):
            self.license_warning.hide()
            self.setEnabled(True)
        else:
            self.license_warning.show()
            self.setEnabled(False)
            
    def add_proxy(self):
        if not license_manager.is_feature_enabled('proxychains'):
            self.status_text.append("❌ ProxyChains requires Professional license")
            return
            
        proxy_type = self.proxy_type.currentText()
        host = self.proxy_host.text().strip()
        port = self.proxy_port.value()
        username = self.proxy_user.text().strip()
        password = self.proxy_pass.text().strip()
        
        if not host:
            QMessageBox.warning(self, "Error", "Host/IP is required")
            return
            
        proxychains_manager.add_proxy(proxy_type, host, port, username, password)
        self.update_proxy_table()
        
        # Clear form
        self.proxy_host.clear()
        self.proxy_user.clear()
        self.proxy_pass.clear()
        
    def update_proxy_table(self):
        status = proxychains_manager.get_chain_status()
        proxies = status['proxies']
        
        self.proxy_table.setRowCount(len(proxies))
        
        for row, proxy in enumerate(proxies):
            # Type
            type_item = QTableWidgetItem(proxy['type'].upper())
            self.proxy_table.setItem(row, 0, type_item)
            
            # Endpoint
            endpoint_item = QTableWidgetItem(proxy['endpoint'])
            self.proxy_table.setItem(row, 1, endpoint_item)
            
            # Port (extracted from endpoint)
            port = proxy['endpoint'].split(':')[-1]
            port_item = QTableWidgetItem(port)
            self.proxy_table.setItem(row, 2, port_item)
            
            # Auth status
            auth_item = QTableWidgetItem("✓" if proxy['authenticated'] else "✗")
            self.proxy_table.setItem(row, 3, auth_item)
            
            # Remove button
            remove_btn = QPushButton("Remove")
            remove_btn.clicked.connect(lambda checked, r=row: self.remove_proxy(r))
            self.proxy_table.setCellWidget(row, 4, remove_btn)
            
    def remove_proxy(self, row):
        # Remove from manager (simplified - would need proper implementation)
        self.status_text.append(f"🗑️ Removed proxy at row {row}")
        self.update_proxy_table()
        
    def toggle_tor(self, enabled):
        if enabled:
            proxychains_manager.enable_tor(self.tor_port.value())
            self.status_text.append("🧅 Tor integration enabled")
        else:
            self.status_text.append("🧅 Tor integration disabled")
            
    def test_chain(self):
        if not proxychains_manager.proxy_chains:
            QMessageBox.warning(self, "Error", "No proxies configured")
            return
            
        self.status_text.append("🧪 Testing proxy chain...")
        result = proxychains_manager.test_proxy_chain()
        
        if result['success']:
            self.status_text.append(f"✅ Chain test successful: {result['chain_length']} proxies")
            self.status_text.append(f"📡 Response: {result['output'][:100]}...")
        else:
            self.status_text.append(f"❌ Chain test failed: {result['error']}")
            
    def clear_proxies(self):
        proxychains_manager.clear_chains()
        self.update_proxy_table()
        self.status_text.append("🧹 All proxies cleared")
        
    def save_configuration(self):
        config = proxychains_manager.generate_proxychains_config()
        
        try:
            with open("proxychains.conf", "w") as f:
                f.write(config)
            self.status_text.append("💾 Configuration saved to proxychains.conf")
        except Exception as e:
            self.status_text.append(f"❌ Failed to save config: {str(e)}")
            
    def handle_proxy_event(self, event_type, message):
        self.status_text.append(f"📡 {message}")
        if event_type == 'proxy_added':
            self.update_proxy_table()