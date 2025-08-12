# app/widgets/wireless_security_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QComboBox, QPushButton, QTextEdit, QGroupBox,
                            QTableWidget, QTableWidgetItem, QHeaderView,
                            QTabWidget, QLineEdit, QCheckBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor
from app.core.wireless_security import wireless_security
from app.core.license_manager import license_manager

class WirelessScanWorker(QThread):
    """Worker thread for wireless scanning"""
    scan_completed = pyqtSignal(dict)
    
    def __init__(self, scan_type, **kwargs):
        super().__init__()
        self.scan_type = scan_type
        self.kwargs = kwargs
        
    def run(self):
        if self.scan_type == 'wifi_discovery':
            result = wireless_security.discover_wifi_networks()
        elif self.scan_type == 'bluetooth_discovery':
            result = wireless_security.discover_bluetooth_devices()
        elif self.scan_type == 'wpa_test':
            result = wireless_security.test_wpa_security(self.kwargs['ssid'], self.kwargs.get('wordlist'))
        elif self.scan_type == 'evil_twin':
            result = wireless_security.evil_twin_attack(self.kwargs['ssid'])
        elif self.scan_type == 'bluetooth_attack':
            result = wireless_security.bluetooth_attack(self.kwargs['address'], self.kwargs['attack_type'])
        else:
            result = {'error': 'Unknown scan type'}
            
        self.scan_completed.emit(result)

class WirelessSecurityWidget(QWidget):
    """Wireless security testing widget"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scan_worker = None
        self.setup_ui()
        self.connect_signals()
        self.check_license()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Header
        header = QLabel("Wireless Security Testing Framework")
        header.setStyleSheet("font-size: 16pt; font-weight: bold; color: #64C8FF;")
        layout.addWidget(header)
        
        # License warning
        self.license_warning = QLabel("⚠️ Wireless Security requires Enterprise license")
        self.license_warning.setStyleSheet("color: #FF6B6B; font-weight: bold; padding: 10px;")
        layout.addWidget(self.license_warning)
        
        # Tabs for different wireless technologies
        self.wireless_tabs = QTabWidget()
        
        # WiFi Tab
        self.wifi_tab = self.create_wifi_tab()
        self.wireless_tabs.addTab(self.wifi_tab, "WiFi Security")
        
        # Bluetooth Tab
        self.bluetooth_tab = self.create_bluetooth_tab()
        self.wireless_tabs.addTab(self.bluetooth_tab, "Bluetooth Security")
        
        # Reports Tab
        self.reports_tab = self.create_reports_tab()
        self.wireless_tabs.addTab(self.reports_tab, "Reports")
        
        layout.addWidget(self.wireless_tabs)
        
        # Status
        self.status_text = QTextEdit()
        self.status_text.setMaximumHeight(100)
        self.status_text.setReadOnly(True)
        layout.addWidget(self.status_text)
        
    def create_wifi_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # WiFi Discovery
        discovery_group = QGroupBox("WiFi Network Discovery")
        discovery_layout = QVBoxLayout(discovery_group)
        
        self.wifi_discover_btn = QPushButton("Discover WiFi Networks")
        self.wifi_discover_btn.setStyleSheet("background-color: #64C8FF; font-weight: bold;")
        discovery_layout.addWidget(self.wifi_discover_btn)
        
        # WiFi Networks Table
        self.wifi_networks_table = QTableWidget()
        self.wifi_networks_table.setColumnCount(5)
        self.wifi_networks_table.setHorizontalHeaderLabels(["SSID", "Security", "Cipher", "Signal", "Risk Level"])
        self.wifi_networks_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        discovery_layout.addWidget(self.wifi_networks_table)
        
        layout.addWidget(discovery_group)
        
        # WiFi Attacks
        attacks_group = QGroupBox("WiFi Security Testing")
        attacks_layout = QVBoxLayout(attacks_group)
        
        # WPA Testing
        wpa_layout = QHBoxLayout()
        wpa_layout.addWidget(QLabel("Target SSID:"))
        self.wpa_target_input = QLineEdit()
        self.wpa_target_input.setPlaceholderText("Select from discovered networks")
        wpa_layout.addWidget(self.wpa_target_input)
        
        self.wpa_test_btn = QPushButton("Test WPA Security")
        wpa_layout.addWidget(self.wpa_test_btn)
        attacks_layout.addLayout(wpa_layout)
        
        # Evil Twin Attack
        evil_twin_layout = QHBoxLayout()
        evil_twin_layout.addWidget(QLabel("Evil Twin Target:"))
        self.evil_twin_input = QLineEdit()
        self.evil_twin_input.setPlaceholderText("Target SSID for evil twin")
        evil_twin_layout.addWidget(self.evil_twin_input)
        
        self.evil_twin_btn = QPushButton("Launch Evil Twin")
        self.evil_twin_btn.setStyleSheet("background-color: #FF6B6B; font-weight: bold;")
        evil_twin_layout.addWidget(self.evil_twin_btn)
        attacks_layout.addLayout(evil_twin_layout)
        
        layout.addWidget(attacks_group)
        
        return widget
        
    def create_bluetooth_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Bluetooth Discovery
        discovery_group = QGroupBox("Bluetooth Device Discovery")
        discovery_layout = QVBoxLayout(discovery_group)
        
        self.bt_discover_btn = QPushButton("Discover Bluetooth Devices")
        self.bt_discover_btn.setStyleSheet("background-color: #64C8FF; font-weight: bold;")
        discovery_layout.addWidget(self.bt_discover_btn)
        
        # Bluetooth Devices Table
        self.bt_devices_table = QTableWidget()
        self.bt_devices_table.setColumnCount(4)
        self.bt_devices_table.setHorizontalHeaderLabels(["Name", "Address", "Type", "Security Level"])
        self.bt_devices_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        discovery_layout.addWidget(self.bt_devices_table)
        
        layout.addWidget(discovery_group)
        
        # Bluetooth Attacks
        attacks_group = QGroupBox("Bluetooth Security Testing")
        attacks_layout = QVBoxLayout(attacks_group)
        
        # Attack configuration
        attack_config_layout = QHBoxLayout()
        attack_config_layout.addWidget(QLabel("Target Address:"))
        self.bt_target_input = QLineEdit()
        self.bt_target_input.setPlaceholderText("Select from discovered devices")
        attack_config_layout.addWidget(self.bt_target_input)
        
        attack_config_layout.addWidget(QLabel("Attack Type:"))
        self.bt_attack_type = QComboBox()
        self.bt_attack_type.addItems(["bluejacking", "bluesnarfing", "bluebugging"])
        attack_config_layout.addWidget(self.bt_attack_type)
        attacks_layout.addLayout(attack_config_layout)
        
        self.bt_attack_btn = QPushButton("Execute Bluetooth Attack")
        self.bt_attack_btn.setStyleSheet("background-color: #FF6B6B; font-weight: bold;")
        attacks_layout.addWidget(self.bt_attack_btn)
        
        layout.addWidget(attacks_group)
        
        return widget
        
    def create_reports_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Report Generation
        report_group = QGroupBox("Wireless Security Report")
        report_layout = QVBoxLayout(report_group)
        
        self.generate_report_btn = QPushButton("Generate Wireless Security Report")
        report_layout.addWidget(self.generate_report_btn)
        
        # Report Display
        self.report_display = QTextEdit()
        self.report_display.setReadOnly(True)
        report_layout.addWidget(self.report_display)
        
        layout.addWidget(report_group)
        
        return widget
        
    def connect_signals(self):
        self.wifi_discover_btn.clicked.connect(self.discover_wifi)
        self.bt_discover_btn.clicked.connect(self.discover_bluetooth)
        self.wpa_test_btn.clicked.connect(self.test_wpa_security)
        self.evil_twin_btn.clicked.connect(self.launch_evil_twin)
        self.bt_attack_btn.clicked.connect(self.execute_bluetooth_attack)
        self.generate_report_btn.clicked.connect(self.generate_report)
        
        # Table selection handlers
        self.wifi_networks_table.itemSelectionChanged.connect(self.on_wifi_selection_changed)
        self.bt_devices_table.itemSelectionChanged.connect(self.on_bt_selection_changed)
        
        wireless_security.wireless_event.connect(self.handle_wireless_event)
        
    def check_license(self):
        if license_manager.is_feature_enabled('wireless_security'):
            self.license_warning.hide()
            self.setEnabled(True)
        else:
            self.license_warning.show()
            self.setEnabled(False)
            
    def discover_wifi(self):
        if not license_manager.is_feature_enabled('wireless_security'):
            self.status_text.append("❌ Wireless Security requires Enterprise license")
            return
            
        self.wifi_discover_btn.setEnabled(False)
        self.status_text.append("🔍 Discovering WiFi networks...")
        
        self.scan_worker = WirelessScanWorker('wifi_discovery')
        self.scan_worker.scan_completed.connect(self.handle_wifi_discovery_completed)
        self.scan_worker.start()
        
    def discover_bluetooth(self):
        if not license_manager.is_feature_enabled('wireless_security'):
            self.status_text.append("❌ Wireless Security requires Enterprise license")
            return
            
        self.bt_discover_btn.setEnabled(False)
        self.status_text.append("🔍 Discovering Bluetooth devices...")
        
        self.scan_worker = WirelessScanWorker('bluetooth_discovery')
        self.scan_worker.scan_completed.connect(self.handle_bluetooth_discovery_completed)
        self.scan_worker.start()
        
    def test_wpa_security(self):
        ssid = self.wpa_target_input.text().strip()
        if not ssid:
            self.status_text.append("❌ Please enter target SSID")
            return
            
        self.wpa_test_btn.setEnabled(False)
        self.status_text.append(f"🔓 Testing WPA security for {ssid}...")
        
        self.scan_worker = WirelessScanWorker('wpa_test', ssid=ssid)
        self.scan_worker.scan_completed.connect(self.handle_wpa_test_completed)
        self.scan_worker.start()
        
    def launch_evil_twin(self):
        ssid = self.evil_twin_input.text().strip()
        if not ssid:
            self.status_text.append("❌ Please enter target SSID")
            return
            
        self.evil_twin_btn.setEnabled(False)
        self.status_text.append(f"👥 Launching evil twin attack against {ssid}...")
        
        self.scan_worker = WirelessScanWorker('evil_twin', ssid=ssid)
        self.scan_worker.scan_completed.connect(self.handle_evil_twin_completed)
        self.scan_worker.start()
        
    def execute_bluetooth_attack(self):
        address = self.bt_target_input.text().strip()
        attack_type = self.bt_attack_type.currentText()
        
        if not address:
            self.status_text.append("❌ Please enter target Bluetooth address")
            return
            
        self.bt_attack_btn.setEnabled(False)
        self.status_text.append(f"📱 Executing {attack_type} attack against {address}...")
        
        self.scan_worker = WirelessScanWorker('bluetooth_attack', address=address, attack_type=attack_type)
        self.scan_worker.scan_completed.connect(self.handle_bluetooth_attack_completed)
        self.scan_worker.start()
        
    def generate_report(self):
        report = wireless_security.generate_wireless_report()
        
        if 'error' in report:
            self.status_text.append(f"❌ Report generation failed: {report['error']}")
            return
            
        # Format report for display
        report_text = f"""
WIRELESS SECURITY ASSESSMENT REPORT
Generated: {report.get('generated_at', 'Unknown')}

WiFi NETWORKS ASSESSMENT:
- Total Networks Discovered: {report['wifi_networks']['total_discovered']}
- Critical Security Issues: {report['wifi_networks']['critical_issues']}

Security Level Breakdown:
"""
        
        for level, count in report['wifi_networks']['security_breakdown'].items():
            report_text += f"  {level}: {count} networks\n"
            
        report_text += f"""
BLUETOOTH DEVICES ASSESSMENT:
- Total Devices Discovered: {report['bluetooth_devices']['total_discovered']}
- Vulnerable Devices: {report['bluetooth_devices']['vulnerable_devices']}

RECOMMENDATIONS:
"""
        
        for rec in report.get('recommendations', []):
            report_text += f"• {rec}\n"
            
        self.report_display.setPlainText(report_text)
        self.status_text.append("📊 Wireless security report generated")
        
    def handle_wifi_discovery_completed(self, result):
        self.wifi_discover_btn.setEnabled(True)
        
        if 'error' in result:
            self.status_text.append(f"❌ WiFi discovery failed: {result['error']}")
            return
            
        networks = result.get('networks', [])
        self.wifi_networks_table.setRowCount(len(networks))
        
        for row, network in enumerate(networks):
            self.wifi_networks_table.setItem(row, 0, QTableWidgetItem(network.get('ssid', '')))
            self.wifi_networks_table.setItem(row, 1, QTableWidgetItem(network.get('authentication', '')))
            self.wifi_networks_table.setItem(row, 2, QTableWidgetItem(network.get('cipher', '')))
            
            signal_strength = network.get('signal_strength', 'N/A')
            self.wifi_networks_table.setItem(row, 3, QTableWidgetItem(str(signal_strength)))
            
            # Color code security level
            security_level = network.get('security_level', 'Unknown')
            security_item = QTableWidgetItem(security_level)
            
            if security_level == 'Critical':
                security_item.setForeground(QColor("#FF0000"))
            elif security_level == 'High':
                security_item.setForeground(QColor("#FF6B6B"))
            elif security_level == 'Medium':
                security_item.setForeground(QColor("#FFA500"))
            else:
                security_item.setForeground(QColor("#00FF41"))
                
            self.wifi_networks_table.setItem(row, 4, security_item)
            
        self.status_text.append(f"✅ WiFi discovery completed: {len(networks)} networks found")
        
    def handle_bluetooth_discovery_completed(self, result):
        self.bt_discover_btn.setEnabled(True)
        
        if 'error' in result:
            self.status_text.append(f"❌ Bluetooth discovery failed: {result['error']}")
            return
            
        devices = result.get('devices', [])
        self.bt_devices_table.setRowCount(len(devices))
        
        for row, device in enumerate(devices):
            self.bt_devices_table.setItem(row, 0, QTableWidgetItem(device.get('name', '')))
            self.bt_devices_table.setItem(row, 1, QTableWidgetItem(device.get('address', '')))
            self.bt_devices_table.setItem(row, 2, QTableWidgetItem(device.get('device_type', '')))
            
            # Color code security level
            security_level = device.get('security_level', 'Unknown')
            security_item = QTableWidgetItem(security_level)
            
            if security_level == 'Low':
                security_item.setForeground(QColor("#FF6B6B"))
            elif security_level == 'Medium':
                security_item.setForeground(QColor("#FFA500"))
            else:
                security_item.setForeground(QColor("#00FF41"))
                
            self.bt_devices_table.setItem(row, 3, security_item)
            
        self.status_text.append(f"✅ Bluetooth discovery completed: {len(devices)} devices found")
        
    def handle_wpa_test_completed(self, result):
        self.wpa_test_btn.setEnabled(True)
        
        if result.get('success'):
            password = result.get('cracked_password', 'Unknown')
            self.status_text.append(f"🔓 WPA cracked! Password: {password}")
        else:
            self.status_text.append(f"🔒 WPA test completed - Password not cracked")
            
        self.status_text.append(f"📊 Tested {result.get('passwords_tested', 0)} passwords in {result.get('time_elapsed', 'unknown time')}")
        
    def handle_evil_twin_completed(self, result):
        self.evil_twin_btn.setEnabled(True)
        
        clients = result.get('clients_connected', 0)
        if clients > 0:
            self.status_text.append(f"👥 Evil twin successful: {clients} clients connected")
            credentials = result.get('credentials_captured', [])
            if credentials:
                self.status_text.append(f"🔑 Captured {len(credentials)} credential sets")
        else:
            self.status_text.append("👥 Evil twin completed - No clients connected")
            
    def handle_bluetooth_attack_completed(self, result):
        self.bt_attack_btn.setEnabled(True)
        
        if result.get('success'):
            self.status_text.append(f"📱 Bluetooth attack successful: {result.get('attack_type')}")
            data = result.get('data_accessed', [])
            if data:
                self.status_text.append(f"📊 Data accessed: {', '.join(data)}")
        else:
            self.status_text.append(f"📱 Bluetooth attack failed: {result.get('attack_type')}")
            
    def on_wifi_selection_changed(self):
        current_row = self.wifi_networks_table.currentRow()
        if current_row >= 0:
            ssid_item = self.wifi_networks_table.item(current_row, 0)
            if ssid_item:
                self.wpa_target_input.setText(ssid_item.text())
                self.evil_twin_input.setText(ssid_item.text())
                
    def on_bt_selection_changed(self):
        current_row = self.bt_devices_table.currentRow()
        if current_row >= 0:
            address_item = self.bt_devices_table.item(current_row, 1)
            if address_item:
                self.bt_target_input.setText(address_item.text())
                
    def handle_wireless_event(self, event_type, message, data):
        self.status_text.append(f"📡 {message}")