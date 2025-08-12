# app/widgets/vpn_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QLineEdit, QComboBox, QTextEdit,
                             QFileDialog, QGroupBox, QSpinBox, QTabWidget,
                             QProgressBar, QFrame)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont
from app.core.vpn_manager import vpn_manager
# from app.core.python_vpn import python_vpn  # Removed - using official OpenVPN

class VPNWidget(QWidget):
    """VPN connection management widget"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("VPN Connection Manager")
        self.resize(1000, 800)
        self.setMinimumSize(900, 500)
        
        self.is_connecting = False
        
        self.setup_ui()
        self.connect_signals()
        self.update_status()
        
        # Status update timer
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_status)
        self.status_timer.start(2000)  # Update every 2 seconds
    
    def setup_ui(self):
        """Setup the UI"""
        layout = QVBoxLayout(self)
        
        # Professional license notice
        license_frame = QFrame()
        license_frame.setStyleSheet("background-color: rgba(0, 100, 0, 50); border-radius: 5px; padding: 5px;")
        license_layout = QHBoxLayout(license_frame)
        license_label = QLabel("✓ Licensed Features")
        license_label.setStyleSheet("color: #00FF00; font-weight: bold;")
        license_layout.addWidget(license_label)
        layout.addWidget(license_frame)
        
        # Status section
        status_group = QGroupBox("Connection Status")
        status_layout = QVBoxLayout(status_group)
        
        self.status_label = QLabel("Disconnected")
        self.status_label.setStyleSheet("font-weight: bold; font-size: 14pt;")
        status_layout.addWidget(self.status_label)
        
        self.status_details = QLabel("No active VPN connection")
        status_layout.addWidget(self.status_details)
        
        # Connection controls
        controls_layout = QHBoxLayout()
        
        self.connect_btn = QPushButton("Connect")
        self.connect_btn.clicked.connect(self.connect_vpn)
        controls_layout.addWidget(self.connect_btn)
        
        self.disconnect_btn = QPushButton("Disconnect")
        self.disconnect_btn.clicked.connect(self.disconnect_vpn)
        self.disconnect_btn.setEnabled(False)
        controls_layout.addWidget(self.disconnect_btn)
        
        self.test_btn = QPushButton("Test Connection")
        self.test_btn.clicked.connect(self.test_connection)
        controls_layout.addWidget(self.test_btn)
        
        status_layout.addLayout(controls_layout)
        layout.addWidget(status_group)
        
        # Connection tabs
        self.tabs = QTabWidget()
        
        # OpenVPN config tab
        self.setup_config_tab()
        
        # Manual connection tab
        self.setup_manual_tab()
        
        # Python VPN tab removed - using official OpenVPN only
        
        layout.addWidget(self.tabs, 1)  # Give tabs more vertical space
        
        # Output area
        output_group = QGroupBox("Connection Log")
        output_layout = QVBoxLayout(output_group)
        
        self.output_text = QTextEdit()
        self.output_text.setMaximumHeight(200)  # Increased height
        self.output_text.setReadOnly(True)
        output_layout.addWidget(self.output_text)
        
        layout.addWidget(output_group)
    
    def setup_config_tab(self):
        """Setup OpenVPN config file tab"""
        config_widget = QWidget()
        layout = QVBoxLayout(config_widget)
        
        # Config file selection
        file_layout = QHBoxLayout()
        file_layout.addWidget(QLabel("Config File:"))
        
        self.config_file_input = QLineEdit()
        self.config_file_input.setPlaceholderText("Select .ovpn config file...")
        file_layout.addWidget(self.config_file_input)
        
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_config_file)
        file_layout.addWidget(browse_btn)
        
        layout.addLayout(file_layout)
        
        # Authentication
        auth_group = QGroupBox("Authentication (Optional)")
        auth_group.setFixedHeight(120)  # Set fixed height to fit username and password fields
        auth_layout = QVBoxLayout(auth_group)
        
        username_layout = QHBoxLayout()
        username_layout.addWidget(QLabel("Username:"))
        self.config_username = QLineEdit()
        username_layout.addWidget(self.config_username)
        auth_layout.addLayout(username_layout)
        
        password_layout = QHBoxLayout()
        password_layout.addWidget(QLabel("Password:"))
        self.config_password = QLineEdit()
        self.config_password.setEchoMode(QLineEdit.EchoMode.Password)
        password_layout.addWidget(self.config_password)
        auth_layout.addLayout(password_layout)
        
        layout.addWidget(auth_group)
        
        self.tabs.addTab(config_widget, "OpenVPN Config")
    
    def setup_manual_tab(self):
        """Setup manual connection tab"""
        manual_widget = QWidget()
        layout = QVBoxLayout(manual_widget)
        
        # Server settings
        server_group = QGroupBox("Server Settings")
        server_layout = QVBoxLayout(server_group)
        
        server_layout.addWidget(QLabel("Server:"))
        self.manual_server = QLineEdit()
        self.manual_server.setPlaceholderText("vpn.example.com")
        server_layout.addWidget(self.manual_server)
        
        port_protocol_layout = QHBoxLayout()
        
        port_protocol_layout.addWidget(QLabel("Port:"))
        self.manual_port = QSpinBox()
        self.manual_port.setRange(1, 65535)
        self.manual_port.setValue(1194)
        port_protocol_layout.addWidget(self.manual_port)
        
        port_protocol_layout.addWidget(QLabel("Protocol:"))
        self.manual_protocol = QComboBox()
        self.manual_protocol.addItems(["UDP", "TCP"])
        port_protocol_layout.addWidget(self.manual_protocol)
        
        server_layout.addLayout(port_protocol_layout)
        layout.addWidget(server_group)
        
        # Authentication
        auth_group = QGroupBox("Authentication")
        auth_layout = QVBoxLayout(auth_group)
        
        auth_layout.addWidget(QLabel("Username:"))
        self.manual_username = QLineEdit()
        auth_layout.addWidget(self.manual_username)
        
        auth_layout.addWidget(QLabel("Password:"))
        self.manual_password = QLineEdit()
        self.manual_password.setEchoMode(QLineEdit.EchoMode.Password)
        auth_layout.addWidget(self.manual_password)
        
        layout.addWidget(auth_group)
        
        self.tabs.addTab(manual_widget, "Manual Setup")
    
    def setup_python_vpn_tab(self):
        """Setup Python VPN tab"""
        python_widget = QWidget()
        layout = QVBoxLayout(python_widget)
        
        # Connection type
        type_group = QGroupBox("Connection Type")
        type_layout = QVBoxLayout(type_group)
        
        self.python_connection_type = QComboBox()
        self.python_connection_type.addItems(["SSL/TLS Tunnel", "TCP Tunnel", "SOCKS5 Proxy"])
        type_layout.addWidget(self.python_connection_type)
        layout.addWidget(type_group)
        
        # Server settings
        server_group = QGroupBox("Server Settings")
        server_layout = QVBoxLayout(server_group)
        
        server_layout.addWidget(QLabel("Server:"))
        self.python_server = QLineEdit()
        self.python_server.setPlaceholderText("vpn.example.com")
        server_layout.addWidget(self.python_server)
        
        port_layout = QHBoxLayout()
        port_layout.addWidget(QLabel("Port:"))
        self.python_port = QSpinBox()
        self.python_port.setRange(1, 65535)
        self.python_port.setValue(443)
        port_layout.addWidget(self.python_port)
        server_layout.addLayout(port_layout)
        
        layout.addWidget(server_group)
        
        # Authentication
        auth_group = QGroupBox("Authentication")
        auth_layout = QVBoxLayout(auth_group)
        
        auth_layout.addWidget(QLabel("Username:"))
        self.python_username = QLineEdit()
        auth_layout.addWidget(self.python_username)
        
        auth_layout.addWidget(QLabel("Password:"))
        self.python_password = QLineEdit()
        self.python_password.setEchoMode(QLineEdit.EchoMode.Password)
        auth_layout.addWidget(self.python_password)
        
        layout.addWidget(auth_group)
        layout.addStretch()
        
        self.tabs.addTab(python_widget, "Python VPN")
    
    def connect_signals(self):
        """Connect VPN manager signals"""
        vpn_manager.connection_status_changed.connect(self.on_status_changed)
        # python_vpn.connection_status_changed.connect(self.on_status_changed)  # Removed
    
    def browse_config_file(self):
        """Browse for OpenVPN config file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select OpenVPN Config File",
            "",
            "OpenVPN Config (*.ovpn);;All Files (*)"
        )
        
        if file_path:
            self.config_file_input.setText(file_path)
    
    def connect_vpn(self):
        """Connect VPN based on current tab"""
        # Set status to connecting immediately
        self.is_connecting = True
        self.status_label.setText("Connecting...")
        self.status_label.setStyleSheet("color: #FFAA00; font-weight: bold; font-size: 14pt;")
        self.status_details.setText("Establishing VPN connection...")
        self.connect_btn.setEnabled(False)
        self.disconnect_btn.setEnabled(True)
        
        current_tab = self.tabs.currentIndex()
        
        if current_tab == 0:  # OpenVPN config
            config_file = self.config_file_input.text().strip()
            if not config_file:
                self.log_message("Please select a config file")
                return
            
            username = self.config_username.text().strip()
            password = self.config_password.text().strip()
            
            result = vpn_manager.connect_openvpn(config_file, username, password)
            
        elif current_tab == 1:  # Manual setup
            server = self.manual_server.text().strip()
            if not server:
                self.log_message("Please enter server address")
                return
            
            port = self.manual_port.value()
            protocol = self.manual_protocol.currentText()
            username = self.manual_username.text().strip()
            password = self.manual_password.text().strip()
            
            if not username or not password:
                self.log_message("Please enter username and password")
                return
            
            result = vpn_manager.connect_manual(server, port, protocol, username, password)
            
        elif current_tab == 2:  # Python VPN
            server = self.python_server.text().strip()
            if not server:
                self.log_message("Please enter server address")
                return
            
            port = self.python_port.value()
            username = self.python_username.text().strip()
            password = self.python_password.text().strip()
            connection_type = self.python_connection_type.currentText()
            
            self.log_message("Python VPN removed - use OpenVPN config tab")
            return
        else:
            self.log_message("Unknown tab selected")
            return
        
        if result["success"]:
            self.log_message(result["message"])
            self.connect_btn.setEnabled(False)
            self.disconnect_btn.setEnabled(True)
        else:
            self.log_message(f"Connection failed: {result['error']}")
    
    def disconnect_vpn(self):
        """Disconnect VPN"""
        # Try disconnecting both VPN types
        result1 = vpn_manager.disconnect()
        result2 = {"success": True, "message": ""}
        
        # Use the successful result or the first error
        result = result1 if result1["success"] else result2
        
        if result["success"]:
            self.log_message(result["message"])
            self.connect_btn.setEnabled(True)
            self.disconnect_btn.setEnabled(False)
        else:
            self.log_message(f"Disconnect failed: {result['error']}")
    
    def test_connection(self):
        """Test VPN connection"""
        self.log_message("Testing connection...")
        
        # Test both VPN types
        result1 = vpn_manager.test_connectivity()
        result2 = {"success": False, "error": "Python VPN removed"}
        
        # Use the successful result
        result = result1 if result1["success"] else result2
        
        if result["success"]:
            latency = result.get("latency")
            if latency:
                self.log_message(f"Connection test successful (latency: {latency}ms)")
            else:
                self.log_message("Connection test successful")
        else:
            self.log_message(f"Connection test failed: {result.get('error', 'Unknown error')}")
    
    def update_status(self):
        """Update connection status display"""
        # Skip updates while connecting
        if self.is_connecting:
            return
            
        # Check both VPN types
        openvpn_status = vpn_manager.get_status()
        python_status = {"connected": False}
        
        # Use whichever is connected
        status = openvpn_status if openvpn_status["connected"] else python_status
        
        if status["connected"]:
            self.status_label.setText("Connected")
            self.status_label.setStyleSheet("color: #00AA00; font-weight: bold; font-size: 14pt;")
            
            if status["connection"]:
                conn = status["connection"]
                if conn["type"] == "openvpn":
                    details = f"OpenVPN - {conn.get('config', 'Unknown config')}"
                    if conn.get("username"):
                        details += f" (User: {conn['username']})"
                else:
                    details = "Manual connection"
                self.status_details.setText(details)
            
            self.connect_btn.setEnabled(False)
            self.disconnect_btn.setEnabled(True)
            
        else:
            self.status_label.setText("Disconnected")
            self.status_label.setStyleSheet("color: #FF4444; font-weight: bold; font-size: 14pt;")
            self.status_details.setText("No active VPN connection")
            
            self.connect_btn.setEnabled(True)
            self.disconnect_btn.setEnabled(False)
    
    def on_status_changed(self, status, message):
        """Handle VPN status changes"""
        self.log_message(f"Status: {status} - {message}")
        
        if status == "connecting":
            self.status_label.setText("Connecting...")
            self.status_label.setStyleSheet("color: #FFAA00; font-weight: bold; font-size: 14pt;")
            self.status_details.setText(message)
            self.connect_btn.setEnabled(False)
            self.disconnect_btn.setEnabled(True)
        elif status == "connected":
            self.is_connecting = False
            self.status_label.setText("Connected")
            self.status_label.setStyleSheet("color: #00AA00; font-weight: bold; font-size: 14pt;")
        elif status == "error":
            self.is_connecting = False
            self.status_label.setText("Error")
            self.status_label.setStyleSheet("color: #FF4444; font-weight: bold; font-size: 14pt;")
            self.status_details.setText(message)
        elif status == "disconnected":
            self.is_connecting = False
            self.status_label.setText("Disconnected")
            self.status_label.setStyleSheet("color: #FF4444; font-weight: bold; font-size: 14pt;")
            self.status_details.setText("No active VPN connection")
            self.connect_btn.setEnabled(True)
            self.disconnect_btn.setEnabled(False)
    
    def log_message(self, message):
        """Add message to output log"""
        import datetime
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.output_text.append(f"[{timestamp}] {message}")
    
    def closeEvent(self, event):
        """Handle widget close"""
        self.status_timer.stop()
        event.accept()