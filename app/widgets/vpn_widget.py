# app/widgets/vpn_widget.py
import datetime
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QLineEdit, QComboBox, QTextEdit,
                             QFileDialog, QGroupBox, QSpinBox, QTabWidget,
                             QFrame, QSplitter, QFormLayout)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont
from app.core.vpn_manager import vpn_manager


class VPNWidget(QWidget):
    """VPN connection management widget"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("VPN Connection Manager")
        self.resize(1000, 600)
        self.setMinimumSize(800, 400)
        
        self.is_connecting = False
        
        self.setup_ui()
        self.connect_signals()
        self.update_status()
        
        # Status update timer
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_status)
        self.status_timer.start(2000)
    
    def setup_ui(self):
        """Setup the UI with side-by-side layout"""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(8)
        
        # Status bar at the top
        self._create_status_bar(main_layout)
        
        # Side-by-side: config (left) | log (right)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel: connection config
        left_panel = self._create_config_panel()
        splitter.addWidget(left_panel)
        
        # Right panel: connection log
        right_panel = self._create_log_panel()
        splitter.addWidget(right_panel)
        
        # Set initial split ratio (55% config, 45% log)
        splitter.setSizes([550, 450])
        
        main_layout.addWidget(splitter, 1)
    
    def _create_status_bar(self, parent_layout):
        """Create the compact status bar with connection state"""
        status_frame = QFrame()
        status_frame.setStyleSheet(
            "QFrame { background-color: rgba(30, 30, 50, 180); "
            "border-radius: 6px; padding: 4px; }"
        )
        status_layout = QHBoxLayout(status_frame)
        status_layout.setContentsMargins(12, 6, 12, 6)
        status_layout.setSpacing(12)
        
        # Status indicator
        self.status_label = QLabel("● Disconnected")
        self.status_label.setStyleSheet("color: #FF4444; font-weight: bold; font-size: 12pt;")
        status_layout.addWidget(self.status_label)
        
        self.status_details = QLabel("No active VPN connection")
        self.status_details.setStyleSheet("color: #AAAAAA; font-size: 9pt;")
        status_layout.addWidget(self.status_details)
        
        status_layout.addStretch()
        
        parent_layout.addWidget(status_frame)
    
    def _create_config_panel(self):
        """Create the left config panel with tabs and action buttons"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        self.tabs = QTabWidget()
        self._setup_config_tab()
        self._setup_manual_tab()
        
        # Action buttons as corner widget (sits next to tab labels)
        btn_widget = QWidget()
        btn_layout = QHBoxLayout(btn_widget)
        btn_layout.setContentsMargins(4, 0, 4, 0)
        btn_layout.setSpacing(6)
        
        self.connect_btn = QPushButton("Connect")
        self.connect_btn.setFixedWidth(90)
        self.connect_btn.setFixedHeight(26)
        self.connect_btn.setStyleSheet(
            "QPushButton { background-color: #2E7D32; color: white; "
            "border-radius: 4px; padding: 4px 8px; font-weight: bold; }"
            "QPushButton:hover { background-color: #388E3C; }"
            "QPushButton:disabled { background-color: #555555; color: #888888; }"
        )
        self.connect_btn.clicked.connect(self.connect_vpn)
        btn_layout.addWidget(self.connect_btn)
        
        self.disconnect_btn = QPushButton("Disconnect")
        self.disconnect_btn.setFixedWidth(120)
        self.disconnect_btn.setFixedHeight(26)
        self.disconnect_btn.setStyleSheet(
            "QPushButton { background-color: #C62828; color: white; "
            "border-radius: 4px; padding: 4px 8px; font-weight: bold; }"
            "QPushButton:hover { background-color: #D32F2F; }"
            "QPushButton:disabled { background-color: #555555; color: #888888; }"
        )
        self.disconnect_btn.clicked.connect(self.disconnect_vpn)
        self.disconnect_btn.setEnabled(False)
        btn_layout.addWidget(self.disconnect_btn)
        
        self.test_btn = QPushButton("Test")
        self.test_btn.setFixedWidth(55)
        self.test_btn.setFixedHeight(26)
        self.test_btn.setStyleSheet(
            "QPushButton { background-color: #1565C0; color: white; "
            "border-radius: 4px; padding: 4px 8px; }"
            "QPushButton:hover { background-color: #1976D2; }"
        )
        self.test_btn.clicked.connect(self.test_connection)
        btn_layout.addWidget(self.test_btn)
        
        self.tabs.setCornerWidget(btn_widget, Qt.Corner.TopRightCorner)
        
        layout.addWidget(self.tabs)
        
        return panel
    
    def _setup_config_tab(self):
        """Setup OpenVPN config file tab with form layout"""
        config_widget = QWidget()
        layout = QVBoxLayout(config_widget)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)
        
        # Config file row
        file_group = QGroupBox("Configuration File")
        file_layout = QHBoxLayout(file_group)
        file_layout.setContentsMargins(10, 14, 10, 10)
        
        self.config_file_input = QLineEdit()
        self.config_file_input.setPlaceholderText("Select .ovpn config file...")
        file_layout.addWidget(self.config_file_input)
        
        browse_btn = QPushButton("Browse")
        browse_btn.setFixedWidth(90)
        browse_btn.clicked.connect(self.browse_config_file)
        file_layout.addWidget(browse_btn)
        
        layout.addWidget(file_group)
        
        # Authentication section
        auth_group = QGroupBox("Authentication (Optional)")
        auth_form = QFormLayout(auth_group)
        auth_form.setContentsMargins(10, 14, 10, 10)
        auth_form.setSpacing(8)
        auth_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        
        self.config_username = QLineEdit()
        self.config_username.setPlaceholderText("Leave blank if not required")
        auth_form.addRow("Username:", self.config_username)
        
        self.config_password = QLineEdit()
        self.config_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.config_password.setPlaceholderText("Leave blank if not required")
        auth_form.addRow("Password:", self.config_password)
        
        layout.addWidget(auth_group)
        layout.addStretch()
        
        self.tabs.addTab(config_widget, "OpenVPN Config")
    
    def _setup_manual_tab(self):
        """Setup manual connection tab with form layout"""
        manual_widget = QWidget()
        layout = QVBoxLayout(manual_widget)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)
        
        # Server section
        server_group = QGroupBox("Server Settings")
        server_form = QFormLayout(server_group)
        server_form.setContentsMargins(10, 14, 10, 10)
        server_form.setSpacing(8)
        server_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        
        self.manual_server = QLineEdit()
        self.manual_server.setPlaceholderText("vpn.example.com")
        server_form.addRow("Server:", self.manual_server)
        
        # Port and protocol on one row
        port_proto_widget = QWidget()
        port_proto_layout = QHBoxLayout(port_proto_widget)
        port_proto_layout.setContentsMargins(0, 0, 0, 0)
        port_proto_layout.setSpacing(10)
        
        self.manual_port = QSpinBox()
        self.manual_port.setRange(1, 65535)
        self.manual_port.setValue(1194)
        self.manual_port.setFixedWidth(100)
        port_proto_layout.addWidget(self.manual_port)
        
        port_proto_layout.addWidget(QLabel("Protocol:"))
        self.manual_protocol = QComboBox()
        self.manual_protocol.addItems(["UDP", "TCP"])
        self.manual_protocol.setFixedWidth(80)
        port_proto_layout.addWidget(self.manual_protocol)
        port_proto_layout.addStretch()
        
        server_form.addRow("Port:", port_proto_widget)
        
        layout.addWidget(server_group)
        
        # Authentication section
        auth_group = QGroupBox("Authentication")
        auth_form = QFormLayout(auth_group)
        auth_form.setContentsMargins(10, 14, 10, 10)
        auth_form.setSpacing(8)
        auth_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        
        self.manual_username = QLineEdit()
        self.manual_username.setPlaceholderText("VPN username")
        auth_form.addRow("Username:", self.manual_username)
        
        self.manual_password = QLineEdit()
        self.manual_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.manual_password.setPlaceholderText("VPN password")
        auth_form.addRow("Password:", self.manual_password)
        
        layout.addWidget(auth_group)
        layout.addStretch()
        
        self.tabs.addTab(manual_widget, "Manual Setup")
    
    def _create_log_panel(self):
        """Create the right log panel"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        log_group = QGroupBox("Connection Log")
        log_layout = QVBoxLayout(log_group)
        log_layout.setContentsMargins(8, 14, 8, 8)
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setStyleSheet(
            "QTextEdit { background-color: #1a1a2e; color: #e0e0e0; "
            "font-family: 'Neuropol X', 'Neuropol', sans-serif; font-size: 9pt; "
            "border: none; }"
        )
        log_layout.addWidget(self.output_text)
        
        # Clear button at bottom of log
        clear_btn = QPushButton("Clear Log")
        clear_btn.setFixedHeight(24)
        clear_btn.setStyleSheet(
            "QPushButton { background-color: #333; color: #aaa; border-radius: 3px; font-size: 8pt; }"
            "QPushButton:hover { background-color: #444; color: #fff; }"
        )
        clear_btn.clicked.connect(self.output_text.clear)
        log_layout.addWidget(clear_btn)
        
        layout.addWidget(log_group)
        return panel
    
    def connect_signals(self):
        """Connect VPN manager signals"""
        vpn_manager.connection_status_changed.connect(self.on_status_changed)
    
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
        self.is_connecting = True
        self.status_label.setText("● Connecting...")
        self.status_label.setStyleSheet("color: #FFAA00; font-weight: bold; font-size: 12pt;")
        self.status_details.setText("Establishing VPN connection...")
        self.connect_btn.setEnabled(False)
        self.disconnect_btn.setEnabled(True)
        
        current_tab = self.tabs.currentIndex()
        
        if current_tab == 0:  # OpenVPN config
            config_file = self.config_file_input.text().strip()
            if not config_file:
                self.log_message("Please select a config file")
                self._reset_connecting_state()
                return
            
            username = self.config_username.text().strip()
            password = self.config_password.text().strip()
            result = vpn_manager.connect_openvpn(config_file, username, password)
            
        elif current_tab == 1:  # Manual setup
            server = self.manual_server.text().strip()
            if not server:
                self.log_message("Please enter server address")
                self._reset_connecting_state()
                return
            
            port = self.manual_port.value()
            protocol = self.manual_protocol.currentText()
            username = self.manual_username.text().strip()
            password = self.manual_password.text().strip()
            
            if not username or not password:
                self.log_message("Please enter username and password")
                self._reset_connecting_state()
                return
            
            result = vpn_manager.connect_manual(server, port, protocol, username, password)
        else:
            self.log_message("Unknown tab selected")
            self._reset_connecting_state()
            return
        
        if result["success"]:
            self.log_message(result["message"])
        else:
            self.log_message(f"Connection failed: {result['error']}")
            self._reset_connecting_state()
    
    def _reset_connecting_state(self):
        """Reset UI state when connection attempt fails immediately"""
        self.is_connecting = False
        self.connect_btn.setEnabled(True)
        self.disconnect_btn.setEnabled(False)
        self.status_label.setText("● Disconnected")
        self.status_label.setStyleSheet("color: #FF4444; font-weight: bold; font-size: 12pt;")
        self.status_details.setText("No active VPN connection")
    
    def disconnect_vpn(self):
        """Disconnect VPN"""
        result = vpn_manager.disconnect()
        if result["success"]:
            self.log_message(result["message"])
            self.connect_btn.setEnabled(True)
            self.disconnect_btn.setEnabled(False)
        else:
            self.log_message(f"Disconnect failed: {result['error']}")
    
    def test_connection(self):
        """Test VPN connection"""
        self.log_message("Testing connection...")
        result = vpn_manager.test_connectivity()
        
        if result["success"]:
            latency = result.get("latency")
            if latency:
                self.log_message(f"Connection OK (latency: {latency}ms)")
            else:
                self.log_message("Connection OK")
        else:
            self.log_message(f"Test failed: {result.get('error', 'Unknown error')}")
    
    def update_status(self):
        """Update connection status display"""
        if self.is_connecting:
            return
        
        status = vpn_manager.get_status()
        
        if status["connected"]:
            vpn_ip = status.get("vpn_ip")
            if vpn_ip:
                self.status_label.setText(f"● Connected — {vpn_ip}")
            else:
                self.status_label.setText("● Connected")
            self.status_label.setStyleSheet("color: #00CC00; font-weight: bold; font-size: 12pt;")
            
            if status["connection"]:
                conn = status["connection"]
                if conn["type"] == "openvpn":
                    import os
                    config_name = os.path.basename(conn.get('config', 'Unknown'))
                    details = f"OpenVPN — {config_name}"
                else:
                    details = "Manual connection"
                self.status_details.setText(details)
            
            self.connect_btn.setEnabled(False)
            self.disconnect_btn.setEnabled(True)
        elif status.get("process_running"):
            # Process is alive but not yet connected — still connecting
            self.status_label.setText("● Connecting...")
            self.status_label.setStyleSheet("color: #FFAA00; font-weight: bold; font-size: 12pt;")
            self.connect_btn.setEnabled(False)
            self.disconnect_btn.setEnabled(True)
        else:
            self.status_label.setText("● Disconnected")
            self.status_label.setStyleSheet("color: #FF4444; font-weight: bold; font-size: 12pt;")
            self.status_details.setText("No active VPN connection")
            self.connect_btn.setEnabled(True)
            self.disconnect_btn.setEnabled(False)
    
    def on_status_changed(self, status, message):
        """Handle VPN status changes"""
        self.log_message(f"Status: {status} - {message}")
        
        if status == "connecting":
            self.status_label.setText("● Connecting...")
            self.status_label.setStyleSheet("color: #FFAA00; font-weight: bold; font-size: 12pt;")
            self.status_details.setText(message)
            self.connect_btn.setEnabled(False)
            self.disconnect_btn.setEnabled(True)
        elif status == "connected":
            self.is_connecting = False
            vpn_ip = vpn_manager.vpn_ip
            if vpn_ip:
                self.status_label.setText(f"● Connected — {vpn_ip}")
            else:
                self.status_label.setText("● Connected")
            self.status_label.setStyleSheet("color: #00CC00; font-weight: bold; font-size: 12pt;")
            self.status_details.setText(message)
        elif status == "error":
            self.is_connecting = False
            self.status_label.setText("● Error")
            self.status_label.setStyleSheet("color: #FF4444; font-weight: bold; font-size: 12pt;")
            self.status_details.setText(message)
            self.connect_btn.setEnabled(True)
            self.disconnect_btn.setEnabled(False)
        elif status == "disconnected":
            self.is_connecting = False
            self.status_label.setText("● Disconnected")
            self.status_label.setStyleSheet("color: #FF4444; font-weight: bold; font-size: 12pt;")
            self.status_details.setText("No active VPN connection")
            self.connect_btn.setEnabled(True)
            self.disconnect_btn.setEnabled(False)
    
    def log_message(self, message):
        """Add message to output log"""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.output_text.append(f"[{timestamp}] {message}")
    
    def closeEvent(self, event):
        """Handle widget close"""
        self.status_timer.stop()
        event.accept()
