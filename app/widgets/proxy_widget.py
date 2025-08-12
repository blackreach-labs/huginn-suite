# app/widgets/proxy_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QLineEdit, QPushButton, QCheckBox, QComboBox, QGroupBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from app.core.proxy_manager import proxy_manager

class ProxyTestWorker(QThread):
    """Worker thread for proxy testing"""
    result = pyqtSignal(bool, str)
    
    def run(self):
        success, message = proxy_manager.test_proxy()
        self.result.emit(success, message)

class ProxyWidget(QWidget):
    """Widget for proxy configuration"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.test_worker = None
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Proxy group
        proxy_group = QGroupBox("🌐 Proxy Configuration")
        proxy_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                color: #64C8FF;
                border: 2px solid #555;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)
        
        proxy_layout = QVBoxLayout(proxy_group)
        
        # Enable checkbox
        self.enable_checkbox = QCheckBox("Enable Proxy")
        self.enable_checkbox.setStyleSheet("color: #DCDCDC; font-size: 11pt;")
        self.enable_checkbox.toggled.connect(self.toggle_proxy)
        
        # Proxy type
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Type:"))
        self.proxy_type = QComboBox()
        self.proxy_type.addItems(["HTTP/HTTPS", "SOCKS5"])
        self.proxy_type.setFixedWidth(120)
        type_layout.addWidget(self.proxy_type)
        type_layout.addStretch()
        
        # Proxy URL
        url_layout = QHBoxLayout()
        url_layout.addWidget(QLabel("Proxy URL:"))
        self.proxy_url = QLineEdit()
        self.proxy_url.setPlaceholderText("http://proxy.example.com:8080")
        self.proxy_url.setStyleSheet(self._get_input_style())
        url_layout.addWidget(self.proxy_url)
        
        # Authentication
        auth_layout = QHBoxLayout()
        auth_layout.addWidget(QLabel("Username:"))
        self.username = QLineEdit()
        self.username.setFixedWidth(120)
        self.username.setStyleSheet(self._get_input_style())
        auth_layout.addWidget(self.username)
        
        auth_layout.addWidget(QLabel("Password:"))
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setFixedWidth(120)
        self.password.setStyleSheet(self._get_input_style())
        auth_layout.addWidget(self.password)
        auth_layout.addStretch()
        
        # Buttons
        button_layout = QHBoxLayout()
        self.test_button = QPushButton("🔍 Test Proxy")
        self.test_button.clicked.connect(self.test_proxy)
        self.test_button.setEnabled(False)
        
        self.apply_button = QPushButton("✅ Apply")
        self.apply_button.clicked.connect(self.apply_proxy)
        self.apply_button.setEnabled(False)
        
        button_style = """
            QPushButton {
                background-color: rgba(100, 200, 255, 150);
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 16px;
                font-size: 10pt;
            }
            QPushButton:hover {
                background-color: rgba(100, 200, 255, 200);
            }
            QPushButton:disabled {
                background-color: rgba(60, 60, 60, 100);
                color: #888;
            }
        """
        self.test_button.setStyleSheet(button_style)
        self.apply_button.setStyleSheet(button_style)
        
        button_layout.addWidget(self.test_button)
        button_layout.addWidget(self.apply_button)
        button_layout.addStretch()
        
        # Status label
        self.status_label = QLabel("Proxy disabled")
        self.status_label.setStyleSheet("color: #888; font-size: 10pt; padding: 5px;")
        
        # Add to proxy layout
        proxy_layout.addWidget(self.enable_checkbox)
        proxy_layout.addLayout(type_layout)
        proxy_layout.addLayout(url_layout)
        proxy_layout.addLayout(auth_layout)
        proxy_layout.addLayout(button_layout)
        proxy_layout.addWidget(self.status_label)
        
        layout.addWidget(proxy_group)
        layout.addStretch()
        
    def _get_input_style(self):
        return """
            QLineEdit {
                background-color: rgba(20, 30, 40, 180);
                border: 1px solid #555;
                border-radius: 4px;
                color: #DCDCDC;
                padding: 4px 8px;
                font-size: 10pt;
            }
            QLineEdit:focus {
                border: 2px solid #64C8FF;
            }
        """
    
    def toggle_proxy(self, enabled):
        """Toggle proxy controls"""
        self.proxy_type.setEnabled(enabled)
        self.proxy_url.setEnabled(enabled)
        self.username.setEnabled(enabled)
        self.password.setEnabled(enabled)
        self.test_button.setEnabled(enabled)
        self.apply_button.setEnabled(enabled)
        
        if not enabled:
            proxy_manager.disable()
            self.status_label.setText("Proxy disabled")
            self.status_label.setStyleSheet("color: #888; font-size: 10pt; padding: 5px;")
    
    def apply_proxy(self):
        """Apply proxy settings"""
        if not self.enable_checkbox.isChecked():
            return
        
        proxy_url = self.proxy_url.text().strip()
        if not proxy_url:
            self.status_label.setText("❌ Please enter proxy URL")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
            return
        
        proxy_type = 'http' if self.proxy_type.currentText() == 'HTTP/HTTPS' else 'socks'
        username = self.username.text().strip()
        password = self.password.text().strip()
        
        proxy_manager.set_proxy(proxy_type, proxy_url, username, password)
        
        self.status_label.setText("✅ Proxy configured")
        self.status_label.setStyleSheet("color: #00AA00; font-size: 10pt; padding: 5px;")
    
    def test_proxy(self):
        """Test proxy connection"""
        if not self.enable_checkbox.isChecked():
            return
        
        # Apply settings first
        self.apply_proxy()
        
        if not proxy_manager.is_enabled():
            return
        
        self.test_button.setEnabled(False)
        self.status_label.setText("🔍 Testing proxy...")
        self.status_label.setStyleSheet("color: #FFAA00; font-size: 10pt; padding: 5px;")
        
        # Start test worker
        self.test_worker = ProxyTestWorker()
        self.test_worker.result.connect(self.on_test_result)
        self.test_worker.start()
    
    def on_test_result(self, success, message):
        """Handle proxy test result"""
        self.test_button.setEnabled(True)
        
        if success:
            self.status_label.setText(f"✅ {message}")
            self.status_label.setStyleSheet("color: #00AA00; font-size: 10pt; padding: 5px;")
        else:
            self.status_label.setText(f"❌ {message}")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")