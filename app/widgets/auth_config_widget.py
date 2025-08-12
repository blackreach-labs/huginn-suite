# app/widgets/auth_config_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, 
                            QComboBox, QLineEdit, QTextEdit, QPushButton, 
                            QLabel, QCheckBox, QTabWidget, QFormLayout,
                            QTableWidget, QTableWidgetItem, QHeaderView,
                            QFileDialog, QMessageBox, QSpinBox)
from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtGui import QFont
import json
import base64
from ..core.credential_manager import credential_manager

class AuthConfigWidget(QWidget):
    """Widget for configuring authentication settings"""
    
    auth_configured = pyqtSignal(dict)  # Emits auth configuration
    
    def __init__(self):
        super().__init__()
        self.auth_config = {}
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Title
        title = QLabel("🔐 Authentication Configuration")
        title.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        title.setStyleSheet("color: #00FF41; margin-bottom: 10px;")
        layout.addWidget(title)
        
        # Tab widget for different auth methods
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)
        
        # Setup tabs
        self.setup_session_replay_tab()
        self.setup_form_login_tab()
        self.setup_header_auth_tab()
        self.setup_basic_auth_tab()
        self.setup_advanced_tab()
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        self.test_auth_btn = QPushButton("🧪 Test Authentication")
        self.test_auth_btn.clicked.connect(self.test_authentication)
        button_layout.addWidget(self.test_auth_btn)
        
        self.save_config_btn = QPushButton("💾 Save Config")
        self.save_config_btn.clicked.connect(self.save_configuration)
        button_layout.addWidget(self.save_config_btn)
        
        self.load_config_btn = QPushButton("📁 Load Config")
        self.load_config_btn.clicked.connect(self.load_configuration)
        button_layout.addWidget(self.load_config_btn)
        
        self.apply_btn = QPushButton("✅ Apply Authentication")
        self.apply_btn.clicked.connect(self.apply_authentication)
        self.apply_btn.setStyleSheet("background-color: #00FF41; color: black; font-weight: bold;")
        button_layout.addWidget(self.apply_btn)
        
        layout.addLayout(button_layout)
        
    def setup_session_replay_tab(self):
        """Setup session replay authentication tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Description
        desc = QLabel("Use existing session cookies to authenticate")
        desc.setStyleSheet("color: #87CEEB; font-style: italic;")
        layout.addWidget(desc)
        
        # Cookie input methods
        cookie_group = QGroupBox("Cookie Input Methods")
        cookie_layout = QVBoxLayout(cookie_group)
        
        # Manual cookie entry
        manual_group = QGroupBox("Manual Cookie Entry")
        manual_layout = QFormLayout(manual_group)
        
        self.cookie_text = QTextEdit()
        self.cookie_text.setPlaceholderText("Enter cookies in format:\nname1=value1; name2=value2\n\nOr JSON format:\n{\"name1\": \"value1\", \"name2\": \"value2\"}")
        self.cookie_text.setMaximumHeight(100)
        manual_layout.addRow("Cookies:", self.cookie_text)
        
        cookie_layout.addWidget(manual_group)
        
        # Browser import
        browser_group = QGroupBox("Browser Cookie Import")
        browser_layout = QHBoxLayout(browser_group)
        
        self.import_browser_btn = QPushButton("📥 Import from Browser")
        self.import_browser_btn.clicked.connect(self.import_browser_cookies)
        browser_layout.addWidget(self.import_browser_btn)
        
        self.import_har_btn = QPushButton("📄 Import from HAR file")
        self.import_har_btn.clicked.connect(self.import_har_cookies)
        browser_layout.addWidget(self.import_har_btn)
        
        cookie_layout.addWidget(browser_group)
        layout.addWidget(cookie_group)
        
        # Cookie table for viewing/editing
        self.cookie_table = QTableWidget()
        self.cookie_table.setColumnCount(2)
        self.cookie_table.setHorizontalHeaderLabels(["Cookie Name", "Cookie Value"])
        self.cookie_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.cookie_table)
        
        self.tab_widget.addTab(tab, "🍪 Session Replay")
        
    def setup_form_login_tab(self):
        """Setup form-based login tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Description
        desc = QLabel("Automatically detect and submit login forms")
        desc.setStyleSheet("color: #87CEEB; font-style: italic;")
        layout.addWidget(desc)
        
        # Login credentials
        creds_group = QGroupBox("Login Credentials")
        creds_layout = QFormLayout(creds_group)
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter username/email")
        creds_layout.addRow("Username:", self.username_input)
        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Enter password")
        creds_layout.addRow("Password:", self.password_input)
        
        # Credential manager integration
        cred_buttons = QHBoxLayout()
        
        self.load_creds_btn = QPushButton("📋 Load from Credential Manager")
        self.load_creds_btn.clicked.connect(lambda: self.load_stored_credentials('Credentials'))
        cred_buttons.addWidget(self.load_creds_btn)
        
        self.save_creds_btn = QPushButton("💾 Save to Credential Manager")
        self.save_creds_btn.clicked.connect(self.save_credentials)
        cred_buttons.addWidget(self.save_creds_btn)
        
        creds_layout.addRow(cred_buttons)
        layout.addWidget(creds_group)
        
        # Advanced form options
        form_group = QGroupBox("Form Detection Options")
        form_layout = QFormLayout(form_group)
        
        self.auto_detect_cb = QCheckBox("Auto-detect login forms")
        self.auto_detect_cb.setChecked(True)
        form_layout.addRow(self.auto_detect_cb)
        
        self.handle_csrf_cb = QCheckBox("Handle CSRF tokens automatically")
        self.handle_csrf_cb.setChecked(True)
        form_layout.addRow(self.handle_csrf_cb)
        
        self.follow_redirects_cb = QCheckBox("Follow login redirects")
        self.follow_redirects_cb.setChecked(True)
        form_layout.addRow(self.follow_redirects_cb)
        
        layout.addWidget(form_group)
        
        self.tab_widget.addTab(tab, "📝 Form Login")
        
    def setup_header_auth_tab(self):
        """Setup header-based authentication tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Description
        desc = QLabel("Use custom headers for API authentication")
        desc.setStyleSheet("color: #87CEEB; font-style: italic;")
        layout.addWidget(desc)
        
        # Common auth types
        auth_type_group = QGroupBox("Authentication Type")
        auth_type_layout = QVBoxLayout(auth_type_group)
        
        self.auth_type_combo = QComboBox()
        self.auth_type_combo.addItems([
            "Custom Headers",
            "Bearer Token",
            "API Key",
            "JWT Token",
            "OAuth2 Token"
        ])
        self.auth_type_combo.currentTextChanged.connect(self.on_auth_type_changed)
        auth_type_layout.addWidget(self.auth_type_combo)
        
        layout.addWidget(auth_type_group)
        
        # Token input
        token_group = QGroupBox("Token/Key Input")
        token_layout = QFormLayout(token_group)
        
        self.token_input = QLineEdit()
        self.token_input.setPlaceholderText("Enter your token/API key")
        token_layout.addRow("Token/Key:", self.token_input)
        
        self.header_name_input = QLineEdit()
        self.header_name_input.setPlaceholderText("Authorization")
        token_layout.addRow("Header Name:", self.header_name_input)
        
        layout.addWidget(token_group)
        
        # Custom headers table
        headers_group = QGroupBox("Custom Headers")
        headers_layout = QVBoxLayout(headers_group)
        
        self.headers_table = QTableWidget()
        self.headers_table.setColumnCount(2)
        self.headers_table.setHorizontalHeaderLabels(["Header Name", "Header Value"])
        self.headers_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        headers_layout.addWidget(self.headers_table)
        
        # Header control buttons
        header_buttons = QHBoxLayout()
        
        self.add_header_btn = QPushButton("➕ Add Header")
        self.add_header_btn.clicked.connect(self.add_custom_header)
        header_buttons.addWidget(self.add_header_btn)
        
        self.remove_header_btn = QPushButton("➖ Remove Header")
        self.remove_header_btn.clicked.connect(self.remove_custom_header)
        header_buttons.addWidget(self.remove_header_btn)
        
        headers_layout.addLayout(header_buttons)
        layout.addWidget(headers_group)
        
        self.tab_widget.addTab(tab, "🔑 Header Auth")
        
    def setup_basic_auth_tab(self):
        """Setup HTTP Basic Authentication tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Description
        desc = QLabel("HTTP Basic Authentication (RFC 7617)")
        desc.setStyleSheet("color: #87CEEB; font-style: italic;")
        layout.addWidget(desc)
        
        # Basic auth credentials
        basic_group = QGroupBox("Basic Authentication Credentials")
        basic_layout = QFormLayout(basic_group)
        
        self.basic_username = QLineEdit()
        self.basic_username.setPlaceholderText("Enter username")
        basic_layout.addRow("Username:", self.basic_username)
        
        self.basic_password = QLineEdit()
        self.basic_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.basic_password.setPlaceholderText("Enter password")
        basic_layout.addRow("Password:", self.basic_password)
        
        # Preview encoded credentials
        self.basic_preview = QLineEdit()
        self.basic_preview.setReadOnly(True)
        self.basic_preview.setPlaceholderText("Base64 encoded credentials will appear here")
        basic_layout.addRow("Encoded:", self.basic_preview)
        
        # Update preview when credentials change
        self.basic_username.textChanged.connect(self.update_basic_preview)
        self.basic_password.textChanged.connect(self.update_basic_preview)
        
        layout.addWidget(basic_group)
        
        self.tab_widget.addTab(tab, "🔐 Basic Auth")
        
    def setup_advanced_tab(self):
        """Setup advanced authentication options"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Description
        desc = QLabel("Advanced authentication and session management")
        desc.setStyleSheet("color: #87CEEB; font-style: italic;")
        layout.addWidget(desc)
        
        # Session management
        session_group = QGroupBox("Session Management")
        session_layout = QFormLayout(session_group)
        
        self.session_timeout = QSpinBox()
        self.session_timeout.setRange(30, 3600)
        self.session_timeout.setValue(300)
        self.session_timeout.setSuffix(" seconds")
        session_layout.addRow("Session Timeout:", self.session_timeout)
        
        self.keep_alive_cb = QCheckBox("Keep session alive")
        self.keep_alive_cb.setChecked(True)
        session_layout.addRow(self.keep_alive_cb)
        
        self.auto_refresh_cb = QCheckBox("Auto-refresh tokens")
        session_layout.addRow(self.auto_refresh_cb)
        
        layout.addWidget(session_group)
        
        # Proxy settings
        proxy_group = QGroupBox("Proxy Settings")
        proxy_layout = QFormLayout(proxy_group)
        
        self.use_proxy_cb = QCheckBox("Use proxy for authentication")
        proxy_layout.addRow(self.use_proxy_cb)
        
        self.proxy_url = QLineEdit()
        self.proxy_url.setPlaceholderText("http://proxy:8080")
        self.proxy_url.setEnabled(False)
        proxy_layout.addRow("Proxy URL:", self.proxy_url)
        
        self.use_proxy_cb.toggled.connect(self.proxy_url.setEnabled)
        
        layout.addWidget(proxy_group)
        
        # Export/Import session
        export_group = QGroupBox("Session Export/Import")
        export_layout = QHBoxLayout(export_group)
        
        self.export_session_btn = QPushButton("📤 Export Session")
        self.export_session_btn.clicked.connect(self.export_auth_session)
        export_layout.addWidget(self.export_session_btn)
        
        self.import_session_btn = QPushButton("📥 Import Session")
        self.import_session_btn.clicked.connect(self.import_auth_session)
        export_layout.addWidget(self.import_session_btn)
        
        layout.addWidget(export_group)
        
        self.tab_widget.addTab(tab, "⚙️ Advanced")
        
    def on_auth_type_changed(self, auth_type):
        """Handle authentication type change"""
        if auth_type == "Bearer Token":
            self.header_name_input.setText("Authorization")
            self.token_input.setPlaceholderText("Enter Bearer token (without 'Bearer ' prefix)")
        elif auth_type == "API Key":
            self.header_name_input.setText("X-API-Key")
            self.token_input.setPlaceholderText("Enter API key")
        elif auth_type == "JWT Token":
            self.header_name_input.setText("Authorization")
            self.token_input.setPlaceholderText("Enter JWT token")
        else:
            self.header_name_input.setText("")
            self.token_input.setPlaceholderText("Enter token/key value")
    
    def update_basic_preview(self):
        """Update Basic Auth preview"""
        username = self.basic_username.text()
        password = self.basic_password.text()
        
        if username and password:
            credentials = f"{username}:{password}"
            encoded = base64.b64encode(credentials.encode()).decode()
            self.basic_preview.setText(f"Basic {encoded}")
        else:
            self.basic_preview.clear()
    
    def add_custom_header(self):
        """Add custom header to table"""
        row = self.headers_table.rowCount()
        self.headers_table.insertRow(row)
        self.headers_table.setItem(row, 0, QTableWidgetItem(""))
        self.headers_table.setItem(row, 1, QTableWidgetItem(""))
    
    def remove_custom_header(self):
        """Remove selected header from table"""
        current_row = self.headers_table.currentRow()
        if current_row >= 0:
            self.headers_table.removeRow(current_row)
    
    def import_browser_cookies(self):
        """Import cookies from browser (placeholder)"""
        QMessageBox.information(self, "Browser Import", 
                               "Browser cookie import feature coming soon!\n\n"
                               "For now, please copy cookies manually from browser DevTools.")
    
    def import_har_cookies(self):
        """Import cookies from HAR file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Import HAR File", "", "HAR Files (*.har);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    har_data = json.load(f)
                
                cookies = {}
                # Extract cookies from HAR file
                for entry in har_data.get('log', {}).get('entries', []):
                    for cookie in entry.get('request', {}).get('cookies', []):
                        cookies[cookie['name']] = cookie['value']
                
                if cookies:
                    self.populate_cookie_table(cookies)
                    QMessageBox.information(self, "Success", 
                                          f"Imported {len(cookies)} cookies from HAR file")
                else:
                    QMessageBox.warning(self, "No Cookies", "No cookies found in HAR file")
                    
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to import HAR file: {str(e)}")
    
    def populate_cookie_table(self, cookies):
        """Populate cookie table with cookies"""
        self.cookie_table.setRowCount(len(cookies))
        for row, (name, value) in enumerate(cookies.items()):
            self.cookie_table.setItem(row, 0, QTableWidgetItem(name))
            self.cookie_table.setItem(row, 1, QTableWidgetItem(value))
    
    def load_stored_credentials(self, auth_type='Credentials'):
        """Load credentials from credential manager based on auth type"""
        # Filter credentials based on auth type
        filtered_credentials = credential_manager.get_credentials_by_auth_type(auth_type)
        
        if filtered_credentials:
            # Show selection dialog if multiple credentials
            if len(filtered_credentials) > 1:
                from PyQt6.QtWidgets import QInputDialog
                items = [f"{cred.username}@{cred.domain} ({cred.service})" if cred.domain else f"{cred.username} ({cred.service})" for cred in filtered_credentials]
                item, ok = QInputDialog.getItem(self, "Select Credential", "Choose credential:", items, 0, False)
                if ok:
                    selected_index = items.index(item)
                    selected_cred = filtered_credentials[selected_index]
                else:
                    return
            else:
                selected_cred = filtered_credentials[0]
            
            # Load credential based on type
            if auth_type in ['Credentials', 'Kerberos Password']:
                self.username_input.setText(selected_cred.username)
                self.password_input.setText(selected_cred.password)
            elif auth_type == 'Pass-the-Hash':
                self.username_input.setText(selected_cred.username)
                self.password_input.setText(selected_cred.password)  # NTLM hash stored as password
            elif auth_type == 'Kerberos Ticket':
                # For Kerberos ticket, the ticket file path is stored as password
                self.username_input.setText("")
                self.password_input.setText(selected_cred.password)  # Ticket file path
            
            QMessageBox.information(self, "Loaded", f"Loaded credential: {selected_cred.username or 'Ticket'}")
        else:
            QMessageBox.information(self, "No Credentials", "No Username/Password credentials found in manager")
    
    def set_auth_type(self, auth_type: str):
        """Set the current auth type for credential filtering"""
        self.current_auth_type = auth_type
    
    def save_credentials(self):
        """Save credentials to credential manager"""
        username = self.username_input.text()
        password = self.password_input.text()
        
        if username and password:
            credential_manager.add_credential(
                username=username,
                password=password,
                service="web_authentication",
                source="auth_config_widget"
            )
            QMessageBox.information(self, "Saved", "Credentials saved to manager")
        else:
            QMessageBox.warning(self, "Invalid", "Please enter both username and password")
    
    def test_authentication(self):
        """Test authentication configuration"""
        config = self.get_auth_config()
        if config:
            # This would integrate with the authenticated crawler for testing
            QMessageBox.information(self, "Test", 
                                   f"Testing authentication with method: {config['method']}")
        else:
            QMessageBox.warning(self, "No Config", "Please configure authentication first")
    
    def save_configuration(self):
        """Save authentication configuration to file"""
        config = self.get_auth_config()
        if config:
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Save Auth Config", "auth_config.json", "JSON Files (*.json)"
            )
            if file_path:
                try:
                    with open(file_path, 'w') as f:
                        json.dump(config, f, indent=2)
                    QMessageBox.information(self, "Saved", "Configuration saved successfully")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to save: {str(e)}")
    
    def load_configuration(self):
        """Load authentication configuration from file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Load Auth Config", "", "JSON Files (*.json);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    config = json.load(f)
                self.set_auth_config(config)
                QMessageBox.information(self, "Loaded", "Configuration loaded successfully")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load: {str(e)}")
    
    def export_auth_session(self):
        """Export authentication session"""
        QMessageBox.information(self, "Export", "Session export feature coming soon!")
    
    def import_auth_session(self):
        """Import authentication session"""
        QMessageBox.information(self, "Import", "Session import feature coming soon!")
    
    def get_auth_config(self) -> dict:
        """Get current authentication configuration"""
        current_tab = self.tab_widget.currentIndex()
        
        if current_tab == 0:  # Session Replay
            cookies = {}
            for row in range(self.cookie_table.rowCount()):
                name_item = self.cookie_table.item(row, 0)
                value_item = self.cookie_table.item(row, 1)
                if name_item and value_item:
                    cookies[name_item.text()] = value_item.text()
            
            return {
                'method': 'session_replay',
                'cookies': cookies
            }
            
        elif current_tab == 1:  # Form Login
            return {
                'method': 'form_login',
                'username': self.username_input.text(),
                'password': self.password_input.text(),
                'auto_detect': self.auto_detect_cb.isChecked(),
                'handle_csrf': self.handle_csrf_cb.isChecked(),
                'follow_redirects': self.follow_redirects_cb.isChecked()
            }
            
        elif current_tab == 2:  # Header Auth
            headers = {}
            
            # Add main token/key
            token = self.token_input.text()
            header_name = self.header_name_input.text()
            auth_type = self.auth_type_combo.currentText()
            
            if token and header_name:
                if auth_type == "Bearer Token":
                    headers[header_name] = f"Bearer {token}"
                else:
                    headers[header_name] = token
            
            # Add custom headers
            for row in range(self.headers_table.rowCount()):
                name_item = self.headers_table.item(row, 0)
                value_item = self.headers_table.item(row, 1)
                if name_item and value_item and name_item.text() and value_item.text():
                    headers[name_item.text()] = value_item.text()
            
            return {
                'method': 'header_auth',
                'headers': headers,
                'auth_type': auth_type
            }
            
        elif current_tab == 3:  # Basic Auth
            return {
                'method': 'basic_auth',
                'username': self.basic_username.text(),
                'password': self.basic_password.text()
            }
        
        return {}
    
    def set_auth_config(self, config: dict):
        """Set authentication configuration"""
        method = config.get('method', '')
        
        if method == 'session_replay':
            self.tab_widget.setCurrentIndex(0)
            cookies = config.get('cookies', {})
            self.populate_cookie_table(cookies)
            
        elif method == 'form_login':
            self.tab_widget.setCurrentIndex(1)
            self.username_input.setText(config.get('username', ''))
            self.password_input.setText(config.get('password', ''))
            self.auto_detect_cb.setChecked(config.get('auto_detect', True))
            self.handle_csrf_cb.setChecked(config.get('handle_csrf', True))
            self.follow_redirects_cb.setChecked(config.get('follow_redirects', True))
            
        elif method == 'header_auth':
            self.tab_widget.setCurrentIndex(2)
            headers = config.get('headers', {})
            auth_type = config.get('auth_type', 'Custom Headers')
            self.auth_type_combo.setCurrentText(auth_type)
            
            # Populate headers table
            self.headers_table.setRowCount(len(headers))
            for row, (name, value) in enumerate(headers.items()):
                self.headers_table.setItem(row, 0, QTableWidgetItem(name))
                self.headers_table.setItem(row, 1, QTableWidgetItem(value))
                
        elif method == 'basic_auth':
            self.tab_widget.setCurrentIndex(3)
            self.basic_username.setText(config.get('username', ''))
            self.basic_password.setText(config.get('password', ''))
    
    def apply_authentication(self):
        """Apply authentication configuration"""
        config = self.get_auth_config()
        if config:
            self.auth_config = config
            self.auth_configured.emit(config)
            QMessageBox.information(self, "Applied", 
                                   f"Authentication configured with method: {config['method']}")
        else:
            QMessageBox.warning(self, "No Config", "Please configure authentication first")
    
    def get_current_config(self) -> dict:
        """Get current authentication configuration"""
        return self.auth_config