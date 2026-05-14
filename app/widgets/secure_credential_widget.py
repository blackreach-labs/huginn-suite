# app/widgets/secure_credential_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                            QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
                            QComboBox, QTextEdit, QGroupBox, QTabWidget,
                            QMessageBox, QProgressBar, QCheckBox, QFormLayout,
                            QDialog, QDialogButtonBox, QHeaderView, QFrame,
                            QSizePolicy, QGridLayout, QScrollArea)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QIcon
from ..core.secure_credential_manager import secure_credential_manager

class CredentialTestWorker(QThread):
    """Worker thread for testing credentials"""
    test_completed = pyqtSignal(str, dict)
    
    def __init__(self, service):
        super().__init__()
        self.service = service
    
    def run(self):
        result = secure_credential_manager.test_credential(self.service)
        self.test_completed.emit(self.service, result)

class SecretsManagerDialog(QDialog):
    """Dialog for configuring enterprise secrets management"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Configure Secrets Manager")
        self.setModal(True)
        self.resize(500, 400)
        
        layout = QVBoxLayout(self)
        
        # Provider selection
        provider_group = QGroupBox("Secrets Manager Provider")
        provider_layout = QFormLayout(provider_group)
        
        self.provider_combo = QComboBox()
        self.provider_combo.addItems(["HashiCorp Vault", "AWS Secrets Manager", "Azure Key Vault"])
        self.provider_combo.currentTextChanged.connect(self.on_provider_changed)
        provider_layout.addRow("Provider:", self.provider_combo)
        
        layout.addWidget(provider_group)
        
        # Configuration fields
        self.config_group = QGroupBox("Configuration")
        self.config_layout = QFormLayout(self.config_group)
        
        self.vault_url_edit = QLineEdit()
        self.vault_url_edit.setPlaceholderText("https://vault.example.com:8200")
        
        self.vault_token_edit = QLineEdit()
        self.vault_token_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.vault_token_edit.setPlaceholderText("hvs.XXXXXXXXXXXXXXXX")
        
        self.aws_region_edit = QLineEdit()
        self.aws_region_edit.setText("us-east-1")
        self.aws_region_edit.setPlaceholderText("us-east-1")
        
        layout.addWidget(self.config_group)
        
        # Test connection button
        self.test_btn = QPushButton("Test Connection")
        self.test_btn.clicked.connect(self.test_connection)
        layout.addWidget(self.test_btn)
        
        # Status
        self.status_label = QLabel("")
        layout.addWidget(self.status_label)
        
        # Dialog buttons
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | 
                                 QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
        self.on_provider_changed("HashiCorp Vault")
    
    def on_provider_changed(self, provider):
        """Update configuration fields based on provider"""
        # Clear existing fields
        for i in reversed(range(self.config_layout.count())):
            self.config_layout.itemAt(i).widget().setParent(None)
        
        if provider == "HashiCorp Vault":
            self.config_layout.addRow("Vault URL:", self.vault_url_edit)
            self.config_layout.addRow("Vault Token:", self.vault_token_edit)
        elif provider == "AWS Secrets Manager":
            self.config_layout.addRow("AWS Region:", self.aws_region_edit)
            info_label = QLabel("Uses AWS credentials from environment/profile")
            info_label.setStyleSheet("color: #666; font-style: italic;")
            self.config_layout.addRow("", info_label)
        elif provider == "Azure Key Vault":
            self.config_layout.addRow("Key Vault URL:", self.vault_url_edit)
            info_label = QLabel("Uses DefaultAzureCredential for authentication")
            info_label.setStyleSheet("color: #666; font-style: italic;")
            self.config_layout.addRow("", info_label)
    
    def test_connection(self):
        """Test connection to secrets manager"""
        provider = self.provider_combo.currentText()
        
        try:
            if provider == "HashiCorp Vault":
                success = secure_credential_manager.configure_secrets_manager(
                    "vault",
                    vault_url=self.vault_url_edit.text(),
                    vault_token=self.vault_token_edit.text()
                )
            elif provider == "AWS Secrets Manager":
                success = secure_credential_manager.configure_secrets_manager(
                    "aws",
                    region=self.aws_region_edit.text()
                )
            elif provider == "Azure Key Vault":
                success = secure_credential_manager.configure_secrets_manager(
                    "azure",
                    vault_url=self.vault_url_edit.text()
                )
            
            if success:
                self.status_label.setText("✓ Connection successful")
                self.status_label.setStyleSheet("color: green;")
            else:
                self.status_label.setText("✗ Connection failed")
                self.status_label.setStyleSheet("color: red;")
                
        except Exception as e:
            self.status_label.setText(f"✗ Error: {str(e)}")
            self.status_label.setStyleSheet("color: red;")

class SecureCredentialWidget(QWidget):
    """Widget for managing secure credentials and API keys"""
    
    def __init__(self):
        super().__init__()
        self.test_workers = {}
        self.init_ui()
        self.connect_signals()
        self.refresh_credentials()
    
    def init_ui(self):
        """Initialize the user interface"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Tab widget — no title bar above it
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)

        # Credentials tab
        self.credentials_tab = QWidget()
        self.init_credentials_tab()
        self.tab_widget.addTab(self.credentials_tab, "🔑 Credentials")

        # Security tab
        self.security_tab = QWidget()
        self.init_security_tab()
        self.tab_widget.addTab(self.security_tab, "🔒 Security")

        # Enterprise tab
        self.enterprise_tab = QWidget()
        self.init_enterprise_tab()
        self.tab_widget.addTab(self.enterprise_tab, "🏢 Enterprise")
    
    def init_credentials_tab(self):
        """Initialize credentials management tab — original compact style."""

        widget_layout = QVBoxLayout(self.credentials_tab)
        widget_layout.setContentsMargins(10, 10, 10, 10)
        widget_layout.setSpacing(8)

        FIELD_HEIGHT = 30
        LABEL_STYLE  = "font-size: 10pt; font-weight: bold; color: #DCDCDC;"
        HDR_STYLE    = ("font-size: 10pt; font-weight: bold; color: #64C8FF;"
                        " padding: 8px 0px 4px 0px;")

        # ── Form frame ────────────────────────────────────────────────────
        form_frame = QFrame()
        form_frame.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 150);
                border-radius: 10px;
                border: 1px solid rgba(100, 200, 255, 50);
            }
        """)
        form_frame.setSizePolicy(QSizePolicy.Policy.Expanding,
                                 QSizePolicy.Policy.Expanding)
        form_layout = QVBoxLayout(form_frame)
        form_layout.setContentsMargins(15, 15, 15, 15)
        form_layout.setSpacing(0)

        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(6)
        grid.setColumnStretch(1, 1)

        def hdr(text):
            l = QLabel(text); l.setStyleSheet(HDR_STYLE); return l

        def lbl(text):
            l = QLabel(text); l.setStyleSheet(LABEL_STYLE); return l

        def field(placeholder, echo=False):
            w = QLineEdit()
            w.setPlaceholderText(placeholder)
            w.setFixedHeight(FIELD_HEIGHT)
            w.setStyleSheet("font-size: 10pt; color: #DCDCDC;")
            if echo:
                w.setEchoMode(QLineEdit.EchoMode.Password)
            return w

        r = 0
        # Type header + dropdown
        grid.addWidget(hdr("Type:"), r, 0)
        self.type_combo = QComboBox()
        self.type_combo.addItems(["Username/Password", "NTLM Hash",
                                  "Kerberos Ticket", "SQL Server Auth",
                                  "Windows Auth", "Contacts"])
        self.type_combo.setFixedHeight(FIELD_HEIGHT)
        self.type_combo.setStyleSheet("font-size: 10pt;")
        self.type_combo.currentTextChanged.connect(self.on_type_changed)
        grid.addWidget(self.type_combo, r, 1); r += 1

        # Dynamic fields
        self.username_label   = lbl("Username:")
        self.username_edit    = field("Enter username")
        self.password_label   = lbl("Password:")
        self.password_edit    = field("Enter password", echo=True)
        self.ntlm_hash_label  = lbl("NTLM Hash:")
        self.ntlm_hash_edit   = field("Enter NTLM hash", echo=True)
        self.ticket_file_label= lbl("Ticket File:")
        self.ticket_file_edit = field("Path to ticket file")
        self.domain_label     = lbl("Domain:")
        self.domain_edit      = field("e.g., DOMAIN or leave blank")
        self.service_label    = lbl("Service:")
        self.service_edit     = field("e.g., SSH, RDP, SMB, HTTP")
        self.notes_label      = lbl("Notes:")
        self.notes_edit       = field("Optional notes")

        # Contacts fields
        self.account_name_label  = lbl("Account Name:")
        self.account_name_edit   = field("e.g., jdoe, admin")
        self.first_name_label    = lbl("First Name:")
        self.first_name_edit     = field("First name")
        self.middle_name_label   = lbl("Middle Name:")
        self.middle_name_edit    = field("Middle name (optional)")
        self.last_name_label     = lbl("Last Name:")
        self.last_name_edit      = field("Last name")
        self.email_label         = lbl("Email Address:")
        self.email_edit          = field("e.g., john.doe@company.com")
        self.mobile_label        = lbl("Mobile Phone:")
        self.mobile_edit         = field("e.g., +1-555-123-4567")
        self.address_label       = lbl("Address:")
        self.address_edit        = field("Physical address (optional)")

        all_fields = [
            (self.username_label,    self.username_edit),
            (self.password_label,    self.password_edit),
            (self.ntlm_hash_label,   self.ntlm_hash_edit),
            (self.ticket_file_label, self.ticket_file_edit),
            (self.domain_label,      self.domain_edit),
            (self.service_label,     self.service_edit),
            (self.notes_label,       self.notes_edit),
            (self.account_name_label,self.account_name_edit),
            (self.first_name_label,  self.first_name_edit),
            (self.middle_name_label, self.middle_name_edit),
            (self.last_name_label,   self.last_name_edit),
            (self.email_label,       self.email_edit),
            (self.mobile_label,      self.mobile_edit),
            (self.address_label,     self.address_edit),
        ]
        for label, widget in all_fields:
            grid.addWidget(label, r, 0)
            grid.addWidget(widget, r, 1)
            r += 1

        form_layout.addLayout(grid)
        form_layout.addStretch()

        # Buttons inside frame
        btn_row = QHBoxLayout()
        add_btn = QPushButton("Add Credential")
        add_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(50, 150, 50, 150);
                border: 2px solid #64C8FF; border-radius: 5px;
                color: #000000; font-weight: bold;
                padding: 8px 15px; font-size: 12pt;
            }
            QPushButton:hover { background-color: rgba(70, 170, 70, 200); }
        """)
        add_btn.clicked.connect(self.save_credential)
        btn_row.addWidget(add_btn)

        del_btn = QPushButton("Delete Selected")
        del_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(50, 150, 50, 150);
                border: 2px solid #FF6347; border-radius: 5px;
                color: #FFFFFF; font-weight: bold;
                padding: 8px 15px; font-size: 12pt;
            }
            QPushButton:hover { background-color: rgba(70, 170, 70, 200); }
        """)
        del_btn.clicked.connect(self.delete_selected_credential)
        btn_row.addWidget(del_btn)
        btn_row.addStretch()
        form_layout.addLayout(btn_row)

        widget_layout.addWidget(form_frame, stretch=1)

        # ── Stored Credentials header ─────────────────────────────────────
        cred_header = QHBoxLayout()
        cred_lbl = QLabel("Stored Credentials:")
        cred_lbl.setStyleSheet("font-weight: bold; color: #64C8FF; margin-top: 4px;")
        cred_header.addWidget(cred_lbl)
        cred_header.addStretch()

        self.show_passwords_cb = QCheckBox("Show Passwords")
        self.show_passwords_cb.setStyleSheet("color: #DCDCDC; font-weight: bold;")
        self.show_passwords_cb.stateChanged.connect(self._toggle_password_display)
        cred_header.addWidget(self.show_passwords_cb)
        widget_layout.addLayout(cred_header)

        # ── Credentials table — original 7-column format ──────────────────
        self.credentials_table = QTableWidget()
        self.credentials_table.setColumnCount(7)
        self.credentials_table.setHorizontalHeaderLabels(
            ["Source", "Type", "Username", "Password", "Domain", "Service", "Notes"])
        self.credentials_table.setMaximumHeight(200)
        self.credentials_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows)
        self.credentials_table.setStyleSheet("""
            QTableWidget {
                background-color: rgba(20, 30, 40, 150);
                border: 1px solid rgba(100, 200, 255, 50);
                border-radius: 5px; color: #DCDCDC;
                gridline-color: rgba(100, 200, 255, 50); font-size: 9pt;
            }
            QHeaderView::section {
                background-color: rgba(100, 200, 255, 100);
                color: #000000; font-weight: bold; padding: 3px; border: none;
            }
        """)
        hdr_view = self.credentials_table.horizontalHeader()
        hdr_view.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        hdr_view.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        widget_layout.addWidget(self.credentials_table)

        # Initialise field visibility
        self.on_type_changed("Username/Password")
    
    def init_security_tab(self):
        """Initialize security overview tab"""
        layout = QVBoxLayout(self.security_tab)
        
        # Security summary
        summary_group = QGroupBox("Security Summary")
        summary_layout = QVBoxLayout(summary_group)
        
        self.security_summary = QLabel()
        summary_layout.addWidget(self.security_summary)
        
        layout.addWidget(summary_group)
        
        # Security options
        options_group = QGroupBox("Security Options")
        options_layout = QFormLayout(options_group)
        
        self.use_env_checkbox = QCheckBox("Prioritize environment variables")
        self.use_env_checkbox.setChecked(True)
        options_layout.addRow("", self.use_env_checkbox)
        
        self.use_secrets_checkbox = QCheckBox("Use enterprise secrets manager")
        self.use_secrets_checkbox.setChecked(True)
        options_layout.addRow("", self.use_secrets_checkbox)
        
        # Memory management
        memory_buttons = QHBoxLayout()
        self.clear_memory_btn = QPushButton("Clear Secure Memory")
        self.clear_memory_btn.clicked.connect(self.clear_secure_memory)
        memory_buttons.addWidget(self.clear_memory_btn)
        memory_buttons.addStretch()
        options_layout.addRow("Memory:", memory_buttons)
        
        layout.addWidget(options_group)
        
        # Environment variables
        env_group = QGroupBox("Environment Variables")
        env_layout = QVBoxLayout(env_group)
        
        env_info = QLabel("""
Environment variables take priority over stored credentials. Use these patterns:
• SERVICE_USERNAME or SERVICE_USER
• SERVICE_PASSWORD or SERVICE_PASS  
• SERVICE_API_KEY or SERVICE_KEY
• SERVICE_TOKEN

Examples:
• SHODAN_API_KEY=your_key_here
• AWS_ACCESS_KEY_ID=AKIA...
• AWS_SECRET_ACCESS_KEY=...
        """)
        env_info.setStyleSheet("color: #666; font-family: monospace;")
        env_layout.addWidget(env_info)
        
        layout.addWidget(env_group)
        
        layout.addStretch()
    
    def init_enterprise_tab(self):
        """Initialize enterprise secrets management tab"""
        layout = QVBoxLayout(self.enterprise_tab)
        
        # Configuration
        config_group = QGroupBox("Secrets Manager Configuration")
        config_layout = QVBoxLayout(config_group)
        
        config_info = QLabel("""
Enterprise secrets management provides centralized, secure credential storage
with features like access logging, rotation, and fine-grained permissions.
        """)
        config_layout.addWidget(config_info)
        
        self.configure_secrets_btn = QPushButton("Configure Secrets Manager")
        self.configure_secrets_btn.clicked.connect(self.configure_secrets_manager)
        config_layout.addWidget(self.configure_secrets_btn)
        
        self.secrets_status = QLabel("Not configured")
        config_layout.addWidget(self.secrets_status)
        
        layout.addWidget(config_group)
        
        # Best practices
        practices_group = QGroupBox("Security Best Practices")
        practices_layout = QVBoxLayout(practices_group)
        
        practices_text = QLabel("""
• Use environment variables for development/testing
• Use enterprise secrets managers for production
• Rotate credentials regularly
• Use least-privilege access principles
• Monitor credential usage and access logs
• Never commit credentials to version control
• Use separate credentials for different environments
        """)
        practices_text.setStyleSheet("color: #333;")
        practices_layout.addWidget(practices_text)
        
        layout.addWidget(practices_group)
        
        layout.addStretch()
    
    def connect_signals(self):
        """Connect signals from credential manager"""
        secure_credential_manager.credential_stored.connect(self.on_credential_stored)
        secure_credential_manager.security_event.connect(self.on_security_event)
    
    def save_credential(self):
        """Save credential to secure storage"""
        from app.core.credential_manager import credential_manager

        credential_type = self.type_combo.currentText()
        service = self.service_edit.text().strip()
        notes   = self.notes_edit.text().strip()
        success = False

        if credential_type == "Username/Password":
            username = self.username_edit.text().strip()
            password = self.password_edit.text()
            if not username or not password:
                QMessageBox.warning(self, "Error", "Username and password are required")
                return
            credential_manager.add_credential(
                username=username, password=password,
                domain=self.domain_edit.text().strip(),
                service=service, notes=notes,
                source="manual", credential_type=credential_type)
            success = True

        elif credential_type == "NTLM Hash":
            username  = self.username_edit.text().strip()
            ntlm_hash = self.ntlm_hash_edit.text()
            if not username or not ntlm_hash:
                QMessageBox.warning(self, "Error", "Username and NTLM hash are required")
                return
            credential_manager.add_credential(
                username=username, password=ntlm_hash,
                service=service, notes=notes,
                source="manual", credential_type=credential_type)
            success = True

        elif credential_type == "Kerberos Ticket":
            ticket = self.ticket_file_edit.text().strip()
            if not ticket:
                QMessageBox.warning(self, "Error", "Ticket file path is required")
                return
            credential_manager.add_credential(
                username="", password=ticket,
                service=service, notes=notes,
                source="manual", credential_type=credential_type)
            success = True

        elif credential_type == "SQL Server Auth":
            username = self.username_edit.text().strip()
            password = self.password_edit.text()
            if not username or not password:
                QMessageBox.warning(self, "Error", "Username and password are required")
                return
            credential_manager.add_credential(
                username=username, password=password,
                service=service or "MSSQL", notes=notes,
                source="manual", credential_type=credential_type)
            success = True

        elif credential_type == "Windows Auth":
            username = self.username_edit.text().strip()
            password = self.password_edit.text()
            domain   = self.domain_edit.text().strip()
            if not username or not password:
                QMessageBox.warning(self, "Error", "Username and password are required")
                return
            if not domain:
                QMessageBox.warning(self, "Error", "Domain is required for Windows Auth")
                return
            credential_manager.add_credential(
                username=username, password=password, domain=domain,
                service=service or "MSSQL", notes=notes,
                source="manual", credential_type=credential_type)
            success = True

        elif credential_type == "Contacts":
            account = self.account_name_edit.text().strip()
            email   = self.email_edit.text().strip()
            if not account and not email:
                QMessageBox.warning(self, "Error", "Account name or email is required")
                return
            contact_info = " ".join(filter(None, [
                self.first_name_edit.text().strip(),
                self.middle_name_edit.text().strip(),
                self.last_name_edit.text().strip(),
            ]))
            if self.mobile_edit.text().strip():
                contact_info += f" | Phone: {self.mobile_edit.text().strip()}"
            if self.address_edit.text().strip():
                contact_info += f" | Address: {self.address_edit.text().strip()}"
            credential_manager.add_credential(
                username=account or email, password=contact_info,
                domain=email, service="Contact", notes=notes,
                source="manual", credential_type=credential_type)
            success = True

        if success:
            self.clear_form()
            self.refresh_credentials()
    
    def on_type_changed(self, credential_type):
        """Handle credential type change — show/hide fields."""
        all_pairs = [
            (self.username_label,    self.username_edit),
            (self.password_label,    self.password_edit),
            (self.ntlm_hash_label,   self.ntlm_hash_edit),
            (self.ticket_file_label, self.ticket_file_edit),
            (self.domain_label,      self.domain_edit),
            (self.service_label,     self.service_edit),
            (self.notes_label,       self.notes_edit),
            (self.account_name_label,self.account_name_edit),
            (self.first_name_label,  self.first_name_edit),
            (self.middle_name_label, self.middle_name_edit),
            (self.last_name_label,   self.last_name_edit),
            (self.email_label,       self.email_edit),
            (self.mobile_label,      self.mobile_edit),
            (self.address_label,     self.address_edit),
        ]
        for lbl, wgt in all_pairs:
            lbl.setVisible(False)
            wgt.setVisible(False)

        show_map = {
            "Username/Password": [
                (self.username_label, self.username_edit),
                (self.password_label, self.password_edit),
                (self.domain_label,   self.domain_edit),
                (self.service_label,  self.service_edit),
                (self.notes_label,    self.notes_edit),
            ],
            "NTLM Hash": [
                (self.username_label,  self.username_edit),
                (self.ntlm_hash_label, self.ntlm_hash_edit),
                (self.service_label,   self.service_edit),
                (self.notes_label,     self.notes_edit),
            ],
            "Kerberos Ticket": [
                (self.ticket_file_label, self.ticket_file_edit),
                (self.service_label,     self.service_edit),
                (self.notes_label,       self.notes_edit),
            ],
            "SQL Server Auth": [
                (self.username_label, self.username_edit),
                (self.password_label, self.password_edit),
                (self.service_label,  self.service_edit),
                (self.notes_label,    self.notes_edit),
            ],
            "Windows Auth": [
                (self.username_label, self.username_edit),
                (self.password_label, self.password_edit),
                (self.domain_label,   self.domain_edit),
                (self.service_label,  self.service_edit),
                (self.notes_label,    self.notes_edit),
            ],
            "Contacts": [
                (self.account_name_label, self.account_name_edit),
                (self.first_name_label,   self.first_name_edit),
                (self.middle_name_label,  self.middle_name_edit),
                (self.last_name_label,    self.last_name_edit),
                (self.email_label,        self.email_edit),
                (self.mobile_label,       self.mobile_edit),
                (self.address_label,      self.address_edit),
                (self.notes_label,        self.notes_edit),
            ],
        }
        for lbl, wgt in show_map.get(credential_type, []):
            lbl.setVisible(True)
            wgt.setVisible(True)
    
    def clear_form(self):
        """Clear the credential form"""
        for w in (self.username_edit, self.password_edit, self.ntlm_hash_edit,
                  self.ticket_file_edit, self.domain_edit, self.service_edit,
                  self.notes_edit, self.account_name_edit, self.first_name_edit,
                  self.middle_name_edit, self.last_name_edit, self.email_edit,
                  self.mobile_edit, self.address_edit):
            w.clear()
        self.type_combo.setCurrentIndex(0)
        self.on_type_changed("Username/Password")
    
    def refresh_credentials(self):
        """Refresh the credentials table — original 7-column format."""
        from app.core.credential_manager import credential_manager

        credentials = credential_manager.get_credentials()
        show_pw = (hasattr(self, 'show_passwords_cb')
                   and self.show_passwords_cb.isChecked())

        self.credentials_table.setRowCount(len(credentials))

        for row, cred in enumerate(credentials):
            source_icon = {
                'manual':      '👤 Manual',
                'enumeration': '🔍 Enum',
                'exploitation':'💥 Exploit',
                'scanned':     '🔍 Scanned',
            }.get(cred.source, '❓ Unknown')

            cred_type = getattr(cred, 'credential_type', 'Username/Password')
            password  = cred.password if show_pw else '*' * len(cred.password)

            for col, text in enumerate([
                source_icon, cred_type, cred.username,
                password, cred.domain, cred.service, cred.notes
            ]):
                item = QTableWidgetItem(text)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.credentials_table.setItem(row, col, item)

        self.credentials_table.resizeColumnsToContents()
        self.update_security_summary()

    def _toggle_password_display(self):
        """Re-render the table when Show Passwords is toggled."""
        self.refresh_credentials()
    
    def test_credential(self, service):
        """Test a specific credential"""
        if service in self.test_workers:
            return  # Test already running
        
        worker = CredentialTestWorker(service)
        worker.test_completed.connect(self.on_test_completed)
        self.test_workers[service] = worker
        worker.start()
        
        # Update status to show testing
        for row in range(self.credentials_table.rowCount()):
            if self.credentials_table.item(row, 0).text() == service:
                self.credentials_table.item(row, 4).setText("Testing...")
                break
    
    def test_selected_credential(self):
        """Test the selected credential"""
        current_row = self.credentials_table.currentRow()
        if current_row >= 0:
            self.test_credential_by_index(current_row)
    
    def test_credential_by_index(self, index):
        """Test credential by table index"""
        from app.core.credential_manager import credential_manager
        credentials = credential_manager.get_credentials()
        if 0 <= index < len(credentials):
            credential = credentials[index]
            # Placeholder test functionality
            QMessageBox.information(self, "Test Result", f"Testing {credential.credential_type} for {credential.service}...")
    
    def delete_selected_credential(self):
        """Delete the selected credential"""
        current_row = self.credentials_table.currentRow()
        if current_row >= 0:
            from app.core.credential_manager import credential_manager
            credentials = credential_manager.get_credentials()
            
            if current_row < len(credentials):
                credential = credentials[current_row]
                service = credential.service
                
                reply = QMessageBox.question(
                    self, "Confirm Delete",
                    f"Are you sure you want to delete the {credential.credential_type} for {service}?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                
                if reply == QMessageBox.StandardButton.Yes:
                    if credential_manager.remove_credential(current_row):
                        QMessageBox.information(self, "Success", f"Credential for {service} deleted")
                        self.refresh_credentials()
                        self.update_profile_label()  # Update profile info
                    else:
                        QMessageBox.warning(self, "Error", "Failed to delete credential")
    
    def configure_secrets_manager(self):
        """Open secrets manager configuration dialog"""
        dialog = SecretsManagerDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.update_security_summary()
    
    def clear_secure_memory(self):
        """Clear all secure memory"""
        secure_credential_manager.clear_secure_memory()
        QMessageBox.information(self, "Success", "Secure memory cleared")
        self.update_security_summary()
    
    def update_security_summary(self):
        """Update security summary display"""
        from app.core.credential_manager import credential_manager
        
        summary_text = f"""
<b>Security Status:</b><br>
• {credential_manager.get_credential_summary()}<br>
• Profile: {credential_manager.get_current_profile()}<br>
<br>
<b>Credential Types:</b><br>
        """
        
        # Count by type
        type_counts = {}
        for cred in credential_manager.get_credentials():
            cred_type = cred.credential_type
            type_counts[cred_type] = type_counts.get(cred_type, 0) + 1
        
        for cred_type, count in type_counts.items():
            summary_text += f"• {cred_type}: {count}<br>"
        
        self.security_summary.setText(summary_text)
        
        # Update secrets manager status
        if hasattr(self, 'secrets_status'):
            self.secrets_status.setText("✗ Not configured")
            self.secrets_status.setStyleSheet("color: red;")
    
    def update_profile_label(self):
        """No-op — profile label removed from UI."""
        pass
    

    
    def on_test_completed(self, service, result):
        """Handle credential test completion"""
        if service in self.test_workers:
            del self.test_workers[service]
        
        # Update table status
        for row in range(self.credentials_table.rowCount()):
            if self.credentials_table.item(row, 0).text() == service:
                status = "✓ Valid" if result['success'] else "✗ Invalid"
                self.credentials_table.item(row, 4).setText(status)
                
                if result['success']:
                    self.credentials_table.item(row, 4).setBackground(Qt.GlobalColor.green)
                else:
                    self.credentials_table.item(row, 4).setBackground(Qt.GlobalColor.red)
                break
    
    def on_credential_stored(self, service):
        """Handle credential stored event"""
        self.refresh_credentials()
    
    def on_security_event(self, event_type, message):
        """Handle security events"""
        if event_type in ['store_error', 'load_error', 'save_error']:
            QMessageBox.critical(self, "Security Error", message)