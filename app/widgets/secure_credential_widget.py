# app/widgets/secure_credential_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
                            QComboBox, QTextEdit, QGroupBox, QTabWidget,
                            QMessageBox, QProgressBar, QCheckBox, QFormLayout,
                            QDialog, QDialogButtonBox)
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
        
        # Title with profile info
        title_layout = QHBoxLayout()
        title = QLabel("Credential Management")
        title.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        title_layout.addWidget(title)
        
        # Profile indicator
        self.profile_label = QLabel()
        self.profile_label.setStyleSheet("color: #64C8FF; font-weight: bold;")
        self.update_profile_label()
        title_layout.addWidget(self.profile_label)
        title_layout.addStretch()
        
        layout.addLayout(title_layout)
        
        # Tab widget
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)
        
        # Credentials tab
        self.credentials_tab = QWidget()
        self.init_credentials_tab()
        self.tab_widget.addTab(self.credentials_tab, "Credentials")
        
        # Security tab
        self.security_tab = QWidget()
        self.init_security_tab()
        self.tab_widget.addTab(self.security_tab, "Security")
        
        # Enterprise tab
        self.enterprise_tab = QWidget()
        self.init_enterprise_tab()
        self.tab_widget.addTab(self.enterprise_tab, "Enterprise")
    
    def init_credentials_tab(self):
        """Initialize credentials management tab"""
        layout = QVBoxLayout(self.credentials_tab)
        
        # Add credential form
        form_group = QGroupBox("Credential Management")
        form_layout = QFormLayout(form_group)
        
        # Type dropdown
        type_layout = QHBoxLayout()
        self.type_combo = QComboBox()
        self.type_combo.addItems(["Username/Password", "NTLM Hash", "Kerberos Ticket", "SQL Server Auth", "Windows Auth"])
        self.type_combo.setMinimumWidth(150)
        self.type_combo.currentTextChanged.connect(self.on_type_changed)
        type_layout.addWidget(self.type_combo)
        type_layout.addStretch()
        form_layout.addRow("Type:", type_layout)
        
        # Dynamic fields with labels
        self.username_label = QLabel("Username:")
        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText("Username")
        form_layout.addRow(self.username_label, self.username_edit)
        
        self.password_label = QLabel("Password:")
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_edit.setPlaceholderText("Password")
        form_layout.addRow(self.password_label, self.password_edit)
        
        self.ntlm_hash_label = QLabel("NTLM Hash:")
        self.ntlm_hash_edit = QLineEdit()
        self.ntlm_hash_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.ntlm_hash_edit.setPlaceholderText("NTLM Hash")
        form_layout.addRow(self.ntlm_hash_label, self.ntlm_hash_edit)
        
        self.ticket_file_label = QLabel("Ticket File:")
        self.ticket_file_edit = QLineEdit()
        self.ticket_file_edit.setPlaceholderText("Path to ticket file")
        form_layout.addRow(self.ticket_file_label, self.ticket_file_edit)
        
        self.domain_label = QLabel("Domain:")
        self.domain_edit = QLineEdit()
        self.domain_edit.setPlaceholderText("Domain (optional)")
        form_layout.addRow(self.domain_label, self.domain_edit)
        
        self.service_label = QLabel("Service:")
        self.service_edit = QLineEdit()
        self.service_edit.setPlaceholderText("e.g., SSH, RDP, SMB")
        form_layout.addRow(self.service_label, self.service_edit)
        
        self.notes_label = QLabel("Notes:")
        self.notes_edit = QTextEdit()
        self.notes_edit.setMaximumHeight(60)
        self.notes_edit.setPlaceholderText("Notes (optional)")
        form_layout.addRow(self.notes_label, self.notes_edit)
        
        # Form buttons
        form_buttons = QHBoxLayout()
        self.save_btn = QPushButton("Save Credential")
        self.save_btn.clicked.connect(self.save_credential)
        self.clear_btn = QPushButton("Clear Form")
        self.clear_btn.clicked.connect(self.clear_form)
        form_buttons.addWidget(self.save_btn)
        form_buttons.addWidget(self.clear_btn)
        form_buttons.addStretch()
        form_layout.addRow("", form_buttons)
        
        layout.addWidget(form_group)
        
        # Initialize field visibility
        self.on_type_changed("Username/Password")
        
        # Credentials table
        table_group = QGroupBox("Stored Credentials")
        table_layout = QVBoxLayout(table_group)
        
        # Table controls
        table_controls = QHBoxLayout()
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_credentials)
        self.test_btn = QPushButton("Test Selected")
        self.test_btn.clicked.connect(self.test_selected_credential)
        self.delete_btn = QPushButton("Delete Selected")
        self.delete_btn.clicked.connect(self.delete_selected_credential)
        
        table_controls.addWidget(self.refresh_btn)
        table_controls.addWidget(self.test_btn)
        table_controls.addWidget(self.delete_btn)
        table_controls.addStretch()
        table_layout.addLayout(table_controls)
        
        # Credentials table
        self.credentials_table = QTableWidget()
        self.credentials_table.setColumnCount(7)
        self.credentials_table.setHorizontalHeaderLabels([
            "Service", "Type", "Username", "Source", "Last Used", "Status", "Actions"
        ])
        self.credentials_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table_layout.addWidget(self.credentials_table)
        
        layout.addWidget(table_group)
    
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
        credential_type = self.type_combo.currentText()
        service = self.service_edit.text().strip()
        
        if not service:
            QMessageBox.warning(self, "Error", "Service name is required")
            return
        
        # Use the basic credential manager for now
        from app.core.credential_manager import credential_manager
        
        # Validate based on credential type
        if credential_type == "Username/Password":
            username = self.username_edit.text().strip()
            password = self.password_edit.text()
            if not username or not password:
                QMessageBox.warning(self, "Error", "Username and password are required")
                return
            
            credential_manager.add_credential(
                username=username,
                password=password,
                domain=self.domain_edit.text().strip(),
                service=service,
                notes=self.notes_edit.toPlainText().strip(),
                source="manual",
                credential_type=credential_type
            )
            success = True
        
        elif credential_type == "NTLM Hash":
            username = self.username_edit.text().strip()
            ntlm_hash = self.ntlm_hash_edit.text()
            if not username or not ntlm_hash:
                QMessageBox.warning(self, "Error", "Username and NTLM hash are required")
                return
            
            credential_manager.add_credential(
                username=username,
                password=ntlm_hash,  # Store hash as password
                service=service,
                notes=self.notes_edit.toPlainText().strip(),
                source="manual",
                credential_type=credential_type
            )
            success = True
        
        elif credential_type == "Kerberos Ticket":
            ticket_file = self.ticket_file_edit.text().strip()
            if not ticket_file:
                QMessageBox.warning(self, "Error", "Ticket file path is required")
                return
            
            credential_manager.add_credential(
                username="",  # No username for ticket
                password=ticket_file,  # Store ticket path as password
                service=service,
                notes=self.notes_edit.toPlainText().strip(),
                source="manual",
                credential_type=credential_type
            )
            success = True
        
        elif credential_type == "SQL Server Auth":
            username = self.username_edit.text().strip()
            password = self.password_edit.text()
            if not username or not password:
                QMessageBox.warning(self, "Error", "Username and password are required for SQL Server Auth")
                return
            
            credential_manager.add_credential(
                username=username,
                password=password,
                service=service or "MSSQL",
                notes=self.notes_edit.toPlainText().strip(),
                source="manual",
                credential_type=credential_type
            )
            success = True
        
        elif credential_type == "Windows Auth":
            username = self.username_edit.text().strip()
            password = self.password_edit.text()
            domain = self.domain_edit.text().strip()
            if not username or not password:
                QMessageBox.warning(self, "Error", "Username and password are required for Windows Auth")
                return
            if not domain:
                QMessageBox.warning(self, "Error", "Domain is required for Windows Auth")
                return
            
            credential_manager.add_credential(
                username=username,
                password=password,
                domain=domain,
                service=service or "MSSQL",
                notes=self.notes_edit.toPlainText().strip(),
                source="manual",
                credential_type=credential_type
            )
            success = True
        
        if success:
            QMessageBox.information(self, "Success", f"{credential_type} for {service} saved successfully")
            self.clear_form()
            self.refresh_credentials()
            self.update_profile_label()  # Update profile info
        else:
            QMessageBox.critical(self, "Error", "Failed to save credential")
    
    def on_type_changed(self, credential_type):
        """Handle credential type change"""
        # Hide all fields first
        self.username_label.setVisible(False)
        self.username_edit.setVisible(False)
        self.password_label.setVisible(False)
        self.password_edit.setVisible(False)
        self.ntlm_hash_label.setVisible(False)
        self.ntlm_hash_edit.setVisible(False)
        self.ticket_file_label.setVisible(False)
        self.ticket_file_edit.setVisible(False)
        self.domain_label.setVisible(False)
        self.domain_edit.setVisible(False)
        self.service_label.setVisible(False)
        self.service_edit.setVisible(False)
        self.notes_label.setVisible(False)
        self.notes_edit.setVisible(False)
        
        # Show fields based on type
        if credential_type == "Username/Password":
            self.username_label.setVisible(True)
            self.username_edit.setVisible(True)
            self.password_label.setVisible(True)
            self.password_edit.setVisible(True)
            self.domain_label.setVisible(True)
            self.domain_edit.setVisible(True)
            self.service_label.setVisible(True)
            self.service_edit.setVisible(True)
            self.notes_label.setVisible(True)
            self.notes_edit.setVisible(True)
        elif credential_type == "NTLM Hash":
            self.username_label.setVisible(True)
            self.username_edit.setVisible(True)
            self.ntlm_hash_label.setVisible(True)
            self.ntlm_hash_edit.setVisible(True)
            self.service_label.setVisible(True)
            self.service_edit.setVisible(True)
            self.notes_label.setVisible(True)
            self.notes_edit.setVisible(True)
        elif credential_type == "Kerberos Ticket":
            self.ticket_file_label.setVisible(True)
            self.ticket_file_edit.setVisible(True)
            self.service_label.setVisible(True)
            self.service_edit.setVisible(True)
            self.notes_label.setVisible(True)
            self.notes_edit.setVisible(True)
        elif credential_type == "SQL Server Auth":
            self.username_label.setVisible(True)
            self.username_edit.setVisible(True)
            self.password_label.setVisible(True)
            self.password_edit.setVisible(True)
            self.service_label.setVisible(True)
            self.service_edit.setVisible(True)
            self.notes_label.setVisible(True)
            self.notes_edit.setVisible(True)
        elif credential_type == "Windows Auth":
            self.username_label.setVisible(True)
            self.username_edit.setVisible(True)
            self.password_label.setVisible(True)
            self.password_edit.setVisible(True)
            self.domain_label.setVisible(True)
            self.domain_edit.setVisible(True)
            self.service_label.setVisible(True)
            self.service_edit.setVisible(True)
            self.notes_label.setVisible(True)
            self.notes_edit.setVisible(True)
    
    def clear_form(self):
        """Clear the credential form"""
        self.username_edit.clear()
        self.password_edit.clear()
        self.ntlm_hash_edit.clear()
        self.ticket_file_edit.clear()
        self.domain_edit.clear()
        self.service_edit.clear()
        self.notes_edit.clear()
        self.type_combo.setCurrentIndex(0)
        self.on_type_changed("Username/Password")
    
    def refresh_credentials(self):
        """Refresh the credentials table"""
        from app.core.credential_manager import credential_manager
        
        credentials = credential_manager.get_credentials()
        self.credentials_table.setRowCount(len(credentials))
        
        for row, credential in enumerate(credentials):
            # Service name
            self.credentials_table.setItem(row, 0, QTableWidgetItem(credential.service))
            
            # Credential type
            self.credentials_table.setItem(row, 1, QTableWidgetItem(credential.credential_type))
            
            # Username (or ticket file for Kerberos)
            if credential.credential_type == "Kerberos Ticket":
                username_display = f"Ticket: {credential.password[:20]}..." if len(credential.password) > 20 else f"Ticket: {credential.password}"
            else:
                username_display = credential.username or "N/A"
            self.credentials_table.setItem(row, 2, QTableWidgetItem(username_display))
            
            # Source
            self.credentials_table.setItem(row, 3, QTableWidgetItem(credential.source))
            
            # Last used (placeholder)
            self.credentials_table.setItem(row, 4, QTableWidgetItem("Never"))
            
            # Status (placeholder)
            status_item = QTableWidgetItem("Unknown")
            self.credentials_table.setItem(row, 5, status_item)
            
            # Test button (placeholder)
            test_btn = QPushButton("Test")
            test_btn.clicked.connect(lambda checked, idx=row: self.test_credential_by_index(idx))
            self.credentials_table.setCellWidget(row, 6, test_btn)
        
        self.credentials_table.resizeColumnsToContents()
        self.update_security_summary()
    
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
        """Update profile label with current profile info"""
        from app.core.credential_manager import credential_manager
        profile_name = credential_manager.get_current_profile()
        self.profile_label.setText(f"Profile: {profile_name}")
    

    
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