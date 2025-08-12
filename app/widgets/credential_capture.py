# app/widgets/credential_capture.py
from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                             QLineEdit, QPushButton, QTextEdit, QMessageBox,
                             QTableWidget, QTableWidgetItem, QHeaderView, QCheckBox)
from PyQt6.QtCore import Qt

class CredentialCaptureDialog(QDialog):
    """Dialog for capturing credentials during enumeration/exploitation"""
    
    def __init__(self, parent=None, prefill_data=None):
        super().__init__(parent)
        self.setWindowTitle("Add Discovered Credential")
        self.setModal(True)
        self.setFixedSize(400, 350)
        self.prefill_data = prefill_data or {}
        # Default source to 'scanned' if not specified
        if 'source' not in self.prefill_data:
            self.prefill_data['source'] = 'scanned'
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the dialog UI"""
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # Title
        title = QLabel("Add Credential to Global Store")
        title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #64C8FF;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # Form fields
        self.username = QLineEdit()
        self.username.setPlaceholderText("Username")
        self.username.setText(self.prefill_data.get('username', ''))
        layout.addWidget(QLabel("Username:"))
        layout.addWidget(self.username)
        
        self.password = QLineEdit()
        self.password.setPlaceholderText("Password")
        self.password.setText(self.prefill_data.get('password', ''))
        layout.addWidget(QLabel("Password:"))
        layout.addWidget(self.password)
        
        self.domain = QLineEdit()
        self.domain.setPlaceholderText("Domain (optional)")
        self.domain.setText(self.prefill_data.get('domain', ''))
        layout.addWidget(QLabel("Domain:"))
        layout.addWidget(self.domain)
        
        self.service = QLineEdit()
        self.service.setPlaceholderText("Service (e.g., SSH, RDP, SMB)")
        self.service.setText(self.prefill_data.get('service', ''))
        layout.addWidget(QLabel("Service:"))
        layout.addWidget(self.service)
        
        self.notes = QTextEdit()
        self.notes.setPlaceholderText("Additional notes...")
        self.notes.setMaximumHeight(60)
        self.notes.setText(self.prefill_data.get('notes', ''))
        layout.addWidget(QLabel("Notes:"))
        layout.addWidget(self.notes)
        
        # Buttons
        btn_layout = QHBoxLayout()
        
        save_btn = QPushButton("Save Credential")
        save_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(50, 150, 50, 150);
                border: 2px solid #32CD32;
                border-radius: 5px;
                color: #FFFFFF;
                font-weight: bold;
                padding: 8px;
            }
        """)
        save_btn.clicked.connect(self.save_credential)
        btn_layout.addWidget(save_btn)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(100, 100, 100, 150);
                border: 2px solid #666666;
                border-radius: 5px;
                color: #FFFFFF;
                font-weight: bold;
                padding: 8px;
            }
        """)
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)
        
        layout.addLayout(btn_layout)
    
    def save_credential(self):
        """Save the credential"""
        username = self.username.text().strip()
        password = self.password.text().strip()
        
        if not username or not password:
            QMessageBox.warning(self, "Invalid Input", "Username and password are required.")
            return
        
        from app.core.credential_manager import credential_manager
        
        credential_manager.add_credential(
            username=username,
            password=password,
            domain=self.domain.text().strip(),
            service=self.service.text().strip(),
            notes=self.notes.toPlainText().strip(),
            source=self.prefill_data.get('source', 'enumeration')
        )
        
        self.accept()

def add_credential_from_scan(username="", password="", domain="", service="", 
                           notes="", source="scanned", parent=None):
    """Quick function to add credential from scanning results"""
    prefill_data = {
        'username': username,
        'password': password,
        'domain': domain,
        'service': service,
        'notes': notes,
        'source': source
    }
    
    dialog = CredentialCaptureDialog(parent, prefill_data)
    return dialog.exec() == QDialog.DialogCode.Accepted

def show_credential_details_dialog(parent=None):
    """Show detailed credential view with passwords revealed"""
    from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QTextEdit, QPushButton, 
                                 QHBoxLayout, QTableWidget, QTableWidgetItem, 
                                 QHeaderView, QCheckBox, QMessageBox, QFileDialog)
    from app.core.credential_manager import credential_manager
    import json
    
    dialog = QDialog(parent)
    dialog.setWindowTitle("Credential Details")
    dialog.setModal(True)
    dialog.resize(700, 500)
    
    layout = QVBoxLayout(dialog)
    
    # Title
    title = QLabel("Stored Credentials - Full Details")
    title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #64C8FF;")
    title.setAlignment(Qt.AlignmentFlag.AlignCenter)
    layout.addWidget(title)
    
    # Show passwords checkbox
    show_passwords_cb = QCheckBox("Show Passwords")
    show_passwords_cb.setStyleSheet("color: #DCDCDC; font-weight: bold;")
    layout.addWidget(show_passwords_cb)
    
    # Credential table
    table = QTableWidget()
    table.setColumnCount(6)
    table.setHorizontalHeaderLabels(["Source", "Username", "Password", "Domain", "Service", "Notes"])
    table.setRowCount(len(credential_manager.credentials))
    
    # Populate table
    for i, cred in enumerate(credential_manager.credentials):
        source_icon = {
            'manual': '👤 Manual',
            'enumeration': '🔍 Enum', 
            'exploitation': '💥 Exploit',
            'scanned': '🔍 Scanned'
        }.get(cred.source, '❓ Unknown')
        
        table.setItem(i, 0, QTableWidgetItem(source_icon))
        table.setItem(i, 1, QTableWidgetItem(cred.username))
        table.setItem(i, 2, QTableWidgetItem(cred.password))
        table.setItem(i, 3, QTableWidgetItem(cred.domain))
        table.setItem(i, 4, QTableWidgetItem(cred.service))
        table.setItem(i, 5, QTableWidgetItem(cred.notes))
    
    # Initially hide passwords
    def toggle_passwords(show):
        for i in range(table.rowCount()):
            password_item = table.item(i, 2)
            if password_item:
                if show:
                    password_item.setText(credential_manager.credentials[i].password)
                else:
                    password_item.setText('*' * len(credential_manager.credentials[i].password))
    
    show_passwords_cb.stateChanged.connect(toggle_passwords)
    toggle_passwords(False)  # Start with passwords hidden
    
    # Style table
    table.setStyleSheet("""
        QTableWidget {
            background-color: rgba(20, 30, 40, 150);
            border: 1px solid rgba(100, 200, 255, 50);
            border-radius: 5px;
            color: #DCDCDC;
            gridline-color: rgba(100, 200, 255, 50);
        }
        QHeaderView::section {
            background-color: rgba(100, 200, 255, 100);
            color: #000000;
            font-weight: bold;
            padding: 5px;
            border: none;
        }
    """)
    
    # Auto-resize columns
    header = table.horizontalHeader()
    header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)  # Notes column stretches
    
    layout.addWidget(table)
    
    # Summary
    summary = QLabel(credential_manager.get_credential_summary())
    summary.setStyleSheet("""
        QLabel {
            background-color: rgba(100, 100, 100, 100);
            border: 1px solid #666666;
            border-radius: 3px;
            padding: 5px;
            color: #DCDCDC;
        }
    """)
    layout.addWidget(summary)
    
    # Buttons
    btn_layout = QHBoxLayout()
    
    def export_credentials():
        if not credential_manager.credentials:
            QMessageBox.information(dialog, "No Credentials", "No credentials to export.")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            dialog, "Export Credentials", "credentials.txt", "Text files (*.txt);;JSON files (*.json)"
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    for cred in credential_manager.credentials:
                        f.write(f"Username: {cred.username}\n")
                        f.write(f"Password: {cred.password}\n")
                        if cred.domain:
                            f.write(f"Domain: {cred.domain}\n")
                        if cred.service:
                            f.write(f"Service: {cred.service}\n")
                        if cred.notes:
                            f.write(f"Notes: {cred.notes}\n")
                        f.write(f"Source: {cred.source}\n")
                        f.write("-" * 40 + "\n")
                
                QMessageBox.information(dialog, "Success", f"Credentials exported to {filename}")
            except Exception as e:
                QMessageBox.warning(dialog, "Error", f"Failed to export credentials: {str(e)}")
    
    export_btn = QPushButton("Export to File")
    export_btn.setStyleSheet("""
        QPushButton {
            background-color: rgba(100, 150, 200, 150);
            border: 2px solid #6495ED;
            border-radius: 5px;
            color: #FFFFFF;
            font-weight: bold;
            padding: 8px;
        }
    """)
    export_btn.clicked.connect(export_credentials)
    btn_layout.addWidget(export_btn)
    
    btn_layout.addStretch()
    
    close_btn = QPushButton("Close")
    close_btn.clicked.connect(dialog.accept)
    btn_layout.addWidget(close_btn)
    
    layout.addLayout(btn_layout)
    
    dialog.exec()