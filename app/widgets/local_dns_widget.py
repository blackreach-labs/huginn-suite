# app/widgets/local_dns_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
                            QLabel, QLineEdit, QComboBox, QTableWidget, 
                            QTableWidgetItem, QMessageBox, QGroupBox, QTextEdit)
from PyQt6.QtCore import Qt
from app.core.local_dns_server import local_dns_server
from app.core.license_manager import license_manager

class LocalDNSWidget(QWidget):
    """Widget for managing local DNS server"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.connect_signals()
        self.update_ui_state()
        self.update_server_status()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # License check
        self.license_label = QLabel()
        layout.addWidget(self.license_label)
        
        # Server control
        server_group = QGroupBox("DNS Server Control")
        server_layout = QHBoxLayout(server_group)
        
        self.status_label = QLabel("Server: Stopped")
        self.start_btn = QPushButton("Start Server")
        self.stop_btn = QPushButton("Stop Server")
        
        server_layout.addWidget(self.status_label)
        server_layout.addStretch()
        server_layout.addWidget(self.start_btn)
        server_layout.addWidget(self.stop_btn)
        
        layout.addWidget(server_group)
        
        # Add record section
        add_group = QGroupBox("Add DNS Record")
        add_layout = QVBoxLayout(add_group)
        
        form_layout = QHBoxLayout()
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("example.com")
        self.type_combo = QComboBox()
        self.type_combo.addItems(["A", "AAAA", "CNAME"])
        self.value_input = QLineEdit()
        self.value_input.setPlaceholderText("192.168.1.1 or target.com")
        self.add_btn = QPushButton("Add Record")
        
        form_layout.addWidget(QLabel("Domain:"))
        form_layout.addWidget(self.domain_input)
        form_layout.addWidget(QLabel("Type:"))
        form_layout.addWidget(self.type_combo)
        form_layout.addWidget(QLabel("Value:"))
        form_layout.addWidget(self.value_input)
        form_layout.addWidget(self.add_btn)
        
        add_layout.addLayout(form_layout)
        layout.addWidget(add_group)
        
        # Records table
        records_group = QGroupBox("DNS Records")
        records_layout = QVBoxLayout(records_group)
        
        self.records_table = QTableWidget()
        self.records_table.setColumnCount(3)
        self.records_table.setHorizontalHeaderLabels(["Domain", "Type", "Value"])
        self.records_table.horizontalHeader().setStretchLastSection(True)
        
        table_buttons = QHBoxLayout()
        self.refresh_btn = QPushButton("Refresh")
        self.delete_btn = QPushButton("Delete Selected")
        self.clear_btn = QPushButton("Clear All")
        
        table_buttons.addWidget(self.refresh_btn)
        table_buttons.addWidget(self.delete_btn)
        table_buttons.addWidget(self.clear_btn)
        table_buttons.addStretch()
        
        records_layout.addWidget(self.records_table)
        records_layout.addLayout(table_buttons)
        layout.addWidget(records_group)
        
        # Log output
        log_group = QGroupBox("Server Log")
        log_layout = QVBoxLayout(log_group)
        self.log_output = QTextEdit()
        self.log_output.setMaximumHeight(100)
        self.log_output.setReadOnly(True)
        log_layout.addWidget(self.log_output)
        layout.addWidget(log_group)
        
        # Usage info
        info_group = QGroupBox("Usage Information")
        info_layout = QVBoxLayout(info_group)
        info_text = QLabel(
            "To use LocalDNS in tools:\n"
            "• Set DNS Server to 'LocalDNS' in any DNS tool\n"
            "• Server runs on 127.0.0.1:53530 (or next available port)\n"
            "• Supports A, AAAA, and CNAME records\n"
            "• Records are automatically saved and restored"
        )
        info_text.setWordWrap(True)
        info_layout.addWidget(info_text)
        layout.addWidget(info_group)
        
    def connect_signals(self):
        self.start_btn.clicked.connect(self.start_server)
        self.stop_btn.clicked.connect(self.stop_server)
        self.add_btn.clicked.connect(self.add_record)
        self.refresh_btn.clicked.connect(self.refresh_records)
        self.delete_btn.clicked.connect(self.delete_record)
        self.clear_btn.clicked.connect(self.clear_records)
        
        local_dns_server.status_changed.connect(self.on_status_changed)
        
    def update_ui_state(self):
        """Update UI based on license status"""
        license_info = license_manager.get_license_info()
        is_licensed = license_info.get("licensed", False) and \
                     license_info.get("license_type") in ["Professional", "Enterprise"]
        
        if is_licensed:
            self.license_label.setText(f"✓ Licensed: {license_info.get('license_type')}")
            self.license_label.setStyleSheet("color: green;")
        else:
            self.license_label.setText("⚠ Local DNS requires Professional or Enterprise license")
            self.license_label.setStyleSheet("color: orange;")
            
        # Enable/disable controls based on license
        for widget in [self.start_btn, self.stop_btn, self.add_btn, 
                      self.delete_btn, self.clear_btn]:
            widget.setEnabled(is_licensed)
            
        self.refresh_records()
        
    def start_server(self):
        """Start the DNS server"""
        local_dns_server.start_server()
        
    def stop_server(self):
        """Stop the DNS server"""
        local_dns_server.stop_server()
        
    def add_record(self):
        """Add a new DNS record"""
        domain = self.domain_input.text().strip()
        record_type = self.type_combo.currentText()
        value = self.value_input.text().strip()
        
        if not domain or not value:
            QMessageBox.warning(self, "Error", "Please fill in all fields")
            return
            
        if local_dns_server.add_record(domain, record_type, value):
            self.domain_input.clear()
            self.value_input.clear()
            self.refresh_records()
            QMessageBox.information(self, "Success", "DNS record added successfully")
        else:
            QMessageBox.warning(self, "Error", "Failed to add DNS record")
            
    def delete_record(self):
        """Delete selected DNS record"""
        current_row = self.records_table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "Error", "Please select a record to delete")
            return
            
        domain = self.records_table.item(current_row, 0).text()
        record_type = self.records_table.item(current_row, 1).text()
        value = self.records_table.item(current_row, 2).text()
        
        reply = QMessageBox.question(self, "Confirm Delete", 
                                   f"Delete record: {domain} {record_type} {value}?")
        if reply == QMessageBox.StandardButton.Yes:
            if local_dns_server.remove_record(domain, record_type, value):
                self.refresh_records()
                QMessageBox.information(self, "Success", "DNS record deleted successfully")
            else:
                QMessageBox.warning(self, "Error", "Failed to delete DNS record")
                
    def clear_records(self):
        """Clear all DNS records"""
        reply = QMessageBox.question(self, "Confirm Clear", 
                                   "Clear all DNS records?")
        if reply == QMessageBox.StandardButton.Yes:
            local_dns_server.clear_records()
            self.refresh_records()
            QMessageBox.information(self, "Success", "All DNS records cleared")
            
    def refresh_records(self):
        """Refresh the records table"""
        records = local_dns_server.get_records()
        
        # Count total records
        total_records = sum(len(types) for types in records.values() 
                          for type_records in types.values())
        
        self.records_table.setRowCount(total_records)
        
        row = 0
        for domain, types in records.items():
            for record_type, values in types.items():
                for value in values:
                    self.records_table.setItem(row, 0, QTableWidgetItem(domain))
                    self.records_table.setItem(row, 1, QTableWidgetItem(record_type))
                    self.records_table.setItem(row, 2, QTableWidgetItem(value))
                    row += 1
                    
    def on_status_changed(self, message: str, is_running: bool):
        """Handle server status changes"""
        self.status_label.setText(f"Server: {'Running' if is_running else 'Stopped'}")
        self.start_btn.setEnabled(not is_running)
        self.stop_btn.setEnabled(is_running)
        
        # Add message to log
        clean_message = message.replace("Local DNS server running on ", "Local DNS server started on ")
        self.log_output.append(clean_message)
        
    def update_server_status(self):
        """Update UI to reflect current server status"""
        is_running = local_dns_server.running
        self.status_label.setText(f"Server: {'Running' if is_running else 'Stopped'}")
        self.start_btn.setEnabled(not is_running)
        self.stop_btn.setEnabled(is_running)