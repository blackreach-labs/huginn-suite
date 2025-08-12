# app/widgets/asset_update_dialog.py
from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                             QLineEdit, QComboBox, QSpinBox, QTextEdit, 
                             QPushButton, QGroupBox, QGridLayout, QListWidget,
                             QListWidgetItem, QMessageBox, QTabWidget, QWidget,
                             QFormLayout, QCheckBox)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
import json
from datetime import datetime

class AssetUpdateDialog(QDialog):
    """Dialog for updating asset information"""
    
    asset_updated = pyqtSignal(dict)  # Emitted when asset is successfully updated
    
    def __init__(self, asset_data, parent=None):
        super().__init__(parent)
        self.asset_data = asset_data.copy()
        self.original_data = asset_data.copy()
        self.setup_ui()
        self.populate_fields()
        
    def setup_ui(self):
        """Setup the dialog UI"""
        self.setWindowTitle(f"Update Asset - {self.asset_data['ip_address']}")
        self.setModal(True)
        self.resize(600, 700)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        
        # Title
        title = QLabel(f"Update Asset: {self.asset_data['ip_address']}")
        title.setStyleSheet("font-size: 16pt; font-weight: bold; color: #64C8FF; margin-bottom: 10px;")
        layout.addWidget(title)
        
        # Tab widget for different sections
        self.tab_widget = QTabWidget()
        
        # Basic Information Tab
        basic_tab = self.create_basic_info_tab()
        self.tab_widget.addTab(basic_tab, "Basic Info")
        
        # Ports & Services Tab
        ports_tab = self.create_ports_services_tab()
        self.tab_widget.addTab(ports_tab, "Ports & Services")
        
        # Vulnerabilities Tab
        vulns_tab = self.create_vulnerabilities_tab()
        self.tab_widget.addTab(vulns_tab, "Vulnerabilities")
        
        # Metadata Tab
        metadata_tab = self.create_metadata_tab()
        self.tab_widget.addTab(metadata_tab, "Metadata")
        
        layout.addWidget(self.tab_widget)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.history_btn = QPushButton("📈 View History")
        self.history_btn.clicked.connect(self.show_history)
        self.history_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(150, 100, 255, 150);
                color: #000000;
                border: none;
                border-radius: 5px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(150, 100, 255, 200);
            }
        """)
        
        self.reset_btn = QPushButton("Reset")
        self.reset_btn.clicked.connect(self.reset_fields)
        self.reset_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(255, 165, 0, 150);
                color: #000000;
                border: none;
                border-radius: 5px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(255, 165, 0, 200);
            }
        """)
        
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        self.cancel_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(255, 100, 100, 150);
                color: #000000;
                border: none;
                border-radius: 5px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(255, 100, 100, 200);
            }
        """)
        
        self.save_btn = QPushButton("Save Changes")
        self.save_btn.clicked.connect(self.save_changes)
        self.save_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(100, 200, 255, 150);
                color: #000000;
                border: none;
                border-radius: 5px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(100, 200, 255, 200);
            }
        """)
        
        button_layout.addWidget(self.history_btn)
        button_layout.addWidget(self.reset_btn)
        button_layout.addStretch()
        button_layout.addWidget(self.cancel_btn)
        button_layout.addWidget(self.save_btn)
        
        layout.addLayout(button_layout)
        
        # Apply dark theme styling
        self.setStyleSheet("""
            QDialog {
                background-color: #1e1e1e;
                color: #ffffff;
            }
            QTabWidget::pane {
                border: 1px solid rgba(100, 200, 255, 100);
                background-color: rgba(0, 0, 0, 50);
            }
            QTabBar::tab {
                background-color: rgba(20, 30, 40, 150);
                color: #DCDCDC;
                padding: 8px 16px;
                margin-right: 2px;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
            }
            QTabBar::tab:selected {
                background-color: rgba(100, 200, 255, 150);
                color: #000000;
            }
            QLineEdit, QComboBox, QSpinBox, QTextEdit {
                background-color: rgba(20, 30, 40, 150);
                color: #DCDCDC;
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 3px;
                padding: 5px;
            }
            QGroupBox {
                font-weight: bold;
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                color: #64C8FF;
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
            QListWidget {
                background-color: rgba(20, 30, 40, 150);
                color: #DCDCDC;
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 3px;
            }
            QLabel {
                color: #DCDCDC;
            }
        """)
    
    def create_basic_info_tab(self):
        """Create the basic information tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Basic Info Group
        basic_group = QGroupBox("Basic Information")
        basic_layout = QFormLayout(basic_group)
        
        # IP Address (read-only)
        self.ip_edit = QLineEdit(self.asset_data['ip_address'])
        self.ip_edit.setReadOnly(True)
        self.ip_edit.setStyleSheet("background-color: rgba(50, 50, 50, 100);")
        basic_layout.addRow("IP Address:", self.ip_edit)
        
        # Hostname
        self.hostname_edit = QLineEdit()
        basic_layout.addRow("Hostname:", self.hostname_edit)
        
        # OS Type
        self.os_type_combo = QComboBox()
        self.os_type_combo.setEditable(True)
        os_types = ["Unknown", "Windows", "Linux", "macOS", "Router", "Switch", "Printer", "Server", "Workstation"]
        self.os_type_combo.addItems(os_types)
        basic_layout.addRow("OS Type:", self.os_type_combo)
        
        # OS Version
        self.os_version_edit = QLineEdit()
        basic_layout.addRow("OS Version:", self.os_version_edit)
        
        layout.addWidget(basic_group)
        
        # Status Group
        status_group = QGroupBox("Status Information")
        status_layout = QFormLayout(status_group)
        
        # Status
        self.status_combo = QComboBox()
        self.status_combo.addItems(["DISCOVERED", "IDENTIFIED", "KNOWN"])
        status_layout.addRow("Status:", self.status_combo)
        
        # Confidence
        self.confidence_spin = QSpinBox()
        self.confidence_spin.setRange(0, 100)
        self.confidence_spin.setSuffix("%")
        status_layout.addRow("Confidence:", self.confidence_spin)
        
        layout.addWidget(status_group)
        
        layout.addStretch()
        return tab
    
    def create_ports_services_tab(self):
        """Create the ports and services tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Ports Group
        ports_group = QGroupBox("Open Ports")
        ports_layout = QVBoxLayout(ports_group)
        
        # Ports list
        self.ports_list = QListWidget()
        self.ports_list.setMaximumHeight(150)
        ports_layout.addWidget(self.ports_list)
        
        # Port controls
        port_controls = QHBoxLayout()
        
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Port (e.g., 80)")
        
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["tcp", "udp"])
        
        add_port_btn = QPushButton("Add Port")
        add_port_btn.clicked.connect(self.add_port)
        
        remove_port_btn = QPushButton("Remove Selected")
        remove_port_btn.clicked.connect(self.remove_port)
        
        port_controls.addWidget(QLabel("Port:"))
        port_controls.addWidget(self.port_input)
        port_controls.addWidget(QLabel("Protocol:"))
        port_controls.addWidget(self.protocol_combo)
        port_controls.addWidget(add_port_btn)
        port_controls.addWidget(remove_port_btn)
        
        ports_layout.addLayout(port_controls)
        layout.addWidget(ports_group)
        
        # Services Group
        services_group = QGroupBox("Services")
        services_layout = QVBoxLayout(services_group)
        
        # Services list
        self.services_list = QListWidget()
        self.services_list.setMaximumHeight(150)
        services_layout.addWidget(self.services_list)
        
        # Service controls
        service_controls = QHBoxLayout()
        
        self.service_port_input = QLineEdit()
        self.service_port_input.setPlaceholderText("Port")
        
        self.service_name_input = QLineEdit()
        self.service_name_input.setPlaceholderText("Service name")
        
        self.service_version_input = QLineEdit()
        self.service_version_input.setPlaceholderText("Version (optional)")
        
        add_service_btn = QPushButton("Add Service")
        add_service_btn.clicked.connect(self.add_service)
        
        remove_service_btn = QPushButton("Remove Selected")
        remove_service_btn.clicked.connect(self.remove_service)
        
        service_controls.addWidget(QLabel("Port:"))
        service_controls.addWidget(self.service_port_input)
        service_controls.addWidget(QLabel("Service:"))
        service_controls.addWidget(self.service_name_input)
        service_controls.addWidget(QLabel("Version:"))
        service_controls.addWidget(self.service_version_input)
        
        services_layout.addLayout(service_controls)
        
        service_btn_layout = QHBoxLayout()
        service_btn_layout.addWidget(add_service_btn)
        service_btn_layout.addWidget(remove_service_btn)
        service_btn_layout.addStretch()
        services_layout.addLayout(service_btn_layout)
        
        layout.addWidget(services_group)
        
        layout.addStretch()
        return tab
    
    def create_vulnerabilities_tab(self):
        """Create the vulnerabilities tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        vulns_group = QGroupBox("Vulnerabilities")
        vulns_layout = QVBoxLayout(vulns_group)
        
        # Vulnerabilities list
        self.vulns_list = QListWidget()
        vulns_layout.addWidget(self.vulns_list)
        
        # Vulnerability controls
        vuln_controls = QGridLayout()
        
        vuln_controls.addWidget(QLabel("ID/CVE:"), 0, 0)
        self.vuln_id_input = QLineEdit()
        self.vuln_id_input.setPlaceholderText("CVE-2023-1234")
        vuln_controls.addWidget(self.vuln_id_input, 0, 1)
        
        vuln_controls.addWidget(QLabel("Name:"), 1, 0)
        self.vuln_name_input = QLineEdit()
        self.vuln_name_input.setPlaceholderText("Vulnerability name")
        vuln_controls.addWidget(self.vuln_name_input, 1, 1)
        
        vuln_controls.addWidget(QLabel("Severity:"), 2, 0)
        self.vuln_severity_combo = QComboBox()
        self.vuln_severity_combo.addItems(["low", "medium", "high", "critical"])
        vuln_controls.addWidget(self.vuln_severity_combo, 2, 1)
        
        vuln_controls.addWidget(QLabel("Description:"), 3, 0)
        self.vuln_desc_input = QTextEdit()
        self.vuln_desc_input.setMaximumHeight(80)
        self.vuln_desc_input.setPlaceholderText("Vulnerability description")
        vuln_controls.addWidget(self.vuln_desc_input, 3, 1)
        
        vulns_layout.addLayout(vuln_controls)
        
        # Vulnerability buttons
        vuln_btn_layout = QHBoxLayout()
        
        add_vuln_btn = QPushButton("Add Vulnerability")
        add_vuln_btn.clicked.connect(self.add_vulnerability)
        
        remove_vuln_btn = QPushButton("Remove Selected")
        remove_vuln_btn.clicked.connect(self.remove_vulnerability)
        
        vuln_btn_layout.addWidget(add_vuln_btn)
        vuln_btn_layout.addWidget(remove_vuln_btn)
        vuln_btn_layout.addStretch()
        
        vulns_layout.addLayout(vuln_btn_layout)
        
        layout.addWidget(vulns_group)
        return tab
    
    def create_metadata_tab(self):
        """Create the metadata tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        metadata_group = QGroupBox("Additional Metadata")
        metadata_layout = QVBoxLayout(metadata_group)
        
        # Metadata text editor
        self.metadata_edit = QTextEdit()
        self.metadata_edit.setPlaceholderText("Enter metadata as JSON format")
        metadata_layout.addWidget(self.metadata_edit)
        
        # Validation checkbox
        self.validate_json_cb = QCheckBox("Validate JSON format")
        self.validate_json_cb.setChecked(True)
        metadata_layout.addWidget(self.validate_json_cb)
        
        layout.addWidget(metadata_group)
        
        # Notes group
        notes_group = QGroupBox("Notes")
        notes_layout = QVBoxLayout(notes_group)
        
        self.notes_edit = QTextEdit()
        self.notes_edit.setPlaceholderText("Add any additional notes about this asset")
        self.notes_edit.setMaximumHeight(100)
        notes_layout.addWidget(self.notes_edit)
        
        layout.addWidget(notes_group)
        
        return tab
    
    def populate_fields(self):
        """Populate fields with current asset data"""
        # Basic info
        self.hostname_edit.setText(self.asset_data.get('hostname', ''))
        
        os_type = self.asset_data.get('os_type', 'Unknown')
        index = self.os_type_combo.findText(os_type)
        if index >= 0:
            self.os_type_combo.setCurrentIndex(index)
        else:
            self.os_type_combo.setCurrentText(os_type)
        
        self.os_version_edit.setText(self.asset_data.get('os_version', ''))
        
        # Status
        status = self.asset_data.get('status', 'DISCOVERED')
        status_index = self.status_combo.findText(status)
        if status_index >= 0:
            self.status_combo.setCurrentIndex(status_index)
        
        self.confidence_spin.setValue(int(self.asset_data.get('confidence', 0)))
        
        # Ports
        for port in self.asset_data.get('open_ports', []):
            port_text = f"{port.get('port')}/{port.get('protocol', 'tcp')}"
            self.ports_list.addItem(port_text)
        
        # Services
        for service in self.asset_data.get('services', []):
            service_text = f"{service.get('port')}: {service.get('service')}"
            if service.get('version'):
                service_text += f" ({service['version']})"
            self.services_list.addItem(service_text)
        
        # Vulnerabilities
        for vuln in self.asset_data.get('vulnerabilities', []):
            vuln_text = f"{vuln.get('id', 'N/A')} - {vuln.get('name', 'Unknown')} [{vuln.get('severity', 'unknown')}]"
            self.vulns_list.addItem(vuln_text)
        
        # Metadata
        metadata = self.asset_data.get('metadata', {})
        if metadata:
            self.metadata_edit.setPlainText(json.dumps(metadata, indent=2))
        
        # Notes (from metadata if exists)
        notes = metadata.get('notes', '')
        self.notes_edit.setPlainText(notes)
    
    def add_port(self):
        """Add a new port"""
        port_text = self.port_input.text().strip()
        if not port_text:
            return
        
        try:
            port_num = int(port_text)
            if not (1 <= port_num <= 65535):
                QMessageBox.warning(self, "Invalid Port", "Port must be between 1 and 65535")
                return
        except ValueError:
            QMessageBox.warning(self, "Invalid Port", "Port must be a number")
            return
        
        protocol = self.protocol_combo.currentText()
        port_display = f"{port_num}/{protocol}"
        
        # Check for duplicates
        for i in range(self.ports_list.count()):
            if self.ports_list.item(i).text() == port_display:
                QMessageBox.information(self, "Duplicate Port", "This port is already in the list")
                return
        
        self.ports_list.addItem(port_display)
        self.port_input.clear()
    
    def remove_port(self):
        """Remove selected port"""
        current_row = self.ports_list.currentRow()
        if current_row >= 0:
            self.ports_list.takeItem(current_row)
    
    def add_service(self):
        """Add a new service"""
        port = self.service_port_input.text().strip()
        service = self.service_name_input.text().strip()
        version = self.service_version_input.text().strip()
        
        if not port or not service:
            QMessageBox.warning(self, "Missing Information", "Port and service name are required")
            return
        
        try:
            port_num = int(port)
            if not (1 <= port_num <= 65535):
                QMessageBox.warning(self, "Invalid Port", "Port must be between 1 and 65535")
                return
        except ValueError:
            QMessageBox.warning(self, "Invalid Port", "Port must be a number")
            return
        
        service_text = f"{port_num}: {service}"
        if version:
            service_text += f" ({version})"
        
        self.services_list.addItem(service_text)
        self.service_port_input.clear()
        self.service_name_input.clear()
        self.service_version_input.clear()
    
    def remove_service(self):
        """Remove selected service"""
        current_row = self.services_list.currentRow()
        if current_row >= 0:
            self.services_list.takeItem(current_row)
    
    def add_vulnerability(self):
        """Add a new vulnerability"""
        vuln_id = self.vuln_id_input.text().strip()
        vuln_name = self.vuln_name_input.text().strip()
        severity = self.vuln_severity_combo.currentText()
        description = self.vuln_desc_input.toPlainText().strip()
        
        if not vuln_id and not vuln_name:
            QMessageBox.warning(self, "Missing Information", "Either ID or name is required")
            return
        
        vuln_text = f"{vuln_id or 'N/A'} - {vuln_name or 'Unknown'} [{severity}]"
        self.vulns_list.addItem(vuln_text)
        
        self.vuln_id_input.clear()
        self.vuln_name_input.clear()
        self.vuln_desc_input.clear()
    
    def remove_vulnerability(self):
        """Remove selected vulnerability"""
        current_row = self.vulns_list.currentRow()
        if current_row >= 0:
            self.vulns_list.takeItem(current_row)
    
    def reset_fields(self):
        """Reset all fields to original values"""
        reply = QMessageBox.question(
            self, 
            "Reset Fields", 
            "Are you sure you want to reset all fields to their original values?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self.asset_data = self.original_data.copy()
            self.populate_fields()
    
    def save_changes(self):
        """Save the changes to the asset"""
        try:
            # Collect updated data
            updated_data = {
                'hostname': self.hostname_edit.text().strip(),
                'os_type': self.os_type_combo.currentText().strip(),
                'os_version': self.os_version_edit.text().strip(),
                'status': self.status_combo.currentText(),
                'confidence': self.confidence_spin.value()
            }
            
            # Collect ports
            ports = []
            for i in range(self.ports_list.count()):
                port_text = self.ports_list.item(i).text()
                port_parts = port_text.split('/')
                if len(port_parts) == 2:
                    ports.append({
                        'port': int(port_parts[0]),
                        'protocol': port_parts[1]
                    })
            updated_data['open_ports'] = ports
            
            # Collect services
            services = []
            for i in range(self.services_list.count()):
                service_text = self.services_list.item(i).text()
                # Parse "port: service (version)" format
                if ':' in service_text:
                    port_part, service_part = service_text.split(':', 1)
                    port = int(port_part.strip())
                    
                    if '(' in service_part and service_part.endswith(')'):
                        service_name = service_part[:service_part.rfind('(')].strip()
                        version = service_part[service_part.rfind('(')+1:-1].strip()
                    else:
                        service_name = service_part.strip()
                        version = ''
                    
                    services.append({
                        'port': port,
                        'service': service_name,
                        'version': version,
                        'protocol': 'tcp'  # Default to TCP
                    })
            updated_data['services'] = services
            
            # Collect vulnerabilities
            vulnerabilities = []
            for i in range(self.vulns_list.count()):
                vuln_text = self.vulns_list.item(i).text()
                # Parse "ID - Name [severity]" format
                if ' - ' in vuln_text and '[' in vuln_text:
                    id_part, rest = vuln_text.split(' - ', 1)
                    if '[' in rest and rest.endswith(']'):
                        name_part = rest[:rest.rfind('[')].strip()
                        severity = rest[rest.rfind('[')+1:-1].strip()
                    else:
                        name_part = rest
                        severity = 'unknown'
                    
                    vulnerabilities.append({
                        'id': id_part.strip() if id_part.strip() != 'N/A' else '',
                        'name': name_part,
                        'severity': severity,
                        'description': ''
                    })
            updated_data['vulnerabilities'] = vulnerabilities
            
            # Handle metadata
            metadata = {}
            metadata_text = self.metadata_edit.toPlainText().strip()
            if metadata_text:
                if self.validate_json_cb.isChecked():
                    try:
                        metadata = json.loads(metadata_text)
                    except json.JSONDecodeError as e:
                        QMessageBox.warning(self, "Invalid JSON", f"Metadata JSON is invalid: {e}")
                        return
                else:
                    # Store as raw text if validation is disabled
                    metadata = {'raw_metadata': metadata_text}
            
            # Add notes to metadata
            notes = self.notes_edit.toPlainText().strip()
            if notes:
                metadata['notes'] = notes
            
            updated_data['metadata'] = metadata
            
            # Emit the updated data
            self.asset_updated.emit(updated_data)
            self.accept()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save changes: {e}")
    
    def show_history(self):
        """Show asset history dialog"""
        from app.widgets.asset_history_dialog import AssetHistoryDialog
        
        # Extract tenant_id from parent if available
        tenant_id = "default"
        if hasattr(self.parent(), 'tenant_id'):
            tenant_id = self.parent().tenant_id
        
        dialog = AssetHistoryDialog(tenant_id, self.asset_data['ip_address'], self)
        dialog.exec()