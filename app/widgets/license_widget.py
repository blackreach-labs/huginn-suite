# app/widgets/license_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QLineEdit, QPushButton, QTextEdit, QGroupBox,
                            QTableWidget, QTableWidgetItem, QHeaderView,
                            QMessageBox, QProgressBar)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont, QPixmap, QPainter, QColor
from app.core.license_manager import license_manager

class LicenseWidget(QWidget):
    """Professional license management widget"""
    
    license_updated = pyqtSignal(dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.connect_signals()
        self.update_license_display()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # Header
        header = QLabel("Huggin Licensed Features")
        header.setStyleSheet("font-size: 22pt; font-weight: bold; color: #2c3e50; padding: 15px; background: #ecf0f1; border-radius: 8px;")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)
        
        # License Status
        status_group = QGroupBox("License Status")
        status_group.setStyleSheet("QGroupBox { font-weight: bold; border: 2px solid #34495e; border-radius: 6px; margin: 5px; padding-top: 10px; }")
        status_layout = QVBoxLayout(status_group)
        
        self.status_label = QLabel("Free Version")
        self.status_label.setStyleSheet("font-size: 14pt; font-weight: bold; color: #e74c3c;")
        status_layout.addWidget(self.status_label)
        
        self.expiry_label = QLabel("Limited features available")
        self.expiry_label.setStyleSheet("color: #7f8c8d;")
        status_layout.addWidget(self.expiry_label)
        
        layout.addWidget(status_group)
        
        # License Key Input
        key_group = QGroupBox("License Management")
        key_group.setStyleSheet("QGroupBox { font-weight: bold; border: 2px solid #2980b9; border-radius: 6px; margin: 5px; padding-top: 10px; }")
        key_layout = QVBoxLayout(key_group)
        
        self.license_input = QLineEdit()
        self.license_input.setPlaceholderText("Enter your license key...")
        self.license_input.setStyleSheet("padding: 8px; font-size: 11pt;")
        key_layout.addWidget(self.license_input)
        
        button_layout = QHBoxLayout()
        self.validate_btn = QPushButton("Validate License")
        self.trial_btn = QPushButton("Generate Trial")
        self.purchase_btn = QPushButton("Purchase License")
        
        self.validate_btn.setStyleSheet("padding: 10px 16px; font-weight: bold; background: #27ae60; color: white; border-radius: 4px;")
        self.trial_btn.setStyleSheet("padding: 10px 16px; font-weight: bold; background: #f39c12; color: white; border-radius: 4px;")
        self.purchase_btn.setStyleSheet("padding: 10px 16px; font-weight: bold; background: #3498db; color: white; border-radius: 4px;")
        
        button_layout.addWidget(self.validate_btn)
        button_layout.addWidget(self.trial_btn)
        button_layout.addWidget(self.purchase_btn)
        key_layout.addLayout(button_layout)
        
        layout.addWidget(key_group)
        
        # Features Table
        features_group = QGroupBox("Available Features")
        features_group.setStyleSheet("QGroupBox { font-weight: bold; border: 2px solid #e67e22; border-radius: 6px; margin: 5px; padding-top: 10px; }")
        features_layout = QVBoxLayout(features_group)
        
        self.features_table = QTableWidget()
        self.features_table.setColumnCount(3)
        self.features_table.setHorizontalHeaderLabels(["Feature", "Status", "Tier"])
        self.features_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        # Remove height restriction to use available space
        features_layout.addWidget(self.features_table)
        
        layout.addWidget(features_group)
        
        # Upgrade Information
        upgrade_group = QGroupBox("Pricing & Upgrade")
        upgrade_group.setStyleSheet("QGroupBox { font-weight: bold; border: 2px solid #8e44ad; border-radius: 6px; margin: 5px; padding-top: 10px; }")
        upgrade_group.setFixedHeight(200)
        upgrade_layout = QVBoxLayout(upgrade_group)
        
        self.upgrade_text = QTextEdit()
        self.upgrade_text.setFixedHeight(130)
        self.upgrade_text.setReadOnly(True)
        upgrade_layout.addWidget(self.upgrade_text)
        
        self.upgrade_btn = QPushButton("Upgrade to Professional/Enterprise")
        self.upgrade_btn.setStyleSheet("padding: 12px; font-size: 12pt; font-weight: bold; background: #8e44ad; color: white; border-radius: 6px;")
        upgrade_layout.addWidget(self.upgrade_btn)
        
        layout.addWidget(upgrade_group)
        

        
    def connect_signals(self):
        self.validate_btn.clicked.connect(self.validate_license)
        self.trial_btn.clicked.connect(self.generate_trial)
        self.purchase_btn.clicked.connect(self.purchase_license)
        self.upgrade_btn.clicked.connect(self.show_upgrade_info)
        license_manager.license_event.connect(self.handle_license_event)
        
    def validate_license(self):
        license_key = self.license_input.text().strip()
        if not license_key:
            QMessageBox.warning(self, "Error", "Please enter a license key")
            return
            
        result = license_manager.validate_license(license_key)
        
        if result['valid']:
            QMessageBox.information(self, "Success", 
                                  f"License validated successfully!\nType: {result['license_type']}")
            self.update_license_display()
            self.license_updated.emit(result)
        else:
            QMessageBox.critical(self, "Error", f"License validation failed:\n{result['error']}")
            
    def generate_trial(self):
        trial_key = license_manager.generate_trial_license(30)
        self.license_input.setText(trial_key)
        
        reply = QMessageBox.question(self, "Trial License", 
                                   "30-day trial license generated. Validate now?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            self.validate_license()
            
    def update_license_display(self):
        license_info = license_manager.get_license_info()
        
        if license_info['licensed']:
            self.status_label.setText(f"Licensed: {license_info['license_type']}")
            self.status_label.setStyleSheet("font-size: 14pt; font-weight: bold; color: #27ae60;")
            
            if license_info['expiry_date']:
                days_remaining = license_info.get('days_remaining', 0)
                self.expiry_label.setText(f"Expires: {license_info['expiry_date'][:10]} ({days_remaining} days)")
                
            license_type = license_info['license_type']
            if 'Professional' in license_type or 'Enterprise' in license_type:
                self.upgrade_btn.hide()
            else:
                self.upgrade_btn.show()
        else:
            self.status_label.setText("Free Version")
            self.status_label.setStyleSheet("font-size: 14pt; font-weight: bold; color: #e74c3c;")
            self.expiry_label.setText("Limited features available")
            self.upgrade_btn.show()
            
        self.update_features_table()
        self.update_upgrade_text()
        
    def update_features_table(self):
        features = license_manager.get_feature_descriptions()
        enabled_features = license_manager.get_enabled_features()
        
        self.features_table.setRowCount(len(features))
        
        for row, (feature_key, feature_info) in enumerate(features.items()):
            name_item = QTableWidgetItem(feature_info['name'])
            self.features_table.setItem(row, 0, name_item)
            
            is_enabled = feature_key in enabled_features
            status_item = QTableWidgetItem("✓ Enabled" if is_enabled else "✗ Disabled")
            status_item.setForeground(QColor("#27ae60" if is_enabled else "#e74c3c"))
            self.features_table.setItem(row, 1, status_item)
            
            tier_item = QTableWidgetItem(feature_info['tier'])
            self.features_table.setItem(row, 2, tier_item)
            
    def update_upgrade_text(self):
        license_info = license_manager.get_license_info()
        
        if license_info['licensed']:
            text = f"""
Current License: {license_info['license_type']}
Features Enabled: {len(license_info['features'])}
Days Remaining: {license_info.get('days_remaining', 'N/A')}

Thank you for supporting Huggin Professional!
            """
        else:
            text = """
Upgrade to Huggin Professional for advanced features:

Professional Tier ($99/month):
• Stealth Mode - Advanced evasion techniques
• ProxyChains - Multi-proxy traffic routing  
• Web Scanner - OWASP Top 10 vulnerability detection
• Basic Hacking Mode - Limited exploit execution
• Priority Support

Enterprise Tier ($299/month):
• Full Exploit Database - CVE integration
• Post-Exploitation Framework - Complete workflow
• AD Enumeration - Kerberoasting, BloodHound analysis
• Advanced Hacking Mode - Full exploit frameworks
• Custom API Integrations - Shodan, VirusTotal
• Executive Reporting - Compliance templates
            """
            
        self.upgrade_text.setPlainText(text.strip())
        
    def purchase_license(self):
        """Open purchase page"""
        import webbrowser
        webbrowser.open(license_manager.get_purchase_url())
        
    def show_upgrade_info(self):
        QMessageBox.information(self, "Upgrade Information", 
                              "Visit https://huggin.net/upgrade to purchase a license.\n\n"
                              "Professional Tier: $99/month\n"
                              "Enterprise Tier: $299/month\n\n"
                              "Contact sales@huggin.net for enterprise pricing.")
                              
    def handle_license_event(self, event_type, message, data):
        if event_type == 'license_validated':
            self.update_license_display()
        elif event_type == 'license_expired':
            QMessageBox.warning(self, "License Expired", 
                              "Your license has expired. Please renew to continue using premium features.")
        elif event_type == 'license_expiring':
            QMessageBox.information(self, "License Expiring", message)