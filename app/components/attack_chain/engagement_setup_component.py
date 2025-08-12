# app/components/attack_chain/engagement_setup_component.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QLineEdit, QTextEdit, QCheckBox, QPushButton, QTableWidget)
from PyQt6.QtCore import pyqtSignal

class EngagementSetupComponent(QWidget):
    """Engagement setup and target configuration component"""
    
    status_updated = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Target configuration
        target_label = QLabel("🎯 Target Configuration")
        target_label.setStyleSheet("font-size: 14pt; font-weight: bold; color: #FFD700;")
        layout.addWidget(target_label)
        
        # Target name
        self.target_name = QLineEdit()
        self.target_name.setPlaceholderText("Target name")
        layout.addWidget(self.target_name)
        
        # Primary targets
        self.primary_target = QTextEdit()
        self.primary_target.setMaximumHeight(60)
        self.primary_target.setPlaceholderText("In-scope targets")
        layout.addWidget(self.primary_target)
        
        # Scope validation
        self.scope_status = QLabel("Scope: Not configured")
        self.scope_status.setStyleSheet("color: #FFA500; padding: 5px;")
        layout.addWidget(self.scope_status)
        
        # Testing permissions
        permissions_layout = QVBoxLayout()
        self.dos_allowed = QCheckBox("DoS testing allowed")
        self.social_eng_allowed = QCheckBox("Social engineering allowed")
        self.physical_allowed = QCheckBox("Physical testing allowed")
        
        for checkbox in [self.dos_allowed, self.social_eng_allowed, self.physical_allowed]:
            permissions_layout.addWidget(checkbox)
        
        layout.addLayout(permissions_layout)
        
        # Action buttons
        button_layout = QHBoxLayout()
        
        add_btn = QPushButton("📝 Add Target Profile")
        add_btn.clicked.connect(self.add_target)
        button_layout.addWidget(add_btn)
        
        campaign_btn = QPushButton("🎯 Multi-Target Campaign")
        campaign_btn.clicked.connect(self.launch_campaign)
        button_layout.addWidget(campaign_btn)
        
        layout.addLayout(button_layout)
        
        # Target table
        self.target_table = QTableWidget()
        self.target_table.setColumnCount(5)
        self.target_table.setHorizontalHeaderLabels(["Name", "Type", "Target", "Priority", "Status"])
        self.target_table.setMaximumHeight(120)
        layout.addWidget(self.target_table)
    
    def add_target(self):
        """Add target to configuration"""
        name = self.target_name.text().strip()
        target = self.primary_target.toPlainText().strip()
        
        if name and target:
            row = self.target_table.rowCount()
            self.target_table.insertRow(row)
            
            from PyQt6.QtWidgets import QTableWidgetItem
            self.target_table.setItem(row, 0, QTableWidgetItem(name))
            self.target_table.setItem(row, 1, QTableWidgetItem("External"))
            self.target_table.setItem(row, 2, QTableWidgetItem(target))
            self.target_table.setItem(row, 3, QTableWidgetItem("High"))
            self.target_table.setItem(row, 4, QTableWidgetItem("Active"))
            
            self.target_name.clear()
            self.primary_target.clear()
            self.status_updated.emit(f"Added target: {name}")
    
    def launch_campaign(self):
        """Launch multi-target campaign"""
        self.status_updated.emit("Multi-target campaign launched")