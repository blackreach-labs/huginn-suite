# app/widgets/threat_intel_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QPushButton, QTextEdit, QGroupBox, QTableWidget, QTableWidgetItem)
from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtGui import QColor
from app.core.threat_intelligence import threat_intelligence

class ThreatIntelWidget(QWidget):
    """Widget for threat intelligence feed management and IOC checking."""
    
    threat_checked = pyqtSignal(str, dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.connect_signals()
        
    def setup_ui(self):
        """Setup threat intelligence widget UI."""
        layout = QVBoxLayout(self)
        
        # Title
        title = QLabel("Threat Intelligence")
        title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #64C8FF;")
        layout.addWidget(title)
        
        # IOC Check section
        ioc_group = QGroupBox("IOC Reputation Check")
        ioc_layout = QVBoxLayout(ioc_group)
        
        # Check button
        check_layout = QHBoxLayout()
        self.check_button = QPushButton("Check Target Reputation")
        self.check_button.clicked.connect(self.check_target_reputation)
        check_layout.addWidget(self.check_button)
        
        self.feed_status_button = QPushButton("Check Feed Status")
        self.feed_status_button.clicked.connect(self.check_feed_status)
        check_layout.addWidget(self.feed_status_button)
        
        check_layout.addStretch()
        ioc_layout.addLayout(check_layout)
        layout.addWidget(ioc_group)
        
        # Threats table
        threats_label = QLabel("Threat Intelligence Results:")
        threats_label.setStyleSheet("font-weight: bold; margin-top: 10px;")
        layout.addWidget(threats_label)
        
        self.threats_table = QTableWidget()
        self.threats_table.setColumnCount(4)
        self.threats_table.setHorizontalHeaderLabels(["Source", "Type", "Severity", "Description"])
        self.threats_table.setMaximumHeight(200)
        layout.addWidget(self.threats_table)
        
        # Results area
        results_label = QLabel("Detailed Results:")
        results_label.setStyleSheet("font-weight: bold; margin-top: 10px;")
        layout.addWidget(results_label)
        
        self.results_output = QTextEdit()
        self.results_output.setMaximumHeight(150)
        self.results_output.setPlaceholderText("Threat intelligence results will appear here...")
        layout.addWidget(self.results_output)
        
        layout.addStretch()
        
    def connect_signals(self):
        """Connect threat intelligence signals."""
        threat_intelligence.threat_data_updated.connect(self.on_threat_data_updated)
        
    def check_target_reputation(self):
        """Check target reputation against threat feeds."""
        # Get target from parent if available
        target = "example.com"
        if hasattr(self.parent(), 'target_input'):
            target = self.parent().target_input.text().strip() or target
            
        self.results_output.append(f"Checking {target} against threat intelligence feeds...")
        self.threats_table.setRowCount(0)
        
        result = threat_intelligence.get_ioc_summary(target)
        
    def check_feed_status(self):
        """Check status of threat intelligence feeds."""
        self.results_output.append("Checking threat intelligence feed status...")
        
        status = threat_intelligence.get_feed_status()
        
        self.results_output.append("Feed Status:")
        for feed_name, feed_info in status.items():
            status_text = feed_info["status"].upper()
            self.results_output.append(f"  {feed_name}: {status_text}")
        self.results_output.append("---")
        
    def on_threat_data_updated(self, check_type, result):
        """Handle threat intelligence data update."""
        target = result.get("ip", result.get("domain", "Unknown"))
        threats = result.get("threats", [])
        feeds_checked = result.get("feeds_checked", [])
        
        self.results_output.append(f"Target: {target}")
        self.results_output.append(f"Feeds checked: {', '.join(feeds_checked)}")
        self.results_output.append(f"Threats found: {len(threats)}")
        
        # Update threats table
        self.threats_table.setRowCount(len(threats))
        
        for i, threat in enumerate(threats):
            self.threats_table.setItem(i, 0, QTableWidgetItem(threat.get("source", "Unknown")))
            self.threats_table.setItem(i, 1, QTableWidgetItem(threat.get("type", "Unknown")))
            
            severity = threat.get("severity", "medium")
            severity_item = QTableWidgetItem(severity.upper())
            
            # Color code severity
            if severity.lower() == "high":
                severity_item.setBackground(QColor(255, 100, 100, 100))
            elif severity.lower() == "medium":
                severity_item.setBackground(QColor(255, 200, 100, 100))
            else:
                severity_item.setBackground(QColor(200, 200, 200, 100))
                
            self.threats_table.setItem(i, 2, severity_item)
            self.threats_table.setItem(i, 3, QTableWidgetItem(threat.get("description", "No description")))
        
        if threats:
            self.results_output.append("⚠️ THREATS DETECTED - See table above for details")
        else:
            self.results_output.append("✅ No threats found in checked feeds")
            
        self.results_output.append("---")
        self.threat_checked.emit(check_type, result)