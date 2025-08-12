# app/widgets/smart_tool_selector.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QFrame, QButtonGroup, QScrollArea)
from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtGui import QFont, QPixmap

class SmartToolSelector(QWidget):
    """Context-aware tool selector that recommends appropriate tools based on current phase"""
    
    tool_selected = pyqtSignal(str, str)  # tool_name, tool_page
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_phase = "reconnaissance"
        self.discovered_services = []
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the smart tool selector UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Header
        header = QLabel("🎯 Recommended Tools")
        header.setStyleSheet("font-size: 16pt; font-weight: bold; color: #64C8FF; margin-bottom: 10px;")
        layout.addWidget(header)
        
        # Context info
        self.context_label = QLabel()
        self.context_label.setStyleSheet("font-size: 11pt; color: #87CEEB; margin-bottom: 15px;")
        self.context_label.setWordWrap(True)
        layout.addWidget(self.context_label)
        
        # Scroll area for tools
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; }")
        
        self.tools_widget = QWidget()
        self.tools_layout = QVBoxLayout(self.tools_widget)
        scroll.setWidget(self.tools_widget)
        
        layout.addWidget(scroll)
        
        # Update display
        self.update_recommendations()
    
    def set_phase(self, phase):
        """Set current testing phase"""
        self.current_phase = phase
        self.update_recommendations()
    
    def set_discovered_services(self, services):
        """Set discovered services to influence recommendations"""
        self.discovered_services = services
        self.update_recommendations()
    
    def update_recommendations(self):
        """Update tool recommendations based on context"""
        # Clear existing tools
        self.clear_layout(self.tools_layout)
        
        # Get recommendations for current phase
        recommendations = self.get_phase_recommendations()
        
        # Update context label
        context_text = f"Phase: {self.current_phase.title()}"
        if self.discovered_services:
            context_text += f" | Services: {', '.join(self.discovered_services[:3])}"
            if len(self.discovered_services) > 3:
                context_text += f" (+{len(self.discovered_services) - 3} more)"
        self.context_label.setText(context_text)
        
        # Create tool buttons
        for category, tools in recommendations.items():
            if tools:  # Only show categories with tools
                category_frame = self.create_category_frame(category, tools)
                self.tools_layout.addWidget(category_frame)
        
        self.tools_layout.addStretch()
    
    def get_phase_recommendations(self):
        """Get tool recommendations based on current phase and discovered services"""
        
        if self.current_phase == "reconnaissance":
            return {
                "Essential": [
                    ("🌐 OSINT Collection", "osint", "Gather public information about the target"),
                    ("🔍 DNS Enumeration", "recon_enumeration", "Discover subdomains and DNS records"),
                    ("📡 Port Scanning", "recon_enumeration", "Find open ports and services")
                ],
                "Service-Specific": self.get_service_specific_recon_tools(),
                "Advanced": [
                    ("🎯 Huggin Scanner", "huggin_scanner", "AI-powered comprehensive scanning")
                ] if "HTTP" in self.discovered_services else []
            }
        
        elif self.current_phase == "vulnerability_assessment":
            return {
                "Automated": [
                    ("🚀 Huggin Advanced Scanner", "huggin_scanner", "AI-powered vulnerability detection"),
                    ("🔍 Web Vulnerability Scanner", "vuln_scanning", "Traditional web app scanning")
                ],
                "Manual Testing": [
                    ("🌐 Web Application Testing", "web_exploits", "Manual web app security testing"),
                    ("🗄️ Database Testing", "databases", "Database security assessment")
                ] if any(db in self.discovered_services for db in ["MySQL", "MSSQL", "PostgreSQL"]) else [
                    ("🌐 Web Application Testing", "web_exploits", "Manual web app security testing")
                ],
                "Service-Specific": self.get_service_specific_vuln_tools()
            }
        
        elif self.current_phase == "exploitation":
            return {
                "Web Exploitation": [
                    ("💥 Web Exploits", "web_exploits", "Exploit web application vulnerabilities"),
                    ("🔓 Authentication Bypass", "web_exploits", "Test authentication mechanisms")
                ] if "HTTP" in self.discovered_services else [],
                "System Exploitation": [
                    ("💻 OS Exploits", "os_exploits", "Operating system exploitation"),
                    ("🔐 Privilege Escalation", "post_exploitation", "Escalate system privileges")
                ],
                "Network Exploitation": self.get_network_exploit_tools()
            }
        
        elif self.current_phase == "post_exploitation":
            return {
                "Access Management": [
                    ("🐚 Shell Management", "shell_management", "Manage compromised systems"),
                    ("🔑 Credential Harvesting", "cracking", "Extract and crack credentials")
                ],
                "Persistence": [
                    ("🔄 Lateral Movement", "post_exploitation", "Move through the network"),
                    ("📊 Data Exfiltration", "post_exploitation", "Extract sensitive information")
                ],
                "Cleanup": [
                    ("🧹 Anti-Forensics", "post_exploitation", "Cover tracks and clean up")
                ]
            }
        
        elif self.current_phase == "reporting":
            return {
                "Documentation": [
                    ("📋 Findings Management", "findings", "Document and organize findings"),
                    ("📊 Report Generation", "findings", "Generate comprehensive reports")
                ],
                "Analysis": [
                    ("🔗 Vulnerability Correlation", "findings", "Analyze attack chains"),
                    ("📈 Risk Assessment", "findings", "Assess business impact")
                ]
            }
        
        return {"Getting Started": [("🏠 Home", "home", "Return to main dashboard")]}
    
    def get_service_specific_recon_tools(self):
        """Get reconnaissance tools based on discovered services"""
        tools = []
        
        if "HTTP" in self.discovered_services or "HTTPS" in self.discovered_services:
            tools.append(("🌐 HTTP Fingerprinting", "recon_enumeration", "Identify web technologies"))
            tools.append(("📁 Directory Enumeration", "recon_enumeration", "Find hidden directories"))
        
        if "SMB" in self.discovered_services:
            tools.append(("📂 SMB Enumeration", "recon_enumeration", "Enumerate SMB shares"))
        
        if "RPC" in self.discovered_services:
            tools.append(("🔌 RPC Enumeration", "recon_enumeration", "Enumerate RPC services"))
        
        if "LDAP" in self.discovered_services:
            tools.append(("📖 LDAP Enumeration", "recon_enumeration", "Query LDAP directory"))
        
        return tools
    
    def get_service_specific_vuln_tools(self):
        """Get vulnerability assessment tools based on services"""
        tools = []
        
        if any(db in self.discovered_services for db in ["MySQL", "MSSQL", "PostgreSQL", "Oracle"]):
            tools.append(("🗄️ Database Security Testing", "databases", "Test database security"))
        
        if "SMTP" in self.discovered_services:
            tools.append(("📧 Email Security Testing", "enumeration", "Test email server security"))
        
        if "DNS" in self.discovered_services:
            tools.append(("🌐 DNS Security Testing", "enumeration", "Test DNS server security"))
        
        return tools
    
    def get_network_exploit_tools(self):
        """Get network exploitation tools based on services"""
        tools = []
        
        if "SMB" in self.discovered_services:
            tools.append(("📂 SMB Exploitation", "os_exploits", "Exploit SMB vulnerabilities"))
        
        if "RPC" in self.discovered_services:
            tools.append(("🔌 RPC Exploitation", "os_exploits", "Exploit RPC services"))
        
        if any(db in self.discovered_services for db in ["MySQL", "MSSQL"]):
            tools.append(("🗄️ Database Exploitation", "databases", "Exploit database vulnerabilities"))
        
        return tools
    
    def create_category_frame(self, category, tools):
        """Create a frame for a tool category"""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 100);
                border-radius: 8px;
                border: 1px solid rgba(100, 200, 255, 50);
                margin: 5px 0;
            }
        """)
        
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(15, 10, 15, 10)
        
        # Category header
        header = QLabel(category)
        header.setStyleSheet("font-size: 12pt; font-weight: bold; color: #FFD700; margin-bottom: 5px;")
        layout.addWidget(header)
        
        # Tool buttons
        for tool_name, tool_page, description in tools:
            tool_button = self.create_tool_button(tool_name, tool_page, description)
            layout.addWidget(tool_button)
        
        return frame
    
    def create_tool_button(self, tool_name, tool_page, description):
        """Create a tool button with description"""
        button = QPushButton()
        button.setStyleSheet("""
            QPushButton {
                background-color: rgba(20, 30, 40, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 6px;
                color: #DCDCDC;
                font-size: 11pt;
                padding: 10px;
                text-align: left;
                margin: 2px 0;
            }
            QPushButton:hover {
                background-color: rgba(40, 60, 80, 200);
                border: 2px solid #64C8FF;
                color: #FFFFFF;
            }
            QPushButton:pressed {
                background-color: rgba(60, 100, 140, 220);
            }
        """)
        
        # Create button layout
        button_layout = QVBoxLayout()
        button_layout.setContentsMargins(5, 5, 5, 5)
        
        name_label = QLabel(tool_name)
        name_label.setStyleSheet("font-weight: bold; font-size: 12pt;")
        button_layout.addWidget(name_label)
        
        desc_label = QLabel(description)
        desc_label.setStyleSheet("color: #87CEEB; font-size: 10pt;")
        desc_label.setWordWrap(True)
        button_layout.addWidget(desc_label)
        
        # Create widget to hold layout
        button_widget = QWidget()
        button_widget.setLayout(button_layout)
        
        # Set widget as button content
        button_layout_main = QVBoxLayout(button)
        button_layout_main.setContentsMargins(0, 0, 0, 0)
        button_layout_main.addWidget(button_widget)
        
        button.clicked.connect(lambda: self.tool_selected.emit(tool_name, tool_page))
        
        return button
    
    def clear_layout(self, layout):
        """Clear all widgets from a layout"""
        while layout.count():
            child = layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()