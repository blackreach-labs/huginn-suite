#!/usr/bin/env python3
"""
Asset Update Feature Demo

This example demonstrates the complete Update Asset functionality including:
1. Creating sample assets
2. Opening the update dialog
3. Viewing asset history
4. Making updates and seeing the changes
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PyQt6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QPushButton, QLabel
from PyQt6.QtCore import Qt
from app.core.asset_manager import asset_manager
from app.widgets.asset_update_dialog import AssetUpdateDialog
from app.widgets.asset_history_dialog import AssetHistoryDialog

class AssetUpdateDemo(QMainWindow):
    """Demo application for asset update functionality"""
    
    def __init__(self):
        super().__init__()
        self.tenant_id = "demo_tenant"
        self.setup_ui()
        self.create_sample_assets()
        
    def setup_ui(self):
        """Setup the demo UI"""
        self.setWindowTitle("Asset Update Feature Demo")
        self.setGeometry(100, 100, 600, 400)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout(central_widget)
        layout.setSpacing(20)
        
        # Title
        title = QLabel("Asset Update Feature Demo")
        title.setStyleSheet("font-size: 18pt; font-weight: bold; color: #64C8FF;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # Description
        desc = QLabel("""
This demo showcases the Asset Update functionality:

• Update basic asset information (hostname, OS, status)
• Manage ports and services
• Track vulnerabilities
• View change history
• Add custom metadata and notes

Click the buttons below to interact with sample assets.
        """)\n        desc.setStyleSheet(\"color: #DCDCDC; font-size: 12pt;\")\n        desc.setWordWrap(True)\n        layout.addWidget(desc)\n        \n        # Buttons for different assets\n        self.create_asset_button(layout, \"Web Server (192.168.1.10)\", \"192.168.1.10\")\n        self.create_asset_button(layout, \"Database Server (192.168.1.20)\", \"192.168.1.20\")\n        self.create_asset_button(layout, \"Workstation (192.168.1.100)\", \"192.168.1.100\")\n        \n        layout.addStretch()\n        \n        # Apply dark theme\n        self.setStyleSheet(\"\"\"\n            QMainWindow {\n                background-color: #1e1e1e;\n                color: #ffffff;\n            }\n            QPushButton {\n                background-color: rgba(100, 200, 255, 150);\n                color: #000000;\n                border: none;\n                border-radius: 8px;\n                padding: 12px;\n                font-weight: bold;\n                font-size: 12pt;\n            }\n            QPushButton:hover {\n                background-color: rgba(100, 200, 255, 200);\n            }\n            QLabel {\n                color: #DCDCDC;\n            }\n        \"\"\")\n    \n    def create_asset_button(self, layout, text, ip_address):\n        \"\"\"Create a button for an asset\"\"\"\n        btn = QPushButton(f\"Update {text}\")\n        btn.clicked.connect(lambda: self.open_update_dialog(ip_address))\n        layout.addWidget(btn)\n        \n        # Add history button\n        history_btn = QPushButton(f\"View History - {text}\")\n        history_btn.clicked.connect(lambda: self.open_history_dialog(ip_address))\n        history_btn.setStyleSheet(\"\"\"\n            QPushButton {\n                background-color: rgba(150, 100, 255, 150);\n                color: #000000;\n                border: none;\n                border-radius: 8px;\n                padding: 8px;\n                font-weight: bold;\n                font-size: 10pt;\n            }\n            QPushButton:hover {\n                background-color: rgba(150, 100, 255, 200);\n            }\n        \"\"\")\n        layout.addWidget(history_btn)\n    \n    def create_sample_assets(self):\n        \"\"\"Create sample assets for demonstration\"\"\"\n        sample_assets = [\n            {\n                'ip_address': '192.168.1.10',\n                'hostname': 'web-server-01',\n                'os_type': 'Linux',\n                'os_version': 'Ubuntu 22.04 LTS',\n                'status': 'KNOWN',\n                'confidence': 95,\n                'open_ports': [\n                    {'port': 22, 'protocol': 'tcp'},\n                    {'port': 80, 'protocol': 'tcp'},\n                    {'port': 443, 'protocol': 'tcp'}\n                ],\n                'services': [\n                    {'port': 22, 'service': 'ssh', 'version': 'OpenSSH 8.9', 'protocol': 'tcp'},\n                    {'port': 80, 'service': 'http', 'version': 'Apache 2.4.52', 'protocol': 'tcp'},\n                    {'port': 443, 'service': 'https', 'version': 'Apache 2.4.52', 'protocol': 'tcp'}\n                ],\n                'vulnerabilities': [\n                    {'id': 'CVE-2023-0001', 'name': 'Apache HTTP Server Vulnerability', 'severity': 'medium', 'description': 'Sample vulnerability'}\n                ],\n                'metadata': {\n                    'discovery_method': 'nmap_scan',\n                    'environment': 'production',\n                    'owner': 'web_team',\n                    'notes': 'Primary web server for company website'\n                }\n            },\n            {\n                'ip_address': '192.168.1.20',\n                'hostname': 'db-server-01',\n                'os_type': 'Windows',\n                'os_version': 'Windows Server 2019',\n                'status': 'IDENTIFIED',\n                'confidence': 85,\n                'open_ports': [\n                    {'port': 1433, 'protocol': 'tcp'},\n                    {'port': 3389, 'protocol': 'tcp'}\n                ],\n                'services': [\n                    {'port': 1433, 'service': 'mssql', 'version': 'SQL Server 2019', 'protocol': 'tcp'},\n                    {'port': 3389, 'service': 'rdp', 'version': 'Terminal Services', 'protocol': 'tcp'}\n                ],\n                'vulnerabilities': [\n                    {'id': 'CVE-2023-0002', 'name': 'SQL Server Authentication Bypass', 'severity': 'high', 'description': 'Critical database vulnerability'}\n                ],\n                'metadata': {\n                    'discovery_method': 'port_scan',\n                    'environment': 'production',\n                    'owner': 'database_team',\n                    'notes': 'Main database server - handle with care'\n                }\n            },\n            {\n                'ip_address': '192.168.1.100',\n                'hostname': 'workstation-05',\n                'os_type': 'Windows',\n                'os_version': 'Windows 11 Pro',\n                'status': 'DISCOVERED',\n                'confidence': 60,\n                'open_ports': [\n                    {'port': 135, 'protocol': 'tcp'},\n                    {'port': 445, 'protocol': 'tcp'}\n                ],\n                'services': [\n                    {'port': 135, 'service': 'rpc', 'version': 'Microsoft RPC', 'protocol': 'tcp'},\n                    {'port': 445, 'service': 'smb', 'version': 'SMB 3.1.1', 'protocol': 'tcp'}\n                ],\n                'vulnerabilities': [],\n                'metadata': {\n                    'discovery_method': 'ping_sweep',\n                    'environment': 'office',\n                    'owner': 'unknown',\n                    'notes': 'Recently discovered workstation - needs investigation'\n                }\n            }\n        ]\n        \n        print(\"Creating sample assets...\")\n        for asset_data in sample_assets:\n            asset_id = asset_manager.add_or_update_asset(self.tenant_id, **asset_data)\n            print(f\"Created asset {asset_data['ip_address']} with ID: {asset_id}\")\n        \n        print(\"Sample assets created successfully!\")\n    \n    def open_update_dialog(self, ip_address):\n        \"\"\"Open the update dialog for an asset\"\"\"\n        asset = asset_manager.get_asset_by_ip(self.tenant_id, ip_address)\n        if asset:\n            dialog = AssetUpdateDialog(asset, self)\n            dialog.asset_updated.connect(lambda data: self.on_asset_updated(data, ip_address))\n            dialog.exec()\n        else:\n            print(f\"Asset {ip_address} not found\")\n    \n    def open_history_dialog(self, ip_address):\n        \"\"\"Open the history dialog for an asset\"\"\"\n        dialog = AssetHistoryDialog(self.tenant_id, ip_address, self)\n        dialog.exec()\n    \n    def on_asset_updated(self, updated_data, ip_address):\n        \"\"\"Handle asset update\"\"\"\n        try:\n            # Update the asset in the database\n            asset_manager.add_or_update_asset(\n                tenant_id=self.tenant_id,\n                ip_address=ip_address,\n                **updated_data\n            )\n            \n            print(f\"Asset {ip_address} updated successfully!\")\n            print(\"Updated fields:\")\n            for key, value in updated_data.items():\n                print(f\"  {key}: {value}\")\n            \n        except Exception as e:\n            print(f\"Error updating asset: {e}\")\n    \n    def closeEvent(self, event):\n        \"\"\"Clean up when closing\"\"\"\n        # Remove sample assets\n        print(\"Cleaning up sample assets...\")\n        sample_ips = ['192.168.1.10', '192.168.1.20', '192.168.1.100']\n        for ip in sample_ips:\n            asset_manager.remove_asset(self.tenant_id, ip)\n        print(\"Cleanup complete!\")\n        event.accept()\n\ndef main():\n    \"\"\"Main function\"\"\"\n    app = QApplication(sys.argv)\n    \n    # Set application properties\n    app.setApplicationName(\"Asset Update Demo\")\n    app.setApplicationVersion(\"1.0\")\n    \n    # Create and show the demo window\n    demo = AssetUpdateDemo()\n    demo.show()\n    \n    # Run the application\n    sys.exit(app.exec())\n\nif __name__ == \"__main__\":\n    main()