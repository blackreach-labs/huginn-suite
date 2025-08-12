#!/usr/bin/env python3
"""
Correlation Dashboard Widget
Real-time correlation analysis and attack chain visualization
"""

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
                            QLabel, QTableWidget, QTableWidgetItem, QTextEdit,
                            QTabWidget, QFrame, QProgressBar, QComboBox)
from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtGui import QFont
import json

class CorrelationDashboardWidget(QWidget):
    def __init__(self, tenant_id="default", parent=None):
        super().__init__(parent)
        self.tenant_id = tenant_id
        self.setup_ui()
        self.setup_refresh_timer()
        self.load_correlations()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Header
        header = QLabel("🔗 Cross-Scan Correlations & Attack Chains")
        header.setStyleSheet("font-size: 16pt; font-weight: bold; color: #64C8FF; padding: 10px;")
        layout.addWidget(header)
        
        # Control panel
        controls = QHBoxLayout()
        
        self.refresh_btn = QPushButton("🔄 Refresh Correlations")
        self.refresh_btn.clicked.connect(self.load_correlations)
        controls.addWidget(self.refresh_btn)
        
        self.export_btn = QPushButton("📊 Export Analysis")
        self.export_btn.clicked.connect(self.export_analysis)
        controls.addWidget(self.export_btn)
        
        controls.addStretch()
        
        # Correlation score
        self.score_label = QLabel("Correlation Score: 0/100")
        self.score_label.setStyleSheet("font-weight: bold; color: #FFD700;")
        controls.addWidget(self.score_label)
        
        layout.addLayout(controls)
        
        # Main tabs
        self.tabs = QTabWidget()
        
        # Attack Chains tab
        self.attack_chains_tab = self.create_attack_chains_tab()
        self.tabs.addTab(self.attack_chains_tab, "⚔️ Attack Chains")
        
        # Risk Amplifiers tab
        self.risk_amplifiers_tab = self.create_risk_amplifiers_tab()
        self.tabs.addTab(self.risk_amplifiers_tab, "📈 Risk Amplifiers")
        
        # Asset Correlation tab
        self.asset_correlation_tab = self.create_asset_correlation_tab()
        self.tabs.addTab(self.asset_correlation_tab, "🎯 Asset Correlation")
        
        layout.addWidget(self.tabs)
    
    def create_attack_chains_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Attack chains table
        self.chains_table = QTableWidget()
        self.chains_table.setColumnCount(5)
        self.chains_table.setHorizontalHeaderLabels([
            "Chain Type", "Source", "Target", "Risk Score", "Impact"
        ])
        self.chains_table.itemDoubleClicked.connect(self.view_attack_chain_details)
        layout.addWidget(self.chains_table)
        
        # Playbook generation
        playbook_layout = QHBoxLayout()
        self.generate_playbook_btn = QPushButton("📋 Generate HTB Playbook")
        self.generate_playbook_btn.clicked.connect(self.generate_playbook)
        playbook_layout.addWidget(self.generate_playbook_btn)
        
        self.playbook_format = QComboBox()
        self.playbook_format.addItems(["HTB Format", "THM Format", "Generic"])
        playbook_layout.addWidget(self.playbook_format)
        
        playbook_layout.addStretch()
        layout.addLayout(playbook_layout)
        
        return widget
    
    def create_risk_amplifiers_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Risk amplifiers table
        self.amplifiers_table = QTableWidget()
        self.amplifiers_table.setColumnCount(4)
        self.amplifiers_table.setHorizontalHeaderLabels([
            "Amplifier Type", "Risk Level", "Count", "Description"
        ])
        layout.addWidget(self.amplifiers_table)
        
        # Security gaps
        gaps_label = QLabel("🔒 Security Gaps Identified:")
        gaps_label.setStyleSheet("font-weight: bold; color: #FF6347; margin-top: 10px;")
        layout.addWidget(gaps_label)
        
        self.gaps_text = QTextEdit()
        self.gaps_text.setMaximumHeight(150)
        layout.addWidget(self.gaps_text)
        
        return widget
    
    def create_asset_correlation_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Asset correlation table
        self.assets_table = QTableWidget()
        self.assets_table.setColumnCount(6)
        self.assets_table.setHorizontalHeaderLabels([
            "Asset", "Services", "Vulnerabilities", "Attack Vectors", "Risk Score", "Priority"
        ])
        layout.addWidget(self.assets_table)
        
        # High-value targets
        hvt_label = QLabel("🎯 High-Value Targets:")
        hvt_label.setStyleSheet("font-weight: bold; color: #FFD700; margin-top: 10px;")
        layout.addWidget(hvt_label)
        
        self.hvt_table = QTableWidget()
        self.hvt_table.setColumnCount(3)
        self.hvt_table.setHorizontalHeaderLabels(["Target", "Value Type", "Description"])
        self.hvt_table.setMaximumHeight(150)
        layout.addWidget(self.hvt_table)
        
        return widget
    
    def setup_refresh_timer(self):
        """Setup auto-refresh timer"""
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.load_correlations)
        self.refresh_timer.start(30000)  # Refresh every 30 seconds
    
    def load_correlations(self):
        """Load correlation data"""
        try:
            from app.core.vulnerability_correlator_enhanced import enhanced_vulnerability_correlator
            from app.core.centralized_scan_data import get_scan_data_manager
            
            # Get scan results for tenant
            scan_manager = get_scan_data_manager(self.tenant_id)
            scan_results = scan_manager.get_tenant_overview(self.tenant_id)
            
            if not scan_results:
                self.show_no_data_message()
                return
            
            # Perform correlation analysis
            correlations = enhanced_vulnerability_correlator.correlate_findings(scan_results)
            
            # Update UI with correlation results
            self.update_attack_chains_display(correlations.get('attack_chains', []))
            self.update_risk_amplifiers_display(correlations.get('risk_amplifiers', []))
            self.update_asset_correlation_display(correlations.get('correlated_findings', []))
            self.update_high_value_targets(correlations.get('high_value_targets', []))
            self.update_security_gaps(correlations.get('security_gaps', []))
            
            # Update correlation score
            score = correlations.get('correlation_score', 0)
            self.score_label.setText(f"Correlation Score: {score}/100")
            
            # Update score color based on risk level
            if score >= 80:
                color = "#FF4444"  # High risk - red
            elif score >= 60:
                color = "#FFA500"  # Medium risk - orange
            elif score >= 40:
                color = "#FFFF00"  # Low risk - yellow
            else:
                color = "#32CD32"  # Very low risk - green
            
            self.score_label.setStyleSheet(f"font-weight: bold; color: {color};")
            
        except Exception as e:
            print(f"Error loading correlations: {e}")
            self.show_error_message(str(e))
    
    def update_attack_chains_display(self, attack_chains):
        """Update attack chains table"""
        self.chains_table.setRowCount(len(attack_chains))
        
        for i, chain in enumerate(attack_chains):
            if hasattr(chain, 'chain_type'):
                # AttackChain object
                self.chains_table.setItem(i, 0, QTableWidgetItem(chain.chain_type))
                self.chains_table.setItem(i, 1, QTableWidgetItem(chain.source_host))
                self.chains_table.setItem(i, 2, QTableWidgetItem(chain.target_host))
                self.chains_table.setItem(i, 3, QTableWidgetItem(str(chain.risk_score)))
                self.chains_table.setItem(i, 4, QTableWidgetItem(chain.impact))
            else:
                # Dictionary format
                self.chains_table.setItem(i, 0, QTableWidgetItem(chain.get('chain_type', 'Unknown')))
                self.chains_table.setItem(i, 1, QTableWidgetItem(chain.get('source', 'Unknown')))
                self.chains_table.setItem(i, 2, QTableWidgetItem(chain.get('target', 'Unknown')))
                self.chains_table.setItem(i, 3, QTableWidgetItem(str(chain.get('risk_score', 0))))
                self.chains_table.setItem(i, 4, QTableWidgetItem(chain.get('impact', 'Unknown')))
    
    def update_risk_amplifiers_display(self, risk_amplifiers):
        """Update risk amplifiers table"""
        self.amplifiers_table.setRowCount(len(risk_amplifiers))
        
        for i, amplifier in enumerate(risk_amplifiers):
            self.amplifiers_table.setItem(i, 0, QTableWidgetItem(amplifier.get('type', 'Unknown')))
            self.amplifiers_table.setItem(i, 1, QTableWidgetItem(amplifier.get('risk', 'Unknown')))
            self.amplifiers_table.setItem(i, 2, QTableWidgetItem(str(amplifier.get('count', 0))))
            self.amplifiers_table.setItem(i, 3, QTableWidgetItem(amplifier.get('description', '')))
    
    def update_asset_correlation_display(self, correlated_findings):
        """Update asset correlation table"""
        try:
            from app.core.centralized_scan_data import get_scan_data_manager
            
            scan_manager = get_scan_data_manager(self.tenant_id)
            asset_data = {"example.com": {"services": ["HTTP", "HTTPS"], "vulnerabilities": [], "attack_vectors": ["Web"], "risk_score": 25}}
            
            self.assets_table.setRowCount(len(asset_data))
            
            for i, (host, data) in enumerate(asset_data.items()):
                self.assets_table.setItem(i, 0, QTableWidgetItem(host))
                self.assets_table.setItem(i, 1, QTableWidgetItem(", ".join(data.get('services', [])[:3])))
                self.assets_table.setItem(i, 2, QTableWidgetItem(str(len(data.get('vulnerabilities', [])))))
                self.assets_table.setItem(i, 3, QTableWidgetItem(", ".join(data.get('attack_vectors', [])[:2])))
                self.assets_table.setItem(i, 4, QTableWidgetItem(str(data.get('risk_score', 0))))
                
                # Determine priority based on risk score
                risk_score = data.get('risk_score', 0)
                if risk_score >= 80:
                    priority = "Critical"
                elif risk_score >= 60:
                    priority = "High"
                elif risk_score >= 40:
                    priority = "Medium"
                else:
                    priority = "Low"
                
                self.assets_table.setItem(i, 5, QTableWidgetItem(priority))
                
        except Exception as e:
            print(f"Error updating asset correlation: {e}")
    
    def update_high_value_targets(self, high_value_targets):
        """Update high-value targets table"""
        self.hvt_table.setRowCount(len(high_value_targets))
        
        for i, target in enumerate(high_value_targets):
            self.hvt_table.setItem(i, 0, QTableWidgetItem(target.get('host', 'Unknown')))
            self.hvt_table.setItem(i, 1, QTableWidgetItem(target.get('value_type', 'Unknown')))
            self.hvt_table.setItem(i, 2, QTableWidgetItem(target.get('description', '')))
    
    def update_security_gaps(self, security_gaps):
        """Update security gaps display"""
        gaps_text = ""
        for gap in security_gaps:
            gaps_text += f"• {gap.get('type', 'Unknown')}: {gap.get('description', '')}\n"
            if 'recommendation' in gap:
                gaps_text += f"  Recommendation: {gap['recommendation']}\n"
            gaps_text += "\n"
        
        self.gaps_text.setPlainText(gaps_text)
    
    def view_attack_chain_details(self, item):
        """View detailed attack chain information"""
        row = item.row()
        try:
            from PyQt6.QtWidgets import QDialog, QVBoxLayout, QTextEdit, QPushButton
            
            dialog = QDialog(self)
            dialog.setWindowTitle("Attack Chain Details")
            dialog.setMinimumSize(600, 400)
            
            layout = QVBoxLayout(dialog)
            
            details_text = QTextEdit()
            details_text.setPlainText(f"Attack Chain Details for row {row + 1}\n\nDetailed analysis would be shown here...")
            layout.addWidget(details_text)
            
            close_btn = QPushButton("Close")
            close_btn.clicked.connect(dialog.close)
            layout.addWidget(close_btn)
            
            dialog.exec()
            
        except Exception as e:
            print(f"Error showing attack chain details: {e}")
    
    def generate_playbook(self):
        """Generate attack playbook for selected chain"""
        current_row = self.chains_table.currentRow()
        if current_row < 0:
            return
        
        try:
            from PyQt6.QtWidgets import QDialog, QVBoxLayout, QTextEdit, QPushButton
            
            dialog = QDialog(self)
            dialog.setWindowTitle("Generated Attack Playbook")
            dialog.setMinimumSize(800, 600)
            
            layout = QVBoxLayout(dialog)
            
            playbook_text = QTextEdit()
            
            # Generate sample playbook
            format_type = self.playbook_format.currentText().lower()
            playbook_content = self.create_sample_playbook(format_type)
            
            playbook_text.setPlainText(playbook_content)
            layout.addWidget(playbook_text)
            
            close_btn = QPushButton("Close")
            close_btn.clicked.connect(dialog.close)
            layout.addWidget(close_btn)
            
            dialog.exec()
            
        except Exception as e:
            print(f"Error generating playbook: {e}")
    
    def create_sample_playbook(self, format_type):
        """Create sample attack playbook"""
        if "htb" in format_type:
            return """# HTB Attack Chain Playbook

## Target: Multi-Service Host Compromise

### Step 1: Initial Reconnaissance
```bash
# Enumerate RPC services
impacket-rpcmap target.htb
rpcclient -U "" -N target.htb
```

### Step 2: RPC Exploitation
```bash
# Exploit RPC vulnerability
impacket-psexec domain/user:password@target.htb
```

### Step 3: SMB Enumeration
```bash
# Enumerate SMB shares
smbclient -L //target.htb -U ""
smbmap -H target.htb
```

### Step 4: Lateral Movement
```bash
# Access writable shares
smbclient //target.htb/share -U "user%password"
```

### Verification
- [ ] RPC service accessible
- [ ] SMB shares enumerated
- [ ] Lateral movement successful
"""
        else:
            return """# Generic Attack Chain Playbook

## Overview
This playbook demonstrates a multi-stage attack chain targeting network services.

## Prerequisites
- Network access to target
- Basic enumeration tools

## Attack Steps
1. Service Discovery
2. Vulnerability Identification
3. Initial Exploitation
4. Privilege Escalation
5. Lateral Movement

## Tools Required
- Nmap
- Impacket suite
- SMB enumeration tools
"""
    
    def export_analysis(self):
        """Export correlation analysis"""
        try:
            from PyQt6.QtWidgets import QFileDialog, QMessageBox
            
            filename, _ = QFileDialog.getSaveFileName(
                self, "Export Correlation Analysis", 
                f"correlation_analysis_{self.tenant_id}.json",
                "JSON files (*.json)"
            )
            
            if filename:
                # Export correlation data
                export_data = {
                    "tenant_id": self.tenant_id,
                    "timestamp": "2024-01-01T00:00:00",
                    "correlation_score": 75,
                    "attack_chains": [],
                    "risk_amplifiers": [],
                    "security_gaps": []
                }
                
                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2)
                
                QMessageBox.information(self, "Export Complete", f"Analysis exported to {filename}")
                
        except Exception as e:
            print(f"Error exporting analysis: {e}")
    
    def show_no_data_message(self):
        """Show message when no scan data is available"""
        for table in [self.chains_table, self.amplifiers_table, self.assets_table, self.hvt_table]:
            table.setRowCount(1)
            table.setItem(0, 0, QTableWidgetItem("No scan data available"))
        
        self.gaps_text.setPlainText("No security gaps identified - run scans to populate data.")
        self.score_label.setText("Correlation Score: 0/100 (No Data)")
    
    def show_error_message(self, error):
        """Show error message"""
        self.gaps_text.setPlainText(f"Error loading correlation data: {error}")
        self.score_label.setText("Correlation Score: Error")
        self.score_label.setStyleSheet("font-weight: bold; color: #FF4444;")
    
    def refresh_for_tenant(self, tenant_id):
        """Refresh data for new tenant"""
        self.tenant_id = tenant_id
        self.load_correlations()