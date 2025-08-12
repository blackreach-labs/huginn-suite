#!/usr/bin/env python3
"""
Enhanced Recon & Enumeration Page
Integrates AD Enumerator, Kerberos Tools, and Attack Graph Engine
"""

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
                            QLabel, QLineEdit, QTextEdit, QTabWidget, QFrame,
                            QTableWidget, QTableWidgetItem, QComboBox, QCheckBox)
from PyQt6.QtCore import pyqtSignal, Qt, QTimer
from PyQt6.QtGui import QFont
from app.pages.components.base_page import BasePage

class EnhancedReconEnumerationPage(BasePage):
    navigate_signal = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.tenant_id = getattr(parent, 'current_profile_name', 'default')
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Header
        header = QLabel("🔍 Enhanced Reconnaissance & Enumeration")
        header.setStyleSheet("font-size: 18pt; font-weight: bold; color: #64C8FF; padding: 10px;")
        layout.addWidget(header)
        
        # Main tabs
        self.tabs = QTabWidget()
        
        # AD Enumeration tab
        self.ad_enum_tab = self.create_ad_enumeration_tab()
        self.tabs.addTab(self.ad_enum_tab, "🏢 AD Enumeration")
        
        # Kerberos Analysis tab
        self.kerberos_tab = self.create_kerberos_analysis_tab()
        self.tabs.addTab(self.kerberos_tab, "🎫 Kerberos Analysis")
        
        # Attack Graph tab
        self.attack_graph_tab = self.create_attack_graph_tab()
        self.tabs.addTab(self.attack_graph_tab, "📊 Attack Graph")
        
        # Network Discovery tab (existing functionality)
        self.network_tab = self.create_network_discovery_tab()
        self.tabs.addTab(self.network_tab, "🌐 Network Discovery")
        
        layout.addWidget(self.tabs)
    
    def create_ad_enumeration_tab(self):
        """Create AD enumeration tab"""
        tab = QWidget()
        layout = QHBoxLayout(tab)
        
        # Left panel - controls
        left_panel = QFrame()
        left_panel.setFixedWidth(350)
        left_layout = QVBoxLayout(left_panel)
        
        # Connection settings
        left_layout.addWidget(QLabel("Domain Connection:"))
        
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("example.local")
        left_layout.addWidget(self.domain_input)
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username (optional)")
        left_layout.addWidget(self.username_input)
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password (optional)")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        left_layout.addWidget(self.password_input)
        
        # Enumeration options
        left_layout.addWidget(QLabel("Enumeration Options:"))
        
        self.enum_users_cb = QCheckBox("Enumerate Users")
        self.enum_users_cb.setChecked(True)
        left_layout.addWidget(self.enum_users_cb)
        
        self.enum_computers_cb = QCheckBox("Enumerate Computers")
        self.enum_computers_cb.setChecked(True)
        left_layout.addWidget(self.enum_computers_cb)
        
        self.enum_groups_cb = QCheckBox("Enumerate Groups")
        self.enum_groups_cb.setChecked(True)
        left_layout.addWidget(self.enum_groups_cb)
        
        self.enum_ous_cb = QCheckBox("Enumerate OUs")
        left_layout.addWidget(self.enum_ous_cb)
        
        self.enum_gpos_cb = QCheckBox("Enumerate GPOs")
        left_layout.addWidget(self.enum_gpos_cb)
        
        self.enum_trusts_cb = QCheckBox("Enumerate Trusts")
        left_layout.addWidget(self.enum_trusts_cb)
        
        # Action buttons
        left_layout.addWidget(QLabel("Actions:"))
        
        connect_btn = QPushButton("🔗 Connect to Domain")
        connect_btn.clicked.connect(self.connect_to_domain)
        left_layout.addWidget(connect_btn)
        
        enumerate_all_btn = QPushButton("🔍 Enumerate All")
        enumerate_all_btn.clicked.connect(self.enumerate_all_ad)
        left_layout.addWidget(enumerate_all_btn)
        
        export_results_btn = QPushButton("📊 Export Results")
        export_results_btn.clicked.connect(self.export_ad_results)
        left_layout.addWidget(export_results_btn)
        
        left_layout.addStretch()
        layout.addWidget(left_panel)
        
        # Right panel - results
        right_panel = QFrame()
        right_layout = QVBoxLayout(right_panel)
        
        # Status
        self.ad_status = QLabel("Status: Disconnected")
        self.ad_status.setStyleSheet("color: #FF6347; font-weight: bold;")
        right_layout.addWidget(self.ad_status)
        
        # Results display
        self.ad_results = QTextEdit()
        self.ad_results.setReadOnly(True)
        right_layout.addWidget(self.ad_results)
        
        # Statistics table
        stats_label = QLabel("Enumeration Statistics:")
        stats_label.setStyleSheet("font-weight: bold; color: #64C8FF; margin-top: 10px;")
        right_layout.addWidget(stats_label)
        
        self.ad_stats_table = QTableWidget()
        self.ad_stats_table.setColumnCount(2)
        self.ad_stats_table.setHorizontalHeaderLabels(["Object Type", "Count"])
        self.ad_stats_table.setMaximumHeight(200)
        right_layout.addWidget(self.ad_stats_table)
        
        layout.addWidget(right_panel)
        return tab
    
    def create_kerberos_analysis_tab(self):
        """Create Kerberos analysis tab"""
        tab = QWidget()
        layout = QHBoxLayout(tab)
        
        # Left panel - controls
        left_panel = QFrame()
        left_panel.setFixedWidth(350)
        left_layout = QVBoxLayout(left_panel)
        
        # Connection settings (reuse from AD tab)
        left_layout.addWidget(QLabel("Domain Connection:"))
        
        self.krb_domain_input = QLineEdit()
        self.krb_domain_input.setPlaceholderText("example.local")
        left_layout.addWidget(self.krb_domain_input)
        
        self.krb_username_input = QLineEdit()
        self.krb_username_input.setPlaceholderText("Username (optional)")
        left_layout.addWidget(self.krb_username_input)
        
        self.krb_password_input = QLineEdit()
        self.krb_password_input.setPlaceholderText("Password (optional)")
        self.krb_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        left_layout.addWidget(self.krb_password_input)
        
        # Analysis options
        left_layout.addWidget(QLabel("Kerberos Analysis:"))
        
        enumerate_spns_btn = QPushButton("🎫 Enumerate SPNs")
        enumerate_spns_btn.clicked.connect(self.enumerate_spns)
        left_layout.addWidget(enumerate_spns_btn)
        
        enumerate_asrep_btn = QPushButton("🔓 Find AS-REP Users")
        enumerate_asrep_btn.clicked.connect(self.enumerate_asrep_users)
        left_layout.addWidget(enumerate_asrep_btn)
        
        analyze_policy_btn = QPushButton("📋 Analyze Policy")
        analyze_policy_btn.clicked.connect(self.analyze_kerberos_policy)
        left_layout.addWidget(analyze_policy_btn)
        
        # Ticket analysis
        left_layout.addWidget(QLabel("Ticket Analysis:"))
        
        self.ticket_file_input = QLineEdit()
        self.ticket_file_input.setPlaceholderText("Path to ticket file")
        left_layout.addWidget(self.ticket_file_input)
        
        browse_ticket_btn = QPushButton("📁 Browse Ticket File")
        browse_ticket_btn.clicked.connect(self.browse_ticket_file)
        left_layout.addWidget(browse_ticket_btn)
        
        parse_ticket_btn = QPushButton("🔍 Parse Ticket")
        parse_ticket_btn.clicked.connect(self.parse_ticket_file)
        left_layout.addWidget(parse_ticket_btn)
        
        # Generate reports
        left_layout.addWidget(QLabel("Reports:"))
        
        kerberoast_report_btn = QPushButton("📊 Kerberoast Report")
        kerberoast_report_btn.clicked.connect(self.generate_kerberoast_report)
        left_layout.addWidget(kerberoast_report_btn)
        
        asrep_report_btn = QPushButton("📊 AS-REP Report")
        asrep_report_btn.clicked.connect(self.generate_asrep_report)
        left_layout.addWidget(asrep_report_btn)
        
        left_layout.addStretch()
        layout.addWidget(left_panel)
        
        # Right panel - results
        right_panel = QFrame()
        right_layout = QVBoxLayout(right_panel)
        
        # Status
        self.krb_status = QLabel("Status: Ready")
        self.krb_status.setStyleSheet("color: #32CD32; font-weight: bold;")
        right_layout.addWidget(self.krb_status)
        
        # Results display
        self.krb_results = QTextEdit()
        self.krb_results.setReadOnly(True)
        right_layout.addWidget(self.krb_results)
        
        layout.addWidget(right_panel)
        return tab
    
    def create_attack_graph_tab(self):
        """Create attack graph analysis tab"""
        tab = QWidget()
        layout = QHBoxLayout(tab)
        
        # Left panel - controls
        left_panel = QFrame()
        left_panel.setFixedWidth(350)
        left_layout = QVBoxLayout(left_panel)
        
        # Graph analysis options
        left_layout.addWidget(QLabel("Attack Graph Analysis:"))
        
        build_graph_btn = QPushButton("🏗️ Build Attack Graph")
        build_graph_btn.clicked.connect(self.build_attack_graph)
        left_layout.addWidget(build_graph_btn)
        
        find_paths_btn = QPushButton("🎯 Find Attack Paths")
        find_paths_btn.clicked.connect(self.find_attack_paths)
        left_layout.addWidget(find_paths_btn)
        
        shortest_da_btn = QPushButton("👑 Shortest Path to DA")
        shortest_da_btn.clicked.connect(self.find_shortest_path_to_da)
        left_layout.addWidget(shortest_da_btn)
        
        privesc_opps_btn = QPushButton("⬆️ Privilege Escalation")
        privesc_opps_btn.clicked.connect(self.identify_privilege_escalation)
        left_layout.addWidget(privesc_opps_btn)
        
        # Playbook generation
        left_layout.addWidget(QLabel("Playbook Generation:"))
        
        self.playbook_format_combo = QComboBox()
        self.playbook_format_combo.addItems(["HTB Format", "THM Format", "Generic"])\n        left_layout.addWidget(self.playbook_format_combo)
        
        generate_playbook_btn = QPushButton("📋 Generate Playbook")
        generate_playbook_btn.clicked.connect(self.generate_attack_playbook)
        left_layout.addWidget(generate_playbook_btn)
        
        # Export options
        left_layout.addWidget(QLabel("Export:"))
        
        export_graph_btn = QPushButton("📊 Export Graph Data")
        export_graph_btn.clicked.connect(self.export_graph_data)
        left_layout.addWidget(export_graph_btn)
        
        left_layout.addStretch()
        layout.addWidget(left_panel)
        
        # Right panel - results
        right_panel = QFrame()
        right_layout = QVBoxLayout(right_panel)
        
        # Graph status
        self.graph_status = QLabel("Graph Status: Not Built")
        self.graph_status.setStyleSheet("color: #FFA500; font-weight: bold;")
        right_layout.addWidget(self.graph_status)
        
        # Results display
        self.graph_results = QTextEdit()
        self.graph_results.setReadOnly(True)
        right_layout.addWidget(self.graph_results)
        
        # Attack paths table
        paths_label = QLabel("Attack Paths:")
        paths_label.setStyleSheet("font-weight: bold; color: #64C8FF; margin-top: 10px;")
        right_layout.addWidget(paths_label)
        
        self.attack_paths_table = QTableWidget()
        self.attack_paths_table.setColumnCount(4)
        self.attack_paths_table.setHorizontalHeaderLabels(["Source", "Target", "Steps", "Risk Score"])
        self.attack_paths_table.setMaximumHeight(200)
        self.attack_paths_table.itemDoubleClicked.connect(self.view_attack_path_details)
        right_layout.addWidget(self.attack_paths_table)
        
        layout.addWidget(right_panel)
        return tab
    
    def create_network_discovery_tab(self):
        """Create network discovery tab (placeholder for existing functionality)"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        placeholder = QLabel("🌐 Network Discovery\\n\\nExisting network discovery functionality would be integrated here")
        placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        placeholder.setStyleSheet("color: #DCDCDC; font-size: 14pt; padding: 50px;")
        layout.addWidget(placeholder)
        
        return tab
    
    # AD Enumeration methods
    def connect_to_domain(self):
        """Connect to Active Directory domain"""
        domain = self.domain_input.text().strip()
        if not domain:
            self.ad_results.append("❌ Please enter a domain name")
            return
        
        try:
            from app.tools.ad_enum import ADEnumerator
            
            username = self.username_input.text().strip() or None
            password = self.password_input.text().strip() or None
            
            self.ad_enumerator = ADEnumerator(domain, username, password)
            
            if self.ad_enumerator.connect():
                self.ad_results.append(f"✅ Connected to domain: {domain}")
                self.ad_status.setText("Status: Connected")
                self.ad_status.setStyleSheet("color: #32CD32; font-weight: bold;")
            else:
                self.ad_results.append(f"❌ Failed to connect to domain: {domain}")
                self.ad_status.setText("Status: Connection Failed")
                self.ad_status.setStyleSheet("color: #FF6347; font-weight: bold;")
                
        except Exception as e:
            self.ad_results.append(f"❌ Error: {e}")
    
    def enumerate_all_ad(self):
        """Enumerate all AD objects"""
        if not hasattr(self, 'ad_enumerator'):
            self.ad_results.append("❌ Please connect to domain first")
            return
        
        try:
            self.ad_results.append("🔍 Starting comprehensive AD enumeration...")
            
            results = self.ad_enumerator.enumerate_all()
            
            self.ad_results.append("\\n📊 Enumeration Results:")
            self.ad_results.append("=" * 50)
            
            for obj_type, count in results.items():
                self.ad_results.append(f"  {obj_type.title()}: {count}")
            
            # Update statistics table
            self.update_ad_statistics()
            
            self.ad_results.append("\\n✅ Enumeration completed successfully")
            
        except Exception as e:
            self.ad_results.append(f"❌ Enumeration error: {e}")
    
    def update_ad_statistics(self):
        """Update AD statistics table"""
        try:
            stats = self.ad_enumerator.get_statistics()
            
            self.ad_stats_table.setRowCount(len(stats))
            
            for i, (stat_type, count) in enumerate(stats.items()):
                self.ad_stats_table.setItem(i, 0, QTableWidgetItem(stat_type.replace('_', ' ').title()))
                self.ad_stats_table.setItem(i, 1, QTableWidgetItem(str(count)))
                
        except Exception as e:
            print(f"Error updating AD statistics: {e}")
    
    def export_ad_results(self):
        """Export AD enumeration results"""
        try:
            from PyQt6.QtWidgets import QFileDialog, QMessageBox
            
            filename, _ = QFileDialog.getSaveFileName(
                self, "Export AD Results", 
                f"ad_enum_{self.domain_input.text()}_{int(time.time())}.json",
                "JSON files (*.json)"
            )
            
            if filename:
                stats = self.ad_enumerator.get_statistics()
                
                export_data = {
                    "domain": self.domain_input.text(),
                    "timestamp": datetime.now().isoformat(),
                    "statistics": stats
                }
                
                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2)
                
                QMessageBox.information(self, "Export Complete", f"Results exported to {filename}")
                
        except Exception as e:
            self.ad_results.append(f"❌ Export error: {e}")
    
    # Kerberos Analysis methods
    def enumerate_spns(self):
        """Enumerate Service Principal Names"""
        domain = self.krb_domain_input.text().strip()
        if not domain:
            self.krb_results.append("❌ Please enter a domain name")
            return
        
        try:
            from app.tools.kerberos_tools import KerberosTools
            
            username = self.krb_username_input.text().strip() or None
            password = self.krb_password_input.text().strip() or None
            
            kerberos_tools = KerberosTools(domain)
            
            if kerberos_tools.connect_ldap(username, password):
                self.krb_results.append("🎫 Enumerating SPNs...")
                
                spn_users = kerberos_tools.enumerate_spns()
                
                self.krb_results.append(f"\\n📊 Found {len(spn_users)} users with SPNs:")
                self.krb_results.append("=" * 50)
                
                for spn_user in spn_users[:10]:  # Show top 10
                    self.krb_results.append(f"\\n👤 {spn_user.sam_account}")
                    self.krb_results.append(f"  SPN: {spn_user.spn}")
                    self.krb_results.append(f"  Risk Score: {spn_user.risk_score}/10")
                    self.krb_results.append(f"  Encryption: {', '.join(spn_user.encryption_types)}")
                
                if len(spn_users) > 10:
                    self.krb_results.append(f"\\n... and {len(spn_users) - 10} more")
                
                self.krb_status.setText(f"Status: Found {len(spn_users)} SPNs")
                
            else:
                self.krb_results.append("❌ Failed to connect to domain")
                
        except Exception as e:
            self.krb_results.append(f"❌ Error: {e}")
    
    def enumerate_asrep_users(self):
        """Enumerate AS-REP roastable users"""
        domain = self.krb_domain_input.text().strip()
        if not domain:
            self.krb_results.append("❌ Please enter a domain name")
            return
        
        try:
            from app.tools.kerberos_tools import KerberosTools
            
            username = self.krb_username_input.text().strip() or None
            password = self.krb_password_input.text().strip() or None
            
            kerberos_tools = KerberosTools(domain)
            
            if kerberos_tools.connect_ldap(username, password):
                self.krb_results.append("🔓 Enumerating AS-REP roastable users...")
                
                asrep_users = kerberos_tools.enumerate_asrep_users()
                
                self.krb_results.append(f"\\n📊 Found {len(asrep_users)} AS-REP roastable users:")
                self.krb_results.append("=" * 50)
                
                for asrep_user in asrep_users:
                    self.krb_results.append(f"\\n👤 {asrep_user.sam_account}")
                    self.krb_results.append(f"  UPN: {asrep_user.user_principal_name}")
                    self.krb_results.append(f"  Risk Score: {asrep_user.risk_score}/10")
                    self.krb_results.append(f"  Last Logon: {asrep_user.last_logon or 'Never'}")
                
                self.krb_status.setText(f"Status: Found {len(asrep_users)} AS-REP users")
                
            else:
                self.krb_results.append("❌ Failed to connect to domain")
                
        except Exception as e:
            self.krb_results.append(f"❌ Error: {e}")
    
    def analyze_kerberos_policy(self):
        """Analyze Kerberos domain policy"""
        domain = self.krb_domain_input.text().strip()
        if not domain:
            self.krb_results.append("❌ Please enter a domain name")
            return
        
        try:
            from app.tools.kerberos_tools import KerberosTools
            
            username = self.krb_username_input.text().strip() or None
            password = self.krb_password_input.text().strip() or None
            
            kerberos_tools = KerberosTools(domain)
            
            if kerberos_tools.connect_ldap(username, password):
                self.krb_results.append("📋 Analyzing Kerberos policy...")
                
                policy = kerberos_tools.analyze_kerberos_policy()
                
                self.krb_results.append("\\n📊 Kerberos Policy Analysis:")
                self.krb_results.append("=" * 50)
                
                for key, value in policy.items():
                    if key != 'weaknesses':
                        self.krb_results.append(f"  {key.replace('_', ' ').title()}: {value}")
                
                if 'weaknesses' in policy and policy['weaknesses']:
                    self.krb_results.append("\\n⚠️ Policy Weaknesses:")
                    for weakness in policy['weaknesses']:
                        self.krb_results.append(f"  • {weakness}")
                
            else:
                self.krb_results.append("❌ Failed to connect to domain")
                
        except Exception as e:
            self.krb_results.append(f"❌ Error: {e}")
    
    def browse_ticket_file(self):
        """Browse for ticket file"""
        try:
            from PyQt6.QtWidgets import QFileDialog
            
            filename, _ = QFileDialog.getOpenFileName(
                self, "Select Ticket File", "",
                "All files (*.*)"
            )
            
            if filename:
                self.ticket_file_input.setText(filename)
                
        except Exception as e:
            self.krb_results.append(f"❌ Error: {e}")
    
    def parse_ticket_file(self):
        """Parse Kerberos ticket file"""
        ticket_path = self.ticket_file_input.text().strip()
        if not ticket_path:
            self.krb_results.append("❌ Please select a ticket file")
            return
        
        try:
            from app.tools.kerberos_tools import KerberosTools
            
            kerberos_tools = KerberosTools("dummy.local")  # Domain not needed for parsing
            tickets = kerberos_tools.parse_ticket_file(ticket_path)
            
            self.krb_results.append(f"🎫 Parsing ticket file: {ticket_path}")
            self.krb_results.append(f"\\n📊 Found {len(tickets)} tickets:")
            self.krb_results.append("=" * 50)
            
            for ticket in tickets:
                self.krb_results.append(f"\\n🎫 {ticket.ticket_type}")
                self.krb_results.append(f"  Client: {ticket.client_name}")
                self.krb_results.append(f"  Service: {ticket.service_name}")
                self.krb_results.append(f"  Encryption: {ticket.encryption_type}")
                self.krb_results.append(f"  Size: {len(ticket.ticket_data)} bytes")
                
        except Exception as e:
            self.krb_results.append(f"❌ Error parsing ticket: {e}")
    
    def generate_kerberoast_report(self):
        """Generate Kerberoast assessment report"""
        try:
            # This would use previously enumerated SPN data
            self.krb_results.append("📊 Generating Kerberoast report...")
            self.krb_results.append("\\n📋 Kerberoast Assessment Report")
            self.krb_results.append("=" * 50)
            self.krb_results.append("\\nReport generation completed - detailed analysis would be shown here")
            
        except Exception as e:
            self.krb_results.append(f"❌ Error: {e}")
    
    def generate_asrep_report(self):
        """Generate AS-REP Roasting assessment report"""
        try:
            # This would use previously enumerated AS-REP data
            self.krb_results.append("📊 Generating AS-REP report...")
            self.krb_results.append("\\n📋 AS-REP Roasting Assessment Report")
            self.krb_results.append("=" * 50)
            self.krb_results.append("\\nReport generation completed - detailed analysis would be shown here")
            
        except Exception as e:
            self.krb_results.append(f"❌ Error: {e}")
    
    # Attack Graph methods
    def build_attack_graph(self):
        """Build attack graph from AD data"""
        try:
            from app.core.graph_engine import GraphEngine
            
            # Use AD enumeration database
            if hasattr(self, 'ad_enumerator'):
                db_path = self.ad_enumerator.db_path
                
                self.graph_results.append("🏗️ Building attack graph from AD data...")
                
                self.graph_engine = GraphEngine(db_path)
                
                self.graph_results.append("✅ Attack graph built successfully")
                self.graph_status.setText("Graph Status: Built")
                self.graph_status.setStyleSheet("color: #32CD32; font-weight: bold;")
                
            else:
                self.graph_results.append("❌ Please enumerate AD objects first")
                
        except Exception as e:
            self.graph_results.append(f"❌ Error: {e}")
    
    def find_attack_paths(self):
        """Find attack paths in the graph"""
        if not hasattr(self, 'graph_engine'):
            self.graph_results.append("❌ Please build attack graph first")
            return
        
        try:
            self.graph_results.append("🎯 Finding attack paths...")
            
            attack_paths = self.graph_engine.find_attack_paths()
            
            self.graph_results.append(f"\\n📊 Found {len(attack_paths)} attack paths:")
            self.graph_results.append("=" * 50)
            
            # Update attack paths table
            self.attack_paths_table.setRowCount(len(attack_paths))
            
            for i, path in enumerate(attack_paths):
                self.attack_paths_table.setItem(i, 0, QTableWidgetItem(path.source))
                self.attack_paths_table.setItem(i, 1, QTableWidgetItem(path.target))
                self.attack_paths_table.setItem(i, 2, QTableWidgetItem(str(len(path.steps))))
                self.attack_paths_table.setItem(i, 3, QTableWidgetItem(str(path.risk_score)))
                
                # Show summary in results
                self.graph_results.append(f"\\n🎯 Path {i+1}: {path.description}")
                self.graph_results.append(f"  Risk Score: {path.risk_score}")
                self.graph_results.append(f"  Steps: {len(path.steps)}")
            
        except Exception as e:
            self.graph_results.append(f"❌ Error: {e}")
    
    def find_shortest_path_to_da(self):
        """Find shortest path to Domain Admin"""
        if not hasattr(self, 'graph_engine'):
            self.graph_results.append("❌ Please build attack graph first")
            return
        
        try:
            self.graph_results.append("👑 Finding shortest path to Domain Admin...")
            
            da_path = self.graph_engine.find_shortest_path_to_da()
            
            if da_path:
                self.graph_results.append(f"\\n🎯 Shortest Path to DA Found:")
                self.graph_results.append("=" * 50)
                self.graph_results.append(f"  Source: {da_path.source}")
                self.graph_results.append(f"  Target: {da_path.target}")
                self.graph_results.append(f"  Steps: {len(da_path.steps)}")
                self.graph_results.append(f"  Risk Score: {da_path.risk_score}")
                
                for i, step in enumerate(da_path.steps):
                    self.graph_results.append(f"\\n  Step {i+1}: {step.get('description', 'Unknown step')}")
            else:
                self.graph_results.append("❌ No path to Domain Admin found")
                
        except Exception as e:
            self.graph_results.append(f"❌ Error: {e}")
    
    def identify_privilege_escalation(self):
        """Identify privilege escalation opportunities"""
        if not hasattr(self, 'graph_engine'):
            self.graph_results.append("❌ Please build attack graph first")
            return
        
        try:
            self.graph_results.append("⬆️ Identifying privilege escalation opportunities...")
            
            opportunities = self.graph_engine.identify_privilege_escalation_opportunities()
            
            self.graph_results.append(f"\\n📊 Found {len(opportunities)} opportunities:")
            self.graph_results.append("=" * 50)
            
            for opp in opportunities:
                self.graph_results.append(f"\\n⬆️ {opp['type'].upper()}")
                self.graph_results.append(f"  Target: {opp['target']}")
                self.graph_results.append(f"  Technique: {opp['technique']}")
                self.graph_results.append(f"  Risk Score: {opp['risk_score']}")
                self.graph_results.append(f"  Description: {opp['description']}")
            
        except Exception as e:
            self.graph_results.append(f"❌ Error: {e}")
    
    def generate_attack_playbook(self):
        """Generate attack playbook"""
        current_row = self.attack_paths_table.currentRow()
        if current_row < 0:
            self.graph_results.append("❌ Please select an attack path from the table")
            return
        
        try:
            from PyQt6.QtWidgets import QDialog, QVBoxLayout, QTextEdit, QPushButton
            
            # Get selected attack path (this would use actual path data)
            format_type = self.playbook_format_combo.currentText().lower()
            
            # Generate playbook
            playbook_content = self.create_sample_playbook(format_type)
            
            # Show in dialog
            dialog = QDialog(self)
            dialog.setWindowTitle("Generated Attack Playbook")
            dialog.setMinimumSize(800, 600)
            
            layout = QVBoxLayout(dialog)
            
            playbook_text = QTextEdit()
            playbook_text.setPlainText(playbook_content)
            layout.addWidget(playbook_text)
            
            close_btn = QPushButton("Close")
            close_btn.clicked.connect(dialog.close)
            layout.addWidget(close_btn)
            
            dialog.exec()
            
        except Exception as e:
            self.graph_results.append(f"❌ Error: {e}")
    
    def create_sample_playbook(self, format_type):
        """Create sample attack playbook"""
        if "htb" in format_type:
            return """# HTB Attack Playbook: AD Privilege Escalation

## Objective
Escalate privileges from standard user to Domain Admin

## Prerequisites
- Domain user credentials
- Network access to domain controller

## Step 1: Initial Enumeration
```bash
# Enumerate domain users
net user /domain

# Find SPNs for Kerberoasting
GetUserSPNs.py domain.local/user:password -dc-ip DC_IP
```

## Step 2: Kerberoasting Attack
```bash
# Request service tickets
GetUserSPNs.py domain.local/user:password -dc-ip DC_IP -request

# Crack the tickets
hashcat -m 13100 tickets.txt wordlist.txt
```

## Step 3: Lateral Movement
```bash
# Use cracked credentials
psexec.py domain.local/service_user:password@target_host
```

## Step 4: Domain Admin Access
```bash
# DCSync attack if permissions allow
secretsdump.py domain.local/user:password@DC_IP
```

## Verification
- [ ] Service tickets obtained
- [ ] Credentials cracked
- [ ] Lateral movement successful
- [ ] Domain Admin achieved
"""
        else:
            return """# Generic AD Attack Playbook

## Overview
This playbook demonstrates Active Directory privilege escalation techniques.

## Attack Chain
1. Domain Enumeration
2. Service Principal Name (SPN) Discovery
3. Kerberoasting Attack
4. Credential Cracking
5. Lateral Movement
6. Privilege Escalation

## Tools Required
- Impacket suite
- Hashcat
- BloodHound (optional)
- PowerView (optional)

## Mitigation
- Use strong service account passwords
- Enable AES encryption
- Monitor for Kerberoasting attacks
- Implement least privilege principles
"""
    
    def export_graph_data(self):
        """Export attack graph data"""
        try:
            from PyQt6.QtWidgets import QFileDialog, QMessageBox
            import json
            import time
            
            filename, _ = QFileDialog.getSaveFileName(
                self, "Export Graph Data", 
                f"attack_graph_{int(time.time())}.json",
                "JSON files (*.json)"
            )
            
            if filename:
                # Export graph data (this would use actual graph data)
                export_data = {
                    "timestamp": datetime.now().isoformat(),
                    "graph_nodes": 0,
                    "graph_edges": 0,
                    "attack_paths": 0
                }
                
                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2)
                
                QMessageBox.information(self, "Export Complete", f"Graph data exported to {filename}")
                
        except Exception as e:
            self.graph_results.append(f"❌ Export error: {e}")
    
    def view_attack_path_details(self, item):
        """View detailed attack path information"""
        try:
            from PyQt6.QtWidgets import QDialog, QVBoxLayout, QTextEdit, QPushButton
            
            row = item.row()
            
            dialog = QDialog(self)
            dialog.setWindowTitle("Attack Path Details")
            dialog.setMinimumSize(600, 400)
            
            layout = QVBoxLayout(dialog)
            
            details_text = QTextEdit()
            details_text.setPlainText(f"Attack Path Details for row {row + 1}\\n\\nDetailed path analysis would be shown here...")
            layout.addWidget(details_text)
            
            close_btn = QPushButton("Close")
            close_btn.clicked.connect(dialog.close)
            layout.addWidget(close_btn)
            
            dialog.exec()
            
        except Exception as e:
            print(f"Error showing attack path details: {e}")