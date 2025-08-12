# app/widgets/ad_enumeration_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QLineEdit, QPushButton, QTextEdit, QGroupBox,
                            QTableWidget, QTableWidgetItem, QHeaderView,
                            QTabWidget, QComboBox, QCheckBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor
from app.core.ad_enumeration import ad_enumeration
from app.core.license_manager import license_manager

class ADEnumWorker(QThread):
    """Worker thread for AD enumeration"""
    enum_completed = pyqtSignal(dict)
    
    def __init__(self, operation, domain, username="", password=""):
        super().__init__()
        self.operation = operation
        self.domain = domain
        self.username = username
        self.password = password
        
    def run(self):
        if self.operation == 'enumerate':
            result = ad_enumeration.enumerate_domain(self.domain, self.username, self.password)
        elif self.operation == 'kerberoasting':
            result = ad_enumeration.kerberoasting_attack(self.domain, self.username, self.password)
        elif self.operation == 'asreproasting':
            result = ad_enumeration.asreproasting_attack(self.domain)
        elif self.operation == 'bloodhound':
            result = ad_enumeration.bloodhound_analysis(self.domain, self.username, self.password)
        else:
            result = {'error': 'Unknown operation'}
            
        self.enum_completed.emit(result)

class ADEnumerationWidget(QWidget):
    """Active Directory enumeration widget"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.enum_worker = None
        self.setup_ui()
        self.connect_signals()
        self.check_license()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Header
        header = QLabel("Active Directory Enumeration & Attacks")
        header.setStyleSheet("font-size: 16pt; font-weight: bold; color: #64C8FF;")
        layout.addWidget(header)
        
        # License warning
        self.license_warning = QLabel("⚠️ AD Enumeration requires Enterprise license")
        self.license_warning.setStyleSheet("color: #FF6B6B; font-weight: bold; padding: 10px;")
        layout.addWidget(self.license_warning)
        
        # Target Configuration
        target_group = QGroupBox("Domain Configuration")
        target_layout = QVBoxLayout(target_group)
        
        domain_layout = QHBoxLayout()
        domain_layout.addWidget(QLabel("Domain:"))
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("example.com")
        domain_layout.addWidget(self.domain_input)
        target_layout.addLayout(domain_layout)
        
        creds_layout = QHBoxLayout()
        creds_layout.addWidget(QLabel("Username:"))
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("domain\\user (optional)")
        creds_layout.addWidget(self.username_input)
        
        creds_layout.addWidget(QLabel("Password:"))
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("password (optional)")
        creds_layout.addWidget(self.password_input)
        target_layout.addLayout(creds_layout)
        
        layout.addWidget(target_group)
        
        # Attack Buttons
        attack_group = QGroupBox("Attack Operations")
        attack_layout = QHBoxLayout(attack_group)
        
        self.enum_btn = QPushButton("Domain Enumeration")
        self.kerb_btn = QPushButton("Kerberoasting")
        self.asrep_btn = QPushButton("ASREPRoasting")
        self.bloodhound_btn = QPushButton("BloodHound Analysis")
        
        attack_layout.addWidget(self.enum_btn)
        attack_layout.addWidget(self.kerb_btn)
        attack_layout.addWidget(self.asrep_btn)
        attack_layout.addWidget(self.bloodhound_btn)
        
        layout.addWidget(attack_group)
        
        # Results Tabs
        self.results_tabs = QTabWidget()
        
        # Enumeration Results
        self.enum_tab = self.create_enumeration_tab()
        self.results_tabs.addTab(self.enum_tab, "Enumeration")
        
        # Attack Results
        self.attack_tab = self.create_attack_tab()
        self.results_tabs.addTab(self.attack_tab, "Attacks")
        
        # BloodHound Analysis
        self.bloodhound_tab = self.create_bloodhound_tab()
        self.results_tabs.addTab(self.bloodhound_tab, "BloodHound")
        
        layout.addWidget(self.results_tabs)
        
        # Status
        self.status_text = QTextEdit()
        self.status_text.setMaximumHeight(100)
        self.status_text.setReadOnly(True)
        layout.addWidget(self.status_text)
        
    def create_enumeration_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Users table
        users_group = QGroupBox("Domain Users")
        users_layout = QVBoxLayout(users_group)
        
        self.users_table = QTableWidget()
        self.users_table.setColumnCount(2)
        self.users_table.setHorizontalHeaderLabels(["Username", "Status"])
        users_layout.addWidget(self.users_table)
        
        layout.addWidget(users_group)
        
        # Computers table
        computers_group = QGroupBox("Domain Computers")
        computers_layout = QVBoxLayout(computers_group)
        
        self.computers_table = QTableWidget()
        self.computers_table.setColumnCount(2)
        self.computers_table.setHorizontalHeaderLabels(["Computer", "Role"])
        computers_layout.addWidget(self.computers_table)
        
        layout.addWidget(computers_group)
        
        return widget
        
    def create_attack_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Attack results table
        self.attack_results_table = QTableWidget()
        self.attack_results_table.setColumnCount(4)
        self.attack_results_table.setHorizontalHeaderLabels(["Attack", "Target", "Result", "Hash/Ticket"])
        self.attack_results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.attack_results_table)
        
        return widget
        
    def create_bloodhound_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Attack paths
        paths_group = QGroupBox("Attack Paths")
        paths_layout = QVBoxLayout(paths_group)
        
        self.paths_table = QTableWidget()
        self.paths_table.setColumnCount(3)
        self.paths_table.setHorizontalHeaderLabels(["Path", "Difficulty", "Impact"])
        paths_layout.addWidget(self.paths_table)
        
        layout.addWidget(paths_group)
        
        # High value targets
        hvt_group = QGroupBox("High Value Targets")
        hvt_layout = QVBoxLayout(hvt_group)
        
        self.hvt_table = QTableWidget()
        self.hvt_table.setColumnCount(3)
        self.hvt_table.setHorizontalHeaderLabels(["Name", "Type", "Members/Role"])
        hvt_layout.addWidget(self.hvt_table)
        
        layout.addWidget(hvt_group)
        
        return widget
        
    def connect_signals(self):
        self.enum_btn.clicked.connect(lambda: self.start_operation('enumerate'))
        self.kerb_btn.clicked.connect(lambda: self.start_operation('kerberoasting'))
        self.asrep_btn.clicked.connect(lambda: self.start_operation('asreproasting'))
        self.bloodhound_btn.clicked.connect(lambda: self.start_operation('bloodhound'))
        ad_enumeration.ad_event.connect(self.handle_ad_event)
        
    def check_license(self):
        if license_manager.is_feature_enabled('ad_enumeration'):
            self.license_warning.hide()
            self.setEnabled(True)
        else:
            self.license_warning.show()
            self.setEnabled(False)
            
    def start_operation(self, operation):
        if not license_manager.is_feature_enabled('ad_enumeration'):
            self.status_text.append("❌ AD Enumeration requires Enterprise license")
            return
            
        domain = self.domain_input.text().strip()
        if not domain:
            self.status_text.append("❌ Please enter a domain name")
            return
            
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()
        
        # Disable buttons during operation
        self.enum_btn.setEnabled(False)
        self.kerb_btn.setEnabled(False)
        self.asrep_btn.setEnabled(False)
        self.bloodhound_btn.setEnabled(False)
        
        self.status_text.append(f"🚀 Starting {operation} against {domain}")
        
        # Start worker thread
        self.enum_worker = ADEnumWorker(operation, domain, username, password)
        self.enum_worker.enum_completed.connect(self.handle_operation_completed)
        self.enum_worker.start()
        
    def handle_operation_completed(self, result):
        # Re-enable buttons
        self.enum_btn.setEnabled(True)
        self.kerb_btn.setEnabled(True)
        self.asrep_btn.setEnabled(True)
        self.bloodhound_btn.setEnabled(True)
        
        if 'error' in result:
            self.status_text.append(f"❌ Operation failed: {result['error']}")
            return
            
        # Handle different result types
        if 'users' in result:  # Domain enumeration
            self.update_enumeration_results(result)
        elif 'attack_type' in result:  # Attack results
            self.update_attack_results(result)
        elif 'attack_paths' in result:  # BloodHound analysis
            self.update_bloodhound_results(result)
            
    def update_enumeration_results(self, result):
        # Update users table
        users = result.get('users', [])
        self.users_table.setRowCount(len(users))
        
        for row, user in enumerate(users):
            self.users_table.setItem(row, 0, QTableWidgetItem(str(user)))
            self.users_table.setItem(row, 1, QTableWidgetItem("Active"))
            
        # Update computers table
        computers = result.get('computers', [])
        self.computers_table.setRowCount(len(computers))
        
        for row, computer in enumerate(computers):
            self.computers_table.setItem(row, 0, QTableWidgetItem(str(computer)))
            self.computers_table.setItem(row, 1, QTableWidgetItem("Workstation"))
            
        self.status_text.append(f"✅ Enumeration completed: {len(users)} users, {len(computers)} computers")
        
    def update_attack_results(self, result):
        attack_type = result.get('attack_type', 'Unknown')
        
        if attack_type == 'Kerberoasting':
            tickets = result.get('tickets', [])
            self.attack_results_table.setRowCount(len(tickets))
            
            for row, ticket in enumerate(tickets):
                self.attack_results_table.setItem(row, 0, QTableWidgetItem("Kerberoasting"))
                self.attack_results_table.setItem(row, 1, QTableWidgetItem(ticket['user']))
                self.attack_results_table.setItem(row, 2, QTableWidgetItem("Success"))
                self.attack_results_table.setItem(row, 3, QTableWidgetItem(ticket['hash'][:50] + "..."))
                
            self.status_text.append(f"✅ Kerberoasting completed: {len(tickets)} tickets extracted")
            
        elif attack_type == 'ASREPRoasting':
            hashes = result.get('hashes', [])
            self.attack_results_table.setRowCount(len(hashes))
            
            for row, hash_data in enumerate(hashes):
                self.attack_results_table.setItem(row, 0, QTableWidgetItem("ASREPRoasting"))
                self.attack_results_table.setItem(row, 1, QTableWidgetItem(hash_data['user']))
                self.attack_results_table.setItem(row, 2, QTableWidgetItem("Success"))
                self.attack_results_table.setItem(row, 3, QTableWidgetItem(hash_data['hash'][:50] + "..."))
                
            self.status_text.append(f"✅ ASREPRoasting completed: {len(hashes)} hashes extracted")
            
    def update_bloodhound_results(self, result):
        # Update attack paths
        paths = result.get('attack_paths', [])
        self.paths_table.setRowCount(len(paths))
        
        for row, path in enumerate(paths):
            self.paths_table.setItem(row, 0, QTableWidgetItem(path['path']))
            
            difficulty_item = QTableWidgetItem(path['difficulty'])
            if path['difficulty'] == 'Low':
                difficulty_item.setForeground(QColor("#FF6B6B"))
            elif path['difficulty'] == 'Medium':
                difficulty_item.setForeground(QColor("#FFA500"))
            self.paths_table.setItem(row, 1, difficulty_item)
            
            impact_item = QTableWidgetItem(path['impact'])
            if path['impact'] == 'Critical':
                impact_item.setForeground(QColor("#FF0000"))
            self.paths_table.setItem(row, 2, impact_item)
            
        # Update high value targets
        hvts = result.get('high_value_targets', [])
        self.hvt_table.setRowCount(len(hvts))
        
        for row, hvt in enumerate(hvts):
            self.hvt_table.setItem(row, 0, QTableWidgetItem(hvt['name']))
            self.hvt_table.setItem(row, 1, QTableWidgetItem(hvt['type']))
            self.hvt_table.setItem(row, 2, QTableWidgetItem(str(hvt.get('members', hvt.get('role', '')))))
            
        self.status_text.append(f"✅ BloodHound analysis completed: {len(paths)} attack paths found")
        
    def handle_ad_event(self, event_type, message, data):
        self.status_text.append(f"📡 {message}")