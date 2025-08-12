from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QLineEdit,
    QTextEdit, QCheckBox, QFileDialog, QMessageBox, QFrame, QSizePolicy,
    QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView, QComboBox
)
from PyQt6.QtCore import pyqtSignal, Qt, QSize
from PyQt6.QtGui import QFont, QIcon
from app.pages.components.base_page import BasePage
from app.widgets.attack_chain_mindmap import AttackChainMindmap
import os

class AttackChainHomePage(BasePage):
    """Attack chain home page with Setup, Mindmap, and Correlations tabs"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("AttackChainHomePage")
        self.main_window = parent
    
    def setup_ui(self):
        """Setup the UI - required by BasePage"""
        self.setup_page()
    
    def setup_page(self):
        """Setup the attack chain home page"""
        # Create main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        
        # Create main tab widget
        self.main_tabs = QTabWidget()
        
        # Setup tab with subtabs
        self.setup_tab = self.create_setup_tab()
        self.main_tabs.addTab(self.setup_tab, "⚙️ Setup")

        
        # Correlations tab
        self.correlations_tab = self.create_correlations_tab()
        self.main_tabs.addTab(self.correlations_tab, "🔗 Correlations")
        
        # Remediation tab
        self.remediation_tab = self.create_remediation_tab()
        self.main_tabs.addTab(self.remediation_tab, "🛠️ Remediation")
        
        # Dashboard tab
        self.dashboard_tab = self.create_dashboard_tab()
        self.main_tabs.addTab(self.dashboard_tab, "🛡️ Dashboard")
        
        # Analytics tab
        self.analytics_tab = self.create_analytics_tab()
        self.main_tabs.addTab(self.analytics_tab, "🔬 Analytics")
        
        main_layout.addWidget(self.main_tabs)
    
    def create_setup_tab(self):
        """Create the Setup tab with Target Profiles and Credential Management subtabs"""
        setup_widget = QWidget()
        setup_layout = QVBoxLayout(setup_widget)
        
        # Create subtab widget
        setup_subtabs = QTabWidget()
        
        # Target Profiles subtab
        target_profiles_tab = self.create_target_profiles_tab()
        setup_subtabs.addTab(target_profiles_tab, "🎯 Target Profiles")
        
        # Credential Management subtab
        credential_mgmt_tab = self.create_credential_management_tab()
        setup_subtabs.addTab(credential_mgmt_tab, "🔑 Credential Management")
        
        setup_layout.addWidget(setup_subtabs)
        return setup_widget
    
    def create_target_profiles_tab(self):
        """Create the Target Profiles subtab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        

        
        # Target configuration form with two-column layout
        form_frame = QFrame()
        form_frame.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 150);
                border-radius: 10px;
                border: 1px solid rgba(100, 200, 255, 50);
            }
        """)
        form_layout = QVBoxLayout(form_frame)
        form_layout.setContentsMargins(20, 20, 20, 20)
        
        # Two-column layout
        columns_layout = QHBoxLayout()
        columns_layout.setSpacing(30)
        
        # Left column - Target Information
        left_column = QVBoxLayout()
        left_column.setSpacing(10)
        
        # Target section header
        target_header = QLabel("📋 Target Information")
        target_header.setStyleSheet("""
            font-size: 12pt;
            font-weight: bold;
            color: #FFD700;
            padding: 2px;
        """)
        left_column.addWidget(target_header)
        
        # Target name
        left_column.addWidget(QLabel("Target Name:"))
        self.target_name = QLineEdit()
        self.target_name.setPlaceholderText("e.g., Company XYZ")
        left_column.addWidget(self.target_name)
        
        # In-scope targets
        left_column.addWidget(QLabel("In-scope Targets:"))
        self.primary_target = QTextEdit()
        self.primary_target.setFixedHeight(60)
        self.primary_target.setPlaceholderText("Domains, IPs, networks (e.g., example.com, 192.168.1.0/24)")
        self.primary_target.textChanged.connect(self.update_scope_validation)
        left_column.addWidget(self.primary_target)
        
        # Known subdomains
        left_column.addWidget(QLabel("Known Subdomains:"))
        self.subdomains = QTextEdit()
        self.subdomains.setFixedHeight(45)
        self.subdomains.setPlaceholderText("e.g., api.example.com, staging.example.com")
        left_column.addWidget(self.subdomains)
        
        # Cloud assets
        left_column.addWidget(QLabel("Cloud Assets:"))
        self.cloud_assets = QTextEdit()
        self.cloud_assets.setFixedHeight(45)
        self.cloud_assets.setPlaceholderText("e.g., s3://bucket-name, Azure VM IPs")
        left_column.addWidget(self.cloud_assets)
        
        columns_layout.addLayout(left_column)
        
        # Right column - Scope & Rules
        right_column = QVBoxLayout()
        right_column.setSpacing(10)
        
        # Scope section header
        scope_header = QLabel("🎯 Scope & Rules of Engagement")
        scope_header.setStyleSheet("""
            font-size: 12pt;
            font-weight: bold;
            color: #FFD700;
            padding: 2px;
        """)
        right_column.addWidget(scope_header)
        
        # Out of scope
        right_column.addWidget(QLabel("Out of Scope:"))
        self.out_scope = QTextEdit()
        self.out_scope.setFixedHeight(60)
        self.out_scope.setPlaceholderText("Excluded targets, IPs, domains")
        self.out_scope.textChanged.connect(self.update_scope_validation)
        right_column.addWidget(self.out_scope)
        
        # Restrictions/Notes
        right_column.addWidget(QLabel("Restrictions/Notes:"))
        self.restrictions = QTextEdit()
        self.restrictions.setFixedHeight(45)
        self.restrictions.setPlaceholderText("Special restrictions or notes")
        right_column.addWidget(self.restrictions)
        
        # Permission checkboxes
        permissions_label = QLabel("Testing Permissions:")
        permissions_label.setStyleSheet("font-weight: bold; color: #64C8FF; margin-top: 10px;")
        right_column.addWidget(permissions_label)
        
        self.dos_allowed = QCheckBox("DOS Attacks Allowed")
        self.dos_allowed.setStyleSheet("color: #DCDCDC; font-weight: bold; padding: 3px;")
        right_column.addWidget(self.dos_allowed)
        
        self.social_eng_allowed = QCheckBox("Social Engineering Allowed")
        self.social_eng_allowed.setStyleSheet("color: #DCDCDC; font-weight: bold; padding: 3px;")
        right_column.addWidget(self.social_eng_allowed)
        
        self.physical_allowed = QCheckBox("Physical Access Allowed")
        self.physical_allowed.setStyleSheet("color: #DCDCDC; font-weight: bold; padding: 3px;")
        right_column.addWidget(self.physical_allowed)
        
        columns_layout.addLayout(right_column)
        form_layout.addLayout(columns_layout)
        
        # Bottom section - Scope status and Add button
        bottom_layout = QHBoxLayout()
        
        # Add target button
        add_btn = QPushButton("📝 Add Target Profile")
        add_btn.setStyleSheet(self.get_button_style("#64C8FF", "#000000"))
        add_btn.clicked.connect(self.add_target)
        bottom_layout.addWidget(add_btn)
        
        bottom_layout.addStretch()
        
        # Scope validation status
        self.scope_status = QLabel("Scope: Not configured")
        self.scope_status.setStyleSheet("""
            QLabel {
                background-color: rgba(255, 165, 0, 100);
                border: 1px solid #FFA500;
                border-radius: 5px;
                padding: 8px 12px;
                color: #FFFFFF;
                font-size: 11pt;
                font-weight: bold;
            }
        """)
        bottom_layout.addWidget(self.scope_status)
        
        form_layout.addLayout(bottom_layout)
        
        layout.addWidget(form_frame)
        
        # Target list table
        list_label = QLabel("📋 Profiles:")
        list_label.setStyleSheet("font-weight: bold; color: #64C8FF; margin-top: 15px;")
        layout.addWidget(list_label)
        
        self.target_table = QTableWidget()
        self.target_table.setColumnCount(5)
        self.target_table.setHorizontalHeaderLabels(["Tenant", "Type", "Target", "Priority", "Status"])
        self.target_table.setMinimumHeight(120)
        self.target_table.setStyleSheet("""
            QTableWidget {
                background-color: rgba(20, 30, 40, 150);
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                color: #DCDCDC;
                gridline-color: rgba(100, 200, 255, 50);
            }
            QHeaderView::section {
                background-color: rgba(100, 200, 255, 100);
                color: #000000;
                font-weight: bold;
                padding: 5px;
                border: none;
            }
        """)
        
        # Auto-resize table columns
        header = self.target_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        
        self.target_table.itemSelectionChanged.connect(self.on_profile_selected)
        layout.addWidget(self.target_table)
        
        # Load existing profiles
        self.load_existing_profiles()
        
        return widget
    
    def create_credential_management_tab(self):
        """Create the Credential Management subtab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Header
        title_layout = QHBoxLayout()
        title = QLabel("Credential Management")
        title.setStyleSheet("""
            font-size: 16pt;
            font-weight: bold;
            color: #64C8FF;
            padding: 10px;
        """)
        title_layout.addWidget(title)
        title_layout.addStretch()
        
        # Type dropdown
        type_label = QLabel("Type:")
        type_label.setStyleSheet("font-weight: bold; color: #64C8FF;")
        title_layout.addWidget(type_label)
        
        self.type_combo = QComboBox()
        self.type_combo.addItems(["Username/Password", "NTLM Hash", "Kerberos Ticket", "SQL Server Auth", "Windows Auth", "Contacts"])
        self.type_combo.setMinimumWidth(180)
        self.type_combo.currentTextChanged.connect(self.on_credential_type_changed)
        title_layout.addWidget(self.type_combo)
        
        layout.addLayout(title_layout)
        
        # Credential form
        form_frame = QFrame()
        form_frame.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 150);
                border-radius: 10px;
                border: 1px solid rgba(100, 200, 255, 50);
            }
        """)
        form_layout = QVBoxLayout(form_frame)
        form_layout.setContentsMargins(15, 15, 15, 15)
        
        # Create all credential fields (will be shown/hidden based on type)
        self.create_credential_fields(form_layout)
        
        # Buttons
        btn_layout = QHBoxLayout()
        add_cred_btn = QPushButton("Add Credential")
        add_cred_btn.setStyleSheet(self.get_button_style("#64C8FF", "#000000"))
        add_cred_btn.clicked.connect(self.add_credential)
        btn_layout.addWidget(add_cred_btn)
        
        delete_cred_btn = QPushButton("Delete Selected")
        delete_cred_btn.setStyleSheet(self.get_button_style("#FF6347"))
        delete_cred_btn.clicked.connect(self.delete_selected_credential)
        btn_layout.addWidget(delete_cred_btn)
        
        clear_creds_btn = QPushButton("Clear All")
        clear_creds_btn.setStyleSheet(self.get_button_style("#CD5C5C"))
        clear_creds_btn.clicked.connect(self.clear_credentials)
        btn_layout.addWidget(clear_creds_btn)
        
        btn_layout.addStretch()
        form_layout.addLayout(btn_layout)
        
        layout.addWidget(form_frame)
        
        # Credential table
        cred_header = QHBoxLayout()
        cred_header.addWidget(QLabel("Stored Credentials:"))
        cred_header.addStretch()
        
        self.show_passwords_cb = QCheckBox("Show Passwords")
        self.show_passwords_cb.setStyleSheet("color: #DCDCDC; font-weight: bold;")
        self.show_passwords_cb.stateChanged.connect(self.toggle_password_display)
        cred_header.addWidget(self.show_passwords_cb)
        
        layout.addLayout(cred_header)
        
        self.cred_table = QTableWidget()
        self.cred_table.setColumnCount(7)
        self.cred_table.setHorizontalHeaderLabels(["Source", "Type", "Username", "Password", "Domain", "Service", "Notes"])
        self.cred_table.setMaximumHeight(200)
        self.cred_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.cred_table.setStyleSheet("""
            QTableWidget {
                background-color: rgba(20, 30, 40, 150);
                border: 1px solid rgba(100, 200, 255, 50);
                border-radius: 5px;
                color: #DCDCDC;
                gridline-color: rgba(100, 200, 255, 50);
                font-size: 9pt;
            }
            QHeaderView::section {
                background-color: rgba(100, 200, 255, 100);
                color: #000000;
                font-weight: bold;
                padding: 3px;
                border: none;
            }
        """)
        
        # Auto-resize columns
        header = self.cred_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        
        layout.addWidget(self.cred_table)
        
        # Initialize field visibility
        self.on_credential_type_changed("Username/Password")
        
        # Load existing credentials
        self.refresh_credential_display()
        
        return widget
    
    def create_mindmap_tab(self):
        """Create the Mindmap tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        try:
            self.mindmap_widget = AttackChainMindmap()
            # Connect to navigation signal if available
            if hasattr(self, 'navigate_signal'):
                self.mindmap_widget.phase_selected.connect(self.on_phase_selected)
            elif hasattr(self.main_window, 'navigation_manager'):
                self.mindmap_widget.phase_selected.connect(
                    lambda phase, data: self.main_window.navigation_manager.navigate_to(
                        self.get_phase_navigation_target(phase)
                    )
                )
            layout.addWidget(self.mindmap_widget)
        except Exception as e:
            print(f"Error creating mindmap: {e}")
            placeholder = QLabel("🧠 Interactive Attack Chain Mindmap\n(Click phases to navigate)")
            placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
            placeholder.setStyleSheet("color: #DCDCDC; padding: 20px; font-size: 14pt;")
            layout.addWidget(placeholder)
        
        return widget
    
    def get_phase_navigation_target(self, phase_name):
        """Get navigation target for phase"""
        phase_mapping = {
            "ENGAGEMENT SETUP": "attack_chain_home",
            "RECON & ENUMERATION": "recon_enumeration",
            "VULNERABILITY ANALYSIS": "vuln_scanning", 
            "EXPLOITATION": "web_exploits",
            "Interactive Shell": "web_exploits",
            "POST-EXPLOITATION": "post_exploitation",
            "REPORTING & TOOLS": "scripts"
        }
        return phase_mapping.get(phase_name, "attack_chain_home")
    
    def create_correlations_tab(self):
        """Create the Correlations tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Try to create correlation dashboard widget
        try:
            from app.widgets.correlation_dashboard_widget import CorrelationDashboardWidget
            tenant_id = getattr(self.main_window, 'current_profile_name', 'default')
            correlation_dashboard = CorrelationDashboardWidget(tenant_id)
            layout.addWidget(correlation_dashboard)
        except ImportError:
            # Placeholder for correlations dashboard
            placeholder = QLabel("🔗 Cross-Scan Correlations Dashboard\n(Vulnerability correlation and analysis)")
            placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
            placeholder.setStyleSheet("color: #DCDCDC; padding: 20px; font-size: 14pt;")
            layout.addWidget(placeholder)
        
        return widget
    
    def create_remediation_tab(self):
        """Create the Remediation tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Try to create remediation widget
        try:
            from app.widgets.remediation_widget import RemediationWidget
            tenant_id = getattr(self.main_window, 'current_profile_name', 'default')
            remediation_widget = RemediationWidget(tenant_id)
            layout.addWidget(remediation_widget)
        except ImportError:
            # Placeholder for remediation
            placeholder = QLabel("🛠️ Automated Remediation Engine\n(Remediation planning and execution)")
            placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
            placeholder.setStyleSheet("color: #DCDCDC; padding: 20px; font-size: 14pt;")
            layout.addWidget(placeholder)
        
        return widget
    
    def create_dashboard_tab(self):
        """Create the Dashboard tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Try to create centralized dashboard
        try:
            from app.pages.centralized_dashboard_page import create_centralized_dashboard
            tenant_id = getattr(self.main_window, 'current_profile_name', 'default')
            centralized_dashboard = create_centralized_dashboard(tenant_id)
            layout.addWidget(centralized_dashboard)
        except ImportError:
            # Placeholder for dashboard
            placeholder = QLabel("🛡️ Centralized Security Dashboard\n(Real-time metrics and monitoring)")
            placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
            placeholder.setStyleSheet("color: #DCDCDC; padding: 20px; font-size: 14pt;")
            layout.addWidget(placeholder)
        
        return widget
    
    def create_analytics_tab(self):
        """Create the Analytics tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Try to create advanced analytics widget
        try:
            from app.widgets.advanced_analytics_widget import create_advanced_analytics_widget
            tenant_id = getattr(self.main_window, 'current_profile_name', 'default')
            advanced_analytics = create_advanced_analytics_widget(tenant_id)
            layout.addWidget(advanced_analytics)
        except ImportError:
            # Placeholder for analytics
            placeholder = QLabel("🔬 Advanced Security Analytics\n(ML-powered threat analysis and insights)")
            placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
            placeholder.setStyleSheet("color: #DCDCDC; padding: 20px; font-size: 14pt;")
            layout.addWidget(placeholder)
        
        return widget
    
    def get_button_style(self, border_color, text_color="#FFFFFF"):
        """Get consistent button styling"""
        return f"""
            QPushButton {{
                background-color: rgba(50, 150, 50, 150);
                border: 2px solid {border_color};
                border-radius: 5px;
                color: {text_color};
                font-weight: bold;
                padding: 8px 15px;
                font-size: 12pt;
            }}
            QPushButton:hover {{
                background-color: rgba(70, 170, 70, 200);
            }}
        """
    
    def create_credential_fields(self, layout):
        """Create all credential form fields"""
        # Username field
        self.username_label = QLabel("Username:")
        self.username_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(self.username_label)
        self.username = QLineEdit()
        self.username.setPlaceholderText("Enter username")
        layout.addWidget(self.username)
        
        # Password field
        self.password_label = QLabel("Password:")
        self.password_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(self.password_label)
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText("Enter password")
        layout.addWidget(self.password)
        
        # Domain field
        self.domain_label = QLabel("Domain:")
        self.domain_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(self.domain_label)
        self.domain = QLineEdit()
        self.domain.setPlaceholderText("e.g., DOMAIN or leave blank")
        layout.addWidget(self.domain)
        
        # Service field
        self.service_label = QLabel("Service:")
        self.service_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(self.service_label)
        self.service = QLineEdit()
        self.service.setPlaceholderText("e.g., SSH, RDP, SMB, HTTP")
        layout.addWidget(self.service)
        
        # Notes field
        self.notes_label = QLabel("Notes:")
        self.notes_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(self.notes_label)
        self.notes = QLineEdit()
        self.notes.setPlaceholderText("Optional notes")
        layout.addWidget(self.notes)
        
        # NTLM Hash field
        self.ntlm_hash_label = QLabel("NTLM Hash:")
        self.ntlm_hash_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(self.ntlm_hash_label)
        self.ntlm_hash = QLineEdit()
        self.ntlm_hash.setEchoMode(QLineEdit.EchoMode.Password)
        self.ntlm_hash.setPlaceholderText("Enter NTLM hash")
        layout.addWidget(self.ntlm_hash)
        
        # Ticket File field
        self.ticket_file_label = QLabel("Ticket File:")
        self.ticket_file_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(self.ticket_file_label)
        self.ticket_file = QLineEdit()
        self.ticket_file.setPlaceholderText("Path to ticket file")
        layout.addWidget(self.ticket_file)
        
        # Contact fields
        self.account_name_label = QLabel("Account Name:")
        self.account_name_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(self.account_name_label)
        self.account_name = QLineEdit()
        self.account_name.setPlaceholderText("e.g., jdoe, admin")
        layout.addWidget(self.account_name)
        
        self.first_name_label = QLabel("First Name:")
        self.first_name_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(self.first_name_label)
        self.first_name = QLineEdit()
        self.first_name.setPlaceholderText("First name")
        layout.addWidget(self.first_name)
        
        self.middle_name_label = QLabel("Middle Name:")
        self.middle_name_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(self.middle_name_label)
        self.middle_name = QLineEdit()
        self.middle_name.setPlaceholderText("Middle name (optional)")
        layout.addWidget(self.middle_name)
        
        self.last_name_label = QLabel("Last Name:")
        self.last_name_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(self.last_name_label)
        self.last_name = QLineEdit()
        self.last_name.setPlaceholderText("Last name")
        layout.addWidget(self.last_name)
        
        self.email_address_label = QLabel("Email Address:")
        self.email_address_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(self.email_address_label)
        self.email_address = QLineEdit()
        self.email_address.setPlaceholderText("e.g., john.doe@company.com")
        layout.addWidget(self.email_address)
        
        self.mobile_phone_label = QLabel("Mobile Phone:")
        self.mobile_phone_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(self.mobile_phone_label)
        self.mobile_phone = QLineEdit()
        self.mobile_phone.setPlaceholderText("e.g., +1-555-123-4567")
        layout.addWidget(self.mobile_phone)
        
        self.address_label = QLabel("Address:")
        self.address_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(self.address_label)
        self.address = QLineEdit()
        self.address.setPlaceholderText("Physical address (optional)")
        layout.addWidget(self.address)
    
    # Placeholder methods for functionality
    def on_credential_type_changed(self, credential_type):
        """Handle credential type change to show/hide appropriate fields"""
        # Hide all fields first
        fields = [
            (self.username_label, self.username),
            (self.password_label, self.password),
            (self.ntlm_hash_label, self.ntlm_hash),
            (self.ticket_file_label, self.ticket_file),
            (self.domain_label, self.domain),
            (self.service_label, self.service),
            (self.notes_label, self.notes),
            (self.account_name_label, self.account_name),
            (self.first_name_label, self.first_name),
            (self.middle_name_label, self.middle_name),
            (self.last_name_label, self.last_name),
            (self.email_address_label, self.email_address),
            (self.mobile_phone_label, self.mobile_phone),
            (self.address_label, self.address)
        ]
        
        for label, field in fields:
            label.setVisible(False)
            field.setVisible(False)
        
        # Show fields based on credential type
        if credential_type == "Username/Password":
            for label, field in [(self.username_label, self.username), (self.password_label, self.password), 
                               (self.domain_label, self.domain), (self.service_label, self.service), (self.notes_label, self.notes)]:
                label.setVisible(True)
                field.setVisible(True)
        elif credential_type == "NTLM Hash":
            for label, field in [(self.username_label, self.username), (self.ntlm_hash_label, self.ntlm_hash), 
                               (self.service_label, self.service), (self.notes_label, self.notes)]:
                label.setVisible(True)
                field.setVisible(True)
        elif credential_type == "Kerberos Ticket":
            for label, field in [(self.ticket_file_label, self.ticket_file), (self.service_label, self.service), (self.notes_label, self.notes)]:
                label.setVisible(True)
                field.setVisible(True)
        elif credential_type == "SQL Server Auth":
            for label, field in [(self.username_label, self.username), (self.password_label, self.password), 
                               (self.service_label, self.service), (self.notes_label, self.notes)]:
                label.setVisible(True)
                field.setVisible(True)
        elif credential_type == "Windows Auth":
            for label, field in [(self.username_label, self.username), (self.password_label, self.password), 
                               (self.domain_label, self.domain), (self.service_label, self.service), (self.notes_label, self.notes)]:
                label.setVisible(True)
                field.setVisible(True)
        elif credential_type == "Contacts":
            for label, field in [(self.account_name_label, self.account_name), (self.first_name_label, self.first_name),
                               (self.middle_name_label, self.middle_name), (self.last_name_label, self.last_name),
                               (self.email_address_label, self.email_address), (self.mobile_phone_label, self.mobile_phone),
                               (self.address_label, self.address), (self.notes_label, self.notes)]:
                label.setVisible(True)
                field.setVisible(True)
    
    def add_target(self):
        """Add target to list"""
        name = self.target_name.text().strip()
        target = self.primary_target.toPlainText().strip()
        
        if not name or not target:
            return
        
        row = self.target_table.rowCount()
        self.target_table.insertRow(row)
        self.target_table.setItem(row, 0, QTableWidgetItem(name))
        self.target_table.setItem(row, 1, QTableWidgetItem("External"))
        self.target_table.setItem(row, 2, QTableWidgetItem(target))
        self.target_table.setItem(row, 3, QTableWidgetItem("High"))
        self.target_table.setItem(row, 4, QTableWidgetItem("Active"))
        
        self.target_name.clear()
        self.primary_target.clear()
        self.subdomains.clear()
        self.cloud_assets.clear()
        self.out_scope.clear()
        self.restrictions.clear()
        self.dos_allowed.setChecked(False)
        self.social_eng_allowed.setChecked(False)
        self.physical_allowed.setChecked(False)
    
    def on_profile_selected(self):
        """Handle profile selection from table"""
        current_row = self.target_table.currentRow()
        if current_row >= 0:
            # Get profile data from table
            name_item = self.target_table.item(current_row, 0)
            target_item = self.target_table.item(current_row, 2)
            
            if name_item:
                profile_name = name_item.text()
                
                # Set current profile name for tenant ID
                if hasattr(self.main_window, 'current_profile_name'):
                    self.main_window.current_profile_name = profile_name
                else:
                    setattr(self.main_window, 'current_profile_name', profile_name)
                
                # Switch credential manager to this profile
                try:
                    from app.core.credential_manager import credential_manager
                    credential_manager.set_profile(profile_name)
                except ImportError:
                    pass
                
                # Trigger tenant change via tenant-aware updater
                try:
                    from app.core.tenant_aware_updater import tenant_aware_updater
                    tenant_aware_updater.set_tenant(profile_name)
                except ImportError:
                    # Fallback to old method
                    self.trigger_tenant_change_updates(profile_name)
                
                # Load profile data from disk if exists
                import os
                import json
                profiles_dir = os.path.join(os.getcwd(), 'profiles')
                profile_file = os.path.join(profiles_dir, f"{profile_name}.json")
                
                if os.path.exists(profile_file):
                    try:
                        with open(profile_file, 'r') as f:
                            profile_data = json.load(f)
                        
                        # Load target information fields
                        self.target_name.setText(profile_data.get('target_name', profile_name))
                        target_text = profile_data.get('primary_target', '') or profile_data.get('scope', '')
                        self.primary_target.setPlainText(target_text)
                        self.subdomains.setPlainText(profile_data.get('subdomains', ''))
                        self.cloud_assets.setPlainText(profile_data.get('cloud_assets', ''))
                        self.out_scope.setPlainText(profile_data.get('out_scope', ''))
                        self.restrictions.setPlainText(profile_data.get('restrictions', ''))
                        self.dos_allowed.setChecked(profile_data.get('dos_allowed', False))
                        self.social_eng_allowed.setChecked(profile_data.get('social_eng_allowed', False))
                        self.physical_allowed.setChecked(profile_data.get('physical_allowed', False))
                        
                        # Load credentials
                        self.load_credentials_from_profile(profile_data.get('credentials', {}))
                        
                        # Update inventory with profile assets
                        self.update_inventory_with_profile_data(profile_data)
                        
                    except Exception as e:
                        # If file load fails, just load basic data from table
                        self.target_name.setText(profile_name)
                        if target_item:
                            self.primary_target.setPlainText(target_item.text())
                else:
                    # No saved file, load basic data from table
                    self.target_name.setText(profile_name)
                    if target_item:
                        self.primary_target.setPlainText(target_item.text())
                
                # Refresh credential display
                self.refresh_credential_display()
                
                # Update scope validation
                self.update_scope_validation()
    
    def save_profile(self):
        """Save current engagement profile"""
        from PyQt6.QtWidgets import QInputDialog, QMessageBox
        import json
        import os
        
        profile_name, ok = QInputDialog.getText(self, 'Save Profile', 'Enter profile name:')
        if not ok or not profile_name.strip():
            return
            
        profile_data = {
            'target_name': self.target_name.text(),
            'primary_target': self.primary_target.toPlainText(),
            'scope': self.primary_target.toPlainText(),
            'subdomains': self.subdomains.toPlainText(),
            'cloud_assets': self.cloud_assets.toPlainText(),
            'out_scope': self.out_scope.toPlainText(),
            'restrictions': self.restrictions.toPlainText(),
            'dos_allowed': self.dos_allowed.isChecked(),
            'social_eng_allowed': self.social_eng_allowed.isChecked(),
            'physical_allowed': self.physical_allowed.isChecked(),
            'credentials': self.get_credentials_for_save()
        }
        
        profiles_dir = os.path.join(os.getcwd(), 'profiles')
        os.makedirs(profiles_dir, exist_ok=True)
        
        profile_file = os.path.join(profiles_dir, f"{profile_name}.json")
        try:
            with open(profile_file, 'w') as f:
                json.dump(profile_data, f, indent=2)
            
            QMessageBox.information(self, 'Success', f'Profile "{profile_name}" saved successfully!')
            self.load_existing_profiles()
        except Exception as e:
            QMessageBox.warning(self, 'Error', f'Failed to save profile: {str(e)}')
    
    def new_profile(self):
        """Create a new blank profile entry"""
        from PyQt6.QtWidgets import QInputDialog, QMessageBox
        
        profile_name, ok = QInputDialog.getText(self, 'New Profile', 'Enter new profile name:')
        if not ok or not profile_name.strip():
            return
        
        profile_name = profile_name.strip()
        
        # Check if profile already exists
        for row in range(self.target_table.rowCount()):
            name_item = self.target_table.item(row, 0)
            if name_item and name_item.text() == profile_name:
                QMessageBox.warning(self, "Profile Exists", f"Profile '{profile_name}' already exists.")
                return
        
        # Clear all form fields
        self.target_name.clear()
        self.primary_target.clear()
        self.subdomains.clear()
        self.cloud_assets.clear()
        self.out_scope.clear()
        self.restrictions.clear()
        self.dos_allowed.setChecked(False)
        self.social_eng_allowed.setChecked(False)
        self.physical_allowed.setChecked(False)
        
        # Set new profile in credential manager and clear credentials
        try:
            from app.core.credential_manager import credential_manager
            credential_manager.set_profile(profile_name)
            self.refresh_credential_display()
        except ImportError:
            pass
        
        # Add blank entry to target table
        row = self.target_table.rowCount()
        self.target_table.insertRow(row)
        self.target_table.setItem(row, 0, QTableWidgetItem(profile_name))
        self.target_table.setItem(row, 1, QTableWidgetItem("New"))
        self.target_table.setItem(row, 2, QTableWidgetItem(""))
        self.target_table.setItem(row, 3, QTableWidgetItem("High"))
        self.target_table.setItem(row, 4, QTableWidgetItem("Active"))
        
        # Select the new row
        self.target_table.selectRow(row)
        
        # Set as current profile and trigger tenant change
        if hasattr(self.main_window, 'current_profile_name'):
            self.main_window.current_profile_name = profile_name
        else:
            setattr(self.main_window, 'current_profile_name', profile_name)
        
        # Trigger tenant change
        try:
            from app.core.tenant_aware_updater import tenant_aware_updater
            tenant_aware_updater.set_tenant(profile_name)
        except ImportError:
            pass
        
        self.update_scope_validation()
    
    def load_profile(self):
        """Load an engagement profile"""
        from PyQt6.QtWidgets import QFileDialog, QMessageBox
        import json
        import os

        profiles_dir = os.path.join(os.getcwd(), 'profiles')
        if not os.path.exists(profiles_dir):
            QMessageBox.information(self, 'No Profiles', 'No saved profiles found.')
            return

        profile_file, _ = QFileDialog.getOpenFileName(
            self, 'Load Profile', profiles_dir, 'JSON files (*.json)'
        )

        if not profile_file:
            return

        try:
            with open(profile_file, 'r') as f:
                profile_data = json.load(f)
            
            # Load target information fields
            self.target_name.setText(profile_data.get('target_name', ''))
            target_text = profile_data.get('primary_target', '') or profile_data.get('scope', '')
            self.primary_target.setPlainText(target_text)
            self.subdomains.setPlainText(profile_data.get('subdomains', ''))
            self.cloud_assets.setPlainText(profile_data.get('cloud_assets', ''))
            self.out_scope.setPlainText(profile_data.get('out_scope', ''))
            self.restrictions.setPlainText(profile_data.get('restrictions', ''))
            self.dos_allowed.setChecked(profile_data.get('dos_allowed', False))
            self.social_eng_allowed.setChecked(profile_data.get('social_eng_allowed', False))
            self.physical_allowed.setChecked(profile_data.get('physical_allowed', False))
            
            # Load credentials
            self.load_credentials_from_profile(profile_data.get('credentials', {}))
            
            profile_name = os.path.basename(profile_file).replace('.json', '')
            
            # Set current profile in main window
            if hasattr(self.main_window, 'current_profile_name'):
                self.main_window.current_profile_name = profile_name
            else:
                setattr(self.main_window, 'current_profile_name', profile_name)
            
            # Add loaded profile to target table if not already present
            self.add_profile_to_table(profile_name, profile_data)
            
            # Update inventory with profile assets
            self.update_inventory_with_profile_data(profile_data)
            
            # Refresh the target profiles table
            self.load_existing_profiles()
            
            QMessageBox.information(self, 'Success', f'Profile "{profile_name}" loaded successfully!')
            self.refresh_credential_display()
            self.update_scope_validation()

        except Exception as e:
            QMessageBox.warning(self, 'Error', f'Failed to load profile: {str(e)}')
    
    def delete_selected_profile(self):
        """Delete the selected profile from table and disk"""
        from PyQt6.QtWidgets import QMessageBox
        import os
        
        current_row = self.target_table.currentRow()
        if current_row >= 0:
            name_item = self.target_table.item(current_row, 0)
            if name_item:
                profile_name = name_item.text()
                reply = QMessageBox.question(self, "Delete Profile", 
                                           f"Delete profile '{profile_name}' permanently?\n\nThis will remove the profile file from disk.",
                                           QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                if reply == QMessageBox.StandardButton.Yes:
                    # Remove from table
                    self.target_table.removeRow(current_row)
                    
                    # Delete the actual profile file from disk
                    profiles_dir = os.path.join(os.getcwd(), 'profiles')
                    profile_file = os.path.join(profiles_dir, f"{profile_name}.json")
                    
                    try:
                        if os.path.exists(profile_file):
                            os.remove(profile_file)
                    except Exception as e:
                        QMessageBox.warning(self, "Error", f"Failed to delete profile file: {str(e)}")
        else:
            QMessageBox.information(self, "No Selection", "Please select a profile to delete")
    
    def load_existing_profiles(self):
        """Load existing profiles from the profiles directory"""
        import json
        import os
        
        profiles_dir = os.path.join(os.getcwd(), 'profiles')
        if not os.path.exists(profiles_dir):
            return
        
        # Clear existing table
        self.target_table.setRowCount(0)
        
        # Load all JSON files from profiles directory
        for filename in os.listdir(profiles_dir):
            if filename.endswith('.json'):
                try:
                    profile_path = os.path.join(profiles_dir, filename)
                    with open(profile_path, 'r') as f:
                        profile_data = json.load(f)
                    
                    # Extract profile information
                    profile_name = filename.replace('.json', '')
                    target = profile_data.get('primary_target', '') or profile_data.get('scope', '')
                    
                    if not target:
                        continue
                    
                    # Determine target type based on content
                    target_type = "External"
                    if any(keyword in target.lower() for keyword in ["api", "rest", "graphql"]):
                        target_type = "API"
                    elif any(keyword in target.lower() for keyword in ["app", "web", "http"]):
                        target_type = "Web Application"
                    elif any(keyword in target.lower() for keyword in ["192.168", "10.", "172."]):
                        target_type = "Internal"
                    
                    # Add to table
                    row = self.target_table.rowCount()
                    self.target_table.insertRow(row)
                    self.target_table.setItem(row, 0, QTableWidgetItem(profile_name))
                    self.target_table.setItem(row, 1, QTableWidgetItem(target_type))
                    self.target_table.setItem(row, 2, QTableWidgetItem(target))
                    self.target_table.setItem(row, 3, QTableWidgetItem("High"))
                    self.target_table.setItem(row, 4, QTableWidgetItem("Active"))
                    
                except Exception:
                    continue
    
    def add_profile_to_table(self, profile_name, profile_data):
        """Add loaded profile to target table if not already present"""
        # Check if profile already exists in table
        for row in range(self.target_table.rowCount()):
            name_item = self.target_table.item(row, 0)
            if name_item and name_item.text() == profile_name:
                # Profile already exists, select it
                self.target_table.selectRow(row)
                return
        
        # Profile doesn't exist, add it
        target = profile_data.get('primary_target', '') or profile_data.get('scope', '')
        if target:
            # Determine target type
            target_type = "External"
            if any(keyword in target.lower() for keyword in ["api", "rest", "graphql"]):
                target_type = "API"
            elif any(keyword in target.lower() for keyword in ["app", "web", "http"]):
                target_type = "Web Application"
            elif any(keyword in target.lower() for keyword in ["192.168", "10.", "172."]):
                target_type = "Internal"
            
            # Add to table
            row = self.target_table.rowCount()
            self.target_table.insertRow(row)
            self.target_table.setItem(row, 0, QTableWidgetItem(profile_name))
            self.target_table.setItem(row, 1, QTableWidgetItem(target_type))
            self.target_table.setItem(row, 2, QTableWidgetItem(target))
            self.target_table.setItem(row, 3, QTableWidgetItem("High"))
            self.target_table.setItem(row, 4, QTableWidgetItem("Active"))
            
            # Select the newly added row
            self.target_table.selectRow(row)
    
    def get_credentials_for_save(self):
        """Get credentials data for profile saving"""
        try:
            from app.core.credential_manager import credential_manager
            return credential_manager.to_dict()
        except ImportError:
            return {}
    
    def add_credential(self):
        """Add credential to global credential manager"""
        try:
            from app.core.credential_manager import credential_manager
            
            credential_type = self.type_combo.currentText()
            service = self.service.text().strip()
            notes = self.notes.text().strip()
            
            if credential_type == "Username/Password":
                username = self.username.text().strip()
                password = self.password.text().strip()
                domain = self.domain.text().strip()
                
                if not username or not password:
                    return
                
                credential_manager.add_credential(
                    username=username, password=password, domain=domain,
                    service=service, notes=notes, source="manual", credential_type=credential_type
                )
                self.username.clear()
                self.password.clear()
                self.domain.clear()
                
            elif credential_type == "NTLM Hash":
                username = self.username.text().strip()
                ntlm_hash = self.ntlm_hash.text().strip()
                
                if not username or not ntlm_hash:
                    return
                
                credential_manager.add_credential(
                    username=username, password=ntlm_hash, domain="",
                    service=service, notes=notes, source="manual", credential_type=credential_type
                )
                self.username.clear()
                self.ntlm_hash.clear()
                
            elif credential_type == "Kerberos Ticket":
                ticket_file = self.ticket_file.text().strip()
                
                if not ticket_file:
                    return
                
                credential_manager.add_credential(
                    username="", password=ticket_file, domain="",
                    service=service, notes=notes, source="manual", credential_type=credential_type
                )
                self.ticket_file.clear()
                
            elif credential_type == "Contacts":
                account_name = self.account_name.text().strip()
                email_address = self.email_address.text().strip()
                
                if not account_name and not email_address:
                    return
                
                contact_info = f"{self.first_name.text().strip()} {self.middle_name.text().strip()} {self.last_name.text().strip()}".strip()
                if self.mobile_phone.text().strip():
                    contact_info += f" | Phone: {self.mobile_phone.text().strip()}"
                if self.address.text().strip():
                    contact_info += f" | Address: {self.address.text().strip()}"
                
                credential_manager.add_credential(
                    username=account_name or email_address, password=contact_info, domain=email_address,
                    service="Contact", notes=notes, source="manual", credential_type=credential_type
                )
                
                for field in [self.account_name, self.first_name, self.middle_name, self.last_name, self.email_address, self.mobile_phone, self.address]:
                    field.clear()
                    
            elif credential_type == "SQL Server Auth":
                username = self.username.text().strip()
                password = self.password.text().strip()
                
                if not username or not password:
                    return
                
                credential_manager.add_credential(
                    username=username, password=password, domain="",
                    service=service or "MSSQL", notes=notes, source="manual", credential_type=credential_type
                )
                self.username.clear()
                self.password.clear()
                
            elif credential_type == "Windows Auth":
                username = self.username.text().strip()
                password = self.password.text().strip()
                domain = self.domain.text().strip()
                
                if not username or not password or not domain:
                    return
                
                credential_manager.add_credential(
                    username=username, password=password, domain=domain,
                    service=service or "MSSQL", notes=notes, source="manual", credential_type=credential_type
                )
                self.username.clear()
                self.password.clear()
                self.domain.clear()
            
            self.service.clear()
            self.notes.clear()
            self.refresh_credential_display()
            
        except ImportError:
            pass
    
    def delete_selected_credential(self):
        """Delete the selected credential"""
        try:
            from app.core.credential_manager import credential_manager
            from PyQt6.QtWidgets import QMessageBox
            
            current_row = self.cred_table.currentRow()
            if current_row >= 0 and current_row < len(credential_manager.credentials):
                cred = credential_manager.credentials[current_row]
                reply = QMessageBox.question(self, "Delete Credential", 
                                           f"Delete {getattr(cred, 'credential_type', 'credential')} for {cred.username or 'ticket'}?",
                                           QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                if reply == QMessageBox.StandardButton.Yes:
                    credential_manager.remove_credential(current_row)
                    self.refresh_credential_display()
            else:
                QMessageBox.information(self, "No Selection", "Please select a credential to delete")
        except ImportError:
            pass
    
    def clear_credentials(self):
        """Clear all credentials"""
        try:
            from app.core.credential_manager import credential_manager
            from PyQt6.QtWidgets import QMessageBox
            
            if credential_manager.credentials:
                reply = QMessageBox.question(self, "Clear Credentials", 
                                           "Are you sure you want to clear all credentials?",
                                           QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                if reply == QMessageBox.StandardButton.Yes:
                    credential_manager.clear_credentials()
                    self.refresh_credential_display()
        except ImportError:
            pass
    
    def toggle_password_display(self, show):
        """Toggle password visibility in the table"""
        try:
            from app.core.credential_manager import credential_manager
            
            for i in range(self.cred_table.rowCount()):
                password_item = self.cred_table.item(i, 3)
                if password_item and i < len(credential_manager.credentials):
                    cred = credential_manager.credentials[i]
                    cred_type = getattr(cred, 'credential_type', 'Username/Password')
                    
                    if cred_type != "Kerberos Ticket":
                        if show:
                            password_item.setText(cred.password)
                        else:
                            password_item.setText('*' * min(len(cred.password), 10))
                    else:
                        password_item.setText("N/A")
        except ImportError:
            pass
    
    def load_credentials_from_profile(self, cred_data):
        """Load credentials from profile data"""
        try:
            from app.core.credential_manager import credential_manager
            
            # Clear existing credentials for current profile
            credential_manager.clear_credentials()
            
            if isinstance(cred_data, dict):
                # Handle nested structure: {"credentials": [{...}, {...}]}
                if 'credentials' in cred_data and isinstance(cred_data['credentials'], list):
                    for cred in cred_data['credentials']:
                        if isinstance(cred, dict):
                            credential_manager.add_credential(
                                username=cred.get('username', ''),
                                password=cred.get('password', ''),
                                domain=cred.get('domain', ''),
                                service=cred.get('service', ''),
                                notes=cred.get('notes', ''),
                                source=cred.get('source', 'manual'),
                                credential_type=cred.get('credential_type', 'Username/Password')
                            )
        except ImportError:
            pass
    
    def update_inventory_with_profile_data(self, profile_data):
        """Update inventory page with profile data"""
        try:
            # Extract assets from profile data
            assets = []
            
            # Add primary targets
            primary_target = profile_data.get('primary_target', '') or profile_data.get('scope', '')
            if primary_target:
                for target in primary_target.split('\n'):
                    target = target.strip()
                    if target:
                        assets.append({
                            'target': target,
                            'type': 'Primary Target',
                            'source': 'Profile',
                            'status': 'Active'
                        })
            
            # Add subdomains
            subdomains = profile_data.get('subdomains', '')
            if subdomains:
                for subdomain in subdomains.split('\n'):
                    subdomain = subdomain.strip()
                    if subdomain:
                        assets.append({
                            'target': subdomain,
                            'type': 'Subdomain',
                            'source': 'Profile',
                            'status': 'Active'
                        })
            
            # Add cloud assets
            cloud_assets = profile_data.get('cloud_assets', '')
            if cloud_assets:
                for asset in cloud_assets.split('\n'):
                    asset = asset.strip()
                    if asset:
                        assets.append({
                            'target': asset,
                            'type': 'Cloud Asset',
                            'source': 'Profile',
                            'status': 'Active'
                        })
            
            # Update inventory if available
            if hasattr(self.main_window, 'inventory_page') and hasattr(self.main_window.inventory_page, 'add_assets_from_profile'):
                self.main_window.inventory_page.add_assets_from_profile(assets)
                
        except Exception:
            pass
    
    def refresh_credential_display(self):
        """Refresh credential display"""
        try:
            from app.core.credential_manager import credential_manager
            
            # Update credential table
            from PyQt6.QtWidgets import QTableWidgetItem
            
            self.cred_table.setRowCount(len(credential_manager.credentials))
            
            for i, cred in enumerate(credential_manager.credentials):
                source_icon = {
                    'manual': '👤 Manual',
                    'enumeration': '🔍 Enum', 
                    'exploitation': '💥 Exploit',
                    'scanned': '🔍 Scanned'
                }.get(cred.source, '❓ Unknown')
                
                self.cred_table.setItem(i, 0, QTableWidgetItem(source_icon))
                
                # Credential type
                cred_type = getattr(cred, 'credential_type', 'Username/Password')
                self.cred_table.setItem(i, 1, QTableWidgetItem(cred_type))
                
                # Username
                self.cred_table.setItem(i, 2, QTableWidgetItem(cred.username))
                
                # Password - check if should be shown
                if hasattr(self, 'show_passwords_cb') and self.show_passwords_cb.isChecked():
                    self.cred_table.setItem(i, 3, QTableWidgetItem(cred.password))
                else:
                    self.cred_table.setItem(i, 3, QTableWidgetItem('*' * len(cred.password)))
                
                self.cred_table.setItem(i, 4, QTableWidgetItem(cred.domain))
                self.cred_table.setItem(i, 5, QTableWidgetItem(cred.service))
                self.cred_table.setItem(i, 6, QTableWidgetItem(cred.notes))
            
            # Update summary
            summary = credential_manager.get_credential_summary()
            if hasattr(self, 'cred_summary'):
                self.cred_summary.setText(f"📊 {summary}")
                
        except ImportError:
            pass
    
    def update_scope_validation(self):
        """Update scope validation status display"""
        in_scope_text = self.primary_target.toPlainText().strip()
        out_scope_text = self.out_scope.toPlainText().strip() if hasattr(self, 'out_scope') else ""
        
        if not in_scope_text:
            self.scope_status.setText("⚠️ Scope: Not configured")
            self.scope_status.setStyleSheet("""
                QLabel {
                    background-color: rgba(255, 165, 0, 100);
                    border: 1px solid #FFA500;
                    border-radius: 5px;
                    padding: 8px 12px;
                    color: #FFFFFF;
                    font-size: 11pt;
                    font-weight: bold;
                }
            """)
            return
        
        # Parse and display scope summary
        import re
        targets = re.split(r'[,;\n\r\s]+', in_scope_text)
        domains = []
        ips = []
        networks = []
        
        for target in targets:
            target = target.strip()
            if not target:
                continue
            
            if '/' in target:  # Network
                networks.append(target)
            elif target.replace('.', '').isdigit() or ':' in target:  # IP
                ips.append(target)
            else:  # Domain
                domains.append(target)
        
        summary_parts = []
        if domains:
            summary_parts.append(f"Domains: {', '.join(domains[:3])}{'...' if len(domains) > 3 else ''}")
        if ips:
            summary_parts.append(f"IPs: {', '.join(ips[:3])}{'...' if len(ips) > 3 else ''}")
        if networks:
            summary_parts.append(f"Networks: {', '.join(networks[:2])}{'...' if len(networks) > 2 else ''}")
        
        summary = "; ".join(summary_parts) if summary_parts else "Configured"
        
        self.scope_status.setText(f"✅ Scope: {summary}")
        self.scope_status.setStyleSheet("""
            QLabel {
                background-color: rgba(50, 150, 50, 100);
                border: 1px solid #32CD32;
                border-radius: 5px;
                padding: 8px 12px;
                color: #FFFFFF;
                font-size: 11pt;
                font-weight: bold;
            }
        """)
        
        # Update global scope manager for validation
        try:
            from app.core.scope_manager import scope_manager
            scope_manager.update_scope(in_scope_text, out_scope_text)
        except ImportError:
            pass
    
    def trigger_tenant_change_updates(self, tenant_id):
        """Trigger real-time updates across all application components when tenant changes"""
        try:
            # Update inventory page
            if hasattr(self.main_window, 'inventory_page'):
                inventory_page = self.main_window.inventory_page
                if hasattr(inventory_page, 'tenant_id'):
                    inventory_page.tenant_id = tenant_id
                    inventory_page.load_assets()
            
            # Update centralized scan data components
            try:
                from app.core.centralized_scan_data import get_scan_data_manager
                scan_data_manager = get_scan_data_manager(tenant_id)
                # Trigger UI refresh for any active scan data displays
            except ImportError:
                pass
            
            # Update any real-time data updaters
            try:
                from app.core.realtime_data_updater import get_realtime_updater
                updater = get_realtime_updater(tenant_id)
                updater.refresh_all_components()
            except ImportError:
                pass
            
            # Update correlation dashboard if active
            try:
                if hasattr(self, 'correlations_tab'):
                    # Refresh correlation data for new tenant
                    pass
            except Exception:
                pass
            
            # Update any other tenant-specific components
            self.refresh_tenant_specific_data(tenant_id)
            
        except Exception as e:
            print(f"Error triggering tenant change updates: {e}")
    
    def refresh_tenant_specific_data(self, tenant_id):
        """Refresh all tenant-specific data displays"""
        try:
            # Refresh asset manager data
            from app.core.asset_manager import asset_manager
            # Force refresh of asset data for new tenant
            
            # Update any dashboard components
            if hasattr(self.main_window, 'dashboard_page'):
                dashboard = self.main_window.dashboard_page
                if hasattr(dashboard, 'refresh_for_tenant'):
                    dashboard.refresh_for_tenant(tenant_id)
            
            # Update scan history displays
            if hasattr(self.main_window, 'scan_history_components'):
                for component in self.main_window.scan_history_components:
                    if hasattr(component, 'refresh_for_tenant'):
                        component.refresh_for_tenant(tenant_id)
                        
        except Exception as e:
            print(f"Error refreshing tenant-specific data: {e}")
    
    def on_phase_selected(self, phase_name, phase_data):
        """Handle mindmap phase selection"""
        phase_mapping = {
            "SETUP": "scripts",
            "RECON": "recon_enumeration",
            "VULN": "vuln_scanning", 
            "EXPLOIT": "os_exploits",
            "POST-EX": "post_exploitation",
            "REPORT": "scripts"
        }
        
        target = phase_mapping.get(phase_name)
        if target:
            self.navigate_signal.emit(target)