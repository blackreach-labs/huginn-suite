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
from app.core.logger import logger
from app.core.engagement_manager import EngagementManager

# Resolve the project root relative to this file.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class AttackChainHomePage(BasePage):
    """Attack chain home page with Setup, Mindmap, and Correlations tabs"""
    
    def __init__(self, parent=None):
        self._engagement_mgr = None
        self.main_window = parent
        super().__init__(parent)
        self.setObjectName("AttackChainHomePage")

    @property
    def engagement_manager(self) -> EngagementManager:
        """Lazily get the EngagementManager from the feature gap integration engines."""
        if self._engagement_mgr is None:
            try:
                from app.core.feature_gap_integration import FeatureGapIntegration
                mgr = FeatureGapIntegration.engines.engagement_manager
                if mgr is not None:
                    self._engagement_mgr = mgr
            except Exception:
                pass
            if self._engagement_mgr is None:
                # Fallback: create a standalone instance (same default DB)
                self._engagement_mgr = EngagementManager()
        return self._engagement_mgr

    def showEvent(self, event):
        """Refresh the engagements table whenever this page becomes visible."""
        super().showEvent(event)
        if hasattr(self, 'target_table'):
            self.load_existing_profiles()
    
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
        
        main_layout.addWidget(self.main_tabs)
    
    def create_setup_tab(self):
        """Create the Setup tab with Target Profiles and Credential Management subtabs"""
        setup_widget = QWidget()
        setup_layout = QVBoxLayout(setup_widget)
        
        # Create subtab widget
        setup_subtabs = QTabWidget()
        
        # Target Profiles subtab
        target_profiles_tab = self.create_target_profiles_tab()
        setup_subtabs.addTab(target_profiles_tab, "🎯 Engagements")
        
        # Credential Management subtab
        credential_mgmt_tab = self.create_credential_management_tab()
        setup_subtabs.addTab(credential_mgmt_tab, "🔑 Credential Management")
        
        setup_layout.addWidget(setup_subtabs)
        return setup_widget
    
    def create_target_profiles_tab(self):
        """Create the Target Profiles subtab"""
        from PyQt6.QtWidgets import QGridLayout, QSplitter
        from PyQt6.QtCore import Qt

        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        # ── Form frame ───────────────────────────────────────────────────────
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
        form_layout.setSpacing(0)

        FIELD_HEIGHT = 30
        LABEL_STYLE  = "font-size: 10pt; font-weight: bold; color: #DCDCDC;"
        HDR_STYLE    = ("font-size: 10pt; font-weight: bold; color: #64C8FF;"
                        " padding: 8px 0px 4px 0px;")

        def hdr(text):
            l = QLabel(text)
            l.setStyleSheet(HDR_STYLE)
            return l

        def lbl(text):
            l = QLabel(text)
            l.setStyleSheet(LABEL_STYLE)
            return l

        def line(placeholder):
            w = QLineEdit()
            w.setPlaceholderText(placeholder)
            w.setFixedHeight(FIELD_HEIGHT)
            w.setStyleSheet("font-size: 10pt; color: #DCDCDC;")
            return w

        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(6)
        grid.setColumnStretch(1, 1)

        r = 0

        # ── Primary fields ───────────────────────────────────────────────────
        grid.addWidget(hdr("📋 Target Information"), r, 0, 1, 2); r += 1

        grid.addWidget(lbl("Target Name:"), r, 0)
        self.target_name = line("e.g., Company XYZ")
        grid.addWidget(self.target_name, r, 1); r += 1

        grid.addWidget(lbl("In-Scope Targets:"), r, 0)
        self.primary_target = line("Domains, IPs, networks (e.g., example.com, 192.168.1.0/24)")
        self.primary_target.textChanged.connect(self.update_scope_validation)
        grid.addWidget(self.primary_target, r, 1); r += 1

        grid.addWidget(lbl("Out of Scope:"), r, 0)
        self.out_scope = line("Excluded targets, IPs, domains")
        self.out_scope.textChanged.connect(self.update_scope_validation)
        grid.addWidget(self.out_scope, r, 1); r += 1

        # ── Secondary fields ─────────────────────────────────────────────────
        grid.addWidget(hdr("🔍 Additional Scope Details"), r, 0, 1, 2); r += 1

        grid.addWidget(lbl("Known Subdomains:"), r, 0)
        self.subdomains = line("e.g., api.example.com, staging.example.com")
        grid.addWidget(self.subdomains, r, 1); r += 1

        grid.addWidget(lbl("Cloud Assets:"), r, 0)
        self.cloud_assets = line("e.g., s3://bucket-name, Azure VM IPs")
        grid.addWidget(self.cloud_assets, r, 1); r += 1

        grid.addWidget(lbl("Restrictions / Notes:"), r, 0)
        self.restrictions = line("Special restrictions or notes")
        grid.addWidget(self.restrictions, r, 1); r += 1

        # ── Permissions row ──────────────────────────────────────────────────
        grid.addWidget(hdr("🛡 Testing Permissions:"), r, 0)

        perm_row = QHBoxLayout()
        perm_row.setSpacing(20)
        perm_row.setContentsMargins(0, 0, 0, 0)
        self.dos_allowed = QCheckBox("DoS Attacks")
        self.dos_allowed.setStyleSheet(LABEL_STYLE)
        self.social_eng_allowed = QCheckBox("Social Engineering")
        self.social_eng_allowed.setStyleSheet(LABEL_STYLE)
        self.physical_allowed = QCheckBox("Physical Access")
        self.physical_allowed.setStyleSheet(LABEL_STYLE)
        perm_row.addWidget(self.dos_allowed)
        perm_row.addWidget(self.social_eng_allowed)
        perm_row.addWidget(self.physical_allowed)
        perm_row.addStretch()

        perm_widget = QWidget()
        perm_widget.setLayout(perm_row)
        perm_widget.setFixedHeight(FIELD_HEIGHT)
        grid.addWidget(perm_widget, r, 1); r += 1

        form_layout.addLayout(grid)
        form_layout.addStretch()

        # ── Scope status badge (full width, below fields) ────────────────────
        self.scope_status = QLabel("Scope: Not configured")
        self.scope_status.setStyleSheet("""
            QLabel {
                background-color: rgba(255, 165, 0, 100);
                border: 1px solid #FFA500;
                border-radius: 5px;
                padding: 5px 12px;
                color: #FFFFFF;
                font-size: 10pt;
                font-weight: bold;
                margin-top: 8px;
            }
        """)
        form_layout.addWidget(self.scope_status)

        from PyQt6.QtWidgets import QSizePolicy
        form_frame.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        layout.addWidget(form_frame, stretch=1)

        # ── Buttons below form, above table ──────────────────────────────────
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(8)

        add_btn = QPushButton("💾 Save Engagement")
        add_btn.setStyleSheet(self.get_button_style("#64C8FF", "#000000"))
        add_btn.clicked.connect(self.save_current_profile)
        btn_layout.addWidget(add_btn)

        delete_btn = QPushButton("🗑 Delete")
        delete_btn.setStyleSheet(self.get_button_style("#FF4444", "#FFFFFF"))
        delete_btn.clicked.connect(self.delete_selected_profile)
        btn_layout.addWidget(delete_btn)

        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        # ── Engagements summary table ────────────────────────────────────────────
        list_label = QLabel("📋 Engagements:")
        list_label.setStyleSheet("font-weight: bold; color: #64C8FF; margin-top: 4px;")
        layout.addWidget(list_label)

        self.target_table = QTableWidget()
        self.target_table.setColumnCount(5)
        self.target_table.setHorizontalHeaderLabels(
            ["Engagement Name", "In-Scope Targets", "Credentials", "Permissions", "Status"])
        self.target_table.setMinimumHeight(300)
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

        header = self.target_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)

        self.target_table.itemSelectionChanged.connect(self.on_profile_selected)
        layout.addWidget(self.target_table, stretch=1)

        # ── Autosave connections ──────────────────────────────────────────────
        self.target_name.textChanged.connect(self._autosave_current_profile)
        self.primary_target.textChanged.connect(self._autosave_current_profile)
        self.subdomains.textChanged.connect(self._autosave_current_profile)
        self.cloud_assets.textChanged.connect(self._autosave_current_profile)
        self.out_scope.textChanged.connect(self._autosave_current_profile)
        self.restrictions.textChanged.connect(self._autosave_current_profile)
        self.dos_allowed.stateChanged.connect(self._autosave_current_profile)
        self.social_eng_allowed.stateChanged.connect(self._autosave_current_profile)
        self.physical_allowed.stateChanged.connect(self._autosave_current_profile)

        self._loading_profile = False
        self.load_existing_profiles()

        return widget
    
    def create_credential_management_tab(self):
        """Create the Credential Management subtab — embeds SecureCredentialWidget."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(0)

        try:
            from app.widgets.secure_credential_widget import SecureCredentialWidget
            self.secure_cred_widget = SecureCredentialWidget()
            layout.addWidget(self.secure_cred_widget)
        except Exception as e:
            logger.error(f"Failed to load SecureCredentialWidget: {e}")
            # Fallback: keep the original inline implementation
            self._build_inline_credential_tab(layout)

        return widget

    def _build_inline_credential_tab(self, layout):
        """Fallback inline credential tab (used if SecureCredentialWidget unavailable)."""
        from PyQt6.QtWidgets import QFrame
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

        self.create_credential_fields(form_layout)
        form_layout.addStretch()

        btn_layout = QHBoxLayout()
        add_cred_btn = QPushButton("Add Credential")
        add_cred_btn.setStyleSheet(self.get_button_style("#64C8FF", "#000000"))
        add_cred_btn.clicked.connect(self.add_credential)
        btn_layout.addWidget(add_cred_btn)

        delete_cred_btn = QPushButton("Delete Selected")
        delete_cred_btn.setStyleSheet(self.get_button_style("#FF6347"))
        delete_cred_btn.clicked.connect(self.delete_selected_credential)
        btn_layout.addWidget(delete_cred_btn)
        btn_layout.addStretch()
        form_layout.addLayout(btn_layout)

        layout.addWidget(form_frame)

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
        self.cred_table.setHorizontalHeaderLabels(
            ["Source", "Type", "Username", "Password", "Domain", "Service", "Notes"])
        self.cred_table.setMaximumHeight(200)
        self.cred_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.cred_table.setStyleSheet("""
            QTableWidget {
                background-color: rgba(20, 30, 40, 150);
                border: 1px solid rgba(100, 200, 255, 50);
                border-radius: 5px; color: #DCDCDC;
                gridline-color: rgba(100, 200, 255, 50); font-size: 9pt;
            }
            QHeaderView::section {
                background-color: rgba(100, 200, 255, 100);
                color: #000000; font-weight: bold; padding: 3px; border: none;
            }
        """)
        hdr = self.cred_table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.cred_table)

        self.on_credential_type_changed("Username/Password")
        self.refresh_credential_display()
    
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
            "REPORTING & TOOLS": "attack_chain_home",
            "REPORT": "attack_chain_home"
        }
        return phase_mapping.get(phase_name, "attack_chain_home")
    
    def create_report_tab(self):
        """Create the Report tab containing Remediation, Dashboard, and Analytics subtabs."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)

        report_subtabs = QTabWidget()

        self.remediation_tab = self.create_remediation_tab()
        report_subtabs.addTab(self.remediation_tab, "🛠️ Remediation")

        self.dashboard_tab = self.create_dashboard_tab()
        report_subtabs.addTab(self.dashboard_tab, "🛡️ Dashboard")

        self.analytics_tab = self.create_analytics_tab()
        report_subtabs.addTab(self.analytics_tab, "🔬 Analytics")

        layout.addWidget(report_subtabs)
        return widget

    def create_correlations_tab(self):
        """Create the Correlations tab"""
        try:
            from app.widgets.correlation_dashboard_widget import CorrelationDashboardWidget
            tenant_id = getattr(self.main_window, 'current_engagement_id', None) or getattr(self.main_window, 'current_profile_name', 'default')
            return CorrelationDashboardWidget(tenant_id)
        except ImportError:
            placeholder = QLabel("🔗 Cross-Scan Correlations Dashboard\n(Vulnerability correlation and analysis)")
            placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
            placeholder.setStyleSheet("color: #DCDCDC; padding: 20px; font-size: 14pt;")
            return placeholder
    
    def create_remediation_tab(self):
        """Create the Remediation tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Try to create remediation widget
        try:
            from app.widgets.remediation_widget import RemediationWidget
            tenant_id = getattr(self.main_window, 'current_engagement_id', None) or getattr(self.main_window, 'current_profile_name', 'default')
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
            tenant_id = getattr(self.main_window, 'current_engagement_id', None) or getattr(self.main_window, 'current_profile_name', 'default')
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
            tenant_id = getattr(self.main_window, 'current_engagement_id', None) or getattr(self.main_window, 'current_profile_name', 'default')
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
        """Create all credential form fields in a compact single-column layout."""
        from PyQt6.QtWidgets import QGridLayout

        FIELD_HEIGHT = 30
        LABEL_STYLE = "font-size: 10pt; font-weight: bold; color: #DCDCDC;"

        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(6)

        def make_label(text):
            lbl = QLabel(text)
            lbl.setStyleSheet(LABEL_STYLE)
            return lbl

        def make_line(placeholder, echo=False):
            le = QLineEdit()
            le.setPlaceholderText(placeholder)
            le.setFixedHeight(FIELD_HEIGHT)
            le.setStyleSheet("font-size: 10pt; color: #DCDCDC;")
            if echo:
                le.setEchoMode(QLineEdit.EchoMode.Password)
            return le

        # ── Type dropdown — row 0, always visible ───────────────────────────
        type_lbl = QLabel("Type:")
        type_lbl.setStyleSheet("font-size: 10pt; font-weight: bold; color: #64C8FF;")
        grid.addWidget(type_lbl, 0, 0)

        self.type_combo = QComboBox()
        self.type_combo.addItems(["Username/Password", "NTLM Hash", "Kerberos Ticket",
                                  "SQL Server Auth", "Windows Auth", "API Key", "Contacts"])
        self.type_combo.setFixedHeight(FIELD_HEIGHT)
        self.type_combo.setStyleSheet("font-size: 10pt;")
        self.type_combo.currentTextChanged.connect(self.on_credential_type_changed)
        grid.addWidget(self.type_combo, 0, 1)

        # ── Username/Password + NTLM + Kerberos shared fields ──────────────
        self.username_label   = make_label("Username:")
        self.username         = make_line("Enter username")

        self.password_label   = make_label("Password:")
        self.password         = make_line("Enter password", echo=True)

        self.ntlm_hash_label  = make_label("NTLM Hash:")
        self.ntlm_hash        = make_line("Enter NTLM hash", echo=True)

        self.ticket_file_label = make_label("Ticket File:")
        self.ticket_file      = make_line("Path to ticket file")

        self.domain_label     = make_label("Domain:")
        self.domain           = make_line("e.g., DOMAIN or leave blank")

        self.service_label    = make_label("Service:")
        self.service          = make_line("e.g., SSH, RDP, SMB, HTTP")

        self.notes_label      = make_label("Notes:")
        self.notes            = make_line("Optional notes")

        # ── API Key fields ──────────────────────────────────────────────────
        self.api_key_name_label  = make_label("Key Name:")
        self.api_key_name        = make_line("e.g., Shodan, VirusTotal")

        self.api_key_value_label = make_label("API Key:")
        self.api_key_value       = make_line("Enter API key", echo=True)

        # ── Contacts fields ─────────────────────────────────────────────────
        self.account_name_label  = make_label("Account Name:")
        self.account_name        = make_line("e.g., jdoe, admin")

        self.first_name_label    = make_label("First Name:")
        self.first_name          = make_line("First name")

        self.middle_name_label   = make_label("Middle Name:")
        self.middle_name         = make_line("Middle name (optional)")

        self.last_name_label     = make_label("Last Name:")
        self.last_name           = make_line("Last name")

        self.email_address_label = make_label("Email Address:")
        self.email_address       = make_line("e.g., john.doe@company.com")

        self.mobile_phone_label  = make_label("Mobile Phone:")
        self.mobile_phone        = make_line("e.g., +1-555-123-4567")

        self.address_label       = make_label("Address:")
        self.address             = make_line("Physical address (optional)")

        # ── Single column layout: label in col 0, field in col 1 ────────────
        fields = [
            (self.username_label,    self.username),
            (self.password_label,    self.password),
            (self.ntlm_hash_label,   self.ntlm_hash),
            (self.ticket_file_label, self.ticket_file),
            (self.domain_label,      self.domain),
            (self.service_label,     self.service),
            (self.notes_label,       self.notes),
            (self.api_key_name_label, self.api_key_name),
            (self.api_key_value_label, self.api_key_value),
            (self.account_name_label,self.account_name),
            (self.first_name_label,  self.first_name),
            (self.middle_name_label, self.middle_name),
            (self.last_name_label,   self.last_name),
            (self.email_address_label,self.email_address),
            (self.mobile_phone_label,self.mobile_phone),
            (self.address_label,     self.address),
        ]

        for r, (label, field) in enumerate(fields):
            grid.addWidget(label, r + 1, 0)
            grid.addWidget(field, r + 1, 1)

        grid.setColumnStretch(1, 1)

        layout.addLayout(grid)
    
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
            (self.api_key_name_label, self.api_key_name),
            (self.api_key_value_label, self.api_key_value),
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
        elif credential_type == "API Key":
            for label, field in [(self.api_key_name_label, self.api_key_name), (self.api_key_value_label, self.api_key_value),
                               (self.service_label, self.service), (self.notes_label, self.notes)]:
                label.setVisible(True)
                field.setVisible(True)
        elif credential_type == "Contacts":
            for label, field in [(self.account_name_label, self.account_name), (self.first_name_label, self.first_name),
                               (self.middle_name_label, self.middle_name), (self.last_name_label, self.last_name),
                               (self.email_address_label, self.email_address), (self.mobile_phone_label, self.mobile_phone),
                               (self.address_label, self.address), (self.notes_label, self.notes)]:
                label.setVisible(True)
                field.setVisible(True)
    
    def save_current_profile(self):
        """Save the current form data into the engagement (create or update)."""
        name = self.target_name.text().strip()
        target = self.primary_target.text().strip()

        if not name:
            QMessageBox.warning(self, "No Engagement Name", "Please enter a Target Name before saving.")
            return

        scope_data = {
            'primary_target': target,
            'out_scope': self.out_scope.text(),
            'subdomains': self.subdomains.text(),
            'cloud_assets': self.cloud_assets.text(),
            'restrictions': self.restrictions.text(),
            'dos_allowed': self.dos_allowed.isChecked(),
            'social_eng_allowed': self.social_eng_allowed.isChecked(),
            'physical_allowed': self.physical_allowed.isChecked(),
        }

        mgr = self.engagement_manager

        # Check if this engagement already exists
        existing = mgr.find_by_name(name)
        if existing:
            # Update existing engagement's scope data
            mgr.update_scope_data(existing["id"], scope_data)
            engagement_id = existing["id"]
        else:
            # Create a new engagement
            profile_data = dict(scope_data)
            profile_data['target_name'] = name
            engagement_id = mgr.create_from_profile(profile_data)

        # Open the engagement so its DB is active
        mgr.open_engagement(engagement_id)

        # Update main window state
        if hasattr(self.main_window, 'current_engagement_id'):
            self.main_window.current_engagement_id = engagement_id
        else:
            setattr(self.main_window, 'current_engagement_id', engagement_id)
        # Keep legacy attribute in sync
        self.main_window.current_profile_name = name

        # Save credentials for this engagement
        try:
            from app.core.credential_manager import credential_manager
            credential_manager.set_profile(engagement_id)
            credential_manager.save_to_profile_json()
        except Exception as e:
            logger.debug(f"Credential save during engagement save: {e}")

        # Refresh the table
        self.load_existing_profiles()

        # Re-select the saved engagement row
        for row in range(self.target_table.rowCount()):
            item = self.target_table.item(row, 0)
            if item and item.text() == name:
                self.target_table.selectRow(row)
                break
    
    def on_profile_selected(self):
        """Handle engagement selection from table — opens the engagement."""
        current_row = self.target_table.currentRow()
        if current_row >= 0:
            name_item = self.target_table.item(current_row, 0)

            if name_item:
                engagement_name = name_item.text()

                # Suppress autosave while we populate the form
                self._loading_profile = True
                try:
                    mgr = self.engagement_manager
                    engagement = mgr.find_by_name(engagement_name)
                    if not engagement:
                        # Engagement not found — might be legacy; just set the name
                        self.target_name.setText(engagement_name)
                        self.update_scope_validation()
                        return

                    engagement_id = engagement["id"]

                    # Open the engagement (connects its isolated DB)
                    mgr.open_engagement(engagement_id)

                    # Update main window state
                    self.main_window.current_profile_name = engagement_name
                    if hasattr(self.main_window, 'current_engagement_id'):
                        self.main_window.current_engagement_id = engagement_id
                    else:
                        setattr(self.main_window, 'current_engagement_id', engagement_id)

                    # Switch credential manager to this engagement
                    try:
                        from app.core.credential_manager import credential_manager
                        credential_manager.set_profile(engagement_id)
                    except Exception as _exc:
                        logger.debug(f"Credential switch on engagement select: {_exc}")

                    # Trigger tenant change via tenant-aware updater
                    try:
                        from app.core.tenant_aware_updater import tenant_aware_updater
                        tenant_aware_updater.set_tenant(engagement_id)
                    except ImportError:
                        pass

                    # Populate form from engagement scope_data
                    scope = engagement.get("scope_data") or {}
                    self.target_name.setText(engagement.get("name", engagement_name))
                    self.primary_target.setText(scope.get("primary_target", ""))
                    self.subdomains.setText(scope.get("subdomains", ""))
                    self.cloud_assets.setText(scope.get("cloud_assets", ""))
                    self.out_scope.setText(scope.get("out_scope", ""))
                    self.restrictions.setText(scope.get("restrictions", ""))
                    self.dos_allowed.setChecked(scope.get("dos_allowed", False))
                    self.social_eng_allowed.setChecked(scope.get("social_eng_allowed", False))
                    self.physical_allowed.setChecked(scope.get("physical_allowed", False))

                    # Refresh credential display
                    self.refresh_credential_display()

                    # Update scope validation
                    self.update_scope_validation()
                finally:
                    self._loading_profile = False
    
    def save_profile(self):
        """Save current engagement — alias for save_current_profile with a name prompt."""
        from PyQt6.QtWidgets import QInputDialog

        profile_name, ok = QInputDialog.getText(self, 'Save Engagement', 'Enter engagement name:')
        if not ok or not profile_name.strip():
            return

        # Set the name in the form and delegate to save_current_profile
        self._loading_profile = True
        try:
            self.target_name.setText(profile_name.strip())
        finally:
            self._loading_profile = False
        self.save_current_profile()

    def new_profile(self):
        """Create a new blank engagement."""
        from PyQt6.QtWidgets import QInputDialog

        engagement_name, ok = QInputDialog.getText(self, 'New Engagement', 'Enter new engagement name:')
        if not ok or not engagement_name.strip():
            return

        engagement_name = engagement_name.strip()

        # Check if engagement already exists
        mgr = self.engagement_manager
        existing = mgr.find_by_name(engagement_name)
        if existing:
            QMessageBox.warning(self, "Engagement Exists", f"Engagement '{engagement_name}' already exists.")
            return

        # Suppress autosave while clearing the form
        self._loading_profile = True
        try:
            self.target_name.clear()
            self.primary_target.clear()
            self.subdomains.clear()
            self.cloud_assets.clear()
            self.out_scope.clear()
            self.restrictions.clear()
            self.dos_allowed.setChecked(False)
            self.social_eng_allowed.setChecked(False)
            self.physical_allowed.setChecked(False)
        finally:
            self._loading_profile = False

        # Create engagement in the DB
        engagement_id = mgr.create_from_profile({'target_name': engagement_name})
        mgr.open_engagement(engagement_id)

        # Set credential manager to new engagement
        try:
            from app.core.credential_manager import credential_manager
            credential_manager.set_profile(engagement_id)
            self.refresh_credential_display()
        except Exception as _exc:
            logger.debug(f"Credential switch on new engagement: {_exc}")

        # Refresh table and select the new engagement
        self.load_existing_profiles()
        for row in range(self.target_table.rowCount()):
            item = self.target_table.item(row, 0)
            if item and item.text() == engagement_name:
                self.target_table.selectRow(row)
                break

        # Set as current engagement
        self.main_window.current_profile_name = engagement_name
        if hasattr(self.main_window, 'current_engagement_id'):
            self.main_window.current_engagement_id = engagement_id
        else:
            setattr(self.main_window, 'current_engagement_id', engagement_id)

        # Trigger tenant change
        try:
            from app.core.tenant_aware_updater import tenant_aware_updater
            tenant_aware_updater.set_tenant(engagement_id)
        except Exception:
            pass

        self.update_scope_validation()
    
    def load_profile(self):
        """Show a list of engagements and open the selected one."""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QListWidget, QDialogButtonBox, QLabel

        mgr = self.engagement_manager
        engagements = mgr.list_engagements()

        if not engagements:
            QMessageBox.information(self, 'No Engagements', 'No saved engagements found.')
            return

        # Build a simple list-picker dialog
        dialog = QDialog(self)
        dialog.setWindowTitle('📁 Load Engagement')
        dialog.setModal(True)
        dialog.resize(400, 300)
        dlg_layout = QVBoxLayout(dialog)

        dlg_layout.addWidget(QLabel('Select an engagement to load:'))

        list_widget = QListWidget()
        for eng in engagements:
            list_widget.addItem(eng["name"])
        list_widget.setCurrentRow(0)
        dlg_layout.addWidget(list_widget)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        dlg_layout.addWidget(buttons)

        list_widget.itemDoubleClicked.connect(lambda _: dialog.accept())

        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        selected = list_widget.currentItem()
        if not selected:
            return

        engagement_name = selected.text()
        engagement = mgr.find_by_name(engagement_name)
        if not engagement:
            QMessageBox.warning(self, 'Error', f'Engagement "{engagement_name}" not found in database.')
            return

        engagement_id = engagement["id"]

        # Guard autosave while we populate the form
        self._loading_profile = True
        try:
            # Open engagement
            mgr.open_engagement(engagement_id)

            # Populate form from scope_data
            scope = engagement.get("scope_data") or {}
            self.target_name.setText(engagement.get("name", engagement_name))
            self.primary_target.setText(scope.get("primary_target", ""))
            self.subdomains.setText(scope.get("subdomains", ""))
            self.cloud_assets.setText(scope.get("cloud_assets", ""))
            self.out_scope.setText(scope.get("out_scope", ""))
            self.restrictions.setText(scope.get("restrictions", ""))
            self.dos_allowed.setChecked(scope.get("dos_allowed", False))
            self.social_eng_allowed.setChecked(scope.get("social_eng_allowed", False))
            self.physical_allowed.setChecked(scope.get("physical_allowed", False))

            # Switch credential manager
            try:
                from app.core.credential_manager import credential_manager
                credential_manager.set_profile(engagement_id)
            except Exception as cred_err:
                logger.warning(f"Could not load credentials for engagement '{engagement_name}': {cred_err}")

            # Rebuild table and select matching row
            self.load_existing_profiles()
            for row in range(self.target_table.rowCount()):
                item = self.target_table.item(row, 0)
                if item and item.text() == engagement_name:
                    self.target_table.blockSignals(True)
                    self.target_table.selectRow(row)
                    self.target_table.blockSignals(False)
                    break

            # Update tenant
            try:
                from app.core.tenant_aware_updater import tenant_aware_updater
                tenant_aware_updater.set_tenant(engagement_id)
            except Exception:
                pass

            self.main_window.current_profile_name = engagement_name
            if hasattr(self.main_window, 'current_engagement_id'):
                self.main_window.current_engagement_id = engagement_id
            else:
                setattr(self.main_window, 'current_engagement_id', engagement_id)

            self.refresh_credential_display()
            self.update_scope_validation()

        except Exception as e:
            logger.error(f"Unexpected error while opening engagement '{engagement_name}': {e}", exc_info=True)
            QMessageBox.warning(self, 'Error', f'Failed to load engagement: {str(e)}')
        finally:
            self._loading_profile = False

    def _autosave_current_profile(self):
        """Silently save scope data to the active engagement whenever a form field changes."""
        if getattr(self, '_loading_profile', False):
            return

        # Determine the active engagement from the selected table row
        current_row = self.target_table.currentRow()
        if current_row < 0:
            return
        name_item = self.target_table.item(current_row, 0)
        if not name_item:
            return
        engagement_name = name_item.text().strip()
        if not engagement_name:
            return

        mgr = self.engagement_manager
        engagement = mgr.find_by_name(engagement_name)
        if not engagement:
            return

        scope_data = {
            'primary_target': self.primary_target.text(),
            'out_scope': self.out_scope.text(),
            'subdomains': self.subdomains.text(),
            'cloud_assets': self.cloud_assets.text(),
            'restrictions': self.restrictions.text(),
            'dos_allowed': self.dos_allowed.isChecked(),
            'social_eng_allowed': self.social_eng_allowed.isChecked(),
            'physical_allowed': self.physical_allowed.isChecked(),
        }

        try:
            mgr.update_scope_data(engagement["id"], scope_data)
        except Exception as e:
            logger.debug(f"Autosave failed for engagement '{engagement_name}': {e}")
    
    def _delete_engagement_by_name(self, engagement_name: str):
        """Delete an engagement and its associated data by name."""
        mgr = self.engagement_manager
        engagement = mgr.find_by_name(engagement_name)
        if engagement:
            engagement_id = engagement["id"]
            # delete_engagement() removes the entire engagement directory
            # (including credentials.enc) and the master index entry
            mgr.delete_engagement(engagement_id)

        # Clear from credential manager if this was the active engagement
        try:
            from app.core.credential_manager import credential_manager
            active_id = getattr(self.main_window, 'current_engagement_id', None)
            if engagement and active_id == engagement.get("id"):
                credential_manager.credentials.clear()
                credential_manager.current_profile = "default"
                credential_manager._explicit_profile = None
        except Exception:
            pass

    def delete_selected_profile(self):
        """Delete the selected engagement from table and database."""
        current_row = self.target_table.currentRow()
        if current_row >= 0:
            name_item = self.target_table.item(current_row, 0)
            if name_item:
                engagement_name = name_item.text()
                reply = QMessageBox.question(
                    self, "Delete Engagement",
                    f"Delete engagement '{engagement_name}' permanently?\n\nThis will remove all associated data.",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                )
                if reply == QMessageBox.StandardButton.Yes:
                    self.target_table.removeRow(current_row)
                    self._delete_engagement_by_name(engagement_name)
        else:
            QMessageBox.information(self, "No Selection", "Please select an engagement to delete.")

    def delete_profile_dialog(self):
        """Show a list of all engagements and delete the one the user selects."""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QListWidget, QDialogButtonBox, QLabel

        mgr = self.engagement_manager
        engagements = mgr.list_engagements()

        if not engagements:
            QMessageBox.information(self, 'No Engagements', 'No saved engagements found.')
            return

        dialog = QDialog(self)
        dialog.setWindowTitle('🗑 Delete Engagement')
        dialog.setModal(True)
        dialog.resize(400, 300)
        dlg_layout = QVBoxLayout(dialog)

        dlg_layout.addWidget(QLabel('Select an engagement to delete:'))

        list_widget = QListWidget()
        for eng in engagements:
            list_widget.addItem(eng["name"])
        list_widget.setCurrentRow(0)
        dlg_layout.addWidget(list_widget)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText('Delete')
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        dlg_layout.addWidget(buttons)

        list_widget.itemDoubleClicked.connect(lambda _: dialog.accept())

        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        selected = list_widget.currentItem()
        if not selected:
            return

        engagement_name = selected.text()
        reply = QMessageBox.question(
            self, 'Confirm Delete',
            f"Delete engagement '{engagement_name}' permanently?\n\nThis cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        self._delete_engagement_by_name(engagement_name)

        # Remove from the table if present
        for row in range(self.target_table.rowCount()):
            item = self.target_table.item(row, 0)
            if item and item.text() == engagement_name:
                self.target_table.removeRow(row)
                break

        # Clear the form if the deleted engagement was active
        active = getattr(self.main_window, 'current_profile_name', None)
        if active == engagement_name:
            self.main_window.current_profile_name = None
            if hasattr(self.main_window, 'current_engagement_id'):
                self.main_window.current_engagement_id = None
            self._loading_profile = True
            try:
                self.target_name.clear()
                self.primary_target.clear()
                self.subdomains.clear()
                self.cloud_assets.clear()
                self.out_scope.clear()
                self.restrictions.clear()
                self.dos_allowed.setChecked(False)
                self.social_eng_allowed.setChecked(False)
                self.physical_allowed.setChecked(False)
            finally:
                self._loading_profile = False
    
    def load_existing_profiles(self):
        """Load existing engagements from the engagement database into the table."""
        mgr = self.engagement_manager
        engagements = mgr.list_engagements()

        # Block signals so inserting rows doesn't fire on_profile_selected
        self.target_table.blockSignals(True)
        try:
            self.target_table.setRowCount(0)

            for eng in engagements:
                scope = eng.get("scope_data") or {}

                # In-Scope Targets — first line only, truncated
                target = scope.get("primary_target", "")
                first_line = target.strip().splitlines()[0] if target.strip() else "—"
                if len(first_line) > 40:
                    first_line = first_line[:38] + "…"

                # Credentials count (not stored in engagement DB; show "—")
                cred_count = "—"

                # Permissions
                perms = []
                if scope.get("dos_allowed"):
                    perms.append("DoS")
                if scope.get("social_eng_allowed"):
                    perms.append("Social")
                if scope.get("physical_allowed"):
                    perms.append("Physical")
                permissions = ", ".join(perms) if perms else "—"

                # Status from engagement state
                status = eng.get("status", "draft").capitalize()

                row = self.target_table.rowCount()
                self.target_table.insertRow(row)
                self.target_table.setItem(row, 0, QTableWidgetItem(eng["name"]))
                self.target_table.setItem(row, 1, QTableWidgetItem(first_line))
                self.target_table.setItem(row, 2, QTableWidgetItem(cred_count))
                self.target_table.setItem(row, 3, QTableWidgetItem(permissions))
                self.target_table.setItem(row, 4, QTableWidgetItem(status))
        finally:
            self.target_table.blockSignals(False)

        # Restore the last active engagement row
        active_id = getattr(self.main_window, 'current_engagement_id', None)
        if active_id:
            active_eng = mgr.get_engagement(active_id)
            if active_eng:
                for row in range(self.target_table.rowCount()):
                    item = self.target_table.item(row, 0)
                    if item and item.text() == active_eng["name"]:
                        self.target_table.blockSignals(True)
                        self.target_table.selectRow(row)
                        self.target_table.blockSignals(False)
                        break
    
    def add_profile_to_table(self, profile_name, profile_data):
        """Add or select an engagement in the table by name."""
        for row in range(self.target_table.rowCount()):
            name_item = self.target_table.item(row, 0)
            if name_item and name_item.text() == profile_name:
                self.target_table.selectRow(row)
                return

        # Not present — refresh the whole table then select the new row
        self.load_existing_profiles()
        for row in range(self.target_table.rowCount()):
            name_item = self.target_table.item(row, 0)
            if name_item and name_item.text() == profile_name:
                self.target_table.selectRow(row)
                return
    
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
            
            elif credential_type == "API Key":
                key_name = self.api_key_name.text().strip()
                key_value = self.api_key_value.text().strip()
                
                if not key_name or not key_value:
                    return
                
                credential_manager.add_credential(
                    username=key_name, password=key_value, domain="",
                    service=service or key_name, notes=notes, source="manual", credential_type=credential_type
                )
                self.api_key_name.clear()
                self.api_key_value.clear()
            
            self.service.clear()
            self.notes.clear()
            self.refresh_credential_display()
            
        except ImportError as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
    
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
        except ImportError as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
    
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
        except ImportError as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
    
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
        except ImportError as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
    
    def load_credentials_from_profile(self, cred_data):
        """Load credentials from profile data.

        This only populates the in-memory list from the profile JSON's
        credential section — it does NOT save to disk.  The authoritative
        on-disk store is the encrypted .enc file, which set_profile() already
        loaded.  We only fall back to the JSON data when the .enc file has
        no credentials (e.g. first time a legacy profile is opened).
        """
        try:
            from app.core.credential_manager import credential_manager

            # If the .enc file already has credentials, trust it — don't
            # overwrite with potentially stale data from the profile JSON.
            if credential_manager.credentials:
                return

            if isinstance(cred_data, dict):
                if 'credentials' in cred_data and isinstance(cred_data['credentials'], list):
                    for cred in cred_data['credentials']:
                        if isinstance(cred, dict):
                            # Use from_dict directly to avoid triggering auto-save
                            from app.core.credential_manager import Credential
                            credential_manager.credentials.append(
                                Credential.from_dict(cred)
                            )
                    # Save once if we imported anything from the JSON
                    if credential_manager.credentials:
                        credential_manager.save_to_profile_json()
        except ImportError as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
    
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
                
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
    
    def refresh_credential_display(self):
        """Refresh credential display"""
        # If the new SecureCredentialWidget is active, delegate to it
        if hasattr(self, 'secure_cred_widget'):
            try:
                self.secure_cred_widget.refresh_credentials()
            except Exception as _exc:
                logger.debug("Suppressed exception", exc_info=True)
            return

        # Fallback: update the inline cred_table (only present when
        # SecureCredentialWidget failed to load)
        if not hasattr(self, 'cred_table'):
            return

        try:
            from app.core.credential_manager import credential_manager
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
                cred_type = getattr(cred, 'credential_type', 'Username/Password')
                self.cred_table.setItem(i, 1, QTableWidgetItem(cred_type))
                self.cred_table.setItem(i, 2, QTableWidgetItem(cred.username))

                if hasattr(self, 'show_passwords_cb') and self.show_passwords_cb.isChecked():
                    self.cred_table.setItem(i, 3, QTableWidgetItem(cred.password))
                else:
                    self.cred_table.setItem(i, 3, QTableWidgetItem('*' * len(cred.password)))

                self.cred_table.setItem(i, 4, QTableWidgetItem(cred.domain))
                self.cred_table.setItem(i, 5, QTableWidgetItem(cred.service))
                self.cred_table.setItem(i, 6, QTableWidgetItem(cred.notes))

            summary = credential_manager.get_credential_summary()
            if hasattr(self, 'cred_summary'):
                self.cred_summary.setText(f"📊 {summary}")

        except ImportError as _exc:
            logger.debug("Suppressed exception", exc_info=True)
    
    def update_scope_validation(self):
        """Update scope validation status display"""
        in_scope_text = self.primary_target.text().strip()
        out_scope_text = self.out_scope.text().strip() if hasattr(self, 'out_scope') else ""
        
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
        except ImportError as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
    
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
            except ImportError as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
            
            # Update any real-time data updaters
            try:
                from app.core.realtime_data_updater import get_realtime_updater
                updater = get_realtime_updater(tenant_id)
                updater.refresh_all_components()
            except ImportError as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
            
            # Update correlation dashboard if active
            try:
                if hasattr(self, 'correlations_tab'):
                    # Refresh correlation data for new tenant
                    pass
            except Exception as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
            
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
            "REPORT": "attack_chain_home"
        }
        
        target = phase_mapping.get(phase_name)
        if target:
            self.navigate_signal.emit(target)

        # When REPORT is clicked, also switch to the Report tab on the home page
        if phase_name == "REPORT":
            try:
                from app.core.page_manager import page_manager
                page = page_manager.get_page("attack_chain_home")
                if page and hasattr(page, 'main_tabs'):
                    for i in range(page.main_tabs.count()):
                        if "Report" in page.main_tabs.tabText(i):
                            page.main_tabs.setCurrentIndex(i)
                            break
            except Exception:
                pass