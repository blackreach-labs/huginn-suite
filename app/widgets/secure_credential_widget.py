# app/widgets/secure_credential_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                            QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
                            QComboBox, QTextEdit, QGroupBox, QTabWidget,
                            QMessageBox, QProgressBar, QCheckBox, QFormLayout,
                            QHeaderView, QFrame, QSizePolicy, QGridLayout,
                            QScrollArea, QStackedWidget)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QIcon
from ..core.secure_credential_manager import secure_credential_manager
from ..core.logger import logger

class CredentialTestWorker(QThread):
    """Worker thread for testing credentials"""
    test_completed = pyqtSignal(str, dict)
    
    def __init__(self, service):
        super().__init__()
        self.service = service
    
    def run(self):
        result = secure_credential_manager.test_credential(self.service)
        self.test_completed.emit(self.service, result)

class SecureCredentialWidget(QWidget):
    """Widget for managing secure credentials and API keys"""
    
    def __init__(self):
        super().__init__()
        self.test_workers = {}
        self.init_ui()
        self.connect_signals()
        self.refresh_credentials()
        self._load_sm_config()
    
    def init_ui(self):
        """Initialize the user interface"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Tab widget — no title bar above it
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)

        # Credentials tab
        self.credentials_tab = QWidget()
        self.init_credentials_tab()
        self.tab_widget.addTab(self.credentials_tab, "🔑 Credentials")

        # Security tab
        self.security_tab = QWidget()
        self.init_security_tab()
        self.tab_widget.addTab(self.security_tab, "🔒 Security")

        # Enterprise tab
        self.enterprise_tab = QWidget()
        self.init_enterprise_tab()
        self.tab_widget.addTab(self.enterprise_tab, "🏢 Enterprise")
    
    def init_credentials_tab(self):
        """Initialize credentials management tab — original compact style."""

        widget_layout = QVBoxLayout(self.credentials_tab)
        widget_layout.setContentsMargins(10, 10, 10, 10)
        widget_layout.setSpacing(8)

        FIELD_HEIGHT = 30
        LABEL_STYLE  = "font-size: 10pt; font-weight: bold; color: #DCDCDC;"
        HDR_STYLE    = ("font-size: 10pt; font-weight: bold; color: #64C8FF;"
                        " padding: 8px 0px 4px 0px;")

        # ── Form frame ────────────────────────────────────────────────────
        form_frame = QFrame()
        form_frame.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 150);
                border-radius: 10px;
                border: 1px solid rgba(100, 200, 255, 50);
            }
        """)
        form_frame.setSizePolicy(QSizePolicy.Policy.Expanding,
                                 QSizePolicy.Policy.Expanding)
        form_layout = QVBoxLayout(form_frame)
        form_layout.setContentsMargins(15, 15, 15, 15)
        form_layout.setSpacing(0)

        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(6)
        grid.setColumnStretch(1, 1)

        def hdr(text):
            l = QLabel(text); l.setStyleSheet(HDR_STYLE); return l

        def lbl(text):
            l = QLabel(text); l.setStyleSheet(LABEL_STYLE); return l

        def field(placeholder, echo=False):
            w = QLineEdit()
            w.setPlaceholderText(placeholder)
            w.setFixedHeight(FIELD_HEIGHT)
            w.setStyleSheet("font-size: 10pt; color: #DCDCDC;")
            if echo:
                w.setEchoMode(QLineEdit.EchoMode.Password)
            return w

        r = 0
        # Type header + dropdown
        grid.addWidget(hdr("Type:"), r, 0)
        self.type_combo = QComboBox()
        self.type_combo.addItems(["Username/Password", "NTLM Hash",
                                  "Kerberos Ticket", "SQL Server Auth",
                                  "Windows Auth", "API Key", "Contacts"])
        self.type_combo.setFixedHeight(FIELD_HEIGHT)
        self.type_combo.setStyleSheet("font-size: 10pt;")
        self.type_combo.currentTextChanged.connect(self.on_type_changed)
        grid.addWidget(self.type_combo, r, 1); r += 1

        # Dynamic fields
        self.username_label   = lbl("Username:")
        self.username_edit    = field("Enter username")
        self.password_label   = lbl("Password:")
        self.password_edit    = field("Enter password", echo=True)
        self.ntlm_hash_label  = lbl("NTLM Hash:")
        self.ntlm_hash_edit   = field("Enter NTLM hash", echo=True)
        self.ticket_file_label= lbl("Ticket File:")
        self.ticket_file_edit = field("Path to ticket file")
        self.domain_label     = lbl("Domain:")
        self.domain_edit      = field("e.g., DOMAIN or leave blank")
        self.service_label    = lbl("Service:")
        self.service_edit     = field("e.g., SSH, RDP, SMB, HTTP")
        self.notes_label      = lbl("Notes:")
        self.notes_edit       = field("Optional notes")

        # API Key fields
        self.api_key_name_label  = lbl("Key Name:")
        self.api_key_name_edit   = field("e.g., Shodan, VirusTotal")
        self.api_key_value_label = lbl("API Key:")
        self.api_key_value_edit  = field("Enter API key", echo=True)

        # Contacts fields
        self.account_name_label  = lbl("Account Name:")
        self.account_name_edit   = field("e.g., jdoe, admin")
        self.first_name_label    = lbl("First Name:")
        self.first_name_edit     = field("First name")
        self.middle_name_label   = lbl("Middle Name:")
        self.middle_name_edit    = field("Middle name (optional)")
        self.last_name_label     = lbl("Last Name:")
        self.last_name_edit      = field("Last name")
        self.email_label         = lbl("Email Address:")
        self.email_edit          = field("e.g., john.doe@company.com")
        self.mobile_label        = lbl("Mobile Phone:")
        self.mobile_edit         = field("e.g., +1-555-123-4567")
        self.address_label       = lbl("Address:")
        self.address_edit        = field("Physical address (optional)")

        all_fields = [
            (self.username_label,    self.username_edit),
            (self.password_label,    self.password_edit),
            (self.ntlm_hash_label,   self.ntlm_hash_edit),
            (self.ticket_file_label, self.ticket_file_edit),
            (self.domain_label,      self.domain_edit),
            (self.service_label,     self.service_edit),
            (self.notes_label,       self.notes_edit),
            (self.api_key_name_label, self.api_key_name_edit),
            (self.api_key_value_label, self.api_key_value_edit),
            (self.account_name_label,self.account_name_edit),
            (self.first_name_label,  self.first_name_edit),
            (self.middle_name_label, self.middle_name_edit),
            (self.last_name_label,   self.last_name_edit),
            (self.email_label,       self.email_edit),
            (self.mobile_label,      self.mobile_edit),
            (self.address_label,     self.address_edit),
        ]
        for label, widget in all_fields:
            grid.addWidget(label, r, 0)
            grid.addWidget(widget, r, 1)
            r += 1

        form_layout.addLayout(grid)
        form_layout.addStretch()

        # Buttons inside frame
        btn_row = QHBoxLayout()
        add_btn = QPushButton("Add Credential")
        add_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(50, 150, 50, 150);
                border: 2px solid #64C8FF; border-radius: 5px;
                color: #000000; font-weight: bold;
                padding: 8px 15px; font-size: 12pt;
            }
            QPushButton:hover { background-color: rgba(70, 170, 70, 200); }
        """)
        add_btn.clicked.connect(self.save_credential)
        btn_row.addWidget(add_btn)

        del_btn = QPushButton("Delete Selected")
        del_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(50, 150, 50, 150);
                border: 2px solid #FF6347; border-radius: 5px;
                color: #FFFFFF; font-weight: bold;
                padding: 8px 15px; font-size: 12pt;
            }
            QPushButton:hover { background-color: rgba(70, 170, 70, 200); }
        """)
        del_btn.clicked.connect(self.delete_selected_credential)
        btn_row.addWidget(del_btn)
        btn_row.addStretch()
        form_layout.addLayout(btn_row)

        widget_layout.addWidget(form_frame, stretch=1)

        # ── Stored Credentials header ─────────────────────────────────────
        cred_header = QHBoxLayout()
        cred_lbl = QLabel("Stored Credentials:")
        cred_lbl.setStyleSheet("font-weight: bold; color: #64C8FF; margin-top: 4px;")
        cred_header.addWidget(cred_lbl)
        cred_header.addStretch()

        self.show_passwords_cb = QCheckBox("Show Passwords")
        self.show_passwords_cb.setStyleSheet("color: #DCDCDC; font-weight: bold;")
        self.show_passwords_cb.stateChanged.connect(self._toggle_password_display)
        cred_header.addWidget(self.show_passwords_cb)
        widget_layout.addLayout(cred_header)

        # ── Credentials table — original 7-column format ──────────────────
        self.credentials_table = QTableWidget()
        self.credentials_table.setColumnCount(7)
        self.credentials_table.setHorizontalHeaderLabels(
            ["Source", "Type", "Username", "Password", "Domain", "Service", "Notes"])
        self.credentials_table.setMinimumHeight(120)
        self.credentials_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows)
        self.credentials_table.setStyleSheet("""
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
        hdr_view = self.credentials_table.horizontalHeader()
        # Resize columns to fit their content so nothing is truncated,
        # then let the Notes column stretch to fill remaining space.
        hdr_view.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        hdr_view.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        hdr_view.setStretchLastSection(True)
        self.credentials_table.verticalHeader().setVisible(False)
        widget_layout.addWidget(self.credentials_table, stretch=1)

        # ── AWS Secrets Manager section (shown only when connected) ───────
        self.aws_sm_frame = QFrame()
        self.aws_sm_frame.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 150);
                border-radius: 10px;
                border: 1px solid rgba(100, 200, 255, 50);
            }
        """)
        aws_sm_layout = QVBoxLayout(self.aws_sm_frame)
        aws_sm_layout.setContentsMargins(12, 10, 12, 10)
        aws_sm_layout.setSpacing(8)

        aws_sm_hdr_row = QHBoxLayout()
        aws_sm_hdr = QLabel("☁  AWS Secrets Manager")
        aws_sm_hdr.setStyleSheet(
            "font-size: 10pt; font-weight: bold; color: #64C8FF;"
        )
        aws_sm_hdr_row.addWidget(aws_sm_hdr)
        aws_sm_hdr_row.addStretch()
        self.aws_sm_connected_lbl = QLabel("● Connected")
        self.aws_sm_connected_lbl.setStyleSheet(
            "font-size: 9pt; color: #50C878;"
        )
        aws_sm_hdr_row.addWidget(self.aws_sm_connected_lbl)
        aws_sm_layout.addLayout(aws_sm_hdr_row)

        # Divider
        div = QFrame()
        div.setFrameShape(QFrame.Shape.HLine)
        div.setStyleSheet("color: rgba(100, 200, 255, 40);")
        aws_sm_layout.addWidget(div)

        # — Push / Pull grid (label | field | buttons) ───────────────────
        BTN_STYLE_BLUE = """
            QPushButton {
                background-color: rgba(50, 150, 50, 150);
                border: 1px solid #64C8FF; border-radius: 4px;
                color: #000000; font-weight: bold; font-size: 9pt;
                padding: 0px 12px; min-width: 90px;
            }
            QPushButton:hover { background-color: rgba(70, 170, 70, 200); }
            QPushButton:disabled { background-color: rgba(60,60,60,120); color: #666; border-color: #444; }
        """
        BTN_STYLE_STEEL = """
            QPushButton {
                background-color: rgba(50, 100, 150, 150);
                border: 1px solid #64C8FF; border-radius: 4px;
                color: #FFFFFF; font-weight: bold; font-size: 9pt;
                padding: 0px 12px; min-width: 70px;
            }
            QPushButton:hover { background-color: rgba(70, 130, 180, 200); }
            QPushButton:disabled { background-color: rgba(60,60,60,120); color: #666; border-color: #444; }
        """
        LBL_STYLE = "font-size: 9pt; font-weight: bold; color: #DCDCDC;"
        FIELD_STYLE = "font-size: 9pt; color: #DCDCDC;"

        pp_grid = QGridLayout()
        pp_grid.setHorizontalSpacing(8)
        pp_grid.setVerticalSpacing(6)
        pp_grid.setColumnStretch(1, 1)   # field column expands

        # Push row
        push_lbl = QLabel("Push:")
        push_lbl.setStyleSheet(LBL_STYLE)
        pp_grid.addWidget(push_lbl, 0, 0)

        self.aws_push_name_edit = QLineEdit()
        self.aws_push_name_edit.setPlaceholderText("Secret name  (e.g. huginn/target-db)")
        self.aws_push_name_edit.setFixedHeight(28)
        self.aws_push_name_edit.setStyleSheet(FIELD_STYLE)
        pp_grid.addWidget(self.aws_push_name_edit, 0, 1)

        push_btn_row = QHBoxLayout()
        push_btn_row.setSpacing(6)
        push_sel_btn = QPushButton("Push Selected")
        push_sel_btn.setFixedHeight(28)
        push_sel_btn.setStyleSheet(BTN_STYLE_BLUE)
        push_sel_btn.clicked.connect(self._aws_push_selected)
        push_btn_row.addWidget(push_sel_btn)

        push_all_btn = QPushButton("Push All")
        push_all_btn.setFixedHeight(28)
        push_all_btn.setStyleSheet(BTN_STYLE_STEEL)
        push_all_btn.clicked.connect(self._aws_push_all)
        push_btn_row.addWidget(push_all_btn)
        pp_grid.addLayout(push_btn_row, 0, 2)

        # Pull row
        pull_lbl = QLabel("Pull:")
        pull_lbl.setStyleSheet(LBL_STYLE)
        pp_grid.addWidget(pull_lbl, 1, 0)

        self.aws_pull_name_edit = QLineEdit()
        self.aws_pull_name_edit.setPlaceholderText("Secret name  (e.g. huginn/target-db)")
        self.aws_pull_name_edit.setFixedHeight(28)
        self.aws_pull_name_edit.setStyleSheet(FIELD_STYLE)
        pp_grid.addWidget(self.aws_pull_name_edit, 1, 1)

        pull_btn = QPushButton("Fetch & Import")
        pull_btn.setFixedHeight(28)
        pull_btn.setStyleSheet(BTN_STYLE_BLUE)
        pull_btn.clicked.connect(self._aws_pull)
        pp_grid.addWidget(pull_btn, 1, 2)

        aws_sm_layout.addLayout(pp_grid)

        # Status line
        self.aws_sm_status_lbl = QLabel("")
        self.aws_sm_status_lbl.setStyleSheet("font-size: 9pt; color: #AAAAAA;")
        aws_sm_layout.addWidget(self.aws_sm_status_lbl)

        self.aws_sm_frame.setVisible(False)   # hidden until connected
        widget_layout.addWidget(self.aws_sm_frame)

        # Initialise field visibility
        self.on_type_changed("Username/Password")
    
    def init_security_tab(self):
        """Initialize security overview tab"""
        layout = QVBoxLayout(self.security_tab)
        
        # Security summary
        summary_group = QGroupBox("Security Summary")
        summary_layout = QVBoxLayout(summary_group)
        
        self.security_summary = QLabel()
        summary_layout.addWidget(self.security_summary)
        
        layout.addWidget(summary_group)
        
        # Security options
        options_group = QGroupBox("Security Options")
        options_layout = QFormLayout(options_group)
        
        self.use_env_checkbox = QCheckBox("Prioritize environment variables")
        self.use_env_checkbox.setChecked(True)
        options_layout.addRow("", self.use_env_checkbox)
        
        self.use_secrets_checkbox = QCheckBox("Use enterprise secrets manager")
        self.use_secrets_checkbox.setChecked(True)
        options_layout.addRow("", self.use_secrets_checkbox)
        
        # Memory management
        memory_buttons = QHBoxLayout()
        self.clear_memory_btn = QPushButton("Clear Secure Memory")
        self.clear_memory_btn.clicked.connect(self.clear_secure_memory)
        memory_buttons.addWidget(self.clear_memory_btn)
        memory_buttons.addStretch()
        options_layout.addRow("Memory:", memory_buttons)
        
        layout.addWidget(options_group)
        
        # Environment variables
        env_group = QGroupBox("Environment Variables")
        env_layout = QVBoxLayout(env_group)
        
        env_info = QLabel("""
Environment variables take priority over stored credentials. Use these patterns:
• SERVICE_USERNAME or SERVICE_USER
• SERVICE_PASSWORD or SERVICE_PASS  
• SERVICE_API_KEY or SERVICE_KEY
• SERVICE_TOKEN

Examples:
• SHODAN_API_KEY=your_key_here
• AWS_ACCESS_KEY_ID=AKIA...
• AWS_SECRET_ACCESS_KEY=...
        """)
        env_info.setStyleSheet("color: #666; font-family: monospace;")
        env_layout.addWidget(env_info)
        
        layout.addWidget(env_group)
        
        layout.addStretch()
    
    def init_enterprise_tab(self):
        """Initialize enterprise secrets management tab with inline configuration."""
        layout = QVBoxLayout(self.enterprise_tab)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        FIELD_HEIGHT = 30
        LABEL_STYLE  = "font-size: 10pt; font-weight: bold; color: #DCDCDC;"
        HDR_STYLE    = "font-size: 10pt; font-weight: bold; color: #64C8FF; padding: 4px 0px;"
        INPUT_STYLE  = "font-size: 10pt; color: #DCDCDC;"
        HINT_STYLE   = "font-size: 9pt; color: #888888; font-style: italic;"

        # ── Connection status banner ──────────────────────────────────────
        self.secrets_status_banner = QFrame()
        self.secrets_status_banner.setStyleSheet("""
            QFrame {
                background-color: rgba(60, 60, 60, 180);
                border-radius: 6px;
                border: 1px solid rgba(100, 200, 255, 40);
            }
        """)
        banner_row = QHBoxLayout(self.secrets_status_banner)
        banner_row.setContentsMargins(12, 6, 12, 6)
        self._status_dot = QLabel("●")
        self._status_dot.setStyleSheet("color: #888888; font-size: 14pt;")
        self._status_text = QLabel("Not connected")
        self._status_text.setStyleSheet("color: #AAAAAA; font-size: 10pt;")
        banner_row.addWidget(self._status_dot)
        banner_row.addWidget(self._status_text)
        banner_row.addStretch()
        layout.addWidget(self.secrets_status_banner)

        # ── Provider selector ─────────────────────────────────────────────
        provider_frame = QFrame()
        provider_frame.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 150);
                border-radius: 10px;
                border: 1px solid rgba(100, 200, 255, 50);
            }
        """)
        provider_layout = QVBoxLayout(provider_frame)
        provider_layout.setContentsMargins(15, 12, 15, 12)
        provider_layout.setSpacing(8)

        provider_hdr = QLabel("Provider")
        provider_hdr.setStyleSheet(HDR_STYLE)
        provider_layout.addWidget(provider_hdr)

        provider_row = QHBoxLayout()
        self.sm_provider_combo = QComboBox()
        self.sm_provider_combo.addItems([
            "HashiCorp Vault",
            "AWS Secrets Manager",
            "Azure Key Vault",
        ])
        self.sm_provider_combo.setFixedHeight(FIELD_HEIGHT)
        self.sm_provider_combo.setStyleSheet("font-size: 10pt;")
        self.sm_provider_combo.currentTextChanged.connect(self._on_sm_provider_changed)
        provider_row.addWidget(self.sm_provider_combo)
        provider_layout.addLayout(provider_row)
        layout.addWidget(provider_frame)

        # ── Dynamic config fields (stacked) ──────────────────────────────
        self.sm_config_stack = QStackedWidget()

        # — HashiCorp Vault page —
        vault_page = QFrame()
        vault_page.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 150);
                border-radius: 10px;
                border: 1px solid rgba(100, 200, 255, 50);
            }
        """)
        vault_grid = QGridLayout(vault_page)
        vault_grid.setContentsMargins(15, 12, 15, 12)
        vault_grid.setHorizontalSpacing(10)
        vault_grid.setVerticalSpacing(8)
        vault_grid.setColumnStretch(1, 1)

        vault_hdr = QLabel("HashiCorp Vault")
        vault_hdr.setStyleSheet(HDR_STYLE)
        vault_grid.addWidget(vault_hdr, 0, 0, 1, 2)

        vault_grid.addWidget(QLabel("Vault URL:"), 1, 0)
        vault_grid.itemAtPosition(1, 0).widget().setStyleSheet(LABEL_STYLE)
        self.sm_vault_url = QLineEdit()
        self.sm_vault_url.setPlaceholderText("https://vault.example.com:8200")
        self.sm_vault_url.setFixedHeight(FIELD_HEIGHT)
        self.sm_vault_url.setStyleSheet(INPUT_STYLE)
        vault_grid.addWidget(self.sm_vault_url, 1, 1)

        vault_grid.addWidget(QLabel("Vault Token:"), 2, 0)
        vault_grid.itemAtPosition(2, 0).widget().setStyleSheet(LABEL_STYLE)
        self.sm_vault_token = QLineEdit()
        self.sm_vault_token.setEchoMode(QLineEdit.EchoMode.Password)
        self.sm_vault_token.setPlaceholderText("hvs.XXXXXXXXXXXXXXXX")
        self.sm_vault_token.setFixedHeight(FIELD_HEIGHT)
        self.sm_vault_token.setStyleSheet(INPUT_STYLE)
        vault_grid.addWidget(self.sm_vault_token, 2, 1)

        vault_hint = QLabel("Secrets are read from the path  huginn/<service>  (KV v2)")
        vault_hint.setStyleSheet(HINT_STYLE)
        vault_grid.addWidget(vault_hint, 3, 0, 1, 2)
        self.sm_config_stack.addWidget(vault_page)   # index 0

        # — AWS Secrets Manager page —
        aws_page = QFrame()
        aws_page.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 150);
                border-radius: 10px;
                border: 1px solid rgba(100, 200, 255, 50);
            }
        """)
        aws_grid = QGridLayout(aws_page)
        aws_grid.setContentsMargins(15, 12, 15, 12)
        aws_grid.setHorizontalSpacing(10)
        aws_grid.setVerticalSpacing(8)
        aws_grid.setColumnStretch(1, 1)

        aws_hdr = QLabel("AWS Secrets Manager")
        aws_hdr.setStyleSheet(HDR_STYLE)
        aws_grid.addWidget(aws_hdr, 0, 0, 1, 2)

        def _aws_lbl(text):
            l = QLabel(text)
            l.setStyleSheet(LABEL_STYLE)
            return l

        def _aws_field(placeholder, echo=False):
            w = QLineEdit()
            w.setPlaceholderText(placeholder)
            w.setFixedHeight(FIELD_HEIGHT)
            w.setStyleSheet(INPUT_STYLE)
            if echo:
                w.setEchoMode(QLineEdit.EchoMode.Password)
            return w

        aws_grid.addWidget(_aws_lbl("Access Key ID:"), 1, 0)
        self.sm_aws_access_key = _aws_field("AKIAIOSFODNN7EXAMPLE")
        aws_grid.addWidget(self.sm_aws_access_key, 1, 1)

        aws_grid.addWidget(_aws_lbl("Secret Access Key:"), 2, 0)
        self.sm_aws_secret_key = _aws_field("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", echo=True)
        aws_grid.addWidget(self.sm_aws_secret_key, 2, 1)

        aws_grid.addWidget(_aws_lbl("Session Token:"), 3, 0)
        self.sm_aws_session_token = _aws_field("Optional — required for temporary/STS credentials", echo=True)
        aws_grid.addWidget(self.sm_aws_session_token, 3, 1)

        aws_grid.addWidget(_aws_lbl("Region:"), 4, 0)
        self.sm_aws_region = _aws_field("e.g. us-east-1, ap-southeast-2")
        self.sm_aws_region.setText("us-east-1")
        aws_grid.addWidget(self.sm_aws_region, 4, 1)

        aws_hint = QLabel(
            "Leave Access Key ID blank to fall back to the standard AWS credential chain\n"
            "(env vars → ~/.aws/credentials → IAM instance role)."
        )
        aws_hint.setStyleSheet(HINT_STYLE)
        aws_grid.addWidget(aws_hint, 5, 0, 1, 2)
        self.sm_config_stack.addWidget(aws_page)     # index 1

        # — Azure Key Vault page —
        az_page = QFrame()
        az_page.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 150);
                border-radius: 10px;
                border: 1px solid rgba(100, 200, 255, 50);
            }
        """)
        az_grid = QGridLayout(az_page)
        az_grid.setContentsMargins(15, 12, 15, 12)
        az_grid.setHorizontalSpacing(10)
        az_grid.setVerticalSpacing(8)
        az_grid.setColumnStretch(1, 1)

        az_hdr = QLabel("Azure Key Vault")
        az_hdr.setStyleSheet(HDR_STYLE)
        az_grid.addWidget(az_hdr, 0, 0, 1, 2)

        az_grid.addWidget(QLabel("Key Vault URL:"), 1, 0)
        az_grid.itemAtPosition(1, 0).widget().setStyleSheet(LABEL_STYLE)
        self.sm_az_vault_url = QLineEdit()
        self.sm_az_vault_url.setPlaceholderText("https://myvault.vault.azure.net")
        self.sm_az_vault_url.setFixedHeight(FIELD_HEIGHT)
        self.sm_az_vault_url.setStyleSheet(INPUT_STYLE)
        az_grid.addWidget(self.sm_az_vault_url, 1, 1)

        az_hint = QLabel(
            "Authentication uses DefaultAzureCredential\n"
            "(env vars → managed identity → Azure CLI)."
        )
        az_hint.setStyleSheet(HINT_STYLE)
        az_grid.addWidget(az_hint, 2, 0, 1, 2)
        self.sm_config_stack.addWidget(az_page)      # index 2

        layout.addWidget(self.sm_config_stack)

        # ── Action buttons ────────────────────────────────────────────────
        btn_frame = QFrame()
        btn_frame.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 150);
                border-radius: 10px;
                border: 1px solid rgba(100, 200, 255, 50);
            }
        """)
        btn_layout = QHBoxLayout(btn_frame)
        btn_layout.setContentsMargins(15, 10, 15, 10)
        btn_layout.setSpacing(10)

        BTN_BASE = """
            QPushButton {{
                background-color: rgba(50, 150, 50, 150);
                border: 2px solid {border};
                border-radius: 5px;
                color: {color};
                font-weight: bold;
                padding: 6px 18px;
                font-size: 10pt;
            }}
            QPushButton:hover {{ background-color: rgba(70, 170, 70, 200); }}
            QPushButton:disabled {{ background-color: rgba(60, 60, 60, 120); color: #666; border-color: #444; }}
        """

        self.sm_connect_btn = QPushButton("Connect")
        self.sm_connect_btn.setStyleSheet(BTN_BASE.format(border="#64C8FF", color="#000000"))
        self.sm_connect_btn.clicked.connect(self.configure_secrets_manager)
        btn_layout.addWidget(self.sm_connect_btn)

        self.sm_test_btn = QPushButton("Test Connection")
        self.sm_test_btn.setStyleSheet(BTN_BASE.format(border="#64C8FF", color="#000000"))
        self.sm_test_btn.clicked.connect(self._test_sm_connection)
        btn_layout.addWidget(self.sm_test_btn)

        self.sm_disconnect_btn = QPushButton("Disconnect")
        self.sm_disconnect_btn.setStyleSheet(BTN_BASE.format(border="#FF6347", color="#FFFFFF"))
        self.sm_disconnect_btn.clicked.connect(self._disconnect_sm)
        btn_layout.addWidget(self.sm_disconnect_btn)

        btn_layout.addStretch()
        layout.addWidget(btn_frame)

        layout.addStretch()

        # Initialise stack to match default provider
        self._on_sm_provider_changed(self.sm_provider_combo.currentText())
    
    def connect_signals(self):
        """Connect signals from credential manager"""
        secure_credential_manager.credential_stored.connect(self.on_credential_stored)
        secure_credential_manager.security_event.connect(self.on_security_event)
    
    def save_credential(self):
        """Save credential to secure storage"""
        from app.core.credential_manager import credential_manager

        credential_type = self.type_combo.currentText()
        service = self.service_edit.text().strip()
        notes   = self.notes_edit.text().strip()
        success = False

        if credential_type == "Username/Password":
            username = self.username_edit.text().strip()
            password = self.password_edit.text()
            if not username or not password:
                QMessageBox.warning(self, "Error", "Username and password are required")
                return
            credential_manager.add_credential(
                username=username, password=password,
                domain=self.domain_edit.text().strip(),
                service=service, notes=notes,
                source="manual", credential_type=credential_type)
            success = True

        elif credential_type == "NTLM Hash":
            username  = self.username_edit.text().strip()
            ntlm_hash = self.ntlm_hash_edit.text()
            if not username or not ntlm_hash:
                QMessageBox.warning(self, "Error", "Username and NTLM hash are required")
                return
            credential_manager.add_credential(
                username=username, password=ntlm_hash,
                service=service, notes=notes,
                source="manual", credential_type=credential_type)
            success = True

        elif credential_type == "Kerberos Ticket":
            ticket = self.ticket_file_edit.text().strip()
            if not ticket:
                QMessageBox.warning(self, "Error", "Ticket file path is required")
                return
            credential_manager.add_credential(
                username="", password=ticket,
                service=service, notes=notes,
                source="manual", credential_type=credential_type)
            success = True

        elif credential_type == "SQL Server Auth":
            username = self.username_edit.text().strip()
            password = self.password_edit.text()
            if not username or not password:
                QMessageBox.warning(self, "Error", "Username and password are required")
                return
            credential_manager.add_credential(
                username=username, password=password,
                service=service or "MSSQL", notes=notes,
                source="manual", credential_type=credential_type)
            success = True

        elif credential_type == "Windows Auth":
            username = self.username_edit.text().strip()
            password = self.password_edit.text()
            domain   = self.domain_edit.text().strip()
            if not username or not password:
                QMessageBox.warning(self, "Error", "Username and password are required")
                return
            if not domain:
                QMessageBox.warning(self, "Error", "Domain is required for Windows Auth")
                return
            credential_manager.add_credential(
                username=username, password=password, domain=domain,
                service=service or "MSSQL", notes=notes,
                source="manual", credential_type=credential_type)
            success = True

        elif credential_type == "API Key":
            key_name  = self.api_key_name_edit.text().strip()
            key_value = self.api_key_value_edit.text().strip()
            if not key_name or not key_value:
                QMessageBox.warning(self, "Error", "Key name and API key are required")
                return
            credential_manager.add_credential(
                username=key_name, password=key_value,
                service=service or key_name, notes=notes,
                source="manual", credential_type=credential_type)
            success = True

        elif credential_type == "Contacts":
            account = self.account_name_edit.text().strip()
            email   = self.email_edit.text().strip()
            if not account and not email:
                QMessageBox.warning(self, "Error", "Account name or email is required")
                return
            contact_info = " ".join(filter(None, [
                self.first_name_edit.text().strip(),
                self.middle_name_edit.text().strip(),
                self.last_name_edit.text().strip(),
            ]))
            if self.mobile_edit.text().strip():
                contact_info += f" | Phone: {self.mobile_edit.text().strip()}"
            if self.address_edit.text().strip():
                contact_info += f" | Address: {self.address_edit.text().strip()}"
            credential_manager.add_credential(
                username=account or email, password=contact_info,
                domain=email, service="Contact", notes=notes,
                source="manual", credential_type=credential_type)
            success = True

        if success:
            self.clear_form()
            self.refresh_credentials()
    
    def on_type_changed(self, credential_type):
        """Handle credential type change — show/hide fields."""
        all_pairs = [
            (self.username_label,    self.username_edit),
            (self.password_label,    self.password_edit),
            (self.ntlm_hash_label,   self.ntlm_hash_edit),
            (self.ticket_file_label, self.ticket_file_edit),
            (self.domain_label,      self.domain_edit),
            (self.service_label,     self.service_edit),
            (self.notes_label,       self.notes_edit),
            (self.api_key_name_label, self.api_key_name_edit),
            (self.api_key_value_label, self.api_key_value_edit),
            (self.account_name_label,self.account_name_edit),
            (self.first_name_label,  self.first_name_edit),
            (self.middle_name_label, self.middle_name_edit),
            (self.last_name_label,   self.last_name_edit),
            (self.email_label,       self.email_edit),
            (self.mobile_label,      self.mobile_edit),
            (self.address_label,     self.address_edit),
        ]
        for lbl, wgt in all_pairs:
            lbl.setVisible(False)
            wgt.setVisible(False)

        show_map = {
            "Username/Password": [
                (self.username_label, self.username_edit),
                (self.password_label, self.password_edit),
                (self.domain_label,   self.domain_edit),
                (self.service_label,  self.service_edit),
                (self.notes_label,    self.notes_edit),
            ],
            "NTLM Hash": [
                (self.username_label,  self.username_edit),
                (self.ntlm_hash_label, self.ntlm_hash_edit),
                (self.service_label,   self.service_edit),
                (self.notes_label,     self.notes_edit),
            ],
            "Kerberos Ticket": [
                (self.ticket_file_label, self.ticket_file_edit),
                (self.service_label,     self.service_edit),
                (self.notes_label,       self.notes_edit),
            ],
            "SQL Server Auth": [
                (self.username_label, self.username_edit),
                (self.password_label, self.password_edit),
                (self.service_label,  self.service_edit),
                (self.notes_label,    self.notes_edit),
            ],
            "Windows Auth": [
                (self.username_label, self.username_edit),
                (self.password_label, self.password_edit),
                (self.domain_label,   self.domain_edit),
                (self.service_label,  self.service_edit),
                (self.notes_label,    self.notes_edit),
            ],
            "API Key": [
                (self.api_key_name_label,  self.api_key_name_edit),
                (self.api_key_value_label, self.api_key_value_edit),
                (self.service_label,       self.service_edit),
                (self.notes_label,         self.notes_edit),
            ],
            "Contacts": [
                (self.account_name_label, self.account_name_edit),
                (self.first_name_label,   self.first_name_edit),
                (self.middle_name_label,  self.middle_name_edit),
                (self.last_name_label,    self.last_name_edit),
                (self.email_label,        self.email_edit),
                (self.mobile_label,       self.mobile_edit),
                (self.address_label,      self.address_edit),
                (self.notes_label,        self.notes_edit),
            ],
        }
        for lbl, wgt in show_map.get(credential_type, []):
            lbl.setVisible(True)
            wgt.setVisible(True)
    
    def clear_form(self):
        """Clear the credential form"""
        for w in (self.username_edit, self.password_edit, self.ntlm_hash_edit,
                  self.ticket_file_edit, self.domain_edit, self.service_edit,
                  self.notes_edit, self.api_key_name_edit, self.api_key_value_edit,
                  self.account_name_edit, self.first_name_edit,
                  self.middle_name_edit, self.last_name_edit, self.email_edit,
                  self.mobile_edit, self.address_edit):
            w.clear()
        self.type_combo.setCurrentIndex(0)
        self.on_type_changed("Username/Password")
    
    def refresh_credentials(self):
        """Refresh the credentials table — always reloads from disk first."""
        from app.core.credential_manager import credential_manager

        # Always reload from the current profile's file so the table reflects
        # what is actually persisted, regardless of in-memory state.
        credential_manager._load_profile_credentials()

        credentials = credential_manager.get_credentials()
        show_pw = (hasattr(self, 'show_passwords_cb')
                   and self.show_passwords_cb.isChecked())

        self.credentials_table.setRowCount(len(credentials))

        for row, cred in enumerate(credentials):
            source_icon = {
                'manual':      '👤 Manual',
                'enumeration': '🔍 Enum',
                'exploitation':'💥 Exploit',
                'scanned':     '🔍 Scanned',
                'aws_secrets': '☁ AWS',
            }.get(cred.source, '❓ Unknown')

            cred_type = getattr(cred, 'credential_type', 'Username/Password')
            password  = cred.password if show_pw else '*' * len(cred.password)

            for col, text in enumerate([
                source_icon, cred_type, cred.username,
                password, cred.domain, cred.service, cred.notes
            ]):
                item = QTableWidgetItem(text)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.credentials_table.setItem(row, col, item)

        self.update_security_summary()

    def _toggle_password_display(self):
        """Re-render the table when Show Passwords is toggled."""
        self.refresh_credentials()
    
    def test_credential(self, service):
        """Test a specific credential"""
        if service in self.test_workers:
            return  # Test already running
        
        worker = CredentialTestWorker(service)
        worker.test_completed.connect(self.on_test_completed)
        self.test_workers[service] = worker
        worker.start()
        
        # Update status to show testing
        for row in range(self.credentials_table.rowCount()):
            if self.credentials_table.item(row, 0).text() == service:
                self.credentials_table.item(row, 4).setText("Testing...")
                break
    
    def test_selected_credential(self):
        """Test the selected credential"""
        current_row = self.credentials_table.currentRow()
        if current_row >= 0:
            self.test_credential_by_index(current_row)
    
    def test_credential_by_index(self, index):
        """Test credential by table index"""
        from app.core.credential_manager import credential_manager
        credentials = credential_manager.get_credentials()
        if 0 <= index < len(credentials):
            credential = credentials[index]
            # Placeholder test functionality
            QMessageBox.information(self, "Test Result", f"Testing {credential.credential_type} for {credential.service}...")
    
    def delete_selected_credential(self):
        """Delete the selected credential"""
        current_row = self.credentials_table.currentRow()
        if current_row >= 0:
            from app.core.credential_manager import credential_manager
            credentials = credential_manager.get_credentials()
            
            if current_row < len(credentials):
                credential = credentials[current_row]
                service = credential.service
                
                reply = QMessageBox.question(
                    self, "Confirm Delete",
                    f"Are you sure you want to delete the {credential.credential_type} for {service}?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                
                if reply == QMessageBox.StandardButton.Yes:
                    if credential_manager.remove_credential(current_row):
                        QMessageBox.information(self, "Success", f"Credential for {service} deleted")
                        self.refresh_credentials()
                        self.update_profile_label()  # Update profile info
                    else:
                        QMessageBox.warning(self, "Error", "Failed to delete credential")
    
    def _on_sm_provider_changed(self, provider: str):
        """Switch the config stack to match the selected provider."""
        index = {"HashiCorp Vault": 0, "AWS Secrets Manager": 1, "Azure Key Vault": 2}.get(provider, 0)
        self.sm_config_stack.setCurrentIndex(index)

    def configure_secrets_manager(self):
        """Apply the inline secrets manager configuration."""
        provider = self.sm_provider_combo.currentText()
        try:
            if provider == "HashiCorp Vault":
                success = secure_credential_manager.configure_secrets_manager(
                    "vault",
                    vault_url=self.sm_vault_url.text().strip(),
                    vault_token=self.sm_vault_token.text().strip(),
                )
                if success:
                    self._save_sm_config({
                        "provider": provider,
                        "vault_url": self.sm_vault_url.text().strip(),
                        "vault_token": self.sm_vault_token.text().strip(),
                    })
            elif provider == "AWS Secrets Manager":
                success = secure_credential_manager.configure_secrets_manager(
                    "aws",
                    region=self.sm_aws_region.text().strip() or "us-east-1",
                    access_key=self.sm_aws_access_key.text().strip() or None,
                    secret_key=self.sm_aws_secret_key.text().strip() or None,
                    session_token=self.sm_aws_session_token.text().strip() or None,
                )
                if success:
                    self._save_sm_config({
                        "provider": provider,
                        "region": self.sm_aws_region.text().strip() or "us-east-1",
                        "access_key": self.sm_aws_access_key.text().strip(),
                        "secret_key": self.sm_aws_secret_key.text().strip(),
                        "session_token": self.sm_aws_session_token.text().strip(),
                    })
            elif provider == "Azure Key Vault":
                success = secure_credential_manager.configure_secrets_manager(
                    "azure",
                    vault_url=self.sm_az_vault_url.text().strip(),
                )
                if success:
                    self._save_sm_config({
                        "provider": provider,
                        "vault_url": self.sm_az_vault_url.text().strip(),
                    })
            else:
                success = False

            self._set_sm_status(success, provider if success else None)
            self.update_security_summary()
        except Exception as e:
            self._set_sm_status(False, None, error=str(e))

    def _save_sm_config(self, config: dict):
        """Persist secrets manager config to the encrypted credential store."""
        import json
        secure_credential_manager.store_credential(
            service="huginn-sm-config",
            notes=json.dumps(config),
            source="internal",
        )

    def _load_sm_config(self):
        """Load saved secrets manager config and auto-connect if present."""
        import json
        cred = secure_credential_manager.get_credential(
            "huginn-sm-config",
            use_env=False,
            use_secrets_manager=False,
        )
        if not cred or not cred.notes:
            return
        try:
            config = json.loads(cred.notes)
        except json.JSONDecodeError:
            return

        provider = config.get("provider", "")
        if not provider:
            return

        # Populate the UI fields silently before connecting
        self.sm_provider_combo.blockSignals(True)
        self.sm_provider_combo.setCurrentText(provider)
        self.sm_provider_combo.blockSignals(False)
        self._on_sm_provider_changed(provider)

        if provider == "HashiCorp Vault":
            self.sm_vault_url.setText(config.get("vault_url", ""))
            self.sm_vault_token.setText(config.get("vault_token", ""))
        elif provider == "AWS Secrets Manager":
            self.sm_aws_region.setText(config.get("region", "us-east-1"))
            self.sm_aws_access_key.setText(config.get("access_key", ""))
            self.sm_aws_secret_key.setText(config.get("secret_key", ""))
            self.sm_aws_session_token.setText(config.get("session_token", ""))
        elif provider == "Azure Key Vault":
            self.sm_az_vault_url.setText(config.get("vault_url", ""))

        # Attempt silent reconnect
        try:
            self.configure_secrets_manager()
        except Exception:
            pass  # Silently ignore on startup — user can reconnect manually

    def _test_sm_connection(self):
        """Test the current secrets manager connection without saving."""
        self.configure_secrets_manager()

    def _disconnect_sm(self):
        """Clear the active secrets manager connection and remove saved config."""
        sm = secure_credential_manager._secrets_manager
        sm.vault_client = None
        sm.aws_client   = None
        sm.azure_client = None
        secure_credential_manager.remove_credential("huginn-sm-config")
        self._set_sm_status(False, None)
        self.update_security_summary()

    def _set_sm_status(self, connected: bool, provider: str | None, error: str = ""):
        """Update the status banner in the Enterprise tab and show/hide the
        AWS section in the Credentials tab."""
        if connected:
            self._status_dot.setStyleSheet("color: #50C878; font-size: 14pt;")
            self._status_text.setText(f"Connected  ·  {provider}")
            self._status_text.setStyleSheet("color: #50C878; font-size: 10pt;")
            self.secrets_status_banner.setStyleSheet("""
                QFrame {
                    background-color: rgba(0, 80, 0, 180);
                    border-radius: 6px;
                    border: 1px solid rgba(80, 200, 120, 80);
                }
            """)
        elif error:
            self._status_dot.setStyleSheet("color: #FF6347; font-size: 14pt;")
            self._status_text.setText(f"Error  ·  {error}")
            self._status_text.setStyleSheet("color: #FF6347; font-size: 10pt;")
            self.secrets_status_banner.setStyleSheet("""
                QFrame {
                    background-color: rgba(80, 0, 0, 180);
                    border-radius: 6px;
                    border: 1px solid rgba(200, 80, 80, 80);
                }
            """)
        else:
            self._status_dot.setStyleSheet("color: #888888; font-size: 14pt;")
            self._status_text.setText("Not connected")
            self._status_text.setStyleSheet("color: #AAAAAA; font-size: 10pt;")
            self.secrets_status_banner.setStyleSheet("""
                QFrame {
                    background-color: rgba(60, 60, 60, 180);
                    border-radius: 6px;
                    border: 1px solid rgba(100, 200, 255, 40);
                }
            """)

        # Show the AWS section in the Credentials tab only when AWS is active
        aws_active = connected and provider == "AWS Secrets Manager"
        self.aws_sm_frame.setVisible(aws_active)
        if aws_active:
            self.aws_sm_status_lbl.setText("")

    # ------------------------------------------------------------------
    # AWS Secrets Manager — push / pull helpers
    # ------------------------------------------------------------------

    def _aws_sm_client(self):
        """Return the active AWS Secrets Manager boto3 client, or None."""
        return secure_credential_manager._secrets_manager.aws_client

    def _aws_set_status(self, msg: str, ok: bool = True):
        colour = "#50C878" if ok else "#FF6347"
        self.aws_sm_status_lbl.setStyleSheet(f"font-size: 9pt; color: {colour};")
        self.aws_sm_status_lbl.setText(msg)

    def _aws_push_selected(self):
        """Push the currently selected credential row to AWS Secrets Manager."""
        import json
        client = self._aws_sm_client()
        if not client:
            self._aws_set_status("✗ Not connected to AWS Secrets Manager", ok=False)
            return

        row = self.credentials_table.currentRow()
        if row < 0:
            self._aws_set_status("✗ Select a credential row first", ok=False)
            return

        from app.core.credential_manager import credential_manager
        creds = credential_manager.get_credentials()
        if row >= len(creds):
            return
        cred = creds[row]

        secret_name = self.aws_push_name_edit.text().strip()
        if not secret_name:
            # Default to huginn/<service> or huginn/credential-<row>
            secret_name = f"huginn/{cred.service}" if cred.service else f"huginn/credential-{row}"

        payload = {
            "username": cred.username,
            "password": cred.password,
            "domain": cred.domain,
            "credential_type": cred.credential_type,
            "notes": cred.notes,
        }

        try:
            # Try update first, fall back to create
            try:
                client.put_secret_value(
                    SecretId=secret_name,
                    SecretString=json.dumps(payload),
                )
                self._aws_set_status(f"✓ Updated  {secret_name}")
            except client.exceptions.ResourceNotFoundException:
                client.create_secret(
                    Name=secret_name,
                    SecretString=json.dumps(payload),
                )
                self._aws_set_status(f"✓ Created  {secret_name}")
        except Exception as exc:
            self._aws_set_status(f"✗ {exc}", ok=False)

    def _aws_push_all(self):
        """Push every credential in the table to AWS Secrets Manager."""
        import json
        client = self._aws_sm_client()
        if not client:
            self._aws_set_status("✗ Not connected to AWS Secrets Manager", ok=False)
            return

        from app.core.credential_manager import credential_manager
        creds = credential_manager.get_credentials()
        if not creds:
            self._aws_set_status("No credentials to push", ok=True)
            return

        ok_count = 0
        errors = []
        for i, cred in enumerate(creds):
            svc = cred.service or f"credential-{i}"
            secret_name = f"huginn/{svc}"
            payload = {
                "username": cred.username,
                "password": cred.password,
                "domain": cred.domain,
                "credential_type": cred.credential_type,
                "notes": cred.notes,
            }
            try:
                try:
                    client.put_secret_value(
                        SecretId=secret_name,
                        SecretString=json.dumps(payload),
                    )
                except client.exceptions.ResourceNotFoundException:
                    client.create_secret(
                        Name=secret_name,
                        SecretString=json.dumps(payload),
                    )
                ok_count += 1
            except Exception as exc:
                errors.append(f"{secret_name}: {exc}")

        if errors:
            self._aws_set_status(
                f"✓ {ok_count} pushed  ✗ {len(errors)} failed — see logs",
                ok=False,
            )
            for e in errors:
                logger.error(f"AWS push error: {e}")
        else:
            self._aws_set_status(f"✓ {ok_count} credential(s) pushed")

    def _aws_pull(self):
        """Fetch a secret from AWS and import it into the active tenant's
        persistent credential store."""
        import json
        client = self._aws_sm_client()
        if not client:
            self._aws_set_status("✗ Not connected to AWS Secrets Manager", ok=False)
            return

        secret_name = self.aws_pull_name_edit.text().strip()
        if not secret_name:
            self._aws_set_status("✗ Enter a secret name to fetch", ok=False)
            return

        try:
            response = client.get_secret_value(SecretId=secret_name)
            raw = response.get("SecretString", "")
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                data = {"password": raw}

            from app.core.credential_manager import credential_manager

            # Derive service name from the secret path (last segment)
            service = secret_name.split("/")[-1]
            credential_manager.add_credential(
                username=data.get("username", ""),
                password=data.get("password", ""),
                domain=data.get("domain", ""),
                service=data.get("service", service),
                notes=data.get("notes", f"Imported from AWS: {secret_name}"),
                source="aws_secrets",
                credential_type=data.get("credential_type", "Username/Password"),
            )
            # add_credential auto-saves, but call explicitly as a guarantee
            credential_manager.save_to_profile_json()

            self.refresh_credentials()
            self._aws_set_status(
                f"✓ Imported  {secret_name}  →  profile '{credential_manager.get_current_profile()}'"
            )
            self.aws_pull_name_edit.clear()
        except Exception as exc:
            self._aws_set_status(f"✗ {exc}", ok=False)
    
    def clear_secure_memory(self):
        """Clear all secure memory"""
        secure_credential_manager.clear_secure_memory()
        QMessageBox.information(self, "Success", "Secure memory cleared")
        self.update_security_summary()
    
    def update_security_summary(self):
        """Update security summary display"""
        from app.core.credential_manager import credential_manager
        
        summary_text = f"""
<b>Security Status:</b><br>
• {credential_manager.get_credential_summary()}<br>
• Profile: {credential_manager.get_current_profile()}<br>
<br>
<b>Credential Types:</b><br>
        """
        
        # Count by type
        type_counts = {}
        for cred in credential_manager.get_credentials():
            cred_type = cred.credential_type
            type_counts[cred_type] = type_counts.get(cred_type, 0) + 1
        
        for cred_type, count in type_counts.items():
            summary_text += f"• {cred_type}: {count}<br>"
        
        self.security_summary.setText(summary_text)

        # Reflect secrets manager connection state in the Enterprise tab banner
        sm = secure_credential_manager._secrets_manager
        if any([sm.vault_client, sm.aws_client, sm.azure_client]):
            provider = (
                "HashiCorp Vault" if sm.vault_client else
                "AWS Secrets Manager" if sm.aws_client else
                "Azure Key Vault"
            )
            self._set_sm_status(True, provider)
        else:
            self._set_sm_status(False, None)
    
    def update_profile_label(self):
        """No-op — profile label removed from UI."""
        pass
    

    
    def on_test_completed(self, service, result):
        """Handle credential test completion"""
        if service in self.test_workers:
            del self.test_workers[service]
        
        # Update table status
        for row in range(self.credentials_table.rowCount()):
            if self.credentials_table.item(row, 0).text() == service:
                status = "✓ Valid" if result['success'] else "✗ Invalid"
                self.credentials_table.item(row, 4).setText(status)
                
                if result['success']:
                    self.credentials_table.item(row, 4).setBackground(Qt.GlobalColor.green)
                else:
                    self.credentials_table.item(row, 4).setBackground(Qt.GlobalColor.red)
                break
    
    def on_credential_stored(self, service):
        """Handle credential stored event"""
        self.refresh_credentials()
    
    def on_security_event(self, event_type, message):
        """Handle security events"""
        if event_type in ['store_error', 'load_error', 'save_error']:
            QMessageBox.critical(self, "Security Error", message)