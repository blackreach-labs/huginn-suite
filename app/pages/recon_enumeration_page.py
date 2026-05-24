# app/pages/recon_enumeration_page.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QFrame, QTabWidget, QPushButton, QLineEdit, QCheckBox, QComboBox, QSpinBox, QTextEdit,
                             QStackedWidget, QTableWidget, QTreeWidget, QToolButton, QSpacerItem, QSizePolicy)
from PyQt6.QtCore import pyqtSignal, Qt, QThreadPool
from PyQt6.QtGui import QIcon
import os
from app.core.logger import logger

# Import mixins for advanced functionality
try:
    from app.pages.recon_enumeration.service_scanners import ServiceScannersMixin
    from app.pages.recon_enumeration.service_ui_components import ServiceUIComponentsMixin
    from app.pages.recon_enumeration.service_field_visibility import ServiceFieldVisibilityMixin
    from app.pages.recon_enumeration.port_scanning import PortScanningMixin
except ImportError:
    # Create empty mixins if not available
    class ServiceScannersMixin: pass
    class ServiceUIComponentsMixin: pass
    class ServiceFieldVisibilityMixin: pass
    class PortScanningMixin: pass

class ReconEnumerationPage(QWidget, ServiceScannersMixin, ServiceUIComponentsMixin, ServiceFieldVisibilityMixin, PortScanningMixin):
    """Reconnaissance & Enumeration phase page with advanced functionality"""
    
    navigate_signal = pyqtSignal(str)
    status_updated = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.setObjectName("ReconEnumerationPage")
        
        # Initialize centralized data collection - tenant will be set later
        self.ui_integration = None
        self.current_tenant = None
        
        # Connect to tenant changes
        try:
            from app.core.tenant_aware_updater import tenant_aware_updater
            tenant_aware_updater.tenant_changed.connect(self.on_tenant_changed)
        except ImportError as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the UI components"""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        
        # Create tabs for different recon categories
        self.tab_widget = QTabWidget()
        
        # OSINT tab
        try:
            from app.pages.osint_page import OSINTPage
            osint_widget = OSINTPage(self)
            self.tab_widget.addTab(osint_widget, "🔍 OSINT")
        except ImportError as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        
        # Network Scanning tab (combines Network Discovery and Port Scanning)
        network_scanning_tab = self.create_network_scanning_tab()
        self.tab_widget.addTab(network_scanning_tab, "🌐 Network Scanning")
        
        # DNS tab - use dedicated DNS enumeration page
        try:
            from app.pages.dns_enumeration_page import DNSEnumerationPage
            dns_tab = DNSEnumerationPage(self)
            self.tab_widget.addTab(dns_tab, "🔎 DNS")
        except ImportError:
            # Fallback to simple DNS tab
            dns_tab = self.create_dns_tab()
            self.tab_widget.addTab(dns_tab, "🔎 DNS")
        
        # Service Enumeration tab
        service_tab = self.create_service_tab()
        self.tab_widget.addTab(service_tab, "⚙️ Service Enumeration")
        
        # AWS Penetration Testing tab
        aws_tab = self.create_aws_tab()
        self.tab_widget.addTab(aws_tab, "☁️ AWS")
        
        # Azure Penetration Testing tab
        azure_tab = self.create_azure_tab()
        self.tab_widget.addTab(azure_tab, "🔷 Azure")
        
        # Active Directory tab
        ad_tab = self.create_ad_tab()
        self.tab_widget.addTab(ad_tab, "🏢 Active Directory")

        # Wireless Security tab
        try:
            from app.widgets.wireless_security_widget import WirelessSecurityWidget
            wireless_tab = WirelessSecurityWidget(self)
            self.tab_widget.addTab(wireless_tab, "📡 Wireless")
        except Exception as _exc:
            logger.debug("Wireless security tab unavailable", exc_info=True)

        # Social Engineering tab
        try:
            from app.widgets.social_engineering_widget import SocialEngineeringWidget
            social_tab = SocialEngineeringWidget(self)
            self.tab_widget.addTab(social_tab, "🎭 Social Engineering")
        except Exception as _exc:
            logger.debug("Social engineering tab unavailable", exc_info=True)

        main_layout.addWidget(self.tab_widget)
    
    def on_tenant_changed(self, old_tenant, new_tenant):
        """Handle tenant change - update existing integration"""
        if self.ui_integration:
            # Just update tenant, don't recreate
            self.ui_integration.tenant_id = new_tenant
            self.current_tenant = new_tenant
        else:
            # Create new integration if none exists
            try:
                from app.core.unified_ui_integration import create_unified_integration
                self.ui_integration = create_unified_integration(new_tenant)
                self.current_tenant = new_tenant
                
                from PyQt6.QtCore import QTimer
                QTimer.singleShot(500, self._register_ui_components)
            except ImportError as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
    
    def _register_ui_components(self):
        """Register UI components after they're created"""
        if not self.ui_integration:
            return
        try:
            # Register components that exist
            if hasattr(self, 'dns_table') and self.dns_table:
                self.ui_integration.register_component("dns_subdomains", "table", self.dns_table)
                self.ui_integration.register_component("dns_records", "table", self.dns_table)
            
            if hasattr(self, 'port_table') and self.port_table:
                self.ui_integration.register_component("port_open_ports", "table", self.port_table)
            
            # Don't start updates here - tenant manager handles it
            pass
        except Exception as e:
            print(f"DEBUG: Error registering UI components: {e}")
    
    def create_tab_icon(self, icon_name):
        """Create tab icon from resources/icons directory"""
        if self.main_window:
            icon_path = os.path.join(self.main_window.project_root, "resources", "icons", icon_name)
            if os.path.exists(icon_path):
                self.tab_widget.setIconSize(QSize(24, 24))
                return QIcon(icon_path)
        return QIcon()
        
    def create_network_scanning_tab(self):
        """Create network scanning tab with sub-tabs"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Create sub-tab widget
        sub_tab_widget = QTabWidget()
        
        # Cloud Discovery sub-tab
        cloud_tab = self.create_cloud_discovery_subtab()
        sub_tab_widget.addTab(cloud_tab, "☁️ Cloud Discovery")
        
        # Port Scanning sub-tab
        port_tab = self.create_port_scanning_subtab()
        sub_tab_widget.addTab(port_tab, "🔌 Port Scanning")
        
        # Removed Huginn Scanner - moved to Vulnerability Analysis section
        
        layout.addWidget(sub_tab_widget)
        return tab
    
    def create_cloud_discovery_subtab(self):
        """Create enhanced cloud discovery sub-tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Import and add the enhanced CloudAssetsWidget
        try:
            from app.widgets.cloud_assets_widget import CloudAssetsWidget
            cloud_assets_widget = CloudAssetsWidget(self)
            
            # Connect signals
            cloud_assets_widget.scan_completed.connect(self.on_cloud_scan_completed)
            
            layout.addWidget(cloud_assets_widget)
        except ImportError:
            # Fallback if widget not available
            layout.addWidget(QLabel("Cloud discovery functionality will be available here"))
        
        return tab
    
    def on_cloud_scan_completed(self, results):
        """Handle cloud scan completion"""
        self.status_updated.emit("Cloud asset discovery completed")
    
    def create_port_scanning_subtab(self):
        """Create port scanning sub-tab with advanced functionality"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Try to use mixin implementation first
        try:
            if hasattr(self, 'create_port_scan_controls'):
                port_controls_layout = self.create_port_scan_controls()
                layout.addLayout(port_controls_layout)
            else:
                raise AttributeError("Mixin not available")
        except:
            # Fallback to basic implementation
            self.create_basic_port_controls(layout)
        
        # Add port scan results area with separate views for each scan type
        try:
            # Create separate stacks for each scan type
            self.port_results_stacks = {}
            self.port_terminals = {}
            self.port_tables = {}
            
            # Main container for all scan type views
            self.port_main_container = QWidget()
            container_layout = QVBoxLayout(self.port_main_container)
            
            for scan_type in ["Ping Sweep", "Huginn Sweep", "Layer2 Sweep", "TCP Scan", "UDP Scan"]:
                # Create stack for this scan type
                stack = QStackedWidget()
                
                # Text view (terminal)
                terminal = QTextEdit()
                terminal.setReadOnly(True)
                self.apply_terminal_theme_to_widget(terminal)
                terminal.setPlaceholderText(f"{scan_type} results will appear here...")
                stack.addWidget(terminal)
                
                # Table view
                table = QTableWidget()
                if scan_type == "Ping Sweep":
                    table.setColumnCount(2)
                    table.setHorizontalHeaderLabels(["IP Address", "Status"])
                elif scan_type == "Huginn Sweep":
                    table.setColumnCount(3)
                    table.setHorizontalHeaderLabels(["IP Address", "Open Ports", "Services"])
                elif scan_type == "Layer2 Sweep":
                    table.setColumnCount(4)
                    table.setHorizontalHeaderLabels(["IP Address", "MAC Address", "Vendor", "Protocol"])
                else:  # TCP/UDP Scan
                    table.setColumnCount(4)
                    table.setHorizontalHeaderLabels(["IP Address", "Port", "State", "Service"])
                stack.addWidget(table)
                
                # Tree view
                tree = QTreeWidget()
                tree.setHeaderLabels(["Item", "Details"])
                stack.addWidget(tree)
                
                # Store references
                self.port_results_stacks[scan_type] = stack
                self.port_terminals[scan_type] = terminal
                self.port_tables[scan_type] = table
                if not hasattr(self, 'port_trees'):
                    self.port_trees = {}
                self.port_trees[scan_type] = tree
                
                # Add to container (initially hidden)
                container_layout.addWidget(stack)
                stack.setVisible(scan_type == "Ping Sweep")  # Show first one by default
            
            layout.addWidget(self.port_main_container, 1)
            
            # Set default references for backward compatibility
            self.port_terminal = self.port_terminals["Ping Sweep"]
            self.port_table = self.port_tables["Ping Sweep"]
            self.port_results_stack = self.port_results_stacks["Ping Sweep"]
            self.port_tree = self.port_trees["Ping Sweep"] if hasattr(self, 'port_trees') else None
            
        except:
            # Fallback to simple results area
            self.port_results = QTextEdit()
            self.port_results.setReadOnly(True)
            self.port_results.setPlaceholderText("Port scan results will appear here...")
            self.apply_terminal_theme_to_widget(self.port_results)
            layout.addWidget(self.port_results)
        
        # Initialize current view and scan state
        self.current_port_view = "text"
        self.port_scan_results = {}
        self.port_scan_results_by_type = {}
        self.port_scanning = False
        self.current_port_scan_type = "Ping Sweep"
        
        return tab
    
    def create_basic_port_controls(self, layout):
        """Create basic port scanning controls as fallback"""
        controls_frame = QFrame()
        controls_layout = QVBoxLayout(controls_frame)
        
        # Target input
        target_layout = QHBoxLayout()
        target_label = QLabel("Target:")
        target_label.setFixedWidth(100)
        target_layout.addWidget(target_label)
        
        self.port_target_input = QLineEdit()
        self.port_target_input.setPlaceholderText("Enter target (IP, range, or hostname)")
        target_layout.addWidget(self.port_target_input)
        controls_layout.addLayout(target_layout)
        
        # Scan type dropdown
        scan_type_layout = QHBoxLayout()
        scan_type_label = QLabel("Scan Type:")
        scan_type_label.setFixedWidth(100)
        scan_type_layout.addWidget(scan_type_label)
        
        self.port_scan_type = QComboBox()
        self.port_scan_type.addItems(["Ping Sweep", "Huginn Sweep", "TCP Scan", "UDP Scan"])
        scan_type_layout.addWidget(self.port_scan_type)
        scan_type_layout.addStretch()
        controls_layout.addLayout(scan_type_layout)
        
        # Port input
        port_layout = QHBoxLayout()
        port_label = QLabel("Ports:")
        port_label.setFixedWidth(100)
        port_layout.addWidget(port_label)
        
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("80,443,8080 or 1-1000")
        port_layout.addWidget(self.port_input)
        
        # Port preset buttons including "All"
        common_btn = QPushButton("Common")
        common_btn.setFixedWidth(80)
        common_btn.clicked.connect(lambda: self.port_input.setText("21,22,23,25,53,80,110,143,443,993,995"))
        port_layout.addWidget(common_btn)
        
        top1000_btn = QPushButton("Top 1000")
        top1000_btn.setFixedWidth(80)
        top1000_btn.clicked.connect(lambda: self.port_input.setText("1-1000"))
        port_layout.addWidget(top1000_btn)
        
        all_btn = QPushButton("All")
        all_btn.setFixedWidth(60)
        all_btn.clicked.connect(lambda: self.port_input.setText("1-65535"))
        port_layout.addWidget(all_btn)
        
        controls_layout.addLayout(port_layout)
        
        # Run button
        run_btn = QPushButton("🚀 Run Port Scan")
        run_btn.setMinimumHeight(40)
        run_btn.clicked.connect(self.run_port_scan)
        controls_layout.addWidget(run_btn)
        
        layout.addWidget(controls_frame)
    
    # Huginn Scanner moved to Vulnerability Analysis section
    
    def create_dns_tab(self):
        """Create simple DNS enumeration tab as fallback"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(20, 20, 20, 20)
        
        info_label = QLabel("DNS enumeration functionality will be available here")
        info_label.setStyleSheet("color: #87CEEB; font-size: 14pt; text-align: center;")
        layout.addWidget(info_label)
        
        layout.addStretch()
        return tab
    
    def create_service_tab(self):
        """Create service enumeration tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Create sub-tab widget for different service types
        sub_tab_widget = QTabWidget()
        sub_tab_widget.setContentsMargins(0, 0, 0, 0)
        
        # Service enumeration tabs with full functionality
        services = [
            ("🌍 HTTP",     "http_enum"),
            ("📡 RPC",      "rpc_enum"),
            ("📂 SMB",      "smb_enum"),
            ("🔐 SSH",      "ssh_enum"),
            ("📧 SMTP",     "smtp_enum"),
            ("📒 LDAP",     "ldap_enum"),
            ("📶 SNMP",     "snmp_enum"),
            ("🔗 API",      "api_enum"),
            ("🗄️ Database", "db_enum"),
            ("🔑 IKE",      "ike_enum"),
            ("🛡️ AV/FW",   "av_detect"),
        ]
        for service_name, tool_key in services:
            try:
                service_tab = self.create_service_subtab(service_name, tool_key)
            except:
                # Fallback to simple tab
                service_tab = self.create_simple_service_tab(service_name, tool_key)
            sub_tab_widget.addTab(service_tab, service_name)
        
        layout.addWidget(sub_tab_widget)
        return tab
    
    def create_simple_service_tab(self, service_name, tool_key):
        """Create a simple service enumeration sub-tab as fallback"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Service controls
        controls_frame = QFrame()
        controls_layout = QVBoxLayout(controls_frame)
        
        # Target input
        target_layout = QHBoxLayout()
        target_label = QLabel("Target:")
        target_label.setFixedWidth(100)
        target_layout.addWidget(target_label)
        
        target_input = QLineEdit()
        target_input.setPlaceholderText(f"Enter target for {service_name} enumeration")
        target_layout.addWidget(target_input)
        controls_layout.addLayout(target_layout)
        
        # Store reference for later use
        setattr(self, f"{tool_key}_target_input", target_input)
        
        # Run button
        run_btn = QPushButton(f"🚀 Run {service_name} Enumeration")
        run_btn.setMinimumHeight(40)
        run_btn.clicked.connect(lambda: self.run_service_scan(tool_key))
        controls_layout.addWidget(run_btn)
        
        layout.addWidget(controls_frame)
        
        # Results area
        results_label = QLabel(f"📊 {service_name} Results:")
        results_label.setStyleSheet("font-size: 14pt; font-weight: bold; color: #64C8FF; margin-top: 15px;")
        layout.addWidget(results_label)
        
        results_area = QTextEdit()
        results_area.setReadOnly(True)
        results_area.setPlaceholderText(f"{service_name} enumeration results will appear here...")
        results_area.setStyleSheet("""
            QTextEdit {
                background-color: #1E1E1E;
                color: #DCDCDC;
                font-family: 'Courier New', monospace;
                font-size: 10pt;
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
            }
        """)
        layout.addWidget(results_area)
        
        # Store reference for later use
        setattr(self, f"{tool_key}_results", results_area)
        
        return tab
    
    def create_aws_tab(self):
        """Create AWS penetration testing tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # AWS tools
        try:
            from app.widgets.aws_pentest_widget import AWSPentestWidget
            aws_widget = AWSPentestWidget(self)
            layout.addWidget(aws_widget)
        except ImportError:
            # Show installation instructions when boto3 not available
            install_frame = QFrame()
            install_layout = QVBoxLayout(install_frame)
            
            install_label = QLabel("❌ AWS features require boto3 installation")
            install_label.setStyleSheet("color: #FF6B6B; font-size: 16pt; font-weight: bold;")
            install_layout.addWidget(install_label)
            
            cmd_label = QLabel("Install with: pip install boto3 botocore")
            cmd_label.setStyleSheet("color: #FFAA00; font-family: monospace; font-size: 12pt; padding: 10px;")
            install_layout.addWidget(cmd_label)
            
            restart_label = QLabel("Restart Huginn after installation to enable AWS features")
            restart_label.setStyleSheet("color: #87CEEB; font-size: 11pt;")
            install_layout.addWidget(restart_label)
            
            install_layout.addStretch()
            layout.addWidget(install_frame)
        
        return tab
    
    def create_azure_tab(self):
        """Create Azure penetration testing tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Warning banner
        warning = QLabel("⚠️ AUTHORIZED TESTING ONLY - Azure Penetration Testing Suite")
        warning.setAlignment(Qt.AlignmentFlag.AlignCenter)
        warning.setStyleSheet("""
            background-color: #0078D4;
            color: white;
            padding: 10px;
            font-weight: bold;
            font-size: 14pt;
            border-radius: 5px;
            margin-bottom: 10px;
        """)
        layout.addWidget(warning)
        
        # Azure toolkit controls using factory
        try:
            from app.core.control_panel_factory import ControlPanelFactory
            from app.core.tool_helpers import load_tool_configs
            
            tool_configs = load_tool_configs()
            if 'azure_toolkit' in tool_configs:
                azure_controls = ControlPanelFactory.create_panel(tool_configs['azure_toolkit'], self)
                
                # Connect authentication method changes
                if hasattr(azure_controls, 'controls') and 'azure_auth_method' in azure_controls.controls:
                    azure_controls.controls['azure_auth_method'].currentTextChanged.connect(
                        lambda auth_method: self.toggle_azure_auth_fields(azure_controls.controls, auth_method)
                    )
                    # Set initial state
                    self.toggle_azure_auth_fields(azure_controls.controls, "Default Credential")
                
                layout.addWidget(azure_controls)
                
                # Add run button
                run_btn = QPushButton("🚀 Run Azure Scan")
                run_btn.setMinimumHeight(50)
                run_btn.setStyleSheet("""
                    QPushButton {
                        background-color: #0078D4;
                        color: white;
                        font-size: 14pt;
                        font-weight: bold;
                        border-radius: 8px;
                        padding: 10px;
                    }
                    QPushButton:hover {
                        background-color: #106EBE;
                    }
                """)
                run_btn.clicked.connect(lambda: self.run_azure_scan(azure_controls.controls))
                layout.addWidget(run_btn)
            else:
                # Fallback if config not found
                error_label = QLabel("Azure toolkit configuration not found")
                error_label.setStyleSheet("color: #FF6B6B; font-size: 14pt;")
                layout.addWidget(error_label)
        except ImportError:
            layout.addWidget(QLabel("Azure toolkit functionality will be available here"))
        
        layout.addStretch()
        return tab
    
    def create_ad_tab(self):
        """Create Active Directory enumeration tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # AD enumeration widget
        try:
            from app.widgets.ad_enumeration_widget import ADEnumerationWidget
            ad_widget = ADEnumerationWidget(self)
            layout.addWidget(ad_widget)
        except ImportError:
            # Show feature info when not available
            info_frame = QFrame()
            info_layout = QVBoxLayout(info_frame)
            
            info_label = QLabel("🏢 Active Directory Enumeration & Attacks")
            info_label.setStyleSheet("color: #64C8FF; font-size: 16pt; font-weight: bold;")
            info_layout.addWidget(info_label)
            
            desc_label = QLabel("Comprehensive AD enumeration, privilege escalation, and attack techniques")
            desc_label.setStyleSheet("color: #DCDCDC; font-size: 12pt; padding: 10px;")
            info_layout.addWidget(desc_label)
            
            features_label = QLabel("• Domain enumeration\n• User and group analysis\n• Kerberos attacks\n• Privilege escalation\n• Lateral movement techniques")
            features_label.setStyleSheet("color: #87CEEB; font-size: 11pt; padding: 10px;")
            info_layout.addWidget(features_label)
            
            info_layout.addStretch()
            layout.addWidget(info_frame)
        
        return tab
    
    def apply_terminal_theme_to_widget(self, widget):
        """Apply theme-specific styling to any terminal widget"""
        current_theme = getattr(self.main_window, 'current_theme', 'dark_blue')
        
        if current_theme == 'matrix':
            widget.setStyleSheet("""
                QTextEdit {
                    background-color: #000000;
                    color: #00FF41;
                    font-family: 'Share Tech Mono', monospace;
                    font-size: 11pt;
                    border: 1px solid #00FF41;
                    border-radius: 5px;
                    selection-background-color: #003300;
                }
            """)
        else:
            widget.setStyleSheet("""
                QTextEdit {
                    background-color: #1E1E1E;
                    color: #DCDCDC;
                    font-family: 'Neuropol X', monospace;
                    font-size: 10pt;
                    border: 1px solid rgba(100, 200, 255, 100);
                    border-radius: 5px;
                    selection-background-color: #2D4F7C;
                }
            """)
    
    def run_port_scan(self):
        """Run port scan - fallback implementation"""
        target = getattr(self, 'port_target_input', None)
        if not target or not target.text().strip():
            self.status_updated.emit("Please enter a target for port scanning")
            return
        
        target_text = target.text().strip()
        
        # Try to use mixin implementation first
        if hasattr(super(), 'run_port_scan'):
            super().run_port_scan()
        else:
            # Fallback implementation
            if hasattr(self, 'port_results'):
                self.port_results.clear()
                self.port_results.append(f"🚀 Starting port scan on {target_text}...")
                self.port_results.append("⏳ Scan in progress...")
            
            self.status_updated.emit(f"Port scan started for {target_text}")
    
    def run_dns_scan(self):
        """Run DNS enumeration - fallback implementation"""
        target = getattr(self, 'dns_target_input', None)
        if not target or not target.text().strip():
            self.status_updated.emit("Please enter a target domain for DNS enumeration")
            return
        
        target_text = target.text().strip()
        
        # Get selected record types
        selected_types = []
        if hasattr(self, 'dns_record_types'):
            selected_types = [rtype for rtype, cb in self.dns_record_types.items() if cb.isChecked()]
        
        if not selected_types:
            selected_types = ['A']  # Default
        
        # Try to use advanced DNS scanning if available
        try:
            from app.tools import dns_utils
            tenant_id = getattr(self.main_window, 'current_profile_name', 'default')
            
            # Clear terminal before starting new scan
            if hasattr(self, 'dns_terminal'):
                self.dns_terminal.clear()
                self.append_dns_output(f"<p style='color: #00BFFF;'>[DNS SCAN] Starting enumeration for {target_text}</p><br>")
            
            # Set button state
            if hasattr(self, 'dns_run_button'):
                self.dns_run_button.setText("End")
                if hasattr(self.dns_run_button, 'start_pulse'):
                    self.dns_run_button.start_pulse("#FF0000")
            
            # Show progress widget
            if hasattr(self, 'dns_progress_widget') and self.dns_progress_widget:
                self.dns_progress_widget.setVisible(True)
                self.dns_progress_widget.reset_progress()
            
            # Get method and wordlist
            method = getattr(self, 'method_combo', None)
            wordlist_combo = getattr(self, 'wordlist_combo', None)
            wordlist_path = wordlist_combo.currentData() if wordlist_combo else None
            
            # Get global DNS server setting
            from app.core.dns_settings import dns_settings
            dns_server = dns_settings.get_current_dns()
            if dns_server == "Default DNS":
                dns_server = None
            
            # Run DNS enumeration
            self.current_worker = dns_utils.enumerate_hostnames(
                target_text,
                wordlist_path,
                self.append_dns_output,
                self.status_updated.emit,
                self.on_dns_scan_finished,
                record_types=selected_types,
                use_bruteforce=(method.currentText() == "Bruteforce" if method else False),
                char_sets=[k for k, v in getattr(self, 'char_checkboxes', {}).items() if v.isChecked()] if hasattr(self, 'char_checkboxes') else [],
                max_length=getattr(self, 'length_spinbox', None).value() if hasattr(self, 'length_spinbox') else 3,
                dns_server=dns_server,
                results_callback=self.store_dns_results,
                progress_callback=self.update_dns_progress,
                progress_start_callback=self.start_dns_progress,
                tenant_id=tenant_id
            )
            
            self.dns_scanning = True
            self.dns_scan_results = {}
            
        except ImportError:
            # Fallback implementation
            if hasattr(self, 'dns_results'):
                self.dns_results.clear()
                self.dns_results.append(f"🚀 Starting DNS enumeration for {target_text}...")
                self.dns_results.append(f"📊 Record types: {', '.join(selected_types)}")
                self.dns_results.append("⏳ Enumeration in progress...")
            
            self.status_updated.emit(f"DNS enumeration started for {target_text}")
    
    def run_service_scan(self, tool_key):
        """Run service enumeration scan - fallback implementation"""
        target_input = getattr(self, f"{tool_key}_target_input", None)
        if not target_input:
            return
        
        target = target_input.text().strip()
        if not target:
            self.status_updated.emit(f"Please enter a target for {tool_key} enumeration")
            return
        
        # Try to use mixin implementation first
        if hasattr(super(), 'run_service_scan'):
            super().run_service_scan(tool_key)
        else:
            # Fallback implementation
            results_area = getattr(self, f"{tool_key}_results", None)
            if results_area:
                results_area.clear()
                results_area.append(f"🚀 Starting {tool_key} enumeration on {target}...")
                results_area.append("⏳ Enumeration in progress...")
            
            self.status_updated.emit(f"{tool_key} enumeration started for {target}")
    
    # Placeholder methods for DNS functionality
    def toggle_dns_scan(self):
        """Toggle DNS scan"""
        if getattr(self, 'dns_scanning', False):
            self.cancel_dns_scan()
        else:
            self.run_dns_scan()
    
    def cancel_dns_scan(self):
        """Cancel DNS scan"""
        if hasattr(self, 'current_worker') and self.current_worker:
            self.current_worker.is_running = False
        
        self.dns_scanning = False
        
        # Reset button state
        if hasattr(self, 'dns_run_button'):
            self.dns_run_button.setText("Run")
            if hasattr(self.dns_run_button, 'stop_pulse'):
                self.dns_run_button.stop_pulse()
        
        # Hide progress widget
        if hasattr(self, 'dns_progress_widget') and self.dns_progress_widget:
            self.dns_progress_widget.setVisible(False)
        
        self.append_dns_output("<p style='color: #FFAA00;'>[SCAN] DNS enumeration cancelled</p><br>")
        self.status_updated.emit("DNS scan cancelled")
    
    def append_dns_output(self, text):
        """Append DNS output"""
        if hasattr(self, 'dns_terminal'):
            self.dns_terminal.insertHtml(text)
    
    def store_dns_results(self, results):
        """Store DNS results"""
        self.dns_scan_results = results
        
        # Update table and tree views if they exist
        if hasattr(self, 'dns_table') and self.dns_table:
            self.update_dns_table(results)
        if hasattr(self, 'dns_tree') and self.dns_tree:
            self.update_dns_tree(results)
    
    def on_dns_scan_finished(self):
        """Handle DNS scan completion"""
        self.dns_scanning = False
        
        # Reset button state
        if hasattr(self, 'dns_run_button'):
            self.dns_run_button.setText("Run")
            if hasattr(self.dns_run_button, 'stop_pulse'):
                self.dns_run_button.stop_pulse()
        
        # Hide progress widget
        if hasattr(self, 'dns_progress_widget') and self.dns_progress_widget:
            self.dns_progress_widget.setVisible(False)
        
        # Enable export button if we have results
        if hasattr(self, 'dns_export_button') and hasattr(self, 'dns_scan_results') and self.dns_scan_results:
            self.dns_export_button.setEnabled(True)
    
    def start_dns_progress(self, total):
        """Start DNS progress"""
        if hasattr(self, 'dns_progress_widget') and self.dns_progress_widget:
            self.dns_progress_widget.start_progress(total, "DNS enumeration...")
    
    def update_dns_progress(self, completed, found, message=""):
        """Update DNS progress"""
        if hasattr(self, 'dns_progress_widget') and self.dns_progress_widget:
            self.dns_progress_widget.update_progress(completed, found, message)
    
    def set_dns_view(self, view_type):
        """Set DNS view"""
        self.current_dns_view = view_type
        
        # Update button states
        if hasattr(self, 'text_view_btn'):
            self.text_view_btn.setChecked(view_type == "text")
        if hasattr(self, 'table_view_btn'):
            self.table_view_btn.setChecked(view_type == "table")
        if hasattr(self, 'graph_view_btn'):
            self.graph_view_btn.setChecked(view_type == "graph")
        
        # Switch view
        if hasattr(self, 'dns_results_stack'):
            if view_type == "text":
                self.dns_results_stack.setCurrentIndex(0)
            elif view_type == "table":
                self.dns_results_stack.setCurrentIndex(1)
                # Update table if we have results
                if hasattr(self, 'dns_scan_results') and self.dns_scan_results:
                    self.update_dns_table(self.dns_scan_results)
            elif view_type == "graph":
                self.dns_results_stack.setCurrentIndex(2)
                # Update tree if we have results
                if hasattr(self, 'dns_scan_results') and self.dns_scan_results:
                    self.update_dns_tree(self.dns_scan_results)
    
    def update_dns_table(self, results):
        """Update DNS table with results"""
        if not self.dns_table:
            return
        
        from PyQt6.QtWidgets import QTableWidgetItem
        
        self.dns_table.setRowCount(0)
        row = 0
        
        for domain, record_types in results.items():
            for record_type, values in record_types.items():
                for value in values:
                    self.dns_table.insertRow(row)
                    self.dns_table.setItem(row, 0, QTableWidgetItem(domain))
                    self.dns_table.setItem(row, 1, QTableWidgetItem(record_type))
                    self.dns_table.setItem(row, 2, QTableWidgetItem(value))
                    row += 1
        
        self.dns_table.resizeColumnsToContents()
    
    def update_dns_tree(self, results):
        """Update DNS tree with results"""
        if not self.dns_tree:
            return
        
        from PyQt6.QtWidgets import QTreeWidgetItem
        
        self.dns_tree.clear()
        
        for domain, record_types in results.items():
            domain_item = QTreeWidgetItem(self.dns_tree, [domain, "Domain", ""])
            
            for record_type, values in record_types.items():
                type_item = QTreeWidgetItem(domain_item, [record_type, "Record Type", f"{len(values)} records"])
                
                for value in values:
                    QTreeWidgetItem(type_item, ["", "Value", value])
                
                type_item.setExpanded(True)
            
            domain_item.setExpanded(True)
        
        self.dns_tree.resizeColumnToContents(0)
        self.dns_tree.resizeColumnToContents(1)
    
    def populate_dns_wordlists(self):
        """Populate DNS wordlist dropdown"""
        if not hasattr(self, 'wordlist_combo'):
            return
        
        try:
            wordlist_dir = os.path.join(self.main_window.project_root, "resources", "wordlists", "dns_enum")
            if os.path.exists(wordlist_dir):
                for file in os.listdir(wordlist_dir):
                    if file.endswith('.txt'):
                        file_path = os.path.join(wordlist_dir, file)
                        self.wordlist_combo.addItem(file, file_path)
            else:
                self.wordlist_combo.addItem("Default wordlist", None)
        except:
            self.wordlist_combo.addItem("Default wordlist", None)
    
    def toggle_method_options(self, method):
        """Toggle between wordlist and bruteforce options"""
        show_wordlist = (method == "Wordlist")
        show_bruteforce = (method == "Bruteforce")
        
        # Toggle wordlist visibility
        if hasattr(self, 'wordlist_combo'):
            self.wordlist_combo.setVisible(show_wordlist)
        
        # Toggle bruteforce options visibility
        if hasattr(self, 'bruteforce_label'):
            self.bruteforce_label.setVisible(show_bruteforce)
        if hasattr(self, 'char_checkboxes'):
            for cb in self.char_checkboxes.values():
                cb.setVisible(show_bruteforce)
        if hasattr(self, 'length_label'):
            self.length_label.setVisible(show_bruteforce)
        if hasattr(self, 'length_spinbox'):
            self.length_spinbox.setVisible(show_bruteforce)
    
    def toggle_all_records(self, state):
        """Toggle all record type checkboxes"""
        if hasattr(self, 'dns_record_types'):
            for cb in self.dns_record_types.values():
                cb.setChecked(state == 2)  # 2 = Qt.CheckState.Checked
        if hasattr(self, 'ptr_checkbox'):
            self.ptr_checkbox.setChecked(state == 2)
    
    def update_all_checkbox(self):
        """Update ALL checkbox based on individual checkboxes"""
        if not hasattr(self, 'all_checkbox') or not hasattr(self, 'dns_record_types'):
            return
        
        all_checked = True
        any_checked = False
        
        for cb in self.dns_record_types.values():
            if cb.isChecked():
                any_checked = True
            else:
                all_checked = False
        
        if hasattr(self, 'ptr_checkbox') and self.ptr_checkbox.isEnabled():
            if self.ptr_checkbox.isChecked():
                any_checked = True
            else:
                all_checked = False
        
        if all_checked:
            self.all_checkbox.setCheckState(2)  # Checked
        elif any_checked:
            self.all_checkbox.setCheckState(1)  # Partially checked
        else:
            self.all_checkbox.setCheckState(0)  # Unchecked
    
    def check_dns_target_type(self, text):
        """Check if target is IP address to enable/disable PTR checkbox"""
        if hasattr(self, 'ptr_checkbox'):
            import re
            # Simple IP pattern check
            ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.'  # Partial IP or range
            is_ip_like = bool(re.match(ip_pattern, text))
            self.ptr_checkbox.setEnabled(is_ip_like)
            if not is_ip_like:
                self.ptr_checkbox.setChecked(False)
    
    def apply_terminal_theme(self):
        """Apply terminal theme to DNS terminal"""
        if hasattr(self, 'dns_terminal'):
            self.apply_terminal_theme_to_widget(self.dns_terminal)
    
    def export_dns_results(self):
        """Export DNS results"""
        if not hasattr(self, 'dns_scan_results') or not self.dns_scan_results:
            self.status_updated.emit("No DNS results to export")
            return
        
        try:
            from app.core.exporter import exporter
            
            target = self.dns_target_input.text().strip() or "dns_target"
            export_format = self.dns_export_combo.currentText().lower()
            
            success, filepath, message = exporter.export_results(
                self.dns_scan_results,
                target,
                export_format,
                scan_type="dns_enum"
            )
            
            if success:
                self.append_dns_output(f"<p style='color: #00FF41;'>[EXPORT] Results exported to {filepath}</p><br>")
                self.status_updated.emit(f"DNS results exported to {filepath}")
            else:
                self.append_dns_output(f"<p style='color: #FF4500;'>[EXPORT ERROR] {message}</p><br>")
                self.status_updated.emit(f"Export failed: {message}")
        except Exception as e:
            self.append_dns_output(f"<p style='color: #FF4500;'>[EXPORT ERROR] Export failed: {str(e)}</p>")
            self.status_updated.emit(f"DNS export error: {str(e)}")
    
    def toggle_azure_auth_fields(self, controls, auth_method):
        """Toggle Azure authentication fields"""
        show_client_secret = (auth_method == "Client Secret")
        
        if 'azure_tenant_id' in controls:
            controls['azure_tenant_id'].setVisible(show_client_secret)
        if 'azure_client_id' in controls:
            controls['azure_client_id'].setVisible(show_client_secret)
        if 'azure_client_secret' in controls:
            controls['azure_client_secret'].setVisible(show_client_secret)
    
    def run_azure_scan(self, controls):
        """Run Azure scan"""
        self.status_updated.emit("Azure scan functionality will be available here")