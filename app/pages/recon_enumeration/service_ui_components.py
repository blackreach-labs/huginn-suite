# app/pages/recon_enumeration/service_ui_components.py
import os
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
                             QStackedWidget, QTextEdit, QTableWidget, QTreeWidget, 
                             QComboBox, QPushButton, QToolButton, QSpacerItem, QSizePolicy)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon
from app.core.logger import logger

class ServiceUIComponentsMixin:
    """Mixin for service enumeration UI components"""
    
    def create_service_subtab(self, service_name, tool_key):
        """Create a generic service enumeration sub-tab with full functionality"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(3)
        
        # Target field
        target_layout = QHBoxLayout()
        target_label = QLabel("Target:")
        target_label.setFixedWidth(100)
        target_layout.addWidget(target_label)
        
        target_input = QLineEdit()
        target_input.setPlaceholderText("Enter target (IP or hostname)")
        target_input.returnPressed.connect(lambda: self.run_service_scan(tool_key))
        target_layout.addWidget(target_input)
        layout.addLayout(target_layout)
        
        # Store target input reference
        setattr(self, f"{tool_key}_target_input", target_input)
        

        
        # Load proper tool configuration from JSON
        try:
            from app.core.control_panel_factory import ControlPanelFactory
            from app.core.tool_helpers import load_tool_configs
            
            tool_configs = load_tool_configs()
            tool_config_key = tool_key.replace('_enum', '').replace('_detect', '')
            
            if tool_config_key == 'av':
                tool_config_key = 'av_firewall'
            elif tool_config_key == 'db':
                tool_config_key = 'db'
            
            if tool_config_key in tool_configs:
                controls = ControlPanelFactory.create_panel(tool_configs[tool_config_key], self)
                controls.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
                layout.addWidget(controls)
                
                # Store control panel reference
                setattr(self, f"{tool_key}_control_panel", controls)
                
                # Setup field interactions based on tool type
                self.setup_service_field_interactions(tool_key, controls)
                
                # Force initial field visibility
                self._setup_initial_field_visibility(tool_key, controls)
                
                # Populate wordlists for tools that need them
                self.populate_service_wordlists(tool_key, controls)
            else:
                layout.addWidget(QLabel(f"{service_name} enumeration controls will be available here"))
                
        except Exception:
            # Fallback if control factory not available
            layout.addWidget(QLabel(f"{service_name} enumeration controls will be available here"))
        
        # Controls row with run button and view toggles
        controls_row = self._create_service_controls_row(tool_key)
        layout.addLayout(controls_row)
        
        # Add results stack with multiple views - give it maximum space
        results_stack = self._create_service_results_stack(tool_key, service_name)
        layout.addWidget(results_stack, 1)
        
        # Initialize state
        self._initialize_service_state(tool_key)
        
        return tab
    
    def _setup_initial_field_visibility(self, tool_key, controls):
        """Setup initial field visibility for all tools"""
        if tool_key == 'rpc_enum' and 'rpc_auth_combo' in controls.controls:
            from PyQt6.QtCore import QTimer
            # Hide all auth fields by default, then set based on current selection
            QTimer.singleShot(0, lambda: self.toggle_rpc_auth_fields(tool_key, "Anonymous"))
            # Get current auth selection and apply it
            current_auth = controls.controls['rpc_auth_combo'].currentText()
            QTimer.singleShot(10, lambda: self.toggle_rpc_auth_fields(tool_key, current_auth))
        elif tool_key == 'smb_enum' and 'smb_auth_combo' in controls.controls:
            from PyQt6.QtCore import QTimer
            QTimer.singleShot(0, lambda: self.toggle_smb_auth_fields(tool_key, "Anonymous"))
            # Set initial scan type to Basic Info
            QTimer.singleShot(5, lambda: self.on_smb_scan_type_changed(tool_key, "Basic Info"))
        elif tool_key == 'http_enum':
            from PyQt6.QtCore import QTimer
            # Set initial scan type to Fingerprinting (which hides all optional fields)
            QTimer.singleShot(0, lambda: self.on_http_scan_type_changed(tool_key, "Fingerprinting"))
            # Set initial auth method to None (which hides auth fields)
            QTimer.singleShot(5, lambda: self.toggle_http_auth_fields(tool_key, "None"))
            # Show listener options for Fingerprinting by default
            QTimer.singleShot(10, lambda: self.toggle_http_listener_options(tool_key, "Fingerprinting"))
        elif tool_key == 'av_detect' and 'av_detection_type' in controls.controls:
            from PyQt6.QtCore import QTimer
            QTimer.singleShot(0, lambda: self.toggle_av_fields(tool_key, "WAF Detection"))
        elif tool_key == 'db_enum' and 'db_type_combo' in controls.controls:
            from PyQt6.QtCore import QTimer
            QTimer.singleShot(0, lambda: self.toggle_db_fields(tool_key, "MSSQL"))
        elif tool_key == 'snmp_enum' and 'snmp_version' in controls.controls:
            from PyQt6.QtCore import QTimer
            QTimer.singleShot(0, lambda: self.toggle_snmp_fields(tool_key, "2c"))
        elif tool_key == 'ssh_enum' and 'ssh_auth_type' in controls.controls:
            from PyQt6.QtCore import QTimer
            QTimer.singleShot(0, lambda: self.toggle_ssh_auth_fields(tool_key, "Anonymous"))
    
    def _create_service_controls_row(self, tool_key):
        """Create controls row with run button and view toggles"""
        controls_row = QHBoxLayout()
        
        # Run button
        try:
            from app.ui.animations.universal_run_button import UniversalRunButton
            run_button = UniversalRunButton("Run")
        except ImportError:
            run_button = QPushButton("Run")
        run_button.setFixedWidth(80)
        run_button.clicked.connect(lambda: self.toggle_service_scan(tool_key))
        controls_row.addWidget(run_button)
        
        # Store run button reference
        setattr(self, f"{tool_key}_run_button", run_button)
        
        # Progress widget
        try:
            from app.widgets.progress_widget import ProgressWidget
            progress_widget = ProgressWidget()
            progress_widget.setVisible(False)
        except ImportError:
            progress_widget = None
        
        # Add spacer
        spacer = QSpacerItem(0, 0, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        controls_row.addItem(spacer)
        if progress_widget:
            controls_row.addWidget(progress_widget, 1)
        
        # Store progress widget reference
        setattr(self, f"{tool_key}_progress_widget", progress_widget)
        
        # View toggle buttons
        text_icon_path = os.path.join(self.main_window.project_root, "resources", "icons", "text.png")
        table_icon_path = os.path.join(self.main_window.project_root, "resources", "icons", "table.png")
        
        text_view_btn = QToolButton()
        if os.path.exists(text_icon_path):
            text_view_btn.setIcon(QIcon(text_icon_path))
        else:
            text_view_btn.setText("Text")
        text_view_btn.setFixedWidth(40)
        text_view_btn.setCheckable(True)
        text_view_btn.setChecked(True)
        text_view_btn.clicked.connect(lambda: self.set_service_view(tool_key, "text"))
        controls_row.addWidget(text_view_btn)
        
        # Second view button - Graph for HTTP/RPC/SMB/SSH/DB, Table for others
        if tool_key in ["http_enum", "rpc_enum", "smb_enum", "ssh_enum", "db_enum"]:
            # Graph/Tree view button
            graph_icon_path = os.path.join(self.main_window.project_root, "resources", "icons", "graph.png")
            graph_view_btn = QToolButton()
            if os.path.exists(graph_icon_path):
                graph_view_btn.setIcon(QIcon(graph_icon_path))
            else:
                graph_view_btn.setText("Tree" if tool_key in ["rpc_enum", "smb_enum", "ssh_enum", "db_enum"] else "Graph")
            graph_view_btn.setFixedWidth(40)
            graph_view_btn.setCheckable(True)
            graph_view_btn.clicked.connect(lambda: self.set_service_view(tool_key, "graph"))
            controls_row.addWidget(graph_view_btn)
            setattr(self, f"{tool_key}_graph_view_btn", graph_view_btn)
            
            # Table view button (only for HTTP, RPC, SMB, and DB, not SSH)
            if tool_key != "ssh_enum":
                table_view_btn = QToolButton()
                if os.path.exists(table_icon_path):
                    table_view_btn.setIcon(QIcon(table_icon_path))
                else:
                    table_view_btn.setText("Table")
                table_view_btn.setFixedWidth(40)
                table_view_btn.setCheckable(True)
                table_view_btn.clicked.connect(lambda: self.set_service_view(tool_key, "table"))
                if tool_key == "http_enum":
                    table_view_btn.setVisible(False)  # Hidden by default for HTTP Fingerprinting
                controls_row.addWidget(table_view_btn)
                setattr(self, f"{tool_key}_table_view_btn", table_view_btn)
        else:
            table_view_btn = QToolButton()
            if os.path.exists(table_icon_path):
                table_view_btn.setIcon(QIcon(table_icon_path))
            else:
                table_view_btn.setText("Table")
            table_view_btn.setFixedWidth(40)
            table_view_btn.setCheckable(True)
            table_view_btn.clicked.connect(lambda: self.set_service_view(tool_key, "table"))
            controls_row.addWidget(table_view_btn)
            setattr(self, f"{tool_key}_table_view_btn", table_view_btn)
        
        # Store view button references
        setattr(self, f"{tool_key}_text_view_btn", text_view_btn)
        
        # Export button
        export_combo = QComboBox()
        export_combo.addItems(["JSON", "CSV", "XML", "HTML"])
        export_combo.setFixedWidth(120)
        controls_row.addWidget(export_combo)
        
        export_button = QPushButton("Export")
        export_button.setFixedWidth(85)
        export_button.setEnabled(False)
        export_button.clicked.connect(lambda: self.export_service_results(tool_key))
        controls_row.addWidget(export_button)
        
        # Store export references
        setattr(self, f"{tool_key}_export_combo", export_combo)
        setattr(self, f"{tool_key}_export_button", export_button)
        
        return controls_row
    
    def _create_service_results_stack(self, tool_key, service_name):
        """Create results stack with multiple views"""
        results_stack = QStackedWidget()
        
        # For HTTP enumeration, create separate terminals for each scan type
        if tool_key == "http_enum":
            # Create terminals for each scan type
            terminals = {}
            tables = {}
            scan_types = ["Fingerprinting", "Directory Enum", "Source Code", "Crawler", "VHost Brute", "Enterprise Scripts", "Huginn Scan", "Full Scan"]
            
            for scan_type in scan_types:
                # Text view (terminal) for this scan type
                terminal = QTextEdit()
                terminal.setReadOnly(True)
                self.apply_terminal_theme_to_widget(terminal)
                terminal.setPlaceholderText(f"{scan_type} results will appear here...")
                terminals[scan_type] = terminal
                
                # Create appropriate second view based on scan type
                if scan_type == "Fingerprinting":
                    # Graph view for Fingerprinting
                    try:
                        from app.widgets.crawl_tree_widget import CrawlTreeWidget
                        graph_view = CrawlTreeWidget()
                        tables[scan_type] = graph_view  # Store in tables dict for consistency
                    except ImportError:
                        # Fallback to simple table
                        table = QTableWidget()
                        table.setColumnCount(3)
                        table.setHorizontalHeaderLabels(["Service", "Port", "Details"])
                        tables[scan_type] = table
                elif scan_type == "Source Code":
                    # Tree view for Source Code
                    try:
                        from app.widgets.crawl_tree_widget import CrawlTreeWidget
                        tree_view = CrawlTreeWidget()
                        tables[scan_type] = tree_view
                    except ImportError:
                        # Fallback to simple tree
                        tree = QTreeWidget()
                        tree.setHeaderLabels(["Finding", "Type", "Details"])
                        tree.setRootIsDecorated(True)
                        tables[scan_type] = tree
                elif scan_type == "Crawler":
                    # Tree view for Crawler (no table view)
                    try:
                        from app.widgets.crawl_tree_widget import CrawlTreeWidget
                        tree_view = CrawlTreeWidget()
                        tables[scan_type] = tree_view
                    except ImportError:
                        # Fallback to simple tree widget for Crawler
                        tree = QTreeWidget()
                        tree.setHeaderLabels(["URL", "Title", "Status"])
                        tree.setRootIsDecorated(True)
                        tables[scan_type] = tree
                elif scan_type == "Directory Enum":
                    # Tree view for Directory Enum (graph view)
                    tree = QTreeWidget()
                    tree.setHeaderLabels(["Path/Status", "Size/Count", "Details"])
                    tree.setRootIsDecorated(True)
                    tables[scan_type] = tree
                elif scan_type == "Enterprise Scripts":
                    # Tree view for Enterprise Scripts using CrawlTreeWidget
                    try:
                        from app.widgets.crawl_tree_widget import CrawlTreeWidget
                        tree_view = CrawlTreeWidget()
                        tables[scan_type] = tree_view
                    except ImportError:
                        # Fallback to simple tree widget for Enterprise Scripts
                        tree = QTreeWidget()
                        tree.setHeaderLabels(["Category", "Value", "Type"])
                        tree.setRootIsDecorated(True)
                        tables[scan_type] = tree
                elif scan_type == "Full Scan":
                    # Table view for Full Scan
                    table = QTableWidget()
                    table.setColumnCount(4)
                    table.setHorizontalHeaderLabels(["Category", "Item", "Status/Value", "Details"])
                    tables[scan_type] = table
                else:
                    # Table view for other scan types
                    table = QTableWidget()
                    table.setColumnCount(3)
                    table.setHorizontalHeaderLabels(["Service", "Port", "Details"])
                    tables[scan_type] = table
            
            # Add current scan type views to stack (start with Fingerprinting)
            results_stack.addWidget(terminals["Fingerprinting"])  # Text view
            results_stack.addWidget(tables["Fingerprinting"])     # Graph view
            
            # For Directory Enum, also create a table view (separate from tree)
            if "Directory Enum" in tables:
                dir_table = QTableWidget()
                dir_table.setColumnCount(3)
                dir_table.setHorizontalHeaderLabels(["Path", "Status", "Size"])
                setattr(self, f"{tool_key}_dir_table", dir_table)
            
            # Store references
            setattr(self, f"{tool_key}_terminals", terminals)
            setattr(self, f"{tool_key}_tables", tables)
            setattr(self, f"{tool_key}_current_scan_type", "Fingerprinting")
            
        elif tool_key == "rpc_enum":
            # RPC enumeration with separate terminals for each scan type
            terminals = {}
            tables = {}
            trees = {}
            scan_types = ["Basic Info", "Full Enumeration", "Vulnerability Scan", "Complete Assessment"]
            
            for scan_type in scan_types:
                # Text view (terminal) for this scan type
                terminal = QTextEdit()
                terminal.setReadOnly(True)
                self.apply_terminal_theme_to_widget(terminal)
                terminal.setPlaceholderText(f"{scan_type} results will appear here...")
                terminals[scan_type] = terminal
                
                # Table view for this scan type
                table = QTableWidget()
                table.setColumnCount(3)
                table.setHorizontalHeaderLabels(["Service", "Port", "Details"])
                tables[scan_type] = table
                
                # Tree view for this scan type
                tree = QTreeWidget()
                tree.setHeaderLabels(["Category", "Count", "Details"])
                tree.setRootIsDecorated(True)
                trees[scan_type] = tree
            
            # Add current scan type views to stack
            results_stack.addWidget(terminals["Basic Info"])  # Default - Text view
            results_stack.addWidget(trees["Basic Info"])      # Tree view
            results_stack.addWidget(tables["Basic Info"])     # Table view
            
            # Store references
            setattr(self, f"{tool_key}_terminals", terminals)
            setattr(self, f"{tool_key}_tables", tables)
            setattr(self, f"{tool_key}_trees", trees)
            setattr(self, f"{tool_key}_current_scan_type", "Basic Info")
        
        elif tool_key == "ssh_enum":
            # SSH enumeration with separate terminals for each scan type
            terminals = {}
            tables = {}
            trees = {}
            scan_types = ["Enumeration", "Banner Grab", "Key Exchange", "Cipher Analysis", "Full Scan"]
            
            for scan_type in scan_types:
                # Text view (terminal) for this scan type
                terminal = QTextEdit()
                terminal.setReadOnly(True)
                self.apply_terminal_theme_to_widget(terminal)
                terminal.setPlaceholderText(f"{scan_type} results will appear here...")
                terminals[scan_type] = terminal
                
                # Table view for this scan type
                table = QTableWidget()
                table.setColumnCount(3)
                table.setHorizontalHeaderLabels(["Item", "Value", "Details"])
                tables[scan_type] = table
                
                # Tree view for this scan type
                tree = QTreeWidget()
                tree.setHeaderLabels(["Category", "Count", "Details"])
                tree.setRootIsDecorated(True)
                trees[scan_type] = tree
            
            # Add current scan type views to stack (only text and graph for SSH)
            results_stack.addWidget(terminals["Enumeration"])  # Default - Text view
            results_stack.addWidget(trees["Enumeration"])      # Tree view only
            
            # Store references
            setattr(self, f"{tool_key}_terminals", terminals)
            setattr(self, f"{tool_key}_tables", tables)
            setattr(self, f"{tool_key}_trees", trees)
            setattr(self, f"{tool_key}_current_scan_type", "Enumeration")
        elif tool_key == "smb_enum":
            # SMB enumeration with separate terminals for each scan type
            terminals = {}
            tables = {}
            trees = {}
            scan_types = ["Basic Info", "Share Enumeration"]
            
            for scan_type in scan_types:
                # Text view (terminal) for this scan type
                terminal = QTextEdit()
                terminal.setReadOnly(True)
                self.apply_terminal_theme_to_widget(terminal)
                terminal.setPlaceholderText(f"{scan_type} results will appear here...")
                terminals[scan_type] = terminal
                
                # Table view for this scan type
                table = QTableWidget()
                table.setColumnCount(3)
                table.setHorizontalHeaderLabels(["Share", "Type", "Details"])
                tables[scan_type] = table
                
                # Tree view for this scan type
                tree = QTreeWidget()
                tree.setHeaderLabels(["Category", "Count", "Details"])
                tree.setRootIsDecorated(True)
                trees[scan_type] = tree
            
            # Add current scan type views to stack (start with Basic Info)
            results_stack.addWidget(terminals["Basic Info"])  # Default - Text view
            results_stack.addWidget(trees["Basic Info"])      # Tree view
            results_stack.addWidget(tables["Basic Info"])     # Table view
            
            # Store references
            setattr(self, f"{tool_key}_terminals", terminals)
            setattr(self, f"{tool_key}_tables", tables)
            setattr(self, f"{tool_key}_trees", trees)
            setattr(self, f"{tool_key}_current_scan_type", "Basic Info")
        elif tool_key == "db_enum":
            # Database enumeration with separate terminals for each scan type
            terminals = {}
            tables = {}
            trees = {}
            scan_types = ["Basic Info", "Scripts", "Full Scan"]
            
            for scan_type in scan_types:
                # Text view (terminal) for this scan type - minimal interaction flags to prevent crashes
                terminal = QTextEdit()
                terminal.setReadOnly(True)
                terminal.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
                self.apply_terminal_theme_to_widget(terminal)
                terminal.setPlaceholderText(f"{scan_type} results will appear here...")
                terminals[scan_type] = terminal
                
                # Table view for this scan type
                table = QTableWidget()
                table.setColumnCount(3)
                table.setHorizontalHeaderLabels(["Property", "Value", "Details"])
                tables[scan_type] = table
                
                # Tree view for this scan type
                tree = QTreeWidget()
                tree.setHeaderLabels(["Category", "Count", "Details"])
                tree.setRootIsDecorated(True)
                trees[scan_type] = tree
            
            # Add current scan type views to stack (start with Basic Info)
            results_stack.addWidget(terminals["Basic Info"])  # Default - Text view
            results_stack.addWidget(trees["Basic Info"])      # Tree view
            results_stack.addWidget(tables["Basic Info"])     # Table view
            
            # Store references
            setattr(self, f"{tool_key}_terminals", terminals)
            setattr(self, f"{tool_key}_tables", tables)
            setattr(self, f"{tool_key}_trees", trees)
            setattr(self, f"{tool_key}_current_scan_type", "Basic Info")
        else:
            # Regular single terminal for other tools
            terminal = QTextEdit()
            terminal.setReadOnly(True)
            self.apply_terminal_theme_to_widget(terminal)
            terminal.setPlaceholderText(f"{service_name} enumeration results will appear here...")
            results_stack.addWidget(terminal)
            
            # Table view
            table = QTableWidget()
            table.setColumnCount(3)
            table.setHorizontalHeaderLabels(["Service", "Port", "Details"])
            results_stack.addWidget(table)
            
            # Store references
            setattr(self, f"{tool_key}_terminal", terminal)
            setattr(self, f"{tool_key}_table", table)
        
        # Set size policy to expand and use all available space
        results_stack.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        
        # Store references
        setattr(self, f"{tool_key}_results_stack", results_stack)
        
        return results_stack
    
    def _initialize_service_state(self, tool_key):
        """Initialize service state variables"""
        setattr(self, f"{tool_key}_scan_results", {})
        setattr(self, f"{tool_key}_scanning", False)
        setattr(self, f"current_{tool_key}_view", "text")
    
    def populate_service_wordlists(self, tool_key, control_panel):
        """Populate wordlists for service enumeration tools"""
        if not hasattr(control_panel, 'controls'):
            return
            
        controls = control_panel.controls
        wordlist_dir = os.path.join(self.main_window.project_root, "resources", "wordlists")
        
        if not os.path.exists(wordlist_dir):
            return
        
        # SMB wordlist
        if tool_key == 'smb_enum' and 'smb_wordlist' in controls:
            wordlist_combo = controls['smb_wordlist']
            wordlist_combo.addItem("Default SMB shares", None)
            for filename in os.listdir(wordlist_dir):
                if filename.endswith(".txt") and ('share' in filename.lower() or 'smb' in filename.lower()):
                    wordlist_combo.addItem(filename, os.path.join(wordlist_dir, filename))
            # Add general wordlists as fallback
            for filename in os.listdir(wordlist_dir):
                if filename.endswith(".txt") and 'share' not in filename.lower() and 'smb' not in filename.lower():
                    wordlist_combo.addItem(f"General: {filename}", os.path.join(wordlist_dir, filename))
            # Set shares-top100.txt as default if available
            shares_path = os.path.join(wordlist_dir, "shares-top100.txt")
            for i in range(wordlist_combo.count()):
                if wordlist_combo.itemData(i) == shares_path:
                    wordlist_combo.setCurrentIndex(i)
                    break
        
        # SMTP wordlist
        elif tool_key == 'smtp_enum' and 'smtp_wordlist' in controls:
            wordlist_combo = controls['smtp_wordlist']
            for filename in os.listdir(wordlist_dir):
                if filename.endswith(".txt"):
                    wordlist_combo.addItem(filename, os.path.join(wordlist_dir, filename))
            # Set usernames-top100.txt as default
            users_path = os.path.join(wordlist_dir, "usernames-top100.txt")
            for i in range(wordlist_combo.count()):
                if wordlist_combo.itemData(i) == users_path:
                    wordlist_combo.setCurrentIndex(i)
                    break
        
        # HTTP wordlist for directory enumeration
        elif tool_key == 'http_enum' and 'http_wordlist' in controls:
            wordlist_combo = controls['http_wordlist']
            http_wordlist_dir = os.path.join(wordlist_dir, "http_enum")
            if os.path.exists(http_wordlist_dir):
                for filename in os.listdir(http_wordlist_dir):
                    if filename.endswith(".txt"):
                        wordlist_combo.addItem(filename, os.path.join(http_wordlist_dir, filename))
            # Add general wordlists as fallback
            for filename in os.listdir(wordlist_dir):
                if filename.endswith(".txt") and not os.path.exists(os.path.join(http_wordlist_dir, filename)):
                    wordlist_combo.addItem(f"General: {filename}", os.path.join(wordlist_dir, filename))
            # Set common.txt as default
            common_path = os.path.join(http_wordlist_dir, "common.txt")
            for i in range(wordlist_combo.count()):
                if wordlist_combo.itemData(i) == common_path:
                    wordlist_combo.setCurrentIndex(i)
                    break
        
        # API wordlist
        elif tool_key == 'api_enum' and 'api_wordlist' in controls:
            wordlist_combo = controls['api_wordlist']
            for filename in os.listdir(wordlist_dir):
                if filename.endswith(".txt") and ('api' in filename.lower() or 'endpoint' in filename.lower()):
                    wordlist_combo.addItem(filename, os.path.join(wordlist_dir, filename))
            # Add general wordlists as fallback
            for filename in os.listdir(wordlist_dir):
                if filename.endswith(".txt") and 'api' not in filename.lower():
                    wordlist_combo.addItem(f"General: {filename}", os.path.join(wordlist_dir, filename))
        
        # LDAP wordlist
        elif tool_key == 'ldap_enum' and 'ldap_wordlist' in controls:
            wordlist_combo = controls['ldap_wordlist']
            for filename in os.listdir(wordlist_dir):
                if filename.endswith(".txt"):
                    wordlist_combo.addItem(filename, os.path.join(wordlist_dir, filename))
            # Set usernames-top100.txt as default
            users_path = os.path.join(wordlist_dir, "usernames-top100.txt")
            for i in range(wordlist_combo.count()):
                if wordlist_combo.itemData(i) == users_path:
                    wordlist_combo.setCurrentIndex(i)
                    break
        
        # SNMP community strings
        elif tool_key == 'snmp_enum' and 'snmp_communities' in controls:
            # Pre-populate common SNMP community strings
            communities_field = controls['snmp_communities']
            if not communities_field.text():
                communities_field.setText("public,private,community,manager,admin")
        
        # SSH wordlist
        elif tool_key == 'ssh_enum' and 'ssh_wordlist' in controls:
            wordlist_combo = controls['ssh_wordlist']
            for filename in os.listdir(wordlist_dir):
                if filename.endswith(".txt") and ('password' in filename.lower() or 'ssh' in filename.lower()):
                    wordlist_combo.addItem(filename, os.path.join(wordlist_dir, filename))
            # Add general wordlists as fallback
            for filename in os.listdir(wordlist_dir):
                if filename.endswith(".txt") and 'password' not in filename.lower() and 'ssh' not in filename.lower():
                    wordlist_combo.addItem(f"General: {filename}", os.path.join(wordlist_dir, filename))
            # Set passwords-top100.txt as default if available
            passwords_path = os.path.join(wordlist_dir, "passwords-top100.txt")
            for i in range(wordlist_combo.count()):
                if wordlist_combo.itemData(i) == passwords_path:
                    wordlist_combo.setCurrentIndex(i)
                    break
    
    def hide_http_optional_fields_by_default(self, tool_key, controls):
        """Hide HTTP optional fields by default on page load"""
        if hasattr(controls, 'row_widgets'):
            # Hide all optional fields by default (Fingerprinting is default scan type)
            optional_rows = ['Preset:', 'Extensions:', 'Wordlist:', 'Auth Method:', 'Username:', 'Password:', 'Credentials:']
            for row_label in optional_rows:
                if row_label in controls.row_widgets and controls.row_widgets[row_label] is not None:
                    try:
                        row_widget = controls.row_widgets[row_label]
                        row_widget.setVisible(False)
                        row_widget.setMaximumHeight(0)
                        row_widget.setMinimumHeight(0)
                    except RuntimeError as _exc:
                        pass  # Widget has been deleted
                        logger.debug("Suppressed exception", exc_info=True)
            
            # Set panel to minimal height (just Scan Type row)
            controls.setMaximumHeight(34)
            controls.setMinimumHeight(34)
    
    def toggle_service_scan(self, tool_key):
        """Toggle service scan - start if not running, stop if running"""
        scanning_attr = f"{tool_key}_scanning"
        if getattr(self, scanning_attr, False):
            self.cancel_service_scan(tool_key)
        else:
            self.run_service_scan(tool_key)
    
    def cancel_service_scan(self, tool_key):
        """Cancel running service scan"""
        # Cancel local workers for HTTP, RPC, and SMB
        if tool_key in ['http_enum', 'rpc_enum', 'smb_enum']:
            worker = getattr(self, f"{tool_key}_worker", None)
            if worker:
                worker.is_running = False
        
        setattr(self, f"{tool_key}_scanning", False)
        
        # Reset button state
        run_button = getattr(self, f"{tool_key}_run_button")
        if hasattr(run_button, 'stop_scan'):
            run_button.stop_scan()
        else:
            run_button.setText("Run")
        
        # Hide progress widget when cancelled
        progress_widget = getattr(self, f"{tool_key}_progress_widget")
        if progress_widget:
            progress_widget.setVisible(False)
        
        self.append_service_output(tool_key, f"<p style='color: #FFAA00;'>[SCAN] {tool_key} enumeration cancelled</p><br>")
        self.status_updated.emit(f"{tool_key} scan cancelled")
    
    def set_service_view(self, tool_key, view_type):
        """Set service results view type"""
        setattr(self, f"current_{tool_key}_view", view_type)
        
        text_view_btn = getattr(self, f"{tool_key}_text_view_btn")
        text_view_btn.setChecked(view_type == "text")
        
        # Handle view buttons for tools with graph/tree views
        if tool_key in ["http_enum", "rpc_enum", "smb_enum", "ssh_enum", "db_enum"]:
            # Handle all view buttons
            graph_view_btn = getattr(self, f"{tool_key}_graph_view_btn", None)
            table_view_btn = getattr(self, f"{tool_key}_table_view_btn", None)
            
            if graph_view_btn:
                graph_view_btn.setChecked(view_type == "graph")
            if table_view_btn:
                table_view_btn.setChecked(view_type == "table")
        else:
            table_view_btn = getattr(self, f"{tool_key}_table_view_btn", None)
            if table_view_btn:
                table_view_btn.setChecked(view_type == "table")
        
        results_stack = getattr(self, f"{tool_key}_results_stack")
        
        # Set correct view index based on current stack contents
        if view_type == "text":
            results_stack.setCurrentIndex(0)
        elif view_type == "graph":
            if tool_key in ["rpc_enum", "smb_enum", "db_enum"]:
                results_stack.setCurrentIndex(1)  # Tree view for RPC, SMB, and DB
            else:
                results_stack.setCurrentIndex(1)  # Graph view for HTTP
        elif view_type == "table":
            if tool_key in ["rpc_enum", "smb_enum", "db_enum"]:
                results_stack.setCurrentIndex(2)  # Table view for RPC, SMB, and DB
            elif tool_key == "http_enum":
                current_scan_type = getattr(self, f"{tool_key}_current_scan_type", "Fingerprinting")
                if current_scan_type == "Directory Enum" and results_stack.count() > 2:
                    results_stack.setCurrentIndex(2)  # Table view for Directory Enum
                else:
                    results_stack.setCurrentIndex(1)  # Graph view for other HTTP types
            else:
                results_stack.setCurrentIndex(1)  # Table view for other tools

    
    def export_service_results(self, tool_key):
        """Export service scan results"""
        # Try multiple result attribute names
        scan_results = getattr(self, f"{tool_key}_scan_results", None)
        if not scan_results:
            scan_results = getattr(self, f"{tool_key}_results", {})
        if not scan_results:
            self.status_updated.emit(f"No {tool_key} results to export")
            return
        
        export_combo = getattr(self, f"{tool_key}_export_combo")
        export_format = export_combo.currentText().lower()
        
        target_input = getattr(self, f"{tool_key}_target_input")
        target = target_input.text().strip() or f"{tool_key}_target"
        
        try:
            from app.core.exporter import exporter
            
            success, filepath, message = exporter.export_results(
                scan_results,
                target,
                export_format,
                scan_type=tool_key
            )
            
            if success:
                # For HTTP enum, append to current scan type terminal
                if tool_key == "http_enum":
                    current_scan_type = getattr(self, f"{tool_key}_current_scan_type", "Fingerprinting")
                    self.append_http_output(tool_key, current_scan_type, f"<p style='color: #00FF41;'>[EXPORT] Results exported to {filepath}</p><br>")
                else:
                    self.append_service_output(tool_key, f"<p style='color: #00FF41;'>[EXPORT] Results exported to {filepath}</p><br>")
                self.status_updated.emit(f"{tool_key} results exported to {filepath}")
            else:
                if tool_key == "http_enum":
                    current_scan_type = getattr(self, f"{tool_key}_current_scan_type", "Fingerprinting")
                    self.append_http_output(tool_key, current_scan_type, f"<p style='color: #FF4500;'>[EXPORT ERROR] {message}</p><br>")
                else:
                    self.append_service_output(tool_key, f"<p style='color: #FF4500;'>[EXPORT ERROR] {message}</p><br>")
                self.status_updated.emit(f"Export failed: {message}")
                
        except Exception as e:
            if tool_key == "http_enum":
                current_scan_type = getattr(self, f"{tool_key}_current_scan_type", "Fingerprinting")
                self.append_http_output(tool_key, current_scan_type, f"<p style='color: #FF4500;'>[EXPORT ERROR] Export failed: {str(e)}</p>")
            else:
                self.append_service_output(tool_key, f"<p style='color: #FF4500;'>[EXPORT ERROR] Export failed: {str(e)}</p>")
            self.status_updated.emit(f"Service export error: {str(e)}")
    
    def switch_smb_scan_view(self, tool_key, scan_type):
        """Switch SMB scan view to show terminals/tables for specific scan type"""
        try:
            results_stack = getattr(self, f"{tool_key}_results_stack")
            terminals = getattr(self, f"{tool_key}_terminals", {})
            tables = getattr(self, f"{tool_key}_tables", {})
            
            if not results_stack or scan_type not in terminals:
                return
            
            while results_stack.count() > 0:
                widget = results_stack.widget(0)
                results_stack.removeWidget(widget)
            
            results_stack.addWidget(terminals[scan_type])
            trees = getattr(self, f"{tool_key}_trees", {})
            if scan_type in trees:
                results_stack.addWidget(trees[scan_type])
            if scan_type in tables:
                results_stack.addWidget(tables[scan_type])
            
            results_stack.setCurrentIndex(0)
        except Exception as e:
            print(f"Error switching SMB view: {e}")
    
    def switch_db_scan_view(self, tool_key, scan_type):
        """Switch database scan view to show terminals/tables for specific scan type"""
        try:
            results_stack = getattr(self, f"{tool_key}_results_stack")
            terminals = getattr(self, f"{tool_key}_terminals", {})
            tables = getattr(self, f"{tool_key}_tables", {})
            
            if not results_stack or scan_type not in terminals:
                return
            
            while results_stack.count() > 0:
                widget = results_stack.widget(0)
                results_stack.removeWidget(widget)
            
            results_stack.addWidget(terminals[scan_type])
            trees = getattr(self, f"{tool_key}_trees", {})
            if scan_type in trees:
                results_stack.addWidget(trees[scan_type])
            if scan_type in tables:
                results_stack.addWidget(tables[scan_type])
            
            results_stack.setCurrentIndex(0)
        except Exception as e:
            print(f"Error switching DB view: {e}")
    
    def append_service_output(self, tool_key, text):
        """Append text to service terminal output"""
        # Handle RPC and SMB with multiple terminals
        if tool_key in ["rpc_enum", "smb_enum"]:
            terminals = getattr(self, f"{tool_key}_terminals", {})
            current_scan_type = getattr(self, f"{tool_key}_current_scan_type", "Basic Info")
            terminal = terminals.get(current_scan_type)
            # Fallback to any available terminal if current scan type not found
            if not terminal and terminals:
                terminal = next(iter(terminals.values()))
        else:
            terminal = getattr(self, f"{tool_key}_terminal", None)
        
        if terminal:
            current_theme = getattr(self.main_window, 'current_theme', 'dark_blue')
            font_family = 'Share Tech Mono' if current_theme == 'matrix' else 'Neuropol X'
            
            if not text.startswith('<div style="font-family:'):
                text = f'<div style="font-family: {font_family}, monospace;">{text}</div>'
            
            # Move cursor to end before inserting to prevent insertion at scroll position
            cursor = terminal.textCursor()
            cursor.movePosition(cursor.MoveOperation.End)
            terminal.setTextCursor(cursor)
            
            terminal.insertHtml(text)
            
            from PyQt6.QtCore import QTimer
            QTimer.singleShot(10, lambda: terminal.verticalScrollBar().setValue(
                terminal.verticalScrollBar().maximum()
            ))