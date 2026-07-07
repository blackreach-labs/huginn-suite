from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QSplitter, 
                             QTreeWidget, QTreeWidgetItem, QTextEdit, QPushButton, 
                             QLabel, QComboBox, QTableWidget, QTableWidgetItem,
                             QGroupBox, QMessageBox, QProgressBar, QTabWidget,
                             QHeaderView, QFrame, QScrollArea, QLineEdit, QSpinBox,
                             QCheckBox, QFormLayout, QListWidget)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QIcon
import sqlite3
import os
from pathlib import Path
from typing import Dict, List, Tuple
from app.core.logger import logger

class DatabaseQueryThread(QThread):
    """Thread for executing database queries"""
    query_completed = pyqtSignal(list, list)  # results, columns
    query_error = pyqtSignal(str)
    
    def __init__(self, db_path: str, query: str):
        super().__init__()
        self.db_path = db_path
        self.query = query
    
    def run(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(self.query)
                
                if self.query.strip().upper().startswith(('SELECT', 'PRAGMA')):
                    results = cursor.fetchall()
                    columns = [desc[0] for desc in cursor.description] if cursor.description else []
                    self.query_completed.emit(results, columns)
                else:
                    conn.commit()
                    self.query_completed.emit([[f"Query executed successfully. Rows affected: {cursor.rowcount}"]], ["Result"])
        except Exception as e:
            self.query_error.emit(str(e))

class DatabaseManagementPage(QWidget):
    """Database Management Page with SQL query capabilities"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_db_path = None
        self.query_thread = None
        self.remote_connections = {}
        self.database_configs = self._load_database_configs()
        self.setup_ui()
        self.load_databases()
    
    def _load_database_configs(self) -> Dict:
        """Load database configurations and categorize them"""
        project_root = Path(__file__).parent.parent.parent
        resources_dir = project_root / "resources"
        
        return {
            "Core Data Management": {
                "Centralized Scan Data": {
                    "path": str(resources_dir / "centralized_scan_data.db"),
                    "description": "Primary data hub with multi-tenant support",
                    "tables": ["scan_data", "scan_metadata", "post_exploit_sessions", "post_exploit_commands"]
                },
                "Scan Results": {
                    "path": str(resources_dir / "scan_results.db"),
                    "description": "Current scan results storage",
                    "tables": ["results", "metadata"]
                },
                "Scan History": {
                    "path": str(resources_dir / "scan_history.db"),
                    "description": "Historical scan data preservation",
                    "tables": ["history", "sessions"]
                }
            },
            "Security Analysis": {
                "Vulnerability Findings": {
                    "path": str(resources_dir / "vulnerability_findings.db"),
                    "description": "Centralized vulnerability collection",
                    "tables": ["vulnerabilities", "scan_sessions"]
                },
                "Pentest Findings": {
                    "path": str(resources_dir / "pentest_findings.db"),
                    "description": "Comprehensive penetration testing data",
                    "tables": ["targets", "services", "vulnerabilities", "credentials", "loot"]
                },
                "Breach Data": {
                    "path": str(resources_dir / "breach_data.db"),
                    "description": "Data breach intelligence and credential lookup",
                    "tables": ["breaches"]
                },
                "Exploit Database": {
                    "path": str(resources_dir / "exploits.db"),
                    "description": "CVE integration and exploit management",
                    "tables": ["exploits", "exploit_categories"]
                }
            },
            "Traffic & Communication": {
                "Proxy Traffic": {
                    "path": str(resources_dir / "proxy.db"),
                    "description": "HTTP/HTTPS traffic interception",
                    "tables": ["requests"]
                },
                "Auth Workflows": {
                    "path": str(resources_dir / "auth_workflows.db"),
                    "description": "Authentication flow analysis",
                    "tables": ["auth_flows", "tokens", "test_results", "vulnerabilities", "state_models"]
                },
                "Listeners": {
                    "path": str(resources_dir / "listeners.db"),
                    "description": "Command & control listener management",
                    "tables": ["listeners", "sessions", "audit_logs"]
                }
            },
            "Asset & Discovery": {
                "Asset Inventory": {
                    "path": str(resources_dir / "asset_inventory.db"),
                    "description": "Comprehensive asset inventory",
                    "tables": ["assets", "services", "vulnerabilities"]
                },
                "Web Crawling": {
                    "path": str(resources_dir / "crawl.db"),
                    "description": "Web application crawling data",
                    "tables": ["crawl_results"]
                },
                "Correlation Analysis": {
                    "path": str(resources_dir / "correlation.db"),
                    "description": "Cross-scan correlation analysis",
                    "tables": ["correlations", "attack_chains"]
                }
            },
            "Specialized Analysis": {
                "Hash Lookup": {
                    "path": str(resources_dir / "hash_lookup.db"),
                    "description": "Password hash analysis and cracking",
                    "tables": ["hashes", "sources"]
                },
                "Header Mappings": {
                    "path": str(resources_dir / "header_mappings.db"),
                    "description": "HTTP header analysis and fingerprinting",
                    "tables": ["headers", "mappings"]
                }
            }
        }
    
    def setup_ui(self):
        """Setup the user interface"""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(5, 5, 5, 5)
        
        # Main splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Database tree
        left_panel = self.create_database_tree_panel()
        splitter.addWidget(left_panel)
        
        # Right panel - Query interface
        right_panel = self.create_query_panel()
        splitter.addWidget(right_panel)
        
        splitter.setSizes([300, 700])
        main_layout.addWidget(splitter)
        
        # Status bar
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("padding: 2px; font-size: 10pt;")
        self.status_label.setMaximumHeight(20)
        self.status_label.setMinimumHeight(20)
        main_layout.addWidget(self.status_label)
    
    def create_database_tree_panel(self) -> QWidget:
        """Create the database tree panel"""
        panel = QFrame()
        panel.setFrameStyle(QFrame.Shape.Box)
        panel.setStyleSheet("""
            QFrame {
                border-radius: 5px;
            }
        """)
        
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Panel title
        title = QLabel("Database Explorer")
        title.setStyleSheet("font-size: 14pt; font-weight: bold; margin-bottom: 10px;")
        layout.addWidget(title)
        
        # Database tree
        self.db_tree = QTreeWidget()
        self.db_tree.setHeaderHidden(True)
        self.db_tree.itemClicked.connect(self.on_database_selected)
        self.db_tree.itemDoubleClicked.connect(self.on_database_double_clicked)
        self.db_tree.setStyleSheet("""
            QTreeWidget {
                border-radius: 3px;
            }
            QTreeWidget::item:selected {
            }
        """)
        layout.addWidget(self.db_tree)
        
        # Quick actions
        actions_group = QGroupBox("Quick Actions")
        actions_group.setStyleSheet("QGroupBox { font-weight: bold; }")
        actions_layout = QVBoxLayout(actions_group)
        
        self.refresh_btn = QPushButton("🔄 Refresh Databases")
        self.refresh_btn.clicked.connect(self.load_databases)
        self.compact_btn = QPushButton("🗜️ Compact Database")
        self.compact_btn.clicked.connect(self.compact_database)
        self.analyze_btn = QPushButton("📊 Analyze Database")
        self.analyze_btn.clicked.connect(self.analyze_database)
        self.backup_btn = QPushButton("💾 Backup Database")
        self.backup_btn.clicked.connect(self.backup_database)
        self.integrity_btn = QPushButton("🔍 Integrity Check")
        self.integrity_btn.clicked.connect(self.check_integrity)
        self.export_btn = QPushButton("📤 Export Table")
        self.export_btn.clicked.connect(self.export_table_data)
        self.cleanup_btn = QPushButton("🧽 Cleanup Old Data")
        self.cleanup_btn.clicked.connect(self.cleanup_old_data)
        
        self.connect_remote_btn = QPushButton("🌐 Connect Remote DB")
        self.connect_remote_btn.clicked.connect(self.toggle_remote_panel)
        self.manage_connections_btn = QPushButton("🔗 Manage Connections")
        self.manage_connections_btn.clicked.connect(self.toggle_connections_panel)
        
        for btn in [self.refresh_btn, self.compact_btn, self.analyze_btn, self.backup_btn, self.integrity_btn, self.export_btn, self.cleanup_btn, self.connect_remote_btn, self.manage_connections_btn]:
            btn.setStyleSheet("""
                QPushButton {
                    border: none;
                    border-radius: 5px;
                    padding: 8px;
                    font-weight: bold;
                    margin: 2px;
                }
                QPushButton:hover {
                }
                QPushButton:disabled {
                }
            """)
            if btn not in [self.refresh_btn, self.connect_remote_btn, self.manage_connections_btn]:
                btn.setEnabled(False)
            actions_layout.addWidget(btn)
        
        layout.addWidget(actions_group)

        # ── Inline: Connect Remote DB panel (hidden by default) ──────────
        self.remote_panel = QFrame()
        self.remote_panel.setVisible(False)
        self.remote_panel.setStyleSheet("""
            QFrame {
                border-radius: 5px;
            }
        """)
        rp_layout = QVBoxLayout(self.remote_panel)
        rp_layout.setContentsMargins(10, 8, 10, 8)
        rp_layout.setSpacing(4)

        rp_title = QLabel("🌐 Remote Database Connection")
        rp_title.setStyleSheet("font-weight: bold; font-size: 11pt;")
        rp_layout.addWidget(rp_title)

        form = QFormLayout()
        form.setSpacing(4)

        self.rp_name = QLineEdit()
        self.rp_name.setPlaceholderText("My Connection")
        form.addRow("Name:", self.rp_name)

        self.rp_type = QComboBox()
        self.rp_type.addItems(["MySQL", "PostgreSQL", "MSSQL", "Oracle"])
        self.rp_type.currentTextChanged.connect(self._rp_update_port)
        form.addRow("Type:", self.rp_type)

        self.rp_host = QLineEdit()
        self.rp_host.setPlaceholderText("host or IP")
        form.addRow("Host:", self.rp_host)

        self.rp_port = QSpinBox()
        self.rp_port.setRange(1, 65535)
        self.rp_port.setValue(3306)
        form.addRow("Port:", self.rp_port)

        self.rp_database = QLineEdit()
        self.rp_database.setPlaceholderText("database name")
        form.addRow("Database:", self.rp_database)

        self.rp_username = QLineEdit()
        self.rp_username.setPlaceholderText("username")
        form.addRow("Username:", self.rp_username)

        self.rp_password = QLineEdit()
        self.rp_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.rp_password.setPlaceholderText("password")
        form.addRow("Password:", self.rp_password)

        self.rp_ssl = QCheckBox("Enable SSL/TLS")
        form.addRow("", self.rp_ssl)

        rp_layout.addLayout(form)

        self.rp_status = QLabel("")
        self.rp_status.setWordWrap(True)
        self.rp_status.setStyleSheet("font-size: 9pt; padding: 2px;")
        rp_layout.addWidget(self.rp_status)

        rp_btn_row = QHBoxLayout()
        _btn_style = """
            QPushButton {
                border: none; border-radius: 4px;
                padding: 6px 10px; font-weight: bold;
            }
            QPushButton:hover { }
        """
        rp_test_btn = QPushButton("🔍 Test")
        rp_test_btn.setStyleSheet(_btn_style)
        rp_test_btn.clicked.connect(self._rp_test_connection)

        rp_connect_btn = QPushButton("🔗 Connect")
        rp_connect_btn.setStyleSheet(_btn_style)
        rp_connect_btn.clicked.connect(self._rp_connect)

        rp_cancel_btn = QPushButton("✕ Cancel")
        rp_cancel_btn.setStyleSheet(_btn_style)
        rp_cancel_btn.clicked.connect(lambda: self.remote_panel.setVisible(False))

        rp_btn_row.addWidget(rp_test_btn)
        rp_btn_row.addWidget(rp_connect_btn)
        rp_btn_row.addWidget(rp_cancel_btn)
        rp_layout.addLayout(rp_btn_row)

        layout.addWidget(self.remote_panel)

        # ── Inline: Manage Connections panel (hidden by default) ─────────
        self.connections_panel = QFrame()
        self.connections_panel.setVisible(False)
        self.connections_panel.setStyleSheet("""
            QFrame {
                border-radius: 5px;
            }
        """)
        cp_layout = QVBoxLayout(self.connections_panel)
        cp_layout.setContentsMargins(10, 8, 10, 8)
        cp_layout.setSpacing(4)

        cp_title = QLabel("🔗 Active Remote Connections")
        cp_title.setStyleSheet("font-weight: bold; font-size: 11pt;")
        cp_layout.addWidget(cp_title)

        self.cp_list = QListWidget()
        self.cp_list.setMaximumHeight(120)
        cp_layout.addWidget(self.cp_list)

        cp_btn_row = QHBoxLayout()
        cp_disconnect_btn = QPushButton("❌ Disconnect")
        cp_disconnect_btn.setStyleSheet(_btn_style)
        cp_disconnect_btn.clicked.connect(self._cp_disconnect_selected)

        cp_disconnect_all_btn = QPushButton("❌ Disconnect All")
        cp_disconnect_all_btn.setStyleSheet(_btn_style)
        cp_disconnect_all_btn.clicked.connect(self._cp_disconnect_all)

        cp_close_btn = QPushButton("✕ Close")
        cp_close_btn.setStyleSheet(_btn_style)
        cp_close_btn.clicked.connect(lambda: self.connections_panel.setVisible(False))

        cp_btn_row.addWidget(cp_disconnect_btn)
        cp_btn_row.addWidget(cp_disconnect_all_btn)
        cp_btn_row.addWidget(cp_close_btn)
        cp_layout.addLayout(cp_btn_row)

        layout.addWidget(self.connections_panel)

        return panel
    
    def create_query_panel(self) -> QWidget:
        """Create the query interface panel"""
        panel = QFrame()
        panel.setFrameStyle(QFrame.Shape.Box)
        panel.setStyleSheet("""
            QFrame {
                border-radius: 5px;
            }
        """)
        
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Panel title and database info
        header_layout = QHBoxLayout()
        
        title = QLabel("SQL Query Interface")
        title.setStyleSheet("font-size: 14pt; font-weight: bold;")
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        self.db_info_label = QLabel("No database selected")
        self.db_info_label.setStyleSheet("font-style: italic;")
        header_layout.addWidget(self.db_info_label)
        
        layout.addLayout(header_layout)
        
        # Query tabs
        self.query_tabs = QTabWidget()
        self.query_tabs.setStyleSheet("""
            QTabWidget::pane {
            }
            QTabBar::tab {
                padding: 8px 16px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
            }
        """)
        
        # SQL Query tab
        query_tab = QWidget()
        query_layout = QVBoxLayout(query_tab)
        
        # Query input
        query_input_layout = QVBoxLayout()
        query_label = QLabel("SQL Query:")
        query_label.setStyleSheet("font-weight: bold; margin-top: 5px;")
        query_label.setMaximumHeight(20)
        query_input_layout.addWidget(query_label)
        
        self.query_input = QTextEdit()
        self.query_input.setMaximumHeight(120)
        self.query_input.setPlaceholderText("Enter your SQL query here...")
        self.query_input.setStyleSheet("""
            QTextEdit {
                border-radius: 3px;
                font-family: 'Courier New', monospace;
                font-size: 10pt;
            }
        """)
        query_input_layout.addWidget(self.query_input)
        
        # Query buttons
        query_btn_layout = QHBoxLayout()
        
        self.execute_btn = QPushButton("▶️ Execute Query")
        self.execute_btn.clicked.connect(self.execute_query)
        self.execute_btn.setEnabled(False)
        
        self.clear_btn = QPushButton("🗑️ Clear")
        self.clear_btn.clicked.connect(lambda: self.query_input.clear())
        
        # Quick query dropdown
        self.quick_query_combo = QComboBox()
        
        # Detect database type and load appropriate queries
        db_type = self.detect_database_type()
        
        if db_type == "mssql":
            self.quick_query_combo.addItems([
                "Select Quick Query...",
                "SELECT name FROM sys.databases;",
                "SELECT name FROM sys.tables;",
                "SELECT name, type_desc FROM sys.objects WHERE type IN ('U','V','P','FN');",
                "SELECT name FROM sys.columns WHERE object_id = OBJECT_ID('users');",
                "SELECT COUNT(*) FROM users;",
                "SELECT name, principal_id FROM sys.server_principals;",
                "SELECT name, principal_id FROM sys.database_principals;",
                "SELECT * FROM sys.server_permissions;",
                "SELECT * FROM sys.database_permissions;",
                "SELECT name FROM sys.servers WHERE is_linked = 1;",
                "SELECT @@VERSION;",
                "SELECT name, is_disabled FROM sys.server_principals WHERE type = 'S';",
                "SELECT name, default_schema_name FROM sys.database_principals WHERE type = 'S';",
                "SELECT name FROM sys.databases WHERE name NOT IN ('master','tempdb','model','msdb');",
                "EXEC sp_helpdb;",
                "SELECT name, filename FROM sys.sysfiles;",
                "SELECT loginname FROM sys.syslogins;",
                "SELECT * FROM INFORMATION_SCHEMA.TABLES;",
                "SELECT * FROM users WHERE username LIKE '%admin%';"
            ])
        else:
            # Default SQLite queries
            self.quick_query_combo.addItems([
                "Select Quick Query...",
                "SELECT name FROM sqlite_master WHERE type='table';",
                "SELECT * FROM sqlite_master;",
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='users';",
                "SELECT * FROM users;",
                "SELECT COUNT(*) FROM users;",
                "PRAGMA table_info(users);",
                "SELECT name, tbl_name, sql FROM sqlite_master WHERE type='index';",
                "SELECT name, sql FROM sqlite_master WHERE type='view';",
                ".dump",
                "SELECT name, sql FROM sqlite_master WHERE sql LIKE '%password%';",
                "SELECT * FROM users WHERE email LIKE '%@%';",
                "SELECT sqlite_version();",
                "PRAGMA foreign_key_list(users);",
                "PRAGMA database_list;",
                "SELECT name, sql FROM sqlite_master WHERE type='trigger';",
                "SELECT * FROM users LIMIT 5;",
                "PRAGMA table_info('<table_name>');",
                "SELECT DISTINCT role FROM users;"
            ])
        self.quick_query_combo.currentTextChanged.connect(self.load_quick_query)
        
        for btn in [self.execute_btn, self.clear_btn]:
            btn.setStyleSheet("""
                QPushButton {
                    border: none;
                    border-radius: 5px;
                    padding: 8px 16px;
                    font-weight: bold;
                    margin: 2px;
                }
                QPushButton:hover {
                }
                QPushButton:disabled {
                }
            """)
        
        self.quick_query_combo.setStyleSheet("""
            QComboBox {
                border-radius: 3px;
                padding: 5px;
                min-width: 200px;
            }
        """)
        
        query_btn_layout.addWidget(self.execute_btn)
        query_btn_layout.addWidget(self.clear_btn)
        query_btn_layout.addStretch()
        query_btn_layout.addWidget(QLabel("Quick Queries:"))
        query_btn_layout.addWidget(self.quick_query_combo)
        
        query_input_layout.addLayout(query_btn_layout)
        query_layout.addLayout(query_input_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border-radius: 3px;
                text-align: center;
            }
            QProgressBar::chunk {
            }
        """)
        query_layout.addWidget(self.progress_bar)
        
        # Results table
        results_label = QLabel("Query Results:")
        results_label.setStyleSheet("font-weight: bold; margin-top: 5px;")
        results_label.setMaximumHeight(20)
        query_layout.addWidget(results_label)
        
        self.results_table = QTableWidget()
        self.results_table.setStyleSheet("""
            QTableWidget {
                border-radius: 5px;
            }
            QTableWidget::item {
                padding: 4px;
            }
            QTableWidget::item:selected {
            }
            QHeaderView::section {
                font-weight: bold;
                padding: 6px;
                border: none;
            }
        """)
        query_layout.addWidget(self.results_table)
        
        self.query_tabs.addTab(query_tab, "SQL Query")
        
        # Database Schema tab
        schema_tab = self.create_schema_tab()
        self.query_tabs.addTab(schema_tab, "Schema")
        
        layout.addWidget(self.query_tabs)
        
        return panel
    
    def create_schema_tab(self) -> QWidget:
        """Create the database schema tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        self.schema_tree = QTreeWidget()
        self.schema_tree.setHeaderLabels(["Object", "Type", "Details"])
        self.schema_tree.setStyleSheet("""
            QTreeWidget {
                border-radius: 3px;
            }
            QTreeWidget::item:selected {
            }
        """)
        layout.addWidget(self.schema_tree)
        
        return tab
    
    def load_databases(self):
        """Load databases into the tree"""
        self.db_tree.clear()
        
        for category, databases in self.database_configs.items():
            category_item = QTreeWidgetItem(self.db_tree, [category])
            category_item.setExpanded(True)
            category_item.setFont(0, QFont("Arial", 10, QFont.Weight.Bold))
            
            for db_name, db_config in databases.items():
                db_item = QTreeWidgetItem(category_item, [db_name])
                db_item.setData(0, Qt.ItemDataRole.UserRole, db_config)
                
                # Check if database file exists
                if os.path.exists(db_config["path"]):
                    db_item.setIcon(0, self.style().standardIcon(self.style().StandardPixmap.SP_ComputerIcon))
                    
                    # Add file size info
                    try:
                        size = os.path.getsize(db_config["path"])
                        size_str = self.format_file_size(size)
                        db_item.setText(0, f"{db_name} ({size_str})")
                    except Exception as _exc:
                        pass
                        logger.debug("Suppressed exception", exc_info=True)
                else:
                    db_item.setIcon(0, self.style().standardIcon(self.style().StandardPixmap.SP_DialogCancelButton))
                    db_item.setText(0, f"{db_name} (Not Found)")
                    db_item.setDisabled(True)
    
    def format_file_size(self, size_bytes: int) -> str:
        """Format file size in human readable format"""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        else:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
    
    def on_database_selected(self, item: QTreeWidgetItem, column: int):
        """Handle database selection"""
        db_config = item.data(0, Qt.ItemDataRole.UserRole)
        if not db_config:
            return
        
        self.current_db_path = db_config["path"]
        
        # Update UI
        self.db_info_label.setText(f"Selected: {item.text(0)}")
        self.status_label.setText(f"Connected to: {os.path.basename(self.current_db_path)} - {db_config['description']}")
        
        # Enable buttons
        for btn in [self.compact_btn, self.analyze_btn, self.backup_btn, self.integrity_btn, self.export_btn, self.cleanup_btn, self.execute_btn]:
            btn.setEnabled(True)
        
        # Refresh quick queries for database type
        self.refresh_quick_queries()
        
        # Load schema
        self.load_database_schema()
    
    def on_database_double_clicked(self, item: QTreeWidgetItem, column: int):
        """Handle database double-click to show quick info"""
        db_config = item.data(0, Qt.ItemDataRole.UserRole)
        if not db_config:
            return
        
        db_path = db_config["path"]
        if not os.path.exists(db_path):
            QMessageBox.warning(self, "Database Not Found", f"Database file not found:\n{db_path}")
            return
        
        try:
            from app.core.database_utils import DatabaseUtils
            
            # Get quick database info
            db_info = DatabaseUtils.get_database_info(db_path)
            
            if "error" in db_info:
                QMessageBox.critical(self, "Error", f"Failed to read database:\n{db_info['error']}")
                return
            
            # Show quick info dialog
            info_text = f"Database: {os.path.basename(db_path)}\n"
            info_text += f"Description: {db_config['description']}\n\n"
            info_text += f"File Size: {db_info['file_size_formatted']}\n"
            info_text += f"Tables: {db_info['table_count']}\n"
            info_text += f"Total Rows: {db_info['total_rows']:,}\n\n"
            
            info_text += "Tables:\n"
            for table_name, table_data in db_info['table_info'].items():
                if "error" not in table_data:
                    info_text += f"  • {table_name}: {table_data['rows']:,} rows\n"
            
            QMessageBox.information(self, "Database Quick Info", info_text)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to get database info:\n{e}")
    
    def load_database_schema(self):
        """Load database schema into the schema tab"""
        if not self.current_db_path or not os.path.exists(self.current_db_path):
            return
        
        self.schema_tree.clear()
        
        try:
            with sqlite3.connect(self.current_db_path) as conn:
                cursor = conn.cursor()
                
                # Get tables
                cursor.execute("SELECT name, type, sql FROM sqlite_master WHERE type IN ('table', 'view') ORDER BY name")
                objects = cursor.fetchall()
                
                for name, obj_type, sql in objects:
                    obj_item = QTreeWidgetItem(self.schema_tree, [name, obj_type.title(), ""])
                    obj_item.setExpanded(False)
                    
                    if obj_type == 'table':
                        # Get column info — bracket-quote the name to prevent
                        # injection via a crafted table name in the opened DB.
                        try:
                            from app.core.database_utils import _quote_identifier
                            quoted_name = _quote_identifier(name)
                        except ValueError:
                            # Skip tables with unquotable names
                            obj_item.setText(2, "skipped (invalid name)")
                            continue

                        cursor.execute("PRAGMA table_info(" + quoted_name + ")")
                        columns = cursor.fetchall()
                        
                        for col_info in columns:
                            col_name = col_info[1]
                            col_type = col_info[2]
                            col_nullable = "NOT NULL" if col_info[3] else "NULL"
                            col_default = f"DEFAULT {col_info[4]}" if col_info[4] else ""
                            col_pk = "PRIMARY KEY" if col_info[5] else ""
                            
                            col_details = f"{col_type} {col_nullable} {col_default} {col_pk}".strip()
                            QTreeWidgetItem(obj_item, [col_name, "Column", col_details])
                        
                        # Get row count
                        try:
                            cursor.execute("SELECT COUNT(*) FROM " + quoted_name)
                            count = cursor.fetchone()[0]
                            obj_item.setText(2, f"{len(columns)} columns, {count} rows")
                        except Exception:
                            obj_item.setText(2, f"{len(columns)} columns")
                    
        except Exception as e:
            self.status_label.setText(f"Error loading schema: {e}")
    
    def load_quick_query(self, query_text: str):
        """Load a quick query into the input"""
        if query_text and query_text != "Select Quick Query...":
            # Handle .dump command specially
            if query_text == ".dump":
                self.query_input.setPlainText("-- SQLite .dump command\n-- Use: sqlite3 database.db .dump > output.sql\n-- This exports the entire database structure and data")
            else:
                self.query_input.setPlainText(query_text)
    
    def execute_query(self):
        """Execute the SQL query"""
        if not self.current_db_path or not os.path.exists(self.current_db_path):
            QMessageBox.warning(self, "Error", "No database selected or database file not found.")
            return
        
        query = self.query_input.toPlainText().strip()
        if not query:
            QMessageBox.warning(self, "Error", "Please enter a SQL query.")
            return
        
        # Show progress
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        self.execute_btn.setEnabled(False)
        
        # Execute query in thread
        self.query_thread = DatabaseQueryThread(self.current_db_path, query)
        self.query_thread.query_completed.connect(self.on_query_completed)
        self.query_thread.query_error.connect(self.on_query_error)
        self.query_thread.start()
    
    def on_query_completed(self, results: List, columns: List):
        """Handle query completion"""
        self.progress_bar.setVisible(False)
        self.execute_btn.setEnabled(True)
        
        # Update results table
        self.results_table.setRowCount(len(results))
        self.results_table.setColumnCount(len(columns))
        self.results_table.setHorizontalHeaderLabels(columns)
        
        for row_idx, row_data in enumerate(results):
            for col_idx, cell_data in enumerate(row_data):
                item = QTableWidgetItem(str(cell_data) if cell_data is not None else "NULL")
                self.results_table.setItem(row_idx, col_idx, item)
        
        # Auto-resize columns
        self.results_table.resizeColumnsToContents()
        
        # Set last column to stretch and limit other columns
        header = self.results_table.horizontalHeader()
        for i in range(self.results_table.columnCount()):
            if i == self.results_table.columnCount() - 1:
                header.setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch)
            elif header.sectionSize(i) > 300:
                header.resizeSection(i, 300)
        
        self.status_label.setText(f"Query executed successfully. {len(results)} rows returned.")
    
    def on_query_error(self, error_msg: str):
        """Handle query error"""
        self.progress_bar.setVisible(False)
        self.execute_btn.setEnabled(True)
        
        QMessageBox.critical(self, "Query Error", f"Error executing query:\n\n{error_msg}")
        self.status_label.setText(f"Query error: {error_msg}")
    
    def compact_database(self):
        """Compact the selected database"""
        if not self.current_db_path:
            return
        
        reply = QMessageBox.question(self, "Compact Database", 
                                   "This will compact the database to reduce file size. Continue?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            try:
                from app.core.database_utils import DatabaseUtils
                
                # Show progress
                self.progress_bar.setVisible(True)
                self.progress_bar.setRange(0, 0)  # Indeterminate
                self.compact_btn.setEnabled(False)
                
                # Compact database
                success, message = DatabaseUtils.vacuum_database(self.current_db_path)
                
                self.progress_bar.setVisible(False)
                self.compact_btn.setEnabled(True)
                
                if success:
                    QMessageBox.information(self, "Success", message)
                    self.load_databases()  # Refresh to show new file size
                    self.status_label.setText("Database compacted successfully")
                else:
                    QMessageBox.critical(self, "Error", message)
                    self.status_label.setText("Database compaction failed")
                    
            except Exception as e:
                self.progress_bar.setVisible(False)
                self.compact_btn.setEnabled(True)
                QMessageBox.critical(self, "Error", f"Failed to compact database:\n{e}")
    
    def analyze_database(self):
        """Analyze the selected database"""
        if not self.current_db_path:
            return
        
        try:
            from app.core.database_utils import DatabaseUtils
            
            # Get comprehensive database info
            db_info = DatabaseUtils.get_database_info(self.current_db_path)
            
            if "error" in db_info:
                QMessageBox.critical(self, "Error", f"Failed to analyze database:\n{db_info['error']}")
                return
            
            info_text = f"Database: {os.path.basename(self.current_db_path)}\n"
            info_text += f"File Size: {db_info['file_size_formatted']}\n"
            info_text += f"Tables: {db_info['table_count']}\n"
            info_text += f"Total Rows: {db_info['total_rows']:,}\n"
            info_text += f"Journal Mode: {db_info['journal_mode']}\n"
            info_text += f"Synchronous: {db_info['synchronous']}\n\n"
            
            info_text += "Table Information:\n"
            for table_name, table_data in db_info['table_info'].items():
                if "error" in table_data:
                    info_text += f"  {table_name}: Error - {table_data['error']}\n"
                else:
                    info_text += f"  {table_name}: {table_data['rows']:,} rows, {table_data['columns']} columns\n"
            
            # Run integrity check
            success, message, issues = DatabaseUtils.integrity_check(self.current_db_path)
            info_text += f"\nIntegrity Check: {message}\n"
            if issues:
                info_text += "Issues found:\n"
                for issue in issues[:5]:  # Show first 5 issues
                    info_text += f"  - {issue}\n"
                if len(issues) > 5:
                    info_text += f"  ... and {len(issues) - 5} more issues\n"
            
            QMessageBox.information(self, "Database Analysis", info_text)
            
            # Run ANALYZE command to update statistics
            analyze_success, analyze_msg = DatabaseUtils.analyze_database(self.current_db_path)
            if analyze_success:
                self.status_label.setText("Database analyzed and statistics updated")
            else:
                self.status_label.setText(f"Analysis completed with warning: {analyze_msg}")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to analyze database:\n{e}")
    
    def backup_database(self):
        """Backup the selected database"""
        if not self.current_db_path:
            return
        
        from PyQt6.QtWidgets import QFileDialog
        
        backup_path, _ = QFileDialog.getSaveFileName(
            self, "Save Database Backup", 
            f"{os.path.splitext(os.path.basename(self.current_db_path))[0]}_backup.db",
            "SQLite Database (*.db);;All Files (*)"
        )
        
        if backup_path:
            try:
                from app.core.database_utils import DatabaseUtils
                
                # Show progress
                self.progress_bar.setVisible(True)
                self.progress_bar.setRange(0, 0)  # Indeterminate
                self.backup_btn.setEnabled(False)
                
                success, message = DatabaseUtils.backup_database(self.current_db_path, backup_path)
                
                self.progress_bar.setVisible(False)
                self.backup_btn.setEnabled(True)
                
                if success:
                    QMessageBox.information(self, "Success", message)
                    self.status_label.setText(f"Database backed up successfully")
                else:
                    QMessageBox.critical(self, "Error", message)
                    self.status_label.setText("Database backup failed")
                    
            except Exception as e:
                self.progress_bar.setVisible(False)
                self.backup_btn.setEnabled(True)
                QMessageBox.critical(self, "Error", f"Failed to backup database:\n{e}")
    
    def check_integrity(self):
        """Check database integrity"""
        if not self.current_db_path:
            return
        
        try:
            from app.core.database_utils import DatabaseUtils
            
            # Show progress
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)  # Indeterminate
            self.integrity_btn.setEnabled(False)
            
            success, message, issues = DatabaseUtils.integrity_check(self.current_db_path)
            
            self.progress_bar.setVisible(False)
            self.integrity_btn.setEnabled(True)
            
            if success:
                QMessageBox.information(self, "Integrity Check", "Database integrity check passed successfully.")
                self.status_label.setText("Database integrity check completed - no issues found")
            else:
                issue_text = message
                if issues:
                    issue_text += "\n\nIssues found:\n"
                    for issue in issues[:10]:  # Show first 10 issues
                        issue_text += f"• {issue}\n"
                    if len(issues) > 10:
                        issue_text += f"... and {len(issues) - 10} more issues"
                
                QMessageBox.warning(self, "Integrity Check", issue_text)
                self.status_label.setText(f"Database integrity check found {len(issues)} issues")
                
        except Exception as e:
            self.progress_bar.setVisible(False)
            self.integrity_btn.setEnabled(True)
            QMessageBox.critical(self, "Error", f"Failed to check database integrity:\n{e}")
    
    def export_table_data(self):
        """Export table data to CSV"""
        if not self.current_db_path:
            return
        
        # Get list of tables
        try:
            with sqlite3.connect(self.current_db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
                tables = [row[0] for row in cursor.fetchall()]
            
            if not tables:
                QMessageBox.information(self, "No Tables", "No tables found in database.")
                return
            
            # Let user select table
            from PyQt6.QtWidgets import QInputDialog
            table_name, ok = QInputDialog.getItem(
                self, "Select Table", "Choose table to export:", tables, 0, False
            )
            
            if not ok or not table_name:
                return
            
            # Get export path
            from PyQt6.QtWidgets import QFileDialog
            export_path, _ = QFileDialog.getSaveFileName(
                self, "Export Table Data", 
                f"{table_name}_export.csv",
                "CSV Files (*.csv);;All Files (*)"
            )
            
            if export_path:
                from app.core.database_utils import DatabaseUtils
                
                # Show progress
                self.progress_bar.setVisible(True)
                self.progress_bar.setRange(0, 0)  # Indeterminate
                self.export_btn.setEnabled(False)
                
                success, message = DatabaseUtils.export_table_csv(self.current_db_path, table_name, export_path)
                
                self.progress_bar.setVisible(False)
                self.export_btn.setEnabled(True)
                
                if success:
                    QMessageBox.information(self, "Export Complete", message)
                    self.status_label.setText(f"Table {table_name} exported successfully")
                else:
                    QMessageBox.critical(self, "Export Failed", message)
                    self.status_label.setText("Table export failed")
                    
        except Exception as e:
            self.progress_bar.setVisible(False)
            self.export_btn.setEnabled(True)
            QMessageBox.critical(self, "Error", f"Failed to export table data:\n{e}")
    
    def toggle_remote_panel(self):
        """Toggle the inline remote connection panel."""
        visible = not self.remote_panel.isVisible()
        self.remote_panel.setVisible(visible)
        # Close the other panel if open
        if visible:
            self.connections_panel.setVisible(False)
            self.rp_status.setText("")

    def toggle_connections_panel(self):
        """Toggle the inline manage-connections panel."""
        visible = not self.connections_panel.isVisible()
        self.connections_panel.setVisible(visible)
        if visible:
            self.remote_panel.setVisible(False)
            self._cp_refresh_list()

    def _rp_update_port(self, db_type: str):
        """Auto-update port when DB type changes."""
        ports = {"MySQL": 3306, "PostgreSQL": 5432, "MSSQL": 1433, "Oracle": 1521}
        self.rp_port.setValue(ports.get(db_type, 3306))

    def _rp_build_config(self):
        from app.core.remote_database_connector import DatabaseConnection
        return DatabaseConnection(
            name=self.rp_name.text().strip() or "Remote Connection",
            db_type=self.rp_type.currentText().lower(),
            host=self.rp_host.text().strip(),
            port=self.rp_port.value(),
            database=self.rp_database.text().strip(),
            username=self.rp_username.text().strip(),
            password=self.rp_password.text(),
            ssl_enabled=self.rp_ssl.isChecked(),
        )

    def _rp_test_connection(self):
        """Test the remote connection inline."""
        from app.core.remote_database_connector import remote_db_manager
        self.rp_status.setText("Testing connection…")
        config = self._rp_build_config()
        success, message = remote_db_manager.test_connection(config)
        if success:
            self.rp_status.setText("✅ Connection successful")
        else:
            self.rp_status.setText(f"❌ {message}")

    def _rp_connect(self):
        """Establish the remote connection inline."""
        from app.core.remote_database_connector import remote_db_manager
        if not all([self.rp_name.text().strip(), self.rp_host.text().strip(),
                    self.rp_database.text().strip(), self.rp_username.text().strip()]):
            self.rp_status.setText("❌ Please fill in all required fields.")
            return

        self.rp_status.setText("Connecting…")
        config = self._rp_build_config()
        success, message = remote_db_manager.connect(config)
        if success:
            self.remote_connections[config.name] = config
            self.load_databases()
            self.rp_status.setText(f"✅ Connected: {config.name}")
            self.status_label.setText(f"Connected to remote {config.db_type.upper()}: {config.host}")
            # Clear the form and collapse after a short delay
            QTimer.singleShot(1500, lambda: self.remote_panel.setVisible(False))
        else:
            self.rp_status.setText(f"❌ {message}")

    def _cp_refresh_list(self):
        """Refresh the active connections list."""
        from app.core.remote_database_connector import remote_db_manager
        self.cp_list.clear()
        for conn_name in remote_db_manager.get_active_connections():
            if conn_name in self.remote_connections:
                cfg = self.remote_connections[conn_name]
                self.cp_list.addItem(
                    f"{conn_name}  ({cfg.db_type.upper()})  {cfg.host}:{cfg.port}/{cfg.database}"
                )

    def _cp_disconnect_selected(self):
        """Disconnect the selected connection."""
        from app.core.remote_database_connector import remote_db_manager
        item = self.cp_list.currentItem()
        if not item:
            return
        conn_name = item.text().split("  ")[0]
        if remote_db_manager.disconnect(conn_name):
            self.remote_connections.pop(conn_name, None)
            self.load_databases()
            self.status_label.setText(f"Disconnected from {conn_name}")
        self._cp_refresh_list()

    def _cp_disconnect_all(self):
        """Disconnect all remote connections."""
        from app.core.remote_database_connector import remote_db_manager
        remote_db_manager.disconnect_all()
        self.remote_connections.clear()
        self.load_databases()
        self.status_label.setText("All remote connections disconnected")
        self._cp_refresh_list()

    def connect_remote_database(self):
        """Legacy entry point — now opens the inline panel instead."""
        self.toggle_remote_panel()

    def manage_remote_connections(self):
        """Legacy entry point — now opens the inline panel instead."""
        self.toggle_connections_panel()
    
    def detect_database_type(self) -> str:
        """Detect database type based on current selection"""
        if hasattr(self, 'current_db_path') and self.current_db_path:
            if self.current_db_path.endswith('.db'):
                return "sqlite"
        
        # Check if we have an active remote connection
        from app.core.remote_database_connector import remote_db_manager
        active_connections = remote_db_manager.get_active_connections()
        
        for conn_name in active_connections:
            if conn_name in getattr(self, 'remote_connections', {}):
                config = self.remote_connections[conn_name]
                if config.db_type.lower() == 'mssql':
                    return "mssql"
        
        return "sqlite"
    
    def refresh_quick_queries(self):
        """Refresh quick queries based on database type"""
        db_type = self.detect_database_type()
        
        self.quick_query_combo.clear()
        
        if db_type == "mssql":
            self.quick_query_combo.addItems([
                "Select Quick Query...",
                "SELECT name FROM sys.databases;",
                "SELECT name FROM sys.tables;",
                "SELECT name, type_desc FROM sys.objects WHERE type IN ('U','V','P','FN');",
                "SELECT name FROM sys.columns WHERE object_id = OBJECT_ID('users');",
                "SELECT COUNT(*) FROM users;",
                "SELECT name, principal_id FROM sys.server_principals;",
                "SELECT name, principal_id FROM sys.database_principals;",
                "SELECT * FROM sys.server_permissions;",
                "SELECT * FROM sys.database_permissions;",
                "SELECT name FROM sys.servers WHERE is_linked = 1;",
                "SELECT @@VERSION;",
                "SELECT name, is_disabled FROM sys.server_principals WHERE type = 'S';",
                "SELECT name, default_schema_name FROM sys.database_principals WHERE type = 'S';",
                "SELECT name FROM sys.databases WHERE name NOT IN ('master','tempdb','model','msdb');",
                "EXEC sp_helpdb;",
                "SELECT name, filename FROM sys.sysfiles;",
                "SELECT loginname FROM sys.syslogins;",
                "SELECT * FROM INFORMATION_SCHEMA.TABLES;",
                "SELECT * FROM users WHERE username LIKE '%admin%';"
            ])
        else:
            # SQLite queries
            self.quick_query_combo.addItems([
                "Select Quick Query...",
                "SELECT name FROM sqlite_master WHERE type='table';",
                "SELECT * FROM sqlite_master;",
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='users';",
                "SELECT * FROM users;",
                "SELECT COUNT(*) FROM users;",
                "PRAGMA table_info(users);",
                "SELECT name, tbl_name, sql FROM sqlite_master WHERE type='index';",
                "SELECT name, sql FROM sqlite_master WHERE type='view';",
                ".dump",
                "SELECT name, sql FROM sqlite_master WHERE sql LIKE '%password%';",
                "SELECT * FROM users WHERE email LIKE '%@%';",
                "SELECT sqlite_version();",
                "PRAGMA foreign_key_list(users);",
                "PRAGMA database_list;",
                "SELECT name, sql FROM sqlite_master WHERE type='trigger';",
                "SELECT * FROM users LIMIT 5;",
                "PRAGMA table_info('<table_name>');",
                "SELECT DISTINCT role FROM users;"
            ])
    
    def cleanup_old_data(self):
        """Cleanup old data from database tables"""
        if not self.current_db_path:
            return
        
        try:
            # Get database name for context
            db_name = os.path.basename(self.current_db_path)
            
            # Show cleanup options dialog
            from PyQt6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QSpinBox, QComboBox, QPushButton, QCheckBox
            
            dialog = QDialog(self)
            dialog.setWindowTitle(f"Cleanup Old Data - {db_name}")
            dialog.setModal(True)
            dialog.resize(400, 300)
            
            layout = QVBoxLayout(dialog)
            
            # Instructions
            instructions = QLabel("Select cleanup options for old data:")
            instructions.setStyleSheet("font-weight: bold; margin-bottom: 10px;")
            layout.addWidget(instructions)
            
            # Days old input
            days_layout = QHBoxLayout()
            days_layout.addWidget(QLabel("Delete data older than:"))
            days_spin = QSpinBox()
            days_spin.setRange(1, 365)
            days_spin.setValue(30)
            days_spin.setSuffix(" days")
            days_layout.addWidget(days_spin)
            days_layout.addStretch()
            layout.addLayout(days_layout)
            
            # Database-specific cleanup options
            cleanup_options = []
            
            if "centralized_scan_data" in db_name:
                cleanup_options.extend([
                    ("scan_data", "last_seen", "Old scan results"),
                    ("scan_metadata", "start_time", "Old scan metadata"),
                    ("post_exploit_sessions", "updated_at", "Old post-exploitation sessions")
                ])
            elif "proxy" in db_name:
                cleanup_options.append(("requests", "timestamp", "Old HTTP requests"))
            elif "vulnerability_findings" in db_name:
                cleanup_options.append(("vulnerabilities", "timestamp", "Old vulnerability findings"))
            elif "auth_workflows" in db_name:
                cleanup_options.extend([
                    ("auth_flows", "created_at", "Old authentication flows"),
                    ("test_results", "created_at", "Old test results")
                ])
            elif "listeners" in db_name:
                cleanup_options.extend([
                    ("sessions", "last_seen", "Old listener sessions"),
                    ("audit_logs", "timestamp", "Old audit logs")
                ])
            elif "crawl" in db_name:
                cleanup_options.append(("crawl_results", "discovered_at", "Old crawl results"))
            
            # Create checkboxes for cleanup options
            checkboxes = []
            if cleanup_options:
                for table, date_col, description in cleanup_options:
                    checkbox = QCheckBox(f"{description} ({table}.{date_col})")
                    checkbox.setChecked(True)
                    checkbox.setProperty("table", table)
                    checkbox.setProperty("date_column", date_col)
                    checkboxes.append(checkbox)
                    layout.addWidget(checkbox)
            else:
                layout.addWidget(QLabel("No automatic cleanup options available for this database."))
            
            # Buttons
            button_layout = QHBoxLayout()
            cleanup_btn = QPushButton("Cleanup Selected")
            cancel_btn = QPushButton("Cancel")
            
            cleanup_btn.clicked.connect(dialog.accept)
            cancel_btn.clicked.connect(dialog.reject)
            
            button_layout.addWidget(cleanup_btn)
            button_layout.addWidget(cancel_btn)
            layout.addLayout(button_layout)
            
            if dialog.exec() == QDialog.DialogCode.Accepted and checkboxes:
                from app.core.database_utils import DatabaseUtils
                
                days_old = days_spin.value()
                total_cleaned = 0
                errors = []
                
                # Show progress
                self.progress_bar.setVisible(True)
                self.progress_bar.setRange(0, 0)
                self.cleanup_btn.setEnabled(False)
                
                for checkbox in checkboxes:
                    if checkbox.isChecked():
                        table = checkbox.property("table")
                        date_col = checkbox.property("date_column")
                        
                        try:
                            success, message = DatabaseUtils.cleanup_old_data(
                                self.current_db_path, table, date_col, days_old
                            )
                            if success:
                                # Extract number of rows from message
                                import re
                                match = re.search(r'(\d+) rows affected', message)
                                if match:
                                    total_cleaned += int(match.group(1))
                            else:
                                errors.append(f"{table}: {message}")
                        except Exception as e:
                            errors.append(f"{table}: {str(e)}")
                
                self.progress_bar.setVisible(False)
                self.cleanup_btn.setEnabled(True)
                
                # Show results
                result_msg = f"Cleanup completed.\n\nRows deleted: {total_cleaned}"
                if errors:
                    result_msg += f"\n\nErrors encountered:\n" + "\n".join(errors)
                
                if errors:
                    QMessageBox.warning(self, "Cleanup Results", result_msg)
                else:
                    QMessageBox.information(self, "Cleanup Results", result_msg)
                
                self.status_label.setText(f"Cleanup completed - {total_cleaned} rows deleted")
                
                # Refresh database info
                self.load_database_schema()
                
        except Exception as e:
            if hasattr(self, 'progress_bar'):
                self.progress_bar.setVisible(False)
            if hasattr(self, 'cleanup_btn'):
                self.cleanup_btn.setEnabled(True)
            QMessageBox.critical(self, "Error", f"Failed to cleanup old data:\n{e}")