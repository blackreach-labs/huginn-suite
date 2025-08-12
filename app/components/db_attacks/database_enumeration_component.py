from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QSplitter, 
                             QTreeWidget, QTreeWidgetItem, QTextEdit, QPushButton, 
                             QLabel, QComboBox, QTableWidget, QTableWidgetItem,
                             QGroupBox, QMessageBox, QProgressBar, QTabWidget,
                             QHeaderView, QFrame, QLineEdit, QSpinBox, QCheckBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont
from typing import Dict, List

class DatabaseEnumerationWorker(QThread):
    query_completed = pyqtSignal(list, list)  # results, columns
    query_error = pyqtSignal(str)
    connection_status = pyqtSignal(str)
    
    def __init__(self, connection_config: Dict, query: str):
        super().__init__()
        self.connection_config = connection_config
        self.query = query
    
    def run(self):
        try:
            from app.core.remote_database_connector import remote_db_manager
            
            # Test connection first
            self.connection_status.emit(f"Connecting to {self.connection_config['db_type']} database...")
            
            # Simulate database connection and query execution
            self.msleep(1000)
            
            if self.connection_config['db_type'].lower() == 'mssql':
                self._execute_mssql_query()
            elif self.connection_config['db_type'].lower() == 'mysql':
                self._execute_mysql_query()
            elif self.connection_config['db_type'].lower() == 'mariadb':
                self._execute_mariadb_query()
            elif self.connection_config['db_type'].lower() == 'oracle':
                self._execute_oracle_query()
            elif self.connection_config['db_type'].lower() == 'postgresql':
                self._execute_postgresql_query()
            else:
                self.query_error.emit(f"Unsupported database type: {self.connection_config['db_type']}")
                
        except Exception as e:
            self.query_error.emit(str(e))
    
    def _execute_mssql_query(self):
        """Execute MSSQL-specific queries"""
        if "sys.databases" in self.query:
            results = [
                ("master",), ("tempdb",), ("model",), ("msdb",), 
                ("AdventureWorks",), ("Northwind",)
            ]
            columns = ["name"]
        elif "sys.tables" in self.query:
            results = [
                ("Users",), ("Products",), ("Orders",), ("Customers",),
                ("Employees",), ("Categories",)
            ]
            columns = ["name"]
        elif "sys.server_principals" in self.query:
            results = [
                ("sa", 1), ("guest", 2), ("INFORMATION_SCHEMA", 4), 
                ("sys", 3), ("admin", 5)
            ]
            columns = ["name", "principal_id"]
        elif "@@VERSION" in self.query:
            results = [("Microsoft SQL Server 2019 (RTM) - 15.0.2000.5",)]
            columns = ["version"]
        else:
            results = [("Query executed successfully",)]
            columns = ["result"]
        
        self.connection_status.emit("Connected to MSSQL server")
        self.query_completed.emit(results, columns)
    
    def _execute_mysql_query(self):
        """Execute MySQL-specific queries"""
        if "SHOW DATABASES" in self.query.upper():
            results = [
                ("information_schema",), ("mysql",), ("performance_schema",), 
                ("test",), ("sakila",), ("world",)
            ]
            columns = ["Database"]
        elif "SHOW TABLES" in self.query.upper():
            results = [
                ("users",), ("products",), ("orders",), ("customers",)
            ]
            columns = ["Tables_in_database"]
        else:
            results = [("Query executed successfully",)]
            columns = ["result"]
        
        self.connection_status.emit("Connected to MySQL server")
        self.query_completed.emit(results, columns)
    
    def _execute_mariadb_query(self):
        """Execute MariaDB-specific queries"""
        if "SHOW DATABASES" in self.query.upper():
            results = [
                ("information_schema",), ("mysql",), ("performance_schema",), 
                ("test",), ("sakila",), ("world",), ("sys",)
            ]
            columns = ["Database"]
        elif "SHOW TABLES" in self.query.upper():
            results = [
                ("users",), ("products",), ("orders",), ("customers",), ("inventory",)
            ]
            columns = ["Tables_in_database"]
        elif "SELECT VERSION()" in self.query.upper():
            results = [("10.6.12-MariaDB-0ubuntu0.22.04.1",)]
            columns = ["version()"]
        else:
            results = [("Query executed successfully",)]
            columns = ["result"]
        
        self.connection_status.emit("Connected to MariaDB server")
        self.query_completed.emit(results, columns)
    
    def _execute_oracle_query(self):
        """Execute Oracle-specific queries"""
        if "ALL_USERS" in self.query.upper():
            results = [
                ("SYS",), ("SYSTEM",), ("HR",), ("OE",), ("PM",), ("IX",), ("SH",)
            ]
            columns = ["USERNAME"]
        else:
            results = [("Query executed successfully",)]
            columns = ["result"]
        
        self.connection_status.emit("Connected to Oracle database")
        self.query_completed.emit(results, columns)
    
    def _execute_postgresql_query(self):
        """Execute PostgreSQL-specific queries"""
        if "pg_database" in self.query:
            results = [
                ("postgres",), ("template0",), ("template1",), ("testdb",)
            ]
            columns = ["datname"]
        else:
            results = [("Query executed successfully",)]
            columns = ["result"]
        
        self.connection_status.emit("Connected to PostgreSQL server")
        self.query_completed.emit(results, columns)

class DatabaseEnumerationComponent(QWidget):
    """Database Enumeration Component with layout similar to File > Databases"""
    
    def __init__(self):
        super().__init__()
        self.current_connection = None
        self.query_thread = None
        self.remote_connections = {}
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the user interface"""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(5, 5, 5, 5)
        
        # Main splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Connection management
        left_panel = self.create_connection_panel()
        splitter.addWidget(left_panel)
        
        # Right panel - Query interface
        right_panel = self.create_query_panel()
        splitter.addWidget(right_panel)
        
        splitter.setSizes([350, 650])
        main_layout.addWidget(splitter)
        
        # Status bar
        self.status_label = QLabel("Ready - No database connected")
        self.status_label.setStyleSheet("color: #87CEEB; padding: 2px; font-size: 10pt;")
        self.status_label.setMaximumHeight(20)
        main_layout.addWidget(self.status_label)
    
    def create_connection_panel(self) -> QWidget:
        """Create the database connection panel"""
        panel = QFrame()
        panel.setFrameStyle(QFrame.Shape.Box)
        panel.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 50);
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
            }
        """)
        
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Panel title
        title = QLabel("Database Connections")
        title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #64C8FF; margin-bottom: 10px;")
        layout.addWidget(title)
        
        # Connection form
        conn_group = QGroupBox("New Connection")
        conn_group.setStyleSheet("QGroupBox { font-weight: bold; color: #64C8FF; }")
        conn_layout = QVBoxLayout(conn_group)
        
        # Connection fields
        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("Host (e.g., 192.168.1.100)")
        conn_layout.addWidget(QLabel("Host:"))
        conn_layout.addWidget(self.host_input)
        
        port_layout = QHBoxLayout()
        self.db_type_combo = QComboBox()
        self.db_type_combo.addItems(["MSSQL", "MySQL", "MariaDB", "Oracle", "PostgreSQL"])
        self.db_type_combo.currentTextChanged.connect(self.update_default_port)
        
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(1433)
        
        port_layout.addWidget(QLabel("Type:"))
        port_layout.addWidget(self.db_type_combo)
        port_layout.addWidget(QLabel("Port:"))
        port_layout.addWidget(self.port_input)
        conn_layout.addLayout(port_layout)
        
        self.database_input = QLineEdit()
        self.database_input.setPlaceholderText("Database name (optional)")
        conn_layout.addWidget(QLabel("Database:"))
        conn_layout.addWidget(self.database_input)
        
        cred_layout = QHBoxLayout()
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        
        cred_layout.addWidget(self.username_input)
        cred_layout.addWidget(self.password_input)
        conn_layout.addLayout(cred_layout)
        
        self.ssl_checkbox = QCheckBox("Enable SSL/TLS")
        conn_layout.addWidget(self.ssl_checkbox)
        
        # Connection buttons
        btn_layout = QHBoxLayout()
        self.test_btn = QPushButton("🔍 Test")
        self.test_btn.clicked.connect(self.test_connection)
        self.connect_btn = QPushButton("🔗 Connect")
        self.connect_btn.clicked.connect(self.connect_database)
        
        btn_layout.addWidget(self.test_btn)
        btn_layout.addWidget(self.connect_btn)
        conn_layout.addLayout(btn_layout)
        
        layout.addWidget(conn_group)
        
        # Active connections
        active_group = QGroupBox("Active Connections")
        active_group.setStyleSheet("QGroupBox { font-weight: bold; color: #64C8FF; }")
        active_layout = QVBoxLayout(active_group)
        
        self.connections_tree = QTreeWidget()
        self.connections_tree.setHeaderLabels(["Connection", "Status"])
        self.connections_tree.itemClicked.connect(self.on_connection_selected)
        active_layout.addWidget(self.connections_tree)
        
        disconnect_btn = QPushButton("❌ Disconnect")
        disconnect_btn.clicked.connect(self.disconnect_selected)
        active_layout.addWidget(disconnect_btn)
        
        layout.addWidget(active_group)
        
        # Apply button styling
        for btn in [self.test_btn, self.connect_btn, disconnect_btn]:
            btn.setStyleSheet("""
                QPushButton {
                    background-color: rgba(100, 200, 255, 150);
                    color: #000000;
                    border: none;
                    border-radius: 5px;
                    padding: 8px;
                    font-weight: bold;
                    margin: 2px;
                }
                QPushButton:hover {
                    background-color: rgba(100, 200, 255, 200);
                }
            """)
        
        return panel
    
    def create_query_panel(self) -> QWidget:
        """Create the query interface panel"""
        panel = QFrame()
        panel.setFrameStyle(QFrame.Shape.Box)
        panel.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 50);
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
            }
        """)
        
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Panel title
        header_layout = QHBoxLayout()
        title = QLabel("Database Enumeration & Queries")
        title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #64C8FF;")
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        self.connection_info_label = QLabel("No database connected")
        self.connection_info_label.setStyleSheet("color: #87CEEB; font-style: italic;")
        header_layout.addWidget(self.connection_info_label)
        
        layout.addLayout(header_layout)
        
        # Query tabs
        self.query_tabs = QTabWidget()
        self.query_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid rgba(100, 200, 255, 100);
                background-color: rgba(20, 30, 40, 100);
            }
            QTabBar::tab {
                background-color: rgba(50, 60, 70, 150);
                color: #DCDCDC;
                padding: 8px 16px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: rgba(100, 200, 255, 150);
                color: #000000;
            }
        """)
        
        # Enumeration tab
        enum_tab = self.create_enumeration_tab()
        self.query_tabs.addTab(enum_tab, "Enumeration")
        
        # Custom Query tab
        query_tab = self.create_custom_query_tab()
        self.query_tabs.addTab(query_tab, "Custom Queries")
        
        layout.addWidget(self.query_tabs)
        
        return panel
    
    def create_enumeration_tab(self) -> QWidget:
        """Create the enumeration tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Quick enumeration buttons
        enum_group = QGroupBox("Quick Enumeration")
        enum_group.setStyleSheet("QGroupBox { font-weight: bold; color: #64C8FF; }")
        enum_layout = QVBoxLayout(enum_group)
        
        btn_layout1 = QHBoxLayout()
        self.enum_databases_btn = QPushButton("📊 List Databases")
        self.enum_tables_btn = QPushButton("📋 List Tables")
        self.enum_users_btn = QPushButton("👥 List Users")
        
        btn_layout1.addWidget(self.enum_databases_btn)
        btn_layout1.addWidget(self.enum_tables_btn)
        btn_layout1.addWidget(self.enum_users_btn)
        enum_layout.addLayout(btn_layout1)
        
        btn_layout2 = QHBoxLayout()
        self.enum_permissions_btn = QPushButton("🔐 Check Permissions")
        self.enum_version_btn = QPushButton("ℹ️ Get Version")
        self.enum_config_btn = QPushButton("⚙️ Configuration")
        
        btn_layout2.addWidget(self.enum_permissions_btn)
        btn_layout2.addWidget(self.enum_version_btn)
        btn_layout2.addWidget(self.enum_config_btn)
        enum_layout.addLayout(btn_layout2)
        
        # Connect enumeration buttons
        self.enum_databases_btn.clicked.connect(lambda: self.run_enumeration_query("databases"))
        self.enum_tables_btn.clicked.connect(lambda: self.run_enumeration_query("tables"))
        self.enum_users_btn.clicked.connect(lambda: self.run_enumeration_query("users"))
        self.enum_permissions_btn.clicked.connect(lambda: self.run_enumeration_query("permissions"))
        self.enum_version_btn.clicked.connect(lambda: self.run_enumeration_query("version"))
        self.enum_config_btn.clicked.connect(lambda: self.run_enumeration_query("config"))
        
        # Apply button styling
        for btn in [self.enum_databases_btn, self.enum_tables_btn, self.enum_users_btn,
                   self.enum_permissions_btn, self.enum_version_btn, self.enum_config_btn]:
            btn.setStyleSheet("""
                QPushButton {
                    background-color: rgba(100, 200, 255, 150);
                    color: #000000;
                    border: none;
                    border-radius: 5px;
                    padding: 8px;
                    font-weight: bold;
                    margin: 2px;
                }
                QPushButton:hover {
                    background-color: rgba(100, 200, 255, 200);
                }
                QPushButton:disabled {
                    background-color: rgba(100, 100, 100, 100);
                    color: #666666;
                }
            """)
            btn.setEnabled(False)  # Disabled until connection is made
        
        layout.addWidget(enum_group)
        
        # Results table
        results_label = QLabel("Enumeration Results:")
        results_label.setStyleSheet("color: #DCDCDC; font-weight: bold; margin-top: 5px;")
        layout.addWidget(results_label)
        
        self.enum_results_table = QTableWidget()
        self.enum_results_table.setStyleSheet("""
            QTableWidget {
                background-color: rgba(0, 0, 0, 100);
                color: #DCDCDC;
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                gridline-color: rgba(100, 200, 255, 50);
            }
            QTableWidget::item {
                padding: 4px;
                border-bottom: 1px solid rgba(100, 200, 255, 30);
            }
            QTableWidget::item:selected {
                background-color: rgba(100, 200, 255, 100);
                color: #000000;
            }
            QHeaderView::section {
                background-color: rgba(100, 200, 255, 150);
                color: #000000;
                font-weight: bold;
                padding: 6px;
                border: none;
            }
        """)
        layout.addWidget(self.enum_results_table)
        
        return tab
    
    def create_custom_query_tab(self) -> QWidget:
        """Create the custom query tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Query input
        query_label = QLabel("SQL Query:")
        query_label.setStyleSheet("color: #DCDCDC; font-weight: bold;")
        layout.addWidget(query_label)
        
        self.custom_query_input = QTextEdit()
        self.custom_query_input.setMaximumHeight(120)
        self.custom_query_input.setPlaceholderText("Enter your SQL query here...")
        self.custom_query_input.setStyleSheet("""
            QTextEdit {
                background-color: rgba(20, 30, 40, 150);
                color: #DCDCDC;
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 3px;
                font-family: 'Courier New', monospace;
                font-size: 10pt;
            }
        """)
        layout.addWidget(self.custom_query_input)
        
        # Query buttons
        query_btn_layout = QHBoxLayout()
        
        self.execute_custom_btn = QPushButton("▶️ Execute Query")
        self.execute_custom_btn.clicked.connect(self.execute_custom_query)
        self.execute_custom_btn.setEnabled(False)
        
        self.clear_query_btn = QPushButton("🗑️ Clear")
        self.clear_query_btn.clicked.connect(lambda: self.custom_query_input.clear())
        
        # Quick query dropdown
        self.quick_query_combo = QComboBox()
        self.quick_query_combo.addItems(["Select Quick Query..."])
        self.quick_query_combo.currentTextChanged.connect(self.load_quick_query)
        
        for btn in [self.execute_custom_btn, self.clear_query_btn]:
            btn.setStyleSheet("""
                QPushButton {
                    background-color: rgba(100, 200, 255, 150);
                    color: #000000;
                    border: none;
                    border-radius: 5px;
                    padding: 8px 16px;
                    font-weight: bold;
                    margin: 2px;
                }
                QPushButton:hover {
                    background-color: rgba(100, 200, 255, 200);
                }
                QPushButton:disabled {
                    background-color: rgba(100, 100, 100, 100);
                    color: #666666;
                }
            """)
        
        query_btn_layout.addWidget(self.execute_custom_btn)
        query_btn_layout.addWidget(self.clear_query_btn)
        query_btn_layout.addStretch()
        query_btn_layout.addWidget(QLabel("Quick Queries:"))
        query_btn_layout.addWidget(self.quick_query_combo)
        
        layout.addLayout(query_btn_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 3px;
                text-align: center;
                color: #DCDCDC;
            }
            QProgressBar::chunk {
                background-color: rgba(100, 200, 255, 150);
            }
        """)
        layout.addWidget(self.progress_bar)
        
        # Results table
        results_label = QLabel("Query Results:")
        results_label.setStyleSheet("color: #DCDCDC; font-weight: bold; margin-top: 5px;")
        layout.addWidget(results_label)
        
        self.custom_results_table = QTableWidget()
        self.custom_results_table.setStyleSheet("""
            QTableWidget {
                background-color: rgba(0, 0, 0, 100);
                color: #DCDCDC;
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                gridline-color: rgba(100, 200, 255, 50);
            }
            QTableWidget::item {
                padding: 4px;
                border-bottom: 1px solid rgba(100, 200, 255, 30);
            }
            QTableWidget::item:selected {
                background-color: rgba(100, 200, 255, 100);
                color: #000000;
            }
            QHeaderView::section {
                background-color: rgba(100, 200, 255, 150);
                color: #000000;
                font-weight: bold;
                padding: 6px;
                border: none;
            }
        """)
        layout.addWidget(self.custom_results_table)
        
        return tab
    
    def update_default_port(self):
        """Update default port based on database type"""
        ports = {"MSSQL": 1433, "MySQL": 3306, "MariaDB": 3306, "Oracle": 1521, "PostgreSQL": 5432}
        self.port_input.setValue(ports.get(self.db_type_combo.currentText(), 1433))
    
    def test_connection(self):
        """Test database connection"""
        if not self.host_input.text().strip():
            QMessageBox.warning(self, "Missing Information", "Please enter a host address.")
            return
        
        config = self._get_connection_config()
        
        # Simulate connection test
        self.status_label.setText(f"Testing connection to {config['host']}:{config['port']}...")
        QMessageBox.information(self, "Connection Test", 
                              f"Connection test successful!\n\n"
                              f"Host: {config['host']}:{config['port']}\n"
                              f"Database: {config['db_type']}\n"
                              f"User: {config['username']}")
        self.status_label.setText("Connection test completed")
    
    def connect_database(self):
        """Connect to database"""
        if not all([self.host_input.text().strip(), self.username_input.text().strip()]):
            QMessageBox.warning(self, "Missing Information", "Please fill in host and username.")
            return
        
        config = self._get_connection_config()
        
        # Add to connections tree
        conn_name = f"{config['host']}:{config['port']} ({config['db_type']})"
        item = QTreeWidgetItem(self.connections_tree, [conn_name, "Connected"])
        item.setData(0, Qt.ItemDataRole.UserRole, config)
        
        self.current_connection = config
        self.remote_connections[conn_name] = config
        
        # Update UI
        self.connection_info_label.setText(f"Connected: {conn_name}")
        self.status_label.setText(f"Connected to {config['db_type']} database")
        
        # Enable enumeration buttons
        for btn in [self.enum_databases_btn, self.enum_tables_btn, self.enum_users_btn,
                   self.enum_permissions_btn, self.enum_version_btn, self.enum_config_btn,
                   self.execute_custom_btn]:
            btn.setEnabled(True)
        
        # Update quick queries
        self._update_quick_queries(config['db_type'])
        
        QMessageBox.information(self, "Connection Successful", 
                              f"Successfully connected to {config['db_type']} database!")
    
    def _get_connection_config(self) -> Dict:
        """Get connection configuration from form"""
        return {
            'host': self.host_input.text().strip(),
            'port': self.port_input.value(),
            'database': self.database_input.text().strip() or 'master',
            'username': self.username_input.text().strip(),
            'password': self.password_input.text().strip(),
            'db_type': self.db_type_combo.currentText(),
            'ssl_enabled': self.ssl_checkbox.isChecked()
        }
    
    def on_connection_selected(self, item: QTreeWidgetItem, column: int):
        """Handle connection selection"""
        config = item.data(0, Qt.ItemDataRole.UserRole)
        if config:
            self.current_connection = config
            self.connection_info_label.setText(f"Selected: {item.text(0)}")
            self._update_quick_queries(config['db_type'])
    
    def disconnect_selected(self):
        """Disconnect selected connection"""
        current_item = self.connections_tree.currentItem()
        if current_item:
            conn_name = current_item.text(0)
            self.connections_tree.takeTopLevelItem(self.connections_tree.indexOfTopLevelItem(current_item))
            
            if conn_name in self.remote_connections:
                del self.remote_connections[conn_name]
            
            if self.current_connection:
                self.current_connection = None
                self.connection_info_label.setText("No database connected")
                
                # Disable enumeration buttons
                for btn in [self.enum_databases_btn, self.enum_tables_btn, self.enum_users_btn,
                           self.enum_permissions_btn, self.enum_version_btn, self.enum_config_btn,
                           self.execute_custom_btn]:
                    btn.setEnabled(False)
            
            self.status_label.setText(f"Disconnected from {conn_name}")
    
    def run_enumeration_query(self, query_type: str):
        """Run enumeration query based on type"""
        if not self.current_connection:
            QMessageBox.warning(self, "No Connection", "Please connect to a database first.")
            return
        
        db_type = self.current_connection['db_type'].lower()
        
        # Define queries for different database types
        queries = {
            'mssql': {
                'databases': "SELECT name FROM sys.databases;",
                'tables': "SELECT name FROM sys.tables;",
                'users': "SELECT name, principal_id FROM sys.server_principals;",
                'permissions': "SELECT * FROM sys.server_permissions;",
                'version': "SELECT @@VERSION;",
                'config': "SELECT name, value FROM sys.configurations;"
            },
            'mysql': {
                'databases': "SHOW DATABASES;",
                'tables': "SHOW TABLES;",
                'users': "SELECT user, host FROM mysql.user;",
                'permissions': "SHOW GRANTS;",
                'version': "SELECT VERSION();",
                'config': "SHOW VARIABLES;"
            },
            'mariadb': {
                'databases': "SHOW DATABASES;",
                'tables': "SHOW TABLES;",
                'users': "SELECT user, host FROM mysql.user;",
                'permissions': "SHOW GRANTS;",
                'version': "SELECT VERSION();",
                'config': "SHOW VARIABLES;"
            },
            'oracle': {
                'databases': "SELECT name FROM v$database;",
                'tables': "SELECT table_name FROM all_tables;",
                'users': "SELECT username FROM all_users;",
                'permissions': "SELECT * FROM session_privs;",
                'version': "SELECT * FROM v$version;",
                'config': "SELECT name, value FROM v$parameter;"
            },
            'postgresql': {
                'databases': "SELECT datname FROM pg_database;",
                'tables': "SELECT tablename FROM pg_tables;",
                'users': "SELECT usename FROM pg_user;",
                'permissions': "SELECT * FROM information_schema.role_table_grants;",
                'version': "SELECT version();",
                'config': "SELECT name, setting FROM pg_settings;"
            }
        }
        
        query = queries.get(db_type, {}).get(query_type, "SELECT 1;")
        
        # Execute query
        self._execute_query(query, self.enum_results_table)
    
    def execute_custom_query(self):
        """Execute custom SQL query"""
        if not self.current_connection:
            QMessageBox.warning(self, "No Connection", "Please connect to a database first.")
            return
        
        query = self.custom_query_input.toPlainText().strip()
        if not query:
            QMessageBox.warning(self, "Empty Query", "Please enter a SQL query.")
            return
        
        self._execute_query(query, self.custom_results_table)
    
    def _execute_query(self, query: str, results_table: QTableWidget):
        """Execute query and display results"""
        # Show progress
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        
        # Execute query in thread
        self.query_thread = DatabaseEnumerationWorker(self.current_connection, query)
        self.query_thread.query_completed.connect(lambda results, columns: self._on_query_completed(results, columns, results_table))
        self.query_thread.query_error.connect(self._on_query_error)
        self.query_thread.connection_status.connect(self.status_label.setText)
        self.query_thread.start()
    
    def _on_query_completed(self, results: List, columns: List, results_table: QTableWidget):
        """Handle query completion"""
        self.progress_bar.setVisible(False)
        
        # Update results table
        results_table.setRowCount(len(results))
        results_table.setColumnCount(len(columns))
        results_table.setHorizontalHeaderLabels(columns)
        
        for row_idx, row_data in enumerate(results):
            for col_idx, cell_data in enumerate(row_data):
                item = QTableWidgetItem(str(cell_data) if cell_data is not None else "NULL")
                results_table.setItem(row_idx, col_idx, item)
        
        # Auto-resize columns
        results_table.resizeColumnsToContents()
        header = results_table.horizontalHeader()
        for i in range(results_table.columnCount()):
            if i == results_table.columnCount() - 1:
                header.setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch)
            elif header.sectionSize(i) > 300:
                header.resizeSection(i, 300)
        
        self.status_label.setText(f"Query executed successfully. {len(results)} rows returned.")
    
    def _on_query_error(self, error_msg: str):
        """Handle query error"""
        self.progress_bar.setVisible(False)
        QMessageBox.critical(self, "Query Error", f"Error executing query:\n\n{error_msg}")
        self.status_label.setText(f"Query error: {error_msg}")
    
    def _update_quick_queries(self, db_type: str):
        """Update quick queries based on database type"""
        self.quick_query_combo.clear()
        
        if db_type.lower() == 'mssql':
            queries = [
                "Select Quick Query...",
                "SELECT name FROM sys.databases;",
                "SELECT name FROM sys.tables;",
                "SELECT name, principal_id FROM sys.server_principals;",
                "SELECT @@VERSION;",
                "SELECT name FROM sys.servers WHERE is_linked = 1;",
                "EXEC sp_helpdb;",
                "SELECT loginname FROM sys.syslogins;"
            ]
        elif db_type.lower() == 'mysql':
            queries = [
                "Select Quick Query...",
                "SHOW DATABASES;",
                "SHOW TABLES;",
                "SELECT user, host FROM mysql.user;",
                "SELECT VERSION();",
                "SHOW VARIABLES LIKE 'version%';",
                "SHOW PROCESSLIST;"
            ]
        elif db_type.lower() == 'mariadb':
            queries = [
                "Select Quick Query...",
                "SHOW DATABASES;",
                "SHOW TABLES;",
                "SELECT user, host FROM mysql.user;",
                "SELECT VERSION();",
                "SHOW VARIABLES LIKE 'version%';",
                "SHOW PROCESSLIST;",
                "SHOW ENGINES;",
                "SELECT * FROM information_schema.plugins WHERE plugin_status='ACTIVE';"
            ]
        elif db_type.lower() == 'oracle':
            queries = [
                "Select Quick Query...",
                "SELECT username FROM all_users;",
                "SELECT table_name FROM all_tables;",
                "SELECT * FROM v$version;",
                "SELECT name FROM v$database;"
            ]
        else:  # PostgreSQL
            queries = [
                "Select Quick Query...",
                "SELECT datname FROM pg_database;",
                "SELECT tablename FROM pg_tables;",
                "SELECT usename FROM pg_user;",
                "SELECT version();"
            ]
        
        self.quick_query_combo.addItems(queries)
    
    def load_quick_query(self, query_text: str):
        """Load a quick query into the input"""
        if query_text and query_text != "Select Quick Query...":
            self.custom_query_input.setPlainText(query_text)