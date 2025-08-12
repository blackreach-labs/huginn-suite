# app/components/db_attacks/data_extraction_component.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QLineEdit, QPushButton, QTextEdit, QComboBox, QSpinBox)
from PyQt6.QtCore import pyqtSignal, QThread
from PyQt6.QtGui import QFont

class DataExtractionWorker(QThread):
    output_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()

    def __init__(self, target, extraction_type, table_name, limit):
        super().__init__()
        self.target = target
        self.extraction_type = extraction_type
        self.table_name = table_name
        self.limit = limit

    def run(self):
        try:
            self.output_signal.emit(f"[INFO] Starting {self.extraction_type} on {self.target}")
            
            if self.extraction_type == "Schema Dump":
                self.extract_schema()
            elif self.extraction_type == "Table Data":
                self.extract_table_data()
            elif self.extraction_type == "User Credentials":
                self.extract_credentials()
            elif self.extraction_type == "System Info":
                self.extract_system_info()
            elif self.extraction_type == "File System":
                self.extract_files()
            
            self.output_signal.emit(f"[COMPLETE] Data extraction finished")
            
        except Exception as e:
            self.output_signal.emit(f"[ERROR] {str(e)}")
        finally:
            self.finished_signal.emit()

    def extract_schema(self):
        self.output_signal.emit("[SCHEMA] Extracting database schema")
        self.msleep(1000)
        
        tables = ["users", "products", "orders", "customers", "inventory"]
        self.output_signal.emit(f"[TABLES] Found {len(tables)} tables:")
        
        for table in tables:
            self.output_signal.emit(f"  Table: {table}")
            self.msleep(300)
            
            if table == "users":
                columns = ["id", "username", "password", "email", "role"]
            elif table == "products":
                columns = ["id", "name", "price", "category", "stock"]
            else:
                columns = ["id", "name", "created_at", "updated_at"]
            
            for col in columns:
                self.output_signal.emit(f"    - {col}")
                self.msleep(100)

    def extract_table_data(self):
        table = self.table_name or "users"
        self.output_signal.emit(f"[DATA] Extracting data from {table} table (limit: {self.limit})")
        self.msleep(800)
        
        if table == "users":
            sample_data = [
                ("1", "admin", "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", "admin@company.com", "admin"),
                ("2", "john_doe", "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f", "john@company.com", "user"),
                ("3", "jane_smith", "secret123", "jane@company.com", "user")
            ]
        else:
            sample_data = [("1", "Sample Data", "2023-01-01", "2023-01-01")]
        
        self.output_signal.emit(f"[RESULTS] Retrieved {len(sample_data)} records:")
        for i, row in enumerate(sample_data[:self.limit], 1):
            self.output_signal.emit(f"  Row {i}: {' | '.join(row)}")
            self.msleep(200)

    def extract_credentials(self):
        self.output_signal.emit("[CREDS] Searching for stored credentials")
        self.msleep(1000)
        
        cred_sources = [
            ("users table", "3 password hashes found"),
            ("config table", "1 database connection string"),
            ("application_settings", "2 API keys found"),
            ("service_accounts", "1 service account password")
        ]
        
        for source, finding in cred_sources:
            self.output_signal.emit(f"[FOUND] {source}: {finding}")
            self.msleep(400)
        
        self.output_signal.emit("[WARNING] Plaintext passwords detected!")

    def extract_system_info(self):
        self.output_signal.emit("[SYSINFO] Gathering system information")
        self.msleep(800)
        
        info_items = [
            ("Database Version", "Microsoft SQL Server 2019"),
            ("Operating System", "Windows Server 2019"),
            ("Server Name", "DB-SERVER-01"),
            ("Instance Name", "MSSQLSERVER"),
            ("Service Account", "NT SERVICE\\MSSQLSERVER"),
            ("Database Size", "2.5 GB"),
            ("Memory Usage", "4 GB allocated")
        ]
        
        for item, value in info_items:
            self.output_signal.emit(f"[INFO] {item}: {value}")
            self.msleep(300)

    def extract_files(self):
        self.output_signal.emit("[FILES] Attempting file system access")
        self.msleep(800)
        
        files = [
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "C:\\inetpub\\wwwroot\\web.config",
            "C:\\Program Files\\Microsoft SQL Server\\MSSQL15.MSSQLSERVER\\MSSQL\\Log\\ERRORLOG"
        ]
        
        for file_path in files:
            self.output_signal.emit(f"[ACCESS] Reading: {file_path}")
            self.msleep(500)
            if "web.config" in file_path:
                self.output_signal.emit("[FOUND] Connection strings in web.config")
            elif "ERRORLOG" in file_path:
                self.output_signal.emit("[FOUND] Database error logs accessible")
            else:
                self.output_signal.emit("[READ] File contents retrieved")

class DataExtractionComponent(QWidget):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        header = QLabel("Data Extraction")
        header.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        layout.addWidget(header)
        
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("192.168.1.100")
        target_layout.addWidget(self.target_input)
        layout.addLayout(target_layout)
        
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Type:"))
        self.extraction_type = QComboBox()
        self.extraction_type.addItems(["Schema Dump", "Table Data", "User Credentials", 
                                      "System Info", "File System"])
        type_layout.addWidget(self.extraction_type)
        layout.addLayout(type_layout)
        
        table_layout = QHBoxLayout()
        table_layout.addWidget(QLabel("Table:"))
        self.table_input = QLineEdit()
        self.table_input.setPlaceholderText("users (for Table Data extraction)")
        table_layout.addWidget(self.table_input)
        layout.addLayout(table_layout)
        
        limit_layout = QHBoxLayout()
        limit_layout.addWidget(QLabel("Limit:"))
        self.limit_spin = QSpinBox()
        self.limit_spin.setRange(1, 1000)
        self.limit_spin.setValue(10)
        limit_layout.addWidget(self.limit_spin)
        layout.addLayout(limit_layout)
        
        self.extract_button = QPushButton("Start Data Extraction")
        self.extract_button.clicked.connect(self.start_extraction)
        layout.addWidget(self.extract_button)
        
        self.results = QTextEdit()
        self.results.setMaximumHeight(200)
        self.results.setPlaceholderText("Data extraction results will appear here...")
        layout.addWidget(self.results)

    def start_extraction(self):
        target = self.target_input.text().strip()
        if not target:
            self.results.append("[ERROR] Please enter a target")
            return
        
        self.extract_button.setEnabled(False)
        self.results.clear()
        
        extraction_type = self.extraction_type.currentText()
        table_name = self.table_input.text().strip()
        limit = self.limit_spin.value()
        
        self.worker = DataExtractionWorker(target, extraction_type, table_name, limit)
        self.worker.output_signal.connect(self.results.append)
        self.worker.finished_signal.connect(self.on_extraction_finished)
        self.worker.start()

    def on_extraction_finished(self):
        self.extract_button.setEnabled(True)
        if self.worker:
            self.worker.quit()
            self.worker.wait()
            self.worker = None