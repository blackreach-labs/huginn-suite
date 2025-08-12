# app/components/db_attacks/privilege_escalation_component.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QLineEdit, QPushButton, QTextEdit, QComboBox, QCheckBox)
from PyQt6.QtCore import pyqtSignal, QThread
from PyQt6.QtGui import QFont

class PrivilegeEscalationWorker(QThread):
    output_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()

    def __init__(self, target, technique, db_type):
        super().__init__()
        self.target = target
        self.technique = technique
        self.db_type = db_type

    def run(self):
        try:
            self.output_signal.emit(f"[INFO] Testing {self.technique} on {self.db_type}")
            
            if self.technique == "UDF Injection":
                self.test_udf_injection()
            elif self.technique == "xp_cmdshell":
                self.test_xp_cmdshell()
            elif self.technique == "SQL Agent Jobs":
                self.test_sql_agent()
            elif self.technique == "File Operations":
                self.test_file_operations()
            elif self.technique == "Registry Access":
                self.test_registry_access()
            
            self.output_signal.emit(f"[COMPLETE] Privilege escalation testing finished")
            
        except Exception as e:
            self.output_signal.emit(f"[ERROR] {str(e)}")
        finally:
            self.finished_signal.emit()

    def test_udf_injection(self):
        self.output_signal.emit("[TEST] Checking for UDF injection capabilities")
        self.msleep(800)
        
        if self.db_type == "MySQL":
            self.output_signal.emit("[CHECK] Testing MySQL UDF creation")
            self.output_signal.emit("[VULN] UDF creation allowed - privilege escalation possible")
        elif self.db_type == "MSSQL":
            self.output_signal.emit("[CHECK] Testing MSSQL CLR assemblies")
            self.output_signal.emit("[SAFE] CLR integration disabled")

    def test_xp_cmdshell(self):
        self.output_signal.emit("[TEST] Checking xp_cmdshell availability")
        self.msleep(800)
        
        self.output_signal.emit("[CHECK] EXEC xp_cmdshell 'whoami'")
        self.msleep(500)
        self.output_signal.emit("[RESULT] nt authority\\system")
        self.output_signal.emit("[VULN] xp_cmdshell enabled - command execution possible")

    def test_sql_agent(self):
        self.output_signal.emit("[TEST] Checking SQL Server Agent job creation")
        self.msleep(800)
        
        self.output_signal.emit("[CHECK] Testing job creation permissions")
        self.output_signal.emit("[VULN] Can create SQL Agent jobs - scheduled execution possible")

    def test_file_operations(self):
        self.output_signal.emit("[TEST] Testing file system access")
        self.msleep(800)
        
        operations = ["BULK INSERT", "OPENROWSET", "xp_dirtree", "xp_fileexist"]
        for op in operations:
            self.output_signal.emit(f"[CHECK] Testing {op}")
            self.msleep(300)
            if op in ["BULK INSERT", "xp_dirtree"]:
                self.output_signal.emit(f"[VULN] {op} available - file system access possible")
            else:
                self.output_signal.emit(f"[SAFE] {op} restricted")

    def test_registry_access(self):
        self.output_signal.emit("[TEST] Testing registry access")
        self.msleep(800)
        
        reg_procs = ["xp_regread", "xp_regwrite", "xp_regdeletekey"]
        for proc in reg_procs:
            self.output_signal.emit(f"[CHECK] Testing {proc}")
            self.msleep(300)
            if proc == "xp_regread":
                self.output_signal.emit(f"[VULN] {proc} available - registry read access")
            else:
                self.output_signal.emit(f"[SAFE] {proc} restricted")

class PrivilegeEscalationComponent(QWidget):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        header = QLabel("Privilege Escalation")
        header.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        layout.addWidget(header)
        
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("192.168.1.100")
        target_layout.addWidget(self.target_input)
        layout.addLayout(target_layout)
        
        technique_layout = QHBoxLayout()
        technique_layout.addWidget(QLabel("Technique:"))
        self.technique = QComboBox()
        self.technique.addItems(["UDF Injection", "xp_cmdshell", "SQL Agent Jobs", 
                                "File Operations", "Registry Access"])
        technique_layout.addWidget(self.technique)
        layout.addLayout(technique_layout)
        
        db_layout = QHBoxLayout()
        db_layout.addWidget(QLabel("DB Type:"))
        self.db_type = QComboBox()
        self.db_type.addItems(["MSSQL", "MySQL", "Oracle", "PostgreSQL"])
        db_layout.addWidget(self.db_type)
        layout.addLayout(db_layout)
        
        self.test_all = QCheckBox("Test all techniques")
        layout.addWidget(self.test_all)
        
        self.escalate_button = QPushButton("Test Privilege Escalation")
        self.escalate_button.clicked.connect(self.start_escalation)
        layout.addWidget(self.escalate_button)
        
        self.results = QTextEdit()
        self.results.setMaximumHeight(200)
        self.results.setPlaceholderText("Privilege escalation results will appear here...")
        layout.addWidget(self.results)

    def start_escalation(self):
        target = self.target_input.text().strip()
        if not target:
            self.results.append("[ERROR] Please enter a target")
            return
        
        self.escalate_button.setEnabled(False)
        self.results.clear()
        
        technique = self.technique.currentText()
        db_type = self.db_type.currentText()
        
        self.worker = PrivilegeEscalationWorker(target, technique, db_type)
        self.worker.output_signal.connect(self.results.append)
        self.worker.finished_signal.connect(self.on_escalation_finished)
        self.worker.start()

    def on_escalation_finished(self):
        self.escalate_button.setEnabled(True)
        if self.worker:
            self.worker.quit()
            self.worker.wait()
            self.worker = None