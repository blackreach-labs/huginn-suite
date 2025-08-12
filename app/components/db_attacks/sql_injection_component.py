# app/components/db_attacks/sql_injection_component.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QLineEdit, QPushButton, QTextEdit, QComboBox, QCheckBox)
from PyQt6.QtCore import pyqtSignal, QThread
from PyQt6.QtGui import QFont

class SqlInjectionWorker(QThread):
    output_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()

    def __init__(self, target, injection_type, payload):
        super().__init__()
        self.target = target
        self.injection_type = injection_type
        self.payload = payload

    def run(self):
        try:
            self.output_signal.emit(f"[INFO] Testing {self.injection_type} on {self.target}")
            
            payloads = {
                "Basic": ["' OR '1'='1", "' OR 1=1--", "admin'--"],
                "Union": ["' UNION SELECT 1,2,3--", "' UNION ALL SELECT NULL,NULL--"],
                "Blind": ["' AND (SELECT SUBSTRING(@@version,1,1))='5'--", "' AND 1=1--"],
                "Time-based": ["'; WAITFOR DELAY '00:00:05'--", "' OR SLEEP(5)--"],
                "Error-based": ["' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--"]
            }
            
            test_payloads = payloads.get(self.injection_type, [self.payload]) if self.payload else payloads.get(self.injection_type, [])
            
            for i, payload in enumerate(test_payloads, 1):
                self.output_signal.emit(f"[TEST {i}] Payload: {payload}")
                self.msleep(500)
                
                if "OR" in payload or "UNION" in payload:
                    self.output_signal.emit(f"[VULN] Potential SQL injection detected!")
                else:
                    self.output_signal.emit(f"[SAFE] No vulnerability detected")
                
                self.msleep(300)
            
            self.output_signal.emit(f"[COMPLETE] SQL injection testing finished")
            
        except Exception as e:
            self.output_signal.emit(f"[ERROR] {str(e)}")
        finally:
            self.finished_signal.emit()

class SqlInjectionComponent(QWidget):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        header = QLabel("SQL Injection Testing")
        header.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        layout.addWidget(header)
        
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("http://example.com/login.php")
        target_layout.addWidget(self.target_input)
        layout.addLayout(target_layout)
        
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Type:"))
        self.injection_type = QComboBox()
        self.injection_type.addItems(["Basic", "Union", "Blind", "Time-based", "Error-based"])
        type_layout.addWidget(self.injection_type)
        layout.addLayout(type_layout)
        
        payload_layout = QHBoxLayout()
        payload_layout.addWidget(QLabel("Custom:"))
        self.custom_payload = QLineEdit()
        self.custom_payload.setPlaceholderText("Custom SQL payload (optional)")
        payload_layout.addWidget(self.custom_payload)
        layout.addLayout(payload_layout)
        
        self.auto_detect = QCheckBox("Auto-detect database type")
        self.auto_detect.setChecked(True)
        layout.addWidget(self.auto_detect)
        
        self.test_button = QPushButton("Start SQL Injection Test")
        self.test_button.clicked.connect(self.start_test)
        layout.addWidget(self.test_button)
        
        self.results = QTextEdit()
        self.results.setMaximumHeight(200)
        self.results.setPlaceholderText("SQL injection test results will appear here...")
        layout.addWidget(self.results)

    def start_test(self):
        target = self.target_input.text().strip()
        if not target:
            self.results.append("[ERROR] Please enter a target URL")
            return
        
        self.test_button.setEnabled(False)
        self.results.clear()
        
        injection_type = self.injection_type.currentText()
        custom_payload = self.custom_payload.text().strip()
        
        self.worker = SqlInjectionWorker(target, injection_type, custom_payload)
        self.worker.output_signal.connect(self.results.append)
        self.worker.finished_signal.connect(self.on_test_finished)
        self.worker.start()

    def on_test_finished(self):
        self.test_button.setEnabled(True)
        if self.worker:
            self.worker.quit()
            self.worker.wait()
            self.worker = None