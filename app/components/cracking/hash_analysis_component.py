# app/components/cracking/hash_analysis_component.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QLineEdit, QPushButton, QTextEdit, QComboBox, QFileDialog)
from PyQt6.QtCore import pyqtSignal, QThread
from PyQt6.QtGui import QFont

class HashAnalysisWorker(QThread):
    output_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()

    def __init__(self, hashes, analysis_type):
        super().__init__()
        self.hashes = hashes
        self.analysis_type = analysis_type

    def run(self):
        try:
            self.output_signal.emit(f"[INFO] Starting {self.analysis_type} analysis")
            
            if self.analysis_type == "Identify":
                self.identify_hashes()
            elif self.analysis_type == "Validate":
                self.validate_hashes()
            elif self.analysis_type == "Statistics":
                self.analyze_statistics()
            
            self.output_signal.emit(f"[COMPLETE] Hash analysis finished")
            
        except Exception as e:
            self.output_signal.emit(f"[ERROR] {str(e)}")
        finally:
            self.finished_signal.emit()

    def identify_hashes(self):
        self.output_signal.emit("[IDENTIFY] Analyzing hash types...")
        self.msleep(800)
        
        hash_types = {
            32: "MD5",
            40: "SHA1", 
            56: "SHA224",
            64: "SHA256",
            96: "SHA384",
            128: "SHA512"
        }
        
        for i, hash_val in enumerate(self.hashes, 1):
            hash_val = hash_val.strip()
            if not hash_val:
                continue
                
            length = len(hash_val)
            hash_type = hash_types.get(length, "Unknown")
            
            self.output_signal.emit(f"[HASH {i}] {hash_val[:16]}... -> {hash_type} ({length} chars)")
            self.msleep(200)
            
            if ":" in hash_val:
                self.output_signal.emit(f"[FORMAT] Appears to be hash:salt format")

    def validate_hashes(self):
        self.output_signal.emit("[VALIDATE] Checking hash formats...")
        self.msleep(600)
        
        valid_count = 0
        invalid_count = 0
        
        for i, hash_val in enumerate(self.hashes, 1):
            hash_val = hash_val.strip()
            if not hash_val:
                continue
                
            if all(c in '0123456789abcdefABCDEF:' for c in hash_val):
                self.output_signal.emit(f"[VALID] Hash {i}: Valid hexadecimal format")
                valid_count += 1
            else:
                self.output_signal.emit(f"[INVALID] Hash {i}: Contains invalid characters")
                invalid_count += 1
            
            self.msleep(150)
        
        self.output_signal.emit(f"[SUMMARY] Valid: {valid_count}, Invalid: {invalid_count}")

    def analyze_statistics(self):
        self.output_signal.emit("[STATS] Generating hash statistics...")
        self.msleep(800)
        
        lengths = {}
        formats = {"hash_only": 0, "hash_salt": 0, "hash_user": 0}
        
        for hash_val in self.hashes:
            hash_val = hash_val.strip()
            if not hash_val:
                continue
                
            length = len(hash_val)
            lengths[length] = lengths.get(length, 0) + 1
            
            if ":" in hash_val:
                parts = hash_val.split(":")
                if len(parts) == 2:
                    formats["hash_salt"] += 1
                elif len(parts) == 3:
                    formats["hash_user"] += 1
            else:
                formats["hash_only"] += 1
        
        self.output_signal.emit(f"[STATS] Total hashes: {len([h for h in self.hashes if h.strip()])}")
        
        for length, count in lengths.items():
            self.output_signal.emit(f"[STATS] Length {length}: {count} hashes")
        
        for format_type, count in formats.items():
            self.output_signal.emit(f"[STATS] {format_type}: {count} hashes")

class HashAnalysisComponent(QWidget):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        header = QLabel("Hash Analysis")
        header.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        layout.addWidget(header)
        
        # Hash input
        self.hash_input = QTextEdit()
        self.hash_input.setMaximumHeight(80)
        self.hash_input.setPlaceholderText("Paste hashes here (one per line)...")
        layout.addWidget(self.hash_input)
        
        # File operations
        file_layout = QHBoxLayout()
        self.load_btn = QPushButton("Load File")
        self.load_btn.clicked.connect(self.load_hash_file)
        self.save_btn = QPushButton("Save")
        self.save_btn.clicked.connect(self.save_hash_file)
        file_layout.addWidget(self.load_btn)
        file_layout.addWidget(self.save_btn)
        layout.addLayout(file_layout)
        
        # Analysis type
        analysis_layout = QHBoxLayout()
        analysis_layout.addWidget(QLabel("Analysis:"))
        self.analysis_type = QComboBox()
        self.analysis_type.addItems(["Identify", "Validate", "Statistics"])
        analysis_layout.addWidget(self.analysis_type)
        layout.addLayout(analysis_layout)
        
        # Analyze button
        self.analyze_btn = QPushButton("Analyze Hashes")
        self.analyze_btn.clicked.connect(self.start_analysis)
        layout.addWidget(self.analyze_btn)
        
        # Results
        self.results = QTextEdit()
        self.results.setMaximumHeight(150)
        self.results.setPlaceholderText("Hash analysis results will appear here...")
        layout.addWidget(self.results)

    def load_hash_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Load Hash File", "", "Text Files (*.txt)")
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                self.hash_input.setPlainText(content)
                self.results.append(f"[+] Loaded {len(content.splitlines())} hashes")
            except Exception as e:
                self.results.append(f"[-] Error loading file: {e}")

    def save_hash_file(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Hash File", "hashes.txt", "Text Files (*.txt)")
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(self.hash_input.toPlainText())
                self.results.append(f"[+] Saved hashes to {file_path}")
            except Exception as e:
                self.results.append(f"[-] Error saving file: {e}")

    def start_analysis(self):
        hashes = [h.strip() for h in self.hash_input.toPlainText().split('\n') if h.strip()]
        if not hashes:
            self.results.append("[ERROR] No hashes to analyze")
            return
        
        self.analyze_btn.setEnabled(False)
        self.results.clear()
        
        analysis_type = self.analysis_type.currentText()
        
        self.worker = HashAnalysisWorker(hashes, analysis_type)
        self.worker.output_signal.connect(self.results.append)
        self.worker.finished_signal.connect(self.on_analysis_finished)
        self.worker.start()

    def on_analysis_finished(self):
        self.analyze_btn.setEnabled(True)
        if self.worker:
            self.worker.quit()
            self.worker.wait()
            self.worker = None