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

        # Prefix-based hash identification
        prefix_types = {
            "$sshng$": ("SSH Private Key (sshng)", "Dictionary attack with targeted wordlist"),
            "$2b$": ("bcrypt", "Dictionary attack (slow — bcrypt KDF)"),
            "$2a$": ("bcrypt", "Dictionary attack (slow — bcrypt KDF)"),
            "$2y$": ("bcrypt", "Dictionary attack (slow — bcrypt KDF)"),
            "$6$": ("SHA-512 Crypt", "Dictionary or Brute Force"),
            "$5$": ("SHA-256 Crypt", "Dictionary or Brute Force"),
            "$1$": ("MD5 Crypt", "Dictionary or Brute Force"),
            "$apr1$": ("Apache MD5", "Dictionary or Brute Force"),
            "$krb5tgs$": ("Kerberos TGS-REP", "Dictionary attack"),
            "$krb5asrep$": ("Kerberos AS-REP", "Dictionary attack"),
            "$office$": ("MS Office", "Dictionary attack"),
            "$zip2$": ("ZIP (PKZIP)", "Dictionary or Brute Force"),
            "$rar5$": ("RAR5", "Dictionary attack"),
            "$keepass$": ("KeePass", "Dictionary attack"),
            "$bitcoin$": ("Bitcoin Wallet", "Dictionary attack"),
            "$ethereum$": ("Ethereum Wallet", "Dictionary attack"),
            "$DCC2$": ("Domain Cached Credentials 2", "Dictionary attack"),
            "$NETNTLMv2$": ("NetNTLMv2", "Dictionary or Brute Force"),
        }
        
        for i, hash_val in enumerate(self.hashes, 1):
            hash_val = hash_val.strip()
            if not hash_val:
                continue

            # Check prefix-based types first
            identified = False
            for prefix, (type_name, hint) in prefix_types.items():
                if hash_val.startswith(prefix):
                    self.output_signal.emit(f"[HASH {i}] {type_name}")
                    self.output_signal.emit(f"  Recommended: {hint}")
                    if prefix == "$sshng$":
                        self._parse_sshng_details(hash_val)
                    identified = True
                    break

            if not identified:
                length = len(hash_val)
                hash_type = hash_types.get(length, "Unknown")
                self.output_signal.emit(f"[HASH {i}] {hash_val[:16]}... -> {hash_type} ({length} chars)")
                if ":" in hash_val:
                    self.output_signal.emit(f"  Format: hash:salt or hash:user")
            
            self.msleep(200)

    def _parse_sshng_details(self, hash_val):
        """Parse $sshng$ hash and display details."""
        try:
            parts = hash_val.split("$")
            # $sshng$<type>$<salt_len>$<salt>$<data_len>$<data>$<rounds>$<offset>
            if len(parts) >= 6:
                sshng_type = parts[2]
                salt_len = parts[3]
                salt = parts[4]
                data_len = parts[5]

                type_names = {
                    "0": "3DES-CBC",
                    "1": "AES-128-CBC (RSA/DSA)",
                    "2": "AES-256-CBC + bcrypt",
                    "3": "AES-128-CBC (EC)",
                    "4": "AES-192-CBC",
                    "5": "AES-256-CBC",
                    "6": "AES-256-CTR + bcrypt",
                }
                cipher = type_names.get(sshng_type, f"type {sshng_type}")
                self.output_signal.emit(f"  Cipher: {cipher}")
                self.output_signal.emit(f"  Salt: {salt} ({salt_len} bytes)")
                self.output_signal.emit(f"  Data: {data_len} bytes")

                if len(parts) >= 8:
                    rounds = parts[7] if len(parts) > 7 else "?"
                    self.output_signal.emit(f"  Rounds: {parts[7]}")
                    offset = parts[8] if len(parts) > 8 else "?"
                    self.output_signal.emit(f"  Ciphertext offset: {offset}")
        except Exception:
            pass

    def validate_hashes(self):
        self.output_signal.emit("[VALIDATE] Checking hash formats...")
        self.msleep(600)
        
        valid_count = 0
        invalid_count = 0
        
        for i, hash_val in enumerate(self.hashes, 1):
            hash_val = hash_val.strip()
            if not hash_val:
                continue

            # Structured hash formats (start with $)
            if hash_val.startswith("$"):
                self.output_signal.emit(f"[VALID] Hash {i}: Structured hash format")
                valid_count += 1
            elif all(c in '0123456789abcdefABCDEF:' for c in hash_val):
                self.output_signal.emit(f"[VALID] Hash {i}: Valid hexadecimal format")
                valid_count += 1
            else:
                self.output_signal.emit(f"[INVALID] Hash {i}: Unrecognized format")
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