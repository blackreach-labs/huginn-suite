# app/components/cracking/attack_configuration_component.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QLineEdit, QPushButton, QComboBox, QSpinBox, QCheckBox, QFileDialog)
from PyQt6.QtCore import pyqtSignal, QThread
from PyQt6.QtGui import QFont

class AttackConfigurationWorker(QThread):
    output_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()

    def __init__(self, tool, mode, config):
        super().__init__()
        self.tool = tool
        self.mode = mode
        self.config = config

    def run(self):
        try:
            self.output_signal.emit(f"[INFO] Configuring {self.tool} {self.mode} attack")
            
            if self.tool == "Hashcat":
                self.configure_hashcat()
            elif self.tool == "John":
                self.configure_john()
            elif self.tool == "Hydra":
                self.configure_hydra()
            elif self.tool == "Custom":
                self.configure_custom()
            
            self.output_signal.emit(f"[COMPLETE] Attack configuration ready")
            
        except Exception as e:
            self.output_signal.emit(f"[ERROR] {str(e)}")
        finally:
            self.finished_signal.emit()

    def configure_hashcat(self):
        self.output_signal.emit("[HASHCAT] Configuring Hashcat attack...")
        self.msleep(800)
        
        if self.mode == "Dictionary":
            self.output_signal.emit(f"[CONFIG] Dictionary attack with wordlist: {self.config.get('wordlist', 'rockyou.txt')}")
            self.output_signal.emit(f"[CONFIG] Threads: {self.config.get('threads', 4)}")
            if self.config.get('gpu'):
                self.output_signal.emit("[CONFIG] GPU acceleration enabled")
            if self.config.get('rules'):
                self.output_signal.emit(f"[CONFIG] Rules file: {self.config.get('rules')}")
        
        elif self.mode == "Brute Force":
            self.output_signal.emit("[CONFIG] Brute force attack configured")
            self.output_signal.emit("[CONFIG] Character set: ?a (all printable)")
            self.output_signal.emit("[CONFIG] Max length: 8 characters")
        
        elif self.mode == "Hybrid":
            self.output_signal.emit("[CONFIG] Hybrid attack: wordlist + mask")
            self.output_signal.emit("[CONFIG] Mask: ?d?d?d?d (4 digits)")
        
        self.output_signal.emit("[READY] Hashcat configuration complete")

    def configure_john(self):
        self.output_signal.emit("[JOHN] Configuring John the Ripper...")
        self.msleep(800)
        
        if self.mode == "Dictionary":
            self.output_signal.emit(f"[CONFIG] Wordlist mode with {self.config.get('wordlist', 'password.lst')}")
        elif self.mode == "Incremental":
            self.output_signal.emit("[CONFIG] Incremental mode (brute force)")
            self.output_signal.emit("[CONFIG] Character set: ASCII")
        elif self.mode == "Rule-based":
            self.output_signal.emit("[CONFIG] Rule-based attack")
            self.output_signal.emit("[CONFIG] Using default rules")
        
        self.output_signal.emit("[READY] John configuration complete")

    def configure_hydra(self):
        self.output_signal.emit("[HYDRA] Configuring Hydra attack...")
        self.msleep(800)
        
        self.output_signal.emit("[CONFIG] Network service attack")
        self.output_signal.emit(f"[CONFIG] Threads: {self.config.get('threads', 16)}")
        self.output_signal.emit("[CONFIG] Protocol: SSH/FTP/HTTP")
        
        self.output_signal.emit("[READY] Hydra configuration complete")

    def configure_custom(self):
        self.output_signal.emit("[CUSTOM] Configuring custom attack...")
        self.msleep(600)
        
        self.output_signal.emit("[CONFIG] Custom script execution")
        self.output_signal.emit("[CONFIG] User-defined parameters")
        
        self.output_signal.emit("[READY] Custom configuration complete")

class AttackConfigurationComponent(QWidget):
    attack_configured = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self.worker = None
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        header = QLabel("Attack Configuration")
        header.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        layout.addWidget(header)
        
        # Tool selection
        tool_layout = QHBoxLayout()
        tool_layout.addWidget(QLabel("Tool:"))
        self.tool_combo = QComboBox()
        self.tool_combo.addItems(["Hashcat", "John", "Hydra", "Custom"])
        self.tool_combo.currentTextChanged.connect(self.on_tool_changed)
        tool_layout.addWidget(self.tool_combo)
        layout.addLayout(tool_layout)
        
        # Attack mode
        mode_layout = QHBoxLayout()
        mode_layout.addWidget(QLabel("Mode:"))
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Dictionary", "Brute Force", "Hybrid", "Rule-based"])
        mode_layout.addWidget(self.mode_combo)
        layout.addLayout(mode_layout)
        
        # Wordlist
        wordlist_layout = QHBoxLayout()
        wordlist_layout.addWidget(QLabel("Wordlist:"))
        self.wordlist_input = QLineEdit()
        self.wordlist_input.setPlaceholderText("rockyou.txt")
        self.browse_btn = QPushButton("Browse")
        self.browse_btn.clicked.connect(self.browse_wordlist)
        wordlist_layout.addWidget(self.wordlist_input)
        wordlist_layout.addWidget(self.browse_btn)
        layout.addLayout(wordlist_layout)
        
        # Advanced options
        advanced_layout = QHBoxLayout()
        advanced_layout.addWidget(QLabel("Threads:"))
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 64)
        self.threads_spin.setValue(4)
        advanced_layout.addWidget(self.threads_spin)
        
        self.gpu_check = QCheckBox("GPU")
        self.optimized_check = QCheckBox("Optimized")
        advanced_layout.addWidget(self.gpu_check)
        advanced_layout.addWidget(self.optimized_check)
        layout.addLayout(advanced_layout)
        
        # Configure button
        self.configure_btn = QPushButton("Configure Attack")
        self.configure_btn.clicked.connect(self.configure_attack)
        layout.addWidget(self.configure_btn)
        
        # Configuration output
        self.config_output = QTextEdit()
        self.config_output.setMaximumHeight(150)
        self.config_output.setPlaceholderText("Attack configuration details will appear here...")
        layout.addWidget(self.config_output)

    def on_tool_changed(self, tool):
        if tool == "Hashcat":
            self.mode_combo.clear()
            self.mode_combo.addItems(["Dictionary", "Brute Force", "Hybrid", "Rule-based"])
        elif tool == "John":
            self.mode_combo.clear()
            self.mode_combo.addItems(["Dictionary", "Incremental", "Rule-based"])
        elif tool == "Hydra":
            self.mode_combo.clear()
            self.mode_combo.addItems(["Dictionary", "Password Spray"])
        elif tool == "Custom":
            self.mode_combo.clear()
            self.mode_combo.addItems(["Custom Script", "Manual"])

    def browse_wordlist(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Wordlist", "", "Text Files (*.txt)")
        if file_path:
            self.wordlist_input.setText(file_path)

    def configure_attack(self):
        self.configure_btn.setEnabled(False)
        self.config_output.clear()
        
        tool = self.tool_combo.currentText()
        mode = self.mode_combo.currentText()
        
        config = {
            'wordlist': self.wordlist_input.text() or 'rockyou.txt',
            'threads': self.threads_spin.value(),
            'gpu': self.gpu_check.isChecked(),
            'optimized': self.optimized_check.isChecked()
        }
        
        self.worker = AttackConfigurationWorker(tool, mode, config)
        self.worker.output_signal.connect(self.config_output.append)
        self.worker.finished_signal.connect(self.on_config_finished)
        self.worker.start()
        
        # Emit configuration for other components
        self.attack_configured.emit({
            'tool': tool,
            'mode': mode,
            'config': config
        })

    def on_config_finished(self):
        self.configure_btn.setEnabled(True)
        if self.worker:
            self.worker.quit()
            self.worker.wait()
            self.worker = None