# app/components/ssh_bruteforce_component.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
                            QPushButton, QTextEdit, QComboBox, QSpinBox, QProgressBar,
                            QFrame, QFileDialog, QCheckBox)
from PyQt6.QtCore import QThreadPool, pyqtSignal, Qt
from PyQt6.QtGui import QFont
from ..tools.ssh_bruteforce_worker import create_ssh_bruteforce_worker, create_ssh_key_bruteforce_worker

class SSHBruteforceComponent(QWidget):
    """SSH bruteforce attack component for exploitation phase"""
    
    credentials_found = pyqtSignal(dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_worker = None
        self.setup_ui()
        self.apply_theme()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Header
        header = QLabel("🔓 SSH Bruteforce Attack")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet("font-size: 16pt; font-weight: bold; color: #FF6B6B; padding: 10px;")
        layout.addWidget(header)
        
        # Target configuration
        target_frame = QFrame()
        target_layout = QVBoxLayout(target_frame)
        
        target_layout.addWidget(QLabel("Target Configuration:"))
        
        # Target input
        target_input_layout = QHBoxLayout()
        target_input_layout.addWidget(QLabel("Target:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("192.168.1.10")
        target_input_layout.addWidget(self.target_input)
        
        target_input_layout.addWidget(QLabel("Port:"))
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(22)
        target_input_layout.addWidget(self.port_input)
        
        target_layout.addLayout(target_input_layout)
        
        # Attack type
        attack_layout = QHBoxLayout()
        attack_layout.addWidget(QLabel("Attack Type:"))
        self.attack_type = QComboBox()
        self.attack_type.addItems(["Password Bruteforce", "SSH Key Bruteforce"])
        self.attack_type.currentTextChanged.connect(self.on_attack_type_changed)
        attack_layout.addWidget(self.attack_type)
        attack_layout.addStretch()
        target_layout.addLayout(attack_layout)
        
        layout.addWidget(target_frame)
        
        # Password bruteforce options
        self.password_frame = QFrame()
        password_layout = QVBoxLayout(self.password_frame)
        
        password_layout.addWidget(QLabel("Password Bruteforce Options:"))
        
        # Usernames
        user_layout = QHBoxLayout()
        user_layout.addWidget(QLabel("Usernames:"))
        self.usernames_input = QLineEdit()
        self.usernames_input.setPlaceholderText("root,admin,user,test (comma-separated)")
        self.usernames_input.setText("root,admin,user,test")
        user_layout.addWidget(self.usernames_input)
        password_layout.addLayout(user_layout)
        
        # Passwords
        pass_layout = QHBoxLayout()
        pass_layout.addWidget(QLabel("Passwords:"))
        self.passwords_input = QLineEdit()
        self.passwords_input.setPlaceholderText("password,admin,123456 (comma-separated)")
        self.passwords_input.setText("password,admin,123456,root,toor")
        pass_layout.addWidget(self.passwords_input)
        password_layout.addLayout(pass_layout)
        
        layout.addWidget(self.password_frame)
        
        # SSH key bruteforce options
        self.key_frame = QFrame()
        key_layout = QVBoxLayout(self.key_frame)
        
        key_layout.addWidget(QLabel("SSH Key Bruteforce Options:"))
        
        # Key usernames
        key_user_layout = QHBoxLayout()
        key_user_layout.addWidget(QLabel("Usernames:"))
        self.key_usernames_input = QLineEdit()
        self.key_usernames_input.setPlaceholderText("root,admin,user")
        self.key_usernames_input.setText("root,admin,user")
        key_user_layout.addWidget(self.key_usernames_input)
        key_layout.addLayout(key_user_layout)
        
        # Key paths
        key_path_layout = QHBoxLayout()
        key_path_layout.addWidget(QLabel("Key Files:"))
        self.key_paths_input = QLineEdit()
        self.key_paths_input.setPlaceholderText("Path to SSH private keys (comma-separated)")
        key_path_layout.addWidget(self.key_paths_input)
        
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_key_files)
        key_path_layout.addWidget(browse_btn)
        key_layout.addLayout(key_path_layout)
        
        self.key_frame.setVisible(False)
        layout.addWidget(self.key_frame)
        
        # Attack options
        options_frame = QFrame()
        options_layout = QVBoxLayout(options_frame)
        
        options_layout.addWidget(QLabel("Attack Options:"))
        
        thread_layout = QHBoxLayout()
        thread_layout.addWidget(QLabel("Max Threads:"))
        self.max_threads = QSpinBox()
        self.max_threads.setRange(1, 20)
        self.max_threads.setValue(5)
        thread_layout.addWidget(self.max_threads)
        
        thread_layout.addWidget(QLabel("Delay (sec):"))
        self.delay_input = QLineEdit()
        self.delay_input.setText("0.1")
        self.delay_input.setMaximumWidth(60)
        thread_layout.addWidget(self.delay_input)
        thread_layout.addStretch()
        options_layout.addLayout(thread_layout)
        
        layout.addWidget(options_frame)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("🚀 Start Attack")
        self.start_btn.clicked.connect(self.start_attack)
        self.start_btn.setMinimumHeight(40)
        button_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("⏹ Stop Attack")
        self.stop_btn.clicked.connect(self.stop_attack)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setMinimumHeight(40)
        button_layout.addWidget(self.stop_btn)
        
        layout.addLayout(button_layout)
        
        # Output terminal
        terminal_label = QLabel("Attack Output:")
        terminal_label.setStyleSheet("font-weight: bold; color: #87CEEB; margin-top: 10px;")
        layout.addWidget(terminal_label)
        
        self.terminal = QTextEdit()
        self.terminal.setReadOnly(True)
        self.terminal.setFont(QFont("Neuropol X", 9))
        self.terminal.setMinimumHeight(200)
        layout.addWidget(self.terminal)
    
    def apply_theme(self):
        self.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 100);
                border-radius: 8px;
                border: 1px solid rgba(100, 200, 255, 50);
                padding: 10px;
                margin: 5px;
            }
            QPushButton {
                background-color: rgba(30, 40, 50, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 6px;
                color: #DCDCDC;
                font-weight: bold;
                padding: 8px;
            }
            QPushButton:hover {
                background-color: rgba(50, 70, 90, 200);
                border: 2px solid #64C8FF;
            }
            QPushButton:disabled {
                background-color: rgba(20, 20, 20, 100);
                border: 2px solid rgba(100, 100, 100, 50);
                color: #666666;
            }
            QLineEdit, QSpinBox {
                background-color: rgba(20, 30, 40, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 4px;
                color: #DCDCDC;
                padding: 5px;
            }
            QComboBox {
                background-color: rgba(20, 30, 40, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 4px;
                color: #DCDCDC;
                padding: 5px;
            }
            QTextEdit {
                background-color: rgba(0, 0, 0, 200);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 6px;
                color: #00FF41;
                padding: 10px;
            }
            QProgressBar {
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 4px;
                background-color: rgba(20, 30, 40, 150);
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #FF6B6B;
                border-radius: 2px;
            }
            QLabel {
                color: #DCDCDC;
                font-weight: bold;
            }
        """)
    
    def on_attack_type_changed(self, attack_type):
        """Handle attack type change"""
        if attack_type == "Password Bruteforce":
            self.password_frame.setVisible(True)
            self.key_frame.setVisible(False)
        else:
            self.password_frame.setVisible(False)
            self.key_frame.setVisible(True)
    
    def browse_key_files(self):
        """Browse for SSH key files"""
        files, _ = QFileDialog.getOpenFileNames(
            self, "Select SSH Private Key Files", "", 
            "SSH Keys (id_rsa id_dsa id_ecdsa id_ed25519);;All Files (*)"
        )
        if files:
            self.key_paths_input.setText(",".join(files))
    
    def start_attack(self):
        """Start SSH bruteforce attack"""
        target = self.target_input.text().strip()
        if not target:
            self.terminal.append("<p style='color: #FF6B6B;'>[ERROR] Please enter a target</p>")
            return
        
        port = self.port_input.value()
        attack_type = self.attack_type.currentText()
        
        self.terminal.clear()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        try:
            if attack_type == "Password Bruteforce":
                usernames = [u.strip() for u in self.usernames_input.text().split(',') if u.strip()]
                passwords = [p.strip() for p in self.passwords_input.text().split(',') if p.strip()]
                delay = float(self.delay_input.text())
                
                self.current_worker = create_ssh_bruteforce_worker(
                    target=target,
                    port=port,
                    usernames=usernames,
                    passwords=passwords,
                    max_threads=self.max_threads.value(),
                    delay=delay
                )
            else:  # SSH Key Bruteforce
                usernames = [u.strip() for u in self.key_usernames_input.text().split(',') if u.strip()]
                key_paths = [k.strip() for k in self.key_paths_input.text().split(',') if k.strip()]
                
                self.current_worker = create_ssh_key_bruteforce_worker(
                    target=target,
                    port=port,
                    usernames=usernames,
                    key_paths=key_paths,
                    max_threads=self.max_threads.value()
                )
            
            # Connect signals
            self.current_worker.signals.output.connect(self.append_output)
            self.current_worker.signals.finished.connect(self.on_attack_finished)
            self.current_worker.signals.credentials_found.connect(self.on_credentials_found)
            self.current_worker.signals.progress_updated.connect(self.update_progress)
            
            # Start worker
            QThreadPool.globalInstance().start(self.current_worker)
            
        except Exception as e:
            self.terminal.append(f"<p style='color: #FF6B6B;'>[ERROR] Failed to start attack: {e}</p>")
            self.on_attack_finished()
    
    def stop_attack(self):
        """Stop current attack"""
        if self.current_worker:
            self.current_worker.stop()
            self.terminal.append("<p style='color: #FFAA00;'>[INFO] Attack stopped by user</p>")
    
    def on_attack_finished(self):
        """Handle attack completion"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.current_worker = None
    
    def on_credentials_found(self, credential):
        """Handle found credentials"""
        self.credentials_found.emit(credential)
    
    def update_progress(self, current, total):
        """Update progress bar"""
        if total > 0:
            progress = int((current / total) * 100)
            self.progress_bar.setValue(progress)
    
    def append_output(self, text):
        """Append text to terminal"""
        self.terminal.insertHtml(text)
        scrollbar = self.terminal.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())