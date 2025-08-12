# app/ui/advanced_credential_extraction_widget.py
"""
Advanced Credential Extraction Widget
Integrates DCSync, NTLM Relay, and LSASS dumping capabilities
"""
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QLineEdit, QPushButton, QTextEdit, QComboBox,
                            QCheckBox, QGroupBox, QTabWidget, QProgressBar)
from PyQt6.QtCore import QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont
from ..core.secrets_extractor import SecretsExtractor
from ..core.base_worker import BaseWorker

class AdvancedCredentialExtractionWidget(QWidget):
    """Advanced credential extraction interface"""
    
    def __init__(self):
        super().__init__()
        self.extractor = SecretsExtractor()
        self.current_worker = None
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface"""
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("🔐 Advanced Credential Extraction")
        title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        layout.addWidget(title)
        
        # Create tabs for different extraction methods
        tabs = QTabWidget()
        
        # DCSync Tab
        dcsync_tab = self.create_dcsync_tab()
        tabs.addTab(dcsync_tab, "🎯 DCSync (MS-DRSR)")
        
        # NTLM Relay Tab
        relay_tab = self.create_relay_tab()
        tabs.addTab(relay_tab, "🔄 NTLM Relay")
        
        # LSASS Dump Tab
        lsass_tab = self.create_lsass_tab()
        tabs.addTab(lsass_tab, "💾 LSASS Memory Dump")
        
        # Legacy Methods Tab
        legacy_tab = self.create_legacy_tab()
        tabs.addTab(legacy_tab, "📁 Legacy Registry")
        
        layout.addWidget(tabs)
        
        # Output area
        self.output_text = QTextEdit()
        self.output_text.setMaximumHeight(200)
        self.output_text.setStyleSheet("background-color: #1e1e1e; color: #ffffff; font-family: 'Courier New';")
        layout.addWidget(QLabel("Output:"))
        layout.addWidget(self.output_text)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        self.setLayout(layout)
    
    def create_dcsync_tab(self):
        """Create DCSync extraction tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Target configuration
        target_group = QGroupBox("Target Configuration")
        target_layout = QVBoxLayout()
        
        self.dcsync_target = QLineEdit()
        self.dcsync_target.setPlaceholderText("dc01.lab.local or 192.168.1.106")
        target_layout.addWidget(QLabel("Domain Controller:"))
        target_layout.addWidget(self.dcsync_target)
        
        # Credentials
        cred_layout = QHBoxLayout()
        
        self.dcsync_username = QLineEdit()
        self.dcsync_username.setPlaceholderText("Administrator")
        cred_layout.addWidget(QLabel("Username:"))
        cred_layout.addWidget(self.dcsync_username)
        
        self.dcsync_password = QLineEdit()
        self.dcsync_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.dcsync_password.setPlaceholderText("Password")
        cred_layout.addWidget(QLabel("Password:"))
        cred_layout.addWidget(self.dcsync_password)
        
        self.dcsync_domain = QLineEdit()
        self.dcsync_domain.setPlaceholderText("LAB")
        cred_layout.addWidget(QLabel("Domain:"))
        cred_layout.addWidget(self.dcsync_domain)
        
        target_layout.addLayout(cred_layout)
        target_group.setLayout(target_layout)
        layout.addWidget(target_group)
        
        # Extraction options
        options_group = QGroupBox("Extraction Options")
        options_layout = QVBoxLayout()
        
        self.dcsync_all_users = QCheckBox("Extract all domain users")
        self.dcsync_all_users.setChecked(True)
        options_layout.addWidget(self.dcsync_all_users)
        
        self.dcsync_specific_user = QLineEdit()
        self.dcsync_specific_user.setPlaceholderText("Specific username (optional)")
        options_layout.addWidget(QLabel("Or extract specific user:"))
        options_layout.addWidget(self.dcsync_specific_user)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Start button
        self.dcsync_button = QPushButton("🎯 Start DCSync Extraction")
        self.dcsync_button.clicked.connect(self.start_dcsync)
        layout.addWidget(self.dcsync_button)
        
        widget.setLayout(layout)
        return widget
    
    def create_relay_tab(self):
        """Create NTLM Relay tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Warning
        warning = QLabel("⚠️ NTLM Relay requires network positioning and may disrupt network operations")
        warning.setStyleSheet("color: orange; font-weight: bold;")
        layout.addWidget(warning)
        
        # Target configuration
        target_group = QGroupBox("Relay Configuration")
        target_layout = QVBoxLayout()
        
        self.relay_target = QLineEdit()
        self.relay_target.setPlaceholderText("Target to capture authentication from")
        target_layout.addWidget(QLabel("Primary Target:"))
        target_layout.addWidget(self.relay_target)
        
        self.relay_destination = QLineEdit()
        self.relay_destination.setPlaceholderText("Destination to relay to (optional)")
        target_layout.addWidget(QLabel("Relay Destination:"))
        target_layout.addWidget(self.relay_destination)
        
        target_group.setLayout(target_layout)
        layout.addWidget(target_group)
        
        # Attack options
        options_group = QGroupBox("Attack Options")
        options_layout = QVBoxLayout()
        
        self.relay_llmnr = QCheckBox("Enable LLMNR poisoning")
        self.relay_llmnr.setChecked(True)
        options_layout.addWidget(self.relay_llmnr)
        
        self.relay_smb_ldap = QCheckBox("SMB to LDAP relay")
        self.relay_smb_ldap.setChecked(True)
        options_layout.addWidget(self.relay_smb_ldap)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        self.relay_start_button = QPushButton("🔄 Start NTLM Relay")
        self.relay_start_button.clicked.connect(self.start_relay)
        button_layout.addWidget(self.relay_start_button)
        
        self.relay_stop_button = QPushButton("⏹️ Stop Relay")
        self.relay_stop_button.clicked.connect(self.stop_relay)
        self.relay_stop_button.setEnabled(False)
        button_layout.addWidget(self.relay_stop_button)
        
        layout.addLayout(button_layout)
        
        widget.setLayout(layout)
        return widget
    
    def create_lsass_tab(self):
        """Create LSASS dump tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Warning
        warning = QLabel("⚠️ LSASS dumping requires SYSTEM privileges and may trigger AV/EDR")
        warning.setStyleSheet("color: red; font-weight: bold;")
        layout.addWidget(warning)
        
        # Method selection
        method_group = QGroupBox("Dump Method")
        method_layout = QVBoxLayout()
        
        self.lsass_method = QComboBox()
        self.lsass_method.addItems([
            "Auto (Try all methods)",
            "ProcDump",
            "comsvcs.dll",
            "WER Dump",
            "Silent Process Exit",
            "nanodump"
        ])
        method_layout.addWidget(QLabel("Extraction Method:"))
        method_layout.addWidget(self.lsass_method)
        
        method_group.setLayout(method_layout)
        layout.addWidget(method_group)
        
        # Privilege check
        self.privilege_check_button = QPushButton("🔍 Check Privileges")
        self.privilege_check_button.clicked.connect(self.check_privileges)
        layout.addWidget(self.privilege_check_button)
        
        # Start button
        self.lsass_button = QPushButton("💾 Dump LSASS Memory")
        self.lsass_button.clicked.connect(self.start_lsass_dump)
        layout.addWidget(self.lsass_button)
        
        widget.setLayout(layout)
        return widget
    
    def create_legacy_tab(self):
        """Create legacy registry methods tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Target configuration
        target_group = QGroupBox("Target Configuration")
        target_layout = QVBoxLayout()
        
        self.legacy_target = QLineEdit()
        self.legacy_target.setPlaceholderText("Target IP or hostname")
        target_layout.addWidget(QLabel("Target:"))
        target_layout.addWidget(self.legacy_target)
        
        # Credentials
        cred_layout = QHBoxLayout()
        
        self.legacy_username = QLineEdit()
        self.legacy_username.setPlaceholderText("Username")
        cred_layout.addWidget(QLabel("Username:"))
        cred_layout.addWidget(self.legacy_username)
        
        self.legacy_password = QLineEdit()
        self.legacy_password.setEchoMode(QLineEdit.EchoMode.Password)
        cred_layout.addWidget(QLabel("Password:"))
        cred_layout.addWidget(self.legacy_password)
        
        target_layout.addLayout(cred_layout)
        target_group.setLayout(target_layout)
        layout.addWidget(target_group)
        
        # Extraction options
        options_group = QGroupBox("Extraction Options")
        options_layout = QVBoxLayout()
        
        self.legacy_sam = QCheckBox("Extract SAM database")
        self.legacy_sam.setChecked(True)
        options_layout.addWidget(self.legacy_sam)
        
        self.legacy_lsa = QCheckBox("Extract LSA secrets")
        self.legacy_lsa.setChecked(True)
        options_layout.addWidget(self.legacy_lsa)
        
        self.legacy_cached = QCheckBox("Extract cached credentials")
        options_layout.addWidget(self.legacy_cached)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Start button
        self.legacy_button = QPushButton("📁 Start Legacy Extraction")
        self.legacy_button.clicked.connect(self.start_legacy_extraction)
        layout.addWidget(self.legacy_button)
        
        widget.setLayout(layout)
        return widget
    
    def start_dcsync(self):
        """Start DCSync extraction"""
        if not self.dcsync_target.text() or not self.dcsync_username.text() or not self.dcsync_password.text():
            self.output_text.append("<span style='color: red;'>[ERROR] Please fill in all required fields</span>")
            return
        
        self.output_text.clear()
        self.output_text.append("<span style='color: cyan;'>[INFO] Starting DCSync extraction...</span>")
        
        # Create worker thread
        self.current_worker = DCSyncWorker(
            self.dcsync_target.text(),
            self.dcsync_username.text(),
            self.dcsync_password.text(),
            self.dcsync_domain.text(),
            self.dcsync_specific_user.text()
        )
        
        self.current_worker.output.connect(self.output_text.append)
        self.current_worker.finished.connect(self.extraction_finished)
        self.current_worker.start()
        
        self.dcsync_button.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate
    
    def start_relay(self):
        """Start NTLM relay attack"""
        if not self.relay_target.text():
            self.output_text.append("<span style='color: red;'>[ERROR] Please specify a target</span>")
            return
        
        self.output_text.clear()
        self.output_text.append("<span style='color: cyan;'>[INFO] Starting NTLM relay attack...</span>")
        
        # Create worker thread
        self.current_worker = RelayWorker(
            self.relay_target.text(),
            self.relay_destination.text()
        )
        
        self.current_worker.output.connect(self.output_text.append)
        self.current_worker.finished.connect(self.relay_finished)
        self.current_worker.start()
        
        self.relay_start_button.setEnabled(False)
        self.relay_stop_button.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
    
    def stop_relay(self):
        """Stop NTLM relay attack"""
        if self.current_worker:
            self.current_worker.stop()
        
        self.relay_start_button.setEnabled(True)
        self.relay_stop_button.setEnabled(False)
        self.progress_bar.setVisible(False)
    
    def start_lsass_dump(self):
        """Start LSASS memory dump"""
        self.output_text.clear()
        self.output_text.append("<span style='color: cyan;'>[INFO] Starting LSASS memory dump...</span>")
        
        method = self.lsass_method.currentText().split(' ')[0].lower()
        if method == "auto":
            method = "auto"
        
        # Create worker thread
        self.current_worker = LSASSWorker(method)
        
        self.current_worker.output.connect(self.output_text.append)
        self.current_worker.finished.connect(self.extraction_finished)
        self.current_worker.start()
        
        self.lsass_button.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
    
    def start_legacy_extraction(self):
        """Start legacy registry extraction"""
        if not self.legacy_target.text():
            self.output_text.append("<span style='color: red;'>[ERROR] Please specify a target</span>")
            return
        
        self.output_text.clear()
        self.output_text.append("<span style='color: cyan;'>[INFO] Starting legacy extraction...</span>")
        
        # Create worker thread
        self.current_worker = LegacyWorker(
            self.legacy_target.text(),
            self.legacy_username.text(),
            self.legacy_password.text(),
            self.legacy_sam.isChecked(),
            self.legacy_lsa.isChecked(),
            self.legacy_cached.isChecked()
        )
        
        self.current_worker.output.connect(self.output_text.append)
        self.current_worker.finished.connect(self.extraction_finished)
        self.current_worker.start()
        
        self.legacy_button.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
    
    def check_privileges(self):
        """Check LSASS dump privileges"""
        from ..core.lsass_dumper import LSASSDumper
        
        dumper = LSASSDumper()
        result = dumper.check_privileges()
        
        if result['sufficient']:
            self.output_text.append("<span style='color: green;'>[SUCCESS] Sufficient privileges for LSASS dump</span>")
        else:
            self.output_text.append(f"<span style='color: red;'>[ERROR] {result.get('error', 'Insufficient privileges')}</span>")
    
    def extraction_finished(self):
        """Handle extraction completion"""
        self.dcsync_button.setEnabled(True)
        self.lsass_button.setEnabled(True)
        self.legacy_button.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.current_worker = None
    
    def relay_finished(self):
        """Handle relay completion"""
        self.relay_start_button.setEnabled(True)
        self.relay_stop_button.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.current_worker = None

class DCSyncWorker(QThread):
    """Worker thread for DCSync extraction"""
    output = pyqtSignal(str)
    
    def __init__(self, target, username, password, domain, specific_user):
        super().__init__()
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.specific_user = specific_user
    
    def run(self):
        try:
            extractor = SecretsExtractor()
            
            # Redirect print statements to signal
            import sys
            from io import StringIO
            
            old_stdout = sys.stdout
            sys.stdout = StringIO()
            
            try:
                result = extractor._extract_via_dcsync(
                    self.target, self.username, self.password, self.domain
                )
                
                output = sys.stdout.getvalue()
                for line in output.split('\n'):
                    if line.strip():
                        self.output.emit(f"<span style='color: white;'>{line}</span>")
                
                if result['success']:
                    self.output.emit(f"<span style='color: green;'>[SUCCESS] DCSync completed successfully</span>")
                else:
                    self.output.emit(f"<span style='color: red;'>[ERROR] {result.get('error', 'Unknown error')}</span>")
                    
            finally:
                sys.stdout = old_stdout
                
        except Exception as e:
            self.output.emit(f"<span style='color: red;'>[ERROR] DCSync failed: {str(e)}</span>")

class RelayWorker(QThread):
    """Worker thread for NTLM relay"""
    output = pyqtSignal(str)
    
    def __init__(self, target, relay_target):
        super().__init__()
        self.target = target
        self.relay_target = relay_target
        self.running = True
    
    def run(self):
        try:
            extractor = SecretsExtractor()
            
            # Redirect output
            import sys
            from io import StringIO
            
            old_stdout = sys.stdout
            sys.stdout = StringIO()
            
            try:
                result = extractor.start_ntlm_relay_attack(self.target, self.relay_target)
                
                output = sys.stdout.getvalue()
                for line in output.split('\n'):
                    if line.strip():
                        self.output.emit(f"<span style='color: white;'>{line}</span>")
                
                if result['success']:
                    self.output.emit(f"<span style='color: green;'>[SUCCESS] NTLM relay completed</span>")
                else:
                    self.output.emit(f"<span style='color: red;'>[ERROR] {result.get('error', 'Unknown error')}</span>")
                    
            finally:
                sys.stdout = old_stdout
                
        except Exception as e:
            self.output.emit(f"<span style='color: red;'>[ERROR] NTLM relay failed: {str(e)}</span>")
    
    def stop(self):
        self.running = False
        self.terminate()

class LSASSWorker(QThread):
    """Worker thread for LSASS dump"""
    output = pyqtSignal(str)
    
    def __init__(self, method):
        super().__init__()
        self.method = method
    
    def run(self):
        try:
            extractor = SecretsExtractor()
            
            # Redirect output
            import sys
            from io import StringIO
            
            old_stdout = sys.stdout
            sys.stdout = StringIO()
            
            try:
                result = extractor._extract_via_lsass_dump()
                
                output = sys.stdout.getvalue()
                for line in output.split('\n'):
                    if line.strip():
                        self.output.emit(f"<span style='color: white;'>{line}</span>")
                
                if result['success']:
                    self.output.emit(f"<span style='color: green;'>[SUCCESS] LSASS dump completed</span>")
                else:
                    self.output.emit(f"<span style='color: red;'>[ERROR] {result.get('error', 'Unknown error')}</span>")
                    
            finally:
                sys.stdout = old_stdout
                
        except Exception as e:
            self.output.emit(f"<span style='color: red;'>[ERROR] LSASS dump failed: {str(e)}</span>")

class LegacyWorker(QThread):
    """Worker thread for legacy extraction"""
    output = pyqtSignal(str)
    
    def __init__(self, target, username, password, sam, lsa, cached):
        super().__init__()
        self.target = target
        self.username = username
        self.password = password
        self.sam = sam
        self.lsa = lsa
        self.cached = cached
    
    def run(self):
        try:
            extractor = SecretsExtractor()
            
            # Redirect output
            import sys
            from io import StringIO
            
            old_stdout = sys.stdout
            sys.stdout = StringIO()
            
            try:
                success = extractor.extract_secrets(
                    self.target, self.username, self.password, None, None,
                    self.sam, self.lsa, False, self.cached
                )
                
                output = sys.stdout.getvalue()
                for line in output.split('\n'):
                    if line.strip():
                        self.output.emit(f"<span style='color: white;'>{line}</span>")
                
                if success:
                    self.output.emit(f"<span style='color: green;'>[SUCCESS] Legacy extraction completed</span>")
                else:
                    self.output.emit(f"<span style='color: orange;'>[WARNING] No credentials extracted</span>")
                    
            finally:
                sys.stdout = old_stdout
                
        except Exception as e:
            self.output.emit(f"<span style='color: red;'>[ERROR] Legacy extraction failed: {str(e)}</span>")