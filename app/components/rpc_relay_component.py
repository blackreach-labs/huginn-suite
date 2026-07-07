from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QLineEdit, QPushButton, QTextEdit, QComboBox, QCheckBox, QFrame)
from PyQt6.QtCore import pyqtSignal, QThreadPool, Qt
from app.core.base_worker import CommandWorker
from app.core.html_utils import h

class RpcRelayComponent(QWidget):
    relay_started = pyqtSignal(str, str)
    relay_completed = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = getattr(parent, 'main_window', parent)
        self.setup_ui()
        self.apply_theme()

    def setup_ui(self):
        """Setup RPC relay UI"""
        layout = QHBoxLayout(self)
        
        # Left panel - controls
        left_panel = self.create_controls_panel()
        layout.addWidget(left_panel, 0)
        
        # Right panel - output
        right_panel = self.create_output_panel()
        layout.addWidget(right_panel, 1)

    def create_controls_panel(self):
        """Create controls panel"""
        panel = QFrame()
        panel.setFixedWidth(280)
        layout = QVBoxLayout(panel)
        
        # Target input
        layout.addWidget(QLabel("Target:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("192.168.1.10")
        layout.addWidget(self.target_input)
        
        # Attacker IP
        layout.addWidget(QLabel("Attacker IP:"))
        self.attacker_input = QLineEdit()
        self.attacker_input.setPlaceholderText("192.168.1.100")
        layout.addWidget(self.attacker_input)
        
        # Relay type
        layout.addWidget(QLabel("Relay Type:"))
        self.relay_type_combo = QComboBox()
        self.relay_type_combo.addItems(["NTLM Relay", "PrinterBug", "PetitPotam", "SpoolSample"])
        layout.addWidget(self.relay_type_combo)
        
        # Target service
        layout.addWidget(QLabel("Target Service:"))
        self.service_combo = QComboBox()
        self.service_combo.addItems(["SMB", "HTTP", "LDAP", "MSSQL"])
        layout.addWidget(self.service_combo)
        
        # Options
        layout.addWidget(QLabel("Options:"))
        
        self.smb_signing_check = QCheckBox("Check SMB Signing")
        self.smb_signing_check.setChecked(True)
        layout.addWidget(self.smb_signing_check)
        
        self.enumerate_check = QCheckBox("Enumerate Interfaces")
        self.enumerate_check.setChecked(True)
        layout.addWidget(self.enumerate_check)
        
        self.simulate_check = QCheckBox("Simulate Attack")
        layout.addWidget(self.simulate_check)
        
        # Action buttons
        layout.addWidget(QLabel("Actions:"))
        
        self.relay_buttons = []
        
        scan_btn = QPushButton("🔍 Scan Relay Potential")
        scan_btn.clicked.connect(self.scan_relay_potential)
        scan_btn.setMinimumHeight(40)
        layout.addWidget(scan_btn)
        self.relay_buttons.append(scan_btn)
        
        mitm_btn = QPushButton("🌐 Map MITM Surface")
        mitm_btn.clicked.connect(self.map_mitm_surface)
        mitm_btn.setMinimumHeight(35)
        layout.addWidget(mitm_btn)
        self.relay_buttons.append(mitm_btn)
        
        layout.addStretch()
        return panel

    def create_output_panel(self):
        """Create output panel"""
        panel = QFrame()
        layout = QVBoxLayout(panel)
               
        self.terminal_output = QTextEdit()
        self.terminal_output.setReadOnly(True)
        self.terminal_output.setPlaceholderText("RPC relay and MITM analysis results will appear here...")
        layout.addWidget(self.terminal_output)
        
        return panel

    def scan_relay_potential(self):
        """Scan for NTLM relay potential"""
        target = self.target_input.text().strip()
        if not target:
            self.show_error("Please enter a target IP address")
            return
        
        relay_type = self.relay_type_combo.currentText()
        self.relay_started.emit(target, relay_type)
        
        self.terminal_output.clear()
        self.set_buttons_enabled(False)
        
        # Build relay scan command
        cmd = ["python", "-m", "app.core.rpc_relay_scanner", "--scan", target]
        
        attacker_ip = self.attacker_input.text().strip()
        if attacker_ip:
            cmd.extend(["--attacker", attacker_ip])
        
        cmd.extend(["--type", relay_type.lower().replace(" ", "_")])
        
        if self.smb_signing_check.isChecked():
            cmd.append("--check-signing")
        
        if self.enumerate_check.isChecked():
            cmd.append("--enumerate")
        
        if self.simulate_check.isChecked():
            cmd.append("--simulate")
        
        worker = CommandWorker(cmd, f"Scanning relay potential on {target}", 
                              str(getattr(self.main_window, 'project_root', '.')))
        worker.signals.output.connect(self.append_terminal_output)
        worker.signals.finished.connect(self.on_relay_finished)
        QThreadPool.globalInstance().start(worker)

    def map_mitm_surface(self):
        """Map MITM attack surface"""
        target = self.target_input.text().strip()
        if not target:
            self.show_error("Please enter a target IP address")
            return
        
        self.relay_started.emit(target, "MITM Mapping")
        
        self.terminal_output.clear()
        self.set_buttons_enabled(False)
        
        # Build MITM mapping command
        cmd = ["python", "-m", "app.core.rpc_relay_scanner", "--mitm", target]
        
        attacker_ip = self.attacker_input.text().strip()
        if attacker_ip:
            cmd.extend(["--attacker", attacker_ip])
        
        target_service = self.service_combo.currentText()
        cmd.extend(["--service", target_service.lower()])
        
        worker = CommandWorker(cmd, f"Mapping MITM surface for {target}", 
                              str(getattr(self.main_window, 'project_root', '.')))
        worker.signals.output.connect(self.append_terminal_output)
        worker.signals.finished.connect(self.on_relay_finished)
        QThreadPool.globalInstance().start(worker)

    def on_relay_finished(self):
        """Handle relay operation completion"""
        self.set_buttons_enabled(True)
        self.relay_completed.emit({"status": "completed"})

    def show_error(self, message):
        """Show error message"""
        self.terminal_output.setHtml(f"<p style='color: #FF4500;'>[ERROR] {h(message)}</p>")

    def append_terminal_output(self, text):
        """Append text to terminal output"""
        self.terminal_output.insertHtml(text)
        scrollbar = self.terminal_output.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def set_buttons_enabled(self, enabled):
        """Enable/disable relay buttons"""
        for button in self.relay_buttons:
            button.setEnabled(enabled)

    def apply_theme(self):
        """Theme is applied globally by UnifiedThemeManager."""
        pass