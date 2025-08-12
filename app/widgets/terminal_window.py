# app/widgets/terminal_window.py
import os
import subprocess
from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QTextEdit, QLineEdit, QPushButton, QLabel, QMenuBar,
                            QMenu, QMessageBox, QApplication)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread, QProcess
from PyQt6.QtGui import QFont, QTextCursor, QColor, QAction, QIcon
from app.core.shell_manager import shell_manager
from app.core.listener_manager import listener_manager
from app.core.logger import logger

class TerminalWindow(QMainWindow):
    """Standalone terminal window for shell sessions"""
    
    window_closed = pyqtSignal(str)  # session_id
    
    def __init__(self, session_id: str = None, listener_id: str = None, parent=None):
        super().__init__(parent)
        self.session_id = session_id
        self.listener_id = listener_id
        self.command_history = []
        self.history_index = -1
        self.is_listener_terminal = listener_id is not None
        
        self.setup_ui()
        self.setup_menu()
        self.connect_signals()
        
        # Update timer for listener terminals
        if self.is_listener_terminal:
            self.update_timer = QTimer()
            self.update_timer.timeout.connect(self.check_listener_connections)
            self.update_timer.start(1000)
        
    def setup_ui(self):
        """Setup the terminal UI"""
        self.setWindowTitle(f"Terminal - {self.session_id or self.listener_id}")
        self.setGeometry(100, 100, 800, 600)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Status bar
        status_layout = QHBoxLayout()
        
        if self.is_listener_terminal:
            self.status_label = QLabel(f"Listener: {self.listener_id}")
            self.connection_label = QLabel("No connections")
        else:
            self.status_label = QLabel(f"Session: {self.session_id}")
            self.connection_label = QLabel("Connected")
            
        self.status_label.setStyleSheet("color: #00FF00; font-weight: bold;")
        self.connection_label.setStyleSheet("color: #FFFF00;")
        
        status_layout.addWidget(self.status_label)
        status_layout.addStretch()
        status_layout.addWidget(self.connection_label)
        
        layout.addLayout(status_layout)
        
        # Terminal output
        self.terminal_output = QTextEdit()
        self.terminal_output.setReadOnly(True)
        self.terminal_output.setFont(QFont("Consolas", 11))
        self.terminal_output.setStyleSheet("""
            QTextEdit {
                background-color: #0C0C0C;
                color: #CCCCCC;
                border: 1px solid #333333;
                font-family: 'Consolas', 'Courier New', monospace;
                selection-background-color: #264F78;
            }
        """)
        layout.addWidget(self.terminal_output)
        
        # Command input area
        input_layout = QHBoxLayout()
        
        self.prompt_label = QLabel("$ ")
        self.prompt_label.setStyleSheet("color: #00FF00; font-weight: bold; font-family: 'Consolas';")
        input_layout.addWidget(self.prompt_label)
        
        self.command_input = QLineEdit()
        self.command_input.setFont(QFont("Consolas", 11))
        self.command_input.setStyleSheet("""
            QLineEdit {
                background-color: #1E1E1E;
                color: #CCCCCC;
                border: 1px solid #333333;
                padding: 5px;
                font-family: 'Consolas', 'Courier New', monospace;
            }
            QLineEdit:focus {
                border: 1px solid #007ACC;
            }
        """)
        self.command_input.returnPressed.connect(self.execute_command)
        self.command_input.keyPressEvent = self.handle_key_press
        input_layout.addWidget(self.command_input)
        

        
        layout.addLayout(input_layout)
        
        # Initial welcome message
        if self.is_listener_terminal:
            self.append_output(f"Listener Terminal - {self.listener_id}", "#00FFFF")
            self.append_output("Waiting for connections...", "#FFFF00")
            self.append_output("Type 'help' for listener management commands.", "#CCCCCC")
        else:
            self.append_output(f"Shell Session - {self.session_id}", "#00FFFF")
            self.append_output("Terminal ready. Type commands below.", "#FFFF00")
            
        # Focus on command input
        self.command_input.setFocus()
        
    def setup_menu(self):
        """Setup menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        
        save_action = QAction("Save Output", self)
        save_action.triggered.connect(self.save_output)
        file_menu.addAction(save_action)
        
        clear_action = QAction("Clear Terminal", self)
        clear_action.triggered.connect(self.clear_terminal)
        file_menu.addAction(clear_action)
        
        file_menu.addSeparator()
        
        close_action = QAction("Close", self)
        close_action.triggered.connect(self.close)
        file_menu.addAction(close_action)
        
        # Edit menu
        edit_menu = menubar.addMenu("Edit")
        
        copy_action = QAction("Copy", self)
        copy_action.setShortcut("Ctrl+C")
        copy_action.triggered.connect(self.copy_selection)
        edit_menu.addAction(copy_action)
        
        paste_action = QAction("Paste", self)
        paste_action.setShortcut("Ctrl+V")
        paste_action.triggered.connect(self.paste_to_input)
        edit_menu.addAction(paste_action)
        
        # Terminal menu
        terminal_menu = menubar.addMenu("Terminal")
        
        if not self.is_listener_terminal:
            disconnect_action = QAction("Disconnect", self)
            disconnect_action.triggered.connect(self.disconnect_session)
            terminal_menu.addAction(disconnect_action)
        else:
            stop_listener_action = QAction("Stop Listener", self)
            stop_listener_action.triggered.connect(self.stop_listener)
            terminal_menu.addAction(stop_listener_action)
            
    def connect_signals(self):
        """Connect relevant signals"""
        if not self.is_listener_terminal:
            shell_manager.shell_output.connect(self.on_shell_output)
            shell_manager.session_terminated.connect(self.on_session_terminated)
        else:
            listener_manager.connection_received.connect(self.on_connection_received)
            listener_manager.oob_data_received.connect(self.on_oob_data_received)
            listener_manager.listener_stopped.connect(self.on_listener_stopped)
        
    def handle_key_press(self, event):
        """Handle special key presses for command history"""
        if event.key() == Qt.Key.Key_Up:
            if self.history_index < len(self.command_history) - 1:
                self.history_index += 1
                self.command_input.setText(self.command_history[-(self.history_index + 1)])
        elif event.key() == Qt.Key.Key_Down:
            if self.history_index > 0:
                self.history_index -= 1
                self.command_input.setText(self.command_history[-(self.history_index + 1)])
            elif self.history_index == 0:
                self.history_index = -1
                self.command_input.clear()
        else:
            QLineEdit.keyPressEvent(self.command_input, event)
            
    def execute_command(self):
        """Execute command"""
        command = self.command_input.text().strip()
        if not command:
            return
            
        # Add to history
        if command not in self.command_history:
            self.command_history.append(command)
        self.history_index = -1
        
        # Display command in terminal
        self.append_output(f"$ {command}", "#FFFF00")
        
        # Clear input
        self.command_input.clear()
        
        if self.is_listener_terminal:
            # Check if we have active connections to forward commands to
            listener_info = listener_manager.get_listener_info(self.listener_id)
            if listener_info and listener_info['connections']:
                # Forward command to the first active connection
                self.forward_command_to_connection(command)
            else:
                # Handle listener management commands
                self.handle_listener_command(command)
        else:
            # Execute in shell session
            result = shell_manager.execute_command(self.session_id, command)
            if result.get('success'):
                output = result.get('output', '')
                if output:
                    self.append_output(output)
            else:
                error = result.get('error', 'Unknown error')
                self.append_output(f"Error: {error}", "#FF0000")
                
    def forward_command_to_connection(self, command: str):
        """Forward command to active shell connection"""
        try:
            success = listener_manager.send_command_to_connection(self.listener_id, command)
            if not success:
                self.append_output("Failed to send command to connection", "#FF0000")
        except Exception as e:
            self.append_output(f"Error forwarding command: {str(e)}", "#FF0000")
    
    def handle_listener_command(self, command: str):
        """Handle commands in listener terminal when no connections are active"""
        if command.lower() == "status":
            listener_info = listener_manager.get_listener_info(self.listener_id)
            if listener_info:
                self.append_output(f"Listener Status: {listener_info['status']}")
                self.append_output(f"Port: {listener_info['port']}")
                self.append_output(f"Type: {listener_info['type']}")
                self.append_output(f"Connections: {len(listener_info['connections'])}")
            else:
                self.append_output("Listener not found", "#FF0000")
                
        elif command.lower() == "connections":
            listener_info = listener_manager.get_listener_info(self.listener_id)
            if listener_info and listener_info['connections']:
                self.append_output("Active Connections:")
                for i, conn in enumerate(listener_info['connections']):
                    connected_at = conn.get('connected_at', 'Unknown')
                    self.append_output(f"  {i+1}. {conn['ip']} - Connected at: {connected_at}")
            else:
                self.append_output("No active connections")
                
        elif command.lower() == "clear":
            self.clear_terminal()
            
        elif command.lower() == "help":
            self.append_output("Available commands:")
            self.append_output("  status      - Show listener status")
            self.append_output("  connections - List active connections")
            self.append_output("  clear       - Clear terminal")
            self.append_output("  help        - Show this help")
            self.append_output("")
            self.append_output("Note: When a shell connects, commands will be forwarded directly to the shell.")
            
        else:
            self.append_output(f"Unknown command: {command}", "#FF0000")
            self.append_output("Type 'help' for available commands")
            
    def append_output(self, text: str, color: str = "#CCCCCC"):
        """Append text to terminal output"""
        cursor = self.terminal_output.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        
        # Set text color
        format = cursor.charFormat()
        format.setForeground(QColor(color))
        cursor.setCharFormat(format)
        
        cursor.insertText(text + "\n")
        self.terminal_output.setTextCursor(cursor)
        self.terminal_output.ensureCursorVisible()
        
    def clear_terminal(self):
        """Clear terminal output"""
        self.terminal_output.clear()
        if self.is_listener_terminal:
            self.append_output(f"Listener Terminal - {self.listener_id}", "#00FFFF")
        else:
            self.append_output(f"Shell Session - {self.session_id}", "#00FFFF")
            
    def copy_selection(self):
        """Copy selected text"""
        self.terminal_output.copy()
        
    def paste_to_input(self):
        """Paste clipboard content to input"""
        clipboard = QApplication.clipboard()
        self.command_input.setText(clipboard.text())
        
    def save_output(self):
        """Save terminal output to file"""
        from PyQt6.QtWidgets import QFileDialog
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Terminal Output", "", "Text Files (*.txt);;All Files (*)"
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.terminal_output.toPlainText())
                QMessageBox.information(self, "Success", "Terminal output saved successfully")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save output: {str(e)}")
                
    def disconnect_session(self):
        """Disconnect shell session"""
        if not self.is_listener_terminal:
            reply = QMessageBox.question(
                self, "Confirm Disconnect",
                f"Are you sure you want to disconnect session {self.session_id}?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                shell_manager.terminate_session(self.session_id, "User disconnected")
                self.close()
                
    def stop_listener(self):
        """Stop listener"""
        if self.is_listener_terminal:
            reply = QMessageBox.question(
                self, "Confirm Stop",
                f"Are you sure you want to stop listener {self.listener_id}?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                listener_manager.stop_listener(self.listener_id)
                
    def check_listener_connections(self):
        """Check listener connections and update status"""
        if self.is_listener_terminal:
            listener_info = listener_manager.get_listener_info(self.listener_id)
            if listener_info:
                conn_count = len(listener_info['connections'])
                if conn_count == 0:
                    self.connection_label.setText("Waiting for connections...")
                    self.connection_label.setStyleSheet("color: #FFFF00;")
                    self.prompt_label.setText("$ ")
                else:
                    self.connection_label.setText(f"Interactive Shell ({conn_count} connection(s))")
                    self.connection_label.setStyleSheet("color: #00FF00;")
                    # Update prompt to show first connection IP
                    first_conn_ip = listener_info['connections'][0]['ip']
                    self.prompt_label.setText(f"{first_conn_ip}$ ")
                    
    def on_shell_output(self, session_id: str, output: str):
        """Handle shell output"""
        if session_id == self.session_id:
            self.append_output(output)
            
    def on_session_terminated(self, session_id: str, reason: str):
        """Handle session termination"""
        if session_id == self.session_id:
            self.append_output(f"Session terminated: {reason}", "#FF0000")
            self.connection_label.setText("Disconnected")
            self.connection_label.setStyleSheet("color: #FF0000;")
            self.command_input.setEnabled(False)
            
    def on_connection_received(self, listener_id: str, client_ip: str, data: str):
        """Handle connection received"""
        if listener_id == self.listener_id:
            if data == "Connected":
                self.append_output(f"[CONNECTION] {client_ip}: Connected", "#00FF00")
                self.append_output("🐚 Shell connection established! You can now type commands directly.", "#00FFFF")
                self.append_output("💡 Tip: Use 'python3 -c \"import pty; pty.spawn('/bin/bash')\"' to upgrade to a full TTY", "#CCCCCC")
                # Update prompt to show we're in interactive mode
                self.prompt_label.setText(f"{client_ip}$ ")
            else:
                # This is actual shell output
                self.append_output(data)
            
    def on_oob_data_received(self, listener_id: str, source_ip: str, data: str):
        """Handle OOB data received"""
        if listener_id == self.listener_id:
            self.append_output(f"[OOB] {source_ip}: {data}", "#00FFFF")
            
    def on_listener_stopped(self, listener_id: str):
        """Handle listener stopped"""
        if listener_id == self.listener_id:
            self.append_output("Listener stopped", "#FF0000")
            self.connection_label.setText("Stopped")
            self.connection_label.setStyleSheet("color: #FF0000;")
            
    def closeEvent(self, event):
        """Handle window close event"""
        self.window_closed.emit(self.session_id or self.listener_id)
        event.accept()

class SystemTerminalWindow(QMainWindow):
    """System terminal window using native terminal"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the system terminal UI"""
        self.setWindowTitle("System Terminal")
        self.setGeometry(100, 100, 800, 600)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Info label
        info_label = QLabel("System Terminal - Choose an option:")
        info_label.setStyleSheet("font-size: 14px; font-weight: bold; margin: 10px;")
        layout.addWidget(info_label)
        
        # Terminal options
        options_layout = QVBoxLayout()
        
        cmd_btn = QPushButton("Open Command Prompt (cmd)")
        cmd_btn.clicked.connect(self.open_cmd)
        cmd_btn.setStyleSheet("padding: 10px; font-size: 12px;")
        options_layout.addWidget(cmd_btn)
        
        powershell_btn = QPushButton("Open PowerShell")
        powershell_btn.clicked.connect(self.open_powershell)
        powershell_btn.setStyleSheet("padding: 10px; font-size: 12px;")
        options_layout.addWidget(powershell_btn)
        
        wsl_btn = QPushButton("Open WSL (if available)")
        wsl_btn.clicked.connect(self.open_wsl)
        wsl_btn.setStyleSheet("padding: 10px; font-size: 12px;")
        options_layout.addWidget(wsl_btn)
        
        layout.addLayout(options_layout)
        layout.addStretch()
        
    def open_cmd(self):
        """Open Windows Command Prompt"""
        try:
            subprocess.Popen(['cmd'], creationflags=subprocess.CREATE_NEW_CONSOLE)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to open Command Prompt: {str(e)}")
            
    def open_powershell(self):
        """Open PowerShell"""
        try:
            subprocess.Popen(['powershell'], creationflags=subprocess.CREATE_NEW_CONSOLE)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to open PowerShell: {str(e)}")
            
    def open_wsl(self):
        """Open WSL"""
        try:
            subprocess.Popen(['wsl'], creationflags=subprocess.CREATE_NEW_CONSOLE)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to open WSL: {str(e)}")