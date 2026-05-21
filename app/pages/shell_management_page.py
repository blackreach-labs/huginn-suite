# app/pages/shell_management_page.py
import time
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QPushButton, QFrame, QScrollArea, QMessageBox)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QPixmap, QPainter, QColor, QBrush
from app.widgets.shell_management_widget import ShellManagementWidget
from app.core.logger import logger

class ShellManagementPage(QWidget):
    """Shell Management page for the main application"""
    
    navigate_signal = pyqtSignal(str)
    status_updated = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the shell management page UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(15)
        
        # Header section
        header_frame = QFrame()
        header_frame.setFrameStyle(QFrame.Shape.Box)
        header_frame.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 rgba(30, 40, 50, 200),
                    stop:1 rgba(50, 60, 70, 200));
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 10px;
                margin: 5px;
            }
        """)
        
        header_layout = QVBoxLayout(header_frame)
        
        # Title
        title_label = QLabel("🐚 Shell Management & Post-Exploitation")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet("""
            QLabel {
                color: #64C8FF;
                font-size: 24px;
                font-weight: bold;
                padding: 10px;
                background: transparent;
                border: none;
            }
        """)
        header_layout.addWidget(title_label)
        
        # Description
        desc_label = QLabel(
            "Establish and maintain shell connections to compromised targets. "
            "Manage reverse shells, SSH connections, bind shells, and generate payloads."
        )
        desc_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet("""
            QLabel {
                color: #CCCCCC;
                font-size: 14px;
                padding: 5px 20px 15px 20px;
                background: transparent;
                border: none;
            }
        """)
        header_layout.addWidget(desc_label)
        
        layout.addWidget(header_frame)
        
        # Quick actions section
        actions_frame = QFrame()
        actions_frame.setFrameStyle(QFrame.Shape.Box)
        actions_frame.setStyleSheet("""
            QFrame {
                background: rgba(20, 30, 40, 150);
                border: 1px solid rgba(100, 200, 255, 50);
                border-radius: 8px;
                margin: 2px;
            }
        """)
        
        actions_layout = QHBoxLayout(actions_frame)
        
        # Quick action buttons
        quick_actions = [
            ("🎯 Start Listener", "Start a reverse shell listener", self.quick_start_listener),
            ("🔗 SSH Connect", "Quick SSH connection", self.quick_ssh_connect),
            ("💾 Generate Payload", "Generate reverse shell payload", self.quick_generate_payload),
            ("📊 Session Status", "View all active sessions", self.show_session_status),
        ]
        
        for title, tooltip, callback in quick_actions:
            btn = QPushButton(title)
            btn.setToolTip(tooltip)
            btn.setStyleSheet("""
                QPushButton {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                        stop:0 rgba(100, 200, 255, 150),
                        stop:1 rgba(50, 150, 255, 150));
                    color: #000000;
                    border: none;
                    border-radius: 6px;
                    padding: 8px 16px;
                    font-weight: bold;
                    font-size: 12px;
                }
                QPushButton:hover {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                        stop:0 rgba(120, 220, 255, 180),
                        stop:1 rgba(70, 170, 255, 180));
                }
                QPushButton:pressed {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                        stop:0 rgba(80, 180, 255, 200),
                        stop:1 rgba(30, 130, 255, 200));
                }
            """)
            btn.clicked.connect(callback)
            actions_layout.addWidget(btn)
            
        layout.addWidget(actions_frame)
        
        # Main shell management widget
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setStyleSheet("""
            QScrollArea {
                border: none;
                background: transparent;
            }
        """)
        
        self.shell_widget = ShellManagementWidget()
        self.shell_widget.status_updated.connect(self.status_updated.emit)
        
        scroll_area.setWidget(self.shell_widget)
        layout.addWidget(scroll_area)
        
        # Navigation buttons
        nav_frame = QFrame()
        nav_frame.setStyleSheet("""
            QFrame {
                background: rgba(20, 30, 40, 100);
                border: 1px solid rgba(100, 200, 255, 50);
                border-radius: 6px;
            }
        """)
        
        nav_layout = QHBoxLayout(nav_frame)
        
        back_btn = QPushButton("← Back to Exploitation")
        back_btn.setStyleSheet("""
            QPushButton {
                background: rgba(255, 100, 100, 150);
                color: #FFFFFF;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: rgba(255, 120, 120, 180);
            }
        """)
        back_btn.clicked.connect(lambda: self.navigate_signal.emit("web_exploits"))
        nav_layout.addWidget(back_btn)
        
        nav_layout.addStretch()
        
        post_exploit_btn = QPushButton("Post-Exploitation Tools →")
        post_exploit_btn.setStyleSheet("""
            QPushButton {
                background: rgba(100, 255, 100, 150);
                color: #000000;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: rgba(120, 255, 120, 180);
            }
        """)
        post_exploit_btn.clicked.connect(lambda: self.navigate_signal.emit("cracking"))
        nav_layout.addWidget(post_exploit_btn)
        
        layout.addWidget(nav_frame)
        
        # Set initial status
        self.status_updated.emit("Shell Management - Ready to establish connections")
        
    def quick_start_listener(self):
        """Quick start a reverse shell listener"""
        try:
            from app.core.listener_manager import listener_manager
            from app.widgets.terminal_window import TerminalWindow
            
            listener_id = listener_manager.create_listener(4444, "netcat")
            success = listener_manager.start_listener(listener_id)
            
            if success:
                self.status_updated.emit(f"Listener started on port 4444: {listener_id}")
                
                # Launch standalone terminal window
                if not hasattr(self, '_terminal_windows'):
                    self._terminal_windows = {}
                window = TerminalWindow(listener_id=listener_id)
                window.show()
                self._terminal_windows[listener_id] = window
                
                # Also open tab in the shell widget if possible
                if hasattr(self.shell_widget, 'open_terminal_tab'):
                    try:
                        title = f"Listener: {listener_id}"
                        self.shell_widget.open_terminal_tab(title, listener_id=listener_id)
                    except Exception:
                        pass
            else:
                linfo = listener_manager._listeners.get(listener_id)
                error_info = linfo.get('error', 'Unknown error') if linfo else 'Unknown error'
                QMessageBox.critical(self, "Error", 
                                   f"Failed to start listener on port 4444\n\n{error_info}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start listener: {str(e)}")
            
    def quick_ssh_connect(self):
        """Quick SSH connection dialog"""
        from PyQt6.QtWidgets import QDialog, QFormLayout, QLineEdit, QDialogButtonBox
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Quick SSH Connection")
        dialog.setModal(True)
        
        layout = QFormLayout(dialog)
        
        host_input = QLineEdit()
        host_input.setPlaceholderText("192.168.1.100")
        layout.addRow("Host:", host_input)
        
        port_input = QLineEdit("22")
        layout.addRow("Port:", port_input)
        
        username_input = QLineEdit()
        username_input.setPlaceholderText("root")
        layout.addRow("Username:", username_input)
        
        password_input = QLineEdit()
        password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addRow("Password:", password_input)
        
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            try:
                from app.core.shell_manager import shell_manager
                session_id = shell_manager.establish_ssh_connection(
                    host_input.text(),
                    int(port_input.text()),
                    username_input.text(),
                    password_input.text()
                )
                self.status_updated.emit(f"SSH connection established: {session_id}")
            except Exception as e:
                QMessageBox.critical(self, "Connection Error", str(e))
                
    def quick_generate_payload(self):
        """Quick payload generation"""
        from PyQt6.QtWidgets import QDialog, QFormLayout, QComboBox, QDialogButtonBox, QTextEdit
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Quick Payload Generator")
        dialog.setModal(True)
        dialog.resize(500, 400)
        
        layout = QFormLayout(dialog)
        
        lhost_input = QLineEdit()
        lhost_input.setPlaceholderText("Your IP address")
        layout.addRow("LHOST:", lhost_input)
        
        lport_input = QLineEdit("4444")
        layout.addRow("LPORT:", lport_input)
        
        payload_combo = QComboBox()
        payload_combo.addItems(["bash", "python", "python3", "nc", "powershell"])
        layout.addRow("Payload Type:", payload_combo)
        
        payload_output = QTextEdit()
        payload_output.setReadOnly(True)
        layout.addRow("Generated Payload:", payload_output)
        
        def generate():
            from app.core.shell_manager import shell_manager
            payload = shell_manager.generate_reverse_shell_payload(
                payload_combo.currentText(),
                lhost_input.text(),
                int(lport_input.text() or "4444")
            )
            payload_output.setText(payload)
            
        generate_btn = QPushButton("Generate")
        generate_btn.clicked.connect(generate)
        layout.addRow(generate_btn)
        
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)
        
        dialog.exec()
        
    def show_session_status(self):
        """Show session status overview"""
        from app.core.shell_manager import shell_manager
        
        sessions = shell_manager.get_active_sessions()
        
        if not sessions:
            QMessageBox.information(self, "Session Status", "No active sessions")
            return
            
        status_text = f"Active Sessions: {len(sessions)}\n\n"
        
        for session in sessions:
            uptime = int(session['uptime'])
            uptime_str = f"{uptime//3600:02d}:{(uptime%3600)//60:02d}:{uptime%60:02d}"
            
            status_text += f"ID: {session['session_id']}\n"
            status_text += f"Type: {session['shell_type']}\n"
            status_text += f"Target: {session['target']}\n"
            status_text += f"Uptime: {uptime_str}\n"
            status_text += f"Commands: {session['command_count']}\n\n"
            
        QMessageBox.information(self, "Session Status", status_text)
        
    def export_results(self):
        """Export shell session data"""
        try:
            from app.core.shell_manager import shell_manager
            from PyQt6.QtWidgets import QFileDialog
            import json
            
            sessions = shell_manager.get_active_sessions()
            
            if not sessions:
                QMessageBox.information(self, "Export", "No active sessions to export")
                return
                
            filename, _ = QFileDialog.getSaveFileName(
                self, "Export Shell Sessions", 
                "shell_sessions.json", 
                "JSON Files (*.json);;All Files (*)"
            )
            
            if filename:
                export_data = {
                    'export_time': time.time(),
                    'active_sessions': sessions,
                    'session_histories': {}
                }
                
                # Add command histories
                for session in sessions:
                    session_id = session['session_id']
                    history = shell_manager.get_session_history(session_id)
                    export_data['session_histories'][session_id] = history
                    
                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2)
                    
                self.status_updated.emit(f"Shell sessions exported to {filename}")
                QMessageBox.information(self, "Export Complete", 
                                      f"Shell sessions exported to:\n{filename}")
                                      
        except Exception as e:
            logger.error(f"Export failed: {e}")
            QMessageBox.critical(self, "Export Error", f"Failed to export: {str(e)}")
            
    def clear_terminal(self):
        """Clear terminal output in shell widget"""
        if hasattr(self.shell_widget, 'active_terminals'):
            for terminal in self.shell_widget.active_terminals.values():
                terminal.clear_terminal()
        self.status_updated.emit("Terminal output cleared")