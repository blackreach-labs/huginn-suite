# app/components/session_info/session_management_component.py
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox, QFileDialog, QMessageBox
from PyQt6.QtCore import pyqtSignal, QTimer
from datetime import datetime

class SessionManagementComponent(QWidget):
    session_changed = pyqtSignal(str)  # session_id
    status_updated = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.setup_refresh_timer()

    def setup_ui(self):
        layout = QHBoxLayout(self)
        
        # Session selection
        layout.addWidget(QLabel("Session:"))
        
        self.session_combo = QComboBox()
        self.session_combo.setMinimumWidth(350)
        self.session_combo.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToContents)
        self.session_combo.currentTextChanged.connect(self.on_session_changed)
        layout.addWidget(self.session_combo)
        
        # Control buttons
        self.refresh_button = QPushButton("🔄 Refresh")
        self.refresh_button.clicked.connect(self.refresh_sessions)
        
        self.save_session_button = QPushButton("💾 Save Session")
        self.save_session_button.clicked.connect(self.save_current_session)
        
        self.restore_session_button = QPushButton("📂 Restore Session")
        self.restore_session_button.clicked.connect(self.restore_session)
        
        button_style = """
            QPushButton {
                background-color: rgba(100, 200, 255, 150);
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 12px;
                font-size: 10pt;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(100, 200, 255, 200);
            }
        """
        
        self.refresh_button.setStyleSheet(button_style)
        self.save_session_button.setStyleSheet(button_style.replace("100, 200, 255", "100, 255, 100"))
        self.restore_session_button.setStyleSheet(button_style.replace("100, 200, 255", "255, 200, 100"))
        
        layout.addWidget(self.refresh_button)
        layout.addWidget(self.save_session_button)
        layout.addWidget(self.restore_session_button)
        layout.addStretch()

    def setup_refresh_timer(self):
        """Setup automatic refresh timer"""
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_sessions)
        self.refresh_timer.start(5000)  # Refresh every 5 seconds

    def refresh_sessions(self):
        """Refresh session list"""
        try:
            from app.core.session_manager import session_manager
            
            # Update session combo
            sessions = session_manager.get_all_sessions()
            current_session = session_manager.get_current_session()
            
            self.session_combo.clear()
            for session in sessions:
                self.session_combo.addItem(f"{session['name']} ({session['id']})", session['id'])
            
            # Set current session
            if current_session:
                for i in range(self.session_combo.count()):
                    if self.session_combo.itemData(i) == current_session['id']:
                        self.session_combo.setCurrentIndex(i)
                        break
            
            self.status_updated.emit("Sessions refreshed")
            
        except Exception as e:
            self.status_updated.emit(f"Error refreshing sessions: {str(e)}")

    def on_session_changed(self):
        """Handle session selection change"""
        session_id = self.session_combo.currentData()
        if session_id:
            self.session_changed.emit(session_id)

    def save_current_session(self):
        """Save current session to file"""
        try:
            from app.core.session_manager import session_manager
            
            current_session = session_manager.get_current_session()
            if not current_session:
                QMessageBox.warning(self, "Warning", "No current session to save")
                return
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            default_name = f"session_{current_session['name'].replace(' ', '_')}_{timestamp}.json"
            
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Save Session", default_name, "JSON Files (*.json)"
            )
            
            if file_path:
                if session_manager.save_current_session(file_path):
                    QMessageBox.information(self, "Success", f"Session saved to {file_path}")
                    self.status_updated.emit("Session saved successfully")
                else:
                    QMessageBox.critical(self, "Error", "Failed to save session")
                    self.status_updated.emit("Failed to save session")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error saving session: {str(e)}")
            self.status_updated.emit(f"Error saving session: {str(e)}")

    def restore_session(self):
        """Restore session from file"""
        try:
            from app.core.session_manager import session_manager
            
            file_path, _ = QFileDialog.getOpenFileName(
                self, "Restore Session", "", "JSON Files (*.json)"
            )
            
            if file_path:
                session_id = session_manager.restore_session(file_path)
                if session_id:
                    QMessageBox.information(self, "Success", "Session restored successfully")
                    self.refresh_sessions()
                    self.status_updated.emit("Session restored successfully")
                else:
                    QMessageBox.critical(self, "Error", "Failed to restore session")
                    self.status_updated.emit("Failed to restore session")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error restoring session: {str(e)}")
            self.status_updated.emit(f"Error restoring session: {str(e)}")

    def get_current_session_id(self):
        """Get currently selected session ID"""
        return self.session_combo.currentData()

    def cleanup(self):
        """Cleanup resources"""
        if hasattr(self, 'refresh_timer'):
            self.refresh_timer.stop()