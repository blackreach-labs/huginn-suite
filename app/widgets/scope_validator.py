# app/widgets/scope_validator.py
from PyQt6.QtWidgets import QWidget, QLabel, QHBoxLayout, QPushButton, QMessageBox
from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtGui import QFont

class ScopeValidator(QWidget):
    """Widget to validate targets against engagement scope"""
    
    proceed_signal = pyqtSignal(bool)  # True if user wants to proceed despite warning
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.setVisible(False)
    
    def setup_ui(self):
        """Setup the validation UI"""
        layout = QHBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)
        
        self.warning_label = QLabel()
        self.warning_label.setWordWrap(False)
        self.warning_label.setStyleSheet("""
            QLabel {
                background-color: rgba(255, 69, 0, 150);
                border: 2px solid #FF4500;
                border-radius: 5px;
                padding: 8px;
                color: #FFFFFF;
                font-weight: bold;
            }
        """)
        layout.addWidget(self.warning_label, 1)
        
        # Proceed button
        self.proceed_btn = QPushButton("Run")
        self.proceed_btn.setFixedWidth(60)
        self.proceed_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(255, 69, 0, 150);
                border: 2px solid #FF4500;
                border-radius: 3px;
                color: #FFFFFF;
                font-weight: bold;
                padding: 3px 8px;
            }
            QPushButton:hover {
                background-color: rgba(255, 69, 0, 200);
            }
        """)
        self.proceed_btn.clicked.connect(lambda: self.proceed_signal.emit(True))
        layout.addWidget(self.proceed_btn)
        
        # Cancel button
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setFixedWidth(60)
        self.cancel_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(100, 100, 100, 150);
                border: 2px solid #666666;
                border-radius: 3px;
                color: #FFFFFF;
                font-weight: bold;
                padding: 3px 8px;
            }
            QPushButton:hover {
                background-color: rgba(120, 120, 120, 200);
            }
        """)
        self.cancel_btn.clicked.connect(lambda: self.proceed_signal.emit(False))
        layout.addWidget(self.cancel_btn)
    
    def validate_target(self, target: str) -> bool:
        """Validate target and show warning if out of scope. Returns True if should proceed."""
        from app.core.scope_manager import scope_manager
        
        is_in_scope, reason = scope_manager.is_target_in_scope(target)
        
        if not is_in_scope:
            self.warning_label.setText(f"⚠️ SCOPE WARNING: {reason}")
            self.setVisible(True)
            return False
        else:
            self.setVisible(False)
            return True
    
    def hide_warning(self):
        """Hide the scope warning"""
        self.setVisible(False)

def show_scope_warning_dialog(target: str, parent=None) -> bool:
    """Show scope warning dialog. Returns True if user wants to proceed."""
    from app.core.scope_manager import scope_manager
    
    is_in_scope, reason = scope_manager.is_target_in_scope(target)
    
    if is_in_scope:
        return True
    
    msg = QMessageBox(parent)
    msg.setIcon(QMessageBox.Icon.Warning)
    msg.setWindowTitle("Scope Validation Warning")
    msg.setText(f"Target '{target}' appears to be outside the defined engagement scope.")
    msg.setDetailedText(f"Reason: {reason}\n\nProceeding with this target may violate the rules of engagement.")
    msg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
    msg.setDefaultButton(QMessageBox.StandardButton.No)
    
    yes_btn = msg.button(QMessageBox.StandardButton.Yes)
    yes_btn.setText("Proceed Anyway")
    no_btn = msg.button(QMessageBox.StandardButton.No)
    no_btn.setText("Cancel")
    
    result = msg.exec()
    return result == QMessageBox.StandardButton.Yes