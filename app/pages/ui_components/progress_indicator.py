# app/pages/ui_components/progress_indicator.py
from PyQt6.QtWidgets import (QWidget, QHBoxLayout, QVBoxLayout, QLabel, 
                             QProgressBar, QPushButton)
from PyQt6.QtCore import pyqtSignal, QTimer, Qt
from PyQt6.QtGui import QFont

class ProgressIndicator(QWidget):
    """Reusable progress indicator component with status and controls."""
    
    # Signals
    cancelled = pyqtSignal()
    
    def __init__(self, show_cancel=True, parent=None):
        super().__init__(parent)
        self.show_cancel = show_cancel
        self.is_active = False
        self.setup_ui()
        self.apply_styles()
        self.hide()  # Hidden by default
    
    def setup_ui(self):
        """Setup the progress indicator UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 5, 10, 5)
        layout.setSpacing(5)
        
        # Status label
        self.status_label = QLabel("Ready")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.status_label)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)
        
        # Details row
        details_layout = QHBoxLayout()
        
        self.details_label = QLabel("")
        self.details_label.setAlignment(Qt.AlignmentFlag.AlignLeft)
        details_layout.addWidget(self.details_label)
        
        details_layout.addStretch()
        
        # Cancel button
        if self.show_cancel:
            self.cancel_button = QPushButton("Cancel")
            self.cancel_button.setFixedWidth(80)
            self.cancel_button.clicked.connect(self.cancel_operation)
            details_layout.addWidget(self.cancel_button)
        
        layout.addLayout(details_layout)
    
    def apply_styles(self):
        """Apply component styles."""
        self.setStyleSheet("""
            QWidget {
                background-color: rgba(0, 0, 0, 100);
                border-radius: 8px;
                border: 1px solid rgba(100, 200, 255, 100);
            }
            QLabel {
                color: #DCDCDC;
                font-weight: bold;
                background: transparent;
                border: none;
            }
            QProgressBar {
                background-color: rgba(20, 30, 40, 150);
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 4px;
                text-align: center;
                color: #DCDCDC;
            }
            QProgressBar::chunk {
                background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #64C8FF, stop:1 #87CEEB);
                border-radius: 3px;
            }
            QPushButton {
                background-color: rgba(255, 100, 100, 150);
                border: 1px solid #FF6B6B;
                border-radius: 4px;
                color: #FFFFFF;
                font-weight: bold;
                padding: 5px;
            }
            QPushButton:hover {
                background-color: rgba(255, 120, 120, 200);
            }
            QPushButton:pressed {
                background-color: rgba(255, 80, 80, 220);
            }
        """)
    
    def start_progress(self, total_items=0, status_text="Processing..."):
        """Start progress indication."""
        self.is_active = True
        self.status_label.setText(status_text)
        
        if total_items > 0:
            self.progress_bar.setMaximum(total_items)
            self.progress_bar.setValue(0)
        else:
            # Indeterminate progress
            self.progress_bar.setMaximum(0)
            self.progress_bar.setMinimum(0)
        
        self.details_label.setText("")
        self.show()
    
    def update_progress(self, completed=0, found=0, status_text=""):
        """Update progress with current values."""
        if not self.is_active:
            return
        
        if self.progress_bar.maximum() > 0:
            self.progress_bar.setValue(completed)
        
        if status_text:
            self.status_label.setText(status_text)
        
        # Update details
        if found > 0:
            self.details_label.setText(f"Completed: {completed}, Found: {found}")
        else:
            self.details_label.setText(f"Completed: {completed}")
    
    def finish_progress(self, status_text="Completed"):
        """Finish progress indication."""
        self.is_active = False
        self.status_label.setText(status_text)
        
        if self.progress_bar.maximum() > 0:
            self.progress_bar.setValue(self.progress_bar.maximum())
        
        # Auto-hide after delay
        QTimer.singleShot(2000, self.hide)
    
    def cancel_operation(self):
        """Cancel the current operation."""
        self.is_active = False
        self.status_label.setText("Cancelled")
        self.cancelled.emit()
        
        # Hide after short delay
        QTimer.singleShot(1000, self.hide)
    
    def reset_progress(self):
        """Reset progress to initial state."""
        self.is_active = False
        self.progress_bar.setValue(0)
        self.progress_bar.setMaximum(100)
        self.status_label.setText("Ready")
        self.details_label.setText("")
        self.hide()
    
    def set_status(self, status_text):
        """Set status text."""
        self.status_label.setText(status_text)
    
    def set_details(self, details_text):
        """Set details text."""
        self.details_label.setText(details_text)
    
    def is_progress_active(self):
        """Check if progress is currently active."""
        return self.is_active