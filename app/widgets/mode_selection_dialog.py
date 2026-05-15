# app/widgets/mode_selection_dialog.py
from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QPushButton, 
                             QLabel, QFrame, QApplication)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QPixmap

class ModeSelectionDialog(QDialog):
    """Dialog to select between Guided Workflow and Advanced Mode"""
    
    mode_selected = pyqtSignal(str)  # "guided" or "advanced"
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Huginn - Select Mode")
        self.setModal(True)
        self.setFixedSize(1000, 500)
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the dialog UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)
        
        # Title
        title = QLabel("Welcome to Huginn")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("""
            font-size: 24pt;
            font-weight: bold;
            color: #64C8FF;
            padding: 20px;
        """)
        layout.addWidget(title)
        
        # Subtitle
        subtitle = QLabel("Choose your preferred mode to get started")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet("""
            font-size: 14pt;
            color: #DCDCDC;
            padding-bottom: 20px;
        """)
        layout.addWidget(subtitle)
        
        # Mode selection buttons
        buttons_layout = QHBoxLayout()
        buttons_layout.setSpacing(30)
        
        # Guided Workflow button
        guided_frame = self.create_mode_button(
            "🎯 GUIDED WORKFLOW",
            "Step-by-step penetration testing methodology\nPerfect for beginners",
            "#32CD32",
            lambda: self.select_mode("guided")
        )
        buttons_layout.addWidget(guided_frame)
        
        # Advanced Mode button
        advanced_frame = self.create_mode_button(
            "⚡ ADVANCED MODE",
            "Full access to all tools and features\nFor experienced penetration testers",
            "#FF6347",
            lambda: self.select_mode("advanced")
        )
        buttons_layout.addWidget(advanced_frame)
        
        layout.addLayout(buttons_layout)
        
        # Note
        note = QLabel("You can change this setting later in the application")
        note.setAlignment(Qt.AlignmentFlag.AlignCenter)
        note.setStyleSheet("""
            font-size: 10pt;
            color: #888888;
            font-style: italic;
            padding-top: 20px;
        """)
        layout.addWidget(note)
        
        # Apply dark theme
        self.setStyleSheet("""
            QDialog {
                background-color: #1a1a1a;
                border: 2px solid #64C8FF;
                border-radius: 10px;
            }
        """)
    
    def create_mode_button(self, title, description, color, callback):
        """Create a mode selection button as a single cohesive card."""
        frame = QFrame()
        frame.setStyleSheet(f"""
            QFrame {{
                background-color: rgba(0, 0, 0, 150);
                border: 2px solid {color};
                border-radius: 10px;
            }}
            QFrame:hover {{
                background-color: rgba(50, 50, 50, 150);
                border: 3px solid {color};
            }}
        """)
        frame.setMinimumSize(450, 220)
        frame.setCursor(Qt.CursorShape.PointingHandCursor)

        layout = QVBoxLayout(frame)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(10)

        # Single combined label — title line + description line
        title_label = QLabel(title)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet(f"""
            font-size: 16pt;
            font-weight: bold;
            color: {color};
            background: transparent;
            border: none;
        """)
        layout.addWidget(title_label)

        desc_label = QLabel(description)
        desc_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet("""
            font-size: 11pt;
            color: #DCDCDC;
            background: transparent;
            border: none;
        """)
        layout.addWidget(desc_label)

        frame.mousePressEvent = lambda event: callback() if event.button() == Qt.MouseButton.LeftButton else None

        return frame
    
    def select_mode(self, mode):
        """Handle mode selection"""
        self.mode_selected.emit(mode)
        self.accept()
    
    def keyPressEvent(self, event):
        """Handle key press events"""
        if event.key() == Qt.Key.Key_Escape:
            # Default to advanced mode if user presses escape
            self.select_mode("advanced")
        else:
            super().keyPressEvent(event)