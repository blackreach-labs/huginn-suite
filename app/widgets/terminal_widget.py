from PyQt6.QtWidgets import QTextEdit
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QFontDatabase

class TerminalWidget(QTextEdit):
    """Enhanced terminal widget with improved mouse handling"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setPlaceholderText("Tool output will appear here...")
        self.setAcceptRichText(True)
        
        # Critical: Enable mouse tracking and text selection
        self.setMouseTracking(True)
        self.viewport().setCursor(Qt.CursorShape.IBeamCursor)
        self.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse | 
            Qt.TextInteractionFlag.TextSelectableByKeyboard |
            Qt.TextInteractionFlag.LinksAccessibleByMouse
        )
        
        # Install event filter on viewport to capture mouse events
        self.viewport().installEventFilter(self)
        
        # Set default styling
        self.setStyleSheet("""
            QTextEdit {
                background-color: #0A0A0A;
                color: #DCDCDC;
                border: 1px solid #333333;
                border-radius: 4px;
                padding: 5px;
            }
        """)
        
    def load_custom_font(self, font_path):
        """Load custom font for terminal display"""
        font_id = QFontDatabase.addApplicationFont(font_path)
        if font_id != -1:
            font_family = QFontDatabase.applicationFontFamilies(font_id)[0]
            font = QFont(font_family, 10)
            self.setFont(font)
            return True
        return False
        
    def append_text(self, text):
        """Append text to terminal and scroll to bottom"""
        self.insertHtml(text)
        scrollbar = self.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
        
    def clear_terminal(self):
        """Clear terminal content"""
        self.clear()
        
    def mousePressEvent(self, event):
        """Handle mouse press events"""
        # Force focus when clicked
        self.setFocus()
        super().mousePressEvent(event)
        
    def mouseReleaseEvent(self, event):
        """Handle mouse release events"""
        super().mouseReleaseEvent(event)
        
    def contextMenuEvent(self, event):
        """Enable context menu"""
        super().contextMenuEvent(event)
    def eventFilter(self, obj, event):
        """Event filter to handle mouse events in the viewport"""
        from PyQt6.QtCore import QEvent
        
        # Handle mouse press events
        if event.type() == QEvent.Type.MouseButtonPress:
            # Force focus when clicked
            self.setFocus()
            return False  # Continue processing the event
            
        # Handle mouse move events
        elif event.type() == QEvent.Type.MouseMove:
            # Set cursor to IBeam when moving over text
            self.viewport().setCursor(Qt.CursorShape.IBeamCursor)
            
        return super().eventFilter(obj, event)