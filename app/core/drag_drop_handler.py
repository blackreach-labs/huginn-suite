# app/core/drag_drop_handler.py
import os
from PyQt6.QtCore import QMimeData, QUrl
from PyQt6.QtWidgets import QWidget
from PyQt6.QtGui import QDragEnterEvent, QDropEvent

class DragDropMixin:
    """Mixin class to add drag and drop functionality to widgets"""
    
    def __init__(self):
        self.setAcceptDrops(True)
        self.supported_extensions = ['.txt', '.csv', '.json']
        self.drop_callback = None
    
    def set_drop_callback(self, callback):
        """Set callback function for file drops"""
        self.drop_callback = callback
    
    def dragEnterEvent(self, event: QDragEnterEvent):
        """Handle drag enter event"""
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if self._is_valid_file_drop(urls):
                event.acceptProposedAction()
                self._highlight_drop_zone(True)
            else:
                event.ignore()
        else:
            event.ignore()
    
    def dragLeaveEvent(self, event):
        """Handle drag leave event"""
        self._highlight_drop_zone(False)
        event.accept()
    
    def dropEvent(self, event: QDropEvent):
        """Handle drop event"""
        self._highlight_drop_zone(False)
        
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            file_paths = []
            
            for url in urls:
                if url.isLocalFile():
                    file_path = url.toLocalFile()
                    if self._is_valid_file(file_path):
                        file_paths.append(file_path)
            
            if file_paths and self.drop_callback:
                self.drop_callback(file_paths)
            
            event.acceptProposedAction()
        else:
            event.ignore()
    
    def _is_valid_file_drop(self, urls):
        """Check if dropped files are valid"""
        for url in urls:
            if url.isLocalFile():
                file_path = url.toLocalFile()
                if self._is_valid_file(file_path):
                    return True
        return False
    
    def _is_valid_file(self, file_path):
        """Check if file has supported extension"""
        _, ext = os.path.splitext(file_path.lower())
        return ext in self.supported_extensions
    
    def _highlight_drop_zone(self, highlight):
        """Highlight drop zone during drag"""
        if highlight:
            self.setStyleSheet(self.styleSheet() + """
                border: 2px dashed #64C8FF;
                background-color: rgba(100, 200, 255, 50);
            """)
        else:
            # Remove highlight styling
            style = self.styleSheet()
            style = style.replace("border: 2px dashed #64C8FF;", "")
            style = style.replace("background-color: rgba(100, 200, 255, 50);", "")
            self.setStyleSheet(style)

class DragDropWidget(QWidget, DragDropMixin):
    """Widget with drag and drop support"""
    
    def __init__(self, parent=None):
        QWidget.__init__(self, parent)
        DragDropMixin.__init__(self)