# app/widgets/pdf_preview_widget.py
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QTextEdit
from PyQt6.QtCore import Qt
import os

class PDFPreviewWidget(QWidget):
    """Simple widget to show PDF export status"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Header
        header = QLabel("📄 PDF Report Generator")
        header.setStyleSheet("color: #64C8FF; font-size: 12pt; font-weight: bold;")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Status area
        self.status_text = QTextEdit()
        self.status_text.setFixedHeight(100)
        self.status_text.setReadOnly(True)
        self.status_text.setStyleSheet("""
            QTextEdit {
                background-color: rgba(0, 0, 0, 150);
                border: 1px solid #555;
                border-radius: 5px;
                color: #DCDCDC;
                font-size: 10pt;
                padding: 5px;
            }
        """)
        self.status_text.setPlainText("Ready to generate PDF reports...")
        
        # Open folder button
        self.open_folder_btn = QPushButton("📁 Open Exports Folder")
        self.open_folder_btn.clicked.connect(self.open_exports_folder)
        self.open_folder_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(100, 200, 100, 150);
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px;
                font-size: 10pt;
            }
            QPushButton:hover {
                background-color: rgba(100, 200, 100, 200);
            }
        """)
        
        layout.addWidget(header)
        layout.addWidget(self.status_text)
        layout.addWidget(self.open_folder_btn)
        
    def update_status(self, message):
        """Update status message"""
        self.status_text.append(f"[{self.get_timestamp()}] {message}")
        
    def get_timestamp(self):
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().strftime("%H:%M:%S")
        
    def open_exports_folder(self):
        """Open exports folder in file explorer"""
        exports_dir = "exports"
        if not os.path.exists(exports_dir):
            os.makedirs(exports_dir)
        
        try:
            if os.name == 'nt':  # Windows
                os.startfile(exports_dir)
            elif os.name == 'posix':  # macOS and Linux
                os.system(f'open "{exports_dir}"' if os.uname().sysname == 'Darwin' else f'xdg-open "{exports_dir}"')
        except:
            self.update_status("Could not open exports folder")