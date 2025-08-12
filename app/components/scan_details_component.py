import time
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QTextEdit

class ScanDetailsComponent(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.apply_theme()

    def setup_ui(self):
        """Setup details UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Title
        title = QLabel("Scan Details")
        title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #64C8FF;")
        layout.addWidget(title)
        
        # Details text
        self.details_text = QTextEdit()
        self.details_text.setMaximumHeight(200)
        self.details_text.setReadOnly(True)
        layout.addWidget(self.details_text)

    def update_scan_details(self, scan_item):
        """Update scan details display"""
        details = f"""
Scan ID: {scan_item.scan_id}
Type: {scan_item.scan_type}
Target: {scan_item.target}
Status: {scan_item.status}
Started: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(scan_item.start_time))}
Duration: {self.format_duration(time.time() - scan_item.start_time)}

Progress: {scan_item.completed_items}/{scan_item.total_items} items
Details: {scan_item.details}

Thread Information:
- Thread ID: {scan_item.thread_id or 'N/A'}
- Current Status: {scan_item.status}
        """.strip()
        
        self.details_text.setPlainText(details)

    def format_duration(self, seconds):
        """Format duration in human readable format"""
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            return f"{int(seconds // 60)}m {int(seconds % 60)}s"
        else:
            hours = int(seconds // 3600)
            minutes = int((seconds % 3600) // 60)
            return f"{hours}h {minutes}m"

    def apply_theme(self):
        """Apply component theme"""
        self.setStyleSheet("""
            QTextEdit {
                background-color: rgba(20, 30, 40, 200);
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 6px;
                padding: 10px;
                font-family: 'Consolas', 'Monaco', monospace;
                color: #DCDCDC;
            }
        """)