from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel

class WebScannerComponent(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        try:
            from app.widgets.web_scanner_widget import WebScannerWidget
            self.web_scanner_widget = WebScannerWidget(self)
            layout.addWidget(self.web_scanner_widget)
        except ImportError as e:
            error_label = QLabel(f"Web Scanner widget not available: {str(e)}")
            error_label.setStyleSheet("color: #FF6B6B; padding: 20px;")
            layout.addWidget(error_label)