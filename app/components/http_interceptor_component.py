from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel
from PyQt6.QtCore import pyqtSignal

class HttpInterceptorComponent(QWidget):
    request_intercepted = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        """Setup HTTP interceptor UI"""
        layout = QVBoxLayout(self)
        
        try:
            from app.widgets.curl_widget import CurlWidget
            self.curl_widget = CurlWidget()
            layout.addWidget(self.curl_widget)
        except ImportError:
            info_label = QLabel("HTTP Interceptor - CurlWidget not available")
            info_label.setStyleSheet("color: #FF6B6B; font-size: 14pt; padding: 20px;")
            layout.addWidget(info_label)
            
            # Placeholder for future implementation
            details_label = QLabel("""
            Planned Features:
            • HTTP request/response interception
            • Request modification and replay
            • Traffic analysis and filtering
            • Custom header injection
            • SSL/TLS certificate handling
            """)
            details_label.setStyleSheet("color: #DCDCDC; padding: 20px;")
            layout.addWidget(details_label)