# app/pages/http_interceptor_page.py
from PyQt6.QtWidgets import QVBoxLayout
from PyQt6.QtCore import pyqtSignal

from app.pages.components.base_page import BasePage
from app.core.logger import logger


class HttpInterceptorPage(BasePage):
    """Standalone HTTP Interceptor page accessible from Tools menu."""

    def __init__(self, parent=None):
        super().__init__(parent)

    def setup_ui(self):
        """Setup the UI - required by BasePage."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        try:
            from app.widgets.curl_widget import CurlWidget
            self.curl_widget = CurlWidget()
            layout.addWidget(self.curl_widget)
        except Exception as e:
            from PyQt6.QtWidgets import QLabel
            logger.error(f"Failed to load HTTP Interceptor: {e}")
            fallback = QLabel("HTTP Interceptor could not be loaded.\nEnsure mitmproxy is installed: pip install mitmproxy")
            fallback.setWordWrap(True)
            layout.addWidget(fallback)

    def get_page_title(self):
        return "HTTP Interceptor"
