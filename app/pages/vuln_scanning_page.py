from PyQt6.QtWidgets import QVBoxLayout, QHBoxLayout, QTabWidget, QWidget
from PyQt6.QtCore import pyqtSignal

from app.pages.components.base_page import BasePage
from app.components.vuln_scanner_component import VulnScannerComponent
from app.components.web_scanner_component import WebScannerComponent
from app.components.ssh_vuln_scanner_component import SSHVulnScannerComponent
from shared.events import get_event_bus
# from application.services.vulnerability_service import VulnerabilityService

class VulnScanningPage(BasePage):
    def __init__(self, parent=None):
        super().__init__(parent)
        # self.vulnerability_service = VulnerabilityService()
    
    def setup_ui(self):
        """Setup the UI - required by BasePage"""
        self.setup_page()
        self.connect_events()

    def setup_page(self):
        """Setup page layout and components"""
        # Create main layout
        layout = QVBoxLayout(self)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        
        # Vulnerability Scanner tab
        try:
            self.vuln_scanner = VulnScannerComponent(self)
            self.tab_widget.addTab(self.vuln_scanner, "Vulnerability Scanner")
        except Exception:
            pass
        
        # Web Application Scanner tab
        try:
            self.web_scanner = WebScannerComponent(self)
            self.tab_widget.addTab(self.web_scanner, "Web Application Scanner")
        except Exception:
            pass
        
        # SSH Vulnerability Scanner tab
        try:
            self.ssh_vuln_scanner = SSHVulnScannerComponent(self)
            self.tab_widget.addTab(self.ssh_vuln_scanner, "SSH Vulnerability Scanner")
        except Exception as e:
            print(f"Failed to load SSH vulnerability scanner: {e}")
        
        # Huggin Advanced Scanner tab
        try:
            from app.components.huggin_scanner_component import HugginScannerComponent
            self.huggin_scanner = HugginScannerComponent(self)
            self.tab_widget.addTab(self.huggin_scanner, "🚀 Huggin Advanced Scanner")
        except Exception as e:
            print(f"Failed to load Huggin scanner: {e}")
        
        layout.addWidget(self.tab_widget)

    def connect_events(self):
        """Connect event bus signals"""
        event_bus = get_event_bus()
        event_bus.subscribe('scan_started', self.on_scan_started)
        event_bus.subscribe('scan_completed', self.on_scan_completed)
        event_bus.subscribe('scan_error', self.on_scan_error)

    def on_scan_started(self, scan_id: str, scan_type: str):
        """Handle scan started event"""
        if scan_type in ['vulnerability', 'web_vulnerability']:
            self.show_status(f"Scan {scan_id} started", "info")

    def on_scan_completed(self, scan_id: str, results: dict):
        """Handle scan completed event"""
        self.show_status(f"Scan {scan_id} completed", "success")

    def on_scan_error(self, scan_id: str, error: str):
        """Handle scan error event"""
        self.show_status(f"Scan {scan_id} failed: {error}", "error")