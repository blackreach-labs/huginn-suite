from PyQt6.QtWidgets import QVBoxLayout, QTabWidget

from app.pages.components.base_page import BasePage
from app.components.cloud_discovery_component import CloudDiscoveryComponent
from app.components.network_sweep_component import NetworkSweepComponent
from app.core.logger import logger

class NetworkDiscoveryPage(BasePage):
    def __init__(self, parent=None):
        super().__init__(parent)


    def setup_ui(self):
        """Setup the UI - required by BasePage"""
        try:
            self.setup_page()
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        try:
            self.connect_events()
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)

    def setup_page(self):
        """Setup page layout and components"""
        # Create tab widget
        self.tab_widget = QTabWidget()
        
        # Cloud discovery tab
        self.cloud_component = CloudDiscoveryComponent(self)
        self.tab_widget.addTab(self.cloud_component, "Cloud Asset Discovery")
        
        # Network sweep tab
        self.network_component = NetworkSweepComponent(self)
        self.tab_widget.addTab(self.network_component, "Network Sweep")
        
        self.content_layout.addWidget(self.tab_widget)

    def connect_events(self):
        """Connect component events"""
        # Cloud discovery events
        self.cloud_component.discovery_started.connect(self.on_discovery_started)
        self.cloud_component.discovery_completed.connect(self.on_discovery_completed)
        
        # Network sweep events
        self.network_component.sweep_started.connect(self.on_sweep_started)
        self.network_component.sweep_completed.connect(self.on_sweep_completed)
        
        # Event bus — subscribe using the callback API
        try:
            from shared.events.event_bus import get_event_bus
            bus = get_event_bus()
            bus.subscribe("scan_started", lambda e: self.on_scan_started(
                getattr(e, 'scan_id', ''), getattr(e, 'scanner_type', '')
            ))
            bus.subscribe("scan_completed", lambda e: self.on_scan_completed(
                getattr(e, 'scan_id', ''), getattr(e, 'results', {})
            ))
        except Exception as _exc:
            from app.core.logger import logger
            logger.debug("EventBus subscription skipped", exc_info=True)

    def on_discovery_started(self, target):
        """Handle cloud discovery started"""
        self.show_status(f"Starting cloud asset discovery for {target}", "info")

    def on_discovery_completed(self, results):
        """Handle cloud discovery completed"""
        self.show_status("Cloud asset discovery completed", "success")

    def on_sweep_started(self, target):
        """Handle network sweep started"""
        self.show_status(f"Starting network sweep for {target}", "info")

    def on_sweep_completed(self, results):
        """Handle network sweep completed"""
        self.show_status("Network sweep completed", "success")

    def on_scan_started(self, scan_id, scan_type):
        """Handle scan started event"""
        if scan_type in ["cloud_discovery", "network_sweep"]:
            self.show_status(f"{scan_type} scan {scan_id} started", "info")

    def on_scan_completed(self, scan_id, results):
        """Handle scan completed event"""
        self.show_status(f"Scan {scan_id} completed", "success")