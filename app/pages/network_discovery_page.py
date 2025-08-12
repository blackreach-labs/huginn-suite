from PyQt6.QtWidgets import QVBoxLayout, QTabWidget

from app.pages.components.base_page import BasePage
from app.components.cloud_discovery_component import CloudDiscoveryComponent
from app.components.network_sweep_component import NetworkSweepComponent
from shared.events.event_bus import EventBus

class NetworkDiscoveryPage(BasePage):
    def __init__(self, parent=None):
        super().__init__(parent)


    def setup_ui(self):
        """Setup the UI - required by BasePage"""
        try:
            self.setup_page()
        except Exception:
            pass
        try:
            self.connect_events()
        except Exception:
            pass

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
        
        # Event bus
        EventBus.instance().scan_started.connect(self.on_scan_started)
        EventBus.instance().scan_completed.connect(self.on_scan_completed)

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