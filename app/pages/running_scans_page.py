from PyQt6.QtWidgets import QVBoxLayout, QHBoxLayout, QPushButton, QSplitter
from PyQt6.QtCore import Qt, QTimer

from app.pages.components.base_page import BasePage
from app.components.scan_table_component import ScanTableComponent
from app.components.scan_details_component import ScanDetailsComponent
from app.core.scan_registry import scan_registry
from shared.events.event_bus import EventBus

class RunningScansPage(BasePage):
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
        # Control buttons
        control_layout = QHBoxLayout()
        
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_scans)
        
        self.stop_all_btn = QPushButton("Stop All Scans")
        self.stop_all_btn.clicked.connect(self.stop_all_scans)
        
        self.clear_btn = QPushButton("Clear Completed")
        self.clear_btn.clicked.connect(self.clear_completed_scans)
        
        control_layout.addWidget(self.refresh_btn)
        control_layout.addWidget(self.stop_all_btn)
        control_layout.addWidget(self.clear_btn)
        control_layout.addStretch()
        
        self.content_layout.addLayout(control_layout)
        
        # Create splitter for table and details
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Scan table component
        self.table_component = ScanTableComponent(self)
        splitter.addWidget(self.table_component)
        
        # Scan details component
        self.details_component = ScanDetailsComponent(self)
        splitter.addWidget(self.details_component)
        
        splitter.setSizes([400, 200])
        self.content_layout.addWidget(splitter)

    def setup_timer(self):
        """Setup refresh timer"""
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_display)
        self.timer.start(1000)  # Update every second

    def connect_events(self):
        """Connect event signals"""
        # Table component events
        self.table_component.scan_selected.connect(self.on_scan_selected)
        self.table_component.scan_paused.connect(self.pause_scan)
        self.table_component.scan_resumed.connect(self.resume_scan)
        self.table_component.scan_stopped.connect(self.stop_scan)
        
        # Scan registry events
        scan_registry.scan_started.connect(self.on_scan_started)
        scan_registry.scan_updated.connect(self.on_scan_updated)
        scan_registry.scan_finished.connect(self.on_scan_finished)
        
        # Event bus
        EventBus.instance().scan_started.connect(self.on_scan_started)
        EventBus.instance().scan_completed.connect(self.on_scan_finished)

    def update_display(self):
        """Update display components"""
        all_scans = scan_registry.get_all_scans()
        self.table_component.update_scans(all_scans)

    def refresh_scans(self):
        """Refresh scan list"""
        all_scans = scan_registry.get_all_scans()
        active_scans = scan_registry.get_active_scans()
        self.update_display()
        self.show_status(f"Refreshed - {len(active_scans)} active scans, {len(all_scans)} total", "info")

    def stop_all_scans(self):
        """Stop all running scans"""
        stopped_count = scan_registry.stop_all_scans()
        self.show_status(f"Stopped {stopped_count} scans", "info")

    def clear_completed_scans(self):
        """Clear completed scans"""
        cleared_count = scan_registry.cleanup_finished_scans(max_age_seconds=60)
        self.update_display()
        self.show_status(f"Cleared {cleared_count} completed scans", "info")

    def pause_scan(self, scan_id):
        """Pause specific scan"""
        if scan_registry.pause_scan(scan_id):
            self.show_status(f"Paused scan: {scan_id}", "info")
        else:
            self.show_status(f"Failed to pause scan: {scan_id}", "error")

    def resume_scan(self, scan_id):
        """Resume paused scan"""
        if scan_registry.resume_scan(scan_id):
            self.show_status(f"Resumed scan: {scan_id}", "info")
        else:
            self.show_status(f"Failed to resume scan: {scan_id}", "error")

    def stop_scan(self, scan_id):
        """Stop specific scan"""
        if scan_registry.stop_scan(scan_id):
            self.show_status(f"Stopped scan: {scan_id}", "info")
        else:
            self.show_status(f"Failed to stop scan: {scan_id}", "error")

    def on_scan_selected(self, scan_id):
        """Handle scan selection"""
        all_scans = scan_registry.get_all_scans()
        if scan_id in all_scans:
            scan_item = all_scans[scan_id]
            self.details_component.update_scan_details(scan_item)

    def on_scan_started(self, scan_id, scan_type, target):
        """Handle scan started event"""
        self.update_display()
        self.show_status(f"Started: {scan_type} on {target}", "info")

    def on_scan_updated(self, scan_id, completed_items):
        """Handle scan progress update"""
        self.update_display()

    def on_scan_finished(self, scan_id, status):
        """Handle scan finished event"""
        self.update_display()
        self.show_status(f"Scan finished: {scan_id} - {status}", "info")