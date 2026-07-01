from PyQt6.QtWidgets import (QVBoxLayout, QHBoxLayout, QPushButton, QSplitter,
                             QLabel, QFrame, QWidget)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont

from app.pages.components.base_page import BasePage
from app.components.scan_table_component import ScanTableComponent
from app.components.scan_details_component import ScanDetailsComponent
from app.core.scan_registry import scan_registry
from app.core.logger import logger


class RunningScansPage(BasePage):
    def __init__(self, parent=None):
        super().__init__(parent)

    def setup_ui(self):
        """Setup the UI - required by BasePage"""
        try:
            self.setup_page()
        except Exception as _exc:
            logger.debug("Suppressed exception", exc_info=True)
        try:
            self.connect_events()
        except Exception as _exc:
            logger.debug("Suppressed exception", exc_info=True)
        try:
            self.setup_timer()
        except Exception as _exc:
            logger.debug("Suppressed exception", exc_info=True)

    def setup_page(self):
        """Setup page layout and components"""
        self.content_layout = QVBoxLayout(self)
        self.content_layout.setContentsMargins(16, 16, 16, 16)
        self.content_layout.setSpacing(12)

        # --- Header section ---
        header_frame = QFrame()
        header_frame.setObjectName("scanPageHeader")
        header_frame.setStyleSheet("""
            QFrame#scanPageHeader {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(20, 30, 50, 220),
                    stop:1 rgba(30, 50, 80, 220));
                border: 1px solid rgba(100, 200, 255, 80);
                border-radius: 10px;
                padding: 12px;
            }
        """)
        header_layout = QHBoxLayout(header_frame)
        header_layout.setContentsMargins(16, 12, 16, 12)

        # Title and subtitle
        title_section = QVBoxLayout()
        title_section.setSpacing(2)

        self.page_title = QLabel("Running Scans")
        self.page_title.setFont(QFont("Neuropol X", 16, QFont.Weight.Bold))
        self.page_title.setStyleSheet("color: #64C8FF; background: transparent; border: none;")
        title_section.addWidget(self.page_title)

        self.page_subtitle = QLabel("Monitor and control active scan operations")
        self.page_subtitle.setFont(QFont("Neuropol X", 9))
        self.page_subtitle.setStyleSheet("color: rgba(220, 220, 220, 180); background: transparent; border: none;")
        title_section.addWidget(self.page_subtitle)

        header_layout.addLayout(title_section)
        header_layout.addStretch()

        # Stats indicators
        stats_widget = QWidget()
        stats_widget.setStyleSheet("background: transparent; border: none;")
        stats_layout = QHBoxLayout(stats_widget)
        stats_layout.setContentsMargins(0, 0, 0, 0)
        stats_layout.setSpacing(20)

        self.active_count_label = self._create_stat_label("0", "Active")
        self.completed_count_label = self._create_stat_label("0", "Completed")
        self.total_count_label = self._create_stat_label("0", "Total")

        stats_layout.addWidget(self.active_count_label)
        stats_layout.addWidget(self.completed_count_label)
        stats_layout.addWidget(self.total_count_label)

        header_layout.addWidget(stats_widget)
        self.content_layout.addWidget(header_frame)

        # --- Control buttons ---
        controls_frame = QFrame()
        controls_frame.setObjectName("scanControls")
        controls_frame.setStyleSheet("""
            QFrame#scanControls {
                background: transparent;
                border: none;
            }
        """)
        control_layout = QHBoxLayout(controls_frame)
        control_layout.setContentsMargins(0, 0, 0, 0)
        control_layout.setSpacing(8)

        self.refresh_btn = self._create_control_button("Refresh", "#4CAF50")
        self.refresh_btn.clicked.connect(self.refresh_scans)

        self.stop_all_btn = self._create_control_button("Stop All", "#FF5252")
        self.stop_all_btn.clicked.connect(self.stop_all_scans)

        self.clear_btn = self._create_control_button("Clear Completed", "#FF9800")
        self.clear_btn.clicked.connect(self.clear_completed_scans)

        control_layout.addWidget(self.refresh_btn)
        control_layout.addWidget(self.stop_all_btn)
        control_layout.addWidget(self.clear_btn)
        control_layout.addStretch()

        self.content_layout.addWidget(controls_frame)

        # --- Main content splitter ---
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setHandleWidth(3)
        splitter.setStyleSheet("""
            QSplitter::handle {
                background: rgba(100, 200, 255, 60);
                border-radius: 1px;
            }
            QSplitter::handle:hover {
                background: rgba(100, 200, 255, 150);
            }
        """)

        # Scan table
        self.table_component = ScanTableComponent(self)
        splitter.addWidget(self.table_component)

        # Scan details
        self.details_component = ScanDetailsComponent(self)
        splitter.addWidget(self.details_component)

        splitter.setSizes([350, 350])
        self.content_layout.addWidget(splitter)

    def _create_stat_label(self, value, label):
        """Create a stat indicator widget"""
        widget = QWidget()
        widget.setStyleSheet("background: transparent; border: none;")
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(8, 4, 8, 4)
        layout.setSpacing(0)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        value_lbl = QLabel(value)
        value_lbl.setFont(QFont("Neuropol X", 18, QFont.Weight.Bold))
        value_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        value_lbl.setStyleSheet("color: #00FF41; background: transparent; border: none;")
        value_lbl.setObjectName("statValue")
        layout.addWidget(value_lbl)

        desc_lbl = QLabel(label)
        desc_lbl.setFont(QFont("Neuropol X", 8))
        desc_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc_lbl.setStyleSheet("color: rgba(200, 200, 200, 160); background: transparent; border: none;")
        layout.addWidget(desc_lbl)

        return widget

    def _create_control_button(self, text, color):
        """Create a styled control button"""
        btn = QPushButton(text)
        btn.setFont(QFont("Neuropol X", 9, QFont.Weight.Bold))
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setFixedHeight(32)
        btn.setMinimumWidth(100)
        btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {color};
                color: #FFFFFF;
                border: none;
                border-radius: 6px;
                padding: 4px 14px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {color};
                border: 1px solid rgba(255, 255, 255, 80);
            }}
            QPushButton:pressed {{
                background-color: {color};
                border: 1px solid rgba(255, 255, 255, 120);
            }}
        """)
        return btn

    def setup_timer(self):
        """Setup refresh timer"""
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_display)
        self.timer.start(1000)

    def connect_events(self):
        """Connect event signals"""
        # Table component events
        self.table_component.scan_selected.connect(self.on_scan_selected)
        self.table_component.scan_double_clicked.connect(self.navigate_to_scan_source)
        self.table_component.scan_paused.connect(self.pause_scan)
        self.table_component.scan_resumed.connect(self.resume_scan)
        self.table_component.scan_stopped.connect(self.stop_scan)

        # Scan registry events
        scan_registry.scan_started.connect(self.on_scan_started)
        scan_registry.scan_updated.connect(self.on_scan_updated)
        scan_registry.scan_finished.connect(self.on_scan_finished)

        # Event bus subscription
        try:
            from shared.events.event_bus import get_event_bus
            bus = get_event_bus()
            bus.subscribe("scan_started", lambda e: self.on_scan_started(
                getattr(e, 'scan_id', ''), getattr(e, 'scanner_type', '')
            ))
            bus.subscribe("scan_completed", lambda e: self.on_scan_finished(
                getattr(e, 'scan_id', ''), getattr(e, 'results', {})
            ))
        except Exception as _exc:
            logger.debug("EventBus subscription skipped", exc_info=True)

    def update_display(self):
        """Update display components"""
        all_scans = scan_registry.get_all_scans()
        active_scans = scan_registry.get_active_scans()
        self.table_component.update_scans(all_scans)

        # Update stat counters
        total = len(all_scans)
        active = len(active_scans)
        completed = total - active

        self._update_stat(self.active_count_label, str(active), "#00FF41" if active > 0 else "#808080")
        self._update_stat(self.completed_count_label, str(completed), "#64C8FF")
        self._update_stat(self.total_count_label, str(total), "#DCDCDC")

    def _update_stat(self, widget, value, color):
        """Update a stat widget's value and color"""
        value_label = widget.findChild(QLabel, "statValue")
        if value_label:
            value_label.setText(value)
            value_label.setStyleSheet(f"color: {color}; background: transparent; border: none;")

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

    def navigate_to_scan_source(self, scan_id):
        """Navigate to the page/tab where this scan is running."""
        scan_info = scan_registry.get_scan_info(scan_id)
        if not scan_info or not scan_info.source_page:
            return

        self.main_window.navigate_to(scan_info.source_page)

        try:
            from app.core.lazy_initialization import LazyPageManager
            page = self.main_window.page_manager.get_page(scan_info.source_page)
            if page is None:
                return

            if scan_info.source_tab is not None and hasattr(page, 'tab_widget'):
                page.tab_widget.setCurrentIndex(int(scan_info.source_tab))

            if scan_info.source_subtab is not None and hasattr(page, 'service_sub_tab_widget'):
                page.service_sub_tab_widget.setCurrentIndex(int(scan_info.source_subtab))
        except Exception as e:
            logger.debug(f"Navigation to scan source failed: {e}", exc_info=True)

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
