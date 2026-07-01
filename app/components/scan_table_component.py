import time
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget,
                            QTableWidgetItem, QHeaderView, QProgressBar, QPushButton,
                            QLabel, QFrame)
from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtGui import QFont, QColor


class ScanTableComponent(QWidget):
    scan_selected = pyqtSignal(str)
    scan_double_clicked = pyqtSignal(str)
    scan_paused = pyqtSignal(str)
    scan_resumed = pyqtSignal(str)
    scan_stopped = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_scans = {}
        self.setup_ui()
        self.apply_theme()

    def setup_ui(self):
        """Setup table UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Table container frame
        self.table_frame = QFrame()
        self.table_frame.setObjectName("scanTableFrame")
        frame_layout = QVBoxLayout(self.table_frame)
        frame_layout.setContentsMargins(0, 0, 0, 0)
        frame_layout.setSpacing(0)

        # Empty state label (shown when no scans)
        self.empty_label = QLabel("No scans running")
        self.empty_label.setFont(QFont("Neuropol X", 11))
        self.empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_label.setStyleSheet("""
            color: rgba(200, 200, 200, 120);
            padding: 40px;
            background: transparent;
            border: none;
        """)
        frame_layout.addWidget(self.empty_label)

        # Create table
        self.scans_table = QTableWidget()
        self.scans_table.setFont(QFont("Neuropol X", 9))
        self.scans_table.verticalHeader().setVisible(False)
        self.scans_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.scans_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.scans_table.setShowGrid(False)
        self.scans_table.setAlternatingRowColors(True)
        self.setup_table()
        frame_layout.addWidget(self.scans_table)

        layout.addWidget(self.table_frame)

    def setup_table(self):
        """Setup scans table"""
        headers = ["Scan Type", "Target", "Status", "Progress", "Duration", "Details", "Actions"]
        self.scans_table.setColumnCount(len(headers))
        self.scans_table.setHorizontalHeaderLabels(headers)

        # Configure header font
        header = self.scans_table.horizontalHeader()
        header.setFont(QFont("Neuropol X", 9, QFont.Weight.Bold))
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        header.setMinimumSectionSize(60)

        # Column sizing
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Fixed)

        self.scans_table.setColumnWidth(2, 120)  # Status
        self.scans_table.setColumnWidth(3, 160)  # Progress
        self.scans_table.setColumnWidth(4, 80)   # Duration
        self.scans_table.setColumnWidth(6, 140)  # Actions

        # Row height
        self.scans_table.verticalHeader().setDefaultSectionSize(38)

        # Connect selection
        self.scans_table.itemSelectionChanged.connect(self.on_selection_changed)
        self.scans_table.cellDoubleClicked.connect(self.on_cell_double_clicked)

    def update_scans(self, scans):
        """Update table with scan data, minimizing widget recreation to prevent flicker"""
        self.current_scans = scans

        # Toggle empty state
        has_scans = len(scans) > 0
        self.empty_label.setVisible(not has_scans)
        self.scans_table.setVisible(has_scans)

        if not has_scans:
            self.scans_table.setRowCount(0)
            self._row_status_cache = {}
            return

        # Build ordered list of scan IDs
        scan_ids = list(scans.keys())

        # Only adjust row count if needed
        if self.scans_table.rowCount() != len(scan_ids):
            self.scans_table.setRowCount(len(scan_ids))

        # Initialize status cache if missing
        if not hasattr(self, '_row_status_cache'):
            self._row_status_cache = {}

        for row, scan_id in enumerate(scan_ids):
            scan_item = scans[scan_id]

            # Scan Type — only set if cell is empty or changed
            existing = self.scans_table.item(row, 0)
            if not existing or existing.text() != scan_item.scan_type:
                type_item = QTableWidgetItem(scan_item.scan_type)
                type_item.setFont(QFont("Neuropol X", 9, QFont.Weight.Bold))
                type_item.setForeground(QColor("#64C8FF"))
                self.scans_table.setItem(row, 0, type_item)

            # Target
            existing = self.scans_table.item(row, 1)
            if not existing or existing.text() != scan_item.target:
                target_item = QTableWidgetItem(scan_item.target)
                target_item.setFont(QFont("Neuropol X", 9))
                target_item.setForeground(QColor("#E0E0E0"))
                self.scans_table.setItem(row, 1, target_item)

            # Status
            existing = self.scans_table.item(row, 2)
            if not existing or existing.text() != scan_item.status:
                status_item = QTableWidgetItem(scan_item.status)
                status_item.setFont(QFont("Neuropol X", 9, QFont.Weight.Bold))
                if scan_item.status == "Running":
                    status_item.setForeground(QColor("#00FF41"))
                elif scan_item.status == "Paused":
                    status_item.setForeground(QColor("#FFD700"))
                elif scan_item.status == "Completed":
                    status_item.setForeground(QColor("#64C8FF"))
                elif scan_item.status in ("Stopped", "Failed", "Cancelled"):
                    status_item.setForeground(QColor("#FF5252"))
                else:
                    status_item.setForeground(QColor("#808080"))
                self.scans_table.setItem(row, 2, status_item)

            # Progress bar — reuse existing widget
            progress_widget = self.scans_table.cellWidget(row, 3)
            if not isinstance(progress_widget, QProgressBar):
                progress_widget = QProgressBar()
                progress_widget.setFixedHeight(18)
                progress_widget.setFont(QFont("Neuropol X", 8))
                self.scans_table.setCellWidget(row, 3, progress_widget)

            if scan_item.status == "Completed":
                progress_widget.setRange(0, 100)
                progress_widget.setValue(100)
                progress_widget.setFormat("Complete")
            elif scan_item.total_items > 0:
                progress = int((scan_item.completed_items / scan_item.total_items) * 100)
                progress_widget.setRange(0, 100)
                progress_widget.setValue(progress)
                progress_widget.setFormat(f"{progress}% ({scan_item.completed_items}/{scan_item.total_items})")
            else:
                progress_widget.setRange(0, 0)  # Indeterminate
                progress_widget.setFormat("Running...")

            # Duration — update text in place
            if scan_item.end_time:
                duration = scan_item.end_time - scan_item.start_time
            else:
                duration = time.time() - scan_item.start_time
            duration_text = self.format_duration(duration)
            existing = self.scans_table.item(row, 4)
            if not existing:
                duration_item = QTableWidgetItem(duration_text)
                duration_item.setFont(QFont("Neuropol X", 9))
                duration_item.setForeground(QColor("#B0B0B0"))
                self.scans_table.setItem(row, 4, duration_item)
            else:
                existing.setText(duration_text)

            # Details
            existing = self.scans_table.item(row, 5)
            if not existing or existing.text() != scan_item.details:
                details_item = QTableWidgetItem(scan_item.details)
                details_item.setFont(QFont("Neuropol X", 8))
                details_item.setForeground(QColor("#A0A0A0"))
                self.scans_table.setItem(row, 5, details_item)

            # Actions — only recreate when status changes for this row
            cached_status = self._row_status_cache.get(row)
            if cached_status != scan_item.status:
                actions_widget = self.create_actions_widget(scan_id, scan_item.status)
                self.scans_table.setCellWidget(row, 6, actions_widget)
                self._row_status_cache[row] = scan_item.status

    def create_actions_widget(self, scan_id, status):
        """Create actions widget for scan row"""
        widget = QWidget()
        widget.setStyleSheet("background: transparent; border: none;")
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        if status == "Running":
            pause_btn = self._create_icon_action_button("\u23F8", "#FFD700", "Pause scan")
            pause_btn.clicked.connect(lambda: self.scan_paused.emit(scan_id))
            layout.addWidget(pause_btn)

            stop_btn = self._create_icon_action_button("\u23F9", "#FF5252", "Stop scan")
            stop_btn.clicked.connect(lambda: self.scan_stopped.emit(scan_id))
            layout.addWidget(stop_btn)

        elif status == "Paused":
            resume_btn = self._create_icon_action_button("\u25B6", "#4CAF50", "Resume scan")
            resume_btn.clicked.connect(lambda: self.scan_resumed.emit(scan_id))
            layout.addWidget(resume_btn)

            stop_btn = self._create_icon_action_button("\u23F9", "#FF5252", "Stop scan")
            stop_btn.clicked.connect(lambda: self.scan_stopped.emit(scan_id))
            layout.addWidget(stop_btn)

        else:
            # Completed/Stopped/Failed - no actions
            spacer_label = QLabel("")
            spacer_label.setStyleSheet("background: transparent; border: none;")
            layout.addWidget(spacer_label)

        return widget

    def _create_icon_action_button(self, icon_char, color, tooltip):
        """Create a small icon-based action button"""
        btn = QPushButton(icon_char)
        btn.setToolTip(tooltip)
        btn.setFont(QFont("Segoe UI Symbol", 9))
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setFixedSize(22, 22)
        btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {color};
                color: #000000;
                border: none;
                border-radius: 11px;
                padding: 0px;
            }}
            QPushButton:hover {{
                border: 1px solid rgba(255, 255, 255, 120);
            }}
            QPushButton:pressed {{
                background-color: {color};
                border: 1px solid rgba(255, 255, 255, 200);
            }}
        """)
        return btn

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

    def on_selection_changed(self):
        """Handle table selection change"""
        current_row = self.scans_table.currentRow()
        if current_row >= 0:
            scan_items = list(self.current_scans.keys())
            if current_row < len(scan_items):
                scan_id = scan_items[current_row]
                self.scan_selected.emit(scan_id)

    def on_cell_double_clicked(self, row, column):
        """Handle double-click on a scan row to navigate to its source page"""
        scan_items = list(self.current_scans.keys())
        if 0 <= row < len(scan_items):
            scan_id = scan_items[row]
            self.scan_double_clicked.emit(scan_id)

    def apply_theme(self):
        """Apply component theme"""
        self.setStyleSheet("""
            QFrame#scanTableFrame {
                background-color: rgba(15, 20, 30, 200);
                border: 1px solid rgba(100, 200, 255, 60);
                border-radius: 10px;
            }
            QTableWidget {
                background-color: transparent;
                border: none;
                gridline-color: transparent;
                selection-background-color: rgba(100, 200, 255, 60);
                alternate-background-color: rgba(40, 50, 70, 80);
                outline: none;
            }
            QTableWidget::item {
                padding: 6px 10px;
                border: none;
                border-bottom: 1px solid rgba(100, 200, 255, 20);
            }
            QTableWidget::item:selected {
                background-color: rgba(100, 200, 255, 80);
            }
            QHeaderView::section {
                background-color: rgba(30, 50, 80, 220);
                color: #64C8FF;
                padding: 8px 10px;
                border: none;
                border-bottom: 2px solid rgba(100, 200, 255, 100);
                font-family: 'Neuropol X';
            }
            QProgressBar {
                border: 1px solid rgba(100, 200, 255, 80);
                border-radius: 4px;
                text-align: center;
                background-color: rgba(30, 40, 60, 200);
                color: #E0E0E0;
                font-family: 'Neuropol X';
                font-size: 8pt;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(0, 200, 100, 200),
                    stop:1 rgba(100, 200, 255, 200));
                border-radius: 3px;
            }
        """)
