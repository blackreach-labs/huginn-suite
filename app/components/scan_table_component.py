import time
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, 
                            QTableWidgetItem, QHeaderView, QProgressBar, QPushButton)
from PyQt6.QtCore import pyqtSignal, Qt

class ScanTableComponent(QWidget):
    scan_selected = pyqtSignal(str)
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
        
        # Create table
        self.scans_table = QTableWidget()
        self.setup_table()
        layout.addWidget(self.scans_table)

    def setup_table(self):
        """Setup scans table"""
        headers = ["Scan Type", "Target", "Status", "Progress", "Duration", "Details", "Actions"]
        self.scans_table.setColumnCount(len(headers))
        self.scans_table.setHorizontalHeaderLabels(headers)
        
        # Configure columns
        header = self.scans_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Fixed)
        
        self.scans_table.setColumnWidth(3, 120)  # Progress
        self.scans_table.setColumnWidth(6, 150)  # Actions
        
        # Connect selection
        self.scans_table.itemSelectionChanged.connect(self.on_selection_changed)

    def update_scans(self, scans):
        """Update table with scan data"""
        self.current_scans = scans
        self.scans_table.setRowCount(len(scans))
        
        for row, (scan_id, scan_item) in enumerate(scans.items()):
            # Scan Type
            self.scans_table.setItem(row, 0, QTableWidgetItem(scan_item.scan_type))
            
            # Target
            self.scans_table.setItem(row, 1, QTableWidgetItem(scan_item.target))
            
            # Status
            status_item = QTableWidgetItem(scan_item.status)
            if scan_item.status == "Running":
                status_item.setForeground(Qt.GlobalColor.green)
            elif scan_item.status == "Paused":
                status_item.setForeground(Qt.GlobalColor.yellow)
            elif scan_item.status == "Cancelled":
                status_item.setForeground(Qt.GlobalColor.red)
            else:
                status_item.setForeground(Qt.GlobalColor.gray)
            self.scans_table.setItem(row, 2, status_item)
            
            # Progress
            progress_widget = self.scans_table.cellWidget(row, 3)
            if not progress_widget:
                progress_widget = QProgressBar()
                self.scans_table.setCellWidget(row, 3, progress_widget)
            
            if scan_item.total_items > 0:
                progress = int((scan_item.completed_items / scan_item.total_items) * 100)
                progress_widget.setValue(progress)
                progress_widget.setFormat(f"{progress}% ({scan_item.completed_items}/{scan_item.total_items})")
            else:
                progress_widget.setRange(0, 0)
                progress_widget.setFormat("Running...")
            
            # Duration
            duration = time.time() - scan_item.start_time
            duration_str = self.format_duration(duration)
            self.scans_table.setItem(row, 4, QTableWidgetItem(duration_str))
            
            # Details
            self.scans_table.setItem(row, 5, QTableWidgetItem(scan_item.details))
            
            # Actions
            actions_widget = self.create_actions_widget(scan_id, scan_item.status)
            self.scans_table.setCellWidget(row, 6, actions_widget)

    def create_actions_widget(self, scan_id, status):
        """Create actions widget for scan"""
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(2, 2, 2, 2)
        
        if status == "Running":
            pause_btn = QPushButton("Pause")
            pause_btn.clicked.connect(lambda: self.scan_paused.emit(scan_id))
            layout.addWidget(pause_btn)
        elif status == "Paused":
            resume_btn = QPushButton("Resume")
            resume_btn.clicked.connect(lambda: self.scan_resumed.emit(scan_id))
            layout.addWidget(resume_btn)
        
        stop_btn = QPushButton("Stop")
        stop_btn.clicked.connect(lambda: self.scan_stopped.emit(scan_id))
        layout.addWidget(stop_btn)
        
        return widget

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

    def apply_theme(self):
        """Apply component theme"""
        self.setStyleSheet("""
            QTableWidget {
                background-color: rgba(20, 30, 40, 200);
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 8px;
                gridline-color: rgba(100, 200, 255, 50);
                selection-background-color: rgba(100, 200, 255, 100);
            }
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid rgba(100, 200, 255, 30);
            }
            QHeaderView::section {
                background-color: rgba(100, 200, 255, 150);
                color: #000000;
                padding: 8px;
                border: none;
                font-weight: bold;
            }
            QPushButton {
                background-color: rgba(100, 200, 255, 150);
                color: #000000;
                border: none;
                border-radius: 6px;
                padding: 4px 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(100, 200, 255, 200);
            }
            QProgressBar {
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 4px;
                text-align: center;
                background-color: rgba(50, 50, 50, 150);
            }
            QProgressBar::chunk {
                background-color: rgba(100, 200, 255, 200);
                border-radius: 3px;
            }
        """)