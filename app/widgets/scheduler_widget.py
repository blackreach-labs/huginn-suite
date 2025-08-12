# app/widgets/scheduler_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QPushButton, QLineEdit, QSpinBox, QComboBox, 
                            QDateTimeEdit, QTableWidget, QTableWidgetItem, QGroupBox)
from PyQt6.QtCore import Qt, QDateTime, QTimer, pyqtSignal
from datetime import datetime, timedelta
from app.core.scheduler import scan_scheduler

class SchedulerWidget(QWidget):
    """Widget for managing scan schedules"""
    
    scan_scheduled = pyqtSignal(str)  # Signal when scan is scheduled
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.setup_timer()
        self.refresh_schedule_table()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Schedule creation group
        create_group = QGroupBox("⏰ Schedule New Scan")
        create_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                color: #64C8FF;
                border: 2px solid #555;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)
        
        create_layout = QVBoxLayout(create_group)
        
        # Target and scan type
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target:"))
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("example.com or 192.168.1.1")
        self.target_input.setStyleSheet(self._get_input_style())
        
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(["DNS Enum", "Port Scan", "HTTP Enum", "API Enum"])
        self.scan_type_combo.setFixedWidth(120)
        
        target_layout.addWidget(self.target_input)
        target_layout.addWidget(QLabel("Type:"))
        target_layout.addWidget(self.scan_type_combo)
        
        # Schedule time
        time_layout = QHBoxLayout()
        time_layout.addWidget(QLabel("Schedule Time:"))
        
        self.datetime_edit = QDateTimeEdit()
        self.datetime_edit.setDateTime(QDateTime.currentDateTime().addSecs(3600))  # 1 hour from now
        self.datetime_edit.setDisplayFormat("yyyy-MM-dd hh:mm")
        self.datetime_edit.setFixedWidth(150)
        
        # Quick time buttons
        quick_buttons = [
            ("1h", 1),
            ("6h", 6),
            ("24h", 24),
            ("7d", 168)
        ]
        
        for text, hours in quick_buttons:
            btn = QPushButton(text)
            btn.setFixedWidth(40)
            btn.clicked.connect(lambda checked, h=hours: self.set_quick_time(h))
            btn.setStyleSheet("""
                QPushButton {
                    background-color: rgba(100, 200, 255, 100);
                    color: white;
                    border: none;
                    border-radius: 3px;
                    padding: 4px;
                    font-size: 9pt;
                }
                QPushButton:hover {
                    background-color: rgba(100, 200, 255, 150);
                }
            """)
            time_layout.addWidget(btn)
        
        time_layout.addWidget(self.datetime_edit)
        time_layout.addStretch()
        
        # Repeat options
        repeat_layout = QHBoxLayout()
        repeat_layout.addWidget(QLabel("Repeat every:"))
        
        self.repeat_spinbox = QSpinBox()
        self.repeat_spinbox.setRange(0, 168)  # 0 to 168 hours (1 week)
        self.repeat_spinbox.setValue(0)
        self.repeat_spinbox.setSuffix(" hours")
        self.repeat_spinbox.setSpecialValueText("No repeat")
        self.repeat_spinbox.setFixedWidth(120)
        
        repeat_layout.addWidget(self.repeat_spinbox)
        repeat_layout.addStretch()
        
        # Schedule button
        self.schedule_button = QPushButton("📅 Schedule Scan")
        self.schedule_button.clicked.connect(self.schedule_scan)
        self.schedule_button.setStyleSheet("""
            QPushButton {
                background-color: rgba(100, 255, 100, 150);
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 16px;
                font-size: 11pt;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(100, 255, 100, 200);
            }
        """)
        
        create_layout.addLayout(target_layout)
        create_layout.addLayout(time_layout)
        create_layout.addLayout(repeat_layout)
        create_layout.addWidget(self.schedule_button)
        
        # Scheduled scans table
        table_group = QGroupBox("📋 Scheduled Scans")
        table_group.setStyleSheet(create_group.styleSheet())
        
        table_layout = QVBoxLayout(table_group)
        
        self.schedule_table = QTableWidget()
        self.schedule_table.setColumnCount(6)
        self.schedule_table.setHorizontalHeaderLabels([
            "Target", "Type", "Scheduled Time", "Time Until", "Repeat", "Status"
        ])
        self.schedule_table.setFixedHeight(200)
        self.schedule_table.setStyleSheet("""
            QTableWidget {
                background-color: rgba(0, 0, 0, 150);
                border: 1px solid #555;
                border-radius: 4px;
                color: #DCDCDC;
                font-size: 10pt;
            }
            QHeaderView::section {
                background-color: rgba(100, 200, 255, 150);
                color: white;
                padding: 4px;
                border: none;
                font-weight: bold;
            }
        """)
        
        # Table controls
        table_controls = QHBoxLayout()
        
        self.refresh_button = QPushButton("🔄 Refresh")
        self.refresh_button.clicked.connect(self.refresh_schedule_table)
        
        self.cancel_button = QPushButton("❌ Cancel Selected")
        self.cancel_button.clicked.connect(self.cancel_selected_scan)
        
        button_style = """
            QPushButton {
                background-color: rgba(100, 200, 255, 150);
                color: white;
                border: none;
                border-radius: 4px;
                padding: 6px 12px;
                font-size: 10pt;
            }
            QPushButton:hover {
                background-color: rgba(100, 200, 255, 200);
            }
        """
        
        self.refresh_button.setStyleSheet(button_style)
        self.cancel_button.setStyleSheet(button_style.replace("100, 200, 255", "255, 100, 100"))
        
        table_controls.addWidget(self.refresh_button)
        table_controls.addWidget(self.cancel_button)
        table_controls.addStretch()
        
        table_layout.addWidget(self.schedule_table)
        table_layout.addLayout(table_controls)
        
        # Status label
        self.status_label = QLabel("Ready to schedule scans")
        self.status_label.setStyleSheet("color: #888; font-size: 10pt; padding: 5px;")
        
        layout.addWidget(create_group)
        layout.addWidget(table_group)
        layout.addWidget(self.status_label)
        
    def _get_input_style(self):
        return """
            QLineEdit {
                background-color: rgba(20, 30, 40, 180);
                border: 1px solid #555;
                border-radius: 4px;
                color: #DCDCDC;
                padding: 4px 8px;
                font-size: 10pt;
            }
            QLineEdit:focus {
                border: 2px solid #64C8FF;
            }
        """
    
    def setup_timer(self):
        """Setup timer to refresh table periodically"""
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_schedule_table)
        self.refresh_timer.start(30000)  # Refresh every 30 seconds
    
    def set_quick_time(self, hours):
        """Set quick time offset"""
        future_time = QDateTime.currentDateTime().addSecs(hours * 3600)
        self.datetime_edit.setDateTime(future_time)
    
    def schedule_scan(self):
        """Schedule a new scan"""
        target = self.target_input.text().strip()
        if not target:
            self.status_label.setText("❌ Please enter a target")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
            return
        
        scan_type = self.scan_type_combo.currentText().lower().replace(" ", "_")
        schedule_time = self.datetime_edit.dateTime().toPython()
        repeat_interval = self.repeat_spinbox.value()
        
        # Generate unique scan ID
        scan_id = f"{target}_{scan_type}_{int(schedule_time.timestamp())}"
        
        if scan_scheduler.schedule_scan(scan_id, target, scan_type, schedule_time, None, repeat_interval):
            self.status_label.setText(f"✅ Scheduled: {target} at {schedule_time.strftime('%Y-%m-%d %H:%M')}")
            self.status_label.setStyleSheet("color: #00AA00; font-size: 10pt; padding: 5px;")
            
            self.target_input.clear()
            self.refresh_schedule_table()
            self.scan_scheduled.emit(scan_id)
        else:
            self.status_label.setText("❌ Failed to schedule scan")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
    
    def refresh_schedule_table(self):
        """Refresh the scheduled scans table"""
        scheduled_scans = scan_scheduler.get_scheduled_scans()
        
        self.schedule_table.setRowCount(len(scheduled_scans))
        
        for row, scan in enumerate(scheduled_scans):
            self.schedule_table.setItem(row, 0, QTableWidgetItem(scan['target']))
            self.schedule_table.setItem(row, 1, QTableWidgetItem(scan['scan_type'].replace('_', ' ').title()))
            
            schedule_time = datetime.fromisoformat(scan['schedule_time'])
            self.schedule_table.setItem(row, 2, QTableWidgetItem(schedule_time.strftime('%Y-%m-%d %H:%M')))
            self.schedule_table.setItem(row, 3, QTableWidgetItem(scan['time_until']))
            
            repeat_text = f"{scan['repeat_interval']}h" if scan['repeat_interval'] > 0 else "Once"
            self.schedule_table.setItem(row, 4, QTableWidgetItem(repeat_text))
            
            status_item = QTableWidgetItem(scan['status'].title())
            if scan['status'] == 'scheduled':
                status_item.setForeground(Qt.GlobalColor.yellow)
            elif scan['status'] == 'running':
                status_item.setForeground(Qt.GlobalColor.blue)
            elif scan['status'] == 'completed':
                status_item.setForeground(Qt.GlobalColor.green)
            else:
                status_item.setForeground(Qt.GlobalColor.red)
            
            self.schedule_table.setItem(row, 5, status_item)
        
        self.schedule_table.resizeColumnsToContents()
    
    def cancel_selected_scan(self):
        """Cancel the selected scheduled scan"""
        current_row = self.schedule_table.currentRow()
        if current_row < 0:
            self.status_label.setText("❌ Please select a scan to cancel")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
            return
        
        scheduled_scans = scan_scheduler.get_scheduled_scans()
        if current_row < len(scheduled_scans):
            scan_id = scheduled_scans[current_row]['scan_id']
            
            if scan_scheduler.cancel_scan(scan_id):
                self.status_label.setText("🗑️ Scan cancelled")
                self.status_label.setStyleSheet("color: #FFAA00; font-size: 10pt; padding: 5px;")
                self.refresh_schedule_table()
            else:
                self.status_label.setText("❌ Failed to cancel scan")
                self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")