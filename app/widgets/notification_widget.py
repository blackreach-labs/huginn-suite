# app/widgets/notification_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QPushButton, QTextEdit, QTableWidget, 
                            QTableWidgetItem, QGroupBox, QCheckBox, QTabWidget)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QFont
from app.core.notification_manager import notification_manager
from datetime import datetime

class NotificationWidget(QWidget):
    """Widget for managing notifications and settings"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.refresh_notifications()
        
        # Auto-refresh timer
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_notifications)
        self.refresh_timer.start(5000)  # Refresh every 5 seconds
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Main group
        main_group = QGroupBox("🔔 Notifications & Alerts")
        main_group.setStyleSheet("""
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
        
        main_layout = QVBoxLayout(main_group)
        
        # Controls
        controls_layout = QHBoxLayout()
        
        self.mark_read_button = QPushButton("✅ Mark All Read")
        self.mark_read_button.clicked.connect(self.mark_all_read)
        
        self.clear_button = QPushButton("🗑️ Clear All")
        self.clear_button.clicked.connect(self.clear_notifications)
        
        self.test_button = QPushButton("🧪 Test Notification")
        self.test_button.clicked.connect(self.test_notification)
        
        self.refresh_button = QPushButton("🔄 Refresh")
        self.refresh_button.clicked.connect(self.refresh_notifications)
        
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
        
        self.mark_read_button.setStyleSheet(button_style.replace("100, 200, 255", "100, 255, 100"))
        self.clear_button.setStyleSheet(button_style.replace("100, 200, 255", "255, 100, 100"))
        self.test_button.setStyleSheet(button_style.replace("100, 200, 255", "255, 200, 100"))
        self.refresh_button.setStyleSheet(button_style)
        
        controls_layout.addWidget(self.mark_read_button)
        controls_layout.addWidget(self.clear_button)
        controls_layout.addWidget(self.test_button)
        controls_layout.addWidget(self.refresh_button)
        controls_layout.addStretch()
        
        # Results tabs
        self.results_tabs = QTabWidget()
        self.results_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #555;
                background-color: rgba(0, 0, 0, 100);
            }
            QTabBar::tab {
                background-color: rgba(50, 50, 50, 150);
                color: #DCDCDC;
                padding: 8px 12px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: rgba(100, 200, 255, 150);
                color: #000;
            }
        """)
        
        # Notifications table
        self.notifications_table = QTableWidget()
        self.notifications_table.setColumnCount(5)
        self.notifications_table.setHorizontalHeaderLabels([
            "Time", "Type", "Title", "Message", "Status"
        ])
        self.notifications_table.setStyleSheet("""
            QTableWidget {
                background-color: rgba(0, 0, 0, 150);
                border: 1px solid #555;
                border-radius: 4px;
                color: #DCDCDC;
                gridline-color: #555;
            }
            QHeaderView::section {
                background-color: rgba(100, 200, 255, 150);
                color: white;
                padding: 4px;
                border: none;
                font-weight: bold;
            }
        """)
        self.notifications_table.cellDoubleClicked.connect(self.mark_notification_read)
        self.results_tabs.addTab(self.notifications_table, "📋 All Notifications")
        
        # Settings tab
        settings_widget = QWidget()
        settings_layout = QVBoxLayout(settings_widget)
        
        settings_layout.addWidget(QLabel("Notification Settings:"))
        
        self.desktop_notifications_cb = QCheckBox("Desktop Notifications")
        self.desktop_notifications_cb.toggled.connect(self.update_settings)
        
        self.system_tray_cb = QCheckBox("System Tray Icon")
        self.system_tray_cb.toggled.connect(self.update_settings)
        
        self.sound_alerts_cb = QCheckBox("Sound Alerts")
        self.sound_alerts_cb.toggled.connect(self.update_settings)
        
        self.scan_completion_cb = QCheckBox("Scan Completion Notifications")
        self.scan_completion_cb.toggled.connect(self.update_settings)
        
        self.vulnerability_alerts_cb = QCheckBox("Vulnerability Alerts")
        self.vulnerability_alerts_cb.toggled.connect(self.update_settings)
        
        self.error_notifications_cb = QCheckBox("Error Notifications")
        self.error_notifications_cb.toggled.connect(self.update_settings)
        
        checkbox_style = "color: #DCDCDC; font-size: 11pt; padding: 5px;"
        
        self.desktop_notifications_cb.setStyleSheet(checkbox_style)
        self.system_tray_cb.setStyleSheet(checkbox_style)
        self.sound_alerts_cb.setStyleSheet(checkbox_style)
        self.scan_completion_cb.setStyleSheet(checkbox_style)
        self.vulnerability_alerts_cb.setStyleSheet(checkbox_style)
        self.error_notifications_cb.setStyleSheet(checkbox_style)
        
        settings_layout.addWidget(self.desktop_notifications_cb)
        settings_layout.addWidget(self.system_tray_cb)
        settings_layout.addWidget(self.sound_alerts_cb)
        settings_layout.addWidget(self.scan_completion_cb)
        settings_layout.addWidget(self.vulnerability_alerts_cb)
        settings_layout.addWidget(self.error_notifications_cb)
        settings_layout.addStretch()
        
        self.results_tabs.addTab(settings_widget, "⚙️ Settings")
        
        # Status label
        self.status_label = QLabel("Notifications ready")
        self.status_label.setStyleSheet("color: #888; font-size: 10pt; padding: 5px;")
        
        # Add to main layout
        main_layout.addLayout(controls_layout)
        main_layout.addWidget(self.results_tabs)
        main_layout.addWidget(self.status_label)
        
        layout.addWidget(main_group)
        
        # Load current settings
        self.load_settings()
        
    def refresh_notifications(self):
        """Refresh notifications display"""
        try:
            notifications = notification_manager.get_notifications()
            
            # Update table
            self.notifications_table.setRowCount(len(notifications))
            
            unread_count = 0
            
            for row, notification in enumerate(reversed(notifications)):  # Show newest first
                # Time
                timestamp = notification.get('timestamp', '')
                if timestamp:
                    try:
                        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        time_str = dt.strftime('%H:%M:%S')
                    except:
                        time_str = timestamp[:8]
                else:
                    time_str = 'N/A'
                
                time_item = QTableWidgetItem(time_str)
                self.notifications_table.setItem(row, 0, time_item)
                
                # Type
                notification_type = notification.get('type', 'info')
                type_item = QTableWidgetItem(notification_type.title())
                
                # Color code by type
                if notification_type == 'error':
                    type_item.setForeground(Qt.GlobalColor.red)
                elif notification_type == 'vulnerability':
                    type_item.setForeground(Qt.GlobalColor.yellow)
                elif notification_type == 'scan_complete':
                    type_item.setForeground(Qt.GlobalColor.green)
                else:
                    type_item.setForeground(Qt.GlobalColor.cyan)
                
                self.notifications_table.setItem(row, 1, type_item)
                
                # Title
                title = notification.get('title', '')
                title_item = QTableWidgetItem(title)
                if not notification.get('read', False):
                    font = QFont()
                    font.setBold(True)
                    title_item.setFont(font)
                    unread_count += 1
                
                self.notifications_table.setItem(row, 2, title_item)
                
                # Message
                message = notification.get('message', '')
                if len(message) > 50:
                    message = message[:47] + "..."
                message_item = QTableWidgetItem(message)
                self.notifications_table.setItem(row, 3, message_item)
                
                # Status
                status = "Read" if notification.get('read', False) else "Unread"
                status_item = QTableWidgetItem(status)
                if status == "Unread":
                    status_item.setForeground(Qt.GlobalColor.yellow)
                else:
                    status_item.setForeground(Qt.GlobalColor.green)
                
                self.notifications_table.setItem(row, 4, status_item)
            
            self.notifications_table.resizeColumnsToContents()
            
            # Update status
            total_count = len(notifications)
            if unread_count > 0:
                self.status_label.setText(f"{unread_count} unread of {total_count} total notifications")
                self.status_label.setStyleSheet("color: #FFAA00; font-size: 10pt; padding: 5px;")
            else:
                self.status_label.setText(f"{total_count} notifications (all read)")
                self.status_label.setStyleSheet("color: #00AA00; font-size: 10pt; padding: 5px;")
            
        except Exception as e:
            self.status_label.setText(f"Error loading notifications: {str(e)}")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
    
    def mark_notification_read(self, row, column):
        """Mark specific notification as read"""
        try:
            notifications = notification_manager.get_notifications()
            if row < len(notifications):
                # Get notification (reversed order)
                notification = list(reversed(notifications))[row]
                notification_manager.mark_notification_read(notification['id'])
                self.refresh_notifications()
        except Exception:
            pass
    
    def mark_all_read(self):
        """Mark all notifications as read"""
        notification_manager.mark_all_read()
        self.refresh_notifications()
        
        self.status_label.setText("All notifications marked as read")
        self.status_label.setStyleSheet("color: #00AA00; font-size: 10pt; padding: 5px;")
    
    def clear_notifications(self):
        """Clear all notifications"""
        notification_manager.clear_notifications()
        self.refresh_notifications()
        
        self.status_label.setText("All notifications cleared")
        self.status_label.setStyleSheet("color: #FFAA00; font-size: 10pt; padding: 5px;")
    
    def test_notification(self):
        """Send test notification"""
        notification_manager.show_info_notification(
            "Test Notification",
            "This is a test notification from Huggin"
        )
        
        self.status_label.setText("Test notification sent")
        self.status_label.setStyleSheet("color: #64C8FF; font-size: 10pt; padding: 5px;")
    
    def load_settings(self):
        """Load current notification settings"""
        settings = notification_manager.get_settings()
        
        self.desktop_notifications_cb.setChecked(settings.get('desktop_notifications', True))
        self.system_tray_cb.setChecked(settings.get('system_tray', True))
        self.sound_alerts_cb.setChecked(settings.get('sound_alerts', False))
        self.scan_completion_cb.setChecked(settings.get('scan_completion', True))
        self.vulnerability_alerts_cb.setChecked(settings.get('vulnerability_alerts', True))
        self.error_notifications_cb.setChecked(settings.get('error_notifications', True))
    
    def update_settings(self):
        """Update notification settings"""
        settings = {
            'desktop_notifications': self.desktop_notifications_cb.isChecked(),
            'system_tray': self.system_tray_cb.isChecked(),
            'sound_alerts': self.sound_alerts_cb.isChecked(),
            'scan_completion': self.scan_completion_cb.isChecked(),
            'vulnerability_alerts': self.vulnerability_alerts_cb.isChecked(),
            'error_notifications': self.error_notifications_cb.isChecked()
        }
        
        notification_manager.update_settings(settings)
        
        self.status_label.setText("Notification settings updated")
        self.status_label.setStyleSheet("color: #00AA00; font-size: 10pt; padding: 5px;")