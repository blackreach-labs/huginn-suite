# app/core/notification_manager.py
import os
import sys
from typing import Dict, List, Callable
from datetime import datetime
from PyQt6.QtWidgets import QSystemTrayIcon, QMenu, QApplication
from PyQt6.QtCore import QObject, pyqtSignal, QTimer
from PyQt6.QtGui import QIcon, QPixmap
from app.core.logger import logger

class NotificationManager(QObject):
    """Manage real-time notifications and system tray"""
    
    notification_clicked = pyqtSignal(str)  # Signal when notification is clicked
    
    def __init__(self):
        super().__init__()
        self.tray_icon = None
        self.notifications = []
        self.notification_settings = {
            'desktop_notifications': True,
            'system_tray': True,
            'sound_alerts': False,
            'scan_completion': True,
            'vulnerability_alerts': True,
            'error_notifications': True
        }
        self.setup_system_tray()
    
    def setup_system_tray(self):
        """Setup system tray icon and menu"""
        
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        
        # Create tray icon
        self.tray_icon = QSystemTrayIcon()
        
        # Set icon
        icon_path = self._get_icon_path()
        if os.path.exists(icon_path):
            self.tray_icon.setIcon(QIcon(icon_path))
        else:
            # Create simple colored icon if file not found
            pixmap = QPixmap(16, 16)
            pixmap.fill()
            self.tray_icon.setIcon(QIcon(pixmap))
        
        # Create context menu
        tray_menu = QMenu()
        
        show_action = tray_menu.addAction("Show Huggin")
        show_action.triggered.connect(self._show_main_window)
        
        tray_menu.addSeparator()
        
        notifications_action = tray_menu.addAction("View Notifications")
        notifications_action.triggered.connect(self._show_notifications)
        
        settings_action = tray_menu.addAction("Notification Settings")
        settings_action.triggered.connect(self._show_settings)
        
        tray_menu.addSeparator()
        
        quit_action = tray_menu.addAction("Quit")
        quit_action.triggered.connect(QApplication.quit)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.setToolTip("Huggin - Security Assessment Tool")
        
        # Connect signals
        self.tray_icon.activated.connect(self._tray_icon_activated)
        self.tray_icon.messageClicked.connect(self._notification_clicked)
        
        # Show tray icon
        if self.notification_settings['system_tray']:
            self.tray_icon.show()
    
    def show_notification(self, title: str, message: str, notification_type: str = 'info', 
                         duration: int = 5000, clickable: bool = True):
        """Show desktop notification"""
        
        # Check if notifications are enabled
        if not self.notification_settings['desktop_notifications']:
            return
        
        # Check type-specific settings
        if notification_type == 'scan_complete' and not self.notification_settings['scan_completion']:
            return
        elif notification_type == 'vulnerability' and not self.notification_settings['vulnerability_alerts']:
            return
        elif notification_type == 'error' and not self.notification_settings['error_notifications']:
            return
        
        # Store notification
        notification = {
            'id': len(self.notifications),
            'title': title,
            'message': message,
            'type': notification_type,
            'timestamp': datetime.now().isoformat(),
            'read': False,
            'clickable': clickable
        }
        
        self.notifications.append(notification)
        
        # Show system tray notification
        if self.tray_icon and self.tray_icon.isVisible():
            icon_type = self._get_notification_icon_type(notification_type)
            self.tray_icon.showMessage(title, message, icon_type, duration)
        
        # Play sound if enabled
        if self.notification_settings['sound_alerts']:
            self._play_notification_sound(notification_type)
    
    def show_scan_completion(self, target: str, scan_type: str, results_count: int):
        """Show scan completion notification"""
        
        title = "Scan Completed"
        message = f"{scan_type.title()} scan of {target} completed with {results_count} results"
        
        self.show_notification(title, message, 'scan_complete')
    
    def show_vulnerability_alert(self, target: str, vulnerability_count: int, high_severity: int):
        """Show vulnerability detection notification"""
        
        title = "Vulnerabilities Detected"
        message = f"Found {vulnerability_count} vulnerabilities on {target} ({high_severity} high severity)"
        
        self.show_notification(title, message, 'vulnerability')
    
    def show_error_notification(self, title: str, error_message: str):
        """Show error notification"""
        
        self.show_notification(title, error_message, 'error')
    
    def show_info_notification(self, title: str, message: str):
        """Show informational notification"""
        
        self.show_notification(title, message, 'info')
    
    def get_notifications(self, unread_only: bool = False) -> List[Dict]:
        """Get notifications list"""
        
        if unread_only:
            return [n for n in self.notifications if not n['read']]
        
        return self.notifications.copy()
    
    def mark_notification_read(self, notification_id: int):
        """Mark notification as read"""
        
        for notification in self.notifications:
            if notification['id'] == notification_id:
                notification['read'] = True
                break
    
    def mark_all_read(self):
        """Mark all notifications as read"""
        
        for notification in self.notifications:
            notification['read'] = True
    
    def clear_notifications(self):
        """Clear all notifications"""
        
        self.notifications.clear()
    
    def update_settings(self, settings: Dict):
        """Update notification settings"""
        
        self.notification_settings.update(settings)
        
        # Update system tray visibility
        if self.tray_icon:
            if self.notification_settings['system_tray']:
                self.tray_icon.show()
            else:
                self.tray_icon.hide()
    
    def get_settings(self) -> Dict:
        """Get current notification settings"""
        
        return self.notification_settings.copy()
    
    def _get_icon_path(self) -> str:
        """Get application icon path"""
        
        # Try different icon locations
        possible_paths = [
            "resources/icons/app_icon.png",
            "resources/icons/huggin.png",
            "app_icon.png"
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
        
        return ""
    
    def _get_notification_icon_type(self, notification_type: str):
        """Get system tray icon type for notification"""
        
        if notification_type == 'error':
            return QSystemTrayIcon.MessageIcon.Critical
        elif notification_type == 'vulnerability':
            return QSystemTrayIcon.MessageIcon.Warning
        elif notification_type == 'scan_complete':
            return QSystemTrayIcon.MessageIcon.Information
        else:
            return QSystemTrayIcon.MessageIcon.Information
    
    def _play_notification_sound(self, notification_type: str):
        """Play notification sound"""
        
        try:
            if sys.platform == "win32":
                import winsound
                if notification_type == 'error':
                    winsound.MessageBeep(winsound.MB_ICONHAND)
                elif notification_type == 'vulnerability':
                    winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
                else:
                    winsound.MessageBeep(winsound.MB_ICONASTERISK)
        except ImportError as _exc:
            pass  # Sound not available
            logger.debug("Suppressed exception", exc_info=True)
    
    def _tray_icon_activated(self, reason):
        """Handle tray icon activation"""
        
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self._show_main_window()
    
    def _notification_clicked(self):
        """Handle notification click"""
        
        self.notification_clicked.emit("notification_clicked")
    
    def _show_main_window(self):
        """Show main application window"""
        
        app = QApplication.instance()
        if app:
            for widget in app.topLevelWidgets():
                if hasattr(widget, 'show') and hasattr(widget, 'raise_') and hasattr(widget, 'activateWindow'):
                    widget.show()
                    widget.raise_()
                    widget.activateWindow()
                    break
    
    def _show_notifications(self):
        """Show notifications panel"""
        
        self.notification_clicked.emit("show_notifications")
    
    def _show_settings(self):
        """Show notification settings"""
        
        self.notification_clicked.emit("show_settings")

# Global instance
notification_manager = NotificationManager()