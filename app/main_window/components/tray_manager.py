"""System tray management for main window."""
from PyQt6.QtWidgets import QSystemTrayIcon, QMessageBox
from app.core.system_tray import SystemTrayManager


class MainWindowTrayManager:
    """Manages system tray integration for the main window."""
    
    def __init__(self, main_window, project_root):
        self.main_window = main_window
        self.project_root = project_root
        self.tray_manager = None
        
    def setup_system_tray(self):
        """Initialize system tray functionality."""
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray_manager = SystemTrayManager(self.main_window, self.project_root)
            if self.tray_manager.setup_tray():
                self.tray_manager.show_tray()
                self.main_window.status_bar.showMessage("System tray integration enabled")
                return True
            else:
                self.tray_manager = None
                self.main_window.status_bar.showMessage("System tray not available")
                return False
        else:
            self.tray_manager = None
            self.main_window.status_bar.showMessage("System tray not supported on this system")
            return False
    
    def minimize_to_tray(self):
        """Minimize application to system tray."""
        if self.tray_manager and self.tray_manager.is_available():
            self.main_window.hide()
            self.tray_manager.show_message(
                "Huginn", 
                "Application minimized to tray. Double-click to restore.",
                QSystemTrayIcon.MessageIcon.Information
            )
            self.main_window.status_bar.showMessage("Minimized to system tray")
        else:
            self.main_window.showMinimized()
            self.main_window.status_bar.showMessage("System tray not available - minimized to taskbar")
    
    def handle_window_state_change(self, event):
        """Handle window state changes for tray integration."""
        if event.type() == event.Type.WindowStateChange:
            if self.main_window.isMinimized() and self.tray_manager and self.tray_manager.is_available():
                # Auto-minimize to tray when minimized
                self.main_window.hide()
                event.ignore()
                return True
        return False
    
    def handle_close_event(self, event):
        """Handle application close event with tray integration."""
        if self.tray_manager and self.tray_manager.is_available():
            # Ask user if they want to minimize to tray instead of closing
            reply = QMessageBox.question(
                self.main_window, 'Huginn', 
                "Close to system tray instead of exiting?\\n\\n"
                "Click 'Yes' to minimize to tray\\n"
                "Click 'No' to exit completely",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self.main_window.hide()
                self.tray_manager.show_message(
                    "Huginn", 
                    "Application closed to tray. Right-click tray icon to quit.",
                    QSystemTrayIcon.MessageIcon.Information
                )
                event.ignore()
                return True
        return False
    
    def cleanup(self):
        """Cleanup tray manager."""
        if self.tray_manager:
            self.tray_manager.hide_tray()
    
    def is_available(self):
        """Check if tray manager is available."""
        return self.tray_manager and self.tray_manager.is_available()