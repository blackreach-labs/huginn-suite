# app/core/system_tray.py
from PyQt6.QtWidgets import QSystemTrayIcon, QMenu
from PyQt6.QtGui import QIcon, QAction
from PyQt6.QtCore import QObject, pyqtSignal
import os

class SystemTrayManager(QObject):
    """Manages system tray functionality for Huggin"""
    
    show_window = pyqtSignal()
    hide_window = pyqtSignal()
    quit_application = pyqtSignal()
    
    def __init__(self, main_window, project_root):
        super().__init__()
        self.main_window = main_window
        self.project_root = project_root
        self.tray_icon = None
        self.setup_tray()
        
    def setup_tray(self):
        """Initialize system tray icon and menu"""
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return False
            
        # Create tray icon
        self.tray_icon = QSystemTrayIcon(self.main_window)
        
        # Set icon (use a default icon if custom one doesn't exist)
        icon_path = os.path.join(self.project_root, "resources", "icons", "1.png")
        if os.path.exists(icon_path):
            self.tray_icon.setIcon(QIcon(icon_path))
        else:
            # Use default system icon
            self.tray_icon.setIcon(self.main_window.style().standardIcon(self.main_window.style().StandardPixmap.SP_ComputerIcon))
        
        # Create context menu
        self.create_tray_menu()
        
        # Connect signals
        self.tray_icon.activated.connect(self.on_tray_activated)
        self.show_window.connect(self.main_window.show)
        self.show_window.connect(self.main_window.raise_)
        self.show_window.connect(self.main_window.activateWindow)
        self.hide_window.connect(self.main_window.hide)
        self.quit_application.connect(self.main_window.close)
        
        # Set tooltip
        self.tray_icon.setToolTip("Huggin - Cybersecurity Toolkit")
        
        return True
        
    def create_tray_menu(self):
        """Create the system tray context menu"""
        tray_menu = QMenu()
        
        # Show/Hide action
        show_action = QAction("Show Huggin", self.main_window)
        show_action.triggered.connect(self.show_window.emit)
        tray_menu.addAction(show_action)
        
        tray_menu.addSeparator()
        
        # Quick actions
        enum_action = QAction("Open Enumeration", self.main_window)
        enum_action.triggered.connect(lambda: self.quick_navigate("enumeration"))
        tray_menu.addAction(enum_action)
        
        tray_menu.addSeparator()
        
        # Quit action
        quit_action = QAction("Quit", self.main_window)
        quit_action.triggered.connect(self.force_quit_application)
        tray_menu.addAction(quit_action)
        
        self.tray_icon.setContextMenu(tray_menu)
        
    def on_tray_activated(self, reason):
        """Handle tray icon activation"""
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            if self.main_window.isVisible():
                self.hide_window.emit()
            else:
                self.show_window.emit()
                
    def quick_navigate(self, page):
        """Quick navigation from tray menu"""
        self.show_window.emit()
        if hasattr(self.main_window, 'navigate_to'):
            self.main_window.navigate_to(page)
            
    def show_tray(self):
        """Show the system tray icon"""
        if self.tray_icon:
            self.tray_icon.show()
            
    def hide_tray(self):
        """Hide the system tray icon"""
        if self.tray_icon:
            self.tray_icon.hide()
            
    def show_message(self, title, message, icon=QSystemTrayIcon.MessageIcon.Information):
        """Show a system tray notification"""
        if self.tray_icon and self.tray_icon.isVisible():
            self.tray_icon.showMessage(title, message, icon, 3000)
            
    def is_available(self):
        """Check if system tray is available"""
        return QSystemTrayIcon.isSystemTrayAvailable()
    
    def force_quit_application(self):
        """Force quit application with cleanup"""
        # Trigger cleanup in main window
        if hasattr(self.main_window, 'cleanup_services'):
            self.main_window.cleanup_services()
        
        # Force close without tray dialog
        self.main_window.tray_manager = None  # Disable tray dialog
        self.quit_application.emit()