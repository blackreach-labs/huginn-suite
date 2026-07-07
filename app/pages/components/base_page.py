# app/pages/components/base_page.py
from abc import ABC, abstractmethod
from PyQt6.QtWidgets import QWidget
from PyQt6.QtCore import pyqtSignal
# from shared.events.event_bus import EventBus  # Import when available

class BasePageMeta(type(QWidget), type(ABC)):
    """Metaclass to resolve QWidget and ABC metaclass conflict."""
    pass

class BasePage(QWidget, ABC, metaclass=BasePageMeta):
    """Base class for all application pages with common functionality."""
    
    # Common signals
    navigate_signal = pyqtSignal(str)
    status_updated = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        # self.event_bus = EventBus()  # Initialize when available
        self._setup_base_ui()
        self.setup_ui()
        self.connect_signals()
    
    def _setup_base_ui(self):
        """Setup base UI components common to all pages."""
        self.setObjectName(self.__class__.__name__)
    
    @abstractmethod
    def setup_ui(self):
        """Setup page-specific UI components. Must be implemented by subclasses."""
        pass
    
    def connect_signals(self):
        """Connect page-specific signals. Override in subclasses if needed."""
        pass
    
    def apply_theme(self):
        """Apply theme to the page. Override in subclasses for custom theming.
        
        Theme is applied globally by UnifiedThemeManager via QApplication.setStyleSheet().
        Pages inherit the global theme automatically. Override only if truly needed.
        """
        pass
    
    def cleanup(self):
        """Cleanup resources when page is destroyed. Override in subclasses."""
        pass
    
    def get_page_title(self):
        """Get the display title for this page."""
        return self.__class__.__name__.replace('Page', '')
    
    def get_page_icon(self):
        """Get the icon path for this page. Override in subclasses."""
        return None
    
    def is_page_ready(self):
        """Check if page is ready for display. Override in subclasses."""
        return True
    
    def on_page_activated(self):
        """Called when page becomes active. Override in subclasses."""
        pass
    
    def on_page_deactivated(self):
        """Called when page becomes inactive. Override in subclasses."""
        pass
    
    def show_status(self, message, status_type="info"):
        """Show status message. Override in subclasses for custom implementation."""
        if hasattr(self.main_window, 'show_status'):
            self.main_window.show_status(message, status_type)
        else:
            print(f"[{status_type.upper()}] {message}")