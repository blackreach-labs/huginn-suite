from abc import abstractmethod
from typing import Optional, Dict, Any
from PyQt5.QtWidgets import QWidget
from .plugin_interface import PluginInterface, PluginMetadata

class UIPluginInterface(PluginInterface):
    """Interface for UI-based plugins"""
    
    @abstractmethod
    def create_widget(self, parent: Optional[QWidget] = None) -> QWidget:
        """Create and return the plugin's UI widget"""
        pass
    
    @abstractmethod
    def get_menu_text(self) -> str:
        """Return text for menu integration"""
        pass
    
    def get_icon_path(self) -> Optional[str]:
        """Return path to plugin icon"""
        return None
    
    def get_shortcut(self) -> Optional[str]:
        """Return keyboard shortcut"""
        return None