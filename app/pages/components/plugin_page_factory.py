from typing import Dict, Optional, Type
from PyQt5.QtWidgets import QWidget
from .base_page import BasePage
from shared.plugins.ui_plugin_interface import UIPluginInterface
from shared.plugins.plugin_manager import PluginManager

class PluginPageFactory:
    """Factory for creating plugin-based pages"""
    
    def __init__(self, plugin_manager: PluginManager):
        self.plugin_manager = plugin_manager
        self._plugin_pages: Dict[str, Type[BasePage]] = {}
    
    def register_ui_plugins(self):
        """Register all UI plugins as pages"""
        ui_plugins = self.plugin_manager.get_plugins_by_category("ui")
        
        for plugin_name in ui_plugins:
            plugin = self.plugin_manager.registry.get_plugin(plugin_name)
            if isinstance(plugin, UIPluginInterface):
                page_class = self._create_plugin_page_class(plugin)
                self._plugin_pages[plugin_name] = page_class
    
    def _create_plugin_page_class(self, plugin: UIPluginInterface) -> Type[BasePage]:
        """Create a page class wrapper for UI plugin"""
        
        class PluginPage(BasePage):
            def __init__(self, parent=None):
                super().__init__(parent)
                self.plugin = plugin
                self.setup_ui()
            
            def setup_ui(self):
                widget = self.plugin.create_widget(self)
                layout = self.get_main_layout()
                layout.addWidget(widget)
            
            def get_page_title(self) -> str:
                return self.plugin.get_menu_text()
        
        return PluginPage
    
    def create_plugin_page(self, plugin_name: str, parent: Optional[QWidget] = None) -> Optional[BasePage]:
        """Create instance of plugin page"""
        if plugin_name in self._plugin_pages:
            return self._plugin_pages[plugin_name](parent)
        return None
    
    def get_available_plugin_pages(self) -> Dict[str, str]:
        """Get available plugin pages with their display names"""
        result = {}
        for plugin_name in self._plugin_pages:
            plugin = self.plugin_manager.registry.get_plugin(plugin_name)
            if plugin:
                result[plugin_name] = plugin.get_menu_text()
        return result