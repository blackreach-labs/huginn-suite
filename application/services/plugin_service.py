from typing import Dict, Any, List
from shared.plugins.plugin_manager import PluginManager
from shared.configuration.config_manager import ConfigManager
from shared.events.event_bus import EventBus

class PluginService:
    """Service layer for plugin management"""
    
    def __init__(self, config_manager: ConfigManager, event_bus: EventBus):
        self.config_manager = config_manager
        self.event_bus = event_bus
        plugin_config = config_manager.get_plugin_config()
        
        self.plugin_manager = PluginManager(
            plugin_dirs=plugin_config.plugin_dirs,
            event_bus=event_bus
        )
        
        if plugin_config.auto_load:
            self.load_all_plugins()
    
    def load_all_plugins(self) -> int:
        """Load all available plugins"""
        return self.plugin_manager.load_plugins()
    
    def execute_plugin(self, plugin_name: str, data: Dict[str, Any]) -> Any:
        """Execute a plugin with data"""
        return self.plugin_manager.execute_plugin(plugin_name, data)
    
    def get_plugins_by_category(self, category: str) -> List[str]:
        """Get plugins filtered by category"""
        return self.plugin_manager.get_plugins_by_category(category)
    
    def get_available_plugins(self) -> List[str]:
        """Get all available plugin names"""
        return self.plugin_manager.get_available_plugins()