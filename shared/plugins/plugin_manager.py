import os
import sys
import importlib.util
from typing import Dict, Any, List, Optional
from pathlib import Path
from .plugin_interface import PluginInterface
from .plugin_registry import PluginRegistry
from ..events.event_bus import EventBus
from ..events.plugin_events import PluginLoadedEvent, PluginExecutedEvent

class PluginManager:
    """Advanced plugin manager with dynamic loading and event integration"""
    
    def __init__(self, plugin_dirs: List[str] = None, event_bus: EventBus = None):
        self.registry = PluginRegistry()
        self.event_bus = event_bus or EventBus()
        self.plugin_dirs = plugin_dirs or ['plugins']
        self.context: Dict[str, Any] = {}
    
    def set_context(self, context: Dict[str, Any]):
        """Set global context for plugins"""
        self.context = context
    
    def load_plugins(self) -> int:
        """Load all plugins from plugin directories"""
        loaded_count = 0
        
        for plugin_dir in self.plugin_dirs:
            if not os.path.exists(plugin_dir):
                continue
                
            for file_path in Path(plugin_dir).rglob('*.py'):
                if file_path.name.startswith('__'):
                    continue
                
                if self._load_plugin_file(str(file_path)):
                    loaded_count += 1
        
        return loaded_count
    
    def _load_plugin_file(self, file_path: str) -> bool:
        """Load a single plugin file"""
        try:
            spec = importlib.util.spec_from_file_location("plugin", file_path)
            if not spec or not spec.loader:
                return False
            
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Find plugin classes
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (isinstance(attr, type) and 
                    issubclass(attr, PluginInterface) and 
                    attr != PluginInterface):
                    
                    if self.registry.register(attr):
                        self.event_bus.publish(PluginLoadedEvent(
                            plugin_name=attr_name,
                            file_path=file_path
                        ))
                        return True
            
            return False
        except Exception:
            return False
    
    def execute_plugin(self, plugin_name: str, *args, **kwargs) -> Any:
        """Execute a plugin with event publishing"""
        plugin = self.registry.get_plugin(plugin_name)
        if not plugin:
            return None
        
        try:
            if not hasattr(plugin, '_initialized'):
                plugin.initialize(self.context)
                plugin._initialized = True
            
            result = plugin.execute(*args, **kwargs)
            
            self.event_bus.publish(PluginExecutedEvent(
                plugin_name=plugin_name,
                success=True,
                result=result
            ))
            
            return result
        except Exception as e:
            self.event_bus.publish(PluginExecutedEvent(
                plugin_name=plugin_name,
                success=False,
                error=str(e)
            ))
            return None
    
    def get_available_plugins(self) -> List[str]:
        """Get list of available plugin names"""
        return [meta.name for meta in self.registry.list_plugins()]
    
    def get_plugins_by_category(self, category: str) -> List[str]:
        """Get plugins filtered by category"""
        return self.registry.get_plugins_by_category(category)
    
    def reload_plugin(self, plugin_name: str) -> bool:
        """Reload a specific plugin"""
        self.registry.unregister(plugin_name)
        return self.load_plugins() > 0