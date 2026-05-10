from typing import Dict, List, Optional, Type
from .plugin_interface import PluginInterface, PluginMetadata
import threading
import logging

class PluginRegistry:
    """Thread-safe plugin registry"""
    
    def __init__(self):
        self._plugins: Dict[str, Type[PluginInterface]] = {}
        self._instances: Dict[str, PluginInterface] = {}
        self._metadata: Dict[str, PluginMetadata] = {}
        self._lock = threading.RLock()
    
    def register(self, plugin_class: Type[PluginInterface]) -> bool:
        """Register a plugin class"""
        with self._lock:
            try:
                instance = plugin_class()
                metadata = instance.get_metadata()
                
                if metadata.name in self._plugins:
                    return False
                
                self._plugins[metadata.name] = plugin_class
                self._metadata[metadata.name] = metadata
                return True
            except Exception:
                return False
    
    def unregister(self, plugin_name: str) -> bool:
        """Unregister a plugin"""
        with self._lock:
            if plugin_name in self._instances:
                try:
                    self._instances[plugin_name].cleanup()
                except Exception as _exc:
                    pass
                    logging.debug("Suppressed exception", exc_info=True)
                del self._instances[plugin_name]
            
            if plugin_name in self._plugins:
                del self._plugins[plugin_name]
                del self._metadata[plugin_name]
                return True
            return False
    
    def get_plugin(self, plugin_name: str) -> Optional[PluginInterface]:
        """Get plugin instance (singleton)"""
        with self._lock:
            if plugin_name in self._instances:
                return self._instances[plugin_name]
            
            if plugin_name in self._plugins:
                try:
                    instance = self._plugins[plugin_name]()
                    self._instances[plugin_name] = instance
                    return instance
                except Exception:
                    return None
            return None
    
    def list_plugins(self) -> List[PluginMetadata]:
        """List all registered plugins"""
        with self._lock:
            return list(self._metadata.values())
    
    def get_plugins_by_category(self, category: str) -> List[str]:
        """Get plugins by category"""
        with self._lock:
            return [name for name, meta in self._metadata.items() 
                   if meta.category == category]