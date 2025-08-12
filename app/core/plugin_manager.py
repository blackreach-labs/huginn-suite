# app/core/plugin_manager.py
import os
import importlib.util
import inspect
from PyQt6.QtCore import QObject, pyqtSignal

class PluginBase:
    """Base class for all plugins."""
    
    def __init__(self):
        self.name = "Unknown Plugin"
        self.version = "1.0.0"
        self.description = "No description"
    
    def execute(self, target, **kwargs):
        """Execute plugin functionality."""
        raise NotImplementedError("Plugin must implement execute method")

class PluginManager(QObject):
    """Manages plugin loading and execution."""
    
    plugin_loaded = pyqtSignal(str)
    plugin_executed = pyqtSignal(str, dict)
    
    def __init__(self, plugins_dir="plugins"):
        super().__init__()
        self.plugins_dir = plugins_dir
        self.loaded_plugins = {}
        
    def load_plugins(self):
        """Load all plugins from plugins directory."""
        if not os.path.exists(self.plugins_dir):
            return
            
        for filename in os.listdir(self.plugins_dir):
            if filename.endswith('.py') and not filename.startswith('__'):
                self.load_plugin(filename)
    
    def load_plugin(self, filename):
        """Load a single plugin file."""
        try:
            plugin_path = os.path.join(self.plugins_dir, filename)
            spec = importlib.util.spec_from_file_location(filename[:-3], plugin_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Find plugin classes
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if issubclass(obj, PluginBase) and obj != PluginBase:
                    plugin_instance = obj()
                    self.loaded_plugins[plugin_instance.name] = plugin_instance
                    self.plugin_loaded.emit(plugin_instance.name)
                    
        except Exception as e:
            print(f"Failed to load plugin {filename}: {e}")
    
    def get_plugins(self):
        """Get list of loaded plugins."""
        return list(self.loaded_plugins.keys())
    
    def execute_plugin(self, plugin_name, target, **kwargs):
        """Execute a specific plugin."""
        if plugin_name in self.loaded_plugins:
            try:
                result = self.loaded_plugins[plugin_name].execute(target, **kwargs)
                self.plugin_executed.emit(plugin_name, result or {})
                return result
            except Exception as e:
                return {"error": str(e)}
        return {"error": "Plugin not found"}

# Global plugin manager instance
plugin_manager = PluginManager()