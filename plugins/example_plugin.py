# plugins/example_plugin.py
from app.core.plugin_manager import PluginBase

class ExamplePlugin(PluginBase):
    """Example plugin demonstrating plugin architecture."""
    
    def __init__(self):
        super().__init__()
        self.name = "Example Plugin"
        self.version = "1.0.0"
        self.description = "Example plugin for demonstration"
    
    def execute(self, target, **kwargs):
        """Execute example plugin functionality."""
        return {
            "plugin": self.name,
            "target": target,
            "result": f"Example scan completed for {target}",
            "data": ["example.result1", "example.result2"]
        }