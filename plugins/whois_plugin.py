# plugins/whois_plugin.py
from app.core.plugin_manager import PluginBase
import subprocess

class WhoisPlugin(PluginBase):
    """WHOIS lookup plugin."""
    
    def __init__(self):
        super().__init__()
        self.name = "WHOIS Lookup"
        self.version = "1.0.0"
        self.description = "Perform WHOIS domain lookups"
    
    def execute(self, target, **kwargs):
        """Execute WHOIS lookup."""
        try:
            result = subprocess.run(['nslookup', target], 
                                  capture_output=True, text=True, timeout=10)
            return {
                "plugin": self.name,
                "target": target,
                "result": result.stdout if result.returncode == 0 else "Lookup failed",
                "success": result.returncode == 0
            }
        except Exception as e:
            return {
                "plugin": self.name,
                "target": target,
                "result": f"Error: {str(e)}",
                "success": False
            }