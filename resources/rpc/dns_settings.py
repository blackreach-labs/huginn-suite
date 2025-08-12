# app/core/dns_settings.py
import json
import os
from PyQt6.QtCore import QObject, pyqtSignal
from app.core.logger import logger

class DNSSettingsManager(QObject):
    """Global DNS settings manager"""
    
    dns_changed = pyqtSignal(str)  # dns_server
    
    def __init__(self):
        super().__init__()
        self.settings_file = os.path.join("resources", "config", "dns_settings.json")
        self.current_dns = "Default DNS"  # Always start with Default DNS
        self.load_settings()
        # Override loaded settings to always start with Default DNS
        self.current_dns = "Default DNS"
    
    def get_current_dns(self):
        """Get current DNS server setting"""
        return self.current_dns
    
    def set_dns_server(self, dns_server):
        """Set global DNS server"""
        self.current_dns = dns_server
        self.save_settings()
        self.dns_changed.emit(dns_server)
        logger.info(f"DNS server changed to: {dns_server}")
    
    def set_local_dns_port(self, port):
        """Set LocalDNS port"""
        self.local_dns_port = port
        self.save_settings()
        logger.info(f"LocalDNS port set to: {port}")
    
    def get_local_dns_port(self):
        """Get LocalDNS port"""
        return getattr(self, 'local_dns_port', 53530)
    
    def get_available_dns_servers(self):
        """Get list of available DNS servers"""
        return [
            "Default DNS",
            "LocalDNS"
        ]
    
    def save_settings(self):
        """Save DNS settings to file"""
        try:
            # Ensure config directory exists
            os.makedirs(os.path.dirname(self.settings_file), exist_ok=True)
            
            settings = {
                "current_dns": self.current_dns,
                "local_dns_port": getattr(self, 'local_dns_port', 53530)
            }
            with open(self.settings_file, 'w') as f:
                json.dump(settings, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save DNS settings: {e}")
    
    def load_settings(self):
        """Load DNS settings from file"""
        try:
            # Ensure config directory exists
            os.makedirs(os.path.dirname(self.settings_file), exist_ok=True)
            
            if os.path.exists(self.settings_file):
                with open(self.settings_file, 'r') as f:
                    settings = json.load(f)
                    self.current_dns = settings.get("current_dns", "Default DNS")
                    # Also load LocalDNS port if available
                    self.local_dns_port = settings.get("local_dns_port", 53530)
            else:
                # Create default settings file
                self.current_dns = "Default DNS"
                self.local_dns_port = 53530
                self.save_settings()
        except Exception as e:
            logger.error(f"Failed to load DNS settings: {e}")
            self.current_dns = "Default DNS"
            self.local_dns_port = 53530

# Global DNS settings instance
dns_settings = DNSSettingsManager()