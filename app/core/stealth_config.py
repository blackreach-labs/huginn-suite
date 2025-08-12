# app/core/stealth_config.py
import json
import os

class StealthConfig:
    """Stealth Mode Configuration Manager"""
    
    def __init__(self):
        self.config_file = os.path.join(os.path.dirname(__file__), '..', '..', 'resources', 'config', 'stealth_config.json')
        self.default_config = {
            'enabled': True,
            'timeout': 1.0,
            'probe_types': {
                'icmp': [],
                'tcp_syn': [22, 80, 443, 3389],
                'tcp_ack': [80, 443]
            }
        }
        self.config = self.load_config()
    
    def load_config(self):
        """Load stealth configuration from file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    return json.load(f)
        except:
            pass
        return self.default_config.copy()
    
    def save_config(self):
        """Save stealth configuration to file"""
        try:
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
        except:
            pass
    
    def is_enabled(self):
        """Check if stealth mode is enabled"""
        return self.config.get('enabled', True)
    
    def get_timeout(self):
        """Get probe timeout"""
        return self.config.get('timeout', 1.0)
    
    def get_probe_config(self):
        """Get probe types configuration"""
        return self.config.get('probe_types', self.default_config['probe_types'])

# Global instance
stealth_config = StealthConfig()