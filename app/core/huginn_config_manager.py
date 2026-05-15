import os
import yaml
import json
from typing import Dict, Any, Optional
from app.core.logger import logger

class ConfigManager:
    """Configuration and profile management for Huginn Scanner"""
    
    def __init__(self, config_path: str = "resources/config/scanner_config.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or create default"""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    return yaml.safe_load(f)
            except Exception as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        
        return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Default configuration with multiple scan profiles"""
        return {
            'scan_profile': 'normal',
            'profiles': {
                'light': {
                    'scan_profile': 'light',
                    'max_concurrent': 20,
                    'timeout': 5,
                    'modules': ['banner', 'tech_fingerprint', 'security_headers'],
                    'payload_limit': 2,
                    'deep_crawl': False
                },
                'normal': {
                    'scan_profile': 'normal',
                    'max_concurrent': 50,
                    'timeout': 10,
                    'modules': ['all'],
                    'payload_limit': 3,
                    'deep_crawl': False
                },
                'aggressive': {
                    'scan_profile': 'aggressive',
                    'max_concurrent': 100,
                    'timeout': 15,
                    'modules': ['all'],
                    'payload_limit': 5,
                    'deep_crawl': True
                },
                'insane': {
                    'scan_profile': 'insane',
                    'max_concurrent': 200,
                    'timeout': 20,
                    'modules': ['all', 'deep_crawl', 'bruteforce_extended'],
                    'payload_limit': 8,
                    'deep_crawl': True
                }
            },
            'authentication': {
                'method': None,
                'token': None,
                'username': None,
                'password': None,
                'cookies': {}
            },
            'custom_headers': {},
            'proxy': {
                'enabled': False,
                'url': None
            },
            'wordlists': {
                'directories': 'resources/wordlists/directories.txt',
                'files': 'resources/wordlists/files.txt',
                'parameters': 'resources/wordlists/parameters.txt'
            }
        }
    
    def get_profile(self, profile_name: Optional[str] = None) -> Dict[str, Any]:
        """Get scan profile configuration"""
        if not profile_name:
            profile_name = self.config.get('scan_profile', 'normal')
        
        return self.config['profiles'].get(profile_name, self.config['profiles']['normal'])
    
    def get_auth_config(self) -> Dict[str, Any]:
        """Get authentication configuration"""
        return self.config.get('authentication', {})
    
    def get_headers(self) -> Dict[str, str]:
        """Get custom headers"""
        return self.config.get('custom_headers', {})
    
    def save_config(self):
        """Save current configuration to file"""
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, 'w') as f:
            yaml.dump(self.config, f, default_flow_style=False)
    
    def update_profile(self, profile_name: str, updates: Dict[str, Any]):
        """Update a scan profile"""
        if profile_name in self.config['profiles']:
            self.config['profiles'][profile_name].update(updates)
            self.save_config()
    
    def set_auth(self, method: str, **kwargs):
        """Set authentication configuration"""
        self.config['authentication']['method'] = method
        self.config['authentication'].update(kwargs)
        self.save_config()