"""Global settings manager for Huginn"""

import json
import os
from typing import Dict, Any
import logging

class GlobalSettings:
    """Manages global application settings"""
    
    _instance = None
    _settings = {}
    _settings_file = "resources/global_settings.json"
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load_settings()
        return cls._instance
    
    def _load_settings(self):
        """Load settings from file"""
        if os.path.exists(self._settings_file):
            try:
                with open(self._settings_file, 'r') as f:
                    self._settings = json.load(f)
            except Exception:
                self._settings = self._get_default_settings()
        else:
            self._settings = self._get_default_settings()
            self._save_settings()
    
    def _save_settings(self):
        """Save settings to file"""
        os.makedirs(os.path.dirname(self._settings_file), exist_ok=True)
        with open(self._settings_file, 'w') as f:
            json.dump(self._settings, f, indent=2)
    
    def _get_default_settings(self) -> Dict[str, Any]:
        """Get default settings"""
        return {
            "api_keys": {
                "hashes_com": "",
                "md5decrypt_email": "",
                "md5decrypt_key": "",
                "shodan": "",
                "virustotal": "",
                "urlvoid": ""
            },
            "general": {
                "default_timeout": 30,
                "max_threads": 50,
                "auto_save": True
            },
            "proxy": {
                "enabled": False,
                "host": "",
                "port": 8080,
                "username": "",
                "password": ""
            }
        }
    
    def get(self, key: str, default=None):
        """Get setting value"""
        keys = key.split('.')
        value = self._settings
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value
    
    def set(self, key: str, value: Any):
        """Set setting value"""
        keys = key.split('.')
        setting = self._settings
        for k in keys[:-1]:
            if k not in setting:
                setting[k] = {}
            setting = setting[k]
        setting[keys[-1]] = value
        self._save_settings()
    
    def get_all(self) -> Dict[str, Any]:
        """Get all settings"""
        return self._settings.copy()

# Global instance
global_settings = GlobalSettings()