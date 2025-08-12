# app/core/config.py
import json
import os
from pathlib import Path
from app.core.logger import logger

class ConfigManager:
    """Manages application configuration and user preferences"""
    
    def __init__(self, config_file="config.json"):
        self.config_file = Path(config_file)
        self.config = self._load_default_config()
        self.load_config()
    
    def _load_default_config(self):
        """Returns default configuration values"""
        return {
            "dns": {
                "timeout": 3,
                "lifetime": 10,
                "max_workers": min(50, (os.cpu_count() or 1) * 5),
                "wildcard_test_count": 3,
                "wildcard_test_length": 12
            },
            "ui": {
                "animation_duration": 500,
                "auto_scroll": True,
                "show_timestamps": False,
                "theme": "default"
            },
            "export": {
                "default_format": "json",
                "include_metadata": True,
                "auto_timestamp": True
            },
            "logging": {
                "level": "INFO",
                "max_log_files": 30,
                "max_file_size_mb": 10
            },
            "security": {
                "max_wordlist_size_mb": 100,
                "validate_inputs": True,
                "sanitize_outputs": True,
                "ssl_verify": False,
                "suppress_ssl_warnings": True
            }
        }
    
    def load_config(self):
        """Load configuration from file"""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    file_config = json.load(f)
                    # Merge with defaults (file config takes precedence)
                    self._merge_config(self.config, file_config)
                logger.info(f"Configuration loaded from {self.config_file}")
            else:
                logger.info("Using default configuration")
        except Exception as e:
            logger.error(f"Error loading config file: {e}")
            logger.info("Using default configuration")
    
    def save_config(self):
        """Save current configuration to file"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=4)
            logger.info(f"Configuration saved to {self.config_file}")
            return True
        except Exception as e:
            logger.error(f"Error saving config file: {e}")
            return False
    
    def _merge_config(self, default, override):
        """Recursively merge configuration dictionaries"""
        for key, value in override.items():
            if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                self._merge_config(default[key], value)
            else:
                default[key] = value
    
    def get(self, key_path, default=None):
        """Get configuration value using dot notation (e.g., 'dns.timeout')"""
        keys = key_path.split('.')
        value = self.config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value
    
    def set(self, key_path, value, validate=True):
        """Set configuration value using dot notation"""
        if validate and not self._validate_config_value(key_path, value):
            raise ValueError(f"Invalid value for {key_path}: {value}")
            
        keys = key_path.split('.')
        config = self.config
        
        # Navigate to the parent dictionary
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        
        # Set the value
        config[keys[-1]] = value
        logger.debug(f"Config updated: {key_path} = {value}")
        
    def _validate_config_value(self, key_path, value):
        """Validate configuration values"""
        validators = {
            'dns.timeout': lambda x: isinstance(x, (int, float)) and 0 < x <= 30,
            'dns.max_workers': lambda x: isinstance(x, int) and 1 <= x <= 200,
            'ui.animation_duration': lambda x: isinstance(x, int) and 0 <= x <= 2000,
            'logging.level': lambda x: x in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        }
        
        validator = validators.get(key_path)
        return validator(value) if validator else True
    
    def get_dns_config(self):
        """Get DNS-specific configuration"""
        return self.config.get("dns", {})
    
    def get_ui_config(self):
        """Get UI-specific configuration"""
        return self.config.get("ui", {})
    
    def get_export_config(self):
        """Get export-specific configuration"""
        return self.config.get("export", {})
    
    def reset_to_defaults(self):
        """Reset configuration to default values"""
        self.config = self._load_default_config()
        self.save_config()
        logger.info("Configuration reset to defaults")
        
    def backup_config(self):
        """Create backup of current configuration"""
        backup_file = self.config_file.with_suffix('.backup.json')
        try:
            if self.config_file.exists():
                import shutil
                shutil.copy2(self.config_file, backup_file)
                logger.info(f"Configuration backed up to {backup_file}")
                return True
        except Exception as e:
            logger.error(f"Failed to backup config: {e}")
        return False

# Global configuration instance
config = ConfigManager()