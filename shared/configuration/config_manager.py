"""Configuration management for the Huginn application."""
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional
from dataclasses import dataclass, asdict
from ..events.event_bus import EventBus
from ..events.plugin_events import PluginLoadedEvent
import logging


@dataclass
class ScannerConfig:
    """Scanner configuration settings."""
    timeout: int = 30
    max_concurrent: int = 50
    retry_count: int = 3
    user_agent: str = "Huginn-Scanner/1.0"
    rate_limit: int = 10

@dataclass
class PluginConfig:
    """Plugin configuration settings."""
    enabled: bool = True
    auto_load: bool = True
    plugin_dirs: list = None
    max_execution_time: int = 300
    
    def __post_init__(self):
        if self.plugin_dirs is None:
            self.plugin_dirs = ['plugins']


class ConfigManager:
    """Manages application configuration."""
    
    def __init__(self, config_path: Optional[str] = None, event_bus: Optional[EventBus] = None):
        self.config_path = config_path or self._get_default_config_path()
        self.event_bus = event_bus
        self.config = self._load_config()
    
    def _get_default_config_path(self) -> str:
        """Get default configuration file path."""
        return os.path.join(os.path.dirname(__file__), "..", "..", "resources", "config", "app_config.json")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file."""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as _exc:
                pass
                logging.debug("Suppressed exception", exc_info=True)
        return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            "scanner": asdict(ScannerConfig()),
            "plugins": asdict(PluginConfig()),
            "database": {
                "path": "resources/centralized_scan_data.db",
                "timeout": 30
            },
            "ui": {
                "theme": "default",
                "update_interval": 1000
            },
            "performance": {
                "monitoring_enabled": True,
                "collection_interval": 1.0,
                "max_memory_mb": 1024
            }
        }
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value."""
        keys = key.split('.')
        value = self.config
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value
    
    def set(self, key: str, value: Any) -> None:
        """Set configuration value."""
        keys = key.split('.')
        config = self.config
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        config[keys[-1]] = value
        self._save_config()
    
    def _save_config(self) -> None:
        """Save configuration to file."""
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    def get_scanner_config(self) -> ScannerConfig:
        """Get scanner configuration."""
        scanner_data = self.get("scanner", {})
        return ScannerConfig(**scanner_data)
    
    def get_plugin_config(self) -> PluginConfig:
        """Get plugin configuration."""
        plugin_data = self.get("plugins", {})
        return PluginConfig(**plugin_data)
    
    def reload_config(self) -> None:
        """Reload configuration from file."""
        self.config = self._load_config()