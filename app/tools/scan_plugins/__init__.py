# app/tools/scan_plugins/__init__.py
from .security_plugin import SecurityPlugin
from .ai_ssti_plugin import AISSTIPlugin

def get_available_plugins():
    """Return list of available scan plugins"""
    return [
        SecurityPlugin(),
        AISSTIPlugin(None)  # Will be initialized with session later
    ]

__all__ = ['SecurityPlugin', 'AISSTIPlugin', 'get_available_plugins']