# app/tools/scan_plugins/base_plugin.py
from abc import ABC, abstractmethod

class BaseScanPlugin(ABC):
    """Base class for HTTP scan plugins"""
    
    def __init__(self, name, description):
        self.name = name
        self.description = description
    
    @abstractmethod
    def scan(self, url, response, session):
        """Perform scan and return results"""
        pass
    
    def is_applicable(self, response):
        """Check if plugin is applicable to this response"""
        return True