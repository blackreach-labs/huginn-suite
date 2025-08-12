from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from dataclasses import dataclass

@dataclass
class PluginMetadata:
    name: str
    version: str
    description: str
    author: str
    category: str
    dependencies: list = None
    
    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []

class PluginInterface(ABC):
    """Base interface for all Huggin plugins"""
    
    @abstractmethod
    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata"""
        pass
    
    @abstractmethod
    def initialize(self, context: Dict[str, Any]) -> bool:
        """Initialize plugin with context"""
        pass
    
    @abstractmethod
    def execute(self, *args, **kwargs) -> Any:
        """Execute plugin functionality"""
        pass
    
    @abstractmethod
    def cleanup(self) -> None:
        """Cleanup plugin resources"""
        pass
    
    def validate_dependencies(self) -> bool:
        """Validate plugin dependencies"""
        return True
    
    def get_config_schema(self) -> Optional[Dict[str, Any]]:
        """Return configuration schema"""
        return None