# app/pages/components/page_factory.py
from typing import Dict, Type, Optional
from .base_page import BasePage

class PageFactory:
    """Factory for creating page instances with dependency injection."""
    
    _page_registry: Dict[str, Type[BasePage]] = {}
    _page_instances: Dict[str, BasePage] = {}
    
    @classmethod
    def register_page(cls, page_name: str, page_class: Type[BasePage]):
        """Register a page class with the factory."""
        cls._page_registry[page_name] = page_class
    
    @classmethod
    def create_page(cls, page_name: str, parent=None, **kwargs) -> Optional[BasePage]:
        """Create a page instance with dependency injection."""
        if page_name not in cls._page_registry:
            raise ValueError(f"Page '{page_name}' not registered")
        
        # Check if instance already exists (singleton pattern)
        if page_name in cls._page_instances:
            return cls._page_instances[page_name]
        
        page_class = cls._page_registry[page_name]
        page_instance = page_class(parent, **kwargs)
        
        # Store instance for reuse
        cls._page_instances[page_name] = page_instance
        
        return page_instance
    
    @classmethod
    def get_registered_pages(cls) -> Dict[str, Type[BasePage]]:
        """Get all registered page classes."""
        return cls._page_registry.copy()
    
    @classmethod
    def clear_instances(cls):
        """Clear all cached page instances."""
        for instance in cls._page_instances.values():
            if hasattr(instance, 'cleanup'):
                instance.cleanup()
        cls._page_instances.clear()
    
    @classmethod
    def get_page_instance(cls, page_name: str) -> Optional[BasePage]:
        """Get existing page instance if available."""
        return cls._page_instances.get(page_name)
    
    @classmethod
    def destroy_page(cls, page_name: str):
        """Destroy a specific page instance."""
        if page_name in cls._page_instances:
            instance = cls._page_instances[page_name]
            if hasattr(instance, 'cleanup'):
                instance.cleanup()
            del cls._page_instances[page_name]