# app/core/component_deduplication.py
from typing import Dict, Any

class ComponentRegistry:
    """Prevents duplicate component creation"""
    
    def __init__(self):
        self._components = {}
        self._tenant_components = {}
        
    def get_or_create(self, component_type: str, tenant_id: str, factory_func):
        """Get existing component or create new one"""
        key = f"{component_type}_{tenant_id}"
        
        if key not in self._components:
            self._components[key] = factory_func()
            print(f"DEBUG: Created {component_type} for tenant: {tenant_id}")
        else:
            print(f"DEBUG: Reusing existing {component_type} for tenant: {tenant_id}")
            
        return self._components[key]
        
    def clear_tenant(self, tenant_id: str):
        """Clear all components for a tenant"""
        keys_to_remove = [k for k in self._components.keys() if k.endswith(f"_{tenant_id}")]
        for key in keys_to_remove:
            del self._components[key]

# Global registry
component_registry = ComponentRegistry()