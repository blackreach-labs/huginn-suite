# app/core/component_singleton.py
from typing import Dict, Any

class ComponentSingleton:
    """Ensures only one instance of each component type per tenant"""
    
    _instances = {}
    
    @classmethod
    def get_instance(cls, component_type: str, tenant_id: str, factory_func):
        """Get or create singleton instance"""
        key = f"{component_type}_{tenant_id}"
        
        if key not in cls._instances:
            cls._instances[key] = factory_func()
            print(f"DEBUG: Created {component_type} for tenant: {tenant_id}")
        
        return cls._instances[key]
    
    @classmethod
    def clear_tenant(cls, tenant_id: str):
        """Clear all instances for a tenant"""
        keys_to_remove = [k for k in cls._instances.keys() if k.endswith(f"_{tenant_id}")]
        for key in keys_to_remove:
            del cls._instances[key]

# Global singleton manager
component_singleton = ComponentSingleton()