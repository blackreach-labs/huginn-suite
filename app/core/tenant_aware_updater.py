# app/core/tenant_aware_updater.py
from typing import Dict, Optional
from PyQt6.QtCore import QObject, pyqtSignal
from .realtime_data_updater import RealtimeDataManager

class TenantAwareUpdaterManager(QObject):
    """Manages real-time updates with proper tenant switching"""
    
    tenant_changed = pyqtSignal(str, str)  # old_tenant, new_tenant
    
    def __init__(self):
        super().__init__()
        self.current_tenant = "default"
        self.active_updater = None
        self.realtime_manager = RealtimeDataManager()
        
    def set_tenant(self, tenant_id: str):
        """Switch to new tenant and update all components"""
        if tenant_id == self.current_tenant:
            return
            
        old_tenant = self.current_tenant
        
        # Stop current updater
        if self.active_updater:
            self.active_updater.stop_updates()
            
        # Switch to new tenant
        self.current_tenant = tenant_id
        self.active_updater = self.realtime_manager.get_updater(tenant_id)
        self.active_updater.start_updates()
        
        # Emit signal for components to update
        self.tenant_changed.emit(old_tenant, tenant_id)
        print(f"Switched real-time updates from tenant: {old_tenant} to tenant: {tenant_id}")
        
    def get_current_tenant(self) -> str:
        """Get current active tenant"""
        return self.current_tenant
        
    def get_updater(self, tenant_id: Optional[str] = None) -> 'RealtimeDataUpdater':
        """Get current active updater"""
        return self.active_updater
        
    def stop_all_updates(self):
        """Stop all active updates"""
        if self.active_updater:
            self.active_updater.stop_updates()

# Global instance
tenant_aware_updater = TenantAwareUpdaterManager()