# app/core/realtime_data_updater.py
import threading
import time
from typing import Dict, List, Callable, Optional
from PyQt6.QtCore import QObject, pyqtSignal, QTimer
from .centralized_scan_data import centralized_scan_data
from .rpc_data_collector import create_rpc_collector

class RealtimeDataUpdater(QObject):
    """Real-time data updater that refreshes UI components every 5 seconds"""
    
    # Signals for UI updates
    data_updated = pyqtSignal(str, str, dict)  # scan_type, tenant_id, data
    summary_updated = pyqtSignal(str, dict)    # tenant_id, summary
    
    def __init__(self, tenant_id: str = "default"):
        super().__init__()
        self.tenant_id = tenant_id
        self.update_interval = 1000  # 1 second in milliseconds
        self.timer = None
        
        # Track registered scan types and their callbacks
        self.registered_scan_types = set()
        self.ui_callbacks = {}
        
        # Data cache to detect changes
        self.data_cache = {}
        
        # RPC collector for this tenant
        self.rpc_collector = create_rpc_collector(tenant_id)
        
        self.running = False
    
    def register_scan_type(self, scan_type: str, callback: Optional[Callable] = None):
        """Register a scan type for real-time updates"""
        self.registered_scan_types.add(scan_type)
        if callback:
            self.ui_callbacks[scan_type] = callback
    
    def unregister_scan_type(self, scan_type: str):
        """Unregister a scan type from real-time updates"""
        self.registered_scan_types.discard(scan_type)
        self.ui_callbacks.pop(scan_type, None)
    
    def start_updates(self):
        """Start real-time updates"""
        if not self.running:
            self.running = True
            # Create timer in main thread
            from PyQt6.QtWidgets import QApplication
            if QApplication.instance():
                self.timer = QTimer()
                self.timer.timeout.connect(self.update_all_data)
                self.timer.start(self.update_interval)
                print(f"Started real-time updates for tenant: {self.tenant_id}")
    
    def stop_updates(self):
        """Stop real-time updates"""
        if self.running:
            self.running = False
            if self.timer:
                self.timer.stop()
                self.timer = None
            print(f"Stopped real-time updates for tenant: {self.tenant_id}")
    
    def update_all_data(self):
        """Update all registered scan types"""
        if not self.running:
            return
        
        try:
            # Update each registered scan type
            for scan_type in self.registered_scan_types:
                self.update_scan_type_data(scan_type)
            
            # Update tenant summary
            self.update_tenant_summary()
            
        except Exception as e:
            print(f"Error in real-time update: {e}")
    
    def update_scan_type_data(self, scan_type: str):
        """Update data for specific scan type"""
        try:
            # Get current data
            if scan_type.startswith('rpc_'):
                current_data = self.rpc_collector.get_rpc_data_for_ui(scan_type)
            else:
                # For other scan types, get raw data
                raw_data = centralized_scan_data.get_scan_data(
                    tenant_id=self.tenant_id,
                    scan_type=scan_type
                )
                current_data = self._format_generic_data(scan_type, raw_data)
            
            # Check if data has changed
            cache_key = f"{self.tenant_id}_{scan_type}"
            if cache_key not in self.data_cache or self.data_cache[cache_key] != current_data:
                self.data_cache[cache_key] = current_data
                
                # Emit signal for UI update
                self.data_updated.emit(scan_type, self.tenant_id, current_data)
                
                # Call registered callback if exists
                if scan_type in self.ui_callbacks:
                    try:
                        self.ui_callbacks[scan_type](current_data)
                    except Exception as e:
                        print(f"Error calling callback for {scan_type}: {e}")
        
        except Exception as e:
            print(f"Error updating {scan_type}: {e}")
    
    def update_tenant_summary(self):
        """Update tenant overview summary"""
        try:
            # Skip tenant overview for now to avoid errors
            return
            
            # Check if summary has changed
            cache_key = f"{self.tenant_id}_summary"
            if cache_key not in self.data_cache or self.data_cache[cache_key] != current_summary:
                self.data_cache[cache_key] = current_summary
                self.summary_updated.emit(self.tenant_id, current_summary)
        
        except Exception as e:
            print(f"Error getting tenant overview: {e}")
    
    def force_update(self, scan_type: str = None):
        """Force immediate update of specific scan type or all"""
        if scan_type:
            if scan_type in self.registered_scan_types:
                self.update_scan_type_data(scan_type)
        else:
            self.update_all_data()
    
    def get_current_data(self, scan_type: str) -> Dict:
        """Get current cached data for scan type"""
        cache_key = f"{self.tenant_id}_{scan_type}"
        return self.data_cache.get(cache_key, {})
    
    def clear_cache(self):
        """Clear data cache"""
        self.data_cache.clear()
    
    def _format_generic_data(self, scan_type: str, raw_data: List[Dict]) -> Dict:
        """Format generic scan data for UI"""
        return {
            'table_data': [{
                'Type': item['data'].get('type', 'Unknown'),
                'Target': item['target'],
                'Scanner': item['scanner'],
                'First Seen': item['first_seen'],
                'Last Seen': item['last_seen'],
                'Count': item['count']
            } for item in raw_data],
            'graph_data': {
                scan_type.replace('_', ' ').title(): {
                    'count': len(raw_data),
                    'details': f"Total {scan_type} results",
                    'children': {}
                }
            },
            'summary': centralized_scan_data.get_scan_summary(
                tenant_id=self.tenant_id,
                scan_type=scan_type
            )
        }

class RealtimeDataManager:
    """Manager for multiple tenant updaters"""
    
    def __init__(self):
        self.updaters = {}
        self.lock = threading.Lock()
    
    def get_updater(self, tenant_id: str = "default") -> RealtimeDataUpdater:
        """Get or create updater for tenant"""
        with self.lock:
            if tenant_id not in self.updaters:
                self.updaters[tenant_id] = RealtimeDataUpdater(tenant_id)
            return self.updaters[tenant_id]
    
    def start_all_updates(self):
        """Start updates for all tenants"""
        with self.lock:
            for updater in self.updaters.values():
                updater.start_updates()
    
    def stop_all_updates(self):
        """Stop updates for all tenants"""
        with self.lock:
            for updater in self.updaters.values():
                updater.stop_updates()
    
    def cleanup_tenant(self, tenant_id: str):
        """Clean up updater for tenant"""
        with self.lock:
            if tenant_id in self.updaters:
                self.updaters[tenant_id].stop_updates()
                del self.updaters[tenant_id]

# Global manager instance
realtime_data_manager = RealtimeDataManager()