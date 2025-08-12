# app/core/unified_ui_integration.py
from typing import Dict, List, Optional
from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtWidgets import QTreeWidget, QTreeWidgetItem, QTableWidget, QTableWidgetItem
from .realtime_data_updater import realtime_data_manager
from .rpc_data_collector import create_rpc_collector
from .dns_data_collector import create_dns_collector
from .port_data_collector import create_port_collector
from .http_data_collector import create_http_collector
from .smb_data_collector import create_smb_collector

class UnifiedUIIntegration(QObject):
    """Unified UI integration for all scan types"""
    
    data_updated = pyqtSignal(str, dict)  # scan_type, data
    
    def __init__(self, tenant_id: str = "default"):
        super().__init__()
        self.tenant_id = tenant_id
        self.updater = realtime_data_manager.get_updater(tenant_id)
        
        # Connect updater signals
        self.updater.data_updated.connect(self.handle_data_update)
        
        # Data collectors
        self.rpc_collector = create_rpc_collector(tenant_id)
        self.dns_collector = create_dns_collector(tenant_id)
        self.port_collector = create_port_collector(tenant_id)
        self.http_collector = create_http_collector(tenant_id)
        self.smb_collector = create_smb_collector(tenant_id)
        
        # UI components registry
        self.components = {}
    
    def register_component(self, scan_type: str, component_type: str, component):
        """Register UI component for automatic updates"""
        if scan_type not in self.components:
            self.components[scan_type] = {}
        
        self.components[scan_type][component_type] = component
        self.updater.register_scan_type(scan_type)
    
    def handle_data_update(self, scan_type: str, tenant_id: str, data: Dict):
        """Handle data updates from real-time updater"""
        if tenant_id != self.tenant_id:
            return
        
        # Update registered components
        if scan_type in self.components:
            components = self.components[scan_type]
            
            # Update table widget
            if 'table' in components and 'table_data' in data:
                self.update_table(components['table'], data['table_data'])
            
            # Update tree widget
            if 'tree' in components and 'graph_data' in data:
                self.update_tree(components['tree'], data['graph_data'])
        
        # Emit signal for custom handlers
        self.data_updated.emit(scan_type, data)
    
    def update_table(self, table_widget: QTableWidget, table_data: List[Dict]):
        """Update table widget with data"""
        if not table_data:
            return
        
        try:
            table_widget.setRowCount(0)
            headers = list(table_data[0].keys())
            table_widget.setColumnCount(len(headers))
            table_widget.setHorizontalHeaderLabels(headers)
            
            table_widget.setRowCount(len(table_data))
            for row_idx, row_data in enumerate(table_data):
                for col_idx, (key, value) in enumerate(row_data.items()):
                    item = QTableWidgetItem(str(value))
                    table_widget.setItem(row_idx, col_idx, item)
            
            table_widget.resizeColumnsToContents()
        except Exception as e:
            print(f"Error updating table: {e}")
    
    def update_tree(self, tree_widget: QTreeWidget, graph_data: Dict):
        """Update tree widget with graph data"""
        try:
            tree_widget.clear()
            
            for category, category_data in graph_data.items():
                category_item = QTreeWidgetItem([
                    category, 
                    str(category_data.get('count', 0)),
                    category_data.get('details', '')
                ])
                tree_widget.addTopLevelItem(category_item)
                
                # Add children
                children = category_data.get('children', {})
                for child_name, child_data in children.items():
                    child_item = QTreeWidgetItem([
                        child_name,
                        str(child_data.get('count', 0)),
                        child_data.get('details', '')
                    ])
                    category_item.addChild(child_item)
                
                category_item.setExpanded(True)
        except Exception as e:
            print(f"Error updating tree: {e}")
    
    def get_data_for_scan_type(self, scan_type: str, target: str = None) -> Dict:
        """Get formatted data for specific scan type"""
        if scan_type.startswith('rpc_'):
            return self.rpc_collector.get_rpc_data_for_ui(scan_type, target)
        elif scan_type.startswith('dns_'):
            return self.dns_collector.get_dns_data_for_ui(scan_type, target)
        elif scan_type.startswith('port_'):
            return self.port_collector.get_port_data_for_ui(scan_type, target)
        elif scan_type.startswith('http_'):
            return self.http_collector.get_http_data_for_ui(scan_type, target)
        elif scan_type.startswith('smb_'):
            return self.smb_collector.get_smb_data_for_ui(scan_type, target)
        else:
            return {'table_data': [], 'graph_data': {}, 'summary': {}}
    
    def start_real_time_updates(self):
        """Start real-time updates"""
        self.updater.start_updates()
    
    def stop_real_time_updates(self):
        """Stop real-time updates"""
        self.updater.stop_updates()
    
    def force_update(self, scan_type: str = None):
        """Force immediate update"""
        self.updater.force_update(scan_type)

def create_unified_integration(tenant_id: str = "default") -> UnifiedUIIntegration:
    """Create unified UI integration for tenant"""
    return UnifiedUIIntegration(tenant_id)