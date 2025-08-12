# app/core/ui_data_integration.py
from typing import Dict, List, Optional, Callable
from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtWidgets import QTreeWidget, QTreeWidgetItem, QTableWidget, QTableWidgetItem
from .realtime_data_updater import realtime_data_manager
from .rpc_data_collector import create_rpc_collector

class UIDataIntegration(QObject):
    """Integration layer between centralized data and UI components"""
    
    # Signals for UI updates
    table_update_signal = pyqtSignal(str, list)  # scan_type, table_data
    graph_update_signal = pyqtSignal(str, dict)  # scan_type, graph_data
    
    def __init__(self, tenant_id: str = "default"):
        super().__init__()
        self.tenant_id = tenant_id
        self.updater = realtime_data_manager.get_updater(tenant_id)
        
        # Connect updater signals
        self.updater.data_updated.connect(self.handle_data_update)
        self.updater.summary_updated.connect(self.handle_summary_update)
        
        # Track registered UI components
        self.table_widgets = {}  # scan_type -> QTableWidget
        self.tree_widgets = {}   # scan_type -> QTreeWidget
        self.update_callbacks = {}  # scan_type -> callback function
        
        # RPC data collector
        self.rpc_collector = create_rpc_collector(tenant_id)
    
    def register_table_widget(self, scan_type: str, table_widget: QTableWidget):
        """Register a table widget for automatic updates"""
        self.table_widgets[scan_type] = table_widget
        self.updater.register_scan_type(scan_type)
        
        # Initial data load
        self.update_table_widget(scan_type)
    
    def register_tree_widget(self, scan_type: str, tree_widget: QTreeWidget):
        """Register a tree widget for automatic updates"""
        self.tree_widgets[scan_type] = tree_widget
        self.updater.register_scan_type(scan_type)
        
        # Initial data load
        self.update_tree_widget(scan_type)
    
    def register_update_callback(self, scan_type: str, callback: Callable):
        """Register a custom update callback for scan type"""
        self.update_callbacks[scan_type] = callback
        self.updater.register_scan_type(scan_type, callback)
    
    def handle_data_update(self, scan_type: str, tenant_id: str, data: Dict):
        """Handle data update from real-time updater"""
        if tenant_id != self.tenant_id:
            return
        
        # Update table widget if registered
        if scan_type in self.table_widgets:
            self.update_table_widget_with_data(scan_type, data)
        
        # Update tree widget if registered
        if scan_type in self.tree_widgets:
            self.update_tree_widget_with_data(scan_type, data)
        
        # Emit signals for external handlers
        if 'table_data' in data:
            self.table_update_signal.emit(scan_type, data['table_data'])
        
        if 'graph_data' in data:
            self.graph_update_signal.emit(scan_type, data['graph_data'])
    
    def handle_summary_update(self, tenant_id: str, summary: Dict):
        """Handle summary update from real-time updater"""
        if tenant_id != self.tenant_id:
            return
        
        # Process summary updates
        print(f"Summary updated for tenant {tenant_id}: {len(summary.get('scan_types', {}))} scan types")
    
    def update_table_widget(self, scan_type: str):
        """Update table widget with latest data"""
        if scan_type not in self.table_widgets:
            return
        
        # Get data from collector
        if scan_type.startswith('rpc_'):
            data = self.rpc_collector.get_rpc_data_for_ui(scan_type)
        else:
            # Handle other scan types
            return
        
        self.update_table_widget_with_data(scan_type, data)
    
    def update_table_widget_with_data(self, scan_type: str, data: Dict):
        """Update table widget with provided data"""
        table_widget = self.table_widgets.get(scan_type)
        if not table_widget or 'table_data' not in data:
            return
        
        table_data = data['table_data']
        if not table_data:
            return
        
        try:
            # Clear existing data
            table_widget.setRowCount(0)
            
            # Set headers if data exists
            if table_data:
                headers = list(table_data[0].keys())
                table_widget.setColumnCount(len(headers))
                table_widget.setHorizontalHeaderLabels(headers)
                
                # Add rows
                table_widget.setRowCount(len(table_data))
                for row_idx, row_data in enumerate(table_data):
                    for col_idx, (key, value) in enumerate(row_data.items()):\n                        item = QTableWidgetItem(str(value))\n                        table_widget.setItem(row_idx, col_idx, item)\n                \n                # Resize columns to content\n                table_widget.resizeColumnsToContents()\n        \n        except Exception as e:\n            print(f\"Error updating table widget for {scan_type}: {e}\")\n    \n    def update_tree_widget(self, scan_type: str):\n        \"\"\"Update tree widget with latest data\"\"\"\n        if scan_type not in self.tree_widgets:\n            return\n        \n        # Get data from collector\n        if scan_type.startswith('rpc_'):\n            data = self.rpc_collector.get_rpc_data_for_ui(scan_type)\n        else:\n            return\n        \n        self.update_tree_widget_with_data(scan_type, data)\n    \n    def update_tree_widget_with_data(self, scan_type: str, data: Dict):\n        \"\"\"Update tree widget with provided data\"\"\"\n        tree_widget = self.tree_widgets.get(scan_type)\n        if not tree_widget or 'graph_data' not in data:\n            return\n        \n        graph_data = data['graph_data']\n        if not graph_data:\n            return\n        \n        try:\n            # Clear existing items\n            tree_widget.clear()\n            \n            # Build tree structure\n            for category, category_data in graph_data.items():\n                category_item = QTreeWidgetItem([category, str(category_data.get('count', 0))])\n                tree_widget.addTopLevelItem(category_item)\n                \n                # Add children if they exist\n                children = category_data.get('children', {})\n                for child_name, child_data in children.items():\n                    child_item = QTreeWidgetItem([\n                        child_name, \n                        str(child_data.get('count', 0)),\n                        child_data.get('details', '')\n                    ])\n                    category_item.addChild(child_item)\n                \n                # Expand category\n                category_item.setExpanded(True)\n        \n        except Exception as e:\n            print(f\"Error updating tree widget for {scan_type}: {e}\")\n    \n    def start_real_time_updates(self):\n        \"\"\"Start real-time updates\"\"\"\n        self.updater.start_updates()\n    \n    def stop_real_time_updates(self):\n        \"\"\"Stop real-time updates\"\"\"\n        self.updater.stop_updates()\n    \n    def force_update(self, scan_type: str = None):\n        \"\"\"Force immediate update\"\"\"\n        self.updater.force_update(scan_type)\n    \n    def get_scan_summary(self, scan_type: str) -> Dict:\n        \"\"\"Get summary for specific scan type\"\"\"\n        if scan_type.startswith('rpc_'):\n            return self.rpc_collector.get_rpc_data_summary().get(scan_type, {})\n        return {}\n    \n    def export_scan_data(self, scan_type: str, format: str = 'json') -> str:\n        \"\"\"Export scan data in specified format\"\"\"\n        if scan_type.startswith('rpc_'):\n            data = self.rpc_collector.get_rpc_data_for_ui(scan_type)\n        else:\n            return \"\"\n        \n        if format == 'json':\n            import json\n            return json.dumps(data, indent=2, default=str)\n        elif format == 'csv':\n            return self._export_csv(data.get('table_data', []))\n        else:\n            return \"\"\n    \n    def _export_csv(self, table_data: List[Dict]) -> str:\n        \"\"\"Export table data as CSV\"\"\"\n        if not table_data:\n            return \"\"\n        \n        import csv\n        import io\n        \n        output = io.StringIO()\n        writer = csv.DictWriter(output, fieldnames=table_data[0].keys())\n        writer.writeheader()\n        writer.writerows(table_data)\n        \n        return output.getvalue()\n\nclass RPCUIIntegration(UIDataIntegration):\n    \"\"\"RPC-specific UI integration with enhanced features\"\"\"\n    \n    def __init__(self, tenant_id: str = \"default\"):\n        super().__init__(tenant_id)\n        \n        # RPC-specific scan types\n        self.rpc_scan_types = [\n            \"rpc_endpoints\", \"rpc_services\", \"rpc_vulnerabilities\",\n            \"rpc_security_issues\", \"rpc_network_endpoints\", \"rpc_registry\",\n            \"rpc_samr\", \"rpc_lsa\", \"rpc_enhancements\"\n        ]\n    \n    def register_rpc_components(self, components: Dict[str, object]):\n        \"\"\"Register multiple RPC UI components at once\"\"\"\n        for scan_type, component in components.items():\n            if scan_type in self.rpc_scan_types:\n                if hasattr(component, 'setRowCount'):  # Table widget\n                    self.register_table_widget(scan_type, component)\n                elif hasattr(component, 'addTopLevelItem'):  # Tree widget\n                    self.register_tree_widget(scan_type, component)\n                elif callable(component):  # Callback function\n                    self.register_update_callback(scan_type, component)\n    \n    def get_rpc_overview(self) -> Dict:\n        \"\"\"Get comprehensive RPC scan overview\"\"\"\n        overview = {\n            'total_endpoints': 0,\n            'total_services': 0,\n            'total_vulnerabilities': 0,\n            'total_security_issues': 0,\n            'scan_types': {}\n        }\n        \n        for scan_type in self.rpc_scan_types:\n            summary = self.get_scan_summary(scan_type)\n            overview['scan_types'][scan_type] = summary\n            \n            # Aggregate totals\n            if scan_type == 'rpc_endpoints':\n                overview['total_endpoints'] = summary.get('total_results', 0)\n            elif scan_type == 'rpc_services':\n                overview['total_services'] = summary.get('total_results', 0)\n            elif scan_type == 'rpc_vulnerabilities':\n                overview['total_vulnerabilities'] = summary.get('total_results', 0)\n            elif scan_type == 'rpc_security_issues':\n                overview['total_security_issues'] = summary.get('total_results', 0)\n        \n        return overview\n    \n    def export_all_rpc_data(self, format: str = 'json') -> str:\n        \"\"\"Export all RPC data for tenant\"\"\"\n        all_data = {}\n        \n        for scan_type in self.rpc_scan_types:\n            data = self.rpc_collector.get_rpc_data_for_ui(scan_type)\n            if data.get('table_data'):\n                all_data[scan_type] = data\n        \n        all_data['overview'] = self.get_rpc_overview()\n        all_data['export_timestamp'] = __import__('datetime').datetime.now().isoformat()\n        \n        if format == 'json':\n            import json\n            return json.dumps(all_data, indent=2, default=str)\n        else:\n            return \"\"\n\n# Factory function for creating UI integrations\ndef create_ui_integration(tenant_id: str = \"default\", scan_type: str = \"generic\") -> UIDataIntegration:\n    \"\"\"Create appropriate UI integration based on scan type\"\"\"\n    if scan_type == \"rpc\" or scan_type.startswith(\"rpc_\"):\n        return RPCUIIntegration(tenant_id)\n    else:\n        return UIDataIntegration(tenant_id)