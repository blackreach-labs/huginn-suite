# app/core/snmp_data_collector.py
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional
from .centralized_scan_data import centralized_scan_data

class SNMPDataCollector:
    """SNMP-specific data collector that feeds into centralized system"""
    
    def __init__(self, tenant_id: str = "default"):
        self.tenant_id = tenant_id
        self.scan_type = "snmp"
        self.current_scan_id = None
    
    def start_snmp_scan(self, target: str, scanner: str, scan_subtype: str = "enumeration") -> str:
        """Start a new SNMP scan session"""
        self.current_scan_id = f"snmp_{uuid.uuid4().hex[:8]}_{int(datetime.now().timestamp())}"
        
        centralized_scan_data.start_scan(
            scan_id=self.current_scan_id,
            tenant_id=self.tenant_id,
            scan_type=f"{self.scan_type}_{scan_subtype}",
            target=target,
            scanner=scanner
        )
        
        return self.current_scan_id
    
    def collect_community_strings(self, target: str, communities: List[str]) -> bool:
        """Collect valid SNMP community strings"""
        if not self.current_scan_id:
            return False
        
        for community in communities:
            result_data = {
                'type': 'snmp_community',
                'target': target,
                'community': community,
                'access_level': 'read',  # Could be enhanced to detect read/write
                'timestamp': datetime.now().isoformat()
            }
            
            centralized_scan_data.add_scan_result(
                scan_id=self.current_scan_id,
                tenant_id=self.tenant_id,
                scan_type="snmp_communities",
                target=target,
                scanner="snmp_community_scanner",
                result_data=result_data
            )
        
        return True
    
    def collect_system_info(self, target: str, system_info: Dict) -> bool:
        """Collect SNMP system information"""
        if not self.current_scan_id:
            return False
        
        result_data = {
            'type': 'snmp_system_info',
            'target': target,
            'system_description': system_info.get('system_description', 'Unknown'),
            'system_uptime': system_info.get('system_uptime', ''),
            'system_contact': system_info.get('system_contact', ''),
            'system_name': system_info.get('system_name', ''),
            'system_location': system_info.get('system_location', ''),
            'timestamp': datetime.now().isoformat()
        }
        
        centralized_scan_data.add_scan_result(
            scan_id=self.current_scan_id,
            tenant_id=self.tenant_id,
            scan_type="snmp_system_info",
            target=target,
            scanner="snmp_system_scanner",
            result_data=result_data
        )
        
        return True
    
    def collect_users(self, target: str, users: List[str]) -> bool:
        """Collect SNMP user information"""
        if not self.current_scan_id:
            return False
        
        for user in users:
            result_data = {
                'type': 'snmp_user',
                'target': target,
                'username': user,
                'source': 'snmp_enumeration',
                'timestamp': datetime.now().isoformat()
            }
            
            centralized_scan_data.add_scan_result(
                scan_id=self.current_scan_id,
                tenant_id=self.tenant_id,
                scan_type="snmp_users",
                target=target,
                scanner="snmp_user_enumerator",
                result_data=result_data
            )
        
        return True
    
    def collect_network_interfaces(self, target: str, interfaces: List[str]) -> bool:
        """Collect SNMP network interface information"""
        if not self.current_scan_id:
            return False
        
        for interface in interfaces:
            result_data = {
                'type': 'snmp_interface',
                'target': target,
                'interface_name': interface,
                'interface_type': 'unknown',
                'status': 'unknown',
                'timestamp': datetime.now().isoformat()
            }
            
            centralized_scan_data.add_scan_result(
                scan_id=self.current_scan_id,
                tenant_id=self.tenant_id,
                scan_type="snmp_interfaces",
                target=target,
                scanner="snmp_interface_scanner",
                result_data=result_data
            )
        
        return True
    
    def collect_processes(self, target: str, processes: List[Dict]) -> bool:
        """Collect SNMP process information"""
        if not self.current_scan_id:
            return False
        
        for process in processes:
            result_data = {
                'type': 'snmp_process',
                'target': target,
                'process_name': process.get('name', 'Unknown'),
                'process_id': process.get('pid', 0),
                'process_path': process.get('path', ''),
                'process_args': process.get('args', ''),
                'timestamp': datetime.now().isoformat()
            }
            
            centralized_scan_data.add_scan_result(
                scan_id=self.current_scan_id,
                tenant_id=self.tenant_id,
                scan_type="snmp_processes",
                target=target,
                scanner="snmp_process_scanner",
                result_data=result_data
            )
        
        return True
    
    def collect_installed_software(self, target: str, software: List[Dict]) -> bool:
        """Collect SNMP installed software information"""
        if not self.current_scan_id:
            return False
        
        for sw in software:
            result_data = {
                'type': 'snmp_software',
                'target': target,
                'software_name': sw.get('name', 'Unknown'),
                'software_version': sw.get('version', ''),
                'install_date': sw.get('install_date', ''),
                'timestamp': datetime.now().isoformat()
            }
            
            centralized_scan_data.add_scan_result(
                scan_id=self.current_scan_id,
                tenant_id=self.tenant_id,
                scan_type="snmp_software",
                target=target,
                scanner="snmp_software_scanner",
                result_data=result_data
            )
        
        return True
    
    def complete_snmp_scan(self, total_results: int = 0, error_message: str = None) -> bool:
        """Complete the current SNMP scan"""
        if not self.current_scan_id:
            return False
        
        success = centralized_scan_data.complete_scan(
            scan_id=self.current_scan_id,
            total_results=total_results,
            error_message=error_message
        )
        
        self.current_scan_id = None
        return success
    
    def get_snmp_data_for_ui(self, scan_type: str, target: str = None) -> Dict:
        """Get SNMP data formatted for UI consumption"""
        raw_data = centralized_scan_data.get_scan_data(
            tenant_id=self.tenant_id,
            scan_type=scan_type,
            target=target
        )
        
        ui_data = {
            'table_data': [],
            'graph_data': {},
            'summary': centralized_scan_data.get_scan_summary(
                tenant_id=self.tenant_id,
                scan_type=scan_type
            )
        }
        
        if scan_type == "snmp_communities":
            ui_data['table_data'] = [{
                'Community': item['data'].get('community', 'Unknown'),
                'Access Level': item['data'].get('access_level', 'read'),
                'First Seen': item['first_seen'],
                'Last Seen': item['last_seen'],
                'Count': item['count']
            } for item in raw_data]
            
        elif scan_type == "snmp_system_info":
            ui_data['table_data'] = [{
                'System Name': item['data'].get('system_name', 'Unknown'),
                'Description': item['data'].get('system_description', ''),
                'Contact': item['data'].get('system_contact', ''),
                'Location': item['data'].get('system_location', ''),
                'First Seen': item['first_seen'],
                'Count': item['count']
            } for item in raw_data]
            
        elif scan_type == "snmp_users":
            ui_data['table_data'] = [{
                'Username': item['data'].get('username', 'Unknown'),
                'Source': item['data'].get('source', 'snmp'),
                'First Seen': item['first_seen'],
                'Last Seen': item['last_seen'],
                'Count': item['count']
            } for item in raw_data]
            
        elif scan_type == "snmp_interfaces":
            ui_data['table_data'] = [{
                'Interface': item['data'].get('interface_name', 'Unknown'),
                'Type': item['data'].get('interface_type', 'unknown'),
                'Status': item['data'].get('status', 'unknown'),
                'First Seen': item['first_seen'],
                'Count': item['count']
            } for item in raw_data]
        
        ui_data['graph_data'] = self._generate_snmp_graph_data(scan_type, raw_data)
        return ui_data
    
    def _generate_snmp_graph_data(self, scan_type: str, raw_data: List[Dict]) -> Dict:
        """Generate graph data for SNMP results"""
        if scan_type == "snmp_communities":
            access_levels = {}
            for item in raw_data:
                level = item['data'].get('access_level', 'read')
                if level not in access_levels:
                    access_levels[level] = {'count': 0, 'communities': []}
                access_levels[level]['count'] += item['count']
                access_levels[level]['communities'].append(item['data'].get('community', 'Unknown'))
            
            return {
                'SNMP Communities': {
                    'count': len(raw_data),
                    'details': f"Total valid communities",
                    'children': {level: {
                        'count': data['count'],
                        'details': f"{data['count']} {level} access"
                    } for level, data in access_levels.items()}
                }
            }
            
        elif scan_type == "snmp_system_info":
            return {
                'SNMP Systems': {
                    'count': len(raw_data),
                    'details': f"Total systems enumerated",
                    'children': {
                        'Named Systems': {
                            'count': len([item for item in raw_data if item['data'].get('system_name', 'Unknown') != 'Unknown']),
                            'details': "Systems with configured names"
                        }
                    }
                }
            }
        
        return {}

def create_snmp_collector(tenant_id: str = "default") -> SNMPDataCollector:
    """Create SNMP data collector for specific tenant"""
    return SNMPDataCollector(tenant_id=tenant_id)