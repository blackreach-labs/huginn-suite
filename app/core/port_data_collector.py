# app/core/port_data_collector.py
from datetime import datetime
from typing import Dict, List, Optional
from .centralized_scan_data import centralized_scan_data

class PortDataCollector:
    """Centralized data collector for port scanning results"""
    
    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id
        self.current_scan_id = None
    
    def start_port_scan(self, target: str, scanner: str, scan_subtype: str = "port_scan") -> str:
        """Start a new port scan session"""
        import uuid
        scan_id = str(uuid.uuid4())
        centralized_scan_data.start_scan(
            scan_id=scan_id,
            tenant_id=self.tenant_id,
            scan_type="port_scan",
            target=target,
            scanner=scanner
        )
        self.current_scan_id = scan_id
        return self.current_scan_id
    
    def collect_ping_sweep_results(self, target: str, results: List[Dict]) -> bool:
        """Collect ping sweep results"""
        if not self.current_scan_id:
            return False
        
        for result in results:
            result_data = {
                'type': 'ping_result',
                'target': target,
                'ip_address': result.get('ip', 'Unknown'),
                'status': result.get('status', 'Unknown'),
                'response_time': result.get('response_time', 0),
                'timestamp': datetime.now().isoformat()
            }
            
            centralized_scan_data.add_scan_result(
                scan_id=self.current_scan_id,
                tenant_id=self.tenant_id,
                scan_type="ping_sweep",
                target=target,
                scanner="ping_scanner",
                result_data=result_data
            )
        
        return True
    
    def collect_port_scan_results(self, target: str, results: List[Dict]) -> bool:
        """Collect targeted port scan results"""
        if not self.current_scan_id:
            return False
        
        for result in results:
            result_data = {
                'type': 'port_scan_result',
                'target': target,
                'ip_address': result.get('ip', target),
                'port': result.get('port', 'Unknown'),
                'status': result.get('status', 'open'),
                'service': result.get('service', 'Unknown'),
                'details': result.get('service', 'Unknown'),  # Use service as details for targeted scan
                'protocol': result.get('protocol', 'tcp'),
                'timestamp': datetime.now().isoformat()
            }
            
            centralized_scan_data.add_scan_result(
                scan_id=self.current_scan_id,
                tenant_id=self.tenant_id,
                scan_type="port_scan",
                target=target,
                scanner="port_scanner",
                result_data=result_data
            )
        
        return True
    
    def collect_open_ports(self, target: str, ports: List[Dict]) -> bool:
        """Collect open ports data"""
        if not self.current_scan_id:
            return False
        
        for port_info in ports:
            result_data = {
                'type': 'open_port',
                'target': target,
                'port': port_info.get('port', 'Unknown'),
                'service': port_info.get('service', 'Unknown'),
                'protocol': port_info.get('protocol', 'tcp'),
                'state': port_info.get('state', 'open'),
                'banner': port_info.get('banner', ''),
                'timestamp': datetime.now().isoformat()
            }
            
            centralized_scan_data.add_scan_result(
                scan_id=self.current_scan_id,
                tenant_id=self.tenant_id,
                scan_type="open_ports",
                target=target,
                scanner="port_scanner",
                result_data=result_data
            )
        
        return True
    
    def complete_port_scan(self, total_results: int = 0, error_message: str = None) -> bool:
        """Complete the port scan session"""
        if not self.current_scan_id:
            return False
        
        success = centralized_scan_data.complete_scan(
            scan_id=self.current_scan_id,
            total_results=total_results,
            error_message=error_message
        )
        
        self.current_scan_id = None
        return success

def create_port_collector(tenant_id: str) -> PortDataCollector:
    """Factory function to create port data collector"""
    return PortDataCollector(tenant_id)