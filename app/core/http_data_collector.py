# app/core/http_data_collector.py
from .listener_manager import listener_manager

def create_http_collector(tenant_id):
    """Create HTTP data collector instance"""
    return HTTPDataCollector(tenant_id)

class HTTPDataCollector:
    def __init__(self, tenant_id):
        self.tenant_id = tenant_id
        self.scan_id = None
    
    def start_http_scan(self, target, scanner, scan_subtype):
        """Start HTTP scan data collection"""
        self.scan_id = f"{scanner}_{target}_{scan_subtype}"
        return self.scan_id
    
    def complete_http_scan(self, total_results=0, error_message=None):
        """Complete HTTP scan data collection"""
        pass
    
    def collect_directories(self, target, directories):
        """Collect directory enumeration results"""
        pass
    
    def collect_headers(self, target, headers_info):
        """Collect HTTP headers information"""
        pass
    
    def collect_vulnerabilities(self, target, vulnerabilities):
        """Collect vulnerability information"""
        pass
    
    def collect_oob_hits(self):
        """Collect all OOB hits recorded by the listener manager"""
        return listener_manager.get_oob_hits()