# app/core/dns_data_collector.py
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional
from .centralized_scan_data import centralized_scan_data

class DNSDataCollector:
    """DNS-specific data collector that feeds into centralized system"""
    
    def __init__(self, tenant_id: str = "default"):
        self.tenant_id = tenant_id
        self.scan_type = "dns"
        self.current_scan_id = None
    
    def start_dns_scan(self, target: str, scanner: str, scan_subtype: str = "enumeration") -> str:
        """Start a new DNS scan session"""
        self.current_scan_id = f"dns_{uuid.uuid4().hex[:8]}_{int(datetime.now().timestamp())}"
        
        centralized_scan_data.start_scan(
            scan_id=self.current_scan_id,
            tenant_id=self.tenant_id,
            scan_type=f"{self.scan_type}_{scan_subtype}",
            target=target,
            scanner=scanner
        )
        
        return self.current_scan_id
    
    def collect_subdomains(self, target: str, subdomains: List[str]) -> bool:
        """Collect subdomain enumeration data"""
        if not self.current_scan_id:
            return False
        
        for subdomain in subdomains:
            result_data = {
                'type': 'subdomain',
                'target': target,
                'subdomain': subdomain,
                'domain': target,
                'timestamp': datetime.now().isoformat()
            }
            
            centralized_scan_data.add_scan_result(
                scan_id=self.current_scan_id,
                tenant_id=self.tenant_id,
                scan_type="dns_subdomains",
                target=target,
                scanner="subdomain_enumerator",
                result_data=result_data
            )
        
        return True
    
    def collect_dns_records(self, target: str, records: List[Dict]) -> bool:
        """Collect DNS record data"""
        if not self.current_scan_id:
            return False
        
        for record in records:
            result_data = {
                'type': 'dns_record',
                'target': target,
                'record_type': record.get('type', 'A'),
                'name': record.get('name', ''),
                'value': record.get('value', ''),
                'ttl': record.get('ttl', 0),
                'timestamp': datetime.now().isoformat()
            }
            
            centralized_scan_data.add_scan_result(
                scan_id=self.current_scan_id,
                tenant_id=self.tenant_id,
                scan_type="dns_records",
                target=target,
                scanner="dns_resolver",
                result_data=result_data
            )
        
        return True
    
    def collect_zone_transfer(self, target: str, zone_data: Dict) -> bool:
        """Collect DNS zone transfer data"""
        if not self.current_scan_id:
            return False
        
        result_data = {
            'type': 'zone_transfer',
            'target': target,
            'success': zone_data.get('success', False),
            'records_count': len(zone_data.get('records', [])),
            'nameserver': zone_data.get('nameserver', ''),
            'records': zone_data.get('records', []),
            'timestamp': datetime.now().isoformat()
        }
        
        centralized_scan_data.add_scan_result(
            scan_id=self.current_scan_id,
            tenant_id=self.tenant_id,
            scan_type="dns_zone_transfer",
            target=target,
            scanner="zone_transfer_scanner",
            result_data=result_data
        )
        
        return True
    
    def complete_dns_scan(self, total_results: int = 0, error_message: str = None) -> bool:
        """Complete the current DNS scan"""
        if not self.current_scan_id:
            return False
        
        success = centralized_scan_data.complete_scan(
            scan_id=self.current_scan_id,
            total_results=total_results,
            error_message=error_message
        )
        
        self.current_scan_id = None
        return success
    
    def get_dns_data_for_ui(self, scan_type: str, target: str = None) -> Dict:
        """Get DNS data formatted for UI consumption"""
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
        
        if scan_type == "dns_subdomains":
            ui_data['table_data'] = [{
                'Subdomain': item['data'].get('subdomain', 'Unknown'),
                'Domain': item['data'].get('domain', 'Unknown'),
                'First Seen': item['first_seen'],
                'Last Seen': item['last_seen'],
                'Count': item['count']
            } for item in raw_data]
            
        elif scan_type == "dns_records":
            ui_data['table_data'] = [{
                'Name': item['data'].get('name', 'Unknown'),
                'Type': item['data'].get('record_type', 'A'),
                'Value': item['data'].get('value', ''),
                'TTL': item['data'].get('ttl', 0),
                'First Seen': item['first_seen'],
                'Count': item['count']
            } for item in raw_data]
        
        ui_data['graph_data'] = self._generate_dns_graph_data(scan_type, raw_data)
        return ui_data
    
    def _generate_dns_graph_data(self, scan_type: str, raw_data: List[Dict]) -> Dict:
        """Generate graph data for DNS results"""
        if scan_type == "dns_subdomains":
            domains = {}
            for item in raw_data:
                domain = item['data'].get('domain', 'Unknown')
                if domain not in domains:
                    domains[domain] = {'count': 0, 'subdomains': []}
                domains[domain]['count'] += item['count']
                domains[domain]['subdomains'].append(item['data'].get('subdomain', ''))
            
            return {
                'DNS Subdomains': {
                    'count': len(raw_data),
                    'details': f"Total unique subdomains",
                    'children': {domain: {
                        'count': data['count'],
                        'details': f"{data['count']} subdomains"
                    } for domain, data in domains.items()}
                }
            }
        
        return {}

def create_dns_collector(tenant_id: str = "default") -> DNSDataCollector:
    """Create DNS data collector for specific tenant"""
    return DNSDataCollector(tenant_id=tenant_id)