# app/core/rpc_data_collector.py
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional
from .centralized_scan_data import centralized_scan_data

class RPCDataCollector:
    """RPC-specific data collector that feeds into centralized system"""
    
    def __init__(self, tenant_id: str = "default"):
        self.tenant_id = tenant_id
        self.scan_type = "rpc"
        self.current_scan_id = None
    
    def start_rpc_scan(self, target: str, scanner: str, scan_subtype: str = "enumeration") -> str:
        """Start a new RPC scan session"""
        self.current_scan_id = f"rpc_{uuid.uuid4().hex[:8]}_{int(datetime.now().timestamp())}"
        
        # Register scan start
        centralized_scan_data.start_scan(
            scan_id=self.current_scan_id,
            tenant_id=self.tenant_id,
            scan_type=f"{self.scan_type}_{scan_subtype}",
            target=target,
            scanner=scanner
        )
        
        return self.current_scan_id
    
    def collect_rpc_endpoints(self, target: str, endpoints: List[Dict]) -> bool:
        """Collect RPC endpoint data"""
        if not self.current_scan_id:
            return False
        
        for endpoint in endpoints:
            result_data = {
                'type': 'rpc_endpoint',
                'target': target,
                'protocol': endpoint.get('protocol', 'Unknown'),
                'uuid': endpoint.get('uuid', ''),
                'port': endpoint.get('port', 'unknown'),
                'version_major': endpoint.get('version_major', 0),
                'version_minor': endpoint.get('version_minor', 0),
                'annotation': endpoint.get('annotation', ''),
                'timestamp': datetime.now().isoformat()
            }
            
            centralized_scan_data.add_scan_result(
                scan_id=self.current_scan_id,
                tenant_id=self.tenant_id,
                scan_type="rpc_endpoints",
                target=target,
                scanner="rpc_enumerator",
                result_data=result_data
            )
        
        return True
    
    def collect_rpc_services(self, target: str, services: List[Dict]) -> bool:
        """Collect Windows services data"""
        if not self.current_scan_id:
            return False
        
        for service in services:
            result_data = {
                'type': 'windows_service',
                'target': target,
                'name': service.get('name', 'Unknown'),
                'display_name': service.get('display_name', ''),
                'state': service.get('state', 'Unknown'),
                'start_type': service.get('start_type', ''),
                'service_type': service.get('service_type', ''),
                'binary_path': service.get('binary_path', ''),
                'timestamp': datetime.now().isoformat()
            }
            
            centralized_scan_data.add_scan_result(
                scan_id=self.current_scan_id,
                tenant_id=self.tenant_id,
                scan_type="rpc_services",
                target=target,
                scanner="service_enumerator",
                result_data=result_data
            )
        
        return True
    
    def collect_rpc_vulnerabilities(self, target: str, vulnerabilities: List[Dict]) -> bool:
        """Collect RPC vulnerability data"""
        if not self.current_scan_id:
            return False
        
        for vuln in vulnerabilities:
            result_data = {
                'type': 'rpc_vulnerability',
                'target': target,
                'name': vuln.get('name', 'Unknown Vulnerability'),
                'severity': vuln.get('severity', 'info'),
                'cve': vuln.get('cve', ''),
                'interface': vuln.get('interface', ''),
                'description': vuln.get('description', ''),
                'impact': vuln.get('impact', ''),
                'remediation': vuln.get('remediation', ''),
                'exploitable': vuln.get('exploitable', False),
                'timestamp': datetime.now().isoformat()
            }
            
            centralized_scan_data.add_scan_result(
                scan_id=self.current_scan_id,
                tenant_id=self.tenant_id,
                scan_type="rpc_vulnerabilities",
                target=target,
                scanner="vulnerability_scanner",
                result_data=result_data
            )
        
        return True
    
    def collect_rpc_security_issues(self, target: str, issues: List[Dict]) -> bool:
        """Collect RPC security issues"""
        if not self.current_scan_id:
            return False
        
        for issue in issues:
            result_data = {
                'type': 'rpc_security_issue',
                'target': target,
                'name': issue.get('name', 'Unknown Issue'),
                'severity': issue.get('severity', 'info'),
                'interface': issue.get('interface', ''),
                'description': issue.get('description', ''),
                'risk': issue.get('risk', ''),
                'category': issue.get('category', 'general'),
                'timestamp': datetime.now().isoformat()
            }
            
            centralized_scan_data.add_scan_result(
                scan_id=self.current_scan_id,
                tenant_id=self.tenant_id,
                scan_type="rpc_security_issues",
                target=target,
                scanner="security_analyzer",
                result_data=result_data
            )
        
        return True
    
    def collect_network_endpoints(self, target: str, endpoints: List[Dict]) -> bool:
        """Collect network endpoint data"""
        if not self.current_scan_id:
            return False
        
        for endpoint in endpoints:
            result_data = {
                'type': 'network_endpoint',
                'target': target,
                'port': endpoint.get('port', 0),
                'protocol': endpoint.get('protocol', 'tcp'),
                'service': endpoint.get('service', 'Unknown'),
                'state': endpoint.get('state', 'open'),
                'banner': endpoint.get('banner', ''),
                'version': endpoint.get('version', ''),
                'timestamp': datetime.now().isoformat()
            }
            
            centralized_scan_data.add_scan_result(
                scan_id=self.current_scan_id,
                tenant_id=self.tenant_id,
                scan_type="rpc_network_endpoints",
                target=target,
                scanner="network_scanner",
                result_data=result_data
            )
        
        return True
    
    def collect_registry_data(self, target: str, registry_info: Dict) -> bool:
        """Collect registry enumeration data"""
        if not self.current_scan_id:
            return False
        
        result_data = {
            'type': 'registry_data',
            'target': target,
            'accessible': registry_info.get('accessible', False),
            'os_info': registry_info.get('os_info', {}),
            'keys_enumerated': registry_info.get('keys_enumerated', []),
            'timestamp': datetime.now().isoformat()
        }
        
        centralized_scan_data.add_scan_result(
            scan_id=self.current_scan_id,
            tenant_id=self.tenant_id,
            scan_type="rpc_registry",
            target=target,
            scanner="registry_enumerator",
            result_data=result_data
        )
        
        return True
    
    def collect_samr_data(self, target: str, samr_info: Dict) -> bool:
        """Collect SAMR enumeration data"""
        if not self.current_scan_id:
            return False
        
        result_data = {
            'type': 'samr_data',
            'target': target,
            'domains': samr_info.get('domains', []),
            'users': samr_info.get('sample_users', []),
            'groups': samr_info.get('groups', []),
            'password_policy': samr_info.get('password_policy', {}),
            'timestamp': datetime.now().isoformat()
        }
        
        centralized_scan_data.add_scan_result(
            scan_id=self.current_scan_id,
            tenant_id=self.tenant_id,
            scan_type="rpc_samr",
            target=target,
            scanner="samr_enumerator",
            result_data=result_data
        )
        
        return True
    
    def collect_lsa_data(self, target: str, lsa_info: Dict) -> bool:
        """Collect LSA enumeration data"""
        if not self.current_scan_id:
            return False
        
        result_data = {
            'type': 'lsa_data',
            'target': target,
            'domain_name': lsa_info.get('domain_name', ''),
            'trusted_domains': lsa_info.get('trusted_domains', []),
            'policy_info': lsa_info.get('policy_info', {}),
            'timestamp': datetime.now().isoformat()
        }
        
        centralized_scan_data.add_scan_result(
            scan_id=self.current_scan_id,
            tenant_id=self.tenant_id,
            scan_type="rpc_lsa",
            target=target,
            scanner="lsa_enumerator",
            result_data=result_data
        )
        
        return True
    
    def collect_shares_data(self, target: str, shares: List[Dict]) -> bool:
        """Collect SMB shares data"""
        if not self.current_scan_id:
            return False
        
        for share in shares:
            result_data = {
                'type': 'smb_share',
                'target': target,
                'name': share.get('name', 'Unknown'),
                'type': share.get('type', 'Unknown'),
                'permissions': share.get('permissions', 'Unknown'),
                'comment': share.get('comment', ''),
                'accessible': share.get('accessible', False),
                'timestamp': datetime.now().isoformat()
            }
            
            centralized_scan_data.add_scan_result(
                scan_id=self.current_scan_id,
                tenant_id=self.tenant_id,
                scan_type="rpc_shares",
                target=target,
                scanner="share_enumerator",
                result_data=result_data
            )
        
        return True
    
    def collect_enhancement_data(self, target: str, enhancements: Dict) -> bool:
        """Collect RPC enhancement data"""
        if not self.current_scan_id:
            return False
        
        # Collect different enhancement types
        enhancement_types = [
            'runecraft_payloads', 'memory_loader', 'shell_capabilities',
            'relay_capabilities', 'token_impersonation', 'dcom_alpc_summary'
        ]
        
        for enhancement_type in enhancement_types:
            if enhancement_type in enhancements:
                result_data = {
                    'type': f'rpc_enhancement_{enhancement_type}',
                    'target': target,
                    'enhancement_type': enhancement_type,
                    'data': enhancements[enhancement_type],
                    'timestamp': datetime.now().isoformat()
                }
                
                centralized_scan_data.add_scan_result(
                    scan_id=self.current_scan_id,
                    tenant_id=self.tenant_id,
                    scan_type="rpc_enhancements",
                    target=target,
                    scanner="enhancement_integrator",
                    result_data=result_data
                )
        
        return True
    
    def complete_rpc_scan(self, total_results: int = 0, error_message: str = None) -> bool:
        """Complete the current RPC scan"""
        if not self.current_scan_id:
            return False
        
        success = centralized_scan_data.complete_scan(
            scan_id=self.current_scan_id,
            total_results=total_results,
            error_message=error_message
        )
        
        self.current_scan_id = None
        return success
    
    def get_rpc_data_summary(self, target: str = None) -> Dict:
        """Get summary of all RPC data for tenant"""
        rpc_scan_types = [
            "rpc_endpoints", "rpc_services", "rpc_vulnerabilities", 
            "rpc_security_issues", "rpc_network_endpoints", "rpc_registry",
            "rpc_samr", "rpc_lsa", "rpc_enhancements"
        ]
        
        summary = {}
        for scan_type in rpc_scan_types:
            summary[scan_type] = centralized_scan_data.get_scan_summary(
                tenant_id=self.tenant_id,
                scan_type=scan_type
            )
        
        return summary
    
    def get_rpc_data_for_ui(self, scan_type: str, target: str = None) -> Dict:
        """Get RPC data formatted for UI consumption"""
        raw_data = centralized_scan_data.get_scan_data(
            tenant_id=self.tenant_id,
            scan_type=scan_type,
            target=target
        )
        
        # Transform data for UI
        ui_data = {
            'table_data': [],
            'graph_data': {},
            'summary': centralized_scan_data.get_scan_summary(
                tenant_id=self.tenant_id,
                scan_type=scan_type
            )
        }
        
        # Format table data based on scan type
        if scan_type == "rpc_endpoints":
            ui_data['table_data'] = [{
                'Protocol': item['data'].get('protocol', 'Unknown'),
                'UUID': item['data'].get('uuid', 'N/A'),
                'Port': item['data'].get('port', 'unknown'),
                'First Seen': item['first_seen'],
                'Last Seen': item['last_seen'],
                'Count': item['count']
            } for item in raw_data]
            
        elif scan_type == "rpc_services":
            ui_data['table_data'] = [{
                'Service Name': item['data'].get('name', 'Unknown'),
                'Display Name': item['data'].get('display_name', ''),
                'State': item['data'].get('state', 'Unknown'),
                'First Seen': item['first_seen'],
                'Last Seen': item['last_seen'],
                'Count': item['count']
            } for item in raw_data]
            
        elif scan_type == "rpc_vulnerabilities":
            ui_data['table_data'] = [{
                'Vulnerability': item['data'].get('name', 'Unknown'),
                'Severity': item['data'].get('severity', 'info'),
                'CVE': item['data'].get('cve', ''),
                'Interface': item['data'].get('interface', ''),
                'Exploitable': 'Yes' if item['data'].get('exploitable') else 'No',
                'First Seen': item['first_seen'],
                'Count': item['count']
            } for item in raw_data]
        
        # Generate graph data
        ui_data['graph_data'] = self._generate_graph_data(scan_type, raw_data)
        
        return ui_data
    
    def _generate_graph_data(self, scan_type: str, raw_data: List[Dict]) -> Dict:
        """Generate graph data structure for UI"""
        if scan_type == "rpc_endpoints":
            protocols = {}
            for item in raw_data:
                protocol = item['data'].get('protocol', 'Unknown')
                if protocol not in protocols:
                    protocols[protocol] = {'count': 0, 'details': []}
                protocols[protocol]['count'] += item['count']
                protocols[protocol]['details'].append({
                    'uuid': item['data'].get('uuid', 'N/A'),
                    'port': item['data'].get('port', 'unknown')
                })
            
            return {
                'RPC Endpoints': {
                    'count': len(raw_data),
                    'details': f"Total unique endpoints",
                    'children': {protocol: {
                        'count': data['count'],
                        'details': f"{data['count']} instances"
                    } for protocol, data in protocols.items()}
                }
            }
            
        elif scan_type == "rpc_services":
            states = {}
            for item in raw_data:
                state = item['data'].get('state', 'Unknown')
                if state not in states:
                    states[state] = {'count': 0, 'services': []}
                states[state]['count'] += item['count']
                states[state]['services'].append(item['data'].get('name', 'Unknown'))
            
            return {
                'Windows Services': {
                    'count': len(raw_data),
                    'details': f"Total unique services",
                    'children': {state: {
                        'count': data['count'],
                        'details': f"{data['count']} services"
                    } for state, data in states.items()}
                }
            }
            
        elif scan_type == "rpc_vulnerabilities":
            severities = {}
            for item in raw_data:
                severity = item['data'].get('severity', 'info')
                if severity not in severities:
                    severities[severity] = {'count': 0, 'vulns': []}
                severities[severity]['count'] += item['count']
                severities[severity]['vulns'].append(item['data'].get('name', 'Unknown'))
            
            return {
                'RPC Vulnerabilities': {
                    'count': len(raw_data),
                    'details': f"Total vulnerabilities found",
                    'children': {severity: {
                        'count': data['count'],
                        'details': f"{data['count']} {severity} severity"
                    } for severity, data in severities.items()}
                }
            }
        
        return {}

# Factory function to create tenant-specific collectors
def create_rpc_collector(tenant_id: str = "default") -> RPCDataCollector:
    """Create RPC data collector for specific tenant"""
    return RPCDataCollector(tenant_id=tenant_id)