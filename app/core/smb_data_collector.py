# app/core/smb_data_collector.py
from .centralized_scan_data import create_centralized_scan_data
from datetime import datetime
import hashlib

class SMBDataCollector:
    """SMB-specific data collector with centralized storage"""
    
    def __init__(self, tenant_id: str = "default"):
        self.tenant_id = tenant_id
        self.db = create_centralized_scan_data()
        self.current_scan_id = None
    
    def start_smb_scan(self, target: str, scanner_name: str) -> str:
        """Start SMB scan and return scan ID"""
        import uuid
        self.current_scan_id = str(uuid.uuid4())
        self.db.start_scan(
            scan_id=self.current_scan_id,
            tenant_id=self.tenant_id,
            scan_type="smb_enum",
            target=target,
            scanner=scanner_name
        )
        return self.current_scan_id
    
    def collect_shares(self, target: str, shares: list):
        """Collect SMB shares with deduplication"""
        for share in shares:
            if isinstance(share, dict):
                # New structured share data
                self.db.add_scan_result(
                    scan_id=self.current_scan_id,
                    tenant_id=self.tenant_id,
                    scan_type="smb_shares",
                    target=target,
                    scanner="smb_scanner",
                    result_data={
                        "target": target,
                        "share_name": share.get('name', 'Unknown'),
                        "exists": share.get('exists', False),
                        "anonymous_access": share.get('anonymous_access', False),
                        "status_code": share.get('status', 0),
                        "discovered_at": datetime.now().isoformat(),
                        "scan_id": self.current_scan_id
                    }
                )
            else:
                # Legacy string format
                self.db.add_scan_result(
                    scan_id=self.current_scan_id,
                    tenant_id=self.tenant_id,
                    scan_type="smb_shares",
                    target=target,
                    scanner="smb_scanner",
                    result_data={
                        "target": target,
                        "share_name": share,
                        "discovered_at": datetime.now().isoformat(),
                        "scan_id": self.current_scan_id
                    }
                )
    
    def collect_ports(self, target: str, ports: list):
        """Collect SMB ports with deduplication"""
        for port_info in ports:
            # Extract port number
            port = port_info.split(' ')[0] if ' ' in port_info else port_info
            
            self.db.add_scan_result(
                scan_id=self.current_scan_id,
                tenant_id=self.tenant_id,
                scan_type="smb_ports",
                target=target,
                scanner="smb_scanner",
                result_data={
                    "target": target,
                    "port": port,
                    "service": "SMB",
                    "description": port_info,
                    "discovered_at": datetime.now().isoformat(),
                    "scan_id": self.current_scan_id
                }
            )
    
    def collect_vulnerabilities(self, target: str, vulnerabilities: list):
        """Collect SMB vulnerabilities"""
        for vuln in vulnerabilities:
            self.db.add_scan_result(
                scan_id=self.current_scan_id,
                tenant_id=self.tenant_id,
                scan_type="smb_vulnerabilities",
                target=target,
                scanner="smb_scanner",
                result_data={
                    "target": target,
                    "vulnerability_name": vuln['name'],
                    "severity": vuln.get('severity', 'medium'),
                    "description": vuln.get('description', ''),
                    "discovered_at": datetime.now().isoformat(),
                    "scan_id": self.current_scan_id
                }
            )
    
    def collect_smb_capabilities(self, target: str, capabilities: dict):
        """Collect SMB capabilities and security posture"""
        self.db.add_scan_result(
            scan_id=self.current_scan_id,
            tenant_id=self.tenant_id,
            scan_type="smb_capabilities",
            target=target,
            scanner="smb_scanner",
            result_data={
                "target": target,
                "negotiation": capabilities.get('negotiation', {}),
                "security": capabilities.get('security', {}),
                "session": capabilities.get('session', {}),
                "discovered_at": datetime.now().isoformat(),
                "scan_id": self.current_scan_id
            }
        )
    
    def collect_smb_services(self, target: str, services: list):
        """Collect available SMB services (pipes)"""
        for service in services:
            if isinstance(service, dict):
                self.db.add_scan_result(
                    scan_id=self.current_scan_id,
                    tenant_id=self.tenant_id,
                    scan_type="smb_services",
                    target=target,
                    scanner="smb_scanner",
                    result_data={
                        "target": target,
                        "service_name": service.get('name', 'Unknown'),
                        "status_code": service.get('status', 0),
                        "available": service.get('status', 0) != 0xC0000034,
                        "discovered_at": datetime.now().isoformat(),
                        "scan_id": self.current_scan_id
                    }
                )
    
    def complete_smb_scan(self, results_count: int, error: str = None):
        """Complete SMB scan"""
        if self.current_scan_id:
            self.db.complete_scan(self.current_scan_id, results_count, error)
    
    def get_smb_data(self, target: str = None) -> dict:
        """Get all SMB data for tenant"""
        data = {}
        
        # Get shares
        shares_data = self.db.get_scan_data(self.tenant_id, "smb_shares", target)
        data['shares'] = shares_data
        
        # Get ports
        ports_data = self.db.get_scan_data(self.tenant_id, "smb_ports", target)
        data['ports'] = ports_data
        
        # Get vulnerabilities
        vulns_data = self.db.get_scan_data(self.tenant_id, "smb_vulnerabilities", target)
        data['vulnerabilities'] = vulns_data
        
        return data
    
    def get_smb_data_for_ui(self, scan_type: str, target: str = None) -> dict:
        """Get SMB data formatted for UI components"""
        if scan_type == "smb_shares":
            shares_data = self.db.get_scan_data(self.tenant_id, "smb_shares", target)
            return {
                'table_data': [{
                    'Target': item['data'].get('target', 'Unknown'),
                    'Share Name': item['data'].get('share_name', str(item['data'])),
                    'Discovered': item['data'].get('discovered_at', item.get('timestamp', ''))[:19],
                    'Count': item.get('count', 1)
                } for item in shares_data],
                'graph_data': {
                    'SMB Shares': {
                        'count': len(shares_data),
                        'details': f"{len(set(item.get('target', 'Unknown') for item in shares_data))} targets",
                        'children': {}
                    }
                },
                'summary': {'total_shares': len(shares_data)}
            }
        
        elif scan_type == "smb_ports":
            ports_data = self.db.get_scan_data(self.tenant_id, "smb_ports", target)
            return {
                'table_data': [{
                    'Target': item['data'].get('target', 'Unknown'),
                    'Port': item['data'].get('port', 'Unknown'),
                    'Service': item['data'].get('service', 'SMB'),
                    'Description': item['data'].get('description', ''),
                    'Count': item.get('count', 1)
                } for item in ports_data],
                'graph_data': {
                    'SMB Ports': {
                        'count': len(ports_data),
                        'details': f"{len(set(item.get('target', 'Unknown') for item in ports_data))} targets",
                        'children': {}
                    }
                },
                'summary': {'total_ports': len(ports_data)}
            }
        
        elif scan_type == "smb_vulnerabilities":
            vulns_data = self.db.get_scan_data(self.tenant_id, "smb_vulnerabilities", target)
            return {
                'table_data': [{
                    'Target': item['data'].get('target', 'Unknown'),
                    'Vulnerability': item['data'].get('vulnerability_name', 'Unknown'),
                    'Severity': item['data'].get('severity', 'medium').upper(),
                    'Description': item['data'].get('description', ''),
                    'Count': item.get('count', 1)
                } for item in vulns_data],
                'graph_data': {
                    'SMB Vulnerabilities': {
                        'count': len(vulns_data),
                        'details': f"{len(set(item.get('target', 'Unknown') for item in vulns_data))} targets",
                        'children': {}
                    }
                },
                'summary': {'total_vulnerabilities': len(vulns_data)}
            }
        
        elif scan_type == "smb_capabilities":
            caps_data = self.db.get_scan_data(self.tenant_id, "smb_capabilities", target)
            return {
                'table_data': [{
                    'Target': item['data'].get('target', 'Unknown'),
                    'Dialect': item['data'].get('negotiation', {}).get('dialect', 'Unknown'),
                    'Signing': 'Required' if item['data'].get('security', {}).get('signing_required', False) else 'Optional',
                    'Guest': 'Yes' if item['data'].get('session', {}).get('is_guest', False) else 'No',
                    'Time Skew': f"{item['data'].get('negotiation', {}).get('time_skew_ms', 0)//1000}s",
                    'Count': item.get('count', 1)
                } for item in caps_data],
                'graph_data': {
                    'SMB Capabilities': {
                        'count': len(caps_data),
                        'details': f"{len(set(item.get('target', 'Unknown') for item in caps_data))} targets",
                        'children': {}
                    }
                },
                'summary': {'total_capabilities': len(caps_data)}
            }
        
        elif scan_type == "smb_services":
            services_data = self.db.get_scan_data(self.tenant_id, "smb_services", target)
            return {
                'table_data': [{
                    'Target': item['data'].get('target', 'Unknown'),
                    'Service': item['data'].get('service_name', 'Unknown'),
                    'Available': 'Yes' if item['data'].get('available', False) else 'No',
                    'Status Code': hex(item['data'].get('status_code', 0)),
                    'Count': item.get('count', 1)
                } for item in services_data],
                'graph_data': {
                    'SMB Services': {
                        'count': len(services_data),
                        'details': f"{len(set(item.get('target', 'Unknown') for item in services_data))} targets",
                        'children': {}
                    }
                },
                'summary': {'total_services': len(services_data)}
            }
        
        else:
            # Return all SMB data
            all_data = self.get_smb_data(target)
            return {
                'table_data': [],
                'graph_data': {
                    'SMB Shares': {'count': len(all_data.get('shares', [])), 'details': 'Network shares', 'children': {}},
                    'SMB Ports': {'count': len(all_data.get('ports', [])), 'details': 'Open ports', 'children': {}},
                    'SMB Vulnerabilities': {'count': len(all_data.get('vulnerabilities', [])), 'details': 'Security issues', 'children': {}}
                },
                'summary': {
                    'total_shares': len(all_data.get('shares', [])),
                    'total_ports': len(all_data.get('ports', [])),
                    'total_vulnerabilities': len(all_data.get('vulnerabilities', []))
                }
            }

def create_smb_collector(tenant_id: str = "default") -> SMBDataCollector:
    """Create SMB data collector for specific tenant"""
    return SMBDataCollector(tenant_id=tenant_id)