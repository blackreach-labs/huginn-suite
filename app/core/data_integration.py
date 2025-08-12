# app/core/data_integration.py
import re
import json
from typing import Dict, List, Optional
from .pentest_database import pentest_db

class DataIntegration:
    """Integrates scan results into centralized database"""
    
    def __init__(self):
        self.db = pentest_db
    
    def process_scan_results(self, target: str, scan_type: str, results: Dict) -> Dict:
        """Process and integrate scan results into database"""
        integration_summary = {
            'targets_added': 0,
            'services_added': 0,
            'vulnerabilities_added': 0,
            'credentials_added': 0,
            'loot_added': 0
        }
        
        # Ensure target exists
        target_id = self._ensure_target(target)
        if target_id:
            integration_summary['targets_added'] = 1
        
        # Process based on scan type
        if scan_type == 'port_scan':
            integration_summary.update(self._process_port_scan(target_id, results))
        elif scan_type == 'vuln_scan':
            integration_summary.update(self._process_vuln_scan(target_id, results))
        elif scan_type == 'dns_enum':
            integration_summary.update(self._process_dns_enum(results))
        elif scan_type == 'credential_dump':
            integration_summary.update(self._process_credentials(target_id, results))
        elif scan_type == 'file_extraction':
            integration_summary.update(self._process_loot(target_id, results))
        
        return integration_summary
    
    def _ensure_target(self, target: str) -> int:
        """Ensure target exists in database, create if not"""
        # Check if it's an IP or hostname
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        
        if re.match(ip_pattern, target):
            # It's an IP
            existing = self.db.get_target_by_ip(target)
            if existing:
                return existing['id']
            return self.db.add_target(ip=target)
        else:
            # It's a hostname/domain
            # Try to find existing target with this hostname
            targets = self.db.get_targets()
            for t in targets:
                if t['hostname'] == target or t['domain'] == target:
                    return t['id']
            
            # Create new target with hostname
            return self.db.add_target(ip="", hostname=target, domain=target)
    
    def _process_port_scan(self, target_id: int, results: Dict) -> Dict:
        """Process port scan results"""
        summary = {'services_added': 0}
        
        if 'ports' in results:
            for port_info in results['ports']:
                if isinstance(port_info, dict):
                    port = port_info.get('port', 0)
                    service = port_info.get('service', '')
                    version = port_info.get('version', '')
                    state = port_info.get('state', 'open')
                    banner = port_info.get('banner', '')
                elif isinstance(port_info, (int, str)):
                    port = int(port_info)
                    service = self._guess_service_by_port(port)
                    version = ''
                    state = 'open'
                    banner = ''
                else:
                    continue
                
                if port > 0:
                    self.db.add_service(
                        target_id=target_id,
                        port=port,
                        service=service,
                        version=version,
                        state=state,
                        banner=banner
                    )
                    summary['services_added'] += 1
        
        elif 'open_ports' in results:
            for port in results['open_ports']:
                port_num = int(port) if isinstance(port, str) else port
                service = self._guess_service_by_port(port_num)
                
                self.db.add_service(
                    target_id=target_id,
                    port=port_num,
                    service=service,
                    state='open'
                )
                summary['services_added'] += 1
        
        return summary
    
    def _process_vuln_scan(self, target_id: int, results: Dict) -> Dict:
        """Process vulnerability scan results"""
        summary = {'vulnerabilities_added': 0}
        
        vulnerabilities = results.get('vulnerabilities', [])
        if isinstance(vulnerabilities, dict):
            vulnerabilities = [vulnerabilities]
        
        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue
            
            # Extract vulnerability details
            name = vuln.get('name', vuln.get('title', 'Unknown Vulnerability'))
            severity = vuln.get('severity', vuln.get('risk', 'info')).lower()
            cve = vuln.get('cve', vuln.get('CVE', ''))
            description = vuln.get('description', vuln.get('summary', ''))
            
            # Try to match to a service
            service_id = None
            if 'port' in vuln:
                services = self.db.get_services(target_id=target_id, port=vuln['port'])
                if services:
                    service_id = services[0]['id']
            
            self.db.add_vulnerability(
                target_id=target_id,
                service_id=service_id,
                name=name,
                severity=severity,
                cve=cve,
                description=description,
                exploitable=vuln.get('exploitable', False)
            )
            summary['vulnerabilities_added'] += 1
        
        return summary
    
    def _process_dns_enum(self, results: Dict) -> Dict:
        """Process DNS enumeration results"""
        summary = {'targets_added': 0}
        
        # Handle different DNS result formats
        domains = []
        if isinstance(results, dict):
            if 'subdomains' in results:
                domains = results['subdomains']
            elif 'domains' in results:
                domains = results['domains']
            else:
                # Assume keys are domains
                domains = list(results.keys())
        elif isinstance(results, list):
            domains = results
        
        for domain in domains:
            if isinstance(domain, str) and domain:
                # Extract root domain
                parts = domain.split('.')
                if len(parts) >= 2:
                    root_domain = '.'.join(parts[-2:])
                    
                    # Add as target
                    target_id = self.db.add_target(
                        ip="",
                        hostname=domain,
                        domain=root_domain
                    )
                    if target_id:
                        summary['targets_added'] += 1
        
        return summary
    
    def _process_credentials(self, target_id: int, results: Dict) -> Dict:
        """Process credential dump results"""
        summary = {'credentials_added': 0}
        
        credentials = results.get('credentials', [])
        if isinstance(credentials, dict):
            credentials = [credentials]
        
        for cred in credentials:
            if not isinstance(cred, dict):
                continue
            
            username = cred.get('username', cred.get('user', ''))
            password = cred.get('password', '')
            hash_value = cred.get('hash', cred.get('ntlm', ''))
            hash_type = cred.get('hash_type', 'ntlm' if hash_value else '')
            domain = cred.get('domain', '')
            source = cred.get('source', 'dump')
            
            if username or password or hash_value:
                self.db.add_credential(
                    target_id=target_id,
                    username=username,
                    password=password,
                    hash_value=hash_value,
                    hash_type=hash_type,
                    domain=domain,
                    source=source
                )
                summary['credentials_added'] += 1
        
        return summary
    
    def _process_loot(self, target_id: int, results: Dict) -> Dict:
        """Process loot/file extraction results"""
        summary = {'loot_added': 0}
        
        files = results.get('files', results.get('loot', []))
        if isinstance(files, dict):
            files = [files]
        
        for file_info in files:
            if not isinstance(file_info, dict):
                continue
            
            name = file_info.get('name', file_info.get('filename', 'Unknown File'))
            path = file_info.get('path', '')
            content = file_info.get('content', '')
            size = file_info.get('size', 0)
            file_type = file_info.get('type', 'file')
            sensitive = file_info.get('sensitive', False)
            
            # Detect sensitive files
            if not sensitive:
                sensitive_patterns = [
                    'password', 'passwd', 'secret', 'key', 'token',
                    'config', 'backup', 'dump', 'shadow', 'sam'
                ]
                sensitive = any(pattern in name.lower() for pattern in sensitive_patterns)
            
            self.db.add_loot(
                target_id=target_id,
                name=name,
                type=file_type,
                path=path,
                content=content,
                size=size,
                sensitive=sensitive
            )
            summary['loot_added'] += 1
        
        return summary
    
    def _guess_service_by_port(self, port: int) -> str:
        """Guess service name by port number"""
        common_ports = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'dns', 80: 'http', 110: 'pop3', 135: 'msrpc',
            139: 'netbios-ssn', 143: 'imap', 443: 'https',
            445: 'microsoft-ds', 993: 'imaps', 995: 'pop3s',
            1433: 'mssql', 3306: 'mysql', 3389: 'rdp',
            5432: 'postgresql', 5985: 'winrm', 5986: 'winrm-https'
        }
        return common_ports.get(port, f'unknown-{port}')
    
    def import_nmap_xml(self, xml_path: str) -> Dict:
        """Import Nmap XML results"""
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(xml_path)
            root = tree.getroot()
            
            summary = {'targets_added': 0, 'services_added': 0}
            
            for host in root.findall('.//host'):
                # Get IP address
                ip_elem = host.find('.//address[@addrtype="ipv4"]')
                if ip_elem is None:
                    continue
                
                ip = ip_elem.get('addr')
                target_id = self.db.add_target(ip=ip)
                summary['targets_added'] += 1
                
                # Get hostname if available
                hostname_elem = host.find('.//hostname')
                if hostname_elem is not None:
                    hostname = hostname_elem.get('name')
                    self.db.add_target(ip=ip, hostname=hostname)
                
                # Process ports
                for port in host.findall('.//port'):
                    port_num = int(port.get('portid'))
                    protocol = port.get('protocol', 'tcp')
                    
                    state_elem = port.find('state')
                    state = state_elem.get('state') if state_elem is not None else 'unknown'
                    
                    service_elem = port.find('service')
                    service = ''
                    version = ''
                    if service_elem is not None:
                        service = service_elem.get('name', '')
                        version = service_elem.get('version', '')
                    
                    self.db.add_service(
                        target_id=target_id,
                        port=port_num,
                        protocol=protocol,
                        service=service,
                        version=version,
                        state=state
                    )
                    summary['services_added'] += 1
            
            return summary
            
        except Exception as e:
            return {'error': str(e)}
    
    def export_findings(self, format: str = 'json') -> str:
        """Export all findings in specified format"""
        if format == 'json':
            return self._export_json()
        elif format == 'csv':
            return self._export_csv()
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _export_json(self) -> str:
        """Export findings as JSON"""
        data = {
            'targets': self.db.get_targets(),
            'services': self.db.get_services(),
            'vulnerabilities': self.db.get_vulnerabilities(),
            'credentials': self.db.get_credentials(),
            'loot': self.db.get_loot(),
            'statistics': self.db.get_statistics()
        }
        return json.dumps(data, indent=2, default=str)
    
    def _export_csv(self) -> str:
        """Export findings as CSV (simplified)"""
        lines = []
        lines.append("Type,Target,Port,Service,Severity,Name,Details")
        
        # Export vulnerabilities
        for vuln in self.db.get_vulnerabilities():
            lines.append(f"Vulnerability,{vuln['ip']},{vuln.get('port', '')},{vuln.get('service', '')},{vuln['severity']},{vuln['name']},{vuln.get('description', '')}")
        
        # Export services
        for service in self.db.get_services():
            lines.append(f"Service,{service['ip']},{service['port']},{service['service']},,Open Port,{service.get('version', '')}")
        
        return '\n'.join(lines)

# Global instance
data_integration = DataIntegration()