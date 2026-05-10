# app/core/cross_scan_correlator.py
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from .centralized_scan_data import centralized_scan_data
from app.core.logger import logger

@dataclass
class CorrelationFinding:
    """Individual correlation finding"""
    correlation_id: str
    correlation_type: str
    severity: str
    title: str
    description: str
    affected_targets: List[str]
    scan_types_involved: List[str]
    evidence: List[Dict[str, Any]]
    attack_path: List[str]
    risk_score: float
    remediation: str
    timestamp: str

@dataclass
class AttackChain:
    """Attack chain representation"""
    chain_id: str
    entry_points: List[str]
    attack_steps: List[Dict[str, Any]]
    final_objectives: List[str]
    risk_level: str
    likelihood: float

class CrossScanCorrelator:
    """Cross-scan data correlation engine"""
    
    def __init__(self, tenant_id: str = "default"):
        self.tenant_id = tenant_id
        self.correlation_rules = self._load_correlation_rules()
        
    def _load_correlation_rules(self) -> Dict[str, Any]:
        """Load correlation rules for different attack patterns"""
        return {
            'lateral_movement': {
                'description': 'Identify lateral movement opportunities',
                'scan_types': ['rpc_endpoints', 'rpc_services', 'smb_shares', 'port_open_ports'],
                'conditions': [
                    {'type': 'service_exposure', 'services': ['RPC', 'SMB', 'WinRM', 'RDP']},
                    {'type': 'credential_access', 'methods': ['SAMR', 'LSA', 'Registry']},
                    {'type': 'privilege_escalation', 'vectors': ['Service Misconfiguration', 'Unquoted Paths']}
                ]
            },
            'credential_harvesting': {
                'description': 'Identify credential harvesting opportunities',
                'scan_types': ['rpc_samr', 'rpc_lsa', 'rpc_registry', 'smb_shares'],
                'conditions': [
                    {'type': 'anonymous_access', 'interfaces': ['SAMR', 'LSA']},
                    {'type': 'readable_shares', 'share_types': ['ADMIN$', 'C$', 'IPC$']},
                    {'type': 'registry_access', 'keys': ['SAM', 'SECURITY', 'SOFTWARE']}
                ]
            },
            'service_exploitation': {
                'description': 'Identify exploitable service configurations',
                'scan_types': ['rpc_services', 'rpc_vulnerabilities', 'port_service_detection'],
                'conditions': [
                    {'type': 'vulnerable_service', 'criteria': ['CVE', 'Unpatched', 'Misconfigured']},
                    {'type': 'privilege_context', 'levels': ['SYSTEM', 'Administrator']},
                    {'type': 'network_exposure', 'accessibility': ['External', 'Internal']}
                ]
            },
            'information_disclosure': {
                'description': 'Identify information disclosure vulnerabilities',
                'scan_types': ['dns_subdomains', 'http_directories', 'smb_files', 'rpc_registry'],
                'conditions': [
                    {'type': 'sensitive_exposure', 'data_types': ['Credentials', 'Configuration', 'Source Code']},
                    {'type': 'directory_listing', 'paths': ['Admin', 'Config', 'Backup']},
                    {'type': 'file_access', 'extensions': ['.config', '.bak', '.log']}
                ]
            },
            'network_pivoting': {
                'description': 'Identify network pivoting opportunities',
                'scan_types': ['port_open_ports', 'dns_subdomains', 'rpc_network_endpoints'],
                'conditions': [
                    {'type': 'multi_homed', 'networks': ['Internal', 'DMZ', 'External']},
                    {'type': 'trust_relationships', 'domains': ['Child', 'Forest', 'External']},
                    {'type': 'routing_services', 'services': ['VPN', 'Proxy', 'Gateway']}
                ]
            }
        }
    
    def correlate_all_findings(self, time_window_hours: int = 24) -> List[CorrelationFinding]:
        """Correlate findings across all scan types"""
        correlations = []
        
        # Get recent data from all scan types
        scan_data = self._get_recent_scan_data(time_window_hours)
        
        # Apply each correlation rule
        for rule_name, rule_config in self.correlation_rules.items():
            rule_correlations = self._apply_correlation_rule(rule_name, rule_config, scan_data)
            correlations.extend(rule_correlations)
        
        # Sort by risk score
        correlations.sort(key=lambda x: x.risk_score, reverse=True)
        
        return correlations
    
    def _get_recent_scan_data(self, hours: int) -> Dict[str, List[Dict]]:
        """Get recent scan data from all types"""
        scan_types = [
            'rpc_endpoints', 'rpc_services', 'rpc_vulnerabilities', 'rpc_samr', 'rpc_lsa',
            'dns_subdomains', 'dns_records', 'port_open_ports', 'port_service_detection',
            'http_directories', 'http_vulnerabilities', 'smb_shares', 'smb_files'
        ]
        
        data = {}
        for scan_type in scan_types:
            try:
                data[scan_type] = centralized_scan_data.get_scan_data(
                    tenant_id=self.tenant_id,
                    scan_type=scan_type,
                    limit=500
                )
            except Exception:
                data[scan_type] = []
        
        return data
    
    def _apply_correlation_rule(self, rule_name: str, rule_config: Dict, 
                               scan_data: Dict[str, List[Dict]]) -> List[CorrelationFinding]:
        """Apply specific correlation rule"""
        correlations = []
        
        if rule_name == 'lateral_movement':
            correlations.extend(self._correlate_lateral_movement(scan_data))
        elif rule_name == 'credential_harvesting':
            correlations.extend(self._correlate_credential_harvesting(scan_data))
        elif rule_name == 'service_exploitation':
            correlations.extend(self._correlate_service_exploitation(scan_data))
        elif rule_name == 'information_disclosure':
            correlations.extend(self._correlate_information_disclosure(scan_data))
        elif rule_name == 'network_pivoting':
            correlations.extend(self._correlate_network_pivoting(scan_data))
        
        return correlations
    
    def _correlate_lateral_movement(self, scan_data: Dict) -> List[CorrelationFinding]:
        """Correlate lateral movement opportunities"""
        correlations = []
        
        # Group data by target
        targets = self._group_data_by_target(scan_data)
        
        for target, target_data in targets.items():
            # Check for RPC + SMB exposure
            rpc_services = target_data.get('rpc_services', [])
            rpc_endpoints = target_data.get('rpc_endpoints', [])
            open_ports = target_data.get('port_open_ports', [])
            
            # Look for administrative services
            admin_services = []
            for service in rpc_services:
                service_name = service['data'].get('name', '').lower()
                if any(admin in service_name for admin in ['server', 'workstation', 'netlogon']):
                    admin_services.append(service)
            
            # Look for RPC endpoints that allow enumeration
            enum_endpoints = []
            for endpoint in rpc_endpoints:
                uuid = endpoint['data'].get('uuid', '')
                if uuid in ['12345778-1234-abcd-ef00-0123456789ab',  # SAMR
                           '12345778-1234-abcd-ef00-0123456789ac']:  # LSA
                    enum_endpoints.append(endpoint)
            
            # Look for SMB/RPC ports
            network_ports = []
            for port in open_ports:
                port_num = port['data'].get('port', 0)
                if port_num in [135, 139, 445, 593]:  # RPC and SMB ports
                    network_ports.append(port)
            
            # Create correlation if conditions met
            if admin_services and enum_endpoints and network_ports:
                correlation = CorrelationFinding(
                    correlation_id=f"lateral_{target}_{int(datetime.now().timestamp())}",
                    correlation_type="lateral_movement",
                    severity="High",
                    title=f"Lateral Movement Opportunity - {target}",
                    description=f"Target {target} exposes administrative services with enumeration capabilities",
                    affected_targets=[target],
                    scan_types_involved=['rpc_services', 'rpc_endpoints', 'port_open_ports'],
                    evidence=[
                        {'type': 'admin_services', 'count': len(admin_services), 'services': admin_services[:3]},
                        {'type': 'enum_endpoints', 'count': len(enum_endpoints), 'endpoints': enum_endpoints[:3]},
                        {'type': 'network_ports', 'count': len(network_ports), 'ports': network_ports[:3]}
                    ],
                    attack_path=[
                        "1. Connect to RPC endpoint mapper (port 135)",
                        "2. Enumerate available RPC interfaces",
                        "3. Connect to SAMR/LSA interfaces for user enumeration",
                        "4. Use SMB (port 445) for file system access",
                        "5. Leverage administrative services for privilege escalation"
                    ],
                    risk_score=8.5,
                    remediation="Restrict RPC access, disable unnecessary services, implement network segmentation",
                    timestamp=datetime.now().isoformat()
                )
                correlations.append(correlation)
        
        return correlations
    
    def _correlate_credential_harvesting(self, scan_data: Dict) -> List[CorrelationFinding]:
        """Correlate credential harvesting opportunities"""
        correlations = []
        
        targets = self._group_data_by_target(scan_data)
        
        for target, target_data in targets.items():
            samr_data = target_data.get('rpc_samr', [])
            lsa_data = target_data.get('rpc_lsa', [])
            smb_shares = target_data.get('smb_shares', [])
            
            # Check for anonymous SAMR/LSA access
            anonymous_access = []
            for samr in samr_data:
                if samr['data'].get('domains') or samr['data'].get('users'):
                    anonymous_access.append({'type': 'SAMR', 'data': samr})
            
            for lsa in lsa_data:
                if lsa['data'].get('domain_name') or lsa['data'].get('trusted_domains'):
                    anonymous_access.append({'type': 'LSA', 'data': lsa})
            
            # Check for accessible shares
            accessible_shares = []
            for share in smb_shares:
                share_name = share['data'].get('name', '').upper()
                if share_name in ['ADMIN$', 'C$', 'IPC$'] and share['data'].get('accessible'):
                    accessible_shares.append(share)
            
            if anonymous_access and accessible_shares:
                correlation = CorrelationFinding(
                    correlation_id=f"creds_{target}_{int(datetime.now().timestamp())}",
                    correlation_type="credential_harvesting",
                    severity="Critical",
                    title=f"Credential Harvesting Opportunity - {target}",
                    description=f"Target {target} allows anonymous enumeration and share access",
                    affected_targets=[target],
                    scan_types_involved=['rpc_samr', 'rpc_lsa', 'smb_shares'],
                    evidence=[
                        {'type': 'anonymous_access', 'count': len(anonymous_access), 'methods': anonymous_access[:3]},
                        {'type': 'accessible_shares', 'count': len(accessible_shares), 'shares': accessible_shares[:3]}
                    ],
                    attack_path=[
                        "1. Connect anonymously to RPC services",
                        "2. Enumerate domain users via SAMR interface",
                        "3. Gather domain information via LSA interface",
                        "4. Access administrative shares for credential files",
                        "5. Extract hashes from SAM/SECURITY hives"
                    ],
                    risk_score=9.2,
                    remediation="Disable anonymous access, restrict share permissions, enable SMB signing",
                    timestamp=datetime.now().isoformat()
                )
                correlations.append(correlation)
        
        return correlations
    
    def _correlate_service_exploitation(self, scan_data: Dict) -> List[CorrelationFinding]:
        """Correlate service exploitation opportunities"""
        correlations = []
        
        targets = self._group_data_by_target(scan_data)
        
        for target, target_data in targets.items():
            vulnerabilities = target_data.get('rpc_vulnerabilities', [])
            services = target_data.get('rpc_services', [])
            ports = target_data.get('port_service_detection', [])
            
            # Find high-severity vulnerabilities
            critical_vulns = [v for v in vulnerabilities 
                            if v['data'].get('severity', '').lower() in ['critical', 'high']]
            
            # Find privileged services
            privileged_services = []
            for service in services:
                service_name = service['data'].get('name', '').lower()
                if any(priv in service_name for priv in ['system', 'admin', 'service']):
                    privileged_services.append(service)
            
            # Find exposed network services
            exposed_services = [p for p in ports 
                              if p['data'].get('state') == 'open' and 
                              p['data'].get('service') in ['rpc', 'smb', 'http', 'https']]
            
            if critical_vulns and (privileged_services or exposed_services):
                correlation = CorrelationFinding(
                    correlation_id=f"exploit_{target}_{int(datetime.now().timestamp())}",
                    correlation_type="service_exploitation",
                    severity="High",
                    title=f"Service Exploitation Chain - {target}",
                    description=f"Target {target} has exploitable vulnerabilities in privileged services",
                    affected_targets=[target],
                    scan_types_involved=['rpc_vulnerabilities', 'rpc_services', 'port_service_detection'],
                    evidence=[
                        {'type': 'critical_vulnerabilities', 'count': len(critical_vulns), 'vulns': critical_vulns[:3]},
                        {'type': 'privileged_services', 'count': len(privileged_services), 'services': privileged_services[:3]},
                        {'type': 'exposed_services', 'count': len(exposed_services), 'services': exposed_services[:3]}
                    ],
                    attack_path=[
                        "1. Identify vulnerable service versions",
                        "2. Craft exploit for specific vulnerability",
                        "3. Execute exploit against privileged service",
                        "4. Gain elevated privileges on target system",
                        "5. Use privileges for further compromise"
                    ],
                    risk_score=8.8,
                    remediation="Patch vulnerable services, reduce service privileges, implement defense in depth",
                    timestamp=datetime.now().isoformat()
                )
                correlations.append(correlation)
        
        return correlations
    
    def _correlate_information_disclosure(self, scan_data: Dict) -> List[CorrelationFinding]:
        """Correlate information disclosure opportunities"""
        correlations = []
        
        targets = self._group_data_by_target(scan_data)
        
        for target, target_data in targets.items():
            http_dirs = target_data.get('http_directories', [])
            smb_files = target_data.get('smb_files', [])
            dns_records = target_data.get('dns_subdomains', [])
            
            # Find sensitive directories
            sensitive_dirs = []
            for dir_item in http_dirs:
                path = dir_item['data'].get('path', '').lower()
                if any(sensitive in path for sensitive in ['admin', 'config', 'backup', '.git']):
                    sensitive_dirs.append(dir_item)
            
            # Find sensitive files
            sensitive_files = []
            for file_item in smb_files:
                filename = file_item['data'].get('name', '').lower()
                if any(ext in filename for ext in ['.config', '.bak', '.log', '.key']):
                    sensitive_files.append(file_item)
            
            # Find internal subdomains
            internal_domains = []
            for dns_item in dns_records:
                subdomain = dns_item['data'].get('subdomain', '').lower()
                if any(internal in subdomain for internal in ['admin', 'internal', 'dev', 'test']):
                    internal_domains.append(dns_item)
            
            total_exposures = len(sensitive_dirs) + len(sensitive_files) + len(internal_domains)
            
            if total_exposures >= 3:  # Threshold for correlation
                correlation = CorrelationFinding(
                    correlation_id=f"info_{target}_{int(datetime.now().timestamp())}",
                    correlation_type="information_disclosure",
                    severity="Medium",
                    title=f"Information Disclosure Pattern - {target}",
                    description=f"Target {target} exposes sensitive information across multiple vectors",
                    affected_targets=[target],
                    scan_types_involved=['http_directories', 'smb_files', 'dns_subdomains'],
                    evidence=[
                        {'type': 'sensitive_directories', 'count': len(sensitive_dirs), 'dirs': sensitive_dirs[:3]},
                        {'type': 'sensitive_files', 'count': len(sensitive_files), 'files': sensitive_files[:3]},
                        {'type': 'internal_domains', 'count': len(internal_domains), 'domains': internal_domains[:3]}
                    ],
                    attack_path=[
                        "1. Enumerate exposed directories and files",
                        "2. Access configuration and backup files",
                        "3. Extract credentials and sensitive data",
                        "4. Map internal infrastructure via DNS",
                        "5. Use gathered intelligence for targeted attacks"
                    ],
                    risk_score=6.5,
                    remediation="Restrict directory access, secure file permissions, limit DNS information",
                    timestamp=datetime.now().isoformat()
                )
                correlations.append(correlation)
        
        return correlations
    
    def _correlate_network_pivoting(self, scan_data: Dict) -> List[CorrelationFinding]:
        """Correlate network pivoting opportunities"""
        correlations = []
        
        # Group by network segments
        network_segments = self._group_by_network_segment(scan_data)
        
        # Look for multi-homed hosts
        for segment, targets in network_segments.items():
            if len(targets) > 1:  # Multiple targets in same segment
                pivot_candidates = []
                
                for target, target_data in targets.items():
                    open_ports = target_data.get('port_open_ports', [])
                    rpc_endpoints = target_data.get('rpc_network_endpoints', [])
                    
                    # Look for routing/proxy services
                    routing_ports = [p for p in open_ports 
                                   if p['data'].get('port') in [3389, 5985, 22, 80, 443, 8080]]
                    
                    if routing_ports and rpc_endpoints:
                        pivot_candidates.append({
                            'target': target,
                            'routing_ports': routing_ports,
                            'rpc_endpoints': rpc_endpoints
                        })
                
                if len(pivot_candidates) >= 2:
                    correlation = CorrelationFinding(
                        correlation_id=f"pivot_{segment}_{int(datetime.now().timestamp())}",
                        correlation_type="network_pivoting",
                        severity="Medium",
                        title=f"Network Pivoting Opportunity - {segment}",
                        description=f"Network segment {segment} contains multiple pivot candidates",
                        affected_targets=[c['target'] for c in pivot_candidates],
                        scan_types_involved=['port_open_ports', 'rpc_network_endpoints'],
                        evidence=[
                            {'type': 'pivot_candidates', 'count': len(pivot_candidates), 'candidates': pivot_candidates[:3]}
                        ],
                        attack_path=[
                            "1. Compromise initial target in network segment",
                            "2. Identify routing and proxy services",
                            "3. Use compromised host as pivot point",
                            "4. Access additional targets in segment",
                            "5. Establish persistent access across network"
                        ],
                        risk_score=7.2,
                        remediation="Implement network segmentation, restrict inter-host communication, monitor lateral movement",
                        timestamp=datetime.now().isoformat()
                    )
                    correlations.append(correlation)
        
        return correlations
    
    def _group_data_by_target(self, scan_data: Dict) -> Dict[str, Dict]:
        """Group scan data by target"""
        targets = {}
        
        for scan_type, data_list in scan_data.items():
            for item in data_list:
                target = item.get('target', 'unknown')
                if target not in targets:
                    targets[target] = {}
                if scan_type not in targets[target]:
                    targets[target][scan_type] = []
                targets[target][scan_type].append(item)
        
        return targets
    
    def _group_by_network_segment(self, scan_data: Dict) -> Dict[str, Dict]:
        """Group targets by network segment"""
        segments = {}
        
        targets = self._group_data_by_target(scan_data)
        
        for target, target_data in targets.items():
            # Extract network segment (first 3 octets for IPv4)
            try:
                if '.' in target:
                    octets = target.split('.')
                    if len(octets) >= 3:
                        segment = '.'.join(octets[:3]) + '.0/24'
                    else:
                        segment = 'unknown'
                else:
                    segment = 'non-ip'
            except Exception:
                segment = 'unknown'
            
            if segment not in segments:
                segments[segment] = {}
            segments[segment][target] = target_data
        
        return segments
    
    def generate_attack_chains(self, correlations: List[CorrelationFinding]) -> List[AttackChain]:
        """Generate attack chains from correlations"""
        chains = []
        
        # Group correlations by target
        target_correlations = {}
        for correlation in correlations:
            for target in correlation.affected_targets:
                if target not in target_correlations:
                    target_correlations[target] = []
                target_correlations[target].append(correlation)
        
        # Generate chains for each target
        for target, target_corrs in target_correlations.items():
            if len(target_corrs) >= 2:  # Need multiple correlations for a chain
                chain = AttackChain(
                    chain_id=f"chain_{target}_{int(datetime.now().timestamp())}",
                    entry_points=[target],
                    attack_steps=self._build_attack_steps(target_corrs),
                    final_objectives=self._identify_objectives(target_corrs),
                    risk_level=self._calculate_chain_risk(target_corrs),
                    likelihood=self._calculate_likelihood(target_corrs)
                )
                chains.append(chain)
        
        return chains
    
    def _build_attack_steps(self, correlations: List[CorrelationFinding]) -> List[Dict[str, Any]]:
        """Build attack steps from correlations"""
        steps = []
        
        # Sort by typical attack progression
        order = ['information_disclosure', 'credential_harvesting', 'service_exploitation', 'lateral_movement', 'network_pivoting']
        sorted_corrs = sorted(correlations, key=lambda x: order.index(x.correlation_type) if x.correlation_type in order else 999)
        
        for i, correlation in enumerate(sorted_corrs):
            step = {
                'step_number': i + 1,
                'correlation_type': correlation.correlation_type,
                'title': correlation.title,
                'description': correlation.description,
                'risk_score': correlation.risk_score,
                'attack_path': correlation.attack_path
            }
            steps.append(step)
        
        return steps
    
    def _identify_objectives(self, correlations: List[CorrelationFinding]) -> List[str]:
        """Identify final objectives from correlations"""
        objectives = set()
        
        for correlation in correlations:
            if correlation.correlation_type == 'credential_harvesting':
                objectives.add('Credential Theft')
            elif correlation.correlation_type == 'service_exploitation':
                objectives.add('System Compromise')
            elif correlation.correlation_type == 'lateral_movement':
                objectives.add('Network Propagation')
            elif correlation.correlation_type == 'information_disclosure':
                objectives.add('Data Exfiltration')
            elif correlation.correlation_type == 'network_pivoting':
                objectives.add('Infrastructure Control')
        
        return list(objectives)
    
    def _calculate_chain_risk(self, correlations: List[CorrelationFinding]) -> str:
        """Calculate overall risk level for attack chain"""
        avg_risk = sum(c.risk_score for c in correlations) / len(correlations)
        
        if avg_risk >= 8.0:
            return 'Critical'
        elif avg_risk >= 6.0:
            return 'High'
        elif avg_risk >= 4.0:
            return 'Medium'
        else:
            return 'Low'
    
    def _calculate_likelihood(self, correlations: List[CorrelationFinding]) -> float:
        """Calculate likelihood of successful attack chain"""
        # Base likelihood on number of correlations and their severity
        base_likelihood = min(len(correlations) * 0.2, 1.0)
        
        # Adjust based on severity
        critical_count = sum(1 for c in correlations if c.severity == 'Critical')
        high_count = sum(1 for c in correlations if c.severity == 'High')
        
        severity_multiplier = 1.0 + (critical_count * 0.3) + (high_count * 0.2)
        
        return min(base_likelihood * severity_multiplier, 1.0)
    
    def export_correlations(self, correlations: List[CorrelationFinding], 
                          format: str = 'json') -> str:
        """Export correlations in specified format"""
        if format == 'json':
            return json.dumps([{
                'correlation_id': c.correlation_id,
                'correlation_type': c.correlation_type,
                'severity': c.severity,
                'title': c.title,
                'description': c.description,
                'affected_targets': c.affected_targets,
                'scan_types_involved': c.scan_types_involved,
                'evidence': c.evidence,
                'attack_path': c.attack_path,
                'risk_score': c.risk_score,
                'remediation': c.remediation,
                'timestamp': c.timestamp
            } for c in correlations], indent=2)
        else:
            raise ValueError(f"Unsupported format: {format}")

# Factory function
def create_cross_scan_correlator(tenant_id: str = "default") -> CrossScanCorrelator:
    """Create cross-scan correlator for specific tenant"""
    return CrossScanCorrelator(tenant_id=tenant_id)