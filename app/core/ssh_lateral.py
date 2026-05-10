# app/core/ssh_lateral.py
import re
import ipaddress
from typing import Dict, List, Set, Optional
from .ssh_session_manager import ssh_session_manager
from app.core.logger import logger

class SSHLateralMovement:
    """SSH lateral movement detection and analysis"""
    
    def __init__(self, tenant_id: str = "default"):
        self.tenant_id = tenant_id
        self.session_manager = ssh_session_manager
        
    def analyze_lateral_opportunities(self, session_id: str) -> Dict:
        """Analyze lateral movement opportunities from SSH session"""
        try:
            # Get lateral movement data from session manager
            lateral_data = self.session_manager.check_lateral_movement(session_id)
            
            if not lateral_data.get('success'):
                return {'success': False, 'error': 'Failed to gather lateral movement data'}
            
            results = lateral_data['lateral_movement_data']
            opportunities = {
                'ssh_keys': self._analyze_ssh_keys(results.get('ssh_keys', {})),
                'known_hosts': self._analyze_known_hosts(results.get('known_hosts', {})),
                'network_targets': self._analyze_network_targets(results.get('arp_table', {})),
                'network_shares': self._analyze_network_shares(results.get('network_shares', {})),
                'privilege_escalation': self._analyze_sudo_privileges(results.get('sudo_privileges', {})),
                'scheduled_tasks': self._analyze_cron_jobs(results.get('cron_jobs', {}))
            }
            
            # Calculate risk score
            risk_score = self._calculate_lateral_risk_score(opportunities)
            
            return {
                'success': True,
                'session_id': session_id,
                'opportunities': opportunities,
                'risk_score': risk_score,
                'recommendations': self._generate_recommendations(opportunities)
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _analyze_ssh_keys(self, ssh_keys_result: Dict) -> Dict:
        """Analyze SSH keys for lateral movement"""
        analysis = {
            'private_keys': [],
            'public_keys': [],
            'key_count': 0,
            'risk_level': 'low'
        }
        
        if not ssh_keys_result.get('success'):
            return analysis
        
        output = ssh_keys_result.get('output', '')
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            if 'id_rsa' in line and not line.endswith('.pub'):
                analysis['private_keys'].append(line)
            elif line.endswith('.pub'):
                analysis['public_keys'].append(line)
        
        analysis['key_count'] = len(analysis['private_keys']) + len(analysis['public_keys'])
        
        if len(analysis['private_keys']) > 0:
            analysis['risk_level'] = 'high'
        elif len(analysis['public_keys']) > 2:
            analysis['risk_level'] = 'medium'
        
        return analysis
    
    def _analyze_known_hosts(self, known_hosts_result: Dict) -> Dict:
        """Analyze known hosts for potential targets"""
        analysis = {
            'hosts': [],
            'ip_addresses': [],
            'hostnames': [],
            'host_count': 0,
            'risk_level': 'low'
        }
        
        if not known_hosts_result.get('success'):
            return analysis
        
        output = known_hosts_result.get('output', '')
        lines = output.split('\n')
        
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        hostname_pattern = re.compile(r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\b')
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Extract IP addresses
            ips = ip_pattern.findall(line)
            for ip in ips:
                if self._is_valid_target_ip(ip):
                    analysis['ip_addresses'].append(ip)
            
            # Extract hostnames
            hostnames = hostname_pattern.findall(line)
            for hostname_match in hostnames:
                hostname = hostname_match[0] if isinstance(hostname_match, tuple) else hostname_match
                if len(hostname) > 3 and '.' in hostname:
                    analysis['hostnames'].append(hostname)
        
        analysis['hosts'] = list(set(analysis['ip_addresses'] + analysis['hostnames']))
        analysis['host_count'] = len(analysis['hosts'])
        
        if analysis['host_count'] > 10:
            analysis['risk_level'] = 'high'
        elif analysis['host_count'] > 3:
            analysis['risk_level'] = 'medium'
        
        return analysis
    
    def _analyze_network_targets(self, arp_result: Dict) -> Dict:
        """Analyze ARP table for network targets"""
        analysis = {
            'network_hosts': [],
            'subnets': [],
            'host_count': 0,
            'risk_level': 'low'
        }
        
        if not arp_result.get('success'):
            return analysis
        
        output = arp_result.get('output', '')
        lines = output.split('\n')
        
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        
        for line in lines:
            ips = ip_pattern.findall(line)
            for ip in ips:
                if self._is_valid_target_ip(ip):
                    analysis['network_hosts'].append(ip)
                    
                    # Determine subnet
                    try:
                        network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                        subnet = str(network.network_address) + "/24"
                        if subnet not in analysis['subnets']:
                            analysis['subnets'].append(subnet)
                    except Exception as _exc:
                        pass
                        logger.debug("Suppressed exception", exc_info=True)
        
        analysis['network_hosts'] = list(set(analysis['network_hosts']))
        analysis['host_count'] = len(analysis['network_hosts'])
        
        if analysis['host_count'] > 20:
            analysis['risk_level'] = 'high'
        elif analysis['host_count'] > 5:
            analysis['risk_level'] = 'medium'
        
        return analysis
    
    def _analyze_network_shares(self, shares_result: Dict) -> Dict:
        """Analyze network shares for lateral movement"""
        analysis = {
            'nfs_shares': [],
            'smb_shares': [],
            'share_count': 0,
            'risk_level': 'low'
        }
        
        if not shares_result.get('success'):
            return analysis
        
        output = shares_result.get('output', '')
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip().lower()
            if 'nfs' in line:
                analysis['nfs_shares'].append(line)
            elif 'cifs' in line or 'smb' in line:
                analysis['smb_shares'].append(line)
        
        analysis['share_count'] = len(analysis['nfs_shares']) + len(analysis['smb_shares'])
        
        if analysis['share_count'] > 0:
            analysis['risk_level'] = 'medium'
        
        return analysis
    
    def _analyze_sudo_privileges(self, sudo_result: Dict) -> Dict:
        """Analyze sudo privileges for privilege escalation"""
        analysis = {
            'sudo_commands': [],
            'no_password_commands': [],
            'all_privileges': False,
            'risk_level': 'low'
        }
        
        if not sudo_result.get('success'):
            return analysis
        
        output = sudo_result.get('output', '')
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or 'may run' in line.lower():
                continue
            
            if 'NOPASSWD' in line:
                analysis['no_password_commands'].append(line)
            elif 'ALL' in line:
                analysis['all_privileges'] = True
                analysis['sudo_commands'].append(line)
            elif line.startswith('('):
                analysis['sudo_commands'].append(line)
        
        if analysis['all_privileges']:
            analysis['risk_level'] = 'critical'
        elif len(analysis['no_password_commands']) > 0:
            analysis['risk_level'] = 'high'
        elif len(analysis['sudo_commands']) > 0:
            analysis['risk_level'] = 'medium'
        
        return analysis
    
    def _analyze_cron_jobs(self, cron_result: Dict) -> Dict:
        """Analyze cron jobs for persistence and lateral movement"""
        analysis = {
            'cron_entries': [],
            'suspicious_entries': [],
            'writable_scripts': [],
            'risk_level': 'low'
        }
        
        if not cron_result.get('success'):
            return analysis
        
        output = cron_result.get('output', '')
        lines = output.split('\n')
        
        suspicious_patterns = [
            r'wget|curl.*http',
            r'/tmp/.*\.sh',
            r'nc\s+.*\s+\d+',
            r'bash.*-i',
            r'/dev/tcp/'
        ]
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            analysis['cron_entries'].append(line)
            
            # Check for suspicious patterns
            for pattern in suspicious_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    analysis['suspicious_entries'].append(line)
                    break
        
        if len(analysis['suspicious_entries']) > 0:
            analysis['risk_level'] = 'high'
        elif len(analysis['cron_entries']) > 5:
            analysis['risk_level'] = 'medium'
        
        return analysis
    
    def _is_valid_target_ip(self, ip: str) -> bool:
        """Check if IP is a valid target for lateral movement"""
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            # Exclude loopback, multicast, and broadcast
            return not (ip_obj.is_loopback or ip_obj.is_multicast or 
                       ip_obj.is_reserved or str(ip_obj).endswith('.255'))
        except:
            return False
    
    def _calculate_lateral_risk_score(self, opportunities: Dict) -> int:
        """Calculate overall lateral movement risk score (0-100)"""
        score = 0
        
        # SSH keys risk
        ssh_keys = opportunities.get('ssh_keys', {})
        if ssh_keys.get('risk_level') == 'critical':
            score += 30
        elif ssh_keys.get('risk_level') == 'high':
            score += 20
        elif ssh_keys.get('risk_level') == 'medium':
            score += 10
        
        # Known hosts risk
        known_hosts = opportunities.get('known_hosts', {})
        if known_hosts.get('risk_level') == 'high':
            score += 15
        elif known_hosts.get('risk_level') == 'medium':
            score += 10
        
        # Network targets risk
        network = opportunities.get('network_targets', {})
        if network.get('risk_level') == 'high':
            score += 15
        elif network.get('risk_level') == 'medium':
            score += 10
        
        # Privilege escalation risk
        privesc = opportunities.get('privilege_escalation', {})
        if privesc.get('risk_level') == 'critical':
            score += 25
        elif privesc.get('risk_level') == 'high':
            score += 15
        elif privesc.get('risk_level') == 'medium':
            score += 10
        
        # Network shares risk
        shares = opportunities.get('network_shares', {})
        if shares.get('risk_level') == 'medium':
            score += 10
        
        # Scheduled tasks risk
        cron = opportunities.get('scheduled_tasks', {})
        if cron.get('risk_level') == 'high':
            score += 15
        elif cron.get('risk_level') == 'medium':
            score += 10
        
        return min(score, 100)
    
    def _generate_recommendations(self, opportunities: Dict) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        ssh_keys = opportunities.get('ssh_keys', {})
        if len(ssh_keys.get('private_keys', [])) > 0:
            recommendations.append("Secure or remove unnecessary SSH private keys")
        
        privesc = opportunities.get('privilege_escalation', {})
        if privesc.get('all_privileges'):
            recommendations.append("Review and restrict sudo ALL privileges")
        elif len(privesc.get('no_password_commands', [])) > 0:
            recommendations.append("Review NOPASSWD sudo commands")
        
        network = opportunities.get('network_targets', {})
        if network.get('host_count', 0) > 10:
            recommendations.append("Implement network segmentation")
        
        cron = opportunities.get('scheduled_tasks', {})
        if len(cron.get('suspicious_entries', [])) > 0:
            recommendations.append("Review suspicious cron job entries")
        
        shares = opportunities.get('network_shares', {})
        if shares.get('share_count', 0) > 0:
            recommendations.append("Audit network share permissions")
        
        if not recommendations:
            recommendations.append("No immediate lateral movement risks identified")
        
        return recommendations

def create_ssh_lateral_analyzer(tenant_id: str = "default") -> SSHLateralMovement:
    """Factory function to create SSH lateral movement analyzer"""
    return SSHLateralMovement(tenant_id)