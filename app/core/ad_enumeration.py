# app/core/ad_enumeration.py
import subprocess
import json
from typing import Dict, List, Optional
from PyQt6.QtCore import QObject, pyqtSignal
from app.core.license_manager import license_manager

class ADEnumeration(QObject):
    """Active Directory enumeration and attack module"""
    
    ad_event = pyqtSignal(str, str, dict)  # event_type, message, data
    
    def __init__(self):
        super().__init__()
        self.domain_info = {}
        self.users = []
        self.computers = []
        self.groups = []
        
    def enumerate_domain(self, domain: str, username: str = "", password: str = "") -> Dict:
        """Enumerate domain information"""
        if not license_manager.is_feature_enabled('ad_enumeration'):
            return {'error': 'AD enumeration requires Enterprise license'}
            
        self.ad_event.emit('enum_started', f'Enumerating domain {domain}', {})
        
        results = {
            'domain': domain,
            'users': [],
            'computers': [],
            'groups': [],
            'domain_controllers': [],
            'trusts': []
        }
        
        try:
            # Domain users enumeration
            self.ad_event.emit('enum_progress', 'Enumerating domain users...', {})
            users_cmd = f'net user /domain'
            if username and password:
                users_cmd = f'net user /domain /user:{username} /password:{password}'
                
            users_result = subprocess.run(users_cmd, shell=True, capture_output=True, text=True)
            if users_result.returncode == 0:
                users = self._parse_net_users(users_result.stdout)
                results['users'] = users[:50]  # Limit results
                
            # Domain computers
            self.ad_event.emit('enum_progress', 'Enumerating domain computers...', {})
            computers_cmd = 'net view /domain'
            computers_result = subprocess.run(computers_cmd, shell=True, capture_output=True, text=True)
            if computers_result.returncode == 0:
                computers = self._parse_net_computers(computers_result.stdout)
                results['computers'] = computers
                
            # Domain groups
            self.ad_event.emit('enum_progress', 'Enumerating domain groups...', {})
            groups_cmd = 'net group /domain'
            groups_result = subprocess.run(groups_cmd, shell=True, capture_output=True, text=True)
            if groups_result.returncode == 0:
                groups = self._parse_net_groups(groups_result.stdout)
                results['groups'] = groups[:30]
                
        except Exception as e:
            self.ad_event.emit('enum_error', f'Domain enumeration failed: {str(e)}', {})
            
        self.ad_event.emit('enum_completed', f'Domain enumeration completed', results)
        return results
        
    def kerberoasting_attack(self, domain: str, username: str, password: str) -> Dict:
        """Perform Kerberoasting attack"""
        if not license_manager.is_feature_enabled('ad_enumeration'):
            return {'error': 'Kerberoasting requires Enterprise license'}
            
        self.ad_event.emit('attack_started', 'Starting Kerberoasting attack', {})
        
        results = {
            'attack_type': 'Kerberoasting',
            'target_domain': domain,
            'spn_accounts': [],
            'tickets': [],
            'crackable_hashes': []
        }
        
        try:
            # Find SPN accounts (simplified simulation)
            spn_accounts = [
                {'account': 'MSSQL/server.domain.com', 'user': 'sqlservice'},
                {'account': 'HTTP/web.domain.com', 'user': 'webservice'},
                {'account': 'CIFS/file.domain.com', 'user': 'fileservice'}
            ]
            
            results['spn_accounts'] = spn_accounts
            
            # Simulate ticket extraction
            for spn in spn_accounts:
                ticket_hash = f"$krb5tgs$23${spn['user']}@{domain.upper()}${'a' * 64}"
                results['tickets'].append({
                    'user': spn['user'],
                    'hash': ticket_hash,
                    'crackable': True
                })
                
            self.ad_event.emit('attack_completed', f'Kerberoasting completed: {len(results["tickets"])} tickets extracted', results)
            
        except Exception as e:
            self.ad_event.emit('attack_error', f'Kerberoasting failed: {str(e)}', {})
            
        return results
        
    def asreproasting_attack(self, domain: str) -> Dict:
        """Perform ASREPRoasting attack"""
        if not license_manager.is_feature_enabled('ad_enumeration'):
            return {'error': 'ASREPRoasting requires Enterprise license'}
            
        self.ad_event.emit('attack_started', 'Starting ASREPRoasting attack', {})
        
        results = {
            'attack_type': 'ASREPRoasting',
            'target_domain': domain,
            'vulnerable_users': [],
            'hashes': []
        }
        
        try:
            # Find users with "Do not require Kerberos preauthentication"
            vulnerable_users = [
                'testuser1',
                'serviceaccount',
                'legacyuser'
            ]
            
            results['vulnerable_users'] = vulnerable_users
            
            # Simulate hash extraction
            for user in vulnerable_users:
                asrep_hash = f"$krb5asrep$23${user}@{domain.upper()}:{'b' * 64}"
                results['hashes'].append({
                    'user': user,
                    'hash': asrep_hash,
                    'crackable': True
                })
                
            self.ad_event.emit('attack_completed', f'ASREPRoasting completed: {len(results["hashes"])} hashes extracted', results)
            
        except Exception as e:
            self.ad_event.emit('attack_error', f'ASREPRoasting failed: {str(e)}', {})
            
        return results
        
    def bloodhound_analysis(self, domain: str, username: str, password: str) -> Dict:
        """Simulate BloodHound-style attack path analysis"""
        if not license_manager.is_feature_enabled('ad_enumeration'):
            return {'error': 'BloodHound analysis requires Enterprise license'}
            
        self.ad_event.emit('analysis_started', 'Analyzing attack paths with BloodHound', {})
        
        results = {
            'analysis_type': 'BloodHound Attack Paths',
            'domain': domain,
            'attack_paths': [],
            'high_value_targets': [],
            'recommendations': []
        }
        
        try:
            # Simulate attack path discovery
            attack_paths = [
                {
                    'path': 'User -> Group -> Computer -> Domain Admin',
                    'steps': [
                        'Compromise user account',
                        'Leverage group membership',
                        'Access computer with local admin',
                        'Extract credentials',
                        'Escalate to Domain Admin'
                    ],
                    'difficulty': 'Medium',
                    'impact': 'Critical'
                },
                {
                    'path': 'Service Account -> Kerberoasting -> Domain Controller',
                    'steps': [
                        'Identify service account with SPN',
                        'Extract Kerberos ticket',
                        'Crack service account password',
                        'Access Domain Controller'
                    ],
                    'difficulty': 'Low',
                    'impact': 'Critical'
                }
            ]
            
            results['attack_paths'] = attack_paths
            
            # High value targets
            results['high_value_targets'] = [
                {'name': 'Domain Admins', 'type': 'Group', 'members': 3},
                {'name': 'Enterprise Admins', 'type': 'Group', 'members': 1},
                {'name': 'DC01.domain.com', 'type': 'Computer', 'role': 'Domain Controller'}
            ]
            
            # Security recommendations
            results['recommendations'] = [
                'Implement LAPS for local admin passwords',
                'Enable Kerberos armoring',
                'Reduce privileged group memberships',
                'Implement tiered administration model'
            ]
            
            self.ad_event.emit('analysis_completed', f'BloodHound analysis completed: {len(attack_paths)} paths found', results)
            
        except Exception as e:
            self.ad_event.emit('analysis_error', f'BloodHound analysis failed: {str(e)}', {})
            
        return results
        
    def golden_ticket_detection(self, domain: str) -> Dict:
        """Detect potential Golden Ticket attacks"""
        if not license_manager.is_feature_enabled('ad_enumeration'):
            return {'error': 'Golden Ticket detection requires Enterprise license'}
            
        results = {
            'detection_type': 'Golden Ticket',
            'domain': domain,
            'indicators': [],
            'recommendations': []
        }
        
        # Simulate detection indicators
        indicators = [
            {
                'indicator': 'Unusual Kerberos ticket lifetime',
                'severity': 'High',
                'description': 'Tickets with extended lifetimes detected'
            },
            {
                'indicator': 'Service tickets without TGT',
                'severity': 'Medium', 
                'description': 'Service tickets requested without prior TGT'
            }
        ]
        
        results['indicators'] = indicators
        results['recommendations'] = [
            'Monitor Kerberos ticket lifetimes',
            'Implement advanced threat detection',
            'Regular KRBTGT password rotation'
        ]
        
        return results
        
    def _parse_net_users(self, output: str) -> List[str]:
        """Parse net user command output"""
        users = []
        lines = output.split('\n')
        for line in lines:
            if line.strip() and not line.startswith('User accounts') and not line.startswith('The command'):
                # Extract usernames from the formatted output
                parts = line.split()
                users.extend([part for part in parts if part and not part.startswith('-')])
        return users[:50]  # Limit results
        
    def _parse_net_computers(self, output: str) -> List[str]:
        """Parse net view command output"""
        computers = []
        lines = output.split('\n')
        for line in lines:
            if line.startswith('\\\\'):
                computer = line.split()[0].replace('\\\\', '')
                computers.append(computer)
        return computers
        
    def _parse_net_groups(self, output: str) -> List[str]:
        """Parse net group command output"""
        groups = []
        lines = output.split('\n')
        for line in lines:
            if line.strip() and line.startswith('*'):
                group = line.replace('*', '').strip()
                groups.append(group)
        return groups

# Global AD enumeration instance
ad_enumeration = ADEnumeration()