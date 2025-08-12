"""
LDAP Enumeration Utilities
Worker classes and utility functions for LDAP enumeration
"""

import logging
from typing import Dict, List, Any, Optional, Callable
from PyQt6.QtCore import QObject, pyqtSignal, QRunnable

from app.core.base_worker import WorkerSignals
from .ldap_scanner import ldap_scanner

logger = logging.getLogger(__name__)

class LDAPWorkerSignals(WorkerSignals):
    """Extended signals for LDAP workers"""
    pass

class LDAPEnumWorker(QRunnable):
    """Worker for LDAP enumeration tasks"""
    
    def __init__(self, target: str, scan_type: str = "basic", port: int = 389, 
                 use_ssl: bool = False, username: str = None, password: str = None,
                 base_dn: str = None, output_callback: Callable = None, 
                 results_callback: Callable = None):
        super().__init__()
        self.signals = LDAPWorkerSignals()
        self.target = target
        self.scan_type = scan_type
        self.port = port
        self.use_ssl = use_ssl
        self.username = username
        self.password = password
        self.base_dn = base_dn
        self.output_callback = output_callback
        self.results_callback = results_callback
        self.is_running = True
        
    def run(self):
        """Execute LDAP enumeration"""
        try:
            self.signals.progress_start.emit("Starting LDAP enumeration...")
            
            if self.output_callback:
                protocol = "LDAPS" if self.use_ssl else "LDAP"
                self.output_callback(f"<p style='color: #00BFFF;'>Starting {protocol} enumeration on {self.target}:{self.port}</p>")
            
            results = {}
            
            if self.scan_type == "basic":
                results = self._run_basic_scan()
            elif self.scan_type == "anonymous":
                results = self._run_anonymous_enum()
            elif self.scan_type == "authenticated":
                results = self._run_authenticated_enum()
            elif self.scan_type == "full":
                results = self._run_full_scan()
            
            if self.results_callback:
                self.results_callback(results)
                
            self.signals.finished.emit()
            
        except Exception as e:
            logger.error(f"LDAP enumeration error: {e}")
            if self.output_callback:
                self.output_callback(f"<p style='color: #FF6B6B;'>Error: {str(e)}</p>")
            self.signals.error.emit(str(e))
    
    def _run_basic_scan(self) -> Dict[str, Any]:
        """Run basic LDAP connectivity scan"""
        if self.output_callback:
            self.output_callback("<p style='color: #FFD93D;'>Testing LDAP connectivity...</p>")
        
        results = ldap_scanner.scan_ldap_basic(self.target, self.port, self.use_ssl)
        
        if results['accessible']:
            if self.output_callback:
                self.output_callback(f"<p style='color: #6BCF7F;'>✓ LDAP service accessible on {self.target}:{self.port}</p>")
                if results['server_info']:
                    self.output_callback("<p style='color: #87CEEB;'>Server Information:</p>")
                    for key, value in results['server_info'].items():
                        self.output_callback(f"<p style='margin-left: 20px;'>{key}: {value}</p>")
        else:
            if self.output_callback:
                error_msg = results.get('error', 'Connection failed')
                self.output_callback(f"<p style='color: #FF6B6B;'>✗ LDAP service not accessible: {error_msg}</p>")
        
        return results
    
    def _run_anonymous_enum(self) -> Dict[str, Any]:
        """Run anonymous LDAP enumeration"""
        if self.output_callback:
            self.output_callback("<p style='color: #FFD93D;'>Attempting anonymous LDAP enumeration...</p>")
        
        results = ldap_scanner.anonymous_bind_enum(self.target, self.port, self.base_dn, self.use_ssl)
        
        if results['anonymous_bind']:
            if self.output_callback:
                self.output_callback("<p style='color: #6BCF7F;'>✓ Anonymous bind successful</p>")
                
                if results['base_dn']:
                    self.output_callback(f"<p style='color: #87CEEB;'>Base DN: {results['base_dn']}</p>")
                
                # Display users
                if results['users']:
                    self.output_callback(f"<p style='color: #87CEEB;'>Found {len(results['users'])} users:</p>")
                    for user in results['users'][:10]:  # Limit display
                        sam_account = user.get('sAMAccountName', 'N/A')
                        cn = user.get('cn', 'N/A')
                        self.output_callback(f"<p style='margin-left: 20px;'>• {sam_account} ({cn})</p>")
                    if len(results['users']) > 10:
                        self.output_callback(f"<p style='margin-left: 20px;'>... and {len(results['users']) - 10} more</p>")
                
                # Display groups
                if results['groups']:
                    self.output_callback(f"<p style='color: #87CEEB;'>Found {len(results['groups'])} groups:</p>")
                    for group in results['groups'][:5]:
                        cn = group.get('cn', 'N/A')
                        desc = group.get('description', '')
                        self.output_callback(f"<p style='margin-left: 20px;'>• {cn} - {desc}</p>")
                
                # Display service accounts
                if results['service_accounts']:
                    self.output_callback(f"<p style='color: #FFA500;'>Found {len(results['service_accounts'])} service accounts:</p>")
                    for svc in results['service_accounts']:
                        sam_account = svc.get('sAMAccountName', 'N/A')
                        self.output_callback(f"<p style='margin-left: 20px;'>• {sam_account}</p>")
        else:
            if self.output_callback:
                error_msg = results.get('error', 'Anonymous bind failed')
                self.output_callback(f"<p style='color: #FF6B6B;'>✗ Anonymous bind failed: {error_msg}</p>")
        
        return results
    
    def _run_authenticated_enum(self) -> Dict[str, Any]:
        """Run authenticated LDAP enumeration"""
        if not self.username or not self.password:
            if self.output_callback:
                self.output_callback("<p style='color: #FF6B6B;'>✗ Username and password required for authenticated enumeration</p>")
            return {'error': 'Credentials required'}
        
        if self.output_callback:
            self.output_callback(f"<p style='color: #FFD93D;'>Attempting authenticated LDAP enumeration as {self.username}...</p>")
        
        results = ldap_scanner.authenticated_enum(
            self.target, self.username, self.password, 
            self.port, self.base_dn, self.use_ssl
        )
        
        if results['authenticated']:
            if self.output_callback:
                self.output_callback("<p style='color: #6BCF7F;'>✓ Authentication successful</p>")
                
                if results['base_dn']:
                    self.output_callback(f"<p style='color: #87CEEB;'>Base DN: {results['base_dn']}</p>")
                
                # Display detailed user information
                if results['users']:
                    self.output_callback(f"<p style='color: #87CEEB;'>Found {len(results['users'])} users:</p>")
                    for user in results['users'][:10]:
                        sam_account = user.get('sAMAccountName', 'N/A')
                        cn = user.get('cn', 'N/A')
                        last_logon = user.get('lastLogon', 'N/A')
                        self.output_callback(f"<p style='margin-left: 20px;'>• {sam_account} ({cn}) - Last logon: {last_logon}</p>")
                
                # Display privileged users
                if results['privileged_users']:
                    self.output_callback(f"<p style='color: #FFA500;'>Found {len(results['privileged_users'])} privileged users:</p>")
                    for user in results['privileged_users']:
                        sam_account = user.get('sAMAccountName', 'N/A')
                        member_of = user.get('memberOf', [])
                        groups = ', '.join([g.split(',')[0].replace('CN=', '') for g in member_of[:2]])
                        self.output_callback(f"<p style='margin-left: 20px;'>• {sam_account} (Member of: {groups})</p>")
                
                # Display service accounts
                if results['service_accounts']:
                    self.output_callback(f"<p style='color: #FFA500;'>Found {len(results['service_accounts'])} service accounts:</p>")
                    for svc in results['service_accounts']:
                        sam_account = svc.get('sAMAccountName', 'N/A')
                        spn = svc.get('servicePrincipalName', [])
                        spn_str = spn[0] if spn else 'N/A'
                        self.output_callback(f"<p style='margin-left: 20px;'>• {sam_account} - SPN: {spn_str}</p>")
        else:
            if self.output_callback:
                error_msg = results.get('error', 'Authentication failed')
                self.output_callback(f"<p style='color: #FF6B6B;'>✗ Authentication failed: {error_msg}</p>")
        
        return results
    
    def _run_full_scan(self) -> Dict[str, Any]:
        """Run comprehensive LDAP enumeration"""
        if self.output_callback:
            self.output_callback("<p style='color: #FFD93D;'>Running comprehensive LDAP enumeration...</p>")
        
        all_results = {}
        
        # Basic connectivity
        basic_results = self._run_basic_scan()
        all_results['basic'] = basic_results
        
        if not basic_results.get('accessible'):
            return all_results
        
        # Anonymous enumeration
        anon_results = self._run_anonymous_enum()
        all_results['anonymous'] = anon_results
        
        # Authenticated enumeration if credentials provided
        if self.username and self.password:
            auth_results = self._run_authenticated_enum()
            all_results['authenticated'] = auth_results
        
        return all_results

def run_ldap_enumeration(target: str, scan_type: str = "basic", port: int = 389,
                        use_ssl: bool = False, username: str = None, password: str = None,
                        base_dn: str = None, output_callback: Callable = None,
                        results_callback: Callable = None) -> LDAPEnumWorker:
    """Create and return LDAP enumeration worker"""
    worker = LDAPEnumWorker(
        target=target,
        scan_type=scan_type,
        port=port,
        use_ssl=use_ssl,
        username=username,
        password=password,
        base_dn=base_dn,
        output_callback=output_callback,
        results_callback=results_callback
    )
    return worker

def generate_base_dn_suggestions(target: str) -> List[str]:
    """Generate common base DN suggestions for a target"""
    suggestions = []
    
    if '.' in target:
        # Convert domain.com to DC=domain,DC=com
        parts = target.split('.')
        base_dn = ','.join([f'DC={part}' for part in parts])
        suggestions.append(base_dn)
    
    # Common base DN patterns
    suggestions.extend([
        f'DC={target},DC=local',
        f'DC={target},DC=com',
        f'DC={target},DC=org',
        'DC=domain,DC=com',
        'DC=corp,DC=local',
        'DC=company,DC=com'
    ])
    
    return list(set(suggestions))  # Remove duplicates

def format_ldap_results(results: Dict[str, Any]) -> str:
    """Format LDAP results for display"""
    if not results:
        return "No results available"
    
    output = []
    
    # Basic info
    if 'accessible' in results:
        status = "✓ Accessible" if results['accessible'] else "✗ Not accessible"
        output.append(f"LDAP Status: {status}")
    
    # Users
    if 'users' in results and results['users']:
        output.append(f"\nUsers ({len(results['users'])}):")
        for user in results['users'][:20]:  # Limit output
            sam_account = user.get('sAMAccountName', 'N/A')
            cn = user.get('cn', 'N/A')
            output.append(f"  • {sam_account} ({cn})")
    
    # Service accounts
    if 'service_accounts' in results and results['service_accounts']:
        output.append(f"\nService Accounts ({len(results['service_accounts'])}):")
        for svc in results['service_accounts']:
            sam_account = svc.get('sAMAccountName', 'N/A')
            output.append(f"  • {sam_account}")
    
    # Groups
    if 'groups' in results and results['groups']:
        output.append(f"\nGroups ({len(results['groups'])}):")
        for group in results['groups'][:10]:
            cn = group.get('cn', 'N/A')
            desc = group.get('description', '')
            output.append(f"  • {cn} - {desc}")
    
    return '\n'.join(output)