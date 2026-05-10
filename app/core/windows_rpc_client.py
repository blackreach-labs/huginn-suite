"""
Windows RPC Client using native Windows authentication
Leverages existing Windows session for RPC communication
"""
import subprocess
import socket
import struct
import uuid
from typing import Dict, List, Optional
from .native_rpc_dump import dump_rpc_endpoints
import struct
import socket
from app.core.logger import logger

class WindowsRPCClient:
    def __init__(self):
        self.target = None
        self.authenticated = False
        
    def authenticate(self, target: str, domain: str, username: str, password: str) -> bool:
        """Authenticate using Windows net use command"""
        self.target = target
        
        try:
            # Clean up existing connections first
            self._cleanup_connections(target)
            
            # Establish authenticated session
            cmd = ['net', 'use', f'\\\\{target}\\IPC$', password, f'/user:{domain}\\{username}']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                self.authenticated = True
                return True
            return False
        except:
            return False
    
    def enumerate_services(self) -> List[Dict]:
        """Enumerate services via RPC"""
        if not self.authenticated:
            return []
        
        try:
            cmd = ['sc', f'\\\\{self.target}', 'query', 'state=', 'all']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                return []
            
            services = []
            lines = result.stdout.split('\n')
            current_service = {}
            
            for line in lines:
                line = line.strip()
                if line.startswith('SERVICE_NAME:'):
                    if current_service:
                        services.append(current_service)
                    current_service = {'name': line.split(':', 1)[1].strip()}
                elif line.startswith('DISPLAY_NAME:'):
                    current_service['display_name'] = line.split(':', 1)[1].strip()
                elif line.startswith('STATE'):
                    state_info = line.split(':', 1)[1].strip()
                    current_service['state'] = state_info.split()[0] if state_info else 'UNKNOWN'
                elif line.startswith('TYPE'):
                    type_info = line.split(':', 1)[1].strip()
                    current_service['type'] = type_info
            
            if current_service:
                services.append(current_service)
            
            return services
        except:
            return []
    
    def enumerate_registry(self) -> Dict:
        """Enumerate registry via RPC"""
        if not self.authenticated:
            return {}
        
        registry_data = {}
        
        # Get OS information
        try:
            cmd = ['reg', 'query', f'\\\\{self.target}\\HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                os_info = {}
                for line in result.stdout.split('\n'):
                    if 'REG_SZ' in line:
                        parts = line.strip().split('REG_SZ', 1)
                        if len(parts) == 2:
                            key = parts[0].strip()
                            value = parts[1].strip()
                            os_info[key] = value
                
                registry_data['os_info'] = os_info
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        
        return registry_data
    
    def enumerate_rpc_endpoints(self) -> List[Dict]:
        """Enumerate RPC endpoints"""
        endpoints = []
        
        # Check common RPC ports
        common_ports = [135, 445, 139, 593, 1024, 1025, 1026]
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.target, port))
                sock.close()
                
                if result == 0:
                    service_map = {
                        135: 'RPC Endpoint Mapper',
                        445: 'SMB over TCP',
                        139: 'NetBIOS Session Service',
                        593: 'RPC over HTTP',
                        1024: 'Dynamic RPC',
                        1025: 'Dynamic RPC',
                        1026: 'Dynamic RPC'
                    }
                    
                    endpoints.append({
                        'port': port,
                        'protocol': 'tcp',
                        'service': service_map.get(port, f'RPC Service on port {port}'),
                        'status': 'open'
                    })
            except:
                continue
        
        return endpoints
    
    def _cleanup_connections(self, target: str):
        """Clean up existing network connections"""
        try:
            cleanup_commands = [
                ['net', 'use', f'\\\\{target}', '/delete', '/y'],
                ['net', 'use', f'\\\\{target}\\IPC$', '/delete', '/y']
            ]
            
            for cmd in cleanup_commands:
                try:
                    subprocess.run(cmd, capture_output=True, text=True, timeout=3)
                except Exception as _exc:
                    pass
                    logger.debug("Suppressed exception", exc_info=True)
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
    
    def disconnect(self):
        """Clean up authentication"""
        if self.authenticated and self.target:
            self._cleanup_connections(self.target)
            self.authenticated = False



def enumerate_services_anonymous(target: str) -> List[Dict]:
    """Original working sc command method"""
    try:
        cmd = ["sc", f"\\\\{target}", "query"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0 and result.stdout:
            services = []
            lines = result.stdout.split('\n')
            current_service = {}
            
            for line in lines:
                line = line.strip()
                if line.startswith('SERVICE_NAME:'):
                    if current_service:
                        services.append(current_service)
                    current_service = {'name': line.split(':', 1)[1].strip()}
                elif line.startswith('DISPLAY_NAME:'):
                    current_service['display_name'] = line.split(':', 1)[1].strip()
                elif line.startswith('STATE'):
                    current_service['state'] = line.split(':', 1)[1].strip()
            
            if current_service:
                services.append(current_service)
            
            return services
        
        return []
            
    except Exception:
        return []

# Removed parse_sc_output - now inline in enumerate_services_anonymous

# Remove the parsing functions - they're now inline in the main function

def enumerate_registry_anonymous(target: str) -> Dict:
    """Try to enumerate registry without authentication using multiple methods"""
    registry_data = {}
    
    # Method 1: Try with hostname resolution
    try:
        import socket
        hostname = socket.gethostbyaddr(target)[0]
        cmd = ['reg', 'query', f'\\\\{hostname}\\HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        
        if result.returncode == 0:
            registry_data['os_info'] = parse_registry_output(result.stdout)
            return registry_data
    except Exception as _exc:
        pass
        logger.debug("Suppressed exception", exc_info=True)
    
    # Method 2: Try direct IP
    try:
        cmd = ['reg', 'query', f'\\\\{target}\\HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        
        if result.returncode == 0:
            registry_data['os_info'] = parse_registry_output(result.stdout)
            return registry_data
    except Exception as _exc:
        pass
        logger.debug("Suppressed exception", exc_info=True)
    
    # Method 3: Use WMI as fallback
    try:
        cmd = ['wmic', f'/node:{target}', 'os', 'get', 'caption,version,buildnumber', '/format:csv']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        
        if result.returncode == 0:
            registry_data['os_info'] = parse_wmic_os_output(result.stdout)
    except Exception as _exc:
        pass
        logger.debug("Suppressed exception", exc_info=True)
    
    return registry_data

def parse_registry_output(output: str) -> Dict:
    """Parse registry query output"""
    os_info = {}
    for line in output.split('\n'):
        if 'REG_SZ' in line:
            parts = line.strip().split('REG_SZ', 1)
            if len(parts) == 2:
                key = parts[0].strip()
                value = parts[1].strip()
                os_info[key] = value
    return os_info

def parse_wmic_os_output(output: str) -> Dict:
    """Parse WMIC OS output"""
    os_info = {}
    lines = output.split('\n')[1:]  # Skip header
    
    for line in lines:
        if line.strip() and ',' in line:
            parts = line.split(',')
            if len(parts) >= 4:
                os_info['ProductName'] = parts[2].strip()
                os_info['CurrentVersion'] = parts[3].strip()
                os_info['CurrentBuild'] = parts[1].strip()
                break
    
    return os_info

def get_mock_services_data() -> List[Dict]:
    """Mock service data to demonstrate full functionality"""
    return [
        {'name': 'ADWS', 'display_name': 'Active Directory Web Services', 'state': '4', 'type': 'WIN32_SHARE_PROCESS'},
        {'name': 'DNS', 'display_name': 'DNS Server', 'state': '4', 'type': 'WIN32_OWN_PROCESS'},
        {'name': 'Netlogon', 'display_name': 'Netlogon', 'state': '4', 'type': 'WIN32_SHARE_PROCESS'},
        {'name': 'NTDS', 'display_name': 'Active Directory Domain Services', 'state': '4', 'type': 'WIN32_OWN_PROCESS'},
        {'name': 'W32Time', 'display_name': 'Windows Time', 'state': '4', 'type': 'WIN32_SHARE_PROCESS'},
        {'name': 'DFSR', 'display_name': 'DFS Replication', 'state': '4', 'type': 'WIN32_OWN_PROCESS'},
        {'name': 'KDC', 'display_name': 'Kerberos Key Distribution Center', 'state': '4', 'type': 'WIN32_SHARE_PROCESS'},
        {'name': 'LanmanServer', 'display_name': 'Server', 'state': '4', 'type': 'WIN32_SHARE_PROCESS'},
        {'name': 'LanmanWorkstation', 'display_name': 'Workstation', 'state': '4', 'type': 'WIN32_SHARE_PROCESS'},
        {'name': 'RpcSs', 'display_name': 'Remote Procedure Call (RPC)', 'state': '4', 'type': 'WIN32_SHARE_PROCESS'},
        {'name': 'Spooler', 'display_name': 'Print Spooler', 'state': '4', 'type': 'WIN32_OWN_PROCESS'},
        {'name': 'EventLog', 'display_name': 'Windows Event Log', 'state': '4', 'type': 'WIN32_SHARE_PROCESS'},
        {'name': 'Themes', 'display_name': 'Themes', 'state': '1', 'type': 'WIN32_OWN_PROCESS'},
        {'name': 'BITS', 'display_name': 'Background Intelligent Transfer Service', 'state': '1', 'type': 'WIN32_OWN_PROCESS'},
        {'name': 'WSearch', 'display_name': 'Windows Search', 'state': '1', 'type': 'WIN32_OWN_PROCESS'}
    ]

def get_mock_registry_data() -> Dict:
    """Mock registry data to demonstrate full functionality"""
    return {
        'os_info': {
            'ProductName': 'Windows Server 2019 Standard',
            'CurrentVersion': '10.0',
            'CurrentBuild': '17763',
            'RegisteredOwner': 'Windows User',
            'RegisteredOrganization': 'LAB',
            'InstallDate': '1640995200'
        }
    }

def enumerate_target_rpc(target: str, domain: str, username: str, password: str) -> Dict:
    """Complete RPC enumeration of target"""
    results = {
        'target': target,
        'endpoints': [],
        'services': [],
        'registry': {},
        'rpc_endpoints': [],
        'errors': []
    }
    
    # Use Windows RPC client for authenticated operations (if credentials provided)
    if username and password:
        client = WindowsRPCClient()
        
        try:
            # Authenticate
            if client.authenticate(target, domain, username, password):
                # Enumerate services
                services = client.enumerate_services()
                results['services'] = services
                
                # Enumerate registry
                registry_data = client.enumerate_registry()
                results['registry'] = registry_data
            else:
                results['errors'].append('Authentication failed')
            
        except Exception as e:
            results['errors'].append(f'Enumeration error: {str(e)}')
        
        finally:
            client.disconnect()
    
    # Always try network endpoint enumeration (doesn't require auth)
    try:
        client = WindowsRPCClient()
        client.target = target  # Set target without authentication
        endpoints = client.enumerate_rpc_endpoints()
        results['endpoints'] = endpoints
    except Exception as e:
        results['errors'].append(f'Network enumeration error: {str(e)}')
    
    # Try the original working service enumeration method
    try:
        services = enumerate_services_anonymous(target)
        if services:
            results['services'] = services
    except Exception as e:
        results['errors'].append(f'Service enumeration error: {str(e)}')
    
    # Try anonymous registry access
    try:
        registry_data = enumerate_registry_anonymous(target)
        if registry_data:
            results['registry'] = registry_data
    except Exception as e:
        results['errors'].append(f'Anonymous registry enumeration error: {str(e)}')
    
    # Try enhanced RPC transport
    try:
        from .rpc_transport import RPCTransport
        transport = RPCTransport(target)
        transport.debug = False
        
        if transport.connect(username or '', password or '', domain or ''):
            # Get available endpoints
            endpoints = transport.get_endpoints()
            if endpoints:
                results['rpc_endpoints'] = endpoints
            
            # Real RPC enumeration calls
            samr_domains = transport.enumerate_samr_domains()
            if samr_domains:
                results['samr_domains'] = samr_domains
                # Extract users from domains
                all_users = []
                for domain in samr_domains:
                    all_users.extend(domain.get('users', []))
                if all_users:
                    results['samr_users'] = all_users
            
            lsa_policy = transport.query_lsa_policy()
            if lsa_policy:
                results['lsa_policy'] = lsa_policy
            
            # Service enumeration via RPC transport
            services = transport.enumerate_services_via_pipe()
            if services:
                results['services'] = services
            
            # Enhanced service enumeration
            from .rpc_service_enum import RPCServiceEnumerator
            enumerator = RPCServiceEnumerator(target)
            enumerator.debug = False
            
            enum_results = enumerator.enumerate_all_services()
            if enum_results.get('service_info'):
                results['service_info'] = enum_results['service_info']
            
            transport.disconnect()
        else:
            # Fallback to native RPC dump
            rpc_endpoints = dump_rpc_endpoints(target, 135)
            if rpc_endpoints:
                results['rpc_endpoints'] = rpc_endpoints
            
            # Try service enumeration as fallback
            if 'services' not in results:
                services = enumerate_services_anonymous(target)
                if services:
                    results['services'] = services
    except Exception as e:
        results['errors'].append(f'RPC endpoint query failed: {str(e)}')
    
    return results