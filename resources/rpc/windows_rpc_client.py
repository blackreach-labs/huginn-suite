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

class WindowsRPCClient:
    def __init__(self):
        self.target = None
        self.authenticated = False
        
    def authenticate(self, target: str, domain: str, username: str, password: str) -> bool:
        """Authenticate using Windows net use command"""
        self.target = target
        
        try:
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
        except:
            pass
        
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
    
    def disconnect(self):
        """Clean up authentication"""
        if self.authenticated and self.target:
            try:
                subprocess.run(['net', 'use', f'\\\\{self.target}\\IPC$', '/delete'], 
                             capture_output=True, text=True, timeout=5)
            except:
                pass
            self.authenticated = False



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
    
    # Use Windows RPC client for authenticated operations
    client = WindowsRPCClient()
    
    try:
        # Authenticate
        if not client.authenticate(target, domain, username, password):
            results['errors'].append('Authentication failed')
            return results
        
        # Enumerate services
        services = client.enumerate_services()
        results['services'] = services
        
        # Enumerate registry
        registry_data = client.enumerate_registry()
        results['registry'] = registry_data
        
        # Enumerate network endpoints
        endpoints = client.enumerate_rpc_endpoints()
        results['endpoints'] = endpoints
        
    except Exception as e:
        results['errors'].append(f'Enumeration error: {str(e)}')
    
    finally:
        client.disconnect()
    
    # Try native RPC endpoint mapper query
    try:
        rpc_endpoints = dump_rpc_endpoints(target, 135)
        if rpc_endpoints:
            results['rpc_endpoints'] = rpc_endpoints
    except Exception as e:
        results['errors'].append(f'RPC endpoint query failed: {str(e)}')
    
    return results