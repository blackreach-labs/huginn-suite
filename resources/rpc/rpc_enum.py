"""
Main RPC Enumeration Orchestrator
Coordinates SMB authentication and RPC enumeration
"""
from typing import Dict, Optional, List
from .smb_client import SMBClient
from .rpc_transport import RPCTransport
from .svcctl_client import SvcCtlClient
from .winreg_client import WinRegClient
from .secure_credential_manager import secure_credential_manager
import logging

class RPCEnumerator:
    def __init__(self):
        self.smb_client = None
        self.rpc_transport = None
        self.svcctl_client = None
        self.winreg_client = None
        
    def connect(self, target: str, domain: str = "", username: str = "", password: str = None, ntlm_hash: str = None, service_name: str = None) -> bool:
        """Establish authenticated connection to target"""
        try:
            # Get credentials from secure manager if service_name provided
            if service_name and not username:
                credential = secure_credential_manager.get_credential(service_name)
                if credential:
                    username = credential.username
                    password = credential.password
                    if credential.domain:
                        domain = credential.domain
                    elif '\\' in username:
                        domain, username = username.split('\\', 1)
                    elif '@' in username:
                        username, domain = username.split('@', 1)
            
            # Initialize SMB client
            self.smb_client = SMBClient()
            
            # Connect to SMB
            if not self.smb_client.connect(target):
                return False
            
            # Negotiate protocol
            if not self.smb_client.negotiate_protocol():
                return False
            
            # Authenticate
            if not self.smb_client.session_setup(domain, username, password, ntlm_hash):
                return False
            
            # Connect to IPC$
            if not self.smb_client.tree_connect("IPC$"):
                return False
            
            # Initialize RPC transport
            self.rpc_transport = RPCTransport(self.smb_client)
            
            return True
            
        except Exception as e:
            print(f"Connection failed: {e}")
            return False
    
    def enumerate_services(self) -> List[Dict]:
        """Enumerate Windows services"""
        if not self.rpc_transport:
            return []
        
        try:
            # Initialize service client
            self.svcctl_client = SvcCtlClient(self.rpc_transport)
            
            # Connect to service control manager
            if not self.svcctl_client.connect():
                return []
            
            # Open SCM
            if not self.svcctl_client.open_scm():
                return []
            
            # Enumerate services
            services = self.svcctl_client.enum_services()
            
            # Close SCM
            self.svcctl_client.close_scm()
            
            return services
            
        except Exception as e:
            print(f"Service enumeration failed: {e}")
            return []
    
    def enumerate_registry(self, keys_to_check: List[str] = None) -> Dict:
        """Enumerate registry information"""
        if not self.rpc_transport:
            return {}
        
        if keys_to_check is None:
            keys_to_check = [
                r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion',
                r'HKLM\SYSTEM\CurrentControlSet\Services',
                r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
            ]
        
        try:
            # Initialize registry client
            self.winreg_client = WinRegClient(self.rpc_transport)
            
            # Connect to registry
            if not self.winreg_client.connect():
                return {}
            
            registry_data = {}
            
            # Get OS information
            os_info = self.winreg_client.get_os_info()
            if os_info:
                registry_data['os_info'] = os_info
            
            # Check specific keys
            for key_path in keys_to_check:
                try:
                    # Parse hive and subkey
                    parts = key_path.split('\\', 1)
                    if len(parts) != 2:
                        continue
                    
                    hive, subkey = parts
                    
                    # Open key
                    key_handle = self.winreg_client.open_key(hive, subkey)
                    if key_handle:
                        # Get key info
                        key_info = {
                            'subkeys': self.winreg_client.enum_keys(key_handle),
                            'values': self.winreg_client.enum_values(key_handle)
                        }
                        
                        registry_data[key_path] = key_info
                        self.winreg_client.close_key(key_handle)
                        
                except Exception as e:
                    print(f"Failed to access key {key_path}: {e}")
                    continue
            
            return registry_data
            
        except Exception as e:
            print(f"Registry enumeration failed: {e}")
            return {}
    
    def enumerate_rpc_endpoints(self) -> List[Dict]:
        """Enumerate RPC endpoints via endpoint mapper"""
        # This would connect to port 135 and query the endpoint mapper
        # For now, return basic port information
        endpoints = []
        
        try:
            import socket
            
            # Check common RPC ports
            common_ports = [135, 445, 139, 593]
            target_ip = self.smb_client.socket.getpeername()[0] if self.smb_client and self.smb_client.socket else None
            
            if target_ip:
                for port in common_ports:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(2)
                        result = sock.connect_ex((target_ip, port))
                        sock.close()
                        
                        if result == 0:
                            port_info = {
                                'port': port,
                                'protocol': 'tcp',
                                'service': self._get_port_service(port),
                                'status': 'open'
                            }
                            endpoints.append(port_info)
                    except Exception:
                        continue
            
        except Exception as e:
            print(f"Endpoint enumeration failed: {e}")
        
        return endpoints
    
    def _get_port_service(self, port: int) -> str:
        """Map port numbers to service names"""
        port_map = {
            135: 'RPC Endpoint Mapper',
            139: 'NetBIOS Session Service',
            445: 'SMB over TCP',
            593: 'RPC over HTTP'
        }
        return port_map.get(port, f'Unknown service on port {port}')
    
    def full_enumeration(self) -> Dict:
        """Perform complete RPC enumeration"""
        results = {
            'endpoints': [],
            'services': [],
            'registry': {},
            'errors': []
        }
        
        try:
            # Enumerate RPC endpoints
            results['endpoints'] = self.enumerate_rpc_endpoints()
            
            # Enumerate services
            services = self.enumerate_services()
            results['services'] = services
            
            # Enumerate registry
            registry_data = self.enumerate_registry()
            results['registry'] = registry_data
            
        except Exception as e:
            results['errors'].append(f"Full enumeration error: {e}")
        
        return results
    
    def disconnect(self):
        """Clean up connections"""
        try:
            if self.svcctl_client:
                self.svcctl_client.close_scm()
            
            if self.smb_client:
                self.smb_client.close()
                
        except Exception as e:
            print(f"Disconnect error: {e}")
        
        finally:
            self.smb_client = None
            self.rpc_transport = None
            self.svcctl_client = None
            self.winreg_client = None

# Convenience function for quick enumeration
def enumerate_target(target: str, domain: str = "", username: str = "", password: str = None, ntlm_hash: str = None, service_name: str = None) -> Dict:
    """Perform RPC enumeration on target"""
    enumerator = RPCEnumerator()
    
    try:
        if not enumerator.connect(target, domain, username, password, ntlm_hash, service_name):
            return {'error': 'Failed to connect to target'}
        
        results = enumerator.full_enumeration()
        return results
        
    finally:
        enumerator.disconnect()

# Example usage
if __name__ == "__main__":
    # Example enumeration
    target = "192.168.1.100"
    domain = "DOMAIN"
    username = "user"
    password = "password"
    
    results = enumerate_target(target, domain, username, password)
    
    print("RPC Enumeration Results:")
    print(f"Endpoints found: {len(results.get('endpoints', []))}")
    print(f"Services found: {len(results.get('services', []))}")
    print(f"Registry keys accessed: {len(results.get('registry', {}))}")
    
    if results.get('errors'):
        print(f"Errors: {results['errors']}")