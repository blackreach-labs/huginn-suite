# app/core/rpc_enum_fixed.py
"""
Fixed RPC Enumeration Engine
Provides reliable RPC enumeration functionality for the new architecture
"""
import subprocess
import socket
import struct
from typing import Dict, List, Optional, Tuple
import uuid

class RPCEnumerator:
    """Enhanced RPC enumerator with fallback mechanisms"""
    
    def __init__(self, target: str):
        self.target = target
        self.debug = False
        self.timeout = 10
    
    def enumerate_rpc_services(self, username: str = "", password: str = "", domain: str = "") -> Dict:
        """Main RPC enumeration method with multiple fallback strategies"""
        results = {
            'target': self.target,
            'endpoints': [],
            'services': [],
            'rpc_endpoints': [],
            'registry': {},
            'errors': []
        }
        
        try:
            # Strategy 1: Direct RPC endpoint mapper query
            if self._test_rpc_connectivity():
                self._enumerate_rpc_endpoints(results)
            
            # Strategy 2: Service enumeration via sc command
            self._enumerate_services_sc(results, username, password, domain)
            
            # Strategy 3: Registry enumeration (if authenticated)
            if username and password:
                self._enumerate_registry_info(results, username, password, domain)
            
            # Strategy 4: Network port enumeration
            self._enumerate_network_ports(results)
            
        except Exception as e:
            results['errors'].append(f"RPC enumeration failed: {str(e)}")
        
        return results
    
    def _test_rpc_connectivity(self) -> bool:
        """Test basic RPC connectivity"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.target, 135))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def _enumerate_rpc_endpoints(self, results: Dict):
        """Enumerate RPC endpoints via endpoint mapper"""
        try:
            # Basic RPC endpoint detection
            rpc_services = [
                {'uuid': '12345778-1234-abcd-ef00-0123456789ac', 'name': 'SAMR', 'port': 135},
                {'uuid': '12345778-1234-abcd-ef00-0123456789ab', 'name': 'LSARPC', 'port': 135},
                {'uuid': '367abb81-9844-35f1-ad32-98f038001003', 'name': 'SVCCTL', 'port': 135},
                {'uuid': '338cd001-2244-31f1-aaaa-900038001003', 'name': 'WINREG', 'port': 135}
            ]
            
            accessible_endpoints = []
            for service in rpc_services:
                if self._test_rpc_service(service['name']):
                    accessible_endpoints.append({
                        'protocol': service['name'],
                        'uuid': service['uuid'],
                        'port': service['port'],
                        'annotation': f"RPC {service['name']} interface"
                    })
            
            results['rpc_endpoints'] = accessible_endpoints
            
        except Exception as e:
            results['errors'].append(f"RPC endpoint enumeration failed: {str(e)}")
    
    def _test_rpc_service(self, service_name: str) -> bool:
        """Test if specific RPC service is accessible"""
        try:
            if service_name == 'SVCCTL':
                # Test service control manager
                cmd = ["sc", f"\\\\{self.target}", "query", "state=", "all"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                return result.returncode == 0
            
            elif service_name == 'WINREG':
                # Test registry access
                cmd = ["reg", "query", f"\\\\{self.target}\\HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "/v", "ProductName"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                return result.returncode == 0 and "ProductName" in result.stdout
            
            elif service_name in ['SAMR', 'LSARPC']:
                # Test authentication-dependent services
                cmd = ["net", "use", f"\\\\{self.target}\\IPC$", "", "/user:"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    subprocess.run(["net", "use", f"\\\\{self.target}\\IPC$", "/delete"], capture_output=True, timeout=3)
                    return True
            
            return False
            
        except Exception:
            return False
    
    def _enumerate_services_sc(self, results: Dict, username: str, password: str, domain: str):
        """Enumerate services using sc command"""
        try:
            # Try anonymous first
            cmd = ["sc", f"\\\\{self.target}", "query"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 and result.stdout:
                services = self._parse_sc_output(result.stdout)
                results['services'] = services
            else:
                # Try with authentication if available
                if username and password:
                    if self._establish_auth_session(username, password, domain):
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                        if result.returncode == 0 and result.stdout:
                            services = self._parse_sc_output(result.stdout)
                            results['services'] = services
                        self._cleanup_auth_session()
                
        except subprocess.TimeoutExpired:
            results['errors'].append("Service enumeration timed out")
        except Exception as e:
            results['errors'].append(f"Service enumeration failed: {str(e)}")
    
    def _parse_sc_output(self, output: str) -> List[Dict]:
        """Parse sc query output"""
        services = []
        lines = output.split('\n')
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
        
        if current_service:
            services.append(current_service)
        
        return services
    
    def _enumerate_registry_info(self, results: Dict, username: str, password: str, domain: str):
        """Enumerate registry information with authentication"""
        try:
            if self._establish_auth_session(username, password, domain):
                cmd = ["reg", "query", f"\\\\{self.target}\\HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                
                if result.returncode == 0:
                    registry_info = self._parse_registry_output(result.stdout)
                    results['registry'] = {'os_info': registry_info, 'accessible': True}
                else:
                    results['registry'] = {'accessible': False}
                
                self._cleanup_auth_session()
            
        except Exception as e:
            results['errors'].append(f"Registry enumeration failed: {str(e)}")
    
    def _parse_registry_output(self, output: str) -> Dict:
        """Parse registry query output"""
        registry_info = {}
        for line in output.split('\n'):
            if 'REG_SZ' in line:
                parts = line.strip().split('REG_SZ', 1)
                if len(parts) == 2:
                    key = parts[0].strip()
                    value = parts[1].strip()
                    registry_info[key] = value
        return registry_info
    
    def _enumerate_network_ports(self, results: Dict):
        """Enumerate accessible network ports"""
        try:
            common_rpc_ports = [135, 445, 139, 593, 1024, 1025, 1026]
            accessible_ports = []
            
            for port in common_rpc_ports:
                if self._test_port_connectivity(port):
                    service_map = {
                        135: 'RPC Endpoint Mapper',
                        445: 'SMB/RPC Named Pipes',
                        139: 'NetBIOS Session Service',
                        593: 'RPC over HTTP',
                        1024: 'Dynamic RPC',
                        1025: 'Dynamic RPC',
                        1026: 'Dynamic RPC'
                    }
                    
                    accessible_ports.append({
                        'port': port,
                        'service': service_map.get(port, f'RPC Service on port {port}'),
                        'protocol': 'tcp',
                        'status': 'open'
                    })
            
            results['endpoints'] = accessible_ports
            
        except Exception as e:
            results['errors'].append(f"Network port enumeration failed: {str(e)}")
    
    def _test_port_connectivity(self, port: int) -> bool:
        """Test connectivity to specific port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((self.target, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def _establish_auth_session(self, username: str, password: str, domain: str) -> bool:
        """Establish authenticated session"""
        try:
            user_format = f"{domain}\\{username}" if domain else username
            cmd = ["net", "use", f"\\\\{self.target}\\IPC$", password, f"/user:{user_format}"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except Exception:
            return False
    
    def _cleanup_auth_session(self):
        """Clean up authenticated session"""
        try:
            subprocess.run(["net", "use", f"\\\\{self.target}\\IPC$", "/delete", "/y"], 
                         capture_output=True, timeout=5)
        except Exception:
            pass

# Factory function for backward compatibility
def enumerate_target_rpc(target: str, domain: str, username: str, password: str) -> Dict:
    """Factory function to maintain compatibility with existing code"""
    enumerator = RPCEnumerator(target)
    return enumerator.enumerate_rpc_services(username, password, domain)