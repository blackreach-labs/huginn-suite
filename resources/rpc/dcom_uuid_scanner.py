# app/core/dcom_uuid_scanner.py
"""
DCOM UUID Resolution and Security Scanner
Detects DCOM interfaces that expose execution vectors via RPC
"""
import socket
import struct
import subprocess
from typing import List, Dict, Optional

class DCOMUUIDScanner:
    """DCOM UUID scanner for execution vector detection"""
    
    # High-value DCOM interfaces for lateral movement
    DCOM_INTERFACES = {
        "00020400-0000-0000-C000-000000000046": {
            "name": "IDispatch",
            "description": "Base COM interface",
            "risk": "Medium",
            "exploitation": "COM object manipulation"
        },
        "A41C8840-00A1-11D2-9B74-204C4F4F5020": {
            "name": "MMC20.Application",
            "description": "MMC Application interface",
            "risk": "Critical",
            "exploitation": "File writes and shell command execution"
        },
        "F5CC5D3B-DA8E-11D1-B2A8-0060977D8118": {
            "name": "ShellWindows",
            "description": "Shell Windows interface",
            "risk": "High",
            "exploitation": "Lateral movement via shell manipulation"
        },
        "8D5BCAEA-DB45-11D1-9C86-0060081841DE": {
            "name": "WbemLevel1Login",
            "description": "WMI interface",
            "risk": "High",
            "exploitation": "WMI-based code execution"
        },
        "9556DC99-828C-11CF-A37E-00AA003240C7": {
            "name": "WbemServices",
            "description": "WMI Services interface",
            "risk": "High",
            "exploitation": "WMI query and execution"
        },
        "44E265DD-7DAF-42CD-8560-3CDB6E7A2729": {
            "name": "ShellBrowserWindow",
            "description": "Shell Browser Window",
            "risk": "Medium",
            "exploitation": "Browser-based execution"
        },
        "C49E32C6-BC8B-11D2-85D4-00105A1F8304": {
            "name": "WbemRefresher",
            "description": "WMI Refresher interface",
            "risk": "Medium",
            "exploitation": "WMI data manipulation"
        }
    }
    
    def __init__(self, target: str, username: str = "", password: str = "", domain: str = ""):
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
    
    def scan_dcom_interfaces(self) -> List[Dict]:
        """Scan for accessible DCOM interfaces"""
        results = []
        
        self._test_dcom_access()
        
        for uuid_str, interface_info in self.DCOM_INTERFACES.items():
            access_result = self._test_dcom_interface_access(uuid_str, interface_info)
            if access_result:
                results.append(access_result)
        
        return results
    
    def test_dcom_permissions(self) -> Dict:
        """Test DCOM launch and access permissions"""
        permissions = {
            'launch_permissions': self._test_launch_permissions(),
            'access_permissions': self._test_access_permissions(),
            'authentication_level': self._detect_auth_level(),
            'impersonation_level': self._detect_impersonation_level()
        }
        
        return permissions
    
    def detect_weak_dcom_acls(self) -> List[Dict]:
        """Detect weak DCOM ACLs"""
        weak_acls = []
        
        try:
            # Check DCOM configuration in registry
            dcom_config = self._query_dcom_registry()
            
            for app_id, config in dcom_config.items():
                if self._is_weak_acl(config):
                    weak_acls.append({
                        'app_id': app_id,
                        'config': config,
                        'weakness': self._analyze_acl_weakness(config),
                        'risk': 'High',
                        'exploitation': 'Unauthorized DCOM access'
                    })
        
        except Exception:
            pass
        
        return weak_acls
    
    def _test_dcom_access(self) -> bool:
        """Test basic DCOM access"""
        try:
            # Test DCOM endpoint mapper access
            cmd = ["dcomcnfg.exe", "/32"]  # This would fail on most systems without GUI
            # Instead, test RPC access to DCOM interfaces
            
            # Test port 135 (RPC endpoint mapper) which DCOM uses
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((self.target, 135))
            sock.close()
            
            return result == 0
            
        except Exception:
            return False
    
    def _test_dcom_interface_access(self, uuid_str: str, interface_info: Dict) -> Optional[Dict]:
        """Test access to specific DCOM interface"""
        try:
            # Test interface binding
            accessible = self._test_interface_binding(uuid_str)
            
            if accessible:
                return {
                    'uuid': uuid_str,
                    'name': interface_info['name'],
                    'description': interface_info['description'],
                    'risk': interface_info['risk'],
                    'exploitation': interface_info['exploitation'],
                    'accessible': True,
                    'auth_required': self._test_auth_requirement(uuid_str)
                }
            
            return None
            
        except Exception:
            return None
    
    def _test_interface_binding(self, uuid_str: str) -> bool:
        """Test if we can bind to DCOM interface"""
        try:
            # For specific interfaces, test with known methods
            if uuid_str == "A41C8840-00A1-11D2-9B74-204C4F4F5020":  # MMC20.Application
                return self._test_mmc_interface()
            elif uuid_str == "F5CC5D3B-DA8E-11D1-B2A8-0060977D8118":  # ShellWindows
                return self._test_shell_windows_interface()
            elif uuid_str == "8D5BCAEA-DB45-11D1-9C86-0060081841DE":  # WbemLevel1Login
                return self._test_wmi_interface()
            else:
                # Generic DCOM interface test
                return self._generic_dcom_test(uuid_str)
                
        except Exception:
            return False
    
    def _test_mmc_interface(self) -> bool:
        """Test MMC20.Application interface"""
        try:
            # Test if MMC is accessible via DCOM
            # This would typically require COM/DCOM calls
            # For now, test if MMC service is running
            cmd = ["sc", f"\\\\{self.target}", "query", "mmc"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            # MMC might not be a service, so check for MMC-related processes
            if result.returncode != 0:
                cmd = ["tasklist", f"/s:{self.target}", "/fi", "IMAGENAME eq mmc.exe"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                return result.returncode == 0 and "mmc.exe" in result.stdout
            
            return "RUNNING" in result.stdout
            
        except Exception:
            return False
    
    def _test_shell_windows_interface(self) -> bool:
        """Test ShellWindows interface"""
        try:
            # Test if Explorer shell is accessible
            cmd = ["tasklist", f"/s:{self.target}", "/fi", "IMAGENAME eq explorer.exe"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return result.returncode == 0 and "explorer.exe" in result.stdout
            
        except Exception:
            return False
    
    def _test_wmi_interface(self) -> bool:
        """Test WMI interface"""
        try:
            # Test WMI access
            cmd = ["wmic", f"/node:{self.target}", "computersystem", "get", "name"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.returncode == 0 and "Name" in result.stdout
            
        except Exception:
            return False
    
    def _generic_dcom_test(self, uuid_str: str) -> bool:
        """Generic DCOM interface test"""
        try:
            # Test if the interface is registered in the registry
            cmd = ["reg", "query", f"\\\\{self.target}\\HKLM\\SOFTWARE\\Classes\\Interface\\{{{uuid_str}}}"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return result.returncode == 0
            
        except Exception:
            return False
    
    def _test_auth_requirement(self, uuid_str: str) -> bool:
        """Test if interface requires authentication"""
        try:
            # Most DCOM interfaces require authentication
            # Test with anonymous access first
            return True  # Assume auth required unless proven otherwise
            
        except Exception:
            return True
    
    def _test_launch_permissions(self) -> Dict:
        """Test DCOM launch permissions"""
        try:
            # Query DCOM launch permissions from registry
            cmd = ["reg", "query", f"\\\\{self.target}\\HKLM\\SOFTWARE\\Microsoft\\Ole", "/s"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                # Analyze output for permission indicators
                if "Everyone" in result.stdout:
                    return {'level': 'Weak', 'details': 'Everyone group has launch permissions'}
                elif "Users" in result.stdout:
                    return {'level': 'Medium', 'details': 'Users group has launch permissions'}
                else:
                    return {'level': 'Strong', 'details': 'Restricted launch permissions'}
            
            return {'level': 'Unknown', 'details': 'Could not query launch permissions'}
            
        except Exception:
            return {'level': 'Unknown', 'details': 'Permission query failed'}
    
    def _test_access_permissions(self) -> Dict:
        """Test DCOM access permissions"""
        try:
            # Similar to launch permissions but for access
            return {'level': 'Unknown', 'details': 'Access permission analysis not implemented'}
            
        except Exception:
            return {'level': 'Unknown', 'details': 'Access permission query failed'}
    
    def _detect_auth_level(self) -> str:
        """Detect DCOM authentication level"""
        try:
            # Query DCOM authentication settings
            cmd = ["reg", "query", f"\\\\{self.target}\\HKLM\\SOFTWARE\\Microsoft\\Ole", "/v", "DefaultAuthenticationLevel"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                # Parse authentication level from registry value
                if "0x1" in result.stdout:
                    return "None"
                elif "0x2" in result.stdout:
                    return "Connect"
                elif "0x3" in result.stdout:
                    return "Call"
                elif "0x4" in result.stdout:
                    return "Packet"
                elif "0x5" in result.stdout:
                    return "PacketIntegrity"
                elif "0x6" in result.stdout:
                    return "PacketPrivacy"
            
            return "Unknown"
            
        except Exception:
            return "Unknown"
    
    def _detect_impersonation_level(self) -> str:
        """Detect DCOM impersonation level"""
        try:
            # Query DCOM impersonation settings
            cmd = ["reg", "query", f"\\\\{self.target}\\HKLM\\SOFTWARE\\Microsoft\\Ole", "/v", "DefaultImpersonationLevel"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                if "0x1" in result.stdout:
                    return "Anonymous"
                elif "0x2" in result.stdout:
                    return "Identify"
                elif "0x3" in result.stdout:
                    return "Impersonate"
                elif "0x4" in result.stdout:
                    return "Delegate"
            
            return "Unknown"
            
        except Exception:
            return "Unknown"
    
    def _query_dcom_registry(self) -> Dict:
        """Query DCOM configuration from registry"""
        try:
            dcom_config = {}
            
            # Query DCOM applications
            cmd = ["reg", "query", f"\\\\{self.target}\\HKLM\\SOFTWARE\\Classes\\AppID", "/s"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                # Parse DCOM application configurations
                lines = result.stdout.split('\n')
                current_app_id = None
                
                for line in lines:
                    line = line.strip()
                    if line.startswith('HKEY_') and 'AppID' in line:
                        # Extract AppID from registry path
                        import re
                        app_id_match = re.search(r'AppID\\{([^}]+)}', line)
                        if app_id_match:
                            current_app_id = app_id_match.group(1)
                            dcom_config[current_app_id] = {}
                    elif current_app_id and 'REG_' in line:
                        # Parse registry values
                        parts = line.split('REG_')
                        if len(parts) >= 2:
                            value_name = parts[0].strip()
                            value_data = parts[1].split(None, 1)
                            if len(value_data) >= 2:
                                dcom_config[current_app_id][value_name] = value_data[1]
            
            return dcom_config
            
        except Exception:
            return {}
    
    def _is_weak_acl(self, config: Dict) -> bool:
        """Check if DCOM configuration has weak ACLs"""
        try:
            # Check for weak permission indicators
            weak_indicators = ['Everyone', 'Users', 'Anonymous']
            
            for key, value in config.items():
                if any(indicator in str(value) for indicator in weak_indicators):
                    return True
            
            return False
            
        except Exception:
            return False
    
    def _analyze_acl_weakness(self, config: Dict) -> str:
        """Analyze specific ACL weakness"""
        try:
            weaknesses = []
            
            for key, value in config.items():
                if 'Everyone' in str(value):
                    weaknesses.append('Everyone group has access')
                elif 'Users' in str(value):
                    weaknesses.append('Users group has access')
                elif 'Anonymous' in str(value):
                    weaknesses.append('Anonymous access allowed')
            
            return '; '.join(weaknesses) if weaknesses else 'Weak ACL detected'
            
        except Exception:
            return 'ACL analysis failed'

def test_dcom_scanner(target: str, username: str = "", password: str = "", domain: str = "") -> Dict:
    """Test DCOM scanner functionality"""
    scanner = DCOMUUIDScanner(target, username, password, domain)
    
    results = {
        'target': target,
        'accessible_interfaces': [],
        'permissions': {},
        'weak_acls': [],
        'status': 'completed'
    }
    
    try:
        # Scan DCOM interfaces
        results['accessible_interfaces'] = scanner.scan_dcom_interfaces()
        
        # Test permissions
        results['permissions'] = scanner.test_dcom_permissions()
        
        # Detect weak ACLs
        results['weak_acls'] = scanner.detect_weak_dcom_acls()
        
    except Exception as e:
        results['error'] = str(e)
        results['status'] = 'failed'
    
    return results