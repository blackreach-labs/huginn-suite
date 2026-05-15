# app/core/smb_diagnostics.py
import socket
import struct
import time
from typing import Dict, List, Tuple, Optional
from app.core.logger import logger

class SMBDiagnostics:
    """Comprehensive SMB connection diagnostics and troubleshooting"""
    
    def __init__(self, target: str, port: int = 445):
        self.target = target
        self.port = port
        self.results = {}
    
    def run_full_diagnostics(self) -> Dict:
        """Run complete SMB connection diagnostics"""
        print(f"[SMB DIAGNOSTICS] Starting comprehensive analysis for {self.target}:{self.port}")
        
        self.results = {
            'target': self.target,
            'port': self.port,
            'timestamp': time.time(),
            'tests': {}
        }
        
        # Test 1: Basic TCP connectivity
        self.results['tests']['tcp_connectivity'] = self._test_tcp_connectivity()
        
        # Test 2: Port banner/service detection
        self.results['tests']['service_detection'] = self._test_service_detection()
        
        # Test 3: NetBIOS session establishment
        self.results['tests']['netbios_session'] = self._test_netbios_session()
        
        # Test 4: SMB protocol negotiation
        self.results['tests']['smb_negotiation'] = self._test_smb_negotiation()
        
        # Test 5: Alternative connection methods
        self.results['tests']['alternative_methods'] = self._test_alternative_methods()
        
        # Generate recommendations
        self.results['recommendations'] = self._generate_recommendations()
        
        return self.results
    
    def _test_tcp_connectivity(self) -> Dict:
        """Test basic TCP connectivity"""
        print("[TEST 1] Testing TCP connectivity...")
        
        result = {
            'test_name': 'TCP Connectivity',
            'success': False,
            'details': {},
            'errors': []
        }
        
        try:
            # Test with different timeouts
            for timeout in [5, 10, 15]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    
                    start_time = time.time()
                    sock.connect((self.target, self.port))
                    connect_time = time.time() - start_time
                    
                    result['success'] = True
                    result['details']['connect_time'] = connect_time
                    result['details']['timeout_used'] = timeout
                    
                    # Test socket properties
                    result['details']['local_address'] = sock.getsockname()
                    result['details']['remote_address'] = sock.getpeername()
                    
                    sock.close()
                    print(f"[+] TCP connection successful (timeout: {timeout}s, time: {connect_time:.2f}s)")
                    break
                    
                except socket.timeout:
                    result['errors'].append(f"Connection timeout with {timeout}s timeout")
                    print(f"[-] Connection timeout with {timeout}s timeout")
                except socket.error as e:
                    result['errors'].append(f"Socket error with {timeout}s timeout: {str(e)}")
                    print(f"[-] Socket error with {timeout}s timeout: {str(e)}")
                finally:
                    try:
                        sock.close()
                    except Exception as _exc:
                        pass
                        logger.debug("Suppressed exception", exc_info=True)
        
        except Exception as e:
            result['errors'].append(f"TCP test exception: {str(e)}")
            print(f"[-] TCP test exception: {str(e)}")
        
        return result
    
    def _test_service_detection(self) -> Dict:
        """Test service detection and banner grabbing"""
        print("[TEST 2] Testing service detection...")
        
        result = {
            'test_name': 'Service Detection',
            'success': False,
            'details': {},
            'errors': []
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.target, self.port))
            
            # Try to detect service type
            sock.settimeout(3)
            
            # Send a simple probe
            try:
                sock.send(b'\x00\x00\x00\x01')  # Simple probe
                response = sock.recv(1024)
                
                if response:
                    result['details']['probe_response'] = response.hex()
                    result['details']['response_length'] = len(response)
                    
                    # Analyze response
                    if b'SMB' in response or b'\xfeSMB' in response:
                        result['details']['service_type'] = 'SMB/CIFS'
                        result['success'] = True
                        print("[+] SMB/CIFS service detected")
                    else:
                        result['details']['service_type'] = 'Unknown'
                        print(f"[?] Unknown service (response: {response[:20].hex()}...)")
                
            except socket.timeout:
                result['details']['probe_timeout'] = True
                print("[?] Service probe timeout (normal for SMB)")
            
            sock.close()
            
        except Exception as e:
            result['errors'].append(f"Service detection error: {str(e)}")
            print(f"[-] Service detection error: {str(e)}")
        
        return result
    
    def _test_netbios_session(self) -> Dict:
        """Test NetBIOS session establishment with multiple methods"""
        print("[TEST 3] Testing NetBIOS session establishment...")
        
        result = {
            'test_name': 'NetBIOS Session',
            'success': False,
            'details': {},
            'errors': [],
            'methods_tested': []
        }
        
        # Different NetBIOS session methods to try
        methods = [
            ('Standard', '*SMBSERVER', 'HUGINN'),
            ('Target Name', self.target.upper(), 'HUGINN'),
            ('Generic', 'WINDOWS', 'CLIENT'),
            ('Minimal', '*', 'H')
        ]
        
        for method_name, server_name, client_name in methods:
            print(f"  Testing method: {method_name} (server: {server_name}, client: {client_name})")
            
            method_result = {
                'method': method_name,
                'server_name': server_name,
                'client_name': client_name,
                'success': False,
                'error': None
            }
            
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((self.target, self.port))
                
                # Build NetBIOS session request
                called_name = self._build_netbios_name(server_name, 0x20)
                calling_name = self._build_netbios_name(client_name, 0x00)
                
                data_length = len(called_name) + len(calling_name)
                session_request = b'\x81' + struct.pack('>I', data_length)[1:] + called_name + calling_name
                
                method_result['request_length'] = len(session_request)
                method_result['called_name_hex'] = called_name.hex()
                method_result['calling_name_hex'] = calling_name.hex()
                
                # Send request
                sock.send(session_request)
                
                # Receive response
                sock.settimeout(5)
                response = sock.recv(4)
                
                if len(response) >= 1:
                    response_type = response[0]
                    method_result['response_type'] = hex(response_type)
                    
                    if response_type == 0x82:  # Positive session response
                        method_result['success'] = True
                        result['success'] = True
                        result['details']['successful_method'] = method_name
                        print(f"    [+] Success with method: {method_name}")
                    elif response_type == 0x83:  # Negative session response
                        if len(response) >= 2:
                            error_code = response[1]
                            method_result['error_code'] = hex(error_code)
                            method_result['error'] = self._get_netbios_error(error_code)
                        print(f"    [-] Rejected: {method_result.get('error', 'Unknown error')}")
                    else:
                        method_result['error'] = f"Unexpected response type: {hex(response_type)}"
                        print(f"    [?] Unexpected response: {hex(response_type)}")
                else:
                    method_result['error'] = "No response received"
                    print(f"    [-] No response received")
                
                sock.close()
                
            except Exception as e:
                method_result['error'] = str(e)
                print(f"    [-] Exception: {str(e)}")
            
            result['methods_tested'].append(method_result)
            
            if method_result['success']:
                break  # Stop on first success
        
        return result
    
    def _test_smb_negotiation(self) -> Dict:
        """Test SMB protocol negotiation"""
        print("[TEST 4] Testing SMB protocol negotiation...")
        
        result = {
            'test_name': 'SMB Negotiation',
            'success': False,
            'details': {},
            'errors': []
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15)
            sock.connect((self.target, self.port))
            
            # Try NetBIOS session first (use successful method from previous test)
            successful_method = None
            if 'netbios_session' in self.results.get('tests', {}):
                successful_method = self.results['tests']['netbios_session']['details'].get('successful_method')
            
            if successful_method:
                print(f"  Using successful NetBIOS method: {successful_method}")
                # Use the successful NetBIOS method
                for method_data in self.results['tests']['netbios_session']['methods_tested']:
                    if method_data['method'] == successful_method and method_data['success']:
                        server_name = method_data['server_name']
                        client_name = method_data['client_name']
                        
                        called_name = self._build_netbios_name(server_name, 0x20)
                        calling_name = self._build_netbios_name(client_name, 0x00)
                        data_length = len(called_name) + len(calling_name)
                        session_request = b'\x81' + struct.pack('>I', data_length)[1:] + called_name + calling_name
                        
                        sock.send(session_request)
                        response = sock.recv(4)
                        break
            else:
                print("  Skipping NetBIOS session (no successful method found)")
            
            # Test SMB2 negotiate
            print("  Testing SMB2 negotiate...")
            smb2_result = self._test_smb2_negotiate(sock)
            result['details']['smb2'] = smb2_result
            
            if smb2_result['success']:
                result['success'] = True
                print(f"    [+] SMB2 negotiate successful, dialect: {smb2_result.get('dialect', 'Unknown')}")
            else:
                print(f"    [-] SMB2 negotiate failed: {smb2_result.get('error', 'Unknown error')}")
                
                # Try SMB1 negotiate as fallback
                print("  Testing SMB1 negotiate...")
                smb1_result = self._test_smb1_negotiate(sock)
                result['details']['smb1'] = smb1_result
                
                if smb1_result['success']:
                    result['success'] = True
                    print("    [+] SMB1 negotiate successful")
                else:
                    print(f"    [-] SMB1 negotiate failed: {smb1_result.get('error', 'Unknown error')}")
            
            sock.close()
            
        except Exception as e:
            result['errors'].append(f"SMB negotiation test error: {str(e)}")
            print(f"[-] SMB negotiation test error: {str(e)}")
        
        return result
    
    def _test_smb2_negotiate(self, sock: socket.socket) -> Dict:
        """Test SMB2 negotiate"""
        try:
            # SMB2 negotiate request
            negotiate_data = struct.pack('<H', 36)  # StructureSize
            negotiate_data += struct.pack('<H', 1)   # DialectCount
            negotiate_data += struct.pack('<H', 0)   # SecurityMode
            negotiate_data += struct.pack('<H', 0)   # Reserved
            negotiate_data += struct.pack('<I', 0)   # Capabilities
            negotiate_data += b'\x00' * 16           # ClientGuid
            negotiate_data += struct.pack('<Q', 0)   # ClientStartTime
            negotiate_data += struct.pack('<H', 0x0202)  # SMB 2.02
            
            # SMB2 header
            header = b'\xfeSMB'  # Protocol ID
            header += struct.pack('<H', 64)  # StructureSize
            header += struct.pack('<H', 0)   # CreditCharge
            header += struct.pack('<I', 0)   # Status
            header += struct.pack('<H', 0)   # Command (NEGOTIATE)
            header += struct.pack('<H', 1)   # CreditRequest
            header += struct.pack('<I', 0)   # Flags
            header += struct.pack('<I', 0)   # NextCommand
            header += struct.pack('<Q', 1)   # MessageId
            header += struct.pack('<I', 0)   # ProcessId
            header += struct.pack('<I', 0)   # TreeId
            header += struct.pack('<Q', 0)   # SessionId
            header += b'\x00' * 16           # Signature
            
            # NetBIOS header
            total_length = len(header) + len(negotiate_data)
            netbios_header = struct.pack('>I', total_length & 0x00FFFFFF)
            
            full_request = netbios_header + header + negotiate_data
            
            sock.send(full_request)
            
            # Receive response
            sock.settimeout(10)
            netbios_resp = sock.recv(4)
            
            if len(netbios_resp) != 4:
                return {'success': False, 'error': f'Invalid NetBIOS header: {len(netbios_resp)} bytes'}
            
            response_length = struct.unpack('>I', netbios_resp)[0] & 0x00FFFFFF
            
            response = b''
            while len(response) < response_length:
                chunk = sock.recv(response_length - len(response))
                if not chunk:
                    break
                response += chunk
            
            if len(response) >= 72:
                # Parse SMB2 response
                if response[:4] == b'\xfeSMB':
                    status = struct.unpack('<I', response[8:12])[0]
                    if status == 0:
                        dialect = struct.unpack('<H', response[72:74])[0] if len(response) >= 74 else 0
                        return {
                            'success': True,
                            'dialect': hex(dialect),
                            'response_length': len(response)
                        }
                    else:
                        return {
                            'success': False,
                            'error': f'SMB2 error status: {hex(status)}',
                            'status': hex(status)
                        }
                else:
                    return {
                        'success': False,
                        'error': f'Invalid SMB2 response signature: {response[:4].hex()}'
                    }
            else:
                return {
                    'success': False,
                    'error': f'SMB2 response too short: {len(response)} bytes'
                }
        
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _test_smb1_negotiate(self, sock: socket.socket) -> Dict:
        """Test SMB1 negotiate"""
        try:
            # SMB1 negotiate request
            smb1_data = b'\x00'  # Word count
            smb1_data += struct.pack('<H', 12)  # Byte count
            smb1_data += b'\x02'  # Dialect marker
            smb1_data += b'NT LM 0.12\x00'  # Dialect string
            
            # SMB1 header
            header = b'\xffSMB'  # Protocol
            header += b'\x72'    # Command (Negotiate)
            header += struct.pack('<I', 0)  # Status
            header += b'\x18'    # Flags
            header += struct.pack('<H', 0)  # Flags2
            header += struct.pack('<H', 0)  # PID High
            header += b'\x00' * 8  # Signature
            header += struct.pack('<H', 0)  # Reserved
            header += struct.pack('<H', 0)  # TID
            header += struct.pack('<H', 0)  # PID
            header += struct.pack('<H', 0)  # UID
            header += struct.pack('<H', 1)  # MID
            
            full_request = header + smb1_data
            sock.send(full_request)
            
            # Receive response
            sock.settimeout(10)
            response = sock.recv(1024)
            
            if len(response) >= 32 and response[:4] == b'\xffSMB':
                return {
                    'success': True,
                    'response_length': len(response)
                }
            else:
                return {
                    'success': False,
                    'error': f'Invalid SMB1 response: {response[:10].hex() if response else "No response"}'
                }
        
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _test_alternative_methods(self) -> Dict:
        """Test alternative connection methods"""
        print("[TEST 5] Testing alternative connection methods...")
        
        result = {
            'test_name': 'Alternative Methods',
            'methods': {}
        }
        
        # Test direct SMB without NetBIOS
        print("  Testing direct SMB (no NetBIOS session)...")
        result['methods']['direct_smb'] = self._test_direct_smb()
        
        # Test different ports
        print("  Testing alternative ports...")
        result['methods']['alternative_ports'] = self._test_alternative_ports()
        
        return result
    
    def _test_direct_smb(self) -> Dict:
        """Test direct SMB connection without NetBIOS session"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.target, self.port))
            
            # Skip NetBIOS session, go directly to SMB2 negotiate
            smb2_result = self._test_smb2_negotiate(sock)
            
            sock.close()
            
            return {
                'success': smb2_result['success'],
                'details': smb2_result
            }
        
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _test_alternative_ports(self) -> Dict:
        """Test connection on alternative ports"""
        alternative_ports = [139, 445, 135]  # NetBIOS, SMB, RPC
        results = {}
        
        for port in alternative_ports:
            if port == self.port:
                continue  # Skip the port we're already testing
            
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.target, port))
                
                results[port] = {
                    'success': True,
                    'service': self._identify_service(port)
                }
                
                sock.close()
                print(f"    [+] Port {port} is open ({results[port]['service']})")
                
            except Exception as e:
                results[port] = {
                    'success': False,
                    'error': str(e)
                }
                print(f"    [-] Port {port} is closed/filtered")
        
        return results
    
    def _identify_service(self, port: int) -> str:
        """Identify service by port number"""
        services = {
            135: 'RPC Endpoint Mapper',
            139: 'NetBIOS Session Service',
            445: 'SMB over TCP'
        }
        return services.get(port, 'Unknown')
    
    def _build_netbios_name(self, name: str, name_type: int) -> bytes:
        """Build NetBIOS name (same as in SMBClient)"""
        try:
            name_bytes = name.upper().encode('ascii')[:15]
            name_bytes = name_bytes.ljust(15, b' ')
            name_bytes += bytes([name_type])
            
            encoded = b''
            for byte in name_bytes:
                encoded += bytes([0x41 + (byte >> 4)])
                encoded += bytes([0x41 + (byte & 0x0F)])
            
            return bytes([32]) + encoded + b'\x00'
        
        except Exception:
            return b'\x20' + b'A' * 32 + b'\x00'
    
    def _get_netbios_error(self, error_code: int) -> str:
        """Get NetBIOS error message"""
        error_codes = {
            0x80: "Not listening on called name",
            0x81: "Not listening for calling name", 
            0x82: "Called name not present",
            0x83: "Called name present, but insufficient resources",
            0x8F: "Unspecified error"
        }
        return error_codes.get(error_code, f"Unknown error: {hex(error_code)}")
    
    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on test results"""
        recommendations = []
        
        # Check TCP connectivity
        tcp_test = self.results['tests'].get('tcp_connectivity', {})
        if not tcp_test.get('success'):
            recommendations.append("TCP connectivity failed - check network connectivity and firewall rules")
            recommendations.append("Verify the target IP address and port 445 accessibility")
        
        # Check NetBIOS session
        netbios_test = self.results['tests'].get('netbios_session', {})
        if not netbios_test.get('success'):
            recommendations.append("NetBIOS session establishment failed - try direct SMB connection")
            recommendations.append("Consider using alternative NetBIOS names or disabling NetBIOS session")
        
        # Check SMB negotiation
        smb_test = self.results['tests'].get('smb_negotiation', {})
        if not smb_test.get('success'):
            recommendations.append("SMB protocol negotiation failed - check SMB version compatibility")
            recommendations.append("Try different SMB dialects or enable SMB1 if necessary")
        
        # Check alternative methods
        alt_test = self.results['tests'].get('alternative_methods', {})
        if alt_test.get('methods', {}).get('direct_smb', {}).get('success'):
            recommendations.append("Direct SMB connection works - skip NetBIOS session in implementation")
        
        # General recommendations
        if not any(test.get('success') for test in self.results['tests'].values()):
            recommendations.append("All connection methods failed - check target system SMB configuration")
            recommendations.append("Verify Windows firewall and SMB service status on target")
            recommendations.append("Consider using different authentication methods or credentials")
        
        return recommendations
    
    def print_summary(self):
        """Print diagnostic summary"""
        print("\n" + "="*60)
        print("SMB CONNECTION DIAGNOSTICS SUMMARY")
        print("="*60)
        
        for test_name, test_result in self.results['tests'].items():
            status = "[+] PASS" if test_result.get('success') else "[-] FAIL"
            print(f"{test_result.get('test_name', test_name)}: {status}")
            
            if test_result.get('errors'):
                for error in test_result['errors']:
                    print(f"  Error: {error}")
        
        print("\nRECOMMENDATIONS:")
        for i, rec in enumerate(self.results.get('recommendations', []), 1):
            print(f"{i}. {rec}")
        
        print("="*60)

# Usage example and test function
def diagnose_smb_connection(target: str, port: int = 445) -> Dict:
    """Run SMB diagnostics and return results"""
    diagnostics = SMBDiagnostics(target, port)
    results = diagnostics.run_full_diagnostics()
    diagnostics.print_summary()
    return results

if __name__ == "__main__":
    # Test with the problematic target
    target = "192.168.1.106"
    results = diagnose_smb_connection(target)