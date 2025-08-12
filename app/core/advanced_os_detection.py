# app/core/advanced_os_detection.py
import socket
import ssl
import struct
import time
import threading
from typing import Dict, List, Tuple, Optional
from app.core.logger import logger

class AdvancedOSDetection:
    """Advanced OS detection using protocol quirks, timing, and service fingerprinting"""
    
    # Ephemeral port ranges by OS
    EPHEMERAL_RANGES = {
        'windows_xp': (1025, 5000),
        'windows_vista_plus': (49152, 65535),
        'linux': (32768, 65535)
    }
    
    # SMB dialect mapping
    SMB_DIALECTS = {
        0x0202: 'SMBv1 (NT LM 0.12)',
        0x0210: 'SMBv2.0',
        0x0300: 'SMBv3.0',
        0x0302: 'SMBv3.0.2',
        0x0311: 'SMBv3.1.1'
    }
    
    # Windows version indicators
    WINDOWS_INDICATORS = {
        'smb1_only': 'Windows XP/2003',
        'smb2_support': 'Windows Vista/2008+',
        'smb3_encryption': 'Windows 8/2012+',
        'smb3_compression': 'Windows 11/2022+',
        'no_smb1': 'Windows 10+/2016+'
    }
    
    def __init__(self, target_ip: str, timeout: int = 3):
        self.target_ip = target_ip
        self.timeout = timeout
        self.fingerprint_data = {}
        
    def detect_os(self, open_ports: List[Dict]) -> Dict:
        """Main OS detection orchestrator"""
        results = {
            'os': 'Unknown',
            'confidence': 'low',
            'evidence': [],
            'fingerprint_data': {}
        }
        
        port_list = [p['port'] for p in open_ports]
        
        # Store ports for AD detection
        self.open_ports_from_scan = set(port_list)
        
        # Phase 1: Passive fingerprinting
        ephemeral_analysis = self._analyze_ephemeral_ports(port_list)
        if ephemeral_analysis:
            results['evidence'].extend(ephemeral_analysis['evidence'])
            results['fingerprint_data']['ephemeral'] = ephemeral_analysis
        
        # Phase 2: Active probing
        if 135 in port_list:
            rpc_analysis = self._probe_rpc_endpoint_mapper()
            if rpc_analysis:
                results['evidence'].extend(rpc_analysis['evidence'])
                results['fingerprint_data']['rpc'] = rpc_analysis
        
        if 445 in port_list:
            smb_analysis = self._probe_smb_service()
            if smb_analysis:
                results['evidence'].extend(smb_analysis['evidence'])
                results['fingerprint_data']['smb'] = smb_analysis
        
        if 3389 in port_list:
            rdp_analysis = self._probe_rdp_service()
            if rdp_analysis:
                results['evidence'].extend(rdp_analysis['evidence'])
                results['fingerprint_data']['rdp'] = rdp_analysis
        
        if 5985 in port_list or 5986 in port_list:
            winrm_analysis = self._probe_winrm_service()
            if winrm_analysis:
                results['evidence'].extend(winrm_analysis['evidence'])
                results['fingerprint_data']['winrm'] = winrm_analysis
        
        # Phase 3: TCP stack fingerprinting
        tcp_fingerprint = self._tcp_stack_fingerprint(port_list)
        if tcp_fingerprint:
            results['evidence'].extend(tcp_fingerprint['evidence'])
            results['fingerprint_data']['tcp_stack'] = tcp_fingerprint
        
        # Synthesize results
        os_result = self._synthesize_os_detection(results['fingerprint_data'])
        results.update(os_result)
        
        return results
    
    def _analyze_ephemeral_ports(self, port_list: List[int]) -> Optional[Dict]:
        """Analyze ephemeral port ranges to infer OS generation"""
        ephemeral_ports = [p for p in port_list if p > 1024]
        if not ephemeral_ports:
            return None
        
        min_ephemeral = min(ephemeral_ports)
        max_ephemeral = max(ephemeral_ports)
        
        evidence = []
        os_hint = None
        
        # Check for legacy Windows (XP/2003) range
        if min_ephemeral < 10000 and any(p < 5000 for p in ephemeral_ports):
            evidence.append(f"Legacy ephemeral ports detected: {min_ephemeral}-{max_ephemeral}")
            os_hint = 'windows_xp'
        
        # Check for modern Windows (Vista+) range
        elif min_ephemeral > 49000:
            evidence.append(f"Modern ephemeral ports detected: {min_ephemeral}-{max_ephemeral}")
            os_hint = 'windows_vista_plus'
        
        return {
            'range': (min_ephemeral, max_ephemeral),
            'os_hint': os_hint,
            'evidence': evidence
        }
    
    def _probe_rpc_endpoint_mapper(self) -> Optional[Dict]:
        """Probe RPC Endpoint Mapper for version-specific responses"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target_ip, 135))
            
            # RPC bind request for endpoint mapper
            rpc_bind = bytes.fromhex(
                "05000b03100000004800000001000000b810b810000000000100000000000100"
                "6cb71c2c9e4c4991a7b82cb9b5808e20000000000100000000000000045d888a"
                "eb1cc9119fe808002b10486200000000045d888aeb1cc9119fe808002b104862"
                "00000000"
            )
            
            sock.sendall(rpc_bind)
            response = sock.recv(1024)
            sock.close()
            
            if len(response) > 16:
                # Analyze NDR encoding and response structure
                evidence = ["RPC Endpoint Mapper responded"]
                
                # Check for specific Windows version indicators in response
                if b'\x05\x00\x0c\x03' in response[:4]:
                    evidence.append("Standard RPC response format detected")
                
                return {
                    'response_length': len(response),
                    'response_hex': response.hex()[:100],
                    'evidence': evidence
                }
        
        except Exception as e:
            logger.debug(f"RPC probe failed: {e}")
        
        return None
    
    def _probe_smb_service(self) -> Optional[Dict]:
        """Probe SMB service for dialect and capability detection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target_ip, 445))
            
            # SMB negotiate request with multiple dialects
            smb_negotiate = bytes.fromhex(
                "00000085ff534d4272000000001801c80000000000000000000000000000000000000000"
                "000000000000000000000000002400000001000000000000000000000000000000000000"
                "000000000000000000000000000000000000000000000000000000000000000000000000"
                "000000000000000000000000000000000000000000000000000000000000000000000000"
                "0000000000000000000000000000000000000000000000000000000000000000"
            )
            
            sock.sendall(smb_negotiate)
            response = sock.recv(1024)
            sock.close()
            
            if len(response) > 32:
                evidence = []
                capabilities = {}
                
                # Parse SMB response
                if response[4:8] == b'\xff\x53\x4d\x42':  # SMB1 signature
                    evidence.append("SMBv1 protocol detected")
                    capabilities['smb1_support'] = True
                elif response[4:8] == b'\xfe\x53\x4d\x42':  # SMB2/3 signature
                    evidence.append("SMBv2/3 protocol detected")
                    capabilities['smb2_3_support'] = True
                    
                    # Check for SMB3 features
                    if b'\x11\x03' in response:  # SMB 3.1.1
                        evidence.append("SMBv3.1.1 dialect supported")
                        capabilities['smb311_support'] = True
                    
                    # Check for encryption capability
                    if b'\x01\x00\x00\x00' in response[64:68]:
                        evidence.append("SMB encryption capability detected")
                        capabilities['encryption_support'] = True
                
                return {
                    'response_length': len(response),
                    'capabilities': capabilities,
                    'evidence': evidence
                }
        
        except Exception as e:
            logger.debug(f"SMB probe failed: {e}")
        
        return None
    
    def _probe_rdp_service(self) -> Optional[Dict]:
        """Probe RDP service for protocol version and security features"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target_ip, 3389))
            
            # RDP connection request
            rdp_request = bytes.fromhex(
                "030000130ee000000000000100080003000000"
            )
            
            sock.sendall(rdp_request)
            response = sock.recv(1024)
            sock.close()
            
            if len(response) > 10:
                evidence = []
                features = {}
                
                # Check for RDP version indicators
                if b'\x03\x00' in response[:2]:
                    evidence.append("RDP protocol detected")
                
                # Check for security protocols
                if b'\x01\x00' in response:
                    evidence.append("Standard RDP security")
                    features['standard_rdp'] = True
                
                if b'\x02\x00' in response:
                    evidence.append("TLS security supported")
                    features['tls_support'] = True
                
                if b'\x08\x00' in response:
                    evidence.append("CredSSP/NLA supported")
                    features['credssp_support'] = True
                
                return {
                    'response_length': len(response),
                    'features': features,
                    'evidence': evidence
                }
        
        except Exception as e:
            logger.debug(f"RDP probe failed: {e}")
        
        return None
    
    def _probe_winrm_service(self) -> Optional[Dict]:
        """Probe WinRM service for PowerShell remoting capabilities"""
        try:
            import urllib.request
            import urllib.error
            
            # Try HTTP first (5985)
            for port, protocol in [(5985, 'http'), (5986, 'https')]:
                try:
                    url = f"{protocol}://{self.target_ip}:{port}/wsman"
                    req = urllib.request.Request(url, headers={
                        'User-Agent': 'Microsoft WinRM Client',
                        'Content-Type': 'application/soap+xml'
                    })
                    
                    with urllib.request.urlopen(req, timeout=self.timeout) as response:
                        headers = dict(response.headers)
                        content = response.read().decode('utf-8', errors='ignore')
                        
                        evidence = [f"WinRM service detected on port {port}"]
                        features = {'port': port, 'protocol': protocol}
                        
                        # Check server header
                        server = headers.get('Server', '')
                        if 'Microsoft-HTTPAPI' in server:
                            evidence.append(f"Microsoft HTTP API detected: {server}")
                            features['microsoft_httpapi'] = True
                        
                        # Check for PowerShell remoting
                        if 'PowerShell' in content or 'wsman' in content.lower():
                            evidence.append("PowerShell remoting capability detected")
                            features['powershell_remoting'] = True
                        
                        return {
                            'port': port,
                            'protocol': protocol,
                            'server_header': server,
                            'features': features,
                            'evidence': evidence
                        }
                
                except Exception:
                    continue
        
        except Exception as e:
            logger.debug(f"WinRM probe failed: {e}")
        
        return None
    
    def _tcp_stack_fingerprint(self, port_list: List[int]) -> Optional[Dict]:
        """Perform TCP stack fingerprinting for OS detection"""
        if not port_list:
            return None
        
        try:
            # Use first open port for fingerprinting
            target_port = port_list[0]
            
            # Create raw socket for TCP options analysis
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            start_time = time.time()
            result = sock.connect_ex((self.target_ip, target_port))
            connect_time = time.time() - start_time
            
            if result == 0:
                # Get socket options
                try:
                    tcp_info = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 104)
                    sock.close()
                    
                    evidence = []
                    features = {}
                    
                    # Analyze connection timing
                    if connect_time < 0.01:
                        evidence.append("Very fast connection (local/high-speed)")
                        features['fast_connect'] = True
                    elif connect_time > 0.1:
                        evidence.append("Slow connection (remote/filtered)")
                        features['slow_connect'] = True
                    
                    # Basic TCP stack analysis
                    features['connect_time'] = connect_time
                    evidence.append(f"TCP connection established in {connect_time:.3f}s")
                    
                    return {
                        'connect_time': connect_time,
                        'features': features,
                        'evidence': evidence
                    }
                
                except Exception:
                    sock.close()
            
        except Exception as e:
            logger.debug(f"TCP fingerprinting failed: {e}")
        
        return None
    
    def _synthesize_os_detection(self, fingerprint_data: Dict) -> Dict:
        """Synthesize all fingerprinting data into OS detection result"""
        evidence = []
        confidence_score = 0
        os_candidates = []
        
        # First check for network devices (highest priority to prevent misidentification)
        network_device = self._detect_network_device(fingerprint_data)
        if network_device:
            os_candidates.extend(network_device['candidates'])
            evidence.extend(network_device['evidence'])
            confidence_score += network_device['confidence_boost']
            
            return {
                'os': network_device['candidates'][0][0],
                'confidence': 'high',
                'confidence_score': network_device['candidates'][0][1],
                'candidates': network_device['candidates']
            }
        
        # Check for Active Directory services (second priority)
        ad_services = self._detect_active_directory_services(fingerprint_data)
        if ad_services:
            os_candidates.extend(ad_services['candidates'])
            evidence.extend(ad_services['evidence'])
            confidence_score += ad_services['confidence_boost']
        
        # Analyze SMB data for Windows version
        if 'smb' in fingerprint_data:
            smb_data = fingerprint_data['smb']
            capabilities = smb_data.get('capabilities', {})
            
            if capabilities.get('smb1_support') and not capabilities.get('smb2_3_support'):
                if not ad_services:  # Only suggest legacy if no AD detected
                    os_candidates.append(('Windows XP/2003', 0.8))
                    evidence.append("SMBv1 only support indicates legacy Windows")
            
            elif capabilities.get('smb2_3_support'):
                if capabilities.get('smb311_support') and capabilities.get('encryption_support'):
                    os_candidates.append(('Windows 11/Server 2022', 0.9))
                    evidence.append("SMBv3.1.1 with encryption indicates modern Windows")
                elif capabilities.get('encryption_support'):
                    os_candidates.append(('Windows 10/Server 2016+', 0.8))
                    evidence.append("SMB encryption support indicates Windows 10+")
                else:
                    os_candidates.append(('Windows Vista/2008+', 0.7))
                    evidence.append("SMBv2/3 support indicates Vista or later")
        
        # Analyze RDP data
        if 'rdp' in fingerprint_data:
            rdp_data = fingerprint_data['rdp']
            features = rdp_data.get('features', {})
            
            if features.get('credssp_support'):
                evidence.append("CredSSP/NLA support indicates Vista or later")
                confidence_score += 0.1
            
            if features.get('tls_support'):
                evidence.append("RDP TLS support indicates modern Windows")
                confidence_score += 0.1
        
        # Analyze WinRM data
        if 'winrm' in fingerprint_data:
            winrm_data = fingerprint_data['winrm']
            features = winrm_data.get('features', {})
            
            if features.get('powershell_remoting'):
                evidence.append("PowerShell remoting indicates Windows 2008+")
                confidence_score += 0.1
            
            if features.get('microsoft_httpapi'):
                evidence.append("Microsoft HTTP API indicates modern Windows")
                confidence_score += 0.1
        
        # Analyze ephemeral ports (lower priority than service detection)
        if 'ephemeral' in fingerprint_data and not ad_services:
            ephemeral_data = fingerprint_data['ephemeral']
            os_hint = ephemeral_data.get('os_hint')
            
            if os_hint == 'windows_xp':
                os_candidates.append(('Windows XP/2003', 0.5))  # Lower confidence
            elif os_hint == 'windows_vista_plus':
                os_candidates.append(('Windows Vista+', 0.4))  # Lower confidence
        
        # Select best OS candidate
        if os_candidates:
            # Sort by confidence and select highest
            os_candidates.sort(key=lambda x: x[1], reverse=True)
            best_os, best_confidence = os_candidates[0]
            
            # Adjust confidence based on evidence quality
            final_confidence = min(best_confidence + confidence_score, 1.0)
            
            if final_confidence >= 0.8:
                confidence_level = "high"
            elif final_confidence >= 0.6:
                confidence_level = "medium"
            else:
                confidence_level = "low"
            
            return {
                'os': best_os,
                'confidence': confidence_level,
                'confidence_score': final_confidence,
                'candidates': os_candidates
            }
        
        # Fallback to generic detection
        return {
            'os': 'Windows (Generic)',
            'confidence': 'low',
            'confidence_score': 0.3,
            'candidates': [('Windows (Generic)', 0.3)]
        }
    
    def _detect_active_directory_services(self, fingerprint_data: Dict) -> Optional[Dict]:
        """Detect Active Directory services from port combinations"""
        # Check if we have port data from basic fingerprinting
        open_ports = set()
        
        # Extract ports from various sources
        if hasattr(self, 'open_ports_from_scan'):
            open_ports.update(self.open_ports_from_scan)
        
        # AD service indicators
        ad_ports = {88, 389, 464, 636, 3268, 3269, 9389}  # Core AD ports
        dns_port = 53
        kerberos_port = 88
        ldap_ports = {389, 636}
        gc_ports = {3268, 3269}
        
        ad_score = 0
        evidence = []
        
        # Check for Kerberos (essential for AD)
        if kerberos_port in open_ports:
            ad_score += 0.3
            evidence.append("Kerberos service detected (port 88)")
        
        # Check for LDAP services
        ldap_found = ldap_ports.intersection(open_ports)
        if ldap_found:
            ad_score += 0.3
            evidence.append(f"LDAP services detected: {', '.join(map(str, sorted(ldap_found)))}")
        
        # Check for Global Catalog
        gc_found = gc_ports.intersection(open_ports)
        if gc_found:
            ad_score += 0.2
            evidence.append(f"Global Catalog services detected: {', '.join(map(str, sorted(gc_found)))}")
        
        # Check for DNS (common on DCs)
        if dns_port in open_ports:
            ad_score += 0.1
            evidence.append("DNS service detected (port 53)")
        
        # Check for ADWS
        if 9389 in open_ports:
            ad_score += 0.1
            evidence.append("Active Directory Web Services detected (port 9389)")
        
        # Determine if this is likely a domain controller
        if ad_score >= 0.6:  # Need Kerberos + LDAP at minimum
            candidates = []
            
            # Check for Server 2025 indicators
            if 47001 in open_ports or 22 in open_ports:  # WinRM SSL or SSH
                candidates.append(('Windows Server 2025', 0.9))
                evidence.append("Server 2025 indicators detected")
            elif 5985 in open_ports:  # WinRM
                candidates.append(('Windows Server 2019/2022', 0.8))
                evidence.append("Modern Windows Server detected")
            else:
                candidates.append(('Windows Domain Controller', 0.7))
                evidence.append("Domain Controller services detected")
            
            return {
                'candidates': candidates,
                'evidence': evidence,
                'confidence_boost': 0.3
            }
        
        return None
    
    def _detect_network_device(self, fingerprint_data: Dict) -> Optional[Dict]:
        """Detect network devices (routers, switches) from port patterns"""
        # Check if we have port data from basic fingerprinting
        open_ports = set()
        
        # Extract ports from various sources
        if hasattr(self, 'open_ports_from_scan'):
            open_ports.update(self.open_ports_from_scan)
        
        # Network device indicators
        router_ports = {53, 80, 443, 22, 23, 161, 8080, 8443}  # Common router ports
        windows_exclusive = {135, 445, 3389, 5985}  # Windows-only ports
        linux_exclusive = {111, 631}  # Linux-only ports
        
        evidence = []
        device_score = 0
        
        # Check for Windows-exclusive ports (if present, not a router)
        if windows_exclusive.intersection(open_ports):
            return None
        
        # Check for Linux-exclusive ports (if present, not a router)
        if linux_exclusive.intersection(open_ports):
            return None
        
        # Check for typical router port patterns
        router_found = router_ports.intersection(open_ports)
        
        # Router detection logic
        if len(open_ports) <= 8 and router_found:  # Few ports, typical router services
            device_score += 0.3
            evidence.append(f"Limited port exposure typical of network device: {', '.join(map(str, sorted(router_found)))}")
            
            # Common router service patterns
            if {21, 80, 53}.issubset(open_ports):  # FTP + HTTP + DNS
                device_score += 0.4
                evidence.append("Router service pattern: FTP + HTTP + DNS")
            elif open_ports == {53} or open_ports.issubset({53, 80, 443}):
                device_score += 0.4
                evidence.append("DNS-only or minimal web interface pattern detected")
            
            # Management interface pattern
            if {80, 443}.intersection(open_ports):
                device_score += 0.2
                evidence.append("Web management interface detected")
            
            # SNMP management
            if 161 in open_ports:
                device_score += 0.2
                evidence.append("SNMP management interface detected")
        
        # Check for router-specific IP ranges (common router IPs)
        if hasattr(self, 'target_ip'):
            router_ips = ['192.168.1.1', '192.168.0.1', '10.0.0.1', '172.16.0.1']
            if self.target_ip in router_ips:
                device_score += 0.3
                evidence.append(f"Common router IP address: {self.target_ip}")
        
        # Determine if this is likely a network device
        if device_score >= 0.6:
            candidates = []
            
            # Specific router detection
            if {21, 80, 53}.issubset(open_ports):
                candidates.append(('TP-Link Router', 0.9))
                evidence.append("TP-Link router pattern: FTP + HTTP + DNS services")
            elif open_ports == {53}:
                candidates.append(('Network Router/Gateway (DNS-only)', 0.9))
                evidence.append("DNS-only configuration typical of router")
            elif {80, 443}.issubset(open_ports) and len(open_ports) <= 4:
                candidates.append(('Network Router/Gateway (Web Management)', 0.8))
                evidence.append("Web management interface pattern")
            elif 161 in open_ports:
                candidates.append(('Managed Network Switch', 0.8))
                evidence.append("SNMP-managed network device")
            else:
                candidates.append(('Network Device', 0.7))
                evidence.append("Generic network device pattern")
            
            return {
                'candidates': candidates,
                'evidence': evidence,
                'confidence_boost': 0.4
            }
        
        return None
    
    def _extract_ports_from_fingerprint(self, port_list):
        """Extract port numbers from new or legacy fingerprint format"""
        ports = set()
        for item in port_list:
            if isinstance(item, dict):
                ports.add(item.get('port'))
            else:
                ports.add(item)
        return ports

def create_advanced_os_detector(target_ip: str, timeout: int = 3) -> AdvancedOSDetection:
    """Factory function to create advanced OS detector"""
    return AdvancedOSDetection(target_ip, timeout)