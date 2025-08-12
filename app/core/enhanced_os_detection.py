# app/core/enhanced_os_detection.py
import socket
import struct
import time
import random
from collections import defaultdict

class EnhancedOSDetection:
    """Enhanced OS detection using TTL analysis, TCP window size, and IP ID sequences"""
    
    # Known TTL values for different OS families
    TTL_SIGNATURES = {
        64: ['Linux', 'Unix', 'macOS', 'FreeBSD', 'OpenBSD'],
        128: ['Windows', 'Windows Server'],
        255: ['Cisco IOS', 'Network Device', 'Embedded System'],
        32: ['Windows 95/98'],
        60: ['macOS (older)'],
        254: ['Solaris', 'AIX']
    }
    
    # TCP window size signatures
    WINDOW_SIGNATURES = {
        8192: ['Windows XP', 'Windows 2003'],
        65535: ['Linux (default)', 'FreeBSD'],
        16384: ['Windows Vista/7/8/10'],
        5840: ['Google Linux'],
        14600: ['Linux (custom)'],
        32768: ['macOS', 'BSD variants']
    }
    
    def __init__(self):
        self.ttl_data = defaultdict(list)
        self.window_data = defaultdict(list)
        self.ip_id_data = defaultdict(list)
    
    def analyze_tcp_response(self, target_ip, port=80, timeout=3):
        """Analyze TCP response for OS fingerprinting"""
        try:
            # Create raw socket for packet analysis
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Connect and capture response
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                # Get socket info for analysis
                peer_info = sock.getpeername()
                sock_info = sock.getsockname()
                
                # Try to get TTL from socket options (limited on Windows)
                try:
                    ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
                    self.ttl_data[target_ip].append(ttl)
                except:
                    # Fallback: estimate TTL from common values
                    ttl = self._estimate_ttl_from_port_pattern(target_ip, port)
                    if ttl:
                        self.ttl_data[target_ip].append(ttl)
                
                sock.close()
                return True
            
            sock.close()
            return False
            
        except Exception as e:
            return False
    
    def _estimate_ttl_from_port_pattern(self, target_ip, port):
        """Estimate TTL based on port response patterns"""
        # This is a simplified approach - in practice you'd need raw sockets
        # or packet capture to get actual TTL values
        
        # Try multiple ports to gather more data
        test_ports = [22, 80, 135, 443, 445]
        responsive_ports = []
        
        for test_port in test_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target_ip, test_port))
                if result == 0:
                    responsive_ports.append(test_port)
                sock.close()
            except:
                pass
        
        # Estimate based on port patterns
        if 135 in responsive_ports or 445 in responsive_ports:
            return 128  # Likely Windows
        elif 22 in responsive_ports:
            return 64   # Likely Linux/Unix
        
        return None
    
    def analyze_ip_id_sequence(self, target_ip, samples=5):
        """Analyze IP ID sequence behavior"""
        ip_ids = []
        
        for i in range(samples):
            try:
                # Send multiple requests to analyze IP ID patterns
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target_ip, 80))
                
                if result == 0:
                    # In a real implementation, you'd capture the IP ID from raw packets
                    # For now, we'll simulate the behavior
                    simulated_id = random.randint(1, 65535)
                    ip_ids.append(simulated_id)
                
                sock.close()
                time.sleep(0.1)  # Small delay between requests
                
            except:
                continue
        
        if len(ip_ids) >= 3:
            self.ip_id_data[target_ip] = ip_ids
            return self._analyze_ip_id_pattern(ip_ids)
        
        return None
    
    def _analyze_ip_id_pattern(self, ip_ids):
        """Analyze IP ID sequence pattern"""
        if len(ip_ids) < 3:
            return "insufficient_data"
        
        # Calculate differences between consecutive IDs
        diffs = [ip_ids[i+1] - ip_ids[i] for i in range(len(ip_ids)-1)]
        
        # Check for patterns
        if all(abs(diff) <= 10 for diff in diffs):
            return "incremental"  # Windows-like
        elif all(abs(diff) > 1000 for diff in diffs):
            return "random"       # Linux-like
        elif all(diff == 0 for diff in diffs):
            return "constant"     # Embedded/firewall
        else:
            return "mixed"
    
    def tcp_window_analysis(self, target_ip, port=80):
        """Analyze TCP window size"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            
            # Connect to get TCP parameters
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                # Get socket buffer sizes as proxy for window analysis
                try:
                    recv_buf = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
                    send_buf = sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
                    
                    # Estimate window size from buffer sizes
                    estimated_window = min(recv_buf, send_buf) // 4
                    self.window_data[target_ip].append(estimated_window)
                    
                    sock.close()
                    return estimated_window
                except:
                    sock.close()
                    return None
            
            sock.close()
            return None
            
        except Exception:
            return None
    
    def comprehensive_os_detection(self, target_ip, open_ports=None, service_banners=None):
        """Perform comprehensive OS detection using fingerprint database"""
        results = {
            'target': target_ip,
            'os_candidates': [],
            'confidence': 'low',
            'evidence': [],
            'fingerprints': {},
            'vulnerabilities': []
        }
        
        # Grab service banners for enhanced detection
        grabbed_banners = {}
        if open_ports:
            for port in [445, 5985, 80, 443, 3389]:
                if port in open_ports:
                    if port == 445:
                        banner = self._grab_smb_banner(target_ip)
                        if banner:
                            grabbed_banners[port] = banner
                    elif port == 5985:
                        banner = self._grab_winrm_banner(target_ip)
                        if banner:
                            grabbed_banners[port] = banner
                    elif port in [80, 443]:
                        banner = self._grab_http_banner(target_ip, port)
                        if banner:
                            grabbed_banners[port] = banner
                    elif port == 3389:
                        banner = self._grab_rdp_banner(target_ip)
                        if banner:
                            grabbed_banners[port] = str(banner)
        
        # Merge provided banners with grabbed banners
        all_banners = grabbed_banners.copy()
        if service_banners:
            all_banners.update(service_banners)
        
        # Try fingerprint database first
        try:
            fingerprint_matches = self._match_fingerprint_database(target_ip, open_ports, all_banners)
            if fingerprint_matches:
                best_match = fingerprint_matches[0]
                results['os_candidates'] = [{
                    'os': best_match['description'],
                    'score': best_match['score']
                }]
                results['confidence'] = best_match['confidence']
                results['evidence'] = best_match['evidence']
                results['fingerprints'] = best_match['methods']
                
                if best_match.get('vulnerabilities'):
                    results['vulnerabilities'] = best_match['vulnerabilities']
                
                return results
        except Exception:
            pass
        
        # Use enhanced port-based detection
        if open_ports:
            port_result = self._detect_os_from_ports(open_ports)
            if port_result['os'] != 'Unknown':
                results['os_candidates'] = [{'os': port_result['os']}]
                results['confidence'] = port_result['confidence']
                results['evidence'] = [f"Port pattern analysis: {sorted(open_ports)}"]
                
                # Add specific evidence for Domain Controllers
                if 'Domain Controller' in port_result['os']:
                    dc_ports = {88, 135, 389, 445, 53, 464, 636, 3268, 3269, 5985, 9389}
                    found_dc_ports = dc_ports.intersection(set(open_ports))
                    results['evidence'].append(f"Domain Controller services detected: {sorted(found_dc_ports)}")
                    
                    # Boost confidence for clear DC patterns
                    if len(found_dc_ports) >= 6:
                        results['confidence'] = 'high'
        
        return results
    
    def _detect_os_from_ttl(self, target_ip):
        """Detect OS from TTL analysis"""
        # Test multiple ports to get TTL data
        test_ports = [22, 80, 135, 443, 445]
        ttl_values = []
        
        for port in test_ports:
            if self.analyze_tcp_response(target_ip, port):
                break  # Got at least one response
        
        if target_ip in self.ttl_data and self.ttl_data[target_ip]:
            observed_ttl = self.ttl_data[target_ip][0]
            
            # Find closest matching TTL signature
            for expected_ttl, os_list in self.TTL_SIGNATURES.items():
                # Account for hop count (TTL decreases by 1 per hop)
                if abs(observed_ttl - expected_ttl) <= 10:  # Allow for up to 10 hops
                    return {
                        'os': os_list[0],  # Return most likely OS
                        'ttl': observed_ttl,
                        'expected_ttl': expected_ttl,
                        'confidence': 'high' if abs(observed_ttl - expected_ttl) <= 3 else 'medium'
                    }
        
        return None
    
    def _detect_os_from_window(self, target_ip):
        """Detect OS from TCP window size"""
        window_size = self.tcp_window_analysis(target_ip)
        
        if window_size:
            for expected_window, os_list in self.WINDOW_SIGNATURES.items():
                if abs(window_size - expected_window) <= 1024:  # Allow some variance
                    return {
                        'os': os_list[0],
                        'window': window_size,
                        'expected_window': expected_window,
                        'confidence': 'medium'
                    }
        
        return None
    
    def _detect_os_from_ip_id(self, pattern):
        """Detect OS from IP ID sequence pattern"""
        pattern_os_map = {
            'incremental': {'os': 'Windows', 'confidence': 'medium'},
            'random': {'os': 'Linux', 'confidence': 'medium'},
            'constant': {'os': 'Embedded/Firewall', 'confidence': 'low'},
            'mixed': {'os': 'Unknown', 'confidence': 'low'}
        }
        
        return pattern_os_map.get(pattern)
    
    def _detect_os_from_ports(self, open_ports):
        """Enhanced fallback OS detection from port patterns"""
        port_set = set(open_ports)
        
        # Windows Domain Controller patterns (prioritized)
        dc_core_ports = {88, 135, 389, 445}  # Core DC ports
        dc_extended_ports = {53, 464, 636, 3268, 3269, 5985, 9389}  # Extended DC ports
        
        if dc_core_ports.issubset(port_set):
            dc_score = len(dc_extended_ports.intersection(port_set))
            if dc_score >= 3:  # 3+ extended DC ports
                return {'os': 'Windows Server Domain Controller', 'confidence': 'high'}
            elif dc_score >= 1:  # 1+ extended DC ports
                return {'os': 'Windows Server Domain Controller', 'confidence': 'medium'}
            else:
                return {'os': 'Windows Server (Possible DC)', 'confidence': 'medium'}
        
        # TP-Link Router pattern
        if {21, 80, 53}.issubset(port_set) and 139 in port_set and 445 in port_set:
            return {'os': 'TP-Link Router', 'confidence': 'high'}
        
        # Synology NAS pattern
        if {5000, 5001}.intersection(port_set) and {22, 445}.issubset(port_set):
            return {'os': 'Synology NAS (Linux-based)', 'confidence': 'high'}
        
        # Windows Server/Workstation pattern
        if {135, 445}.issubset(port_set):
            if 7680 in port_set:  # Windows Update Delivery Optimization
                return {'os': 'Windows 10/11', 'confidence': 'medium'}
            elif 5985 in port_set:  # WinRM suggests server
                return {'os': 'Windows Server', 'confidence': 'medium'}
            else:
                return {'os': 'Windows Server/Workstation', 'confidence': 'medium'}
        
        # Linux web server pattern
        if 22 in port_set and {80, 443}.intersection(port_set):
            return {'os': 'Linux (Web Server)', 'confidence': 'medium'}
        
        # Basic Linux/Unix pattern
        elif 22 in port_set:
            return {'os': 'Linux/Unix', 'confidence': 'low'}
        
        # Web server only (could be anything)
        elif {80, 443}.intersection(port_set) and len(port_set) <= 2:
            return {'os': 'Web Server (OS Unknown)', 'confidence': 'low'}
        
        # Network device signatures
        if 161 in port_set:  # SNMP
            return {'os': 'Network Device', 'confidence': 'medium'}
        
        return {'os': 'Unknown', 'confidence': 'low'}

    def _match_fingerprint_database(self, target_ip, open_ports=None, service_banners=None):
        """Match against comprehensive fingerprint database"""
        try:
            import json
            import os
            import re
            
            fingerprints_path = os.path.join(
                os.path.dirname(__file__), '..', '..', 'resources', 'config', 'os_fingerprints.json'
            )
            
            with open(fingerprints_path, 'r') as f:
                fingerprints = json.load(f)
            
            matches = []
            open_port_set = set(open_ports) if open_ports else set()
            
            # Check all categories
            for category, os_types in fingerprints.items():
                if category in ['version', 'last_updated'] or not isinstance(os_types, dict):
                    continue
                
                for os_name, fp in os_types.items():
                    if not isinstance(fp, dict):
                        continue
                    
                    score = 0
                    evidence = []
                    methods = {}
                    
                    # 1. Required ports check
                    required_ports = set(p['port'] for p in fp.get('required_ports', []))
                    if required_ports and not required_ports.issubset(open_port_set):
                        missing_required = required_ports - open_port_set
                        print(f"[DEBUG] {fp.get('description', os_name)}: FAILED - Missing required ports: {sorted(missing_required)}")
                        continue  # Skip if required ports not met
                    
                    print(f"[DEBUG] {fp.get('description', os_name)}: Testing fingerprint...")
                    if required_ports:
                        score += 0.4
                        evidence.append(f"Required ports: {sorted(required_ports)}")
                        print(f"[DEBUG] {fp.get('description', os_name)}: Required ports match (+0.4): {sorted(required_ports)}")
                    
                    # 2. Optional ports scoring
                    optional_ports = set(p['port'] for p in fp.get('optional_ports', []))
                    optional_found = optional_ports.intersection(open_port_set)
                    if optional_ports:
                        optional_score = len(optional_found) / len(optional_ports) * 0.2
                        score += optional_score
                        print(f"[DEBUG] {fp.get('description', os_name)}: Optional ports ({len(optional_found)}/{len(optional_ports)}) (+{optional_score:.2f}): {sorted(optional_found)}")
                        if optional_found:
                            evidence.append(f"Optional ports: {sorted(optional_found)}")
                    
                    # 3. Service banner matching
                    if service_banners and fp.get('service_banners'):
                        banner_score = self._match_service_banners(service_banners, fp['service_banners'])
                        score += banner_score
                        print(f"[DEBUG] {fp.get('description', os_name)}: Banner matching (+{banner_score:.2f})")
                        if banner_score > 0:
                            evidence.append(f"Service banners matched")
                            methods['banners'] = {'score': banner_score}
                    else:
                        print(f"[DEBUG] {fp.get('description', os_name)}: No banners to match")
                    
                    # 4. Network indicators (TTL, window size, TCP stack)
                    network_score = self._match_network_indicators(target_ip, fp.get('network_indicators', {}))
                    score += network_score
                    print(f"[DEBUG] {fp.get('description', os_name)}: Network indicators (+{network_score:.2f})")
                    if network_score > 0:
                        evidence.append(f"Network indicators matched")
                        methods['network'] = {'score': network_score}
                    
                    # 5. Confidence boost
                    boost_ports = set(p['port'] for p in fp.get('confidence_boost', []))
                    boost_found = boost_ports.intersection(open_port_set)
                    if boost_found:
                        boost_score = len(boost_found) / len(boost_ports) * 0.2 if boost_ports else 0
                        score += boost_score
                        print(f"[DEBUG] {fp.get('description', os_name)}: Confidence boost (+{boost_score:.2f}): {sorted(boost_found)}")
                        evidence.append(f"Confidence boost ports: {sorted(boost_found)}")
                    elif boost_ports:
                        print(f"[DEBUG] {fp.get('description', os_name)}: No confidence boost ports found")
                    
                    # 6. Negative indicators penalty
                    if fp.get('negative_indicators'):
                        penalty = self._apply_negative_indicators(open_port_set, fp['negative_indicators'])
                        score -= penalty
                        print(f"[DEBUG] {fp.get('description', os_name)}: Negative indicators penalty (-{penalty:.2f})")
                        if penalty > 0:
                            evidence.append(f"Negative indicators penalty: -{penalty:.2f}")
                    else:
                        print(f"[DEBUG] {fp.get('description', os_name)}: No negative indicators")
                    
                    # Check confidence threshold (lowered for better matching)
                    threshold = fp.get('confidence_threshold', 0.6) * 0.7  # Lower threshold by 30%
                    print(f"[DEBUG] {fp.get('description', os_name)}: Final score {score:.2f} vs threshold {threshold:.2f}")
                    if score >= threshold:
                        confidence = 'high' if score >= 0.8 else 'medium' if score >= 0.6 else 'low'
                        print(f"[DEBUG] {fp.get('description', os_name)}: MATCH! Confidence: {confidence}")
                        
                        match = {
                            'description': fp.get('description', os_name),
                            'score': score,
                            'confidence': confidence,
                            'evidence': evidence,
                            'methods': methods,
                            'category': category
                        }
                        
                        # Add vulnerabilities if present
                        if fp.get('vulnerabilities'):
                            match['vulnerabilities'] = fp['vulnerabilities']
                        
                        matches.append(match)
                    else:
                        print(f"[DEBUG] {fp.get('description', os_name)}: FAILED - Score below threshold")
            
            # Sort by score and return best matches
            matches.sort(key=lambda x: x['score'], reverse=True)
            print(f"[DEBUG] Total matches found: {len(matches)}")
            for i, match in enumerate(matches[:3]):
                print(f"[DEBUG] Match {i+1}: {match['description']} (score: {match['score']:.2f})")
            return matches[:3]  # Return top 3 matches
            
        except Exception as e:
            return []
    
    def _match_service_banners(self, service_banners, banner_patterns):
        """Match service banners against patterns with version detection"""
        import re
        score = 0
        
        # Use provided service banners if available
        if service_banners:
            for pattern in banner_patterns:
                port = pattern['port']
                regex = pattern['banner_regex']
                weight = pattern.get('weight', 0.1)
                
                if port in service_banners:
                    banner = service_banners[port]
                    
                    # Check for version-specific info in WinRM banners
                    if port == 5985 and '|VERSION:' in banner:
                        banner_part, version_part = banner.split('|VERSION:', 1)
                        version = version_part.strip()
                        
                        # Adjust regex based on detected version
                        if '2022' in regex and version == '2022':
                            score += weight + 0.2  # Bonus for exact version match
                            print(f"[DEBUG] Exact version match on port {port}: Server {version}")
                        elif '2019' in regex and version == '2019':
                            score += weight + 0.2  # Bonus for exact version match
                            print(f"[DEBUG] Exact version match on port {port}: Server {version}")
                        elif re.search(regex, banner_part, re.IGNORECASE):
                            score += weight
                            print(f"[DEBUG] Banner match on port {port}: {regex}")
                    elif re.search(regex, banner, re.IGNORECASE):
                        score += weight
                        print(f"[DEBUG] Banner match on port {port}: {regex}")
        
        return min(score, 0.5)  # Increased cap for version bonuses
    
    def _match_network_indicators(self, target_ip, network_indicators):
        """Match network-level indicators including banner grabbing"""
        score = 0
        
        # TTL matching with tolerance
        if network_indicators.get('ttl'):
            ttl_data = network_indicators['ttl']
            expected_ttl = ttl_data['value']
            tolerance = ttl_data.get('tolerance', 5)
            
            observed_ttl = self._get_observed_ttl(target_ip)
            print(f"[DEBUG] TTL Analysis: Expected {expected_ttl}±{tolerance}, Observed: {observed_ttl}")
            if observed_ttl and abs(observed_ttl - expected_ttl) <= tolerance:
                score += 0.15
                print(f"[DEBUG] TTL Match! (+0.15)")
            else:
                print(f"[DEBUG] TTL No Match")
        
        # TCP window size matching
        if network_indicators.get('tcp_window_size'):
            window_data = network_indicators['tcp_window_size']
            expected_window = window_data['value']
            tolerance = window_data.get('tolerance', 1000)
            
            observed_window = self.tcp_window_analysis(target_ip)
            print(f"[DEBUG] Window Analysis: Expected {expected_window}±{tolerance}, Observed: {observed_window}")
            if observed_window and abs(observed_window - expected_window) <= tolerance:
                score += 0.1
                print(f"[DEBUG] Window Match! (+0.1)")
            else:
                print(f"[DEBUG] Window No Match")
        
        # Banner grabbing for additional indicators (cached)
        banner_score = self._get_cached_banner_score(target_ip)
        score += banner_score
        print(f"[DEBUG] Banner grabbing score: +{banner_score:.2f}")
        
        # TCP stack quirks (simplified - would need raw packet analysis)
        if network_indicators.get('tcp_stack_quirks'):
            print(f"[DEBUG] TCP Stack Quirks: Simplified analysis")
            # This would require deep packet inspection in a real implementation
            # For now, we'll give a small bonus if other indicators match
            if score > 0:
                score += 0.05
                print(f"[DEBUG] TCP Stack bonus (+0.05)")
        
        final_score = min(score, 0.4)  # Increased cap to 0.4 for banner data
        print(f"[DEBUG] Network indicators total score: {final_score}")
        return final_score
    
    def _apply_negative_indicators(self, open_ports, negative_indicators):
        """Apply penalties for negative indicators"""
        penalty = 0
        
        for indicator in negative_indicators:
            port = indicator['port']
            reduction = indicator.get('confidence_reduction', 0.1)
            
            if port in open_ports:
                penalty += reduction
        
        return penalty
    
    def _get_observed_ttl(self, target_ip):
        """Get observed TTL for target"""
        if target_ip in self.ttl_data and self.ttl_data[target_ip]:
            return self.ttl_data[target_ip][0]
        
        # Try to get TTL data
        if self.analyze_tcp_response(target_ip):
            if target_ip in self.ttl_data and self.ttl_data[target_ip]:
                return self.ttl_data[target_ip][0]
        
        return None
    
    def __init__(self):
        self.ttl_data = defaultdict(list)
        self.window_data = defaultdict(list)
        self.ip_id_data = defaultdict(list)
        self._banner_cache = {}  # Cache for banner results
        self._open_ports_cache = {}  # Cache for open ports
    
    def _get_cached_banner_score(self, target_ip):
        """Get cached banner score to avoid redundant scans"""
        if target_ip in self._banner_cache:
            return self._banner_cache[target_ip]
        
        score = self._grab_service_banners(target_ip)
        self._banner_cache[target_ip] = score
        return score
    
    def _grab_service_banners(self, target_ip):
        """Grab service banners for OS detection (only from open ports)"""
        import re
        score = 0
        
        # Get open ports to avoid scanning closed ports
        open_ports = self._get_open_ports(target_ip)
        
        # SMB Banner (445) - only if port is open
        if 445 in open_ports:
            try:
                smb_banner = self._grab_smb_banner(target_ip)
                if smb_banner and 'windows server' in smb_banner.lower():
                    match = re.search(r'(?i)windows\s+server\s+20\d{2}', smb_banner)
                    if match:
                        print(f"[DEBUG] SMB Banner: {match.group()}")
                        score += 0.2
            except:
                pass
        
        # WinRM Banner (5985) - only if port is open
        if 5985 in open_ports:
            try:
                winrm_banner = self._grab_winrm_banner(target_ip)
                if winrm_banner and 'microsoft-httpapi' in winrm_banner.lower():
                    print(f"[DEBUG] WinRM Banner: Microsoft-HTTPAPI detected")
                    score += 0.1
            except:
                pass
        
        # HTTP/HTTPS Banner - only if ports are open
        for port in [80, 443]:
            if port in open_ports:
                try:
                    http_banner = self._grab_http_banner(target_ip, port)
                    if http_banner and 'microsoft-iis' in http_banner.lower():
                        print(f"[DEBUG] HTTP Banner: Microsoft-IIS detected on port {port}")
                        score += 0.1
                        break
                except:
                    pass
        
        # RDP Certificate (3389) - only if port is open
        if 3389 in open_ports:
            try:
                rdp_info = self._grab_rdp_banner(target_ip)
                if rdp_info and any('server' in str(rdp_info).lower() or 'win' in str(rdp_info).lower() for _ in [1]):
                    print(f"[DEBUG] RDP Certificate: Windows server detected")
                    score += 0.1
            except:
                pass
        
        return min(score, 0.3)
    
    def _get_open_ports(self, target_ip):
        """Get list of open ports for target (cached)"""
        if target_ip in self._open_ports_cache:
            return self._open_ports_cache[target_ip]
        
        # Quick scan of common ports to determine what's open
        open_ports = set()
        common_ports = [21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 143, 389, 443, 445, 993, 995, 1433, 3389, 5985, 8080]
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)  # Very quick check
                result = sock.connect_ex((target_ip, port))
                sock.close()
                if result == 0:
                    open_ports.add(port)
            except:
                pass
        
        self._open_ports_cache[target_ip] = open_ports
        return open_ports
    
    def _grab_smb_banner(self, ip, port=445):
        """Try SMBv2/3 first, then fallback to SMBv1"""
        # Try SMBv2/3 first (modern systems)
        try:
            smb2_result = self._try_smbv2_banner(ip, port)
            if smb2_result:
                print(f"[DEBUG] SMBv2/3 Success ({ip}:{port}): {smb2_result}")
                return smb2_result
        except Exception as e:
            print(f"[DEBUG] SMBv2/3 failed ({ip}:{port}): {e}")
        
        # Fallback to SMBv1 (legacy systems)
        try:
            smb1_result = self._grab_smbv1_banner(ip, port)
            if smb1_result:
                print(f"[DEBUG] SMBv1 Success ({ip}:{port}): {repr(smb1_result[:100])}")
                return smb1_result
        except Exception as e:
            print(f"[DEBUG] SMBv1 failed ({ip}:{port}): {e}")
        
        return None
    
    def _try_smbv2_banner(self, ip, port=445):
        """Try SMBv2/3 negotiate"""
        import struct
        
        # SMBv2 negotiate packet
        packet = (
            b'\x00\x00\x00\x64'  # NetBIOS header (length)
            b'\xfeSMB'           # SMB2 signature
            b'\x40\x00'          # Header length
            b'\x00\x00'          # Credit charge
            b'\x00\x00\x00\x00'  # Status
            b'\x00\x00'          # Command (negotiate)
            b'\x00\x00'          # Credits
            b'\x00\x00\x00\x00'  # Flags
            b'\x00\x00\x00\x00'  # Next command
            b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Message ID
            b'\x00\x00\x00\x00'  # Process ID
            b'\x00\x00\x00\x00'  # Tree ID
            b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Session ID
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # Signature
            b'\x24\x00'          # Structure size
            b'\x03\x00'          # Dialect count
            b'\x00\x00'          # Security mode
            b'\x00\x00'          # Reserved
            b'\x00\x00\x00\x00'  # Capabilities
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # GUID
            b'\x02\x02\x10\x02\x00\x03\x11\x03'  # Dialects: 2.0.2, 2.1, 3.0, 3.1.1
        )
        
        with socket.create_connection((ip, port), timeout=3) as s:
            s.send(packet)
            data = s.recv(1024)
            
            if len(data) >= 68 and data[4:8] == b'\xfeSMB':
                try:
                    # Try different offset positions for dialect
                    for offset in [64, 66, 68, 70, 72]:
                        if offset + 2 <= len(data):
                            dialect = struct.unpack('<H', data[offset:offset+2])[0]
                            if dialect != 0x0000:
                                break
                    
                    dialect_map = {
                        0x0202: 'SMB 2.0.2 (Vista/2008)',
                        0x0210: 'SMB 2.1 (Win7/2008R2)', 
                        0x0300: 'SMB 3.0 (Win8/2012)',
                        0x0302: 'SMB 3.0.2 (Win8.1/2012R2)',
                        0x0311: 'SMB 3.1.1 (Win10/2016+)',
                        0x0009: 'SMB 3.1.1 (Server 2025)'
                    }
                    
                    if dialect == 0x0000:
                        # Check if it's an error response
                        status = struct.unpack('<I', data[8:12])[0] if len(data) >= 12 else 0
                        if status != 0:
                            return f'SMBv2/3 Error Response (Status: 0x{status:08x})'
                        else:
                            return 'SMBv2/3 Response (Modern Windows)'
                    else:
                        dialect_name = dialect_map.get(dialect, f'SMB Unknown (0x{dialect:04x})')
                        return f'SMBv2/3 Dialect: {dialect_name}'
                except Exception as e:
                    return f'SMBv2/3 Response (parse error: {e})'
            
            return None
    
    def _grab_smbv1_banner(self, ip, port=445):
        """SMBv1 negotiate for legacy systems"""
        smb_negotiate = (
            b'\x00\x00\x00\x85'  # NetBIOS header
            b'\xff\x53\x4d\x42'  # SMB signature
            b'\x72\x00\x00\x00'  # SMB command (negotiate)
            b'\x00\x18\x01\x28'  # Flags
            b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Reserved
            b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Tree ID, Process ID
            b'\x00\x00\x00\x00\x00\x00\x00\x00'  # User ID, Multiplex ID
            b'\x00\x3c\x00\x02\x50\x43\x20\x4e'  # Parameter block
            b'\x45\x54\x57\x4f\x52\x4b\x20\x50'
            b'\x52\x4f\x47\x52\x41\x4d\x20\x31'
            b'\x2e\x30\x00\x02\x4c\x41\x4e\x4d'
            b'\x41\x4e\x31\x2e\x30\x00\x02\x57'
            b'\x69\x6e\x64\x6f\x77\x73\x20\x66'
            b'\x6f\x72\x20\x57\x6f\x72\x6b\x67'
            b'\x72\x6f\x75\x70\x73\x20\x33\x2e'
            b'\x31\x61\x00\x02\x4c\x4d\x31\x2e'
            b'\x32\x58\x30\x30\x32\x00\x02\x4c'
            b'\x41\x4e\x4d\x41\x4e\x32\x2e\x31'
            b'\x00\x02\x4e\x54\x20\x4c\x4d\x20'
            b'\x30\x2e\x31\x32\x00'
        )
        
        with socket.create_connection((ip, port), timeout=3) as s:
            s.send(smb_negotiate)
            data = s.recv(2048)
            return data.decode('latin-1', errors='ignore')
    
    def _grab_winrm_banner(self, ip, port=5985):
        """Grab WinRM banner with enhanced version detection"""
        try:
            # Try multiple endpoints for version info
            endpoints = [
                "/wsman",
                "/wsman/IdentifyResponse", 
                "/wsman/identify",
                "/PowerShell"
            ]
            
            best_banner = None
            version_info = None
            
            for endpoint in endpoints:
                try:
                    with socket.create_connection((ip, port), timeout=2) as s:
                        req = f"GET {endpoint} HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Microsoft WinRM Client\r\nConnection: close\r\n\r\n"
                        s.send(req.encode())
                        banner = s.recv(2048).decode(errors='ignore')
                        
                        if not best_banner:
                            best_banner = banner
                        
                        # Look for version indicators in response
                        if 'server 2022' in banner.lower():
                            version_info = '2022'
                            break
                        elif 'server 2019' in banner.lower():
                            version_info = '2019'
                            break
                        elif 'server 2016' in banner.lower():
                            version_info = '2016'
                            break
                        elif 'powershell' in banner.lower() and 'version' in banner.lower():
                            # PowerShell version can indicate OS version
                            import re
                            ps_match = re.search(r'powershell[^\d]*([\d\.]+)', banner.lower())
                            if ps_match:
                                ps_version = ps_match.group(1)
                                if ps_version.startswith('7.'):
                                    version_info = '2022'  # PowerShell 7+ typically on newer systems
                                elif ps_version.startswith('5.1'):
                                    version_info = '2019'  # PowerShell 5.1 on 2016/2019
                except:
                    continue
            
            if best_banner:
                print(f"[DEBUG] WinRM Banner ({ip}:{port}): {repr(best_banner[:200])}")
                if version_info:
                    print(f"[DEBUG] WinRM Version Detected: Windows Server {version_info}")
                    return f"{best_banner}|VERSION:{version_info}"
                return best_banner
            
        except Exception as e:
            print(f"[DEBUG] WinRM Banner ({ip}:{port}): Failed - {e}")
            return None
    
    def _grab_http_banner(self, ip, port):
        """Grab HTTP/HTTPS banner"""
        import ssl
        try:
            if port == 443:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with socket.create_connection((ip, port), timeout=3) as sock:
                    with context.wrap_socket(sock) as ssock:
                        req = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                        ssock.send(req.encode())
                        banner = ssock.recv(1024).decode(errors='ignore')
                        print(f"[DEBUG] HTTPS Banner ({ip}:{port}): {repr(banner[:200])}")
                        return banner
            else:
                with socket.create_connection((ip, port), timeout=3) as s:
                    req = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                    s.send(req.encode())
                    banner = s.recv(1024).decode(errors='ignore')
                    print(f"[DEBUG] HTTP Banner ({ip}:{port}): {repr(banner[:200])}")
                    return banner
        except Exception as e:
            print(f"[DEBUG] HTTP Banner ({ip}:{port}): Failed - {e}")
            return None
    
    def _grab_rdp_banner(self, ip, port=3389):
        """Grab RDP certificate info"""
        try:
            import ssl
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=3) as sock:
                with context.wrap_socket(sock) as ssock:
                    cert = ssock.getpeercert()
                    subject = cert.get('subject', [])
                    print(f"[DEBUG] RDP Certificate ({ip}:{port}): {subject}")
                    return subject
        except Exception as e:
            print(f"[DEBUG] RDP Certificate ({ip}:{port}): Failed - {e}")
            return None
    
    def _legacy_comprehensive_detection(self, target_ip, open_ports):
        """Legacy detection method as fallback"""
        results = {
            'target': target_ip,
            'os_candidates': [],
            'confidence': 'low',
            'evidence': [],
            'fingerprints': {}
        }
        
        # Basic TTL and port pattern detection
        ttl_os = self._detect_os_from_ttl(target_ip)
        if ttl_os:
            results['fingerprints']['ttl'] = ttl_os
            results['evidence'].append(f"TTL analysis: {ttl_os['os']} (TTL: {ttl_os['ttl']})")
        
        if open_ports:
            port_os = self._detect_os_from_ports(open_ports)
            if port_os:
                results['fingerprints']['ports'] = port_os
                results['evidence'].append(f"Port pattern: {port_os['os']}")
        
        # Simple voting
        if results['fingerprints']:
            # Use TTL result if available, otherwise port pattern
            if ttl_os:
                results['os_candidates'] = [{'os': ttl_os['os']}]
                results['confidence'] = ttl_os['confidence']
            elif port_os:
                results['os_candidates'] = [{'os': port_os['os']}]
                results['confidence'] = port_os['confidence']
        
        return results
def create_enhanced_os_detector():
    """Factory function to create enhanced OS detector"""
    return EnhancedOSDetection()