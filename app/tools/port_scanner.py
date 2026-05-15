# app/tools/port_scanner.py
import socket
import threading
import concurrent.futures
import ipaddress
import time
from PyQt6.QtCore import QObject, pyqtSignal, QRunnable
from app.core.html_utils import h
from app.core.logger import logger

class PortScannerSignals(QObject):
    output = pyqtSignal(str)
    status = pyqtSignal(str)
    finished = pyqtSignal()
    results_ready = pyqtSignal(dict)
    progress_update = pyqtSignal(int, int)
    progress_start = pyqtSignal(int)

class PortScanWorker(QRunnable):
    """Port scanning worker for TCP connect scans"""
    
    def __init__(self, target, ports, scan_type="tcp", timeout=3, tenant_id="default"):
        super().__init__()
        self.signals = PortScannerSignals()
        self.target = target
        self.ports = ports
        self.scan_type = scan_type
        self.timeout = timeout
        self.tenant_id = tenant_id
        self.is_running = True
        self.results = {}
    
    def scan_port(self, port):
        """Scan a single port"""
        if not self.is_running:
            return None
            
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                return port, service
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        return None
    
    def run(self):
        try:
            self.signals.status.emit(f"Starting port scan on {self.target}...")
            self.signals.output.emit(f"<p style='color: #00BFFF;'>Scanning {len(self.ports)} ports on {h(self.target)}...</p><br>")
            self.signals.progress_start.emit(len(self.ports))
            
            open_ports = []
            completed = 0
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                future_to_port = {executor.submit(self.scan_port, port): port for port in self.ports}
                
                for future in concurrent.futures.as_completed(future_to_port):
                    if not self.is_running:
                        break
                        
                    result = future.result()
                    completed += 1
                    
                    if result:
                        port, service = result
                        open_ports.append((port, service))
                        self.signals.output.emit(
                            f"<p style='color: #00FF41;'>[+] Port {port}/tcp open - {service}</p><br>"
                        )
                    
                    if completed % 10 == 0:
                        self.signals.progress_update.emit(completed, len(open_ports))
            
            if open_ports:
                port_data = [{'port': port, 'service': service, 'banner': '', 'protocol': 'tcp', 'state': 'open'} for port, service in open_ports]
                self.results[self.target] = {'open_ports': port_data}
                self.signals.results_ready.emit(self.results)
                self.signals.output.emit(f"<br><p style='color: #00FF41;'>Found {len(open_ports)} open ports</p>")
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>No open ports found</p>")
            
            self.signals.status.emit("Port scan completed")
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF4500;'>[ERROR] Port scan failed: {h(str(e))}</p>")
            self.signals.status.emit("Port scan error")
        finally:
            self.signals.finished.emit()

class NetworkSweepWorker(QRunnable):
    """Network sweep worker for host discovery"""
    
    def __init__(self, network_range, timeout=1, tenant_id="default"):
        super().__init__()
        self.signals = PortScannerSignals()
        self.network_range = network_range
        self.timeout = timeout
        self.tenant_id = tenant_id
        self.is_running = True
        
    def ping_host(self, ip):
        """Check if host is alive using TCP fallback"""
        if not self.is_running:
            return None
        
        # Try TCP connect on common ports
        for port in [80, 443, 22, 135, 445]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    return ip
            except Exception:
                continue
        
        return None
    
    def run(self):
        try:
            # Parse network range using proper IP range parser
            if isinstance(self.network_range, list):
                ips = self.network_range
            else:
                from app.core.ip_range_parser import parse_ip_range
                ips = parse_ip_range(self.network_range)
                if not ips:
                    self.signals.output.emit(f"<p style='color: #FF6B6B;'>[ERROR] Invalid network range: {h(self.network_range)}</p><br>")
                    self.signals.finished.emit()
                    return
            
            self.signals.status.emit(f"Starting ping sweep on {len(ips)} hosts...")
            self.signals.output.emit(f"<p style='color: #00BFFF;'>Sweeping {len(ips)} hosts...</p><br>")
            self.signals.progress_start.emit(len(ips))
            
            alive_hosts = []
            completed = 0
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
                future_to_ip = {executor.submit(self.ping_host, ip): ip for ip in ips}
                
                for future in concurrent.futures.as_completed(future_to_ip):
                    if not self.is_running:
                        break
                        
                    result = future.result()
                    completed += 1
                    
                    if result:
                        alive_hosts.append(result)
                        self.signals.output.emit(
                            f"<p style='color: #00FF41;'>[+] Host {result} is alive</p><br>"
                        )
                    
                    if completed % 20 == 0:
                        self.signals.progress_update.emit(completed, len(alive_hosts))
            
            # Final summary
            self.signals.output.emit(f"<br><p style='color: #00FF41;'>Found {len(alive_hosts)} alive hosts</p><br>")
            
            if alive_hosts:
                # Determine scan type based on context
                scan_type = getattr(self, 'scan_type', 'ping_sweep')
                results = {
                    'alive_hosts': alive_hosts,
                    'scan_type': scan_type
                }
                
                # Add assets to inventory (debug output suppressed)
                try:
                    from app.core.asset_manager import asset_manager
                    print(f"[DEBUG] Adding {len(alive_hosts)} assets to inventory for tenant: {self.tenant_id}")
                    
                    added_count = 0
                    for host in alive_hosts:
                        asset_data = {
                            'ip_address': host,
                            'status': 'DISCOVERED',
                            'confidence': 60 if scan_type == 'huginn_sweep' else 50,
                            'metadata': {
                                'discovery_method': 'network_sweep',
                                'scan_type': scan_type
                            }
                        }
                        
                        asset_id = asset_manager.add_or_update_asset(self.tenant_id, **asset_data)
                        print(f"[DEBUG] Added asset {host} with ID: {asset_id}")
                        added_count += 1
                    
                    print(f"[DEBUG] Added {added_count} assets to inventory for tenant {self.tenant_id}")
                    self.signals.output.emit(f"<p style='color: #87CEEB;'>Updated inventory with {h(added_count)} hosts from ping sweep</p><br>")
                    
                except Exception as e:
                    print(f"[ERROR] Failed to add assets to inventory: {e}")
                    import traceback
                    print(f"[ERROR] Traceback: {traceback.format_exc()}")
                
                self.signals.results_ready.emit(results)
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>No alive hosts found</p>")
            
            self.signals.status.emit("Ping sweep completed")
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF4500;'>[ERROR] Ping sweep failed: {h(str(e))}</p>")
            self.signals.status.emit("Ping sweep error")
        finally:
            self.signals.finished.emit()

class EnhancedPortScanWorker(QRunnable):
    """Enhanced port scanning with OS and service detection"""
    
    PROBES = {
        21: b"",  # FTP sends banner immediately
        22: b"",  # SSH sends banner immediately
        25: b"EHLO test\r\n",
        80: b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        110: b"USER test\r\n",
        143: b". LOGIN test test\r\n",
        443: b"",  # HTTPS - will try TLS handshake
        6379: b"PING\r\n",  # Redis
    }
    
    def __init__(self, target_ips, tcp_ports=None, os_detection=False, service_detection=False, timeout=3, tenant_id="default"):
        super().__init__()
        self.signals = PortScannerSignals()
        # Handle both single target and list of targets
        if isinstance(target_ips, str):
            self.target_ips = [target_ips]
        elif isinstance(target_ips, list):
            self.target_ips = target_ips
        else:
            self.target_ips = [str(target_ips)]
        self.tcp_ports = tcp_ports or []
        self.os_detection = os_detection
        self.service_detection = service_detection
        self.timeout = timeout
        self.tenant_id = tenant_id
        self.is_running = True
        self.results = {}
    
    def get_tls_version_for_ip(self, target_ip, port):
        """Get TLS version for specific IP"""
        try:
            import ssl
            sock = socket.create_connection((target_ip, port), timeout=2)
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with context.wrap_socket(sock, server_hostname=target_ip) as ssl_sock:
                return ssl_sock.version()
        except:
            return None
    
    def identify_service_from_banner(self, port, banner):
        """Identify service from banner response with enhanced OS detection"""
        banner_lower = banner.lower()
        confidence = "medium"
        
        if "220" in banner and "ftp" in banner_lower:
            return "FTP", "high"
        elif "ssh" in banner_lower:
            # Enhanced SSH banner parsing for OS detection
            if "ubuntu" in banner_lower:
                import re
                # Extract Ubuntu version from SSH banner
                ubuntu_match = re.search(r'ubuntu-([\d\.]+)ubuntu([\d\.]+)', banner_lower)
                if ubuntu_match:
                    return f"SSH (Ubuntu {ubuntu_match.group(1)})", "high"
                else:
                    return "SSH (Ubuntu)", "high"
            elif "debian" in banner_lower:
                return "SSH (Debian)", "high"
            elif "centos" in banner_lower:
                return "SSH (CentOS)", "high"
            elif "fedora" in banner_lower:
                return "SSH (Fedora)", "high"
            elif "openssh" in banner_lower:
                # Try to extract OpenSSH version for better OS hints
                import re
                version_match = re.search(r'openssh[_\s]([\d\.]+)', banner_lower)
                if version_match:
                    return f"SSH (OpenSSH {version_match.group(1)})", "high"
            return "SSH", "high"
        elif "220" in banner and "smtp" in banner_lower:
            return "SMTP", "high"
        elif "http" in banner_lower or "server:" in banner_lower:
            return "HTTP", "high"
        elif "+ok" in banner_lower and "pop3" in banner_lower:
            return "POP3", "high"
        elif "* ok" in banner_lower and "imap" in banner_lower:
            return "IMAP", "high"
        elif port == 6379 and ("+pong" in banner_lower or "redis" in banner_lower):
            return "Redis", "high"
        elif "mysql" in banner_lower or "mariadb" in banner_lower:
            return "MySQL", "high"
        else:
            try:
                service = socket.getservbyport(port)
                return service, "low"
            except:
                return "unknown", "low"
    
    def detect_os_from_ports(self, port_data, target_ip=None):
        """Enhanced OS detection using multiple techniques"""
        open_ports = [p['port'] for p in port_data]
        
        # Extract service banners for enhanced detection
        service_banners = {}
        for port_info in port_data:
            if port_info.get('banner'):
                service_banners[port_info['port']] = port_info['banner']
        
        # Check for Ubuntu specifically from SSH banner first
        for port_info in port_data:
            if port_info['port'] == 22 and port_info.get('banner'):
                banner = port_info['banner'].lower()
                if 'ubuntu' in banner:
                    import re
                    # Try to extract Ubuntu version
                    version_match = re.search(r'ubuntu-([\d\.]+)ubuntu', banner)
                    if version_match:
                        return {
                            'os': f'Ubuntu Linux {version_match.group(1)}',
                            'confidence': 'high',
                            'evidence': [f'SSH banner: {port_info["banner"][:50]}'],
                            'detection_methods': ['ssh_banner']
                        }
                    else:
                        return {
                            'os': 'Ubuntu Linux',
                            'confidence': 'high', 
                            'evidence': [f'SSH banner: {port_info["banner"][:50]}'],
                            'detection_methods': ['ssh_banner']
                        }
                elif 'debian' in banner:
                    return {
                        'os': 'Debian Linux',
                        'confidence': 'high',
                        'evidence': [f'SSH banner: {port_info["banner"][:50]}'],
                        'detection_methods': ['ssh_banner']
                    }
        
        # Use enhanced OS detection if available
        try:
            from app.core.enhanced_os_detection import create_enhanced_os_detector
            detector = create_enhanced_os_detector()
            
            if target_ip:
                # Perform comprehensive OS detection with banners
                enhanced_result = detector.comprehensive_os_detection(target_ip, open_ports, service_banners)
                
                if enhanced_result['os_candidates']:
                    best_candidate = enhanced_result['os_candidates'][0]
                    return {
                        'os': best_candidate['os'],
                        'confidence': enhanced_result['confidence'],
                        'evidence': enhanced_result['evidence'],
                        'detection_methods': list(enhanced_result['fingerprints'].keys())
                    }
        except Exception as e:
            # Fall back to basic detection if enhanced fails
            pass
            logger.debug("Suppressed exception", exc_info=True)
        
        # Fallback to basic port-based detection
        return self._basic_os_detection(set(open_ports))
    
    def _basic_os_detection(self, open_ports):
        """Fallback basic OS detection"""
        if {135, 445}.issubset(open_ports):
            return {'os': 'Windows', 'confidence': 'medium', 'evidence': ['RPC + SMB ports']}
        elif 22 in open_ports:
            return {'os': 'Linux/Unix', 'confidence': 'medium', 'evidence': ['SSH port 22']}
        return {'os': 'Unknown', 'confidence': 'low', 'evidence': ['No matching patterns']}
    
    def _calculate_fingerprint_score(self, open_ports, fingerprint):
        """Calculate match score for OS fingerprint"""
        required_ports = self._extract_ports_from_fingerprint(fingerprint.get('required_ports', []))
        optional_ports = self._extract_ports_from_fingerprint(fingerprint.get('optional_ports', []))
        boost_ports = self._extract_ports_from_fingerprint(fingerprint.get('confidence_boost', []))
        
        if not required_ports.issubset(open_ports):
            return 0
        
        score = 0.5
        optional_found = optional_ports.intersection(open_ports)
        if optional_ports:
            score += 0.3 * (len(optional_found) / len(optional_ports))
        
        boost_found = boost_ports.intersection(open_ports)
        if boost_ports:
            score += 0.2 * (len(boost_found) / len(boost_ports))
        
        return min(score, 1.0)
    
    def _extract_ports_from_fingerprint(self, port_list):
        """Extract port numbers from fingerprint format"""
        ports = set()
        for item in port_list:
            if isinstance(item, dict):
                ports.add(item.get('port'))
            else:
                ports.add(item)
        return ports
    
    def scan_tcp_port(self, target_ip, port):
        """Enhanced TCP port scanning"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((target_ip, port))
            
            if result != 0:
                sock.close()
                return None
            
            # Port is open - will show in final output
            
            banner = ""
            service = "unknown"
            confidence = "medium"
            tls_version = None
            
            if self.service_detection:
                try:
                    probe = self.PROBES.get(port, b"")
                    if probe:
                        sock.sendall(probe)
                    banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                except Exception as _exc:
                    pass
                    logger.debug("Suppressed exception", exc_info=True)
            
            sock.close()
            
            # TLS detection for HTTPS ports
            if port in [443, 993, 995, 8443] and self.service_detection:
                tls_version = self.get_tls_version_for_ip(target_ip, port)
                if tls_version:
                    service = "HTTPS" if port == 443 else f"SSL/{get_service_description(port)}"
                    confidence = "high"
            
            # Service identification
            if banner and self.service_detection:
                service, confidence = self.identify_service_from_banner(port, banner)
            elif not tls_version:
                from .port_utils import get_service_description
                service = get_service_description(port)
            
            return port, 'tcp', service, banner, confidence, tls_version
            
        except Exception as e:
            # Connection failed - no output needed
            return None
    
    def run(self):
        try:
            total_ports = len(self.tcp_ports)
            total_scans = len(self.target_ips) * total_ports
            
            self.signals.status.emit(f"Starting enhanced scan on {len(self.target_ips)} targets...")
            self.signals.output.emit(f"<p style='color: #00BFFF;'>Enhanced scanning {total_ports} ports on {len(self.target_ips)} targets...</p><br>")
            
            if self.os_detection:
                self.signals.output.emit(f"<p style='color: #FFD700;'>OS Detection enabled</p><br>")
            if self.service_detection:
                self.signals.output.emit(f"<p style='color: #FFD700;'>Service Detection enabled</p><br>")
            
            self.signals.progress_start.emit(total_scans)
            

            
            completed = 0
            all_results = {}
            
            for target_ip in self.target_ips:
                if not self.is_running:
                    break
                
                open_ports = []
                with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                    future_to_port = {executor.submit(self.scan_tcp_port, target_ip, port): port for port in self.tcp_ports}
                    
                    for future in concurrent.futures.as_completed(future_to_port):
                        if not self.is_running:
                            break
                            
                        result = future.result()
                        completed += 1
                        
                        if result:
                            port, protocol, service, banner, confidence, tls_version = result
                            open_ports.append((port, protocol, service, banner, confidence, tls_version))
                            
                            # Format output
                            info_parts = [service]
                            if confidence != "medium":
                                info_parts.append(f"({confidence})")
                            if tls_version:
                                info_parts.append(f"TLS: {tls_version}")
                            if banner and self.service_detection and len(banner) > 0:
                                clean_banner = banner.replace('\r', '').replace('\n', ' ').strip()[:50]
                                info_parts.append(f"Banner: {clean_banner}")
                            
                            service_info = " - ".join(info_parts)
                            self.signals.output.emit(
                                f"<p style='color: #00FF41;'>[+] {target_ip}:{port}/{protocol} open - {service_info}</p><br>"
                            )
                        
                        if completed % 10 == 0:
                            self.signals.progress_update.emit(completed, sum(len(data.get('open_ports', [])) for data in all_results.values()))
                
                if open_ports:
                    port_data = []
                    for port, protocol, service, banner, confidence, tls_version in open_ports:
                        port_info = {
                            'port': port,
                            'protocol': protocol,
                            'service': service,
                            'banner': banner or '',
                            'confidence': confidence,
                            'tls_version': tls_version
                        }
                        port_data.append(port_info)
                    
                    all_results[target_ip] = {'open_ports': port_data}
                    
                    # Add service categorization and server type detection
                    from .port_utils import categorize_services, detect_server_type
                    open_port_nums = [p['port'] for p in port_data]
                    service_categories = categorize_services(open_port_nums)
                    server_type = detect_server_type(open_port_nums)
                    all_results[target_ip]['service_categories'] = service_categories
                    all_results[target_ip]['server_type'] = server_type
                    
                    # Display server type if detected
                    if server_type and server_type != 'Unknown':
                        self.signals.output.emit(f"<br><p style='color: #87CEEB;'>[SERVER TYPE] {h(target_ip)}: {h(server_type)}</p><br>")
                    
                    # Enhanced OS detection
                    if self.os_detection:
                        os_result = self.detect_os_from_ports(port_data, target_ip)
                        all_results[target_ip]['os_detection'] = os_result
                        
                        self.signals.output.emit(f"<br><p style='color: #FFD700;'>[OS Detection] {h(target_ip)}: {h(os_result['os'])} (Confidence: {h(os_result['confidence'])})</p><br>")
                        
                        # Show detection methods used
                        if 'detection_methods' in os_result:
                            methods = ', '.join(os_result['detection_methods'])
                            self.signals.output.emit(f"<p style='color: #87CEEB;'>  Detection methods: {h(methods)}</p><br>")
                        
                        # Show evidence
                        for evidence in os_result.get('evidence', []):
                            self.signals.output.emit(f"<p style='color: #FFAA00;'>  • {h(evidence)}</p><br>")
                        
                        # Show vulnerabilities if found
                        if os_result.get('vulnerabilities'):
                            self.signals.output.emit(f"<p style='color: #FF6B6B;'>  ⚠️ Known vulnerabilities found:</p><br>")
                            for vuln in os_result['vulnerabilities'][:3]:  # Show top 3
                                severity_color = {'Critical': '#FF0000', 'High': '#FF6B6B', 'Medium': '#FFA500', 'Low': '#FFFF00'}.get(vuln.get('severity', 'Medium'), '#FFA500')
                                self.signals.output.emit(f"<p style='color: {severity_color};'>    • {h(vuln['id'])}: {h(vuln['description'])}</p><br>")
            
            if all_results:
                self.results = all_results
                
                # Update inventory with enhanced scan results
                try:
                    from app.core.inventory_integration import update_inventory_from_port_scan
                    update_inventory_from_port_scan(all_results)
                except Exception as e:
                    self.signals.output.emit(f"<p style='color: #FFAA00;'>[WARNING] Inventory update failed: {h(e)}</p><br>")
                
                self.signals.results_ready.emit(self.results)
                total_open = sum(len(data.get('open_ports', [])) for data in all_results.values())
                self.signals.output.emit(f"<br><p style='color: #00FF41;'>Found {total_open} open ports across {len(all_results)} hosts</p>")
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>No open ports found</p>")
            
            self.signals.status.emit("Enhanced port scan completed")
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF4500;'>[ERROR] Enhanced port scan failed: {h(str(e))}</p>")
            self.signals.status.emit("Enhanced port scan error")
        finally:
            self.signals.finished.emit()

class LegacyEnhancedPortScanWorker(QRunnable):
    """Legacy enhanced port scanning worker - kept for compatibility"""
    
    def __init__(self, target, ports, os_detection=False, service_detection=False, timeout=3, tenant_id="default"):
        super().__init__()
        self.signals = PortScannerSignals()
        self.target = target
        self.ports = ports
        self.os_detection = os_detection
        self.service_detection = service_detection
        self.timeout = timeout
        self.tenant_id = tenant_id
        self.is_running = True
        self.results = {}
    
    def detect_os_from_ports(self, port_data, target_ip=None):
        """Enhanced OS detection with multiple techniques"""
        if isinstance(port_data, list) and port_data and isinstance(port_data[0], dict):
            open_ports = set(p['port'] for p in port_data)
            
            # Check for Ubuntu specifically from SSH banner first
            for port_info in port_data:
                if port_info['port'] == 22 and port_info.get('banner'):
                    banner = port_info['banner'].lower()
                    if 'ubuntu' in banner:
                        import re
                        # Try to extract Ubuntu version
                        version_match = re.search(r'ubuntu-([\d\.]+)ubuntu', banner)
                        if version_match:
                            return {
                                'os': f'Ubuntu Linux {version_match.group(1)}',
                                'confidence': 'high',
                                'evidence': [f'SSH banner: {port_info["banner"][:50]}'],
                                'detection_methods': ['ssh_banner']
                            }
                        else:
                            return {
                                'os': 'Ubuntu Linux',
                                'confidence': 'high', 
                                'evidence': [f'SSH banner: {port_info["banner"][:50]}'],
                                'detection_methods': ['ssh_banner']
                            }
                    elif 'debian' in banner:
                        return {
                            'os': 'Debian Linux',
                            'confidence': 'high',
                            'evidence': [f'SSH banner: {port_info["banner"][:50]}'],
                            'detection_methods': ['ssh_banner']
                        }
        else:
            open_ports = set(port_data) if port_data else set()
        
        # Try enhanced detection
        try:
            from app.core.enhanced_os_detection import create_enhanced_os_detector
            detector = create_enhanced_os_detector()
            
            if target_ip:
                enhanced_result = detector.comprehensive_os_detection(target_ip, list(open_ports))
                if enhanced_result['os_candidates']:
                    best_candidate = enhanced_result['os_candidates'][0]
                    return {
                        'os': best_candidate['os'],
                        'confidence': enhanced_result['confidence'],
                        'evidence': enhanced_result['evidence'],
                        'detection_methods': list(enhanced_result['fingerprints'].keys())
                    }
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        
        # Fallback to basic port pattern detection
        if {88, 135, 389, 445, 5985}.issubset(open_ports):
            return {
                'os': 'Windows Server (Domain Controller)',
                'confidence': 'high',
                'evidence': [f'DC port pattern: {sorted({88, 135, 389, 445, 5985})}']
            }
        elif {135, 445}.issubset(open_ports):
            return {
                'os': 'Windows Server',
                'confidence': 'medium',
                'evidence': [f'Windows port pattern: {sorted({135, 445})}']
            }
        elif 22 in open_ports:
            return {
                'os': 'Linux/Unix',
                'confidence': 'medium',
                'evidence': ['SSH service detected']
            }
        
        return None
    
    def enhanced_service_detection(self, port):
        """Enhanced service detection with banner grabbing"""
        from .port_utils import get_service_description
        
        base_service = get_service_description(port)
        
        if not self.service_detection:
            return base_service
        
        # Try banner grabbing for enhanced detection
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((self.target, port))
            
            # Send HTTP request for web services
            if port in [80, 8080, 8000, 8888]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + self.target.encode() + b"\r\n\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                if 'Server:' in banner:
                    server_line = [line for line in banner.split('\n') if 'Server:' in line][0]
                    return server_line.split('Server:')[1].strip()
            
            # Send basic banner grab for other services
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            if banner.strip():
                # Enhanced SSH banner parsing
                if port == 22 and 'ssh' in banner.lower():
                    if 'ubuntu' in banner.lower():
                        return f"SSH (Ubuntu) - {banner.strip()[:50]}"
                    elif 'debian' in banner.lower():
                        return f"SSH (Debian) - {banner.strip()[:50]}"
                    else:
                        return f"SSH - {banner.strip()[:50]}"
                return f"{base_service} ({banner.strip()[:50]})"
            
            sock.close()
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        
        return base_service
    
    def scan_port(self, port):
        """Scan a single port with enhanced detection"""
        if not self.is_running:
            return None
            
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                service = self.enhanced_service_detection(port)
                return port, service
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        return None
    
    def run(self):
        try:
            self.signals.status.emit(f"Starting enhanced port scan on {self.target}...")
            self.signals.output.emit(f"<p style='color: #00BFFF;'>Enhanced scanning {len(self.ports)} ports on 1 targets...</p><br>")
            
            if self.os_detection:
                self.signals.output.emit(f"<p style='color: #00BFFF;'>OS Detection enabled</p><br>")
            if self.service_detection:
                self.signals.output.emit(f"<p style='color: #00BFFF;'>Service Detection enabled</p><br>")
            

            self.signals.progress_start.emit(len(self.ports))
            
            open_ports = []
            completed = 0
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                future_to_port = {executor.submit(self.scan_port, port): port for port in self.ports}
                
                for future in concurrent.futures.as_completed(future_to_port):
                    if not self.is_running:
                        break
                        
                    result = future.result()
                    completed += 1
                    
                    if result:
                        port, service = result
                        open_ports.append((port, service))
                        self.signals.output.emit(f"<p style='color: #00FF41;'>[+] {h(self.target)}:{port}/tcp open - {h(service)}</p><br>")
                    
                    if completed % 10 == 0:
                        self.signals.progress_update.emit(completed, len(open_ports))
            
            if open_ports:
                port_data = []
                open_port_numbers = []
                
                for port, service in open_ports:
                    # Extract banner from service if it contains banner info
                    banner = ''
                    if ' - ' in service and port == 22:
                        parts = service.split(' - ', 1)
                        if len(parts) > 1:
                            banner = parts[1]
                    
                    port_data.append({
                        'port': port,
                        'service': service,
                        'banner': banner,
                        'protocol': 'tcp',
                        'state': 'open',
                        'confidence': 'high'
                    })
                    open_port_numbers.append(port)
                
                result_data = {'open_ports': port_data}
                
                # Add server type detection
                from .port_utils import detect_server_type
                server_type = detect_server_type(open_port_numbers)
                if server_type and server_type != 'Unknown':
                    result_data['server_type'] = server_type
                    self.signals.output.emit(f"<br><p style='color: #87CEEB;'>[SERVER TYPE] {h(self.target)}: {h(server_type)}</p><br>")
                
                # Add enhanced OS detection if enabled
                if self.os_detection:
                    os_info = self.detect_os_from_ports(port_data, self.target)
                    if os_info:
                        result_data['os_detection'] = os_info
                        self.signals.output.emit(f"<p style='color: #FFD700;'>[OS Detection] {h(self.target)}: {h(os_info['os'])} (Confidence: {h(os_info['confidence'])})</p><br>")
                        
                        # Show detection methods if available
                        if 'detection_methods' in os_info:
                            methods = ', '.join(os_info['detection_methods'])
                            self.signals.output.emit(f"<p style='color: #87CEEB;'>  Detection methods: {h(methods)}</p><br>")
                        
                        # Show evidence
                        for evidence in os_info.get('evidence', []):
                            self.signals.output.emit(f"<p style='color: #FFAA00;'>  • {h(evidence)}</p><br>")
                        
                        # Legacy support for 'reason' field
                        if 'reason' in os_info and 'evidence' not in os_info:
                            self.signals.output.emit(f"<p style='color: #FFAA00;'>• {h(os_info['reason'])}</p><br>")
                
                self.results[self.target] = result_data
                self.signals.results_ready.emit(self.results)
                self.signals.output.emit(f"<br><p style='color: #00FF41;'>Found {len(open_ports)} open ports across 1 hosts</p>")
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>No open ports found</p>")
            
            self.signals.status.emit("Enhanced port scan completed")
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF4500;'>[ERROR] Enhanced port scan failed: {h(str(e))}</p>")
            self.signals.status.emit("Enhanced port scan error")
        finally:
            self.signals.finished.emit()

def get_common_ports():
    """Get list of common ports to scan"""
    return [20,21,22,23,25,53,67,68,80,88,110,111,135,137,138,139,143,161,389,443,445,464,554,631,636,993,995,1433,1521,1723,1900,2181,2222,2375,2376,2525,27017,27018,27019,3000,3268,3269,3306,3389,3544,500,5000,5001,5040,5050,5432,5671,5672,5984,5985,5986,5987,6378,6379,6443,7000,7001,7474,7680,8000,8042,8080,8081,8086,8200,8443,8500,8787,8880,8883,8888,9000,9001,9042,9090,9093,9200,9220,9221,9222,9223,9224,9225,9226,9227,9228,9229,11211,15672]

class Layer2SweepWorker(QRunnable):
    """Layer 2 discovery: ARP (IPv4), NDP (IPv6), NetBIOS, mDNS"""

    def __init__(self, target_cidr, interface=None, timeout=2, tenant_id="default"):
        super().__init__()
        self.signals = PortScannerSignals()
        self.target_cidr = target_cidr
        self.interface = interface
        self.timeout = timeout
        self.tenant_id = tenant_id
        self.is_running = True
        self.results = {"layer2_hosts": []}

    def run(self):
        try:
            self.signals.status.emit(f"Starting Layer 2 sweep on {self.target_cidr}...")
            self.signals.output.emit(f"<p style='color: #00BFFF;'>Sending ARP, NDP, NetBIOS, and mDNS probes...</p><br>")
            self.signals.progress_start.emit(4)  # 4 discovery methods

            # ARP IPv4 sweep
            self.do_arp_sweep()
            self.signals.progress_update.emit(1, len(self.results["layer2_hosts"]))

            # IPv6 NDP sweep
            self.do_ndp_sweep()
            self.signals.progress_update.emit(2, len(self.results["layer2_hosts"]))

            # NetBIOS Name Query
            self.do_netbios_probe()
            self.signals.progress_update.emit(3, len(self.results["layer2_hosts"]))

            # mDNS Query
            self.do_mdns_probe()
            self.signals.progress_update.emit(4, len(self.results["layer2_hosts"]))

            # Final summary
            unique_hosts = len(self.results["layer2_hosts"])
            self.signals.output.emit(f"<br><p style='color: #00FF41;'>Found {h(unique_hosts)} unique devices</p><br>")
            
            # Add to inventory
            try:
                from app.core.asset_manager import asset_manager
                added_count = 0
                for host in self.results["layer2_hosts"]:
                    asset_data = {
                        'ip_address': host['ip'],
                        'mac_address': host.get('mac', ''),
                        'vendor': host.get('vendor', ''),
                        'status': 'DISCOVERED',
                        'confidence': 80,  # High confidence for Layer 2 discovery
                        'metadata': {
                            'discovery_method': 'layer2_sweep',
                            'protocol': host.get('protocol', 'Unknown')
                        }
                    }
                    asset_manager.add_or_update_asset(self.tenant_id, **asset_data)
                    added_count += 1
                
                self.signals.output.emit(f"<p style='color: #87CEEB;'>Updated inventory with {h(added_count)} hosts from Layer 2 sweep</p><br>")
            except Exception as e:
                self.signals.output.emit(f"<p style='color: #FFAA00;'>[WARN] Inventory update failed: {h(e)}</p><br>")
            
            self.signals.results_ready.emit(self.results)
            self.signals.status.emit("Layer 2 sweep completed")

        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF4500;'>[ERROR] Layer 2 sweep failed: {h(str(e))}</p>")
            self.signals.status.emit("Layer 2 sweep error")
        finally:
            self.signals.finished.emit()

    def do_arp_sweep(self):
        """ARP sweep for IPv4 hosts"""
        try:
            from scapy.all import ARP, Ether, srp
            
            # Normalize target - convert 192.168.1.0 to 192.168.1.0/24
            target = self.target_cidr
            if not '/' in target and target.endswith('.0'):
                target = f"{target}/24"
            
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp = ARP(pdst=target)
            answered, _ = srp(ether / arp, timeout=self.timeout, iface=self.interface, verbose=False)

            for _, rcv in answered:
                if not self.is_running:
                    break
                self.add_result(ip=rcv.psrc, mac=rcv.hwsrc, proto="ARP")
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>[WARN] ARP sweep error: {h(e)}</p><br>")

    def do_ndp_sweep(self):
        """IPv6 Neighbor Discovery using all-nodes multicast"""
        try:
            from scapy.all import Ether, IPv6, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr, srp
            import netifaces

            # Use Scapy's interface detection instead
            from scapy.all import get_if_list, get_if_hwaddr
            
            if not self.interface:
                scapy_interfaces = get_if_list()
                # Find first non-loopback interface
                for iface in scapy_interfaces:
                    if 'loopback' not in iface.lower() and 'tunnel' not in iface.lower():
                        self.interface = iface
                        break
            
            if not self.interface:
                return

            # Find our MAC for this interface using Scapy
            try:
                mac_addr = get_if_hwaddr(self.interface)
            except:
                mac_addr = "00:00:00:00:00:00"

            # Build NDP request to ff02::1 (all-nodes multicast)
            ether = Ether(dst="33:33:00:00:00:01")
            ipv6 = IPv6(dst="ff02::1")
            ns = ICMPv6ND_NS(tgt="fe80::1")  # Dummy target, just to provoke responses
            opt = ICMPv6NDOptSrcLLAddr(lladdr=mac_addr)

            packet = ether / ipv6 / ns / opt

            # Send and receive at layer 2
            answered, _ = srp(packet, iface=self.interface, timeout=self.timeout, verbose=False)

            for _, rcv in answered:
                src_mac = rcv[Ether].src
                src_ip = rcv[IPv6].src
                self.add_result(ip=src_ip, mac=src_mac, proto="NDP")

        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>[WARN] NDP sweep error: {h(e)}</p>")

    def do_netbios_probe(self):
        """NetBIOS broadcast probe for Windows hosts"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

            # NetBIOS Name Service query (wildcard "*")
            netbios_packet = b'\x80\xF0\x00\x10' + b'\x00'*4 + b'\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' + b'\x00\x00\x21\x00\x01'
            sock.sendto(netbios_packet, ('255.255.255.255', 137))

            start = time.time()
            while time.time() - start < self.timeout and self.is_running:
                try:
                    data, addr = sock.recvfrom(1024)
                    self.add_result(ip=addr[0], mac=None, proto="NetBIOS")
                except socket.timeout:
                    break
            sock.close()
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>[WARN] NetBIOS probe error: {h(e)}</p><br>")

    def do_mdns_probe(self):
        """mDNS multicast probe for Apple/Linux/IoT devices"""
        try:
            from scapy.all import IP, UDP, DNS, DNSQR, sr1
            
            # Send mDNS query without Ether layer to avoid warnings
            query = IP(dst="224.0.0.251")/UDP(sport=5353,dport=5353)/DNS(rd=0,qd=DNSQR(qname="_services._dns-sd._udp.local", qtype="PTR"))
            ans = sr1(query, timeout=self.timeout, verbose=False)
            
            if ans and ans.haslayer(DNS) and ans[DNS].an and ans.haslayer(IP):
                src_ip = ans[IP].src
                self.add_result(ip=src_ip, mac=None, proto="mDNS")
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>[WARN] mDNS probe error: {h(e)}</p><br>")

    def add_result(self, ip, mac=None, proto="Unknown"):
        """Add discovered host to results (avoid duplicates)"""
        # Check for duplicates
        if any(h['ip'] == ip for h in self.results["layer2_hosts"]):
            return
        
        vendor = self.lookup_vendor(mac) if mac else "Unknown"
        host_info = {
            "ip": ip, 
            "mac": mac or "N/A", 
            "vendor": vendor, 
            "protocol": proto
        }
        
        self.results["layer2_hosts"].append(host_info)
        self.signals.output.emit(
            f"<p style='color: #00FF41;'>[+] {ip} - {mac or 'N/A'} ({vendor}) via {proto}</p><br>"
        )

    def lookup_vendor(self, mac):
        """Lookup MAC vendor"""
        if not mac:
            return "Unknown"
        try:
            from mac_vendor_lookup import MacLookup
            return MacLookup().lookup(mac)
        except:
            return "Unknown Vendor"

def get_top_ports(count=100):
    """Get top N ports - returns full range if count exceeds available ports"""
    top_1000 = [1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37, 42, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110, 111, 113, 119, 125, 135, 139, 143, 144, 146, 161, 163, 179, 199, 211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306, 311, 340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636, 646, 648, 666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992, 993, 995, 999, 1000]
    
    # If requesting more ports than available in top_1000, return full range
    if count > len(top_1000):
        return list(range(1, count + 1))
    
    return top_1000[:count]