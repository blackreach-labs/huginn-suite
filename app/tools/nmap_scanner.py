# app/tools/nmap_scanner.py
import socket
import threading
import concurrent.futures
import ipaddress
import time
import random
from typing import Dict, List, Optional, Tuple

def _scan_tcp_port(target: str, port: int, timeout: float = 3.0) -> bool:
    """Scan a single TCP port using socket connection"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def _get_service_name(port: int, protocol: str = 'tcp') -> str:
    """Get service name for port"""
    try:
        return socket.getservbyport(port, protocol)
    except:
        return 'unknown'

def _get_nmap_path():
    """Get path to nmap executable with fallback to system PATH"""
    import os
    import shutil
    
    # Try bundled version first
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(os.path.dirname(current_dir))
    bundled_path = os.path.join(project_root, "resources", "nmap", "nmap.exe")
    
    if os.path.exists(bundled_path):
        return bundled_path
    
    # Fallback to system PATH
    system_nmap = shutil.which('nmap')
    if system_nmap:
        return system_nmap
    
    raise FileNotFoundError("Nmap not found in bundle or system PATH")

def _validate_target(target: str) -> str:
    """Validate and sanitize target input to prevent command injection"""
    import ipaddress
    import re
    
    target = target.strip()
    
    # Check for command injection attempts
    dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '\n', '\r']
    if any(char in target for char in dangerous_chars):
        raise ValueError(f"Invalid characters detected in target: {target}")
    
    # Validate IP address
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError as _exc:
        pass
        logger.debug("Suppressed exception", exc_info=True)
    
    # Validate CIDR notation
    try:
        ipaddress.ip_network(target, strict=False)
        return target
    except ValueError as _exc:
        pass
        logger.debug("Suppressed exception", exc_info=True)
    
    # Validate IP range (e.g., 192.168.1.1-254, 192.168.1-5)
    if '-' in target:
        parts = target.split('-')
        if len(parts) == 2:
            try:
                start_part = parts[0].strip()
                end_part = parts[1].strip()
                
                # Check if start is a complete IP
                try:
                    ipaddress.ip_address(start_part)
                    if '.' not in end_part:
                        # Range like 192.168.1.1-254
                        end_octet = int(end_part)
                        if 0 <= end_octet <= 255:
                            return target
                    else:
                        # Range like 192.168.1.1-192.168.1.254
                        ipaddress.ip_address(end_part)
                        return target
                except ValueError:
                    # Check for partial IP range like 192.168.1-5
                    if start_part.count('.') == 2 and end_part.isdigit():
                        # Construct full start IP by adding .1
                        test_start = start_part + '.1'
                        ipaddress.ip_address(test_start)
                        end_octet = int(end_part)
                        if 0 <= end_octet <= 255:
                            return target
            except (ValueError, ipaddress.AddressValueError) as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
    
    # Validate network range like 192.168.1.0 (treat as 192.168.1.1-254)
    if target.endswith('.0'):
        try:
            base_ip = target[:-1] + '1'
            ipaddress.ip_address(base_ip)
            return target
        except ValueError as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
    
    # Validate hostname (basic check)
    hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    if re.match(hostname_pattern, target) and len(target) <= 253:
        return target
    
    raise ValueError(f"Invalid target format: {target}")

def _get_stealth_flags(stealth_mode=False, decoy_ips=None):
    """Get stealth and evasion flags for nmap commands"""
    flags = []
    if stealth_mode:
        flags.extend(["-f", "-T2"])  # Fragment packets, slower timing
        if decoy_ips:
            flags.extend(["-D", decoy_ips])
    return flags

from PyQt6.QtCore import QObject, pyqtSignal, QRunnable
from app.core.html_utils import h
from app.core.logger import logger

class NetworkSweepSignals(QObject):
    output = pyqtSignal(str)
    status = pyqtSignal(str)
    progress = pyqtSignal(str)
    progress_start = pyqtSignal(int, str)
    progress_update = pyqtSignal(int, int)
    finished = pyqtSignal()

class TargetedScanSignals(QObject):
    output = pyqtSignal(str)
    progress_start = pyqtSignal(int, str)
    progress_update = pyqtSignal(int, int)
    finished = pyqtSignal()
    results = pyqtSignal(dict)

class TargetedScanWorker(QRunnable):
    def __init__(self, target, scan_type, ports):
        super().__init__()
        self.target = target
        self.scan_type = scan_type
        self.ports = ports
        self.signals = TargetedScanSignals()
        self.is_running = True
    
    def run(self):
        try:
            self.signals.progress_start.emit(100, f"Running {self.scan_type}...")
            self.signals.output.emit(f"<p style='color: #87CEEB;'>Starting {h(self.scan_type)} on {h(self.target)}...</p><br>")
            
            # Update progress
            self.signals.progress_update.emit(50, 0)
            
            # Run the scan
            result = scan_targeted(self.target, self.scan_type, self.ports)
            
            if result['success']:
                self.signals.output.emit(f"<pre style='color: #DCDCDC;'>{h(result['output'])}</pre>")
                
                # Parse results for table view using standalone function
                parsed_results = self._parse_nmap_output(result['output'], self.target)
                if parsed_results:
                    self.signals.results.emit(parsed_results)
                    
                    # Update inventory with scan results
                    try:
                        from app.core.inventory_integration import update_inventory_from_enhanced_scan
                        update_inventory_from_enhanced_scan(parsed_results, True, True)
                    except Exception as e:
                        print(f"Error updating inventory from targeted scan: {e}")
                
                self.signals.progress_update.emit(100, 1)
            else:
                self.signals.output.emit(f"<p style='color: #FF4500;'>{h(self.scan_type)} failed: {h(result.get('error', 'Unknown error'))}</p>")
                self.signals.progress_update.emit(100, 0)
                
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF4500;'>Error: {h(str(e))}</p>")
        finally:
            self.signals.finished.emit()
    
    def _parse_nmap_output(self, nmap_output, target):
        """Parse nmap output to extract port information, service versions, OS details, and host scripts"""
        import re
        
        open_ports = []
        os_details = []
        host_scripts = []
        lines = nmap_output.split('\n')
        in_host_scripts = False
        
        for line in lines:
            # Match port lines with service versions
            port_match = re.match(r'(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)(?:\s+(.*))?', line.strip())
            if port_match:
                port = port_match.group(1)
                protocol = port_match.group(2)
                state = port_match.group(3)
                service = port_match.group(4) if port_match.group(4) else 'unknown'
                version = port_match.group(5).strip() if port_match.group(5) else ''
                
                if state == 'open':
                    open_ports.append({
                        'port': int(port),
                        'protocol': protocol,
                        'service': service,
                        'version': version,
                        'state': state,
                        'banner': ''
                    })
            
            # Extract OS information
            elif 'Running:' in line:
                os_info = line.replace('Running:', '').strip()
                if os_info:
                    os_details.append({'type': 'Running', 'value': os_info})
            elif 'OS details:' in line:
                os_info = line.replace('OS details:', '').strip()
                if os_info:
                    os_details.append({'type': 'OS Details', 'value': os_info})
            elif 'Aggressive OS guesses:' in line:
                os_info = line.replace('Aggressive OS guesses:', '').strip()
                if os_info:
                    guesses = [g.strip() for g in os_info.split(',')[:3]]
                    for guess in guesses:
                        if guess:
                            os_details.append({'type': 'OS Guess', 'value': guess})
            elif 'Device type:' in line:
                device_info = line.replace('Device type:', '').strip()
                if device_info:
                    os_details.append({'type': 'Device Type', 'value': device_info})
            
            # Extract host script results
            elif 'Host script results:' in line:
                in_host_scripts = True
            elif in_host_scripts and line.strip():
                if line.startswith('|'):
                    script_line = line.strip()
                    if 'NetBIOS name:' in script_line:
                        match = re.search(r'NetBIOS name: ([^,]+)', script_line)
                        if match:
                            host_scripts.append({'type': 'NetBIOS Name', 'value': match.group(1).strip()})
                    elif 'NetBIOS user:' in script_line:
                        match = re.search(r'NetBIOS user: ([^,]+)', script_line)
                        if match:
                            host_scripts.append({'type': 'NetBIOS User', 'value': match.group(1).strip()})
                    elif 'NetBIOS MAC:' in script_line:
                        match = re.search(r'NetBIOS MAC: ([^,\)]+)', script_line)
                        if match:
                            host_scripts.append({'type': 'NetBIOS MAC', 'value': match.group(1).strip()})
                    elif 'Computer name:' in script_line:
                        match = re.search(r'Computer name: ([^\\x]+)', script_line)
                        if match:
                            host_scripts.append({'type': 'Computer Name', 'value': match.group(1).strip()})
                    elif 'Workgroup:' in script_line:
                        match = re.search(r'Workgroup: ([^\\x]+)', script_line)
                        if match:
                            host_scripts.append({'type': 'Workgroup', 'value': match.group(1).strip()})
                    elif 'OS:' in script_line and 'smb-os-discovery' in script_line:
                        match = re.search(r'OS: ([^\)]+)', script_line)
                        if match:
                            host_scripts.append({'type': 'SMB OS', 'value': match.group(1).strip()})
                elif not line.startswith(' ') and not line.startswith('\t'):
                    in_host_scripts = False
        
        result = {target: {}}
        if open_ports:
            result[target]['open_ports'] = open_ports
        if os_details:
            result[target]['os_details'] = os_details
        if host_scripts:
            result[target]['host_scripts'] = host_scripts
        
        return result if (open_ports or os_details or host_scripts) else None

class NetworkSweepWorker(QRunnable):
    def __init__(self, target, stealth_mode=False, decoy_ips=None, timing='T3', parallelism=100):
        super().__init__()
        try:
            self.target = _validate_target(target)
        except ValueError as e:
            raise ValueError(f"Invalid target: {e}")
        
        self.stealth_mode = stealth_mode
        self.decoy_ips = decoy_ips
        self.timing = timing
        self.parallelism = parallelism
        self.signals = NetworkSweepSignals()
        self.is_running = True
    
    def run(self):
        try:
            import subprocess
            import os
            import re
            import ipaddress
            
            alive_hosts = []
            
            # Handle different target formats
            targets = []
            
            # Start progress widget
            self.signals.progress_start.emit(1, "Nmap sweep...")
            if self.target.endswith('.0'):
                # Convert 192.168.1.0 to 192.168.1.1-254
                base = self.target[:-1]
                targets = [f"{base}{i}" for i in range(1, 255)]
                self.signals.output.emit(f"<p style='color: #87CEEB;'>Scanning subnet {h(self.target)} (192.168.1.1-254)...</p><br>")
            elif '-' in self.target:
                # Handle ranges like 192.168.1.100-106 or 119.82.2.1-254
                parts = self.target.split('-')
                if len(parts) == 2:
                    start_ip = parts[0].strip()
                    end_part = parts[1].strip()
                    
                    # Extract base IP and range
                    ip_parts = start_ip.split('.')
                    if len(ip_parts) == 4:
                        base = '.'.join(ip_parts[:3]) + '.'
                        start_octet = int(ip_parts[3])
                        end_octet = int(end_part)
                        targets = [f"{base}{i}" for i in range(start_octet, end_octet + 1)]
                        self.signals.output.emit(f"<p style='color: #87CEEB;'>Scanning range {h(start_ip)}-{h(base)}{h(end_octet)} ({len(targets)} hosts)...</p><br>")
            else:
                targets = [self.target]
                self.signals.output.emit(f"<p style='color: #87CEEB;'>Trying ping scan for {h(self.target)}...</p><br>")
            
            # Try ping first for each target with progress tracking
            total_targets = len(targets)
            self.signals.progress_start.emit(total_targets, "Ping sweep...")
            
            for i, target in enumerate(targets):
                if not self.is_running:
                    break
                try:
                    ping_cmd = ["ping", "-n", "1", "-w", "1000", target]
                    ping_result = subprocess.run(ping_cmd, capture_output=True, text=True, timeout=2)
                    if ping_result.returncode == 0 and "Reply from" in ping_result.stdout:
                        alive_hosts.append(target)
                        self.signals.output.emit(f"<p style='color: #00FF41;'>Host {h(target)} is up (ping)</p><br>")
                except Exception as _exc:
                    pass
                    logger.debug("Suppressed exception", exc_info=True)
                
                # Emit progress every 5 hosts or on the last one
                if (i + 1) % 5 == 0 or i == total_targets - 1:
                    self.signals.progress_update.emit(i + 1, len(alive_hosts))
                    
                    # Update scan registry progress
                    try:
                        from app.core.scan_registry import scan_registry
                        for scan_id, scan_info in scan_registry.get_all_scans().items():
                            if scan_info.target == self.target and scan_info.scan_type == "Port Scan":
                                scan_registry.update_scan_progress(scan_id, i + 1)
                                break
                    except Exception as _exc:
                        pass
                        logger.debug("Suppressed exception", exc_info=True)
            
            # If ping didn't find hosts, try nmap as fallback
            if not alive_hosts:
                self.signals.output.emit(f"<p style='color: #87CEEB;'>Ping scan complete. Trying nmap scan...</p><br>")
                try:
                    nmap_path = _get_nmap_path()
                except FileNotFoundError as e:
                    self.signals.output.emit(f"<p style='color: #FF4500;'>Error: {h(str(e))}</p>")
                    self.signals.finished.emit()
                    return
                
                # Extract timing value (T0(slow) -> T0)
                timing_value = self.timing.split('(')[0] if '(' in self.timing else self.timing
                
                cmd = [nmap_path, "-sn", f"-{timing_value}", "--min-parallelism", str(self.parallelism), "--max-parallelism", str(self.parallelism), "-v"]
                
                stealth_flags = _get_stealth_flags(self.stealth_mode, self.decoy_ips)
                if stealth_flags:
                    cmd.extend(stealth_flags)
                    cmd.append("--disable-arp-ping")
                
                # Convert range format for nmap
                if '-' in self.target and '.' in self.target:
                    parts = self.target.split('-')
                    if len(parts) == 2:
                        start_ip = parts[0].strip()
                        end_part = parts[1].strip()
                        ip_parts = start_ip.split('.')
                        if len(ip_parts) == 4 and end_part.isdigit():
                            # Convert 119.82.2.1-254 to 119.82.2.1-119.82.2.254
                            base = '.'.join(ip_parts[:3]) + '.'
                            nmap_target = f"{start_ip}-{base}{end_part}"
                            cmd.append(nmap_target)
                        else:
                            cmd.append(self.target)
                    else:
                        cmd.append(self.target)
                else:
                    cmd.append(self.target)
                
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, universal_newlines=True)
                
                output_buffer = []
                progress_count = 0
                self.signals.progress_start.emit(100, "Nmap sweep...")

                while True:
                    if not self.is_running:
                        process.terminate()
                        break
                        
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                        
                    if output:
                        line = output.strip()
                        output_buffer.append(line)

                        if any(keyword in line for keyword in ["Starting", "Completed", "done"]) and "Host" not in line:
                            self.signals.output.emit(f"<p style='color: #87CEEB;'>{h(line)}</p><br>")
                            # Update progress for nmap status lines
                            if "Completed" in line:
                                progress_count += 10
                                # Extract target info from nmap output for status
                                if "Ping Scan" in line:
                                    status_msg = f"Nmap ping scan: {self.target}"
                                elif "Parallel DNS" in line:
                                    status_msg = f"DNS resolution: {self.target}"
                                else:
                                    status_msg = f"Nmap scanning: {self.target}"
                                self.signals.progress_update.emit(min(progress_count, 90), len(alive_hosts))
                                
                                # Update scan registry progress
                                try:
                                    from app.core.scan_registry import scan_registry
                                    for scan_id, scan_info in scan_registry.get_all_scans().items():
                                        if scan_info.target == self.target and scan_info.scan_type == "Port Scan":
                                            scan_registry.update_scan_progress(scan_id, min(progress_count, 90))
                                            break
                                except Exception as _exc:
                                    pass
                                    logger.debug("Suppressed exception", exc_info=True)

                # Parse nmap results
                for i, line in enumerate(output_buffer):
                    if "Nmap scan report for" in line:
                        if (i + 1) < len(output_buffer) and "Host is up" in output_buffer[i+1]:
                            host_match = re.search(r'Nmap scan report for ([\w\.\-]+)', line)
                            if host_match:
                                host_ip = host_match.group(1)
                                if host_ip not in alive_hosts:
                                    alive_hosts.append(host_ip)
                                    self.signals.output.emit(f"<p style='color: #00FF41;'>Host {h(host_ip)} is up (nmap)</p><br>")
                                    self.signals.progress_update.emit(len(alive_hosts), len(alive_hosts))

                _, stderr = process.communicate()
                if stderr:
                    self.signals.output.emit(f"<p style='color: #FFAA00;'>Warnings: {h(stderr)}</p><br>")

            # Update inventory with discovered hosts
            if alive_hosts:
                results = {}
                for host in alive_hosts:
                    results[host] = {'status': 'up'}
                
                try:
                    from app.core.inventory_integration import update_inventory_from_ping_sweep
                    update_inventory_from_ping_sweep(results)
                except Exception as e:
                    print(f"Error updating inventory from network sweep: {e}")
            
            # Final summary
            host_count = len(alive_hosts)
            self.signals.output.emit(f"<p style='color: #00FF41;'>Network sweep completed. Found {h(host_count)} alive host(s).</p><br>")
            self.signals.status.emit(f"Network sweep completed: {host_count} hosts found")
            self.signals.progress_update.emit(100, host_count)
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF4500;'>Unexpected error: {h(str(e))}</p>")
        finally:
            self.signals.finished.emit()
            
def scan_network_sweep(target: str) -> Dict:
    """Network sweep using nmap with input validation"""
    try:
        import subprocess
        
        # Validate target input
        validated_target = _validate_target(target)
        nmap_path = _get_nmap_path()
        
        cmd = [nmap_path, "-sn", validated_target]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        return {
            "scan_type": "network_sweep",
            "target": target,
            "success": result.returncode == 0,
            "output": result.stdout,
            "error": result.stderr if result.returncode != 0 else ""
        }
        
    except ValueError as e:
        return {
            "scan_type": "network_sweep",
            "target": target,
            "success": False,
            "output": "",
            "error": f"Invalid target: {str(e)}"
        }
    except FileNotFoundError as e:
        return {
            "scan_type": "network_sweep",
            "target": target,
            "success": False,
            "output": "",
            "error": str(e)
        }
    except subprocess.TimeoutExpired:
        return {
            "scan_type": "network_sweep",
            "target": target,
            "success": False,
            "output": "",
            "error": "Scan timed out after 5 minutes"
        }
    except PermissionError:
        return {
            "scan_type": "network_sweep",
            "target": target,
            "success": False,
            "output": "",
            "error": "Permission denied. Administrator privileges may be required."
        }
    except Exception as e:
        return {
            "scan_type": "network_sweep",
            "target": target,
            "success": False,
            "output": "",
            "error": f"Unexpected error: {str(e)}"
        }

def scan_syn(target: str, full: bool = True, stealth_mode: bool = False, decoy_ips: str = None) -> Dict:
    """SYN stealth scan using nmap with input validation"""
    try:
        import subprocess
        
        # Validate target input
        validated_target = _validate_target(target)
        nmap_path = _get_nmap_path()
        
        ports = "-p-" if full else "--top-ports 1000" if stealth_mode else "-p1-1000"
        
        cmd = [nmap_path, "-sS"]
        if not stealth_mode:
            cmd.append("-T4")
        cmd.extend([ports, "-v"])
        
        # Add stealth flags
        stealth_flags = _get_stealth_flags(stealth_mode, decoy_ips)
        if stealth_flags:
            cmd.extend(stealth_flags)
        
        cmd.append(validated_target)
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
        # Replace specific ethernet device error with VPN-friendly message
        error_msg = result.stderr if result.returncode != 0 else ""
        if "Only ethernet devices can be used for raw scans on Windows" in error_msg:
            error_msg = "Only ethernet devices can be used for raw scans on Windows and will not work over VPN connections. QUITTING!"
        
        return {
            "scan_type": "syn_stealth",
            "target": target,
            "full_scan": full,
            "success": result.returncode == 0,
            "output": result.stdout,
            "error": error_msg
        }
    except ValueError as e:
        return {
            "scan_type": "syn_stealth",
            "target": target,
            "full_scan": full,
            "success": False,
            "output": "",
            "error": f"Invalid target: {str(e)}"
        }
    except FileNotFoundError as e:
        return {
            "scan_type": "syn_stealth",
            "target": target,
            "full_scan": full,
            "success": False,
            "output": "",
            "error": str(e)
        }
    except subprocess.TimeoutExpired:
        return {
            "scan_type": "syn_stealth",
            "target": target,
            "full_scan": full,
            "success": False,
            "output": "",
            "error": "Scan timed out after 10 minutes"
        }
    except PermissionError:
        return {
            "scan_type": "syn_stealth",
            "target": target,
            "full_scan": full,
            "success": False,
            "output": "",
            "error": "Permission denied. SYN scan requires administrator privileges."
        }
    except Exception as e:
        return {
            "scan_type": "syn_stealth",
            "target": target,
            "full_scan": full,
            "success": False,
            "output": "",
            "error": f"Unexpected error: {str(e)}"
        }

def scan_tcp_connect(target: str, ports: str = "22,80,443") -> Dict:
    """TCP connect scan using bundled nmap"""
    try:
        import subprocess
        
        nmap_path = _get_nmap_path()
        cmd = [nmap_path, "-sT", "-p", ports, target]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        return {
            "scan_type": "tcp_connect",
            "target": target,
            "ports": ports,
            "success": result.returncode == 0,
            "output": result.stdout,
            "error": result.stderr if result.returncode != 0 else ""
        }
    except Exception as e:
        return {
            "scan_type": "tcp_connect",
            "target": target,
            "ports": ports,
            "success": False,
            "output": "",
            "error": str(e)
        }

def scan_service_detection(target: str, ports: str = "22,80,443") -> Dict:
    """Service version detection with banner grabbing"""
    try:
        port_list = []
        for part in ports.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                port_list.extend(range(start, end + 1))
            else:
                port_list.append(int(part.strip()))
        
        open_ports = []
        output_lines = [f"Starting Nmap service detection for {target}"]
        
        def grab_banner(port):
            if not _scan_tcp_port(target, port):
                return None
            
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((target, port))
                
                if port in [80, 8080, 8000, 8888]:
                    sock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
                
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                sock.close()
                
                service = _get_service_name(port)
                return {'port': port, 'service': service, 'banner': banner[:100]}
            except:
                service = _get_service_name(port)
                return {'port': port, 'service': service, 'banner': ''}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_port = {executor.submit(grab_banner, port): port for port in port_list}
            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                if result:
                    open_ports.append(result)
                    banner_info = f" ({result['banner'][:50]}...)" if result['banner'] else ""
                    output_lines.append(f"{result['port']}/tcp open {result['service']}{banner_info}")
        
        output_lines.append(f"Service detection completed. {len(open_ports)} open ports")
        
        return {
            "scan_type": "service_detection",
            "target": target,
            "ports": ports,
            "success": True,
            "output": '\n'.join(output_lines),
            "error": ""
        }
    except Exception as e:
        return {
            "scan_type": "service_detection",
            "target": target,
            "ports": ports,
            "success": False,
            "output": "",
            "error": str(e)
        }

def scan_os_detection(target: str) -> Dict:
    """OS detection using nmap's superior fingerprinting engine"""
    try:
        import subprocess
        
        nmap_path = _get_nmap_path()
        cmd = [nmap_path, "-O", "--osscan-guess", "--max-os-tries", "2", target]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        return {
            "scan_type": "os_detection",
            "target": target,
            "success": result.returncode == 0,
            "output": result.stdout,
            "error": result.stderr if result.returncode != 0 else ""
        }
    except Exception as e:
        return {
            "scan_type": "os_detection",
            "target": target,
            "success": False,
            "output": "",
            "error": str(e)
        }

def scan_udp(target: str, ports_list=None) -> Dict:
    """UDP port scan"""
    try:
        if ports_list is None:
            # Default top UDP ports
            top_udp_ports = [53, 67, 68, 69, 123, 135, 137, 138, 139, 161, 162, 445, 500, 514, 520, 631, 1434, 1900, 4500, 5353]
            ports_to_scan = top_udp_ports[:100]
        elif isinstance(ports_list, list):
            ports_to_scan = ports_list
        else:
            # If it's a number, use top N ports
            top_udp_ports = [53, 67, 68, 69, 123, 135, 137, 138, 139, 161, 162, 445, 500, 514, 520, 631, 1434, 1900, 4500, 5353]
            ports_to_scan = top_udp_ports[:min(ports_list, len(top_udp_ports))]
        
        open_ports = []
        output_lines = [f"Starting Nmap UDP scan for {target}"]
        
        def scan_udp_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(1)
                
                # Send appropriate probe based on port
                if port == 53:  # DNS
                    probe = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
                elif port == 161:  # SNMP
                    probe = b'\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00'
                elif port == 123:  # NTP
                    probe = b'\x1b' + b'\x00' * 47
                else:
                    probe = b'\x00'
                
                sock.sendto(probe, (target, port))
                try:
                    data, addr = sock.recvfrom(1024)
                    sock.close()
                    return port  # Got response, port is open
                except socket.timeout:
                    sock.close()
                    return None  # No response, likely closed/filtered
                except Exception:
                    sock.close()
                    return None
            except Exception:
                return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_port = {executor.submit(scan_udp_port, port): port for port in ports_to_scan}
            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                if result:
                    service = _get_service_name(result, 'udp')
                    open_ports.append({'port': result, 'service': service})
                    output_lines.append(f"{result}/udp open|filtered {service}")
        
        output_lines.append(f"UDP scan completed. {len(open_ports)} open ports")
        
        return {
            "scan_type": "udp_scan",
            "target": target,
            "ports_scanned": len(ports_to_scan),
            "success": True,
            "output": '\n'.join(output_lines),
            "error": ""
        }
    except Exception as e:
        return {
            "scan_type": "udp_scan",
            "target": target,
            "ports_scanned": 0,
            "success": False,
            "output": "",
            "error": str(e)
        }

def scan_aggressive(target: str) -> Dict:
    """Aggressive scan combining multiple techniques"""
    try:
        output_lines = [f"Starting Nmap aggressive scan for {target}"]
        
        # 1. Port scan (top 1000 ports)
        tcp_result = scan_tcp_connect(target, "1-1000")
        if tcp_result['success']:
            output_lines.append("=== TCP SCAN RESULTS ===")
            output_lines.extend(tcp_result['output'].split('\n')[1:])
        
        # 2. Service detection on open ports
        service_result = scan_service_detection(target, "22,80,443,3389,21,25,53,110,135,139,143,993,995")
        if service_result['success']:
            output_lines.append("\n=== SERVICE DETECTION ===")
            output_lines.extend(service_result['output'].split('\n')[1:])
        
        # 3. OS detection
        os_result = scan_os_detection(target)
        if os_result['success']:
            output_lines.append("\n=== OS DETECTION ===")
            output_lines.extend(os_result['output'].split('\n')[1:])
        
        output_lines.append("\nAggressive scan completed")
        
        return {
            "scan_type": "aggressive",
            "target": target,
            "success": True,
            "output": '\n'.join(output_lines),
            "error": ""
        }
    except Exception as e:
        return {
            "scan_type": "aggressive",
            "target": target,
            "success": False,
            "output": "",
            "error": str(e)
        }



def scan_targeted(target: str, scan_type: str, ports: str = "80,443") -> Dict:
    """Execute targeted scan based on scan type"""
    try:
        import subprocess
        
        validated_target = _validate_target(target)
        nmap_path = _get_nmap_path()
        
        if scan_type == "SYN stealth scan":
            cmd = [nmap_path, "-sS", "-n", "-Pn", "--min-rate", "1000", "--max-retries", "2", "--max-scan-delay", "100ms", "-p", ports, validated_target]
        elif scan_type == "TCP connect scan":
            cmd = [nmap_path, "-sT", "-n", "-Pn", "--min-rate", "500", "--max-retries", "2", "-p", ports, validated_target]
        elif scan_type == "UDP scan":
            cmd = [nmap_path, "-sU", "-n", "-Pn", "--reason", "--max-retries", "1", "--min-rate", "500", "--max-scan-delay", "200ms", "-p", ports, validated_target]
        elif scan_type == "UDP with TCP SYN scan":
            cmd = [nmap_path, "-sU", "-sS", "-sV", "-n", "-Pn", "--min-rate", "750", "--max-retries", "2", "--version-intensity", "5", "-p", ports, validated_target]
        elif scan_type == "OS detection":
            cmd = [nmap_path, "-O", "--osscan-guess", "--max-os-tries", "3", "--script", "smb-os-discovery", "-Pn", "-p", ports, validated_target]
        elif scan_type == "Service identification":
            cmd = [nmap_path, "-sV", "-A", "-Pn", "-n", "--version-intensity", "5", "-p", ports, validated_target]
        else:
            cmd = [nmap_path, "-sT", "-n", "-p", ports, validated_target]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
        # Replace specific ethernet device error with VPN-friendly message
        error_msg = result.stderr if result.returncode != 0 else ""
        if "Only ethernet devices can be used for raw scans on Windows" in error_msg:
            error_msg = "Only ethernet devices can be used for raw scans on Windows and will not work over VPN connections. QUITTING!"
        
        return {
            "scan_type": "targeted_scan",
            "target_scan_type": scan_type,
            "target": target,
            "ports": ports if "OS detection" not in scan_type else "N/A",
            "success": result.returncode == 0,
            "output": result.stdout,
            "error": error_msg
        }
        
    except ValueError as e:
        return {
            "scan_type": "targeted_scan",
            "target_scan_type": scan_type,
            "target": target,
            "ports": ports,
            "success": False,
            "output": "",
            "error": f"Invalid target: {str(e)}"
        }
    except FileNotFoundError as e:
        return {
            "scan_type": "targeted_scan",
            "target_scan_type": scan_type,
            "target": target,
            "ports": ports,
            "success": False,
            "output": "",
            "error": str(e)
        }
    except subprocess.TimeoutExpired:
        return {
            "scan_type": "targeted_scan",
            "target_scan_type": scan_type,
            "target": target,
            "ports": ports,
            "success": False,
            "output": "",
            "error": "Scan timed out after 10 minutes"
        }
    except Exception as e:
        return {
            "scan_type": "targeted_scan",
            "target_scan_type": scan_type,
            "target": target,
            "ports": ports,
            "success": False,
            "output": "",
            "error": f"Unexpected error: {str(e)}"
        }

def run_full_scan(target: str, run_udp: bool = True, run_aggressive: bool = False) -> Dict:
    """Execute full scan workflow in logical order"""
    results = {
        "target": target,
        "scan_sequence": [],
        "all_success": True
    }
    
    # 1. Network sweep
    sweep_result = scan_network_sweep(target)
    results["scan_sequence"].append(sweep_result)
    if not sweep_result["success"]:
        results["all_success"] = False
    
    # 2. SYN stealth scan
    syn_result = scan_syn(target, full=True)
    results["scan_sequence"].append(syn_result)
    if not syn_result["success"]:
        results["all_success"] = False
    
    # 3. Service detection on common ports
    service_result = scan_service_detection(target, "20,21,22,23,25,53,67,68,80,88,110,111,123,135,137,138,139,143,161,443,445,993,995,1433,1521,1723,1900,3306,3389,3544,5353,5432,5900,5984,6379,7474,8000,8080,8086,8888,9042,9200,11211,27017")
    results["scan_sequence"].append(service_result)
    if not service_result["success"]:
        results["all_success"] = False
    
    # 4. OS detection
    os_result = scan_os_detection(target)
    results["scan_sequence"].append(os_result)
    if not os_result["success"]:
        results["all_success"] = False
    
    # 5. UDP scan (optional)
    if run_udp:
        udp_result = scan_udp(target, 100)
        results["scan_sequence"].append(udp_result)
        if not udp_result["success"]:
            results["all_success"] = False
    
    # 6. Aggressive scan (optional, final step)
    if run_aggressive:
        aggressive_result = scan_aggressive(target)
        results["scan_sequence"].append(aggressive_result)
        if not aggressive_result["success"]:
            results["all_success"] = False
    
    return results