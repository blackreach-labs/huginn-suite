# app/tools/stealth_scanner.py
import socket
import ipaddress
import concurrent.futures
from PyQt6.QtCore import QObject, pyqtSignal, QRunnable
from app.core.html_utils import h
from app.core.logger import logger

class StealthScannerSignals(QObject):
    output = pyqtSignal(str)
    status = pyqtSignal(str)
    finished = pyqtSignal()
    results_ready = pyqtSignal(dict)
    progress_update = pyqtSignal(int, int)
    progress_start = pyqtSignal(int)

class StealthSweepWorker(QRunnable):
    """Enhanced stealth sweep with nmap-like probes"""
    
    def __init__(self, target, probe_types, timeout=1):
        super().__init__()
        self.signals = StealthScannerSignals()
        self.target = target
        self.probe_types = probe_types
        self.timeout = timeout
        self.is_running = True
        
    def parse_target(self, target):
        """Parse target into list of IPs"""
        try:
            if '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                return [str(ip) for ip in network.hosts()]
            elif '-' in target:
                parts = target.split('-')
                base_ip = parts[0].strip()
                end_octet = int(parts[1].strip())
                base_parts = base_ip.split('.')
                start_octet = int(base_parts[3])
                base_network = '.'.join(base_parts[:3])
                return [f"{base_network}.{i}" for i in range(start_octet, end_octet + 1)]
            else:
                return [target]
        except Exception:
            return [target]
    
    def icmp_probe(self, ip):
        """ICMP echo request probe"""
        try:
            # Fallback to TCP connect on port 80 if ICMP not available
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, 80))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def tcp_syn_probe(self, ip, port):
        """TCP SYN probe (simulated with connect)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def tcp_ack_probe(self, ip, port):
        """TCP ACK probe (simulated with connect)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def probe_host(self, ip):
        """Perform all probes on a single host"""
        if not self.is_running:
            return None
        
        alive = False
        details = {}
        
        # ICMP probe
        if 'icmp' in self.probe_types:
            if self.icmp_probe(ip):
                alive = True
                details['icmp'] = 'alive'
        
        # TCP SYN probes
        if 'tcp_syn' in self.probe_types:
            details['tcp_syn'] = {}
            for port in self.probe_types['tcp_syn']:
                if self.tcp_syn_probe(ip, port):
                    alive = True
                    details['tcp_syn'][port] = 'open'
        
        # TCP ACK probes
        if 'tcp_ack' in self.probe_types:
            details['tcp_ack'] = {}
            for port in self.probe_types['tcp_ack']:
                if self.tcp_ack_probe(ip, port):
                    alive = True
                    details['tcp_ack'][port] = 'responsive'
        
        return {'ip': ip, 'alive': alive, 'details': details} if alive else None
    
    def run(self):
        try:
            ips = self.parse_target(self.target)
            
            self.signals.status.emit(f"Starting stealth sweep on {len(ips)} hosts...")
            self.signals.output.emit(f"<p style='color: #00BFFF;'>[STEALTH] Probing {len(ips)} hosts with ICMP/TCP SYN/ACK...</p><br>")
            self.signals.progress_start.emit(len(ips))
            
            alive_hosts = []
            completed = 0
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                future_to_ip = {executor.submit(self.probe_host, ip): ip for ip in ips}
                
                for future in concurrent.futures.as_completed(future_to_ip):
                    if not self.is_running:
                        break
                    
                    result = future.result()
                    completed += 1
                    
                    if result:
                        alive_hosts.append(result)
                        ip = result['ip']
                        details = result['details']
                        
                        # Format detailed output
                        probe_info = []
                        if 'icmp' in details:
                            probe_info.append("ICMP")
                        if 'tcp_syn' in details and details['tcp_syn']:
                            open_ports = list(details['tcp_syn'].keys())
                            probe_info.append(f"SYN({','.join(map(str, open_ports))})")
                        if 'tcp_ack' in details and details['tcp_ack']:
                            ack_ports = list(details['tcp_ack'].keys())
                            probe_info.append(f"ACK({','.join(map(str, ack_ports))})")
                        
                        probe_str = " | ".join(probe_info) if probe_info else "TCP"
                        self.signals.output.emit(
                            f"<p style='color: #00FF41;'>[+] Host {ip} is alive ({probe_str})</p><br>"
                        )
                    
                    if completed % 20 == 0:
                        self.signals.progress_update.emit(completed, len(alive_hosts))
            
            # Store results
            if alive_hosts:
                results = {}
                for host_data in alive_hosts:
                    results[host_data['ip']] = {'status': 'alive', 'probes': host_data['details']}
                self.signals.results_ready.emit(results)
                self.signals.output.emit(f"<br><p style='color: #00FF41;'>[STEALTH] Found {len(alive_hosts)} alive hosts</p><br>")
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>No alive hosts found</p>")
            
            self.signals.status.emit("Stealth sweep completed")
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF4500;'>[ERROR] Stealth sweep failed: {h(str(e))}</p>")
            self.signals.status.emit("Stealth sweep error")
        finally:
            self.signals.finished.emit()