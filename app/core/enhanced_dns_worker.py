# app/core/enhanced_dns_worker.py
import time
from PyQt6.QtCore import QObject, pyqtSignal, QRunnable
from app.core.scan_registry import scan_registry
from app.core.scan_controller import ScanController
from app.tools.dns_scanner import run_dns_scan

class EnhancedDNSWorker(QRunnable):
    """Enhanced DNS worker with scan registry integration"""
    
    def __init__(self, target, wordlist_path=None, record_types=None, dns_server=None):
        super().__init__()
        self.target = target
        self.wordlist_path = wordlist_path
        self.record_types = record_types or ['A']
        self.dns_server = dns_server
        self.signals = DNSWorkerSignals()
        
        # Create scan controller
        self.controller = ScanController()
        
        # Register scan
        self.scan_id = scan_registry.register_scan(
            "DNS Enumeration", 
            target, 
            total_items=self.get_wordlist_size(),
            controller=self.controller
        )
        
    def get_wordlist_size(self):
        """Get total number of items to scan"""
        if not self.wordlist_path:
            return 5  # Default subdomains
        
        try:
            with open(self.wordlist_path, 'r') as f:
                return len([line for line in f if line.strip()])
        except:
            return 5
    
    def run(self):
        """Execute DNS enumeration with progress tracking"""
        try:
            self.controller.start()
            self.signals.started.emit(self.scan_id)
            
            # Read wordlist
            subdomains = []
            if self.wordlist_path:
                try:
                    with open(self.wordlist_path, 'r') as f:
                        subdomains = [line.strip() for line in f if line.strip()]
                except:
                    subdomains = ['www', 'mail', 'ftp', 'admin', 'test']
            else:
                subdomains = ['www', 'mail', 'ftp', 'admin', 'test']
            
            total_items = len(subdomains) + 1  # +1 for main domain
            completed = 0
            
            # Update total items in registry
            scan_info = scan_registry.get_scan_info(self.scan_id)
            if scan_info:
                scan_info.total_items = total_items
            
            results = {}
            
            # Scan main domain first
            if self.controller.should_continue():
                self.controller.wait_if_paused()
                
                scan_registry.update_scan_details(
                    self.scan_id, 
                    f"Scanning main domain: {self.target}"
                )
                
                domain_results = self.scan_domain(self.target)
                if domain_results:
                    results.update(domain_results)
                
                completed += 1
                scan_registry.update_scan_progress(self.scan_id, completed)
                self.signals.progress.emit(completed, total_items)
            
            # Scan subdomains
            for i, subdomain in enumerate(subdomains):
                if not self.controller.should_continue():
                    break
                    
                self.controller.wait_if_paused()
                
                domain = f"{subdomain}.{self.target}"
                scan_registry.update_scan_details(
                    self.scan_id, 
                    f"Scanning subdomain: {domain}"
                )
                
                domain_results = self.scan_domain(domain)
                if domain_results:
                    results.update(domain_results)
                
                completed += 1
                scan_registry.update_scan_progress(self.scan_id, completed)
                self.signals.progress.emit(completed, total_items)
                
                # Small delay to prevent overwhelming DNS servers
                time.sleep(0.1)
            
            # Emit results
            self.signals.results.emit(results)
            
            # Mark scan as completed
            if self.controller.should_continue():
                scan_registry.finish_scan(self.scan_id, "Completed")
                self.signals.finished.emit(self.scan_id, "Completed")
            else:
                scan_registry.finish_scan(self.scan_id, "Stopped")
                self.signals.finished.emit(self.scan_id, "Stopped")
                
        except Exception as e:
            scan_registry.finish_scan(self.scan_id, "Failed")
            self.signals.error.emit(str(e))
            self.signals.finished.emit(self.scan_id, "Failed")
    
    def scan_domain(self, domain):
        """Scan a single domain for DNS records"""
        try:
            # Direct DNS query for the specific domain
            import dns.resolver
            from collections import defaultdict
            
            resolver = dns.resolver.Resolver()
            if self.dns_server:
                if self.dns_server.lower() == 'localdns':
                    from app.core.local_dns_server import local_dns_server
                    resolver.nameservers = ['127.0.0.1']
                    resolver.port = local_dns_server.port if local_dns_server.running else 53530
                else:
                    import socket
                    import re
                    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
                    if re.match(ip_pattern, self.dns_server):
                        resolver.nameservers = [self.dns_server]
                    else:
                        try:
                            dns_ip = socket.gethostbyname(self.dns_server)
                            resolver.nameservers = [dns_ip]
                        except socket.gaierror:
                            resolver.nameservers = [self.dns_server]
            
            results = defaultdict(lambda: defaultdict(list))
            
            for record_type in self.record_types:
                try:
                    if record_type == 'A':
                        for rtype in ['A', 'AAAA']:
                            try:
                                answers = resolver.resolve(domain, rtype)
                                values = [r.address for r in answers]
                                if values:
                                    results[domain][rtype].extend(values)
                            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                                continue
                    else:
                        answers = resolver.resolve(domain, record_type)
                        if record_type == 'MX':
                            values = [f"{r.preference} {r.exchange.to_text().rstrip('.')}" for r in answers]
                        elif record_type == 'NS':
                            values = [r.target.to_text().rstrip('.') for r in answers]
                        elif record_type == 'TXT':
                            values = [b''.join(r.strings).decode('utf-8', errors='ignore').replace('"', '') for r in answers]
                        elif record_type == 'CNAME':
                            values = [r.target.to_text().rstrip('.') for r in answers]
                        else:
                            values = [r.to_text() for r in answers]
                        
                        if values:
                            results[domain][record_type].extend(values)
                            
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    continue
                except Exception:
                    continue
            
            return dict(results)
            
        except Exception as e:
            self.signals.error.emit(f"Error scanning {domain}: {str(e)}")
            return {}

class DNSWorkerSignals(QObject):
    """Signals for DNS worker"""
    started = pyqtSignal(str)  # scan_id
    progress = pyqtSignal(int, int)  # completed, total
    results = pyqtSignal(dict)  # DNS results
    error = pyqtSignal(str)  # Error message
    finished = pyqtSignal(str, str)  # scan_id, status