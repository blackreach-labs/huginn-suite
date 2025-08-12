# app/tools/recon.py
import os
import dns.resolver
import dns.zone
import dns.query
import random
import string
import concurrent.futures
import itertools
import ipaddress
from collections import defaultdict
from PyQt6.QtCore import QObject, pyqtSignal, QRunnable, QThreadPool
from app.core.logger import logger
from app.core.config import config

class SubdomainGenerator:
    """Dedicated subdomain generator - handles only subdomain generation logic"""
    
    def __init__(self, wordlist_path=None, use_bruteforce=False, char_sets=None, max_length=16):
        self.wordlist_path = wordlist_path
        self.use_bruteforce = use_bruteforce
        self.char_sets = char_sets or []
        self.max_length = max_length
    
    def generate(self):
        """Main generator method - yields subdomains based on configuration"""
        if self.use_bruteforce:
            yield from self._generate_bruteforce()
        else:
            yield from self._generate_wordlist()
    
    def _generate_bruteforce(self):
        """Generate subdomains using bruteforce patterns"""
        # Always yield empty string first to test the domain itself
        yield ""
        
        chars = self._build_charset()
        if not chars:
            return
        
        for length in range(1, self.max_length + 1):
            for combo in itertools.product(chars, repeat=length):
                yield ''.join(combo)
    
    def _build_charset(self):
        """Build character set from configuration"""
        chars = ''
        if '0-9' in self.char_sets: 
            chars += '0123456789'
        if 'a-z' in self.char_sets: 
            chars += 'abcdefghijklmnopqrstuvwxyz'
        if '-' in self.char_sets: 
            chars += '-'
        return chars
    
    def _generate_wordlist(self):
        """Generate subdomains from wordlist file"""
        # Always yield empty string first to test the domain itself
        yield ""
        
        if self.wordlist_path and os.path.exists(self.wordlist_path):
            try:
                with open(self.wordlist_path, 'r') as file:
                    for line in file:
                        subdomain = line.strip()
                        if subdomain:
                            yield subdomain
            except (IOError, OSError):
                yield from self._generate_default()
        else:
            yield from self._generate_default()
    
    def _generate_default(self):
        """Generate default subdomain list as fallback"""
        default_subdomains = ['www', 'mail', 'ftp', 'admin', 'test']
        for subdomain in default_subdomains:
            yield subdomain

class WorkerSignals(QObject):
    output = pyqtSignal(str)
    status = pyqtSignal(str)
    finished = pyqtSignal()
    wildcard_result = pyqtSignal(str)
    results_ready = pyqtSignal(dict)
    progress_update = pyqtSignal(int, int, str)
    progress_start = pyqtSignal(int)
    result_found = pyqtSignal(str, str, list)

class HostWordlistWorker(QRunnable):
    """DNS query worker - consumes subdomains and performs DNS queries"""
    
    def __init__(self, target, subdomain_generator, record_types=None, dns_server=None):
        super().__init__()
        self.signals = WorkerSignals()
        self.target = target
        self.subdomain_generator = subdomain_generator
        self.dns_server = dns_server
        self.is_running = True
        self.record_types = record_types or ['A']
        self.wildcard_test_count = config.get_dns_config().get('wildcard_test_count', 3)
        self.wildcard_test_length = config.get_dns_config().get('wildcard_test_length', 12)
        self.wildcard_ips = set()
        self.resolver = self._setup_resolver()
        self.max_workers = self._get_max_workers()
    
    def _setup_resolver(self):
        """Configure DNS resolver"""
        resolver = dns.resolver.Resolver()
        if self.dns_server:
            if self.dns_server.lower() == 'localdns':
                from app.core.local_dns_server import local_dns_server
                resolver.nameservers = ['127.0.0.1']
                resolver.port = local_dns_server.port if local_dns_server.running else 53530
            else:
                # Resolve FQDN to IP if needed
                dns_ip = self._resolve_dns_server(self.dns_server)
                resolver.nameservers = [dns_ip]
        
        dns_config = config.get_dns_config()
        resolver.timeout = dns_config.get('timeout', 3)
        resolver.lifetime = dns_config.get('lifetime', 10)
        return resolver
    
    def _resolve_dns_server(self, dns_server):
        """Resolve DNS server FQDN to IP address"""
        import socket
        import re
        
        # Check if it's already an IP address
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, dns_server):
            return dns_server
        
        # Resolve FQDN to IP
        try:
            return socket.gethostbyname(dns_server)
        except socket.gaierror:
            # If resolution fails, return original (let DNS library handle the error)
            return dns_server
    
    def _get_max_workers(self):
        """Determine optimal worker count"""
        try:
            from app.core.rate_limiter import rate_limiter
            return rate_limiter.get_recommended_thread_count() if rate_limiter.is_enabled() else config.get_dns_config().get('max_workers', 50)
        except ImportError:
            return config.get_dns_config().get('max_workers', 50)
    
    def _get_formatter(self, record_type):
        """Get formatter function for DNS record type"""
        formatters = {
            'A': lambda r: r.address,
            'AAAA': lambda r: r.address,
            'CNAME': lambda r: r.target.to_text().rstrip('.'),
            'MX': lambda r: f"{r.preference} {r.exchange.to_text().rstrip('.')}",
            'TXT': lambda r: b''.join(r.strings).decode('utf-8', errors='ignore').replace('"', ''),
            'NS': lambda r: r.target.to_text().rstrip('.'),
            'PTR': lambda r: r.target.to_text().rstrip('.'),
            'SRV': lambda r: f"{r.priority} {r.weight} {r.port} {r.target.to_text().rstrip('.')}"
        }
        return formatters.get(record_type, lambda r: r.to_text())

    def _random_string(self, length=None):
        length = length or self.wildcard_test_length
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

    def detect_wildcard(self):
        test_domains = [f"{self._random_string()}.{self.target}" for _ in range(self.wildcard_test_count)]
        for test_domain in test_domains:
            try:
                answers = self.resolver.resolve(test_domain, 'A')
                for rdata in answers:
                    self.wildcard_ips.add(rdata.address)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                continue
            except Exception as e:
                logger.log_dns_error(test_domain, str(e))
                self.signals.output.emit(f"<p style='color: orange;'>[Wildcard Detection Error]: {test_domain} - {e}</p>")

    def query_subdomain(self, subdomain):
        if not self.is_running:
            return
        
        for record_type in self.record_types:
            if not self.is_running:
                return
            
            if record_type == 'SRV':
                # SRV records are handled separately, not per subdomain
                continue
            else:
                # Handle regular subdomain queries
                domain = f"{subdomain}.{self.target}" if subdomain else self.target
                try:
                    answers = self.resolver.resolve(domain, record_type)
                    formatter = self._get_formatter(record_type)
                    values = [formatter(r) for r in answers]
                    
                    # Filter out wildcard results
                    if record_type == "A" and self.wildcard_ips and set(values).issubset(self.wildcard_ips):
                        continue
                        
                    if values:
                        # Emit result as soon as it's found
                        self.signals.result_found.emit(domain, record_type, values)

                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                    continue
                except Exception:
                    pass
    
    def _query_srv_records(self, subdomain):
        """Query SRV records using service wordlist"""
        import os
        srv_wordlist_path = os.path.join(os.path.dirname(__file__), '..', '..', 'resources', 'wordlists', 'srv_wordlist.txt')
        
        try:
            with open(srv_wordlist_path, 'r') as f:
                services = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            services = ['_http', '_https', '_ftp', '_ssh', '_smtp', '_pop3', '_imap', '_ldap', '_kerberos']
        
        for srv in services:
            if not self.is_running:
                return
            
            for protocol in ['_tcp', '_udp']:
                fqdn = f"{srv}.{protocol}.{self.target}"
                try:
                    answers = self.resolver.resolve(fqdn, 'SRV')
                    formatter = self._get_formatter('SRV')
                    values = [formatter(r) for r in answers]
                    
                    if values:
                        self.signals.result_found.emit(fqdn, 'SRV', values)
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                    continue
                except Exception:
                    pass

    def _get_subdomains(self):
        """Get subdomains from the injected generator"""
        for subdomain in self.subdomain_generator.generate():
            if not self.is_running:
                return
            yield subdomain

    def run(self):
        try:
            scan_type = "bruteforce" if self.subdomain_generator.use_bruteforce else os.path.basename(self.subdomain_generator.wordlist_path or "default")
            logger.log_scan_start(self.target, scan_type, self.record_types)
            self.signals.status.emit(f"Running: Enumerate Hostnames on {self.target}...")

            self.signals.wildcard_result.emit("<p style='color: #00FF41;'>Checking for wildcard...</p>")
            self.detect_wildcard()
            if self.wildcard_ips:
                self.signals.wildcard_result.emit("<p style='color: orange;'>[✓] Wildcard DNS detected!</p>")
            else:
                self.signals.wildcard_result.emit("<p style='color: #00FF41;'>[✓] No wildcard DNS detected.</p>")
            
            if self.subdomain_generator.use_bruteforce:
                self.signals.output.emit(f"<p style='color: #00BFFF;'>Bruteforcing.... Please wait....</p><br>")
            
            # Get total count for progress tracking
            subdomains = list(self._get_subdomains())
            total_count = len(subdomains)
            self.signals.progress_start.emit(total_count)
            
            completed_count = 0
            all_results = defaultdict(lambda: defaultdict(list))
            
            # Store results as they're found for export
            def collect_result(domain, record_type, records):
                all_results[domain][record_type].extend(records)
            
            # Connect to result_found signal to collect results
            self.signals.result_found.connect(collect_result)

            # Handle SRV records separately (once per service, not per subdomain)
            if 'SRV' in self.record_types:
                self._query_srv_records(None)
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_sub = {executor.submit(self.query_subdomain, sub): sub for sub in subdomains}
                
                for future in concurrent.futures.as_completed(future_to_sub):
                    if not self.is_running:
                        # Cancel all remaining futures immediately
                        for f in future_to_sub:
                            f.cancel()
                        executor.shutdown(wait=False)
                        break
                    
                    try:
                        future.result()
                    except:
                        pass
                    
                    completed_count += 1
                    current_sub = future_to_sub[future]
                    self.signals.progress_update.emit(completed_count, len(all_results), current_sub)
                    
                    # Check cancellation more frequently
                    if not self.is_running:
                        break
            
            if self.is_running:
                final_count = getattr(self, 'final_result_count', len(all_results))
                logger.log_scan_complete(self.target, final_count)
                # Send final results for export
                if all_results:
                    self.signals.results_ready.emit(dict(all_results))
                self.signals.status.emit("Finished: Enumerate Hostnames")

        except Exception as e:
            logger.error(f"Unexpected error in DNS enumeration: {str(e)}")
            self.signals.output.emit(f"[ERROR] An unexpected error occurred: {e}")
            self.signals.status.emit("Error: Script crashed")
        finally:
            self.signals.finished.emit()

class PTRWorker(QRunnable):
    def __init__(self, ip_range, dns_server):
        super().__init__()
        self.signals = WorkerSignals()
        self.ip_range = ip_range
        self.dns_server = dns_server
        self.is_running = True
        self.completed_count = 0
        self.results_count = 0
    
    def run(self):
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 5
        if self.dns_server:
            if self.dns_server.lower() == 'localdns':
                from app.core.local_dns_server import local_dns_server
                resolver.nameservers = ['127.0.0.1']
                resolver.port = local_dns_server.port if local_dns_server.running else 53530
            else:
                # Resolve FQDN to IP if needed
                dns_ip = self._resolve_dns_server(self.dns_server)
                resolver.nameservers = [dns_ip]
        
        results = {}
        try:
            ips = []
            
            if '-' in self.ip_range:
                parts = self.ip_range.split('-')
                start_ip = parts[0].strip()
                end_part = parts[1].strip()
                
                if '.' in end_part:
                    # Full IP range like 192.168.1.0-192.168.16.0
                    start_parts = start_ip.split('.')
                    end_parts = end_part.split('.')
                    
                    # Check if it's a cross-subnet range
                    if start_parts[2] != end_parts[2]:
                        # Scan subnet by subnet
                        start_subnet = int(start_parts[2])
                        end_subnet = int(end_parts[2])
                        base_network = f"{start_parts[0]}.{start_parts[1]}"
                        
                        self.signals.output.emit(f"<p style='color: #00BFFF;'>[INFO] Cross-subnet range detected. Scanning {end_subnet - start_subnet + 1} subnets...</p>")
                        
                        for subnet in range(start_subnet, end_subnet + 1):
                            # Scan each subnet from .1 to .254 (skip .0 and .255)
                            for host in range(1, 255):
                                ips.append(ipaddress.ip_address(f"{base_network}.{subnet}.{host}"))
                    else:
                        # Same subnet range
                        start = ipaddress.ip_address(start_ip)
                        end = ipaddress.ip_address(end_part)
                        current = int(start)
                        end_int = int(end)
                        
                        while current <= end_int:
                            ips.append(ipaddress.ip_address(current))
                            current += 1
                else:
                    # Last octet range like 192.168.1.1-254
                    base_ip = '.'.join(start_ip.split('.')[:-1])
                    start_octet = int(start_ip.split('.')[-1])
                    end_octet = int(end_part)
                    for i in range(start_octet, end_octet + 1):
                        ips.append(ipaddress.ip_address(f"{base_ip}.{i}"))
            elif '/' in self.ip_range:
                network = ipaddress.ip_network(self.ip_range, strict=False)
                ips = list(network.hosts())
            else:
                ip_parts = self.ip_range.split('.')
                if len(ip_parts) == 4:
                    if ip_parts[3] == '0':
                        if ip_parts[2] == '0':
                            network = ipaddress.ip_network(f"{self.ip_range}/16", strict=False)
                        else:
                            network = ipaddress.ip_network(f"{self.ip_range}/24", strict=False)
                        ips = list(network.hosts())
                    else:
                        ips = [ipaddress.ip_address(self.ip_range)]
            
            self.signals.output.emit(f"<p style='color: #00BFFF;'>Querying PTR records.... please wait...</p><br>")
            self.signals.progress_start.emit(len(ips))
            
            def query_single_ptr(ip):
                if not self.is_running:
                    return None
                try:
                    reverse_name = dns.reversename.from_address(str(ip))
                    answers = resolver.resolve(reverse_name, 'PTR')
                    values = [r.target.to_text().rstrip('.') for r in answers]
                    if values:
                        return str(ip), values
                except dns.resolver.NXDOMAIN:
                    # No PTR record exists
                    pass
                except dns.resolver.Timeout:
                    # DNS timeout
                    pass
                except Exception as e:
                    # Silent error handling
                    pass
                return None
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                future_to_ip = {executor.submit(query_single_ptr, ip): ip for ip in ips}
                for future in concurrent.futures.as_completed(future_to_ip):
                    if not self.is_running:
                        break
                    result = future.result()
                    self.completed_count += 1
                    
                    if result:
                        ip, values = result
                        results[ip] = {'PTR': values}
                        self.results_count += 1
                        self.signals.output.emit(f"<p style='color: #00FF41;'>[+] Found (PTR): {ip}</p>")
                        for value in values:
                            self.signals.output.emit(f"<p style='color: #DCDCDC; padding-left: 20px;'>&nbsp;&nbsp;&nbsp;-&gt; {value}</p>")
                        self.signals.output.emit("<br>")
                        # Store individual result immediately
                        self.signals.results_ready.emit({ip: {'PTR': values}})
                    
                    # Update progress every 10 IPs or at the end
                    if self.completed_count % 10 == 0 or self.completed_count == len(ips):
                        current_ip = str(future_to_ip[future]) if future in future_to_ip else "..."
                        self.signals.progress_update.emit(self.completed_count, self.results_count, current_ip)
            
            # Final results summary already sent individually
        except Exception as e:
            self.signals.output.emit(f"<p style='color: red;'>[ERROR] PTR query failed: {str(e)}</p>")
        finally:
            self.signals.finished.emit()
    
    def _resolve_dns_server(self, dns_server):
        """Resolve DNS server FQDN to IP address"""
        import socket
        import re
        
        # Check if it's already an IP address
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, dns_server):
            return dns_server
        
        # Resolve FQDN to IP
        try:
            return socket.gethostbyname(dns_server)
        except socket.gaierror:
            # If resolution fails, return original (let DNS library handle the error)
            return dns_server

class SRVOnlyWorker(QRunnable):
    """Dedicated SRV record scanner that only checks wordlist entries"""
    
    def __init__(self, target, dns_server=None):
        super().__init__()
        self.signals = WorkerSignals()
        self.target = target
        self.dns_server = dns_server
        self.is_running = True
        self.resolver = self._setup_resolver()
    
    def _setup_resolver(self):
        resolver = dns.resolver.Resolver()
        if self.dns_server:
            if self.dns_server.lower() == 'localdns':
                from app.core.local_dns_server import local_dns_server
                resolver.nameservers = ['127.0.0.1']
                resolver.port = local_dns_server.port if local_dns_server.running else 53530
            else:
                # Resolve FQDN to IP if needed
                dns_ip = self._resolve_dns_server(self.dns_server)
                resolver.nameservers = [dns_ip]
        resolver.timeout = 3
        resolver.lifetime = 10
        return resolver
    
    def _resolve_dns_server(self, dns_server):
        """Resolve DNS server FQDN to IP address"""
        import socket
        import re
        
        # Check if it's already an IP address
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, dns_server):
            return dns_server
        
        # Resolve FQDN to IP
        try:
            return socket.gethostbyname(dns_server)
        except socket.gaierror:
            # If resolution fails, return original (let DNS library handle the error)
            return dns_server
    
    def run(self):
        try:
            self.signals.status.emit(f"Running SRV enumeration on {self.target}...")
            self.signals.output.emit(f"<p style='color: #00BFFF;'>Enumerating SRV records.... Please wait....</p><br>")
            
            # Load SRV wordlist
            srv_wordlist_path = os.path.join(os.path.dirname(__file__), '..', '..', 'resources', 'wordlists', 'srv_wordlist.txt')
            
            try:
                with open(srv_wordlist_path, 'r') as f:
                    services = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                services = ['_http', '_https', '_ftp', '_ssh', '_smtp', '_pop3', '_imap', '_ldap', '_kerberos']
            
            protocols = ['_tcp', '_udp']
            total_queries = len(services) * len(protocols)
            self.signals.progress_start.emit(total_queries)
            
            completed = 0
            results_found = 0
            all_results = {}
            
            for srv in services:
                if not self.is_running:
                    break
                    
                for protocol in protocols:
                    if not self.is_running:
                        break
                        
                    fqdn = f"{srv}.{protocol}.{self.target}"
                    try:
                        answers = self.resolver.resolve(fqdn, 'SRV')
                        values = [f"{r.priority} {r.weight} {r.port} {r.target.to_text().rstrip('.')}" for r in answers]
                        
                        if values:
                            if self.target not in all_results:
                                all_results[self.target] = {}
                            if 'SRV' not in all_results[self.target]:
                                all_results[self.target]['SRV'] = []
                            
                            all_results[self.target]['SRV'].extend(values)
                            results_found += 1
                            
                            self.signals.output.emit(f"<p style='color: #00FF41;'>[+] Found (SRV): {fqdn}</p>")
                            for value in values:
                                self.signals.output.emit(f"<p style='color: #DCDCDC; padding-left: 20px;'>&nbsp;&nbsp;&nbsp;-&gt; {value}</p>")
                            self.signals.output.emit("<br>")
                    
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                        pass
                    except Exception:
                        pass
                    
                    completed += 1
                    self.signals.progress_update.emit(completed, results_found, fqdn)
            
            if all_results:
                self.signals.results_ready.emit(all_results)
            
            self.signals.status.emit("SRV enumeration completed")
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF4500;'>[ERROR] SRV enumeration failed: {str(e)}</p>")
        finally:
            self.signals.finished.emit()