# app/core/subdomain_enumerator.py
import asyncio
import aiohttp
import dns.resolver
import requests
import json
import re
import socket
import subprocess
import threading
import time
from typing import Set, List, Dict, Callable, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import ssl
import OpenSSL.crypto
from dataclasses import dataclass
from pathlib import Path

@dataclass
class SubdomainResult:
    """Represents a discovered subdomain with metadata"""
    subdomain: str
    ip_addresses: List[str]
    source: str
    status_code: Optional[int] = None
    title: Optional[str] = None
    technologies: List[str] = None
    certificate_info: Optional[Dict] = None
    response_time: Optional[float] = None
    
    def __post_init__(self):
        if self.technologies is None:
            self.technologies = []

class SubdomainEnumerator:
    """Advanced subdomain enumeration with multiple techniques"""
    
    def __init__(self, max_workers: int = 50, timeout: int = 10):
        self.max_workers = max_workers
        self.timeout = timeout
        self.discovered_subdomains = set()
        self.results = []
        self.progress_callback = None
        self.stop_event = threading.Event()
        
        # Load wordlists
        self.wordlists = self._load_wordlists()
        
        # DNS resolver setup
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 5
    
    def _load_wordlists(self) -> Dict[str, List[str]]:
        """Load subdomain wordlists"""
        wordlists = {}
        
        try:
            # Get project root
            from pathlib import Path
            project_root = Path(__file__).parent.parent.parent
            wordlist_dir = project_root / "resources" / "wordlists"
            
            # Load different wordlist sizes
            wordlist_files = {
                'small': 'subdomains-top1000.txt',
                'medium': 'subdomains-top10000.txt', 
                'large': 'subdomains-all.txt'
            }
            
            for size, filename in wordlist_files.items():
                filepath = wordlist_dir / filename
                if filepath.exists():
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        wordlists[size] = [line.strip() for line in f if line.strip()]
                else:
                    # Fallback wordlist
                    wordlists[size] = [
                        'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api',
                        'blog', 'shop', 'forum', 'support', 'help', 'docs', 'cdn',
                        'static', 'media', 'images', 'assets', 'files', 'download'
                    ]
        
        except Exception:
            # Minimal fallback
            wordlists['small'] = ['www', 'mail', 'ftp', 'admin', 'test']
            wordlists['medium'] = wordlists['small']
            wordlists['large'] = wordlists['small']
        
        return wordlists
    
    async def enumerate_subdomains(self, domain: str, methods: List[str] = None, 
                                 wordlist_size: str = 'medium',
                                 progress_callback: Callable = None) -> List[SubdomainResult]:
        """
        Comprehensive subdomain enumeration using multiple techniques
        
        Args:
            domain: Target domain
            methods: List of enumeration methods to use
            wordlist_size: Size of wordlist ('small', 'medium', 'large')
            progress_callback: Callback for progress updates
        """
        
        if methods is None:
            methods = [
                'dns_bruteforce',
                'certificate_transparency', 
                'search_engines',
                'dns_zone_transfer',
                'reverse_dns',
                'subdomain_takeover_check'
            ]
        
        self.progress_callback = progress_callback
        self.discovered_subdomains.clear()
        self.results.clear()
        self.stop_event.clear()
        
        if progress_callback:
            progress_callback(f"Starting subdomain enumeration for {domain}")
        
        # Run enumeration methods concurrently
        tasks = []
        
        if 'dns_bruteforce' in methods:
            tasks.append(self._dns_bruteforce(domain, wordlist_size))
        
        if 'certificate_transparency' in methods:
            tasks.append(self._certificate_transparency(domain))
        
        if 'search_engines' in methods:
            tasks.append(self._search_engines(domain))
        
        if 'dns_zone_transfer' in methods:
            tasks.append(self._dns_zone_transfer(domain))
        
        if 'reverse_dns' in methods:
            tasks.append(self._reverse_dns_sweep(domain))
        
        # Execute all enumeration methods
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Collect all discovered subdomains
        all_subdomains = set()
        for result in results:
            if isinstance(result, set):
                all_subdomains.update(result)
        
        if progress_callback:
            progress_callback(f"Found {len(all_subdomains)} unique subdomains")
        
        # Validate and enrich subdomain data
        if all_subdomains:
            validated_results = await self._validate_and_enrich_subdomains(
                list(all_subdomains), domain
            )
            
            # Check for subdomain takeover if requested
            if 'subdomain_takeover_check' in methods:
                await self._check_subdomain_takeover(validated_results)
        
        else:
            validated_results = []
        
        self.results = validated_results
        return validated_results
    
    async def _dns_bruteforce(self, domain: str, wordlist_size: str) -> Set[str]:
        """DNS bruteforce using wordlist"""
        
        if self.progress_callback:
            self.progress_callback("Running DNS bruteforce...")
        
        discovered = set()
        wordlist = self.wordlists.get(wordlist_size, self.wordlists['small'])
        
        # Use ThreadPoolExecutor for DNS queries
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit DNS resolution tasks
            future_to_subdomain = {
                executor.submit(self._resolve_subdomain, f"{word}.{domain}"): f"{word}.{domain}"
                for word in wordlist
            }
            
            completed = 0
            total = len(future_to_subdomain)
            
            for future in as_completed(future_to_subdomain):
                if self.stop_event.is_set():
                    break
                
                subdomain = future_to_subdomain[future]
                try:
                    ip_addresses = future.result()
                    if ip_addresses:
                        discovered.add(subdomain)
                        
                    completed += 1
                    if self.progress_callback and completed % 50 == 0:
                        self.progress_callback(f"DNS bruteforce: {completed}/{total} tested")
                        
                except Exception:
                    pass
        
        return discovered
    
    def _resolve_subdomain(self, subdomain: str) -> List[str]:
        """Resolve subdomain to IP addresses"""
        
        ip_addresses = []
        
        try:
            # Try A record
            answers = self.resolver.resolve(subdomain, 'A')
            ip_addresses.extend([str(rdata) for rdata in answers])
        except:
            pass
        
        try:
            # Try AAAA record
            answers = self.resolver.resolve(subdomain, 'AAAA')
            ip_addresses.extend([str(rdata) for rdata in answers])
        except:
            pass
        
        return ip_addresses
    
    async def _certificate_transparency(self, domain: str) -> Set[str]:
        """Certificate Transparency log search"""
        
        if self.progress_callback:
            self.progress_callback("Searching Certificate Transparency logs...")
        
        discovered = set()
        
        try:
            from app.core.cert_transparency import cert_transparency
            
            ct_results = cert_transparency.search_certificates(domain)
            if 'subdomains' in ct_results:
                discovered.update(ct_results['subdomains'])
                
        except Exception:
            # Fallback to direct crt.sh query
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
                    url = f"https://crt.sh/?q=%.{domain}&output=json"
                    async with session.get(url) as response:
                        if response.status == 200:
                            certificates = await response.json()
                            
                            for cert in certificates[:1000]:  # Limit results
                                name_value = cert.get('name_value', '')
                                if name_value:
                                    # Extract subdomains from certificate
                                    names = name_value.replace('\\n', '\n').split('\n')
                                    for name in names:
                                        name = name.strip().lower()
                                        if (name.endswith('.' + domain) or name == domain) and '*' not in name:
                                            if self._is_valid_domain(name):
                                                discovered.add(name)
            except Exception:
                pass
        
        return discovered
    
    async def _search_engines(self, domain: str) -> Set[str]:
        """Search engine enumeration (Google, Bing, etc.)"""
        
        if self.progress_callback:
            self.progress_callback("Searching engines for subdomains...")
        
        discovered = set()
        
        # Google search
        try:
            await self._google_search(domain, discovered)
        except Exception:
            pass
        
        # Bing search  
        try:
            await self._bing_search(domain, discovered)
        except Exception:
            pass
        
        return discovered
    
    async def _google_search(self, domain: str, discovered: Set[str]):
        """Google dorking for subdomains"""
        
        queries = [
            f"site:*.{domain}",
            f"site:{domain} -www",
            f"inurl:{domain}",
        ]
        
        async with aiohttp.ClientSession() as session:
            for query in queries:
                try:
                    url = f"https://www.google.com/search?q={query}&num=100"
                    headers = {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    }
                    
                    async with session.get(url, headers=headers) as response:
                        if response.status == 200:
                            text = await response.text()
                            # Extract subdomains from search results
                            pattern = r'https?://([a-zA-Z0-9.-]+\.' + re.escape(domain) + r')'
                            matches = re.findall(pattern, text)
                            
                            for match in matches:
                                if self._is_valid_domain(match):
                                    discovered.add(match)
                    
                    # Rate limiting
                    await asyncio.sleep(2)
                    
                except Exception:
                    continue
    
    async def _bing_search(self, domain: str, discovered: Set[str]):
        """Bing search for subdomains"""
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://www.bing.com/search?q=site%3A*.{domain}&count=50"
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
                
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        text = await response.text()
                        # Extract subdomains from search results
                        pattern = r'https?://([a-zA-Z0-9.-]+\.' + re.escape(domain) + r')'
                        matches = re.findall(pattern, text)
                        
                        for match in matches:
                            if self._is_valid_domain(match):
                                discovered.add(match)
        
        except Exception:
            pass
    
    async def _dns_zone_transfer(self, domain: str) -> Set[str]:
        """Attempt DNS zone transfer"""
        
        if self.progress_callback:
            self.progress_callback("Attempting DNS zone transfer...")
        
        discovered = set()
        
        try:
            # Get NS records for domain
            ns_records = []
            try:
                answers = self.resolver.resolve(domain, 'NS')
                ns_records = [str(rdata).rstrip('.') for rdata in answers]
            except:
                pass
            
            # Try zone transfer on each nameserver
            for ns in ns_records:
                try:
                    # Use dig command for zone transfer
                    result = subprocess.run(
                        ['dig', 'axfr', domain, f'@{ns}'],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    
                    if result.returncode == 0 and 'Transfer failed' not in result.stdout:
                        # Parse zone transfer output
                        lines = result.stdout.split('\n')
                        for line in lines:
                            if domain in line and not line.startswith(';'):
                                parts = line.split()
                                if len(parts) > 0:
                                    potential_subdomain = parts[0].rstrip('.')
                                    if (potential_subdomain.endswith('.' + domain) or 
                                        potential_subdomain == domain):
                                        if self._is_valid_domain(potential_subdomain):
                                            discovered.add(potential_subdomain)
                
                except Exception:
                    continue
        
        except Exception:
            pass
        
        return discovered
    
    async def _reverse_dns_sweep(self, domain: str) -> Set[str]:
        """Reverse DNS sweep on IP ranges"""
        
        if self.progress_callback:
            self.progress_callback("Performing reverse DNS sweep...")
        
        discovered = set()
        
        try:
            # Get IP addresses for main domain
            main_ips = self._resolve_subdomain(domain)
            
            for ip in main_ips:
                try:
                    # Get IP network range
                    ip_parts = ip.split('.')
                    if len(ip_parts) == 4:
                        # Sweep /24 subnet
                        base_ip = '.'.join(ip_parts[:3])
                        
                        # Limit sweep to avoid being too aggressive
                        for i in range(1, 255, 5):  # Sample every 5th IP
                            if self.stop_event.is_set():
                                break
                            
                            test_ip = f"{base_ip}.{i}"
                            try:
                                hostname = socket.gethostbyaddr(test_ip)[0]
                                if hostname.endswith('.' + domain) or hostname == domain:
                                    if self._is_valid_domain(hostname):
                                        discovered.add(hostname)
                            except:
                                pass
                
                except Exception:
                    continue
        
        except Exception:
            pass
        
        return discovered
    
    async def _validate_and_enrich_subdomains(self, subdomains: List[str], 
                                            domain: str) -> List[SubdomainResult]:
        """Validate subdomains and enrich with additional data"""
        
        if self.progress_callback:
            self.progress_callback(f"Validating and enriching {len(subdomains)} subdomains...")
        
        results = []
        
        # Use semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(20)
        
        async def process_subdomain(subdomain):
            async with semaphore:
                return await self._enrich_subdomain(subdomain)
        
        # Process subdomains concurrently
        tasks = [process_subdomain(sub) for sub in subdomains]
        enriched_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter successful results
        for result in enriched_results:
            if isinstance(result, SubdomainResult):
                results.append(result)
        
        return results
    
    async def _enrich_subdomain(self, subdomain: str) -> Optional[SubdomainResult]:
        """Enrich subdomain with HTTP info, certificates, etc."""
        
        try:
            # Resolve IP addresses
            ip_addresses = self._resolve_subdomain(subdomain)
            if not ip_addresses:
                return None
            
            result = SubdomainResult(
                subdomain=subdomain,
                ip_addresses=ip_addresses,
                source='validation'
            )
            
            # Try HTTP/HTTPS requests
            await self._check_http_services(result)
            
            # Get certificate info if HTTPS
            if result.status_code:
                await self._get_certificate_info(result)
            
            return result
        
        except Exception:
            return None
    
    async def _check_http_services(self, result: SubdomainResult):
        """Check HTTP/HTTPS services on subdomain"""
        
        protocols = ['https', 'http']
        
        for protocol in protocols:
            try:
                url = f"{protocol}://{result.subdomain}"
                
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=10),
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    
                    start_time = time.time()
                    async with session.get(url, allow_redirects=True) as response:
                        result.response_time = time.time() - start_time
                        result.status_code = response.status
                        
                        # Get page title
                        if response.status == 200:
                            try:
                                content = await response.text()
                                title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
                                if title_match:
                                    result.title = title_match.group(1).strip()
                                
                                # Basic technology detection
                                result.technologies = self._detect_technologies(content, response.headers)
                            except:
                                pass
                        
                        break  # Success, no need to try other protocol
            
            except Exception:
                continue
    
    def _detect_technologies(self, content: str, headers: Dict) -> List[str]:
        """Basic technology detection"""
        
        technologies = []
        content_lower = content.lower()
        
        # Server header
        server = headers.get('Server', '')
        if server:
            technologies.append(f"Server: {server}")
        
        # Common technologies
        tech_patterns = {
            'WordPress': r'wp-content|wordpress',
            'Drupal': r'drupal',
            'Joomla': r'joomla',
            'React': r'react',
            'Angular': r'angular',
            'Vue.js': r'vue\.js',
            'jQuery': r'jquery',
            'Bootstrap': r'bootstrap',
            'PHP': r'\.php',
            'ASP.NET': r'asp\.net',
            'Django': r'django',
            'Flask': r'flask'
        }
        
        for tech, pattern in tech_patterns.items():
            if re.search(pattern, content_lower):
                technologies.append(tech)
        
        return technologies
    
    async def _get_certificate_info(self, result: SubdomainResult):
        """Get SSL certificate information"""
        
        try:
            # Get certificate using OpenSSL
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((result.subdomain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=result.subdomain) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_der)
                    
                    result.certificate_info = {
                        'subject': dict(cert.get_subject().get_components()),
                        'issuer': dict(cert.get_issuer().get_components()),
                        'serial_number': str(cert.get_serial_number()),
                        'not_before': cert.get_notBefore().decode('ascii'),
                        'not_after': cert.get_notAfter().decode('ascii'),
                        'signature_algorithm': cert.get_signature_algorithm().decode('ascii')
                    }
        
        except Exception:
            pass
    
    async def _check_subdomain_takeover(self, results: List[SubdomainResult]):
        """Check for potential subdomain takeover vulnerabilities"""
        
        if self.progress_callback:
            self.progress_callback("Checking for subdomain takeover vulnerabilities...")
        
        # Known takeover signatures
        takeover_signatures = {
            'GitHub Pages': ['There isn\\'t a GitHub Pages site here'],
            'Heroku': ['No such app'],
            'Shopify': ['Sorry, this shop is currently unavailable'],
            'Tumblr': ['Whatever you were looking for doesn\\'t currently exist'],
            'WordPress.com': ['Do you want to register'],
            'Ghost': ['The thing you were looking for is no longer here'],
            'Bitbucket': ['Repository not found'],
            'Fastly': ['Fastly error: unknown domain'],
            'Amazon S3': ['NoSuchBucket', 'The specified bucket does not exist'],
            'Azure': ['404 Web Site not found']
        }
        
        for result in results:
            if result.status_code in [404, 403]:
                try:
                    # Check HTTP response for takeover signatures
                    async with aiohttp.ClientSession() as session:
                        url = f"http://{result.subdomain}"
                        async with session.get(url) as response:
                            content = await response.text()
                            
                            for service, signatures in takeover_signatures.items():
                                for signature in signatures:
                                    if signature.lower() in content.lower():
                                        result.technologies.append(f"POTENTIAL_TAKEOVER: {service}")
                                        break
                
                except Exception:
                    pass
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain format"""
        
        if not domain or len(domain) > 253:
            return False
        
        # Check for valid characters
        if not re.match(r'^[a-zA-Z0-9.-]+$', domain):
            return False
        
        # Check domain parts
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        for part in parts:
            if not part or len(part) > 63:
                return False
            if part.startswith('-') or part.endswith('-'):
                return False
        
        return True
    
    def stop_enumeration(self):
        """Stop the enumeration process"""
        self.stop_event.set()
    
    def get_statistics(self) -> Dict:
        """Get enumeration statistics"""
        
        if not self.results:
            return {}
        
        stats = {
            'total_subdomains': len(self.results),
            'alive_subdomains': len([r for r in self.results if r.status_code]),
            'https_enabled': len([r for r in self.results if r.status_code and 'https' in str(r.certificate_info)]),
            'unique_ips': len(set([ip for r in self.results for ip in r.ip_addresses])),
            'technologies_found': len(set([tech for r in self.results for tech in r.technologies])),
            'potential_takeovers': len([r for r in self.results for tech in r.technologies if 'POTENTIAL_TAKEOVER' in tech])
        }
        
        return stats

# Global instance
subdomain_enumerator = SubdomainEnumerator()