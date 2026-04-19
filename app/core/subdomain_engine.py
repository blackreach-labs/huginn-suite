# app/core/subdomain_engine.py
"""
Professional Subdomain Enumeration Engine
Following OSINT_domains.md specifications for modular, plugin-based architecture
"""

import asyncio
import aiohttp
import json
import time
import logging
import sqlite3
import hashlib
from typing import Dict, List, Set, Optional, Callable, Any
from dataclasses import dataclass, asdict
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, quote
import dns.resolver
import ssl
import socket
from PyQt6.QtCore import QObject, pyqtSignal, QThread
import yaml
import re
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class SubdomainResult:
    """Represents a discovered subdomain with metadata"""
    host: str
    ip: Optional[str] = None
    source: str = ""
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    status: str = "discovered"  # discovered, resolved, wildcard, error
    raw_data: Optional[Dict] = None
    
    def __post_init__(self):
        if self.first_seen is None:
            self.first_seen = datetime.now()
        if self.last_seen is None:
            self.last_seen = datetime.now()

@dataclass
class ScanOptions:
    """Configuration options for subdomain enumeration"""
    sources: List[str] = None
    exclude_sources: List[str] = None
    timeout: int = 30
    rate_limit: float = 10.0  # requests per second
    rate_limit_per_source: Dict[str, float] = None
    resolve_dns: bool = True
    filter_wildcards: bool = True
    max_concurrent: int = 50
    output_format: str = "json"  # json, csv, text
    save_to_db: bool = True
    
    def __post_init__(self):
        if self.sources is None:
            self.sources = ["crtsh", "certspotter", "virustotal", "censys", "wayback"]
        if self.rate_limit_per_source is None:
            self.rate_limit_per_source = {}

class SourcePlugin:
    """Base class for data source plugins"""
    
    def __init__(self, name: str, description: str, requires_auth: bool = False):
        self.name = name
        self.description = description
        self.requires_auth = requires_auth
        self.rate_limiter = None
        self.session = None
    
    async def run(self, domain: str, session: aiohttp.ClientSession, 
                  api_keys: Dict[str, str] = None) -> List[SubdomainResult]:
        """Execute the plugin and return discovered subdomains"""
        raise NotImplementedError("Subclasses must implement run method")
    
    def set_rate_limiter(self, rate: float):
        """Set rate limiting for this source"""
        import asyncio
        self.rate_limiter = asyncio.Semaphore(int(rate))
    
    async def _rate_limit(self):
        """Apply rate limiting if configured"""
        if self.rate_limiter:
            await self.rate_limiter.acquire()
            # Release after a delay to maintain rate
            asyncio.create_task(self._release_after_delay())
    
    async def _release_after_delay(self):
        """Release rate limiter after delay"""
        await asyncio.sleep(1.0)  # 1 second delay
        if self.rate_limiter:
            self.rate_limiter.release()

class CrtShPlugin(SourcePlugin):
    """Certificate Transparency logs via crt.sh"""
    
    def __init__(self):
        super().__init__("crtsh", "Certificate Transparency via crt.sh", requires_auth=False)
    
    async def run(self, domain: str, session: aiohttp.ClientSession, 
                  api_keys: Dict[str, str] = None) -> List[SubdomainResult]:
        results = []
        
        try:
            await self._rate_limit()
            
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            
            async with session.get(url, timeout=30) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    seen_subdomains = set()
                    for cert in data[:1000]:  # Limit to prevent memory issues
                        name_value = cert.get('name_value', '')
                        if name_value:
                            # Parse certificate names
                            names = name_value.replace('\\n', '\n').split('\n')
                            for name in names:
                                name = name.strip().lower()
                                if self._is_valid_subdomain(name, domain) and name not in seen_subdomains:
                                    seen_subdomains.add(name)
                                    results.append(SubdomainResult(
                                        host=name,
                                        source=self.name,
                                        raw_data={
                                            'cert_id': cert.get('id'),
                                            'issuer': cert.get('issuer_name'),
                                            'not_before': cert.get('not_before'),
                                            'not_after': cert.get('not_after')
                                        }
                                    ))
        
        except Exception as e:
            logger.error(f"CrtSh plugin error: {e}")
        
        return results
    
    def _is_valid_subdomain(self, name: str, domain: str) -> bool:
        """Validate if name is a valid subdomain of domain"""
        if not name or '*' in name:
            return False
        
        if name == domain or name.endswith('.' + domain):
            # Basic domain validation
            if re.match(r'^[a-zA-Z0-9.-]+$', name):
                return True
        
        return False

class CertSpotterPlugin(SourcePlugin):
    """CertSpotter Certificate Transparency API"""
    
    def __init__(self):
        super().__init__("certspotter", "CertSpotter CT API", requires_auth=True)
    
    async def run(self, domain: str, session: aiohttp.ClientSession, 
                  api_keys: Dict[str, str] = None) -> List[SubdomainResult]:
        results = []
        
        try:
            await self._rate_limit()
            
            # CertSpotter free tier
            url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
            
            headers = {}
            if api_keys and 'certspotter' in api_keys:
                headers['Authorization'] = f"Bearer {api_keys['certspotter']}"
            
            async with session.get(url, headers=headers, timeout=30) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    seen_subdomains = set()
                    for cert in data[:100]:  # Free tier limit
                        dns_names = cert.get('dns_names', [])
                        for name in dns_names:
                            name = name.lower().strip()
                            if self._is_valid_subdomain(name, domain) and name not in seen_subdomains:
                                seen_subdomains.add(name)
                                results.append(SubdomainResult(
                                    host=name,
                                    source=self.name,
                                    raw_data={
                                        'cert_id': cert.get('id'),
                                        'not_before': cert.get('not_before'),
                                        'not_after': cert.get('not_after')
                                    }
                                ))
        
        except Exception as e:
            logger.error(f"CertSpotter plugin error: {e}")
        
        return results
    
    def _is_valid_subdomain(self, name: str, domain: str) -> bool:
        """Validate if name is a valid subdomain of domain"""
        if not name or '*' in name:
            return False
        
        if name == domain or name.endswith('.' + domain):
            if re.match(r'^[a-zA-Z0-9.-]+$', name):
                return True
        
        return False

class VirusTotalPlugin(SourcePlugin):
    """VirusTotal API for subdomain discovery"""
    
    def __init__(self):
        super().__init__("virustotal", "VirusTotal API", requires_auth=True)
    
    async def run(self, domain: str, session: aiohttp.ClientSession, 
                  api_keys: Dict[str, str] = None) -> List[SubdomainResult]:
        results = []
        
        if not api_keys or 'virustotal' not in api_keys:
            logger.warning("VirusTotal API key not provided")
            return results
        
        try:
            await self._rate_limit()
            
            url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
            headers = {
                'X-Apikey': api_keys['virustotal']
            }
            
            async with session.get(url, headers=headers, timeout=30) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for item in data.get('data', []):
                        subdomain = item.get('id', '').lower()
                        if subdomain and self._is_valid_subdomain(subdomain, domain):
                            results.append(SubdomainResult(
                                host=subdomain,
                                source=self.name,
                                raw_data=item.get('attributes', {})
                            ))
        
        except Exception as e:
            logger.error(f"VirusTotal plugin error: {e}")
        
        return results
    
    def _is_valid_subdomain(self, name: str, domain: str) -> bool:
        """Validate if name is a valid subdomain of domain"""
        if not name or '*' in name:
            return False
        
        if name == domain or name.endswith('.' + domain):
            if re.match(r'^[a-zA-Z0-9.-]+$', name):
                return True
        
        return False

class WaybackPlugin(SourcePlugin):
    """Wayback Machine archive search"""
    
    def __init__(self):
        super().__init__("wayback", "Wayback Machine Archives", requires_auth=False)
    
    async def run(self, domain: str, session: aiohttp.ClientSession, 
                  api_keys: Dict[str, str] = None) -> List[SubdomainResult]:
        results = []
        
        try:
            await self._rate_limit()
            
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey"
            
            async with session.get(url, timeout=30) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    seen_subdomains = set()
                    for item in data[1:]:  # Skip header row
                        if item and len(item) > 0:
                            url_str = item[0]
                            try:
                                parsed = urlparse(url_str)
                                hostname = parsed.hostname
                                if hostname and self._is_valid_subdomain(hostname, domain):
                                    hostname = hostname.lower()
                                    if hostname not in seen_subdomains:
                                        seen_subdomains.add(hostname)
                                        results.append(SubdomainResult(
                                            host=hostname,
                                            source=self.name,
                                            raw_data={'original_url': url_str}
                                        ))
                            except:
                                continue
        
        except Exception as e:
            logger.error(f"Wayback plugin error: {e}")
        
        return results
    
    def _is_valid_subdomain(self, name: str, domain: str) -> bool:
        """Validate if name is a valid subdomain of domain"""
        if not name or '*' in name:
            return False
        
        if name == domain or name.endswith('.' + domain):
            if re.match(r'^[a-zA-Z0-9.-]+$', name):
                return True
        
        return False

class CensysPlugin(SourcePlugin):
    """Censys search API"""
    
    def __init__(self):
        super().__init__("censys", "Censys Search API", requires_auth=True)
    
    async def run(self, domain: str, session: aiohttp.ClientSession, 
                  api_keys: Dict[str, str] = None) -> List[SubdomainResult]:
        results = []
        
        if not api_keys or 'censys_id' not in api_keys or 'censys_secret' not in api_keys:
            logger.warning("Censys API credentials not provided")
            return results
        
        try:
            await self._rate_limit()
            
            # Basic auth for Censys
            import base64
            credentials = base64.b64encode(
                f"{api_keys['censys_id']}:{api_keys['censys_secret']}".encode()
            ).decode()
            
            url = "https://search.censys.io/api/v2/hosts/search"
            headers = {
                'Authorization': f'Basic {credentials}',
                'Content-Type': 'application/json'
            }
            
            query_data = {
                'q': f'names: *.{domain}',
                'per_page': 100
            }
            
            async with session.post(url, headers=headers, json=query_data, timeout=30) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for result in data.get('result', {}).get('hits', []):
                        names = result.get('names', [])
                        for name in names:
                            name = name.lower().strip()
                            if self._is_valid_subdomain(name, domain):
                                results.append(SubdomainResult(
                                    host=name,
                                    source=self.name,
                                    raw_data={
                                        'ip': result.get('ip'),
                                        'services': result.get('services', [])
                                    }
                                ))
        
        except Exception as e:
            logger.error(f"Censys plugin error: {e}")
        
        return results
    
    def _is_valid_subdomain(self, name: str, domain: str) -> bool:
        """Validate if name is a valid subdomain of domain"""
        if not name or '*' in name:
            return False
        
        if name == domain or name.endswith('.' + domain):
            if re.match(r'^[a-zA-Z0-9.-]+$', name):
                return True
        
        return False

class SubdomainDatabase:
    """SQLite database for storing subdomain results"""
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            # Default to resources directory
            from pathlib import Path
            project_root = Path(__file__).parent.parent.parent
            db_path = project_root / "resources" / "subdomain_results.db"
        
        self.db_path = str(db_path)
        self._init_database()
    
    def _init_database(self):
        """Initialize database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables as per OSINT_domains.md schema
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name VARCHAR(255) NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(name)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS subdomains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain_id INTEGER,
                host VARCHAR(255) NOT NULL,
                ip VARCHAR(45),
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                status VARCHAR(50) DEFAULT 'discovered',
                FOREIGN KEY (domain_id) REFERENCES domains (id),
                UNIQUE(domain_id, host)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sub_id INTEGER,
                name VARCHAR(100) NOT NULL,
                detail TEXT,
                discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sub_id) REFERENCES subdomains (id)
            )
        ''')
        
        # Create indexes for performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_subdomains_host ON subdomains(host)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sources_name ON sources(name)')
        
        conn.commit()
        conn.close()
    
    def store_results(self, domain: str, results: List[SubdomainResult]) -> int:
        """Store enumeration results in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Get or create domain
            cursor.execute('INSERT OR IGNORE INTO domains (name) VALUES (?)', (domain,))
            cursor.execute('SELECT id FROM domains WHERE name = ?', (domain,))
            domain_id = cursor.fetchone()[0]
            
            stored_count = 0
            for result in results:
                # Insert or update subdomain
                cursor.execute('''
                    INSERT OR REPLACE INTO subdomains 
                    (domain_id, host, ip, first_seen, last_seen, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    domain_id, result.host, result.ip,
                    result.first_seen, result.last_seen, result.status
                ))
                
                # Get subdomain ID
                cursor.execute('SELECT id FROM subdomains WHERE domain_id = ? AND host = ?', 
                             (domain_id, result.host))
                sub_id = cursor.fetchone()[0]
                
                # Store source information
                cursor.execute('''
                    INSERT INTO sources (sub_id, name, detail)
                    VALUES (?, ?, ?)
                ''', (sub_id, result.source, json.dumps(result.raw_data) if result.raw_data else None))
                
                stored_count += 1
            
            conn.commit()
            return stored_count
        
        except Exception as e:
            logger.error(f"Database storage error: {e}")
            conn.rollback()
            return 0
        
        finally:
            conn.close()
    
    def get_domain_results(self, domain: str) -> List[SubdomainResult]:
        """Retrieve stored results for a domain"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT s.host, s.ip, s.first_seen, s.last_seen, s.status,
                       GROUP_CONCAT(src.name) as sources
                FROM domains d
                JOIN subdomains s ON d.id = s.domain_id
                LEFT JOIN sources src ON s.id = src.sub_id
                WHERE d.name = ?
                GROUP BY s.id
                ORDER BY s.host
            ''', (domain,))
            
            results = []
            for row in cursor.fetchall():
                host, ip, first_seen, last_seen, status, sources = row
                results.append(SubdomainResult(
                    host=host,
                    ip=ip,
                    first_seen=datetime.fromisoformat(first_seen) if first_seen else None,
                    last_seen=datetime.fromisoformat(last_seen) if last_seen else None,
                    status=status,
                    source=sources or ""
                ))
            
            return results
        
        except Exception as e:
            logger.error(f"Database retrieval error: {e}")
            return []
        
        finally:
            conn.close()

class DNSResolver:
    """DNS resolution and wildcard filtering"""
    
    def __init__(self, max_workers: int = 50, timeout: int = 5):
        self.max_workers = max_workers
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
    
    async def resolve_subdomains(self, subdomains: List[SubdomainResult]) -> List[SubdomainResult]:
        """Resolve IP addresses for subdomains"""
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            loop = asyncio.get_event_loop()
            
            # Create resolution tasks
            tasks = []
            for result in subdomains:
                task = loop.run_in_executor(executor, self._resolve_single, result)
                tasks.append(task)
            
            # Wait for all resolutions
            resolved_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter successful resolutions
            valid_results = []
            for result in resolved_results:
                if isinstance(result, SubdomainResult):
                    valid_results.append(result)
            
            return valid_results
    
    def _resolve_single(self, result: SubdomainResult) -> Optional[SubdomainResult]:
        """Resolve a single subdomain"""
        try:
            # Try A record first
            answers = self.resolver.resolve(result.host, 'A')
            if answers:
                result.ip = str(answers[0])
                result.status = "resolved"
                return result
        except:
            try:
                # Try AAAA record
                answers = self.resolver.resolve(result.host, 'AAAA')
                if answers:
                    result.ip = str(answers[0])
                    result.status = "resolved"
                    return result
            except:
                result.status = "unresolved"
                return result
        
        return result
    
    def filter_wildcards(self, results: List[SubdomainResult], domain: str) -> List[SubdomainResult]:
        """Filter out wildcard DNS entries"""
        
        # Test for wildcard by checking a random subdomain
        import random
        import string
        
        random_subdomain = ''.join(random.choices(string.ascii_lowercase, k=20)) + '.' + domain
        
        try:
            wildcard_answers = self.resolver.resolve(random_subdomain, 'A')
            wildcard_ips = {str(answer) for answer in wildcard_answers}
            
            # Filter results that match wildcard IPs
            filtered_results = []
            for result in results:
                if result.ip and result.ip not in wildcard_ips:
                    filtered_results.append(result)
                elif not result.ip:  # Keep unresolved for now
                    filtered_results.append(result)
                else:
                    result.status = "wildcard"
                    filtered_results.append(result)  # Keep but mark as wildcard
            
            return filtered_results
        
        except:
            # No wildcard detected, return all results
            return results

class SubdomainEnumerationEngine:
    """Main enumeration engine following OSINT_domains.md specifications"""
    
    def __init__(self):
        self.plugins = self._load_plugins()
        self.database = SubdomainDatabase()
        self.resolver = DNSResolver()
        self.api_keys = self._load_api_keys()
    
    def _load_plugins(self) -> Dict[str, SourcePlugin]:
        """Load available source plugins"""
        plugins = {
            'crtsh': CrtShPlugin(),
            'certspotter': CertSpotterPlugin(),
            'virustotal': VirusTotalPlugin(),
            'wayback': WaybackPlugin(),
            'censys': CensysPlugin()
        }
        return plugins
    
    def _load_api_keys(self) -> Dict[str, str]:
        """Load API keys from global settings"""
        try:
            from shared.configuration.global_settings import global_settings
            
            api_keys = {}
            
            # Load professional subdomain enumeration API keys
            if global_settings.get("api_keys.certspotter", "").strip():
                api_keys['certspotter'] = global_settings.get("api_keys.certspotter", "")
            
            if global_settings.get("api_keys.virustotal", "").strip():
                api_keys['virustotal'] = global_settings.get("api_keys.virustotal", "")
            
            if (global_settings.get("api_keys.censys_id", "").strip() and 
                global_settings.get("api_keys.censys_secret", "").strip()):
                api_keys['censys_id'] = global_settings.get("api_keys.censys_id", "")
                api_keys['censys_secret'] = global_settings.get("api_keys.censys_secret", "")
            
            if global_settings.get("api_keys.securitytrails", "").strip():
                api_keys['securitytrails'] = global_settings.get("api_keys.securitytrails", "")
            
            if global_settings.get("api_keys.binaryedge", "").strip():
                api_keys['binaryedge'] = global_settings.get("api_keys.binaryedge", "")
            
            if (global_settings.get("api_keys.passivetotal_user", "").strip() and
                global_settings.get("api_keys.passivetotal_key", "").strip()):
                api_keys['passivetotal_user'] = global_settings.get("api_keys.passivetotal_user", "")
                api_keys['passivetotal_key'] = global_settings.get("api_keys.passivetotal_key", "")
            
            if global_settings.get("api_keys.dnsdb", "").strip():
                api_keys['dnsdb'] = global_settings.get("api_keys.dnsdb", "")
            
            # Also load other OSINT keys for compatibility
            if global_settings.get("api_keys.shodan", "").strip():
                api_keys['shodan'] = global_settings.get("api_keys.shodan", "")
            
            return api_keys
            
        except ImportError:
            logger.warning("Global settings not available, using fallback API key loading")
            
        # Fallback to YAML file loading
        try:
            from pathlib import Path
            project_root = Path(__file__).parent.parent.parent
            config_path = project_root / "resources" / "config" / "api_keys.yaml"
            
            if config_path.exists():
                with open(config_path, 'r') as f:
                    return yaml.safe_load(f) or {}
        except Exception as e:
            logger.warning(f"Could not load API keys from YAML: {e}")
        
        return {}
    
    async def enumerate(self, domain: str, options: ScanOptions = None) -> Dict[str, Any]:
        """Main enumeration method"""
        
        if options is None:
            options = ScanOptions()
        
        logger.info(f"Starting subdomain enumeration for {domain}")
        start_time = time.time()
        
        # Filter plugins based on options
        active_plugins = {}
        for name, plugin in self.plugins.items():
            if name in options.sources and (not options.exclude_sources or name not in options.exclude_sources):
                # Set rate limiting
                if name in options.rate_limit_per_source:
                    plugin.set_rate_limiter(options.rate_limit_per_source[name])
                else:
                    plugin.set_rate_limiter(options.rate_limit)
                
                active_plugins[name] = plugin
        
        logger.info(f"Using {len(active_plugins)} plugins: {list(active_plugins.keys())}")
        
        # Run plugins concurrently
        all_results = []
        
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=options.timeout),
            connector=aiohttp.TCPConnector(limit=options.max_concurrent)
        ) as session:
            
            tasks = []
            for name, plugin in active_plugins.items():
                task = self._run_plugin_safe(plugin, domain, session, self.api_keys)
                tasks.append((name, task))
            
            # Collect results from all plugins
            for name, task in tasks:
                try:
                    plugin_results = await task
                    all_results.extend(plugin_results)
                    logger.info(f"Plugin {name}: found {len(plugin_results)} subdomains")
                except Exception as e:
                    logger.error(f"Plugin {name} failed: {e}")
        
        # Deduplicate results
        unique_results = self._deduplicate_results(all_results)
        logger.info(f"Total unique subdomains: {len(unique_results)}")
        
        # DNS resolution if requested
        if options.resolve_dns:
            logger.info("Resolving DNS records...")
            unique_results = await self.resolver.resolve_subdomains(unique_results)
        
        # Wildcard filtering if requested
        if options.filter_wildcards:
            logger.info("Filtering wildcards...")
            unique_results = self.resolver.filter_wildcards(unique_results, domain)
        
        # Store in database if requested
        if options.save_to_db:
            stored_count = self.database.store_results(domain, unique_results)
            logger.info(f"Stored {stored_count} results in database")
        
        # Generate statistics
        end_time = time.time()
        duration = end_time - start_time
        
        stats = self._generate_statistics(domain, unique_results, active_plugins, duration)
        
        return {
            'domain': domain,
            'results': unique_results,
            'statistics': stats,
            'options': asdict(options)
        }
    
    async def _run_plugin_safe(self, plugin: SourcePlugin, domain: str, 
                              session: aiohttp.ClientSession, api_keys: Dict[str, str]) -> List[SubdomainResult]:
        """Run plugin with error handling"""
        try:
            return await plugin.run(domain, session, api_keys)
        except Exception as e:
            logger.error(f"Plugin {plugin.name} error: {e}")
            return []
    
    def _deduplicate_results(self, results: List[SubdomainResult]) -> List[SubdomainResult]:
        """Remove duplicate subdomains, keeping the one with most information"""
        
        unique_map = {}
        
        for result in results:
            key = result.host.lower()
            
            if key not in unique_map:
                unique_map[key] = result
            else:
                # Keep the result with more information
                existing = unique_map[key]
                if (result.raw_data and not existing.raw_data) or \
                   (result.ip and not existing.ip):
                    # Merge sources
                    if existing.source and result.source:
                        result.source = f"{existing.source},{result.source}"
                    unique_map[key] = result
                else:
                    # Update existing with additional source
                    if result.source and result.source not in existing.source:
                        existing.source = f"{existing.source},{result.source}"
        
        return list(unique_map.values())
    
    def _generate_statistics(self, domain: str, results: List[SubdomainResult], 
                           plugins: Dict[str, SourcePlugin], duration: float) -> Dict[str, Any]:
        """Generate enumeration statistics"""
        
        # Count by source
        source_counts = {}
        status_counts = {}
        
        for result in results:
            # Count sources
            sources = result.source.split(',') if result.source else ['unknown']
            for source in sources:
                source = source.strip()
                source_counts[source] = source_counts.get(source, 0) + 1
            
            # Count statuses
            status_counts[result.status] = status_counts.get(result.status, 0) + 1
        
        # Count subdomain levels
        level_counts = {}
        for result in results:
            level = len(result.host.split('.')) - len(domain.split('.'))
            level_key = f"Level {level}"
            level_counts[level_key] = level_counts.get(level_key, 0) + 1
        
        return {
            'total_subdomains': len(results),
            'duration_seconds': round(duration, 2),
            'plugins_used': list(plugins.keys()),
            'source_breakdown': source_counts,
            'status_breakdown': status_counts,
            'level_breakdown': level_counts,
            'resolved_count': len([r for r in results if r.ip]),
            'unique_ips': len(set(r.ip for r in results if r.ip))
        }

# Global instance
subdomain_engine = SubdomainEnumerationEngine()