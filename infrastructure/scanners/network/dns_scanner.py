"""DNS scanner implementation using the new architecture."""
import dns.resolver
import socket
from typing import Dict, Any, List, Optional
from collections import defaultdict

from infrastructure.scanners.base.base_scanner import BaseScanner
from shared.configuration.config_manager import ConfigManager
from shared.exceptions.scanner_exceptions import NetworkException


class DNSScanner(BaseScanner):
    """DNS enumeration scanner implementation."""
    
    def __init__(self, target: str, config: Optional[Dict[str, Any]] = None):
        super().__init__(target, config)
        self.config_manager = ConfigManager()
        self.scanner_config = self.config_manager.get_scanner_config()
        
        # Scanner-specific configuration
        self.record_types = config.get('record_types', ['A', 'AAAA', 'MX', 'NS', 'TXT'])
        self.wordlist_path = config.get('wordlist_path')
        self.dns_server = config.get('dns_server')
        self.timeout = config.get('timeout', 5)
        
        # Setup DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = self.timeout
        self._configure_dns_server()
    
    def get_scanner_type(self) -> str:
        """Get scanner type identifier."""
        return "dns_scanner"
    
    def _configure_dns_server(self):
        """Configure DNS server for resolver."""
        if self.dns_server:
            if self.dns_server.lower() == 'localdns':
                from app.core.local_dns_server import local_dns_server
                self.resolver.nameservers = ['127.0.0.1']
                self.resolver.port = local_dns_server.port if local_dns_server.running else 53530
            else:
                # Resolve FQDN to IP if needed
                import re
                ip_pattern = r'^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$'
                if re.match(ip_pattern, self.dns_server):
                    self.resolver.nameservers = [self.dns_server]
                else:
                    try:
                        dns_ip = socket.gethostbyname(self.dns_server)
                        self.resolver.nameservers = [dns_ip]
                    except socket.gaierror:
                        self.resolver.nameservers = [self.dns_server]
    
    async def scan(self) -> 'ScanResult':
        """Perform DNS scan."""
        try:
            results = defaultdict(lambda: defaultdict(list))
            dns_records = []
            discovered_subdomains = []
            
            # Query main domain
            main_records = await self._query_domain(self.target)
            if main_records:
                results[self.target] = main_records
                dns_records.extend(self._format_records(self.target, main_records))
            
            # Subdomain enumeration if wordlist provided
            if self.wordlist_path:
                subdomains = self._load_wordlist()
                for subdomain in subdomains:
                    domain = f"{subdomain}.{self.target}"
                    subdomain_records = await self._query_domain(domain)
                    if subdomain_records:
                        results[domain] = subdomain_records
                        discovered_subdomains.append(domain)
                        dns_records.extend(self._format_records(domain, subdomain_records))
            
            scan_data = {
                'target': self.target,
                'dns_records': dns_records,
                'discovered_subdomains': discovered_subdomains,
                'record_types_queried': self.record_types,
                'total_records': len(dns_records),
                'total_subdomains': len(discovered_subdomains),
                'results': dict(results)
            }
            
            return self._create_result(scan_data)
            
        except Exception as e:
            raise NetworkException(f"DNS scan failed: {e}")
    
    async def _query_domain(self, domain: str) -> Dict[str, List[str]]:
        """Query a domain for all configured record types."""
        records = defaultdict(list)
        
        for record_type in self.record_types:
            try:
                if record_type == 'A':
                    # Query both A and AAAA for 'A' type
                    for rtype in ['A', 'AAAA']:
                        values = self._query_record_type(domain, rtype)
                        if values:
                            records[rtype].extend(values)
                else:
                    values = self._query_record_type(domain, record_type)
                    if values:
                        records[record_type].extend(values)
            except Exception:
                continue
        
        return dict(records) if records else {}
    
    def _query_record_type(self, domain: str, record_type: str) -> List[str]:
        """Query a specific record type for a domain."""
        try:
            answers = self.resolver.resolve(domain, record_type)
            
            if record_type in ['A', 'AAAA']:
                return [r.address for r in answers]
            elif record_type == 'MX':
                return [f"{r.preference} {r.exchange.to_text().rstrip('.')}" for r in answers]
            elif record_type == 'NS':
                return [r.target.to_text().rstrip('.') for r in answers]
            elif record_type == 'TXT':
                return [b''.join(r.strings).decode('utf-8', errors='ignore').replace('"', '') for r in answers]
            elif record_type == 'CNAME':
                return [r.target.to_text().rstrip('.') for r in answers]
            elif record_type == 'PTR':
                return [r.target.to_text().rstrip('.') for r in answers]
            else:
                return [r.to_text() for r in answers]
                
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, Exception):
            return []
    
    def _load_wordlist(self) -> List[str]:
        """Load subdomain wordlist."""
        if not self.wordlist_path:
            return ['www', 'mail', 'ftp', 'admin', 'test']
        
        try:
            with open(self.wordlist_path, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            return ['www', 'mail', 'ftp', 'admin', 'test']
    
    def _format_records(self, domain: str, records: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        """Format records for centralized storage."""
        formatted_records = []
        for record_type, values in records.items():
            for value in values:
                formatted_records.append({
                    'type': record_type,
                    'name': domain,
                    'value': value,
                    'ttl': 0  # TTL not available in this simplified version
                })
        return formatted_records


class DNSZoneTransferScanner(BaseScanner):
    """DNS zone transfer scanner implementation."""
    
    def __init__(self, target: str, config: Optional[Dict[str, Any]] = None):
        super().__init__(target, config)
        self.timeout = config.get('timeout', 10)
    
    def get_scanner_type(self) -> str:
        """Get scanner type identifier."""
        return "dns_zone_transfer_scanner"
    
    async def scan(self) -> 'ScanResult':
        """Perform DNS zone transfer scan."""
        try:
            zone_data = []
            nameservers = self._get_nameservers()
            
            for ns in nameservers:
                try:
                    zone_records = self._attempt_zone_transfer(ns)
                    if zone_records:
                        zone_data.extend(zone_records)
                except Exception:
                    continue
            
            scan_data = {
                'target': self.target,
                'nameservers_tested': nameservers,
                'zone_transfer_successful': len(zone_data) > 0,
                'zone_records': zone_data,
                'total_records': len(zone_data)
            }
            
            return self._create_result(scan_data)
            
        except Exception as e:
            raise NetworkException(f"DNS zone transfer scan failed: {e}")
    
    def _get_nameservers(self) -> List[str]:
        """Get nameservers for the target domain."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            answers = resolver.resolve(self.target, 'NS')
            return [r.target.to_text().rstrip('.') for r in answers]
        except Exception:
            return []
    
    def _attempt_zone_transfer(self, nameserver: str) -> List[Dict[str, Any]]:
        """Attempt zone transfer from a nameserver."""
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(nameserver, self.target))
            records = []
            
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        records.append({
                            'name': str(name),
                            'type': dns.rdatatype.to_text(rdataset.rdtype),
                            'value': str(rdata),
                            'ttl': rdataset.ttl
                        })
            
            return records
        except Exception:
            return []


# Register scanners with factory
from infrastructure.scanners.base.scanner_factory import ScannerFactory

ScannerFactory.register_scanner("dns_scanner", DNSScanner)
ScannerFactory.register_scanner("dns_zone_transfer_scanner", DNSZoneTransferScanner)