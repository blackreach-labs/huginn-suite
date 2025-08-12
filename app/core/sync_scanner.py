# app/core/sync_scanner.py
import dns.resolver
from concurrent.futures import ThreadPoolExecutor
import threading

def enumerate_hostnames_sync(target, wordlist_path, record_types):
    """Synchronous DNS enumeration for multi-target scanning"""
    results = {}
    
    try:
        # Get DNS server from global settings
        from app.core.dns_settings import dns_settings
        dns_server = dns_settings.get_current_dns()
        if dns_server == "Default DNS":
            dns_server = None
        
        # Setup resolver with global DNS server
        resolver = dns.resolver.Resolver()
        if dns_server:
            if dns_server.lower() == 'localdns':
                from app.core.local_dns_server import local_dns_server
                resolver.nameservers = ['127.0.0.1']
                resolver.port = local_dns_server.port if local_dns_server.running else 53530
            else:
                # Resolve FQDN to IP if needed
                import socket
                import re
                ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
                if re.match(ip_pattern, dns_server):
                    resolver.nameservers = [dns_server]
                else:
                    try:
                        dns_ip = socket.gethostbyname(dns_server)
                        resolver.nameservers = [dns_ip]
                    except socket.gaierror:
                        resolver.nameservers = [dns_server]
        
        # Read wordlist
        with open(wordlist_path, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]
        
        # Limit to prevent overwhelming
        subdomains = subdomains[:500]
        
        def query_subdomain(subdomain):
            hostname = f"{subdomain}.{target}"
            subdomain_results = {}
            
            for record_type in record_types:
                try:
                    answers = resolver.resolve(hostname, record_type)
                    subdomain_results[record_type] = [str(answer) for answer in answers]
                except:
                    continue
            
            return hostname, subdomain_results
        
        # Use limited threading for sync operation
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(query_subdomain, sub) for sub in subdomains[:100]]
            
            for future in futures:
                try:
                    hostname, subdomain_results = future.result(timeout=5)
                    if subdomain_results:
                        results[hostname] = subdomain_results
                except:
                    continue
    
    except Exception as e:
        return {'error': str(e)}
    
    return results