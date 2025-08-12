# app/tools/dns_scanner.py
import dns.resolver
import socket
from collections import defaultdict
from ..core.dns_data_collector import create_dns_collector

def run_dns_scan(target, wordlist_path=None, record_types=None, dns_server=None, tenant_id="default"):
    """
    Run DNS scan and return structured data for both text and tree views
    
    Returns:
        dict: Structured DNS results with domains as keys and record types as nested dict
    """
    if not record_types:
        record_types = ['A']
    
    # Get DNS server from global settings if not provided
    if dns_server is None:
        from app.core.dns_settings import dns_settings
        dns_server = dns_settings.get_current_dns()
        if dns_server == "Default DNS":
            dns_server = None
    
    # Initialize centralized data collector
    data_collector = create_dns_collector(tenant_id)
    scan_id = data_collector.start_dns_scan(
        target=target,
        scanner="dns_enumerator",
        scan_subtype="subdomain_enumeration" if wordlist_path else "record_lookup"
    )
    
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
    
    results = defaultdict(lambda: defaultdict(list))
    
    # Read wordlist if provided
    subdomains = []
    if wordlist_path:
        try:
            with open(wordlist_path, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            subdomains = ['www', 'mail', 'ftp', 'admin', 'test']
    else:
        subdomains = ['www', 'mail', 'ftp', 'admin', 'test']
    
    # Collect DNS records for centralized storage
    dns_records = []
    discovered_subdomains = []
    
    # Query the main domain first for all record types
    for record_type in record_types:
        if record_type == 'SRV':
            continue
        try:
            if record_type == 'A':
                for rtype in ['A', 'AAAA']:
                    try:
                        answers = resolver.resolve(target, rtype)
                        values = [r.address for r in answers]
                        if values:
                            results[target][rtype].extend(values)
                            # Collect for centralized storage
                            for value in values:
                                dns_records.append({
                                    'type': rtype,
                                    'name': target,
                                    'value': value,
                                    'ttl': answers.rrset.ttl if hasattr(answers, 'rrset') else 0
                                })
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                        continue
            else:
                answers = resolver.resolve(target, record_type)
                if record_type == 'MX':
                    values = [f"{r.preference} {r.exchange.to_text().rstrip('.')}" for r in answers]
                elif record_type == 'NS':
                    values = [r.target.to_text().rstrip('.') for r in answers]
                elif record_type == 'TXT':
                    values = [b''.join(r.strings).decode('utf-8', errors='ignore').replace('"', '') for r in answers]
                elif record_type == 'CNAME':
                    values = [r.target.to_text().rstrip('.') for r in answers]
                elif record_type == 'PTR':
                    values = [r.target.to_text().rstrip('.') for r in answers]
                else:
                    values = [r.to_text() for r in answers]
                
                if values:
                    results[target][record_type].extend(values)
                    # Collect for centralized storage
                    for value in values:
                        dns_records.append({
                            'type': record_type,
                            'name': target,
                            'value': value,
                            'ttl': answers.rrset.ttl if hasattr(answers, 'rrset') else 0
                        })
                    
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except Exception:
            continue
    
    # Scan each subdomain only if wordlist is provided
    if wordlist_path:
        for subdomain in subdomains:
            domain = f"{subdomain}.{target}"
            
            for record_type in record_types:
                try:
                    if record_type == 'A':
                        # Query both A and AAAA for 'A' type
                        for rtype in ['A', 'AAAA']:
                            try:
                                answers = resolver.resolve(domain, rtype)
                                values = [r.address for r in answers]
                                if values:
                                    results[domain][rtype].extend(values)
                                    discovered_subdomains.append(domain)
                                    # Collect for centralized storage
                                    for value in values:
                                        dns_records.append({
                                            'type': rtype,
                                            'name': domain,
                                            'value': value,
                                            'ttl': answers.rrset.ttl if hasattr(answers, 'rrset') else 0
                                        })
                            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                                continue
                    elif record_type == 'SRV':
                        # Handle SRV records separately with service wordlist
                        continue  # Skip SRV in regular subdomain scan
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
                        elif record_type == 'PTR':
                            values = [r.target.to_text().rstrip('.') for r in answers]
                        else:
                            values = [r.to_text() for r in answers]
                        
                        if values:
                            results[domain][record_type].extend(values)
                            # Collect for centralized storage
                            for value in values:
                                dns_records.append({
                                    'type': record_type,
                                    'name': domain,
                                    'value': value,
                                    'ttl': answers.rrset.ttl if hasattr(answers, 'rrset') else 0
                                })
                            
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    continue
                except Exception:
                    continue
    

    # Store data in centralized system
    if discovered_subdomains:
        data_collector.collect_subdomains(target, list(set(discovered_subdomains)))
    
    if dns_records:
        data_collector.collect_dns_records(target, dns_records)
    
    # Complete scan
    total_results = len(discovered_subdomains) + len(dns_records)
    data_collector.complete_dns_scan(total_results=total_results)
    
    return dict(results)