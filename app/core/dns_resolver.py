# app/core/dns_resolver.py
import socket
import ipaddress

class DNSResolver:
    def __init__(self):
        pass
    
    def resolve_hostname(self, hostname):
        """Resolve hostname using global DNS configuration"""
        # Check if it's already an IP address
        try:
            ipaddress.ip_address(hostname)
            return hostname  # Already an IP
        except ValueError:
            pass
        
        # Get global DNS configuration from settings
        try:
            import json
            import os
            dns_file = os.path.join(os.path.dirname(__file__), '..', '..', 'resources', 'config', 'dns_settings.json')
            if os.path.exists(dns_file):
                with open(dns_file, 'r') as f:
                    dns_config = json.load(f)
                dns_server = dns_config.get('current_dns')
            else:
                dns_server = None
            use_local_dns = (dns_server == 'LocalDNS')
        except Exception as e:
            dns_server = None
            use_local_dns = False
        
        if use_local_dns:
            # Query local DNS database
            return self._query_local_dns(hostname)
        elif dns_server:
            # Use custom DNS server
            return self._resolve_with_dns(hostname, dns_server)
        else:
            # Use system DNS
            return self._resolve_system_dns(hostname)
    
    def _query_local_dns(self, hostname):
        """Query local DNS database"""
        try:
            import json
            import os
            
            # Load local DNS records from JSON file
            dns_file = os.path.join(os.path.dirname(__file__), '..', '..', 'resources', 'config', 'local_dns_records.json')
            
            if os.path.exists(dns_file):
                with open(dns_file, 'r') as f:
                    dns_records = json.load(f)
                
                if hostname in dns_records and 'A' in dns_records[hostname]:
                    resolved_ip = dns_records[hostname]['A'][0]
                    return resolved_ip
            else:
                pass
                
        except Exception as e:
            pass
        # Fallback to system DNS
        return self._resolve_system_dns(hostname)
    
    def _resolve_with_dns(self, hostname, dns_server):
        """Resolve using custom DNS server"""
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [dns_server]
            answers = resolver.resolve(hostname, 'A')
            if answers:
                return str(answers[0])
        except ImportError:
            pass
        except Exception:
            pass
        
        # Fallback to system DNS
        return self._resolve_system_dns(hostname)
    
    def _resolve_system_dns(self, hostname):
        """Resolve using system DNS"""
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None

# Global DNS resolver instance
dns_resolver = DNSResolver()