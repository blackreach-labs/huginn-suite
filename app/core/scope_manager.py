# app/core/scope_manager.py
import ipaddress
import re
from typing import List, Set, Tuple, Optional

class ScopeManager:
    """Manages engagement scope and validates targets against defined scope"""
    
    def __init__(self):
        self.in_scope_domains: Set[str] = set()
        self.in_scope_ips: Set[str] = set()
        self.in_scope_networks: List[ipaddress.IPv4Network] = []
        self.out_of_scope_domains: Set[str] = set()
        self.out_of_scope_ips: Set[str] = set()
        self.out_of_scope_networks: List[ipaddress.IPv4Network] = []
    
    def update_scope(self, in_scope_text: str, out_of_scope_text: str = ""):
        """Update scope from text input"""
        self.clear_scope()
        self._parse_scope_text(in_scope_text, is_in_scope=True)
        if out_of_scope_text:
            self._parse_scope_text(out_of_scope_text, is_in_scope=False)
    
    def clear_scope(self):
        """Clear all scope definitions"""
        self.in_scope_domains.clear()
        self.in_scope_ips.clear()
        self.in_scope_networks.clear()
        self.out_of_scope_domains.clear()
        self.out_of_scope_ips.clear()
        self.out_of_scope_networks.clear()
    
    def _parse_scope_text(self, text: str, is_in_scope: bool = True):
        """Parse scope text and extract domains, IPs, and networks"""
        if not text:
            return
        
        # Split by common separators
        items = re.split(r'[,;\n\r\s]+', text.strip())
        
        for item in items:
            item = item.strip()
            if not item:
                continue
            
            # Check if it's a network (CIDR notation)
            if '/' in item:
                try:
                    network = ipaddress.IPv4Network(item, strict=False)
                    if is_in_scope:
                        self.in_scope_networks.append(network)
                    else:
                        self.out_of_scope_networks.append(network)
                    continue
                except:
                    pass
            
            # Check if it's an IP address
            try:
                ipaddress.IPv4Address(item)
                if is_in_scope:
                    self.in_scope_ips.add(item)
                else:
                    self.out_of_scope_ips.add(item)
                continue
            except:
                pass
            
            # Treat as domain
            if is_in_scope:
                self.in_scope_domains.add(item.lower())
            else:
                self.out_of_scope_domains.add(item.lower())
    
    def is_target_in_scope(self, target: str) -> Tuple[bool, str]:
        """Check if target is in scope. Returns (is_in_scope, reason)
        
        Scope matching rules:
        - If 10.10.11.221 is configured, then 10.10.11.221/* is in scope
        - If example.com is configured, then example.com/* is in scope
        """
        target = target.strip().lower()
        
        # Extract base target (remove path/port if present)
        base_target = target.split('/')[0].split(':')[0]
        
        # Check explicit out-of-scope first
        if base_target in self.out_of_scope_domains:
            return False, f"Domain '{base_target}' is explicitly out of scope"
        
        if base_target in self.out_of_scope_ips:
            return False, f"IP '{base_target}' is explicitly out of scope"
        
        # Check if IP is in out-of-scope networks
        try:
            ip = ipaddress.IPv4Address(base_target)
            for network in self.out_of_scope_networks:
                if ip in network:
                    return False, f"IP '{base_target}' is in out-of-scope network {network}"
        except:
            pass
        
        # Check in-scope domains (including wildcard matching)
        for domain in self.in_scope_domains:
            # Exact match or wildcard match (domain includes domain/*)
            if base_target == domain or target.startswith(domain + '/'):
                return True, f"Target '{target}' matches scope '{domain}/*'"
            # Subdomain match
            if domain.startswith('*.') and base_target.endswith(domain[2:]):
                return True, f"Domain '{base_target}' matches wildcard scope '{domain}'"
            elif base_target.endswith('.' + domain):
                return True, f"Domain '{base_target}' is subdomain of in-scope '{domain}'"
        
        # Check in-scope IPs (including wildcard matching)
        for ip in self.in_scope_ips:
            # Exact match or wildcard match (IP includes IP/*)
            if base_target == ip or target.startswith(ip + '/'):
                return True, f"Target '{target}' matches scope '{ip}/*'"
        
        # Check if IP is in in-scope networks
        try:
            ip = ipaddress.IPv4Address(base_target)
            for network in self.in_scope_networks:
                if ip in network:
                    return True, f"IP '{target}' is in scope network {network}"
        except:
            pass
        
        # If no scope defined, allow everything
        if not (self.in_scope_domains or self.in_scope_ips or self.in_scope_networks):
            return True, "No scope restrictions defined"
        
        return False, f"Target '{target}' is not in defined scope"
    
    def get_scope_summary(self) -> str:
        """Get a summary of current scope"""
        summary = []
        
        if self.in_scope_domains:
            summary.append(f"Domains: {', '.join(sorted(self.in_scope_domains))}")
        
        if self.in_scope_ips:
            summary.append(f"IPs: {', '.join(sorted(self.in_scope_ips))}")
        
        if self.in_scope_networks:
            summary.append(f"Networks: {', '.join(str(n) for n in self.in_scope_networks)}")
        
        return "; ".join(summary) if summary else "No scope defined"

# Global scope manager instance
scope_manager = ScopeManager()