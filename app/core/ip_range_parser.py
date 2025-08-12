# app/core/ip_range_parser.py
import ipaddress
import re
from typing import List, Iterator

class IPRangeParser:
    """Parse and normalize IP address ranges for scanning"""
    
    RESERVED_RANGES = [
        '127.0.0.0/8',      # Loopback
        '169.254.0.0/16',   # APIPA
        '224.0.0.0/4',      # Multicast
        '255.255.255.255/32' # Broadcast
    ]
    
    @staticmethod
    def parse_target(target: str) -> List[str]:
        """Parse target string into list of IP addresses"""
        if not target.strip():
            return []
        
        ips = []
        # Split by comma for multiple targets
        for part in target.split(','):
            part = part.strip()
            if not part:
                continue
            ips.extend(IPRangeParser._parse_single_target(part))
        
        # Filter reserved ranges and deduplicate
        return sorted(set(ip for ip in ips if not IPRangeParser._is_reserved(ip)))
    
    @staticmethod
    def _parse_single_target(target: str) -> List[str]:
        """Parse single target format"""
        # CIDR notation (192.168.1.0/24)
        if '/' in target:
            return IPRangeParser._parse_cidr(target)
        
        # Wildcard notation (192.168.*.*)
        if '*' in target:
            return IPRangeParser._parse_wildcard(target)
        
        # Range notation (192.168.1.1-10 or 192.168.1.1-192.168.1.10)
        if '-' in target:
            return IPRangeParser._parse_range(target)
        
        # Single IP or network address
        try:
            ip = ipaddress.ip_address(target)
            # Check if it's a network address (ends in .0)
            if str(ip).endswith('.0'):
                # Treat as /24 network
                return IPRangeParser._parse_cidr(f"{target}/24")
            return [target]
        except:
            return []
    
    @staticmethod
    def _parse_cidr(cidr: str) -> List[str]:
        """Parse CIDR notation"""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            if network.num_addresses == 1:  # /32
                return [str(network.network_address)]
            return [str(ip) for ip in network.hosts()]  # Excludes network/broadcast
        except:
            return []
    
    @staticmethod
    def _parse_wildcard(target: str) -> List[str]:
        """Parse wildcard notation (192.168.*.*)"""
        try:
            # Replace wildcards with 0 and calculate CIDR bits
            base = target.replace('*', '0')
            wildcard_parts = target.split('.')
            wildcard_count = wildcard_parts.count('*')
            
            if wildcard_count == 0 or wildcard_count > 4:
                return []
            
            # Calculate CIDR bits: 32 - (8 * wildcards)
            wildcard_bits = 32 - (8 * wildcard_count)
            cidr = f"{base}/{wildcard_bits}"
            
            return IPRangeParser._parse_cidr(cidr)
        except:
            return []
    
    @staticmethod
    def _parse_range(target: str) -> List[str]:
        """Parse range notation"""
        try:
            start, end = target.split('-', 1)
            start = start.strip()
            end = end.strip()
            
            # Short range (192.168.1.1-10)
            if '.' not in end:
                base_parts = start.split('.')
                if len(base_parts) == 4:
                    base = '.'.join(base_parts[:3])
                    start_num = int(base_parts[3])
                    end_num = int(end)
                    
                    # Validate octet boundaries
                    if not (0 <= start_num <= 255 and 0 <= end_num <= 255):
                        return []
                    
                    return [f"{base}.{i}" for i in range(start_num, end_num + 1)]
            
            # Full range (192.168.1.1-192.168.1.10)
            start_ip = ipaddress.ip_address(start)
            end_ip = ipaddress.ip_address(end)
            
            if start_ip > end_ip:
                return []
            
            ips = []
            current = int(start_ip)
            end_int = int(end_ip)
            
            while current <= end_int:
                ips.append(str(ipaddress.ip_address(current)))
                current += 1
                if len(ips) > 65536:  # Safety limit
                    break
            
            return ips
        except:
            return []
    
    @staticmethod
    def _is_reserved(ip: str) -> bool:
        """Check if IP is in reserved range"""
        try:
            ip_addr = ipaddress.ip_address(ip)
            for reserved in IPRangeParser.RESERVED_RANGES:
                if ip_addr in ipaddress.ip_network(reserved):
                    return True
            return False
        except:
            return True  # Invalid IPs are considered reserved

    @staticmethod
    def parse_targets_bulk(targets: List[str]) -> List[str]:
        """Parse multiple target strings into deduplicated IP list"""
        all_ips = []
        for target in targets:
            all_ips.extend(IPRangeParser.parse_target(target))
        return sorted(set(all_ips))

# Convenience functions
def parse_ip_range(target: str) -> List[str]:
    """Parse IP range string into list of IPs"""
    return IPRangeParser.parse_target(target)

def parse_ip_ranges_bulk(targets: List[str]) -> List[str]:
    """Parse multiple IP range strings into deduplicated list"""
    return IPRangeParser.parse_targets_bulk(targets)