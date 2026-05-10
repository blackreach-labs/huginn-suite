# app/core/kerberos_auth.py
import os
import subprocess
import tempfile
from typing import Optional, Dict, Any
from app.core.logger import logger

class KerberosAuth:
    """Minimal Kerberos authentication for RPC enumeration"""
    
    def __init__(self):
        self.ccache_path = None
        self.ticket_cache = {}
    
    def authenticate_with_ticket(self, ticket_path: str, target: str) -> bool:
        """Authenticate using Kerberos ticket file"""
        try:
            if not os.path.exists(ticket_path):
                return False
            
            # Set KRB5CCNAME environment variable
            os.environ['KRB5CCNAME'] = ticket_path
            self.ccache_path = ticket_path
            
            # Test authentication with klist
            result = subprocess.run(['klist'], capture_output=True, text=True, timeout=10)
            return result.returncode == 0 and 'krbtgt' in result.stdout.lower()
            
        except Exception:
            return False
    
    def authenticate_with_password(self, username: str, password: str, domain: str, target: str = None) -> bool:
        """Authenticate using username/password with Kerberos"""
        try:
            # For Kerberos, authenticate against the target using domain credentials
            if target:
                # Use same DNS resolution as RPC scanner
                import socket
                try:
                    socket.inet_aton(target)
                    target_ip = target  # Already an IP
                except socket.error:
                    try:
                        from ..core.dns_settings import dns_settings
                        current_dns = dns_settings.get_current_dns()
                        
                        if current_dns == "LocalDNS":
                            local_dns_port = getattr(dns_settings, 'local_dns_port', 53530)
                            target_ip = self._query_local_dns(target, local_dns_port)
                            if not target_ip:
                                target_ip = socket.gethostbyname(target)
                        elif current_dns != "Default DNS":
                            target_ip = self._query_dns_server(target, current_dns)
                            if not target_ip:
                                target_ip = socket.gethostbyname(target)
                        else:
                            target_ip = socket.gethostbyname(target)
                    except:
                        target_ip = target
                # If DNS resolution failed, skip Kerberos (need hostname for Kerberos)
                if target_ip == target and not self._is_ip_address(target):
                    return False
                
                # Try different credential formats for Kerberos
                auth_formats = [
                    f'{domain}\\{username}',  # DOMAIN\username
                    f'{username}@{domain}',   # username@DOMAIN
                    username                   # just username
                ]
                
                # For Kerberos, use hostname only (IP would use NTLM)
                targets_to_try = [target]
                
                for test_target in targets_to_try:
                    for auth_user in auth_formats:
                        try:
                            cmd = ['net', 'use', f'\\\\{test_target}\\IPC$', f'/user:{auth_user}', password]
                            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                            

                            
                            if result.returncode == 0:
                                # Clean up the connection
                                subprocess.run(['net', 'use', f'\\\\{test_target}\\IPC$', '/delete'], 
                                             capture_output=True, text=True, timeout=5)
                                return True
                        except:
                            continue
            
            return False
            
        except Exception:
            return False
    
    def _resolve_target(self, target: str) -> str:
        """Resolve hostname using LocalDNS if configured"""
        try:
            import socket
            # Check if target is already an IP address
            socket.inet_aton(target)
            return target  # Already an IP
        except socket.error as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        
        try:
            # Try LocalDNS first if available
            from ..core.dns_settings import dns_settings
            current_dns = dns_settings.get_current_dns()

            
            if current_dns == "LocalDNS":
                # Query LocalDNS server
                local_dns_port = getattr(dns_settings, 'local_dns_port', 53530)

                resolved_ip = self._query_local_dns(target, local_dns_port)

                if resolved_ip:
                    return resolved_ip
            elif current_dns != "Default DNS":
                # Use specific DNS server IP
                resolved_ip = self._query_dns_server(target, current_dns)
                if resolved_ip:
                    return resolved_ip
            # Fallback to system DNS
            try:
                return socket.gethostbyname(target)
            except Exception as e:
                # If all DNS fails, check if it's already an IP
                return target
        except:
            return target
    
    def _query_local_dns(self, hostname: str, dns_port: int) -> str:
        """Query local DNS server"""
        try:
            import socket
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
            sock.sendto(dns_query, ('127.0.0.1', dns_port))
            
            response, _ = sock.recvfrom(512)
            sock.close()
            
            # Parse response - handle multiple A records
            if len(response) > 12:
                import struct
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
    
    def _query_dns_server(self, hostname: str, dns_server: str) -> str:
        """Query specific DNS server"""
        try:
            import socket
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
                import struct
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
    
    def _is_ip_address(self, target: str) -> bool:
        """Check if target is an IP address"""
        try:
            import socket
            socket.inet_aton(target)
            return True
        except:
            return False
    
    def get_service_ticket(self, service: str, target: str) -> Optional[str]:
        """Get service ticket for specific service"""
        try:
            if not self.ccache_path:
                return None
            
            spn = f"{service}/{target}"
            cmd = ['kvno', spn]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                self.ticket_cache[spn] = True
                return spn
            
            return None
            
        except Exception:
            return None
    
    def cleanup(self):
        """Clean up temporary files"""
        if self.ccache_path and os.path.exists(self.ccache_path):
            try:
                os.unlink(self.ccache_path)
            except Exception as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        
        if 'KRB5CCNAME' in os.environ:
            del os.environ['KRB5CCNAME']