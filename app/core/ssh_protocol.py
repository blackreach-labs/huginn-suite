# app/core/ssh_protocol.py
import socket
import struct
import hashlib
import hmac
import time
from typing import Dict, List, Optional, Tuple
from app.core.logger import logger

class SSHProtocol:
    """Low-level SSH protocol implementation for advanced reconnaissance"""
    
    def __init__(self, target: str, port: int = 22, timeout: int = 10):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.server_version = None
        self.kex_algorithms = {}
        
    def connect(self) -> bool:
        """Establish TCP connection to SSH server"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.target, self.port))
            return True
        except Exception:
            return False
    
    def disconnect(self):
        """Close connection"""
        if self.sock:
            try:
                self.sock.close()
            except Exception as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
            self.sock = None
    
    def read_banner(self) -> Optional[str]:
        """Read SSH server banner"""
        try:
            if not self.sock:
                return None
            banner = self.sock.recv(1024).decode('utf-8', errors='ignore').strip()
            self.server_version = banner
            return banner
        except Exception:
            return None
    
    def send_client_version(self, version: str = "SSH-2.0-HugginSSH_1.0") -> bool:
        """Send client version string"""
        try:
            if not self.sock:
                return False
            self.sock.send(f"{version}\r\n".encode())
            return True
        except Exception:
            return False
    
    def perform_key_exchange(self) -> Dict:
        """Perform SSH key exchange to enumerate algorithms"""
        try:
            if not self.sock:
                return {}
            
            # Send KEXINIT packet
            kex_packet = self._build_kexinit_packet()
            self._send_packet(kex_packet)
            
            # Receive server KEXINIT
            server_kex = self._receive_packet()
            if server_kex:
                return self._parse_kexinit(server_kex)
            
            return {}
        except Exception:
            return {}
    
    def _build_kexinit_packet(self) -> bytes:
        """Build SSH KEXINIT packet"""
        # SSH packet structure: length + padding_length + payload + padding
        
        # KEXINIT payload
        payload = bytearray()
        payload.append(20)  # SSH_MSG_KEXINIT
        payload.extend(b'\x00' * 16)  # Random bytes (simplified)
        
        # Algorithm lists (simplified - common algorithms)
        algorithms = [
            "diffie-hellman-group14-sha256,ecdh-sha2-nistp256",  # kex
            "rsa-sha2-512,rsa-sha2-256,ssh-ed25519",  # server_host_key
            "aes128-ctr,aes192-ctr,aes256-ctr",  # encryption_client_to_server
            "aes128-ctr,aes192-ctr,aes256-ctr",  # encryption_server_to_client
            "hmac-sha2-256,hmac-sha2-512",  # mac_client_to_server
            "hmac-sha2-256,hmac-sha2-512",  # mac_server_to_client
            "none,zlib@openssh.com",  # compression_client_to_server
            "none,zlib@openssh.com",  # compression_server_to_client
            "",  # languages_client_to_server
            ""   # languages_server_to_client
        ]
        
        for alg_list in algorithms:
            alg_bytes = alg_list.encode()
            payload.extend(struct.pack('>I', len(alg_bytes)))
            payload.extend(alg_bytes)
        
        # Flags
        payload.append(0)  # first_kex_packet_follows
        payload.extend(b'\x00' * 4)  # reserved
        
        return bytes(payload)
    
    def _send_packet(self, payload: bytes):
        """Send SSH packet with proper framing"""
        if not self.sock:
            return
        
        # Calculate padding
        padding_length = 8 - (len(payload) + 1) % 8
        if padding_length < 4:
            padding_length += 8
        
        # Build packet
        packet = bytearray()
        packet.extend(struct.pack('>I', len(payload) + padding_length + 1))
        packet.append(padding_length)
        packet.extend(payload)
        packet.extend(b'\x00' * padding_length)
        
        self.sock.send(packet)
    
    def _receive_packet(self) -> Optional[bytes]:
        """Receive SSH packet"""
        try:
            if not self.sock:
                return None
            
            # Read packet length
            length_data = self.sock.recv(4)
            if len(length_data) != 4:
                return None
            
            packet_length = struct.unpack('>I', length_data)[0]
            if packet_length > 35000:  # Sanity check
                return None
            
            # Read rest of packet
            remaining = self.sock.recv(packet_length)
            if len(remaining) != packet_length:
                return None
            
            padding_length = remaining[0]
            payload = remaining[1:packet_length - padding_length]
            
            return payload
        except Exception:
            return None
    
    def _parse_kexinit(self, payload: bytes) -> Dict:
        """Parse server KEXINIT packet"""
        try:
            if not payload or payload[0] != 20:  # SSH_MSG_KEXINIT
                return {}
            
            offset = 17  # Skip message type + random bytes
            algorithms = {}
            
            alg_names = [
                'kex_algorithms', 'server_host_key_algorithms',
                'encryption_algorithms_client_to_server', 'encryption_algorithms_server_to_client',
                'mac_algorithms_client_to_server', 'mac_algorithms_server_to_client',
                'compression_algorithms_client_to_server', 'compression_algorithms_server_to_client',
                'languages_client_to_server', 'languages_server_to_client'
            ]
            
            for name in alg_names:
                if offset + 4 > len(payload):
                    break
                
                length = struct.unpack('>I', payload[offset:offset+4])[0]
                offset += 4
                
                if offset + length > len(payload):
                    break
                
                alg_list = payload[offset:offset+length].decode('utf-8', errors='ignore')
                algorithms[name] = alg_list.split(',') if alg_list else []
                offset += length
            
            self.kex_algorithms = algorithms
            return algorithms
            
        except Exception:
            return {}
    
    def get_supported_ciphers(self) -> Dict[str, List[str]]:
        """Get supported encryption ciphers"""
        if not self.kex_algorithms:
            return {}
        
        return {
            'encryption_c2s': self.kex_algorithms.get('encryption_algorithms_client_to_server', []),
            'encryption_s2c': self.kex_algorithms.get('encryption_algorithms_server_to_client', []),
            'mac_c2s': self.kex_algorithms.get('mac_algorithms_client_to_server', []),
            'mac_s2c': self.kex_algorithms.get('mac_algorithms_server_to_client', [])
        }
    
    def get_host_key_algorithms(self) -> List[str]:
        """Get supported host key algorithms"""
        return self.kex_algorithms.get('server_host_key_algorithms', [])
    
    def get_kex_algorithms(self) -> List[str]:
        """Get supported key exchange algorithms"""
        return self.kex_algorithms.get('kex_algorithms', [])
    
    def analyze_security_strength(self) -> Dict:
        """Analyze cryptographic strength of algorithms"""
        analysis = {
            'weak_algorithms': [],
            'deprecated_algorithms': [],
            'strong_algorithms': [],
            'security_score': 0
        }
        
        # Weak/deprecated patterns
        weak_patterns = ['des', 'rc4', 'md5', 'sha1', 'diffie-hellman-group1']
        deprecated_patterns = ['hmac-sha1', 'diffie-hellman-group14-sha1']
        
        all_algorithms = []
        for alg_list in self.kex_algorithms.values():
            all_algorithms.extend(alg_list)
        
        for alg in all_algorithms:
            alg_lower = alg.lower()
            if any(weak in alg_lower for weak in weak_patterns):
                analysis['weak_algorithms'].append(alg)
            elif any(dep in alg_lower for dep in deprecated_patterns):
                analysis['deprecated_algorithms'].append(alg)
            else:
                analysis['strong_algorithms'].append(alg)
        
        # Calculate security score (0-100)
        total_algs = len(all_algorithms)
        if total_algs > 0:
            strong_ratio = len(analysis['strong_algorithms']) / total_algs
            weak_penalty = len(analysis['weak_algorithms']) * 0.2
            deprecated_penalty = len(analysis['deprecated_algorithms']) * 0.1
            analysis['security_score'] = max(0, int((strong_ratio - weak_penalty - deprecated_penalty) * 100))
        
        return analysis

def create_ssh_protocol(target: str, port: int = 22) -> SSHProtocol:
    """Factory function to create SSH protocol instance"""
    return SSHProtocol(target, port)