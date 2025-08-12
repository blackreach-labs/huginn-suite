# app/core/ssh_key_parser.py
import base64
import struct
import hashlib
from typing import Dict, List, Optional, Tuple

class SSHKeyParser:
    """SSH key analysis and parsing for reconnaissance"""
    
    def __init__(self):
        self.key_types = {
            'ssh-rsa': 'RSA',
            'ssh-dss': 'DSA', 
            'ecdsa-sha2-nistp256': 'ECDSA P-256',
            'ecdsa-sha2-nistp384': 'ECDSA P-384',
            'ecdsa-sha2-nistp521': 'ECDSA P-521',
            'ssh-ed25519': 'Ed25519'
        }
    
    def parse_public_key(self, key_data: str) -> Dict:
        """Parse SSH public key and extract information"""
        try:
            parts = key_data.strip().split()
            if len(parts) < 2:
                return {'error': 'Invalid key format'}
            
            key_type = parts[0]
            key_blob = parts[1]
            comment = parts[2] if len(parts) > 2 else ''
            
            # Decode base64 key blob
            try:
                decoded = base64.b64decode(key_blob)
            except Exception:
                return {'error': 'Invalid base64 encoding'}
            
            # Parse key blob
            key_info = self._parse_key_blob(decoded, key_type)
            key_info.update({
                'key_type': key_type,
                'algorithm': self.key_types.get(key_type, 'Unknown'),
                'comment': comment,
                'fingerprint_md5': self._calculate_md5_fingerprint(decoded),
                'fingerprint_sha256': self._calculate_sha256_fingerprint(decoded),
                'key_size': self._get_key_size(decoded, key_type)
            })
            
            # Security analysis
            key_info['security_analysis'] = self._analyze_key_security(key_info)
            
            return key_info
            
        except Exception as e:
            return {'error': str(e)}
    
    def _parse_key_blob(self, blob: bytes, key_type: str) -> Dict:
        """Parse key blob based on key type"""
        try:
            offset = 0
            
            # Read key type from blob
            type_len = struct.unpack('>I', blob[offset:offset+4])[0]
            offset += 4
            blob_key_type = blob[offset:offset+type_len].decode()
            offset += type_len
            
            if blob_key_type != key_type:
                return {'error': 'Key type mismatch'}
            
            if key_type == 'ssh-rsa':
                return self._parse_rsa_key(blob, offset)
            elif key_type == 'ssh-dss':
                return self._parse_dsa_key(blob, offset)
            elif key_type.startswith('ecdsa-'):
                return self._parse_ecdsa_key(blob, offset)
            elif key_type == 'ssh-ed25519':
                return self._parse_ed25519_key(blob, offset)
            else:
                return {'parsed': False, 'reason': 'Unsupported key type'}
                
        except Exception as e:
            return {'error': f'Parsing failed: {e}'}
    
    def _parse_rsa_key(self, blob: bytes, offset: int) -> Dict:
        """Parse RSA public key"""
        try:
            # Read public exponent
            e_len = struct.unpack('>I', blob[offset:offset+4])[0]
            offset += 4
            e = int.from_bytes(blob[offset:offset+e_len], 'big')
            offset += e_len
            
            # Read modulus
            n_len = struct.unpack('>I', blob[offset:offset+4])[0]
            offset += 4
            n = int.from_bytes(blob[offset:offset+n_len], 'big')
            
            return {
                'parsed': True,
                'public_exponent': e,
                'modulus_bits': n.bit_length(),
                'modulus': hex(n)[:50] + '...' if len(hex(n)) > 50 else hex(n)
            }
        except Exception as e:
            return {'error': f'RSA parsing failed: {e}'}
    
    def _parse_dsa_key(self, blob: bytes, offset: int) -> Dict:
        """Parse DSA public key"""
        try:
            # Read p, q, g, y parameters
            params = {}
            for param in ['p', 'q', 'g', 'y']:
                param_len = struct.unpack('>I', blob[offset:offset+4])[0]
                offset += 4
                param_value = int.from_bytes(blob[offset:offset+param_len], 'big')
                params[param] = param_value
                offset += param_len
            
            return {
                'parsed': True,
                'p_bits': params['p'].bit_length(),
                'q_bits': params['q'].bit_length(),
                'parameters': {k: hex(v)[:20] + '...' for k, v in params.items()}
            }
        except Exception as e:
            return {'error': f'DSA parsing failed: {e}'}
    
    def _parse_ecdsa_key(self, blob: bytes, offset: int) -> Dict:
        """Parse ECDSA public key"""
        try:
            # Read curve identifier
            curve_len = struct.unpack('>I', blob[offset:offset+4])[0]
            offset += 4
            curve = blob[offset:offset+curve_len].decode()
            offset += curve_len
            
            # Read public key point
            point_len = struct.unpack('>I', blob[offset:offset+4])[0]
            offset += 4
            point = blob[offset:offset+point_len]
            
            return {
                'parsed': True,
                'curve': curve,
                'point_length': len(point),
                'compressed': point[0] in [0x02, 0x03] if point else False
            }
        except Exception as e:
            return {'error': f'ECDSA parsing failed: {e}'}
    
    def _parse_ed25519_key(self, blob: bytes, offset: int) -> Dict:
        """Parse Ed25519 public key"""
        try:
            # Read public key
            key_len = struct.unpack('>I', blob[offset:offset+4])[0]
            offset += 4
            public_key = blob[offset:offset+key_len]
            
            return {
                'parsed': True,
                'key_length': len(public_key),
                'public_key': public_key.hex()[:32] + '...'
            }
        except Exception as e:
            return {'error': f'Ed25519 parsing failed: {e}'}
    
    def _calculate_md5_fingerprint(self, blob: bytes) -> str:
        """Calculate MD5 fingerprint"""
        md5_hash = hashlib.md5(blob).hexdigest()
        return ':'.join(md5_hash[i:i+2] for i in range(0, len(md5_hash), 2))
    
    def _calculate_sha256_fingerprint(self, blob: bytes) -> str:
        """Calculate SHA256 fingerprint"""
        sha256_hash = hashlib.sha256(blob).digest()
        return 'SHA256:' + base64.b64encode(sha256_hash).decode().rstrip('=')
    
    def _get_key_size(self, blob: bytes, key_type: str) -> int:
        """Get key size in bits"""
        try:
            if key_type == 'ssh-rsa':
                # For RSA, extract modulus size
                offset = 4 + struct.unpack('>I', blob[:4])[0]  # Skip key type
                e_len = struct.unpack('>I', blob[offset:offset+4])[0]
                offset += 4 + e_len
                n_len = struct.unpack('>I', blob[offset:offset+4])[0]
                offset += 4
                n = int.from_bytes(blob[offset:offset+n_len], 'big')
                return n.bit_length()
            elif key_type == 'ssh-dss':
                # For DSA, extract p parameter size
                offset = 4 + struct.unpack('>I', blob[:4])[0]  # Skip key type
                p_len = struct.unpack('>I', blob[offset:offset+4])[0]
                offset += 4
                p = int.from_bytes(blob[offset:offset+p_len], 'big')
                return p.bit_length()
            elif key_type == 'ecdsa-sha2-nistp256':
                return 256
            elif key_type == 'ecdsa-sha2-nistp384':
                return 384
            elif key_type == 'ecdsa-sha2-nistp521':
                return 521
            elif key_type == 'ssh-ed25519':
                return 256
            else:
                return 0
        except:
            return 0
    
    def _analyze_key_security(self, key_info: Dict) -> Dict:
        """Analyze key security strength"""
        analysis = {
            'strength': 'unknown',
            'recommendations': [],
            'vulnerabilities': []
        }
        
        key_type = key_info.get('key_type', '')
        key_size = key_info.get('key_size', 0)
        
        # RSA analysis
        if key_type == 'ssh-rsa':
            if key_size < 1024:
                analysis['strength'] = 'very_weak'
                analysis['vulnerabilities'].append('RSA key size too small (< 1024 bits)')
            elif key_size < 2048:
                analysis['strength'] = 'weak'
                analysis['recommendations'].append('Upgrade to RSA 2048+ bits')
            elif key_size >= 2048:
                analysis['strength'] = 'good'
            
            # Check public exponent
            pub_exp = key_info.get('public_exponent', 0)
            if pub_exp == 3:
                analysis['vulnerabilities'].append('Small public exponent (e=3) may be vulnerable')
        
        # DSA analysis
        elif key_type == 'ssh-dss':
            analysis['strength'] = 'deprecated'
            analysis['vulnerabilities'].append('DSA is deprecated and should not be used')
            analysis['recommendations'].append('Replace with RSA, ECDSA, or Ed25519')
        
        # ECDSA analysis
        elif key_type.startswith('ecdsa-'):
            if key_size >= 256:
                analysis['strength'] = 'good'
            else:
                analysis['strength'] = 'weak'
        
        # Ed25519 analysis
        elif key_type == 'ssh-ed25519':
            analysis['strength'] = 'excellent'
            analysis['recommendations'].append('Ed25519 is currently the best choice')
        
        return analysis
    
    def analyze_authorized_keys(self, authorized_keys_content: str) -> Dict:
        """Analyze authorized_keys file content"""
        results = {
            'total_keys': 0,
            'key_types': {},
            'security_issues': [],
            'recommendations': [],
            'keys': []
        }
        
        lines = authorized_keys_content.strip().split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Parse key
            key_info = self.parse_public_key(line)
            if 'error' not in key_info:
                results['total_keys'] += 1
                key_type = key_info.get('key_type', 'unknown')
                results['key_types'][key_type] = results['key_types'].get(key_type, 0) + 1
                
                key_info['line_number'] = line_num
                results['keys'].append(key_info)
                
                # Check for security issues
                security = key_info.get('security_analysis', {})
                if security.get('strength') in ['very_weak', 'weak', 'deprecated']:
                    results['security_issues'].append(f"Line {line_num}: {security.get('strength')} key")
        
        # Generate recommendations
        if 'ssh-dss' in results['key_types']:
            results['recommendations'].append('Remove DSA keys (deprecated)')
        
        weak_rsa = sum(1 for key in results['keys'] 
                      if key.get('key_type') == 'ssh-rsa' and key.get('key_size', 0) < 2048)
        if weak_rsa > 0:
            results['recommendations'].append(f'Upgrade {weak_rsa} weak RSA keys to 2048+ bits')
        
        if not any(key.get('key_type') == 'ssh-ed25519' for key in results['keys']):
            results['recommendations'].append('Consider using Ed25519 keys for new deployments')
        
        return results

def create_ssh_key_parser() -> SSHKeyParser:
    """Factory function to create SSH key parser"""
    return SSHKeyParser()