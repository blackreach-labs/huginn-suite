# app/tools/tls_fingerprint.py
import ssl
import socket
from urllib.parse import urlparse

class TLSFingerprinter:
    def __init__(self):
        self.cipher_suites = {
            'TLS_AES_256_GCM_SHA384': 'TLS 1.3',
            'TLS_CHACHA20_POLY1305_SHA256': 'TLS 1.3',
            'TLS_AES_128_GCM_SHA256': 'TLS 1.3',
            'ECDHE-RSA-AES256-GCM-SHA384': 'TLS 1.2',
            'ECDHE-RSA-AES128-GCM-SHA256': 'TLS 1.2',
            'ECDHE-RSA-AES256-SHA384': 'TLS 1.2',
            'ECDHE-RSA-AES128-SHA256': 'TLS 1.2',
            'AES256-GCM-SHA384': 'TLS 1.2',
            'AES128-GCM-SHA256': 'TLS 1.2'
        }
    
    def fingerprint(self, url):
        """Perform TLS fingerprinting"""
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            port = parsed_url.port or 443
            
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get certificate info
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Extract certificate information
                    cert_info = self._parse_certificate(cert)
                    
                    # Analyze cipher suite
                    cipher_info = self._analyze_cipher(cipher)
                    
                    return {
                        'tls_version': version,
                        'cipher_suite': cipher[0] if cipher else 'Unknown',
                        'cipher_strength': cipher[2] if cipher and len(cipher) > 2 else 'Unknown',
                        'certificate': cert_info,
                        'cipher_analysis': cipher_info,
                        'security_score': self._calculate_security_score(version, cipher)
                    }
                    
        except Exception as e:
            return {'error': str(e)}
    
    def _parse_certificate(self, cert):
        """Parse certificate information"""
        if not cert:
            return {}
        
        return {
            'subject': dict(x[0] for x in cert.get('subject', [])),
            'issuer': dict(x[0] for x in cert.get('issuer', [])),
            'version': cert.get('version'),
            'serial_number': cert.get('serialNumber'),
            'not_before': cert.get('notBefore'),
            'not_after': cert.get('notAfter'),
            'signature_algorithm': cert.get('signatureAlgorithm'),
            'san': [x[1] for x in cert.get('subjectAltName', []) if x[0] == 'DNS']
        }
    
    def _analyze_cipher(self, cipher):
        """Analyze cipher suite security"""
        if not cipher:
            return {}
        
        cipher_name = cipher[0]
        
        # Determine TLS version from cipher
        tls_version = 'Unknown'
        for suite, version in self.cipher_suites.items():
            if suite in cipher_name:
                tls_version = version
                break
        
        # Security analysis
        security_issues = []
        if 'RC4' in cipher_name:
            security_issues.append('Uses RC4 cipher (deprecated)')
        if 'DES' in cipher_name:
            security_issues.append('Uses DES cipher (weak)')
        if 'MD5' in cipher_name:
            security_issues.append('Uses MD5 hash (weak)')
        if 'SHA1' in cipher_name or 'SHA-1' in cipher_name:
            security_issues.append('Uses SHA-1 hash (deprecated)')
        
        return {
            'detected_version': tls_version,
            'security_issues': security_issues,
            'forward_secrecy': 'ECDHE' in cipher_name or 'DHE' in cipher_name,
            'authenticated_encryption': 'GCM' in cipher_name or 'POLY1305' in cipher_name
        }
    
    def _calculate_security_score(self, version, cipher):
        """Calculate security score based on TLS configuration"""
        score = 100
        
        if not version:
            return 0
        
        # Version scoring
        if version == 'TLSv1.3':
            score += 0  # Best
        elif version == 'TLSv1.2':
            score -= 10
        elif version == 'TLSv1.1':
            score -= 30
        elif version == 'TLSv1':
            score -= 50
        else:
            score -= 70
        
        # Cipher scoring
        if cipher:
            cipher_name = cipher[0]
            if 'RC4' in cipher_name:
                score -= 40
            if 'DES' in cipher_name:
                score -= 50
            if 'MD5' in cipher_name:
                score -= 30
            if not ('ECDHE' in cipher_name or 'DHE' in cipher_name):
                score -= 20  # No forward secrecy
        
        return max(0, min(100, score))