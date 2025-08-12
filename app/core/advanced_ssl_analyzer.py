import ssl
import socket
from urllib.parse import urlparse

class AdvancedSSLAnalyzer:
    """Advanced SSL/TLS security analysis"""
    
    def __init__(self):
        self.weak_ciphers = [
            'RC4', 'DES', '3DES', 'MD5', 'SHA1', 'NULL', 'EXPORT', 'ADH', 'AECDH'
        ]
        self.weak_protocols = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
    
    async def analyze_ssl_advanced(self, target_url):
        """Perform advanced SSL/TLS analysis"""
        findings = []
        parsed = urlparse(target_url)
        
        if parsed.scheme != 'https':
            return findings
            
        hostname = parsed.hostname
        port = parsed.port or 443
        
        try:
            # Test SSL/TLS protocols
            protocol_findings = self._test_protocols(hostname, port)
            findings.extend(protocol_findings)
            
            # Test cipher suites
            cipher_findings = self._test_ciphers(hostname, port)
            findings.extend(cipher_findings)
            
            # Certificate analysis
            cert_findings = self._analyze_certificate(hostname, port)
            findings.extend(cert_findings)
            
        except Exception as e:
            findings.append({
                'type': 'SSL Analysis Error',
                'severity': 'INFO',
                'description': f'Could not complete SSL analysis: {str(e)}',
                'recommendation': 'Manual SSL testing may be required'
            })
        
        return findings
    
    def _test_protocols(self, hostname, port):
        """Test for weak SSL/TLS protocols"""
        findings = []
        
        for protocol_name in self.weak_protocols:
            try:
                if protocol_name == 'SSLv2':
                    continue  # Skip SSLv2 as it's not supported in modern Python
                    
                protocol = getattr(ssl, f'PROTOCOL_{protocol_name.replace(".", "_")}', None)
                if protocol:
                    context = ssl.SSLContext(protocol)
                    with socket.create_connection((hostname, port), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            findings.append({
                                'type': 'Weak SSL/TLS Protocol',
                                'severity': 'HIGH',
                                'description': f'{protocol_name} protocol is supported',
                                'protocol': protocol_name,
                                'recommendation': f'Disable {protocol_name} and use TLS 1.2 or higher'
                            })
            except:
                continue  # Protocol not supported (good)
                
        return findings
    
    def _test_ciphers(self, hostname, port):
        """Test for weak cipher suites"""
        findings = []
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name = cipher[0]
                        # Check for weak ciphers
                        for weak in self.weak_ciphers:
                            if weak in cipher_name.upper():
                                findings.append({
                                    'type': 'Weak Cipher Suite',
                                    'severity': 'MEDIUM',
                                    'description': f'Weak cipher in use: {cipher_name}',
                                    'cipher': cipher_name,
                                    'recommendation': 'Configure strong cipher suites only'
                                })
                                break
        except:
            pass
            
        return findings
    
    def _analyze_certificate(self, hostname, port):
        """Analyze SSL certificate"""
        findings = []
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate validity
                    import datetime
                    not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.datetime.now()).days
                    
                    if days_until_expiry < 30:
                        severity = 'HIGH' if days_until_expiry < 7 else 'MEDIUM'
                        findings.append({
                            'type': 'Certificate Expiry Warning',
                            'severity': severity,
                            'description': f'Certificate expires in {days_until_expiry} days',
                            'expiry_date': cert['notAfter'],
                            'recommendation': 'Renew SSL certificate before expiration'
                        })
        except:
            pass
            
        return findings