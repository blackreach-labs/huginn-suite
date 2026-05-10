"""TLS and protocol security analysis"""
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse
from app.core.logger import logger

class TLSAnalyzer:
    """Analyze TLS configuration and certificate security"""
    
    def __init__(self):
        self.security_issues = []
    
    async def analyze_tls(self, url):
        """Analyze TLS configuration for URL"""
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        
        if parsed.scheme != 'https':
            self.security_issues.append({
                'type': 'No HTTPS Encryption',
                'severity': 'HIGH',
                'description': f'Site {hostname} not using HTTPS - all traffic transmitted in plaintext'
            })
            
            # Also check if HTTP is redirecting to HTTPS
            try:
                import aiohttp
                async with aiohttp.ClientSession() as session:
                    async with session.get(f'http://{hostname}', allow_redirects=False) as response:
                        if response.status not in [301, 302, 307, 308]:
                            self.security_issues.append({
                                'type': 'No HTTPS Redirect',
                                'severity': 'MEDIUM',
                                'description': f'HTTP site does not redirect to HTTPS'
                            })
            except Exception as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
            
            return {'tls_enabled': False, 'security_issues': self.security_issues}
        
        # Analyze certificate and TLS
        cert_info = await self._get_certificate_info(hostname, port)
        tls_info = await self._check_tls_versions(hostname, port)
        
        return {
            'tls_enabled': True,
            'certificate': cert_info,
            'tls_versions': tls_info,
            'security_issues': self.security_issues
        }
    
    async def _get_certificate_info(self, hostname, port):
        """Get SSL certificate information"""
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    cert_info = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'san': cert.get('subjectAltName', [])
                    }
                    
                    # Check certificate validity
                    self._check_certificate_security(cert_info, hostname)
                    
                    return cert_info
        except Exception as e:
            self.security_issues.append({
                'type': 'Certificate Error',
                'severity': 'HIGH',
                'description': f'Failed to retrieve certificate: {str(e)}'
            })
            return {}
    
    def _check_certificate_security(self, cert_info, hostname):
        """Check certificate for security issues"""
        # Check expiration
        try:
            not_after = datetime.strptime(cert_info['not_after'], '%b %d %H:%M:%S %Y %Z')
            days_until_expiry = (not_after - datetime.now()).days
            
            if days_until_expiry < 0:
                self.security_issues.append({
                    'type': 'Expired Certificate',
                    'severity': 'CRITICAL',
                    'description': f'Certificate expired {abs(days_until_expiry)} days ago'
                })
            elif days_until_expiry < 30:
                self.security_issues.append({
                    'type': 'Certificate Expiring Soon',
                    'severity': 'MEDIUM',
                    'description': f'Certificate expires in {days_until_expiry} days'
                })
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        
        # Check if self-signed
        if cert_info.get('issuer') == cert_info.get('subject'):
            self.security_issues.append({
                'type': 'Self-Signed Certificate',
                'severity': 'HIGH',
                'description': 'Certificate is self-signed - cannot verify authenticity, vulnerable to MITM attacks'
            })
        
        # Check hostname match (more detailed)
        subject_cn = cert_info.get('subject', {}).get('commonName', '')
        san_names = [name[1] for name in cert_info.get('san', []) if name[0] == 'DNS']
        
        if hostname not in [subject_cn] + san_names:
            # Check for wildcard match
            wildcard_match = any(
                name.startswith('*.') and hostname.endswith(name[2:])
                for name in [subject_cn] + san_names
            )
            
            if not wildcard_match:
                self.security_issues.append({
                    'type': 'Certificate Hostname Mismatch',
                    'severity': 'CRITICAL',
                    'description': f'Certificate not valid for hostname {hostname} - possible man-in-the-middle attack'
                })
        
        # Check for weak signature algorithms
        # Note: This would require more detailed certificate parsing
        # For now, we'll add a placeholder check
        if 'sha1' in str(cert_info).lower():
            self.security_issues.append({
                'type': 'Weak Certificate Signature',
                'severity': 'HIGH',
                'description': 'Certificate may be using weak SHA-1 signature algorithm'
            })
    
    async def _check_tls_versions(self, hostname, port):
        """Check supported TLS versions"""
        tls_versions = {}
        
        # Test different TLS versions
        versions_to_test = [
            ('TLS 1.0', ssl.PROTOCOL_TLSv1),
            ('TLS 1.1', ssl.PROTOCOL_TLSv1_1),
            ('TLS 1.2', ssl.PROTOCOL_TLSv1_2),
        ]
        
        # Add TLS 1.3 if available
        if hasattr(ssl, 'PROTOCOL_TLSv1_3'):
            versions_to_test.append(('TLS 1.3', ssl.PROTOCOL_TLSv1_3))
        
        for version_name, protocol in versions_to_test:
            try:
                context = ssl.SSLContext(protocol)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock) as ssock:
                        tls_versions[version_name] = {
                            'supported': True,
                            'cipher': ssock.cipher()
                        }
            except Exception:
                tls_versions[version_name] = {'supported': False}
        
        # Check for weak TLS versions (more aggressive)
        weak_versions = ['TLS 1.0', 'TLS 1.1']
        for weak_version in weak_versions:
            if tls_versions.get(weak_version, {}).get('supported'):
                severity = 'HIGH' if weak_version == 'TLS 1.0' else 'MEDIUM'
                self.security_issues.append({
                    'type': f'Weak TLS Version Supported',
                    'severity': severity,
                    'description': f'Server supports deprecated {weak_version} - vulnerable to downgrade attacks'
                })
        
        # Check if only TLS 1.2 is supported (should also support 1.3)
        if not tls_versions.get('TLS 1.3', {}).get('supported') and tls_versions.get('TLS 1.2', {}).get('supported'):
            self.security_issues.append({
                'type': 'Missing TLS 1.3 Support',
                'severity': 'LOW',
                'description': 'Server does not support TLS 1.3 - missing latest security improvements'
            })
        
        return tls_versions
    
    def check_hsts_header(self, headers):
        """Check for HSTS header"""
        hsts = headers.get('Strict-Transport-Security')
        if not hsts:
            self.security_issues.append({
                'type': 'Missing HSTS Header',
                'severity': 'MEDIUM',
                'description': 'HTTPS site missing Strict-Transport-Security header'
            })
            return False
        
        # Parse HSTS header
        hsts_info = {'max_age': 0, 'include_subdomains': False, 'preload': False}
        
        for directive in hsts.split(';'):
            directive = directive.strip()
            if directive.startswith('max-age='):
                try:
                    hsts_info['max_age'] = int(directive.split('=')[1])
                except ValueError as _exc:
                    pass
                    logger.debug("Suppressed exception", exc_info=True)
            elif directive == 'includeSubDomains':
                hsts_info['include_subdomains'] = True
            elif directive == 'preload':
                hsts_info['preload'] = True
        
        # Check max-age value (more aggressive thresholds)
        if hsts_info['max_age'] < 31536000:  # 1 year
            severity = 'MEDIUM' if hsts_info['max_age'] < 86400 else 'LOW'  # Less than 1 day is medium risk
            self.security_issues.append({
                'type': 'Weak HSTS Max-Age',
                'severity': severity,
                'description': f'HSTS max-age is {hsts_info["max_age"]} seconds (recommended: 31536000+ for 1 year)'
            })
        
        # Check for missing includeSubDomains
        if not hsts_info['include_subdomains']:
            self.security_issues.append({
                'type': 'HSTS Missing includeSubDomains',
                'severity': 'MEDIUM',
                'description': 'HSTS header missing includeSubDomains directive - subdomains not protected'
            })
        
        return hsts_info