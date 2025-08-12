# app/core/vuln_scanner.py
import requests
import re
import socket
from typing import Dict, List, Callable
from urllib.parse import urljoin, urlparse

class VulnerabilityScanner:
    """Vulnerability scanner for common security issues"""
    
    def __init__(self):
        self.timeout = 10
        self.vulnerability_checks = {
            'http': self._check_http_vulns,
            'ssl': self._check_ssl_vulns,
            'dns': self._check_dns_vulns,
            'port': self._check_port_vulns
        }
    
    def scan_vulnerabilities(self, target: str, scan_type: str = 'http', 
                           progress_callback: Callable = None) -> Dict:
        """Scan for vulnerabilities based on target type"""
        
        results = {
            'target': target,
            'scan_type': scan_type,
            'vulnerabilities': [],
            'summary': {}
        }
        
        try:
            if scan_type in self.vulnerability_checks:
                if progress_callback:
                    progress_callback(f"Scanning {scan_type} vulnerabilities...")
                
                vulns = self.vulnerability_checks[scan_type](target, progress_callback)
                results['vulnerabilities'] = vulns
                
                # Generate summary
                results['summary'] = self._generate_summary(vulns)
            else:
                results['error'] = f"Unsupported scan type: {scan_type}"
                
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _check_http_vulns(self, target: str, progress_callback: Callable) -> List[Dict]:
        """Check for HTTP-based vulnerabilities"""
        
        vulnerabilities = []
        
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        # Get proxy settings
        proxies = {}
        try:
            from app.core.proxy_manager import proxy_manager
            proxies = proxy_manager.get_proxy_dict()
        except ImportError:
            pass
        
        # Check for common HTTP vulnerabilities
        vuln_checks = [
            ('Directory Traversal', self._check_directory_traversal),
            ('SQL Injection', self._check_sql_injection),
            ('XSS Vulnerability', self._check_xss),
            ('Security Headers', self._check_security_headers),
            ('Default Credentials', self._check_default_creds),
            ('Information Disclosure', self._check_info_disclosure)
        ]
        
        for vuln_name, check_func in vuln_checks:
            if progress_callback:
                progress_callback(f"Checking {vuln_name}...")
            
            try:
                # Apply rate limiting
                try:
                    from app.core.rate_limiter import rate_limiter
                    rate_limiter.wait_if_needed('vuln_scanner')
                except ImportError:
                    pass
                
                vuln_result = check_func(target, proxies)
                if vuln_result:
                    vulnerabilities.append(vuln_result)
            except Exception:
                continue  # Skip failed checks
        
        return vulnerabilities
    
    def _check_directory_traversal(self, target: str, proxies: Dict) -> Dict:
        """Check for directory traversal vulnerability"""
        
        payloads = ['../../../etc/passwd', '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts']
        
        for payload in payloads:
            try:
                url = urljoin(target, payload)
                response = requests.get(url, timeout=self.timeout, proxies=proxies, verify=False)
                
                if response.status_code == 200:
                    content = response.text.lower()
                    if 'root:' in content or 'localhost' in content:
                        return {
                            'type': 'Directory Traversal',
                            'severity': 'high',
                            'description': 'Server vulnerable to directory traversal attacks',
                            'evidence': f'Payload: {payload}',
                            'url': url
                        }
            except Exception:
                continue
        
        return None
    
    def _check_sql_injection(self, target: str, proxies: Dict) -> Dict:
        """Check for SQL injection vulnerability"""
        
        payloads = ["'", "1' OR '1'='1", "'; DROP TABLE users; --"]
        
        for payload in payloads:
            try:
                url = f"{target}?id={payload}"
                response = requests.get(url, timeout=self.timeout, proxies=proxies, verify=False)
                
                if response.status_code == 200:
                    content = response.text.lower()
                    sql_errors = ['sql syntax', 'mysql_fetch', 'ora-', 'microsoft jet database']
                    
                    for error in sql_errors:
                        if error in content:
                            return {
                                'type': 'SQL Injection',
                                'severity': 'high',
                                'description': 'Application vulnerable to SQL injection',
                                'evidence': f'SQL error detected with payload: {payload}',
                                'url': url
                            }
            except Exception:
                continue
        
        return None
    
    def _check_xss(self, target: str, proxies: Dict) -> Dict:
        """Check for XSS vulnerability"""
        
        payload = '<script>alert("XSS")</script>'
        
        try:
            url = f"{target}?q={payload}"
            response = requests.get(url, timeout=self.timeout, proxies=proxies, verify=False)
            
            if response.status_code == 200 and payload in response.text:
                return {
                    'type': 'Cross-Site Scripting (XSS)',
                    'severity': 'medium',
                    'description': 'Application vulnerable to XSS attacks',
                    'evidence': f'Payload reflected: {payload}',
                    'url': url
                }
        except Exception:
            pass
        
        return None
    
    def _check_security_headers(self, target: str, proxies: Dict) -> Dict:
        """Check for missing security headers"""
        
        try:
            response = requests.get(target, timeout=self.timeout, proxies=proxies, verify=False)
            
            missing_headers = []
            security_headers = [
                'X-Frame-Options',
                'X-XSS-Protection',
                'X-Content-Type-Options',
                'Strict-Transport-Security',
                'Content-Security-Policy'
            ]
            
            for header in security_headers:
                if header not in response.headers:
                    missing_headers.append(header)
            
            if missing_headers:
                return {
                    'type': 'Missing Security Headers',
                    'severity': 'low',
                    'description': 'Server missing important security headers',
                    'evidence': f'Missing: {", ".join(missing_headers)}',
                    'url': target
                }
        except Exception:
            pass
        
        return None
    
    def _check_default_creds(self, target: str, proxies: Dict) -> Dict:
        """Check for default credentials"""
        
        default_paths = ['/admin', '/login', '/manager/html']
        default_creds = [('admin', 'admin'), ('admin', 'password'), ('root', 'root')]
        
        for path in default_paths:
            try:
                url = urljoin(target, path)
                response = requests.get(url, timeout=self.timeout, proxies=proxies, verify=False)
                
                if response.status_code == 200 and 'login' in response.text.lower():
                    return {
                        'type': 'Default Login Page',
                        'severity': 'medium',
                        'description': 'Default login interface accessible',
                        'evidence': f'Login page found at: {path}',
                        'url': url
                    }
            except Exception:
                continue
        
        return None
    
    def _check_info_disclosure(self, target: str, proxies: Dict) -> Dict:
        """Check for information disclosure"""
        
        info_paths = ['/robots.txt', '/.git/config', '/phpinfo.php', '/server-status']
        
        for path in info_paths:
            try:
                url = urljoin(target, path)
                response = requests.get(url, timeout=self.timeout, proxies=proxies, verify=False)
                
                if response.status_code == 200:
                    return {
                        'type': 'Information Disclosure',
                        'severity': 'low',
                        'description': 'Sensitive information accessible',
                        'evidence': f'Accessible file: {path}',
                        'url': url
                    }
            except Exception:
                continue
        
        return None
    
    def _check_ssl_vulns(self, target: str, progress_callback: Callable) -> List[Dict]:
        """Check for SSL/TLS vulnerabilities"""
        
        vulnerabilities = []
        
        try:
            import ssl
            
            hostname = target.replace('https://', '').replace('http://', '').split('/')[0]
            
            # Check SSL certificate
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    import datetime
                    not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    
                    if not_after < datetime.datetime.now():
                        vulnerabilities.append({
                            'type': 'Expired SSL Certificate',
                            'severity': 'high',
                            'description': 'SSL certificate has expired',
                            'evidence': f'Expired on: {cert["notAfter"]}',
                            'url': f'https://{hostname}'
                        })
                    elif (not_after - datetime.datetime.now()).days < 30:
                        vulnerabilities.append({
                            'type': 'SSL Certificate Expiring Soon',
                            'severity': 'medium',
                            'description': 'SSL certificate expires within 30 days',
                            'evidence': f'Expires on: {cert["notAfter"]}',
                            'url': f'https://{hostname}'
                        })
        
        except Exception:
            pass
        
        return vulnerabilities
    
    def _check_dns_vulns(self, target: str, progress_callback: Callable) -> List[Dict]:
        """Check for DNS-related vulnerabilities"""
        
        vulnerabilities = []
        
        try:
            import dns.resolver
            
            # Check for DNS zone transfer
            try:
                ns_records = dns.resolver.resolve(target, 'NS')
                for ns in ns_records:
                    try:
                        zone = dns.zone.from_xfr(dns.query.xfr(str(ns), target))
                        if zone:
                            vulnerabilities.append({
                                'type': 'DNS Zone Transfer',
                                'severity': 'medium',
                                'description': 'DNS zone transfer allowed',
                                'evidence': f'Zone transfer possible from: {ns}',
                                'url': f'dns://{target}'
                            })
                    except Exception:
                        continue
            except Exception:
                pass
        
        except ImportError:
            pass
        
        return vulnerabilities
    
    def _check_port_vulns(self, target: str, progress_callback: Callable) -> List[Dict]:
        """Check for port-based vulnerabilities"""
        
        vulnerabilities = []
        
        # Check for common vulnerable services
        vulnerable_ports = {
            21: 'FTP',
            23: 'Telnet',
            53: 'DNS',
            135: 'RPC',
            139: 'NetBIOS',
            445: 'SMB',
            1433: 'MSSQL',
            3389: 'RDP'
        }
        
        for port, service in vulnerable_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target, port))
                sock.close()
                
                if result == 0:
                    vulnerabilities.append({
                        'type': f'Exposed {service} Service',
                        'severity': 'medium',
                        'description': f'{service} service accessible on port {port}',
                        'evidence': f'Port {port} open',
                        'url': f'{target}:{port}'
                    })
            except Exception:
                continue
        
        return vulnerabilities
    
    def _generate_summary(self, vulnerabilities: List[Dict]) -> Dict:
        """Generate vulnerability summary"""
        
        summary = {
            'total_vulnerabilities': len(vulnerabilities),
            'severity_breakdown': {'high': 0, 'medium': 0, 'low': 0},
            'vulnerability_types': {}
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low')
            if severity in summary['severity_breakdown']:
                summary['severity_breakdown'][severity] += 1
            
            vuln_type = vuln.get('type', 'Unknown')
            if vuln_type not in summary['vulnerability_types']:
                summary['vulnerability_types'][vuln_type] = 0
            summary['vulnerability_types'][vuln_type] += 1
        
        return summary

# Global instance
vuln_scanner = VulnerabilityScanner()