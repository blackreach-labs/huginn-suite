# app/tools/scan_plugins/security_plugin.py
import re
import urllib.parse
from typing import Dict, List
from .ai_ssti_plugin import AISSTIPlugin

class SecurityPlugin:
    def __init__(self, session=None, progress_callback=None):
        self.name = "Security Analysis"
        self.session = session
        self.progress_callback = progress_callback
        self.ssl_verify = False
        if session:
            self.ai_ssti_plugin = AISSTIPlugin(session, progress_callback)
        
    def scan(self, url, response, session):
        """Legacy scan method for compatibility"""
        try:
            headers = response.headers
            content = response.text
            
            # Security headers analysis
            security_headers = {
                'X-Frame-Options': headers.get('X-Frame-Options'),
                'X-XSS-Protection': headers.get('X-XSS-Protection'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
                'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
                'Content-Security-Policy': headers.get('Content-Security-Policy'),
                'X-Permitted-Cross-Domain-Policies': headers.get('X-Permitted-Cross-Domain-Policies'),
                'Referrer-Policy': headers.get('Referrer-Policy'),
                'Feature-Policy': headers.get('Feature-Policy')
            }
            
            # Count present headers
            present_headers = {k: v for k, v in security_headers.items() if v}
            
            # Security issues detection
            security_issues = []
            
            # Missing security headers
            if not security_headers.get('X-Frame-Options'):
                security_issues.append('Missing X-Frame-Options header (Clickjacking protection)')
            
            if not security_headers.get('X-Content-Type-Options'):
                security_issues.append('Missing X-Content-Type-Options header (MIME sniffing protection)')
            
            if not security_headers.get('Strict-Transport-Security') and url.startswith('https'):
                security_issues.append('Missing HSTS header for HTTPS site')
            
            # Content analysis
            if 'password' in content.lower() and not security_headers.get('Strict-Transport-Security'):
                security_issues.append('Password form without HSTS protection')
            
            # Server information disclosure
            server_header = headers.get('Server', '')
            if server_header and any(info in server_header.lower() for info in ['apache/', 'nginx/', 'iis/']):
                security_issues.append(f'Server version disclosure: {server_header}')
            
            # Cookie security
            cookies_analysis = self._analyze_cookies(response.cookies)
            
            return {
                'security_headers': present_headers,
                'security_issues': security_issues,
                'security_score': max(0, 100 - len(security_issues) * 10),
                'cookies_analysis': cookies_analysis
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    async def comprehensive_scan(self, target_url: str, discovered_forms: List[Dict] = None, js_endpoints: List[str] = None) -> Dict:
        """Comprehensive security vulnerability scanning with AI-driven SSTI"""
        results = {
            'ai_ssti_vulnerabilities': [],
            'traditional_ssti_vulnerabilities': [],
            'xss_vulnerabilities': [],
            'sql_injection': [],
            'command_injection': [],
            'file_inclusion': [],
            'security_headers': {},
            'sensitive_files': [],
            'ai_intelligence': {}
        }
        
        if self.progress_callback:
            self.progress_callback("Starting AI-driven security vulnerability scan...")
        
        # AI-Driven SSTI Testing (Primary)
        if hasattr(self, 'ai_ssti_plugin'):
            ai_ssti_results = await self.ai_ssti_plugin.scan(target_url, js_endpoints)
            results['ai_ssti_vulnerabilities'] = ai_ssti_results['vulnerabilities']
            results['ai_intelligence'] = ai_ssti_results['ai_intelligence']
        
        # Traditional SSTI Testing (Fallback)
        traditional_ssti_results = self._test_ssti_traditional(target_url, discovered_forms, js_endpoints)
        results['traditional_ssti_vulnerabilities'] = traditional_ssti_results
        
        # XSS Testing
        xss_results = self._test_xss(target_url, discovered_forms)
        results['xss_vulnerabilities'] = xss_results
        
        # SQL Injection Testing
        sql_results = self._test_sql_injection(target_url, discovered_forms)
        results['sql_injection'] = sql_results
        
        # Command Injection Testing
        cmd_results = self._test_command_injection(target_url, discovered_forms)
        results['command_injection'] = cmd_results
        
        # File Inclusion Testing
        lfi_results = self._test_file_inclusion(target_url)
        results['file_inclusion'] = lfi_results
        
        # Security Headers Analysis
        headers_analysis = self._analyze_security_headers(target_url)
        results['security_headers'] = headers_analysis
        
        # Sensitive Files Detection
        sensitive_files = self._check_sensitive_files(target_url)
        results['sensitive_files'] = sensitive_files
        
        return results
    
    def _test_ssti_traditional(self, target_url: str, discovered_forms: List[Dict] = None, js_endpoints: List[str] = None) -> List[Dict]:
        """Traditional SSTI testing without AI adaptation"""
        vulnerabilities = []
        
        # Basic SSTI payloads
        ssti_payloads = [
            '{{7*7}}',
            '${7*7}',
            '<%=7*7%>',
            '{{config}}',
            '${@print(7*7)}'
        ]
        
        test_endpoints = js_endpoints or [target_url]
        
        for endpoint in test_endpoints:
            for payload in ssti_payloads:
                try:
                    response = self.session.get(
                        endpoint,
                        params={'q': payload},
                        timeout=10,
                        verify=self.ssl_verify
                    )
                    
                    if '49' in response.text and payload in ['{{7*7}}', '${7*7}', '<%=7*7%>']:
                        vulnerabilities.append({
                            'endpoint': endpoint,
                            'payload': payload,
                            'type': 'SSTI',
                            'evidence': '49 found in response'
                        })
                except:
                    continue
        
        return vulnerabilities
    
    def _test_xss(self, target_url: str, discovered_forms: List[Dict] = None) -> List[Dict]:
        """Basic XSS testing"""
        vulnerabilities = []
        xss_payloads = ['<script>alert(1)</script>', '"><script>alert(1)</script>']
        
        for payload in xss_payloads:
            try:
                response = self.session.get(
                    target_url,
                    params={'q': payload},
                    timeout=10,
                    verify=self.ssl_verify
                )
                
                if payload in response.text:
                    vulnerabilities.append({
                        'endpoint': target_url,
                        'payload': payload,
                        'type': 'XSS',
                        'evidence': 'Payload reflected'
                    })
            except:
                continue
        
        return vulnerabilities
    
    def _test_sql_injection(self, target_url: str, discovered_forms: List[Dict] = None) -> List[Dict]:
        """Basic SQL injection testing"""
        vulnerabilities = []
        sql_payloads = ["'", '"', "' OR '1'='1", '" OR "1"="1']
        
        for payload in sql_payloads:
            try:
                response = self.session.get(
                    target_url,
                    params={'id': payload},
                    timeout=10,
                    verify=self.ssl_verify
                )
                
                error_indicators = ['sql', 'mysql', 'oracle', 'syntax error']
                if any(indicator in response.text.lower() for indicator in error_indicators):
                    vulnerabilities.append({
                        'endpoint': target_url,
                        'payload': payload,
                        'type': 'SQL Injection',
                        'evidence': 'SQL error detected'
                    })
            except:
                continue
        
        return vulnerabilities
    
    def _test_command_injection(self, target_url: str, discovered_forms: List[Dict] = None) -> List[Dict]:
        """Basic command injection testing"""
        vulnerabilities = []
        cmd_payloads = [';id', '|id', '`id`', '$(id)']
        
        for payload in cmd_payloads:
            try:
                response = self.session.get(
                    target_url,
                    params={'cmd': payload},
                    timeout=10,
                    verify=self.ssl_verify
                )
                
                if 'uid=' in response.text:
                    vulnerabilities.append({
                        'endpoint': target_url,
                        'payload': payload,
                        'type': 'Command Injection',
                        'evidence': 'Command output detected'
                    })
            except:
                continue
        
        return vulnerabilities
    
    def _test_file_inclusion(self, target_url: str) -> List[Dict]:
        """Basic file inclusion testing"""
        vulnerabilities = []
        lfi_payloads = ['../../../etc/passwd', '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts']
        
        for payload in lfi_payloads:
            try:
                response = self.session.get(
                    target_url,
                    params={'file': payload},
                    timeout=10,
                    verify=self.ssl_verify
                )
                
                if 'root:' in response.text or 'localhost' in response.text:
                    vulnerabilities.append({
                        'endpoint': target_url,
                        'payload': payload,
                        'type': 'File Inclusion',
                        'evidence': 'System file content detected'
                    })
            except:
                continue
        
        return vulnerabilities
    
    def _analyze_security_headers(self, target_url: str) -> Dict:
        """Analyze security headers"""
        try:
            response = self.session.get(target_url, timeout=10, verify=self.ssl_verify)
            headers = response.headers
            
            security_headers = {
                'X-Frame-Options': headers.get('X-Frame-Options'),
                'X-XSS-Protection': headers.get('X-XSS-Protection'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
                'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
                'Content-Security-Policy': headers.get('Content-Security-Policy')
            }
            
            return {k: v for k, v in security_headers.items() if v}
        except:
            return {}
    
    def _check_sensitive_files(self, target_url: str) -> List[str]:
        """Check for sensitive files"""
        sensitive_files = []
        test_files = ['/robots.txt', '/.env', '/config.php', '/wp-config.php']
        
        for file_path in test_files:
            try:
                response = self.session.get(
                    target_url + file_path,
                    timeout=10,
                    verify=self.ssl_verify
                )
                
                if response.status_code == 200:
                    sensitive_files.append(file_path)
            except:
                continue
        
        return sensitive_files
    
    def _analyze_cookies(self, cookies):
        """Analyze cookie security"""
        cookie_issues = []
        secure_cookies = 0
        total_cookies = len(cookies)
        
        for cookie in cookies:
            if not cookie.secure:
                cookie_issues.append(f'Cookie {cookie.name} not marked as Secure')
            else:
                secure_cookies += 1
            
            if not hasattr(cookie, 'httponly') or not cookie.httponly:
                cookie_issues.append(f'Cookie {cookie.name} not marked as HttpOnly')
        
        return {
            'total_cookies': total_cookies,
            'secure_cookies': secure_cookies,
            'cookie_issues': cookie_issues
        }