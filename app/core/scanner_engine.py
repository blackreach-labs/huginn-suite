# app/core/scanner_engine.py
import re
import json
import time
from PyQt6.QtCore import QObject, pyqtSignal
from typing import Dict, List, Any
try:
    from .http_client import UnifiedHttpClient, HttpRequest, HttpResponse
except ImportError:
    from app.core.http_client import UnifiedHttpClient, HttpRequest, HttpResponse

class PassiveScanner(QObject):
    finding_detected = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.signatures = self._load_signatures()
        self.findings = []
    
    def _load_signatures(self):
        """Load security check signatures"""
        return {
            'security_headers': [
                {'name': 'Missing CSP', 'header': 'content-security-policy'},
                {'name': 'Missing X-Frame-Options', 'header': 'x-frame-options'},
                {'name': 'Missing HSTS', 'header': 'strict-transport-security'},
                {'name': 'Missing X-Content-Type-Options', 'header': 'x-content-type-options'}
            ],
            'error_patterns': [
                {'name': 'SQL Error', 'pattern': r'(mysql_|ora-\d+|microsoft ole db|odbc|jdbc)'},
                {'name': 'PHP Error', 'pattern': r'(fatal error|parse error|warning:|notice:)'},
                {'name': 'ASP.NET Error', 'pattern': r'(server error|runtime error|exception details)'},
                {'name': 'Stack Trace', 'pattern': r'(traceback|stack trace|at line \d+)'}
            ],
            'sensitive_data': [
                {'name': 'Email Address', 'pattern': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'},
                {'name': 'Credit Card', 'pattern': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'},
                {'name': 'SSN', 'pattern': r'\b\d{3}-\d{2}-\d{4}\b'}
            ]
        }
    
    def scan_response(self, http_response: HttpResponse):
        """Perform passive scan on HTTP response"""
        findings = []
        
        # Check security headers
        findings.extend(self._check_security_headers(http_response))
        
        # Check insecure headers
        findings.extend(self._check_insecure_headers(http_response))
        
        # Check cookies
        findings.extend(self._check_cookies(http_response))
        
        # Check response body for patterns
        if http_response.text:
            findings.extend(self._check_error_patterns(http_response.text, http_response.url))
            findings.extend(self._check_sensitive_data(http_response.text, http_response.url))
        
        # Store and emit findings
        for finding in findings:
            finding['confidence'] = 'High'  # Passive scans are high confidence
            self.findings.append(finding)
            self.finding_detected.emit(finding)
        
        return findings
    
    def _check_security_headers(self, http_response: HttpResponse):
        """Check for missing security headers"""
        findings = []
        headers = {k.lower(): v for k, v in http_response.headers.items()}
        
        for sig in self.signatures['security_headers']:
            if sig['header'] not in headers:
                findings.append({
                    'type': 'Missing Security Header',
                    'severity': 'Medium',
                    'title': sig['name'],
                    'url': http_response.url,
                    'description': f"Missing {sig['header']} header"
                })
        
        return findings
    
    def _check_error_patterns(self, body, url):
        """Check for error disclosure patterns"""
        findings = []
        
        for sig in self.signatures['error_patterns']:
            if re.search(sig['pattern'], body, re.IGNORECASE):
                findings.append({
                    'type': 'Information Disclosure',
                    'severity': 'Low',
                    'title': sig['name'],
                    'url': url,
                    'description': f"Potential {sig['name'].lower()} detected in response"
                })
        
        return findings
    
    def _check_sensitive_data(self, body, url):
        """Check for sensitive data exposure"""
        findings = []
        
        for sig in self.signatures['sensitive_data']:
            matches = re.findall(sig['pattern'], body)
            if matches:
                findings.append({
                    'type': 'Sensitive Data Exposure',
                    'severity': 'High',
                    'title': f"{sig['name']} Detected",
                    'url': url,
                    'description': f"Found {len(matches)} potential {sig['name'].lower()}(s)"
                })
        
        return findings
    
    def _check_insecure_headers(self, http_response: HttpResponse):
        """Check for information disclosure in headers"""
        return []  # Placeholder
    
    def _check_cookies(self, http_response: HttpResponse):
        """Check for insecure cookie flags"""
        return []  # Placeholder
    
    def get_findings(self):
        """Get all findings"""
        return getattr(self, 'findings', [])
    
    def clear_findings(self):
        """Clear all findings"""
        self.findings = []

class ActiveScanner(QObject):
    scan_completed = pyqtSignal(dict)
    finding_detected = pyqtSignal(dict)
    scan_progress = pyqtSignal(int, int)  # current, total
    
    def __init__(self):
        super().__init__()
        self.payloads = self._load_payloads()
        self.http_client = UnifiedHttpClient()
        self.findings = []
    
    def _load_payloads(self):
        """Load active scanning payloads"""
        return {
            'xss': ["<script>alert(1)</script>", "javascript:alert(1)", "'\"><script>alert(1)</script>"],
            'sqli': ["'", "' OR '1'='1", "'; DROP TABLE users; --", "1' UNION SELECT NULL--"],
            'lfi': ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"],
            'command_injection': ["; id", "| whoami", "&& dir", "`id`"]
        }
    
    def scan_parameter(self, base_request, param_name, param_value):
        """Scan a specific parameter for vulnerabilities"""
        findings = []
        
        for vuln_type, payloads in self.payloads.items():
            for payload in payloads:
                # Create modified request with payload
                modified_request = self._inject_payload(base_request, param_name, payload)
                
                # Send request and analyze response
                # This would integrate with the connection pool
                response = self._send_request(modified_request)
                
                if self._analyze_response(response, payload, vuln_type):
                    findings.append({
                        'type': vuln_type.upper(),
                        'severity': 'High',
                        'parameter': param_name,
                        'payload': payload,
                        'url': base_request.url
                    })
        
        return findings
    
    def _inject_payload(self, request, param_name, payload):
        """Inject payload into request parameter"""
        # Implementation would modify the request with the payload
        pass
    
    def _send_request(self, request):
        """Send the modified request"""
        # Implementation would use connection pool to send request
        pass
    
    def _analyze_response(self, response, payload, vuln_type):
        """Analyze response for vulnerability indicators"""
        if not response:
            return False
            
        body = response.get('body', '')
        
        if vuln_type == 'xss':
            return payload in body
        elif vuln_type == 'sqli':
            sql_errors = ['mysql_', 'ora-', 'microsoft ole db', 'syntax error']
            return any(error in body.lower() for error in sql_errors)
        elif vuln_type == 'lfi':
            lfi_indicators = ['root:x:', '[boot loader]', 'etc/passwd']
            return any(indicator in body.lower() for indicator in lfi_indicators)
        elif vuln_type == 'command_injection':
            cmd_indicators = ['uid=', 'gid=', 'volume in drive']
            return any(indicator in body.lower() for indicator in cmd_indicators)
        
        return False
    
    def get_findings(self):
        """Get all findings"""
        return getattr(self, 'findings', [])
    
    def clear_findings(self):
        """Clear all findings"""
        self.findings = []