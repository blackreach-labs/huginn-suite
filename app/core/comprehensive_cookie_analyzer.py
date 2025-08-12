"""
Comprehensive Cookie Analyzer
"""
import re
import base64
import json
from typing import Dict, List, Any
from aiohttp import ClientResponse

class ComprehensiveCookieAnalyzer:
    def __init__(self):
        # Security flags to check
        self.security_flags = ['HttpOnly', 'Secure', 'SameSite']
        
        # Default cookie names that indicate weak configuration
        self.default_names = [
            'PHPSESSID', 'JSESSIONID', 'ASP.NET_SessionId', 
            'CFID', 'CFTOKEN', 'session', 'sid'
        ]
        
        # Patterns for detecting serialized data
        self.serialization_patterns = [
            (r'^[a-zA-Z0-9+/]+=*$', 'base64'),  # Base64
            (r'^[a-z]:\d+:', 'php_serialize'),  # PHP serialization
            (r'^\x00\x00\x00', 'java_serialize'),  # Java serialization
            (r'^[\{\[]', 'json')  # JSON
        ]

    def analyze_cookies(self, response: ClientResponse) -> Dict[str, Any]:
        """Analyze cookies from HTTP response"""
        results = {
            'cookies': [],
            'security_issues': [],
            'session_analysis': {
                'session_cookies': [],
                'security_score': 0,
                'issues': []
            }
        }
        
        # Parse Set-Cookie headers
        set_cookies = response.headers.getall('Set-Cookie', [])
        
        for cookie_header in set_cookies:
            cookie_data = self._parse_cookie(cookie_header)
            results['cookies'].append(cookie_data)
            
            # Analyze security issues
            self._analyze_cookie_security(cookie_data, results)
            
            # Analyze session management
            if self._is_session_cookie(cookie_data):
                results['session_analysis']['session_cookies'].append(cookie_data)
                self._analyze_session_cookie(cookie_data, results)
        
        # Calculate overall security score
        self._calculate_security_score(results)
        
        return results
    
    def _parse_cookie(self, cookie_header: str) -> Dict[str, Any]:
        """Parse a Set-Cookie header"""
        parts = [part.strip() for part in cookie_header.split(';')]
        
        # First part is name=value
        name_value = parts[0].split('=', 1)
        cookie_data = {
            'name': name_value[0],
            'value': name_value[1] if len(name_value) > 1 else '',
            'flags': {},
            'attributes': {}
        }
        
        # Parse attributes
        for part in parts[1:]:
            if '=' in part:
                key, value = part.split('=', 1)
                cookie_data['attributes'][key.lower()] = value
            else:
                cookie_data['flags'][part.lower()] = True
        
        # Analyze cookie value
        cookie_data['analysis'] = self._analyze_cookie_value(cookie_data['value'])
        
        return cookie_data
    
    def _analyze_cookie_value(self, value: str) -> Dict[str, Any]:
        """Analyze cookie value for patterns"""
        analysis = {
            'length': len(value),
            'entropy': self._calculate_entropy(value),
            'patterns': [],
            'potential_issues': []
        }
        
        # Check for serialization patterns
        for pattern, type_name in self.serialization_patterns:
            if re.match(pattern, value):
                analysis['patterns'].append(type_name)
        
        # Check for JWT
        if value.count('.') == 2:
            analysis['patterns'].append('jwt')
            jwt_analysis = self._analyze_jwt(value)
            analysis['jwt'] = jwt_analysis
        
        # Check for predictable patterns
        if re.match(r'^\d+$', value):
            analysis['potential_issues'].append('sequential_id')
        elif re.match(r'^[a-f0-9]+$', value) and len(value) < 16:
            analysis['potential_issues'].append('weak_session_id')
        
        return analysis
    
    def _analyze_jwt(self, jwt_token: str) -> Dict[str, Any]:
        """Analyze JWT token"""
        try:
            parts = jwt_token.split('.')
            if len(parts) != 3:
                return {'error': 'Invalid JWT format'}
            
            # Decode header
            header_data = base64.urlsafe_b64decode(parts[0] + '==')
            header = json.loads(header_data)
            
            return {
                'algorithm': header.get('alg', 'unknown'),
                'type': header.get('typ', 'unknown'),
                'issues': self._check_jwt_issues(header)
            }
        except Exception:
            return {'error': 'Failed to decode JWT'}
    
    def _check_jwt_issues(self, header: Dict[str, Any]) -> List[str]:
        """Check JWT for security issues"""
        issues = []
        
        algorithm = header.get('alg', '').lower()
        if algorithm == 'none':
            issues.append('No signature algorithm')
        elif algorithm == 'hs256':
            issues.append('Symmetric algorithm (shared secret)')
        
        return issues
    
    def _analyze_cookie_security(self, cookie_data: Dict[str, Any], results: Dict[str, Any]):
        """Analyze cookie for security issues"""
        name = cookie_data['name']
        flags = cookie_data['flags']
        analysis = cookie_data['analysis']
        
        # Check for missing security flags
        if not flags.get('httponly'):
            severity = 'HIGH' if self._is_auth_cookie(name) else 'MEDIUM'
            results['security_issues'].append({
                'type': 'Missing HttpOnly Flag',
                'severity': severity,
                'description': f'Cookie {name} missing HttpOnly flag',
                'cookie_name': name
            })
        
        if not flags.get('secure'):
            results['security_issues'].append({
                'type': 'Missing Secure Flag',
                'severity': 'MEDIUM',
                'description': f'Cookie {name} missing Secure flag',
                'cookie_name': name
            })
        
        if not flags.get('samesite'):
            results['security_issues'].append({
                'type': 'Missing SameSite Attribute',
                'severity': 'MEDIUM',
                'description': f'Cookie {name} missing SameSite attribute',
                'cookie_name': name
            })
        
        # Check for overly permissive domain
        domain = cookie_data['attributes'].get('domain', '')
        if domain.startswith('.') and domain.count('.') <= 2:
            results['security_issues'].append({
                'type': 'Overly Permissive Cookie Domain',
                'severity': 'MEDIUM',
                'description': f'Cookie {name} has overly broad domain: {domain}',
                'cookie_name': name,
                'domain': domain
            })
        
        # Check for serialized data
        if 'php_serialize' in analysis['patterns'] or 'java_serialize' in analysis['patterns']:
            results['security_issues'].append({
                'type': 'Serialized Cookie Data',
                'severity': 'MEDIUM',
                'description': f'Cookie {name} contains serialized data (potential deserialization risk)',
                'cookie_name': name,
                'patterns': analysis['patterns']
            })
        
        # Check JWT issues
        if 'jwt' in analysis and 'jwt' in analysis:
            jwt_issues = analysis['jwt'].get('issues', [])
            for issue in jwt_issues:
                severity = 'HIGH' if 'none' in issue.lower() else 'MEDIUM'
                results['security_issues'].append({
                    'type': 'Weak JWT Algorithm',
                    'severity': severity,
                    'description': f'Cookie {name} JWT has issue: {issue}',
                    'cookie_name': name,
                    'jwt_issue': issue
                })
    
    def _analyze_session_cookie(self, cookie_data: Dict[str, Any], results: Dict[str, Any]):
        """Analyze session-specific cookie issues"""
        name = cookie_data['name']
        analysis = cookie_data['analysis']
        
        # Check session ID strength
        if analysis['length'] < 16:
            results['session_analysis']['issues'].append({
                'type': 'Weak Session ID',
                'severity': 'HIGH',
                'description': f'Session cookie {name} has weak ID (length: {analysis["length"]})',
                'cookie_name': name,
                'length': analysis['length']
            })
        
        # Check for predictable patterns
        if 'sequential_id' in analysis['potential_issues']:
            results['session_analysis']['issues'].append({
                'type': 'Predictable Session ID',
                'severity': 'HIGH',
                'description': f'Session cookie {name} appears to use sequential IDs',
                'cookie_name': name
            })
        
        # Check for default names
        if name in self.default_names:
            results['session_analysis']['issues'].append({
                'type': 'Default Session Cookie Name',
                'severity': 'LOW',
                'description': f'Using default session cookie name: {name}',
                'cookie_name': name
            })
    
    def _is_session_cookie(self, cookie_data: Dict[str, Any]) -> bool:
        """Determine if cookie is likely a session cookie"""
        name = cookie_data['name'].lower()
        session_indicators = ['session', 'sid', 'phpsessid', 'jsessionid', 'asp.net_sessionid']
        return any(indicator in name for indicator in session_indicators)
    
    def _is_auth_cookie(self, name: str) -> bool:
        """Determine if cookie is likely an authentication cookie"""
        auth_indicators = ['auth', 'login', 'token', 'jwt', 'session']
        return any(indicator in name.lower() for indicator in auth_indicators)
    
    def _calculate_entropy(self, value: str) -> float:
        """Calculate Shannon entropy of cookie value"""
        if not value:
            return 0.0
        
        char_counts = {}
        for char in value:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        entropy = 0.0
        length = len(value)
        for count in char_counts.values():
            probability = count / length
            entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    def _calculate_security_score(self, results: Dict[str, Any]):
        """Calculate overall cookie security score"""
        total_cookies = len(results['cookies'])
        if total_cookies == 0:
            results['session_analysis']['security_score'] = 0
            return
        
        issues = len(results['security_issues']) + len(results['session_analysis']['issues'])
        max_possible_issues = total_cookies * 4  # Rough estimate
        
        score = max(0, 100 - (issues * 100 // max_possible_issues))
        results['session_analysis']['security_score'] = score