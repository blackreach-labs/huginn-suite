"""Cookie and session security analysis"""
import re
import base64
import json

class CookieAnalyzer:
    """Analyze cookies for security issues"""
    
    def __init__(self):
        self.security_issues = []
    
    def analyze_cookies(self, response):
        """Analyze all cookies from response"""
        cookies_data = []
        
        # Get cookies from response
        for cookie in response.cookies:
            cookie_data = self._analyze_cookie(cookie)
            cookies_data.append(cookie_data)
        
        return {
            'cookies': cookies_data,
            'security_issues': self.security_issues
        }
    
    def _analyze_cookie(self, cookie):
        """Analyze individual cookie"""
        cookie_data = {
            'name': cookie.key,
            'value': cookie.value,
            'domain': getattr(cookie, 'domain', ''),
            'path': getattr(cookie, 'path', '/'),
            'secure': getattr(cookie, 'secure', False),
            'httponly': getattr(cookie, 'httponly', False),
            'samesite': getattr(cookie, 'samesite', ''),
            'expires': getattr(cookie, 'expires', ''),
            'analysis': {}
        }
        
        # Security flag checks
        self._check_security_flags(cookie_data)
        
        # Content analysis
        self._analyze_cookie_content(cookie_data)
        
        return cookie_data
    
    def _check_security_flags(self, cookie_data):
        """Check cookie security flags"""
        cookie_name = cookie_data['name'].lower()
        
        # Check for ANY cookie without HttpOnly (more aggressive)
        if not cookie_data['httponly']:
            severity = 'HIGH' if any(session_id in cookie_name for session_id in ['session', 'sess', 'auth', 'login', 'token']) else 'MEDIUM'
            self.security_issues.append({
                'type': 'Missing HttpOnly Flag',
                'severity': severity,
                'description': f'Cookie {cookie_data["name"]} missing HttpOnly flag - vulnerable to XSS attacks',
                'cookie': cookie_data['name']
            })
        
        # Check for missing Secure flag on ANY cookie
        if not cookie_data['secure']:
            self.security_issues.append({
                'type': 'Missing Secure Flag',
                'severity': 'MEDIUM',
                'description': f'Cookie {cookie_data["name"]} missing Secure flag - can be transmitted over HTTP',
                'cookie': cookie_data['name']
            })
        
        # Check SameSite attribute for ALL cookies
        if not cookie_data['samesite']:
            self.security_issues.append({
                'type': 'Missing SameSite Attribute',
                'severity': 'MEDIUM',
                'description': f'Cookie {cookie_data["name"]} missing SameSite attribute - vulnerable to CSRF attacks',
                'cookie': cookie_data['name']
            })
        
        # Check for overly permissive domain settings
        if cookie_data['domain'] and cookie_data['domain'].startswith('.'):
            self.security_issues.append({
                'type': 'Overly Permissive Cookie Domain',
                'severity': 'MEDIUM',
                'description': f'Cookie {cookie_data["name"]} has wildcard domain {cookie_data["domain"]}',
                'cookie': cookie_data['name']
            })
    
    def _analyze_cookie_content(self, cookie_data):
        """Analyze cookie content for sensitive data"""
        value = cookie_data['value']
        analysis = cookie_data['analysis']
        
        # Check if it looks like JWT
        if value.count('.') == 2:
            analysis['type'] = 'Possible JWT'
            try:
                # Try to decode JWT header
                header_b64 = value.split('.')[0]
                # Add padding if needed
                header_b64 += '=' * (4 - len(header_b64) % 4)
                header = json.loads(base64.b64decode(header_b64))
                analysis['jwt_header'] = header
                
                # Check for weak algorithms
                if header.get('alg') in ['none', 'HS256']:
                    self.security_issues.append({
                        'type': 'Weak JWT Algorithm',
                        'severity': 'HIGH',
                        'description': f'JWT cookie uses weak algorithm: {header.get("alg")}',
                        'cookie': cookie_data['name']
                    })
            except Exception:
                pass
        
        # Check for base64 encoded data
        elif self._is_base64(value):
            analysis['type'] = 'Base64 Encoded'
            try:
                decoded = base64.b64decode(value).decode('utf-8')
                analysis['decoded_preview'] = decoded[:100]
                
                # Check for serialized data patterns
                if any(pattern in decoded for pattern in ['O:', 'a:', 's:']):
                    analysis['serialization'] = 'PHP Serialized'
                    self.security_issues.append({
                        'type': 'Serialized Cookie Data',
                        'severity': 'MEDIUM',
                        'description': f'Cookie {cookie_data["name"]} contains serialized data',
                        'cookie': cookie_data['name']
                    })
            except Exception:
                pass
        
        # Check for predictable session IDs (more aggressive)
        if len(value) < 20:  # Increased threshold
            self.security_issues.append({
                'type': 'Weak Session ID',
                'severity': 'HIGH',
                'description': f'Cookie {cookie_data["name"]} has short/weak value - vulnerable to session prediction attacks',
                'cookie': cookie_data['name']
            })
        
        # Check for sequential or predictable patterns
        if value.isdigit() or value.isalnum() and len(set(value)) < 4:
            self.security_issues.append({
                'type': 'Predictable Session ID',
                'severity': 'HIGH',
                'description': f'Cookie {cookie_data["name"]} appears to have predictable pattern',
                'cookie': cookie_data['name']
            })
        
        # Check for default session names and report as security issue
        default_sessions = ['PHPSESSID', 'JSESSIONID', 'ASP.NET_SessionId', 'ASPSESSIONID']
        if cookie_data['name'] in default_sessions or cookie_data['name'].startswith('ASPSESSIONID'):
            analysis['default_session'] = True
            self.security_issues.append({
                'type': 'Default Session Cookie Name',
                'severity': 'LOW',
                'description': f'Using default session cookie name {cookie_data["name"]} - reveals technology stack',
                'cookie': cookie_data['name']
            })
    
    def _is_base64(self, s):
        """Check if string is base64 encoded"""
        try:
            if len(s) % 4 == 0 and re.match(r'^[A-Za-z0-9+/]*={0,2}$', s):
                base64.b64decode(s)
                return True
        except Exception:
            pass
        return False