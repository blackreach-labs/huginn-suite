# app/core/session_harvester.py
"""
Session & Cookie Harvester for HTTP Interceptor.
Automatically extracts and categorizes session tokens, cookies, JWTs,
CSRF tokens, and other authentication artifacts from intercepted proxy traffic.
"""
import re
import json
import time
import base64
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from PyQt6.QtCore import QObject, pyqtSignal


@dataclass
class HarvestedToken:
    """Represents a single harvested session/cookie/token"""
    name: str
    value: str
    category: str  # session, jwt, csrf, remember_me, analytics, feature_role
    source: str  # 'cookie', 'header', 'body'
    domain: str
    path: str = "/"
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    secure: bool = False
    httponly: bool = False
    samesite: str = ""
    expires: str = ""
    raw_header: str = ""

    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'value': self.value,
            'category': self.category,
            'source': self.source,
            'domain': self.domain,
            'path': self.path,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'secure': self.secure,
            'httponly': self.httponly,
            'samesite': self.samesite,
            'expires': self.expires,
            'raw_header': self.raw_header,
        }


# Cookie name patterns for categorization
SESSION_PATTERNS = [
    r'^PHPSESSID$', r'^connect\.sid$', r'^JSESSIONID$', r'^session$',
    r'^session[-_]?id$', r'^sess[-_]?id$', r'^ASP\.NET_SessionId$',
    r'^ASPSESSIONID', r'^ci_session$', r'^laravel_session$',
    r'^_session$', r'^rack\.session$', r'^_rails_session$',
    r'^express[-_.]?sess', r'^flask[-_]?session$', r'^tornado[-_]?session$',
]

JWT_PATTERNS = [
    r'^token$', r'^access[-_]?token$', r'^auth[-_]?token$',
    r'^id[-_]?token$', r'^refresh[-_]?token$', r'^jwt$',
    r'^bearer[-_]?token$', r'^api[-_]?token$', r'^x[-_]?auth[-_]?token$',
]

CSRF_PATTERNS = [
    r'^csrf', r'^_csrf', r'^xsrf', r'^_xsrf', r'^anti[-_]?forgery',
    r'^__RequestVerificationToken', r'^csrfmiddlewaretoken',
    r'^_token$', r'^authenticity_token$', r'^X-CSRF-TOKEN',
]

REMEMBER_ME_PATTERNS = [
    r'^remember[-_]?me', r'^remember[-_]?token', r'^persistent',
    r'^stay[-_]?logged', r'^keep[-_]?me', r'^auto[-_]?login',
]

ANALYTICS_PATTERNS = [
    r'^_ga$', r'^_gid$', r'^_gat', r'^__utm', r'^_fbp$', r'^_fbc$',
    r'^__hstc', r'^hubspotutk', r'^mp_', r'^amplitude',
    r'^_hjid', r'^_hjSession', r'^ajs_', r'^intercom',
    r'^debug', r'^_dd_', r'^trace[-_]?id',
]

FEATURE_ROLE_PATTERNS = [
    r'^role$', r'^user[-_]?role', r'^permissions?$', r'^scope$',
    r'^feature[-_]?flag', r'^ff[-_]', r'^experiment',
    r'^variant$', r'^ab[-_]?test', r'^bucket$',
]


class SessionHarvester(QObject):
    """Harvests and categorizes session/cookie data from proxy traffic"""
    
    token_harvested = pyqtSignal(dict)  # Emitted when a new token is found
    tokens_updated = pyqtSignal()  # Emitted when token list changes
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.tokens: Dict[str, HarvestedToken] = {}  # key = "domain:name"
        self._compiled_patterns = self._compile_patterns()
    
    def _compile_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Pre-compile regex patterns for performance"""
        return {
            'session': [re.compile(p, re.IGNORECASE) for p in SESSION_PATTERNS],
            'jwt': [re.compile(p, re.IGNORECASE) for p in JWT_PATTERNS],
            'csrf': [re.compile(p, re.IGNORECASE) for p in CSRF_PATTERNS],
            'remember_me': [re.compile(p, re.IGNORECASE) for p in REMEMBER_ME_PATTERNS],
            'analytics': [re.compile(p, re.IGNORECASE) for p in ANALYTICS_PATTERNS],
            'feature_role': [re.compile(p, re.IGNORECASE) for p in FEATURE_ROLE_PATTERNS],
        }
    
    def categorize_cookie(self, name: str, value: str = "") -> str:
        """Categorize a cookie/token by its name and optionally its value"""
        # Check name against patterns
        for category, patterns in self._compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(name):
                    return category
        
        # Check if value looks like a JWT (header.payload.signature)
        if value and self._is_jwt(value):
            return 'jwt'
        
        return 'unknown'
    
    def _is_jwt(self, value: str) -> bool:
        """Check if a value looks like a JWT token"""
        parts = value.split('.')
        if len(parts) != 3:
            return False
        try:
            # Try to decode the header
            header = parts[0] + '=' * (4 - len(parts[0]) % 4)
            decoded = base64.urlsafe_b64decode(header)
            parsed = json.loads(decoded)
            return 'alg' in parsed or 'typ' in parsed
        except Exception:
            return False
    
    def decode_jwt(self, token: str) -> Optional[Dict]:
        """Decode a JWT token (without verification) for display"""
        parts = token.split('.')
        if len(parts) != 3:
            return None
        try:
            # Decode header
            header_padded = parts[0] + '=' * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_padded))
            
            # Decode payload
            payload_padded = parts[1] + '=' * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_padded))
            
            return {
                'header': header,
                'payload': payload,
                'signature': parts[2][:20] + '...' if len(parts[2]) > 20 else parts[2]
            }
        except Exception:
            return None
    
    def process_response(self, url: str, request_headers: Dict, response_headers: Dict, response_body: str = ""):
        """Process a response to extract session/cookie information"""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Extract Set-Cookie headers from response
        self._extract_set_cookies(response_headers, domain)
        
        # Extract Cookie headers from request (shows what's being sent)
        self._extract_request_cookies(request_headers, domain)
        
        # Extract Authorization headers
        self._extract_auth_headers(request_headers, domain)
        
        # Extract tokens from response body (JSON responses)
        self._extract_body_tokens(response_body, domain)
    
    def _extract_set_cookies(self, headers: Dict, domain: str):
        """Extract cookies from Set-Cookie response headers"""
        for key, value in headers.items():
            if key.lower() == 'set-cookie':
                self._parse_set_cookie(value, domain)
    
    def _parse_set_cookie(self, header_value: str, domain: str):
        """Parse a Set-Cookie header value"""
        # Handle multiple cookies separated by newlines (some servers)
        for cookie_str in header_value.split('\n'):
            cookie_str = cookie_str.strip()
            if not cookie_str:
                continue
            
            parts = cookie_str.split(';')
            if not parts:
                continue
            
            # First part is name=value
            name_value = parts[0].strip()
            if '=' not in name_value:
                continue
            
            name, value = name_value.split('=', 1)
            name = name.strip()
            value = value.strip()
            
            # Parse attributes
            secure = False
            httponly = False
            samesite = ""
            expires = ""
            path = "/"
            
            for attr in parts[1:]:
                attr = attr.strip().lower()
                if attr == 'secure':
                    secure = True
                elif attr == 'httponly':
                    httponly = True
                elif attr.startswith('samesite='):
                    samesite = attr.split('=', 1)[1]
                elif attr.startswith('expires='):
                    expires = attr.split('=', 1)[1]
                elif attr.startswith('path='):
                    path = attr.split('=', 1)[1]
            
            category = self.categorize_cookie(name, value)
            self._store_token(
                name=name,
                value=value,
                category=category,
                source='cookie',
                domain=domain,
                path=path,
                secure=secure,
                httponly=httponly,
                samesite=samesite,
                expires=expires,
                raw_header=cookie_str,
            )
    
    def _extract_request_cookies(self, headers: Dict, domain: str):
        """Extract cookies from Cookie request header"""
        for key, value in headers.items():
            if key.lower() == 'cookie':
                cookies = value.split(';')
                for cookie in cookies:
                    cookie = cookie.strip()
                    if '=' in cookie:
                        name, val = cookie.split('=', 1)
                        name = name.strip()
                        val = val.strip()
                        category = self.categorize_cookie(name, val)
                        self._store_token(
                            name=name,
                            value=val,
                            category=category,
                            source='cookie',
                            domain=domain,
                        )
    
    def _extract_auth_headers(self, headers: Dict, domain: str):
        """Extract tokens from Authorization and custom auth headers"""
        auth_header_names = ['authorization', 'x-auth-token', 'x-api-key', 'x-csrf-token', 'x-xsrf-token']
        
        for key, value in headers.items():
            if key.lower() in auth_header_names:
                # Bearer token
                if value.lower().startswith('bearer '):
                    token_value = value[7:].strip()
                    category = 'jwt' if self._is_jwt(token_value) else 'session'
                    self._store_token(
                        name=f"Authorization (Bearer)",
                        value=token_value,
                        category=category,
                        source='header',
                        domain=domain,
                    )
                elif key.lower() == 'x-csrf-token' or key.lower() == 'x-xsrf-token':
                    self._store_token(
                        name=key,
                        value=value,
                        category='csrf',
                        source='header',
                        domain=domain,
                    )
                else:
                    self._store_token(
                        name=key,
                        value=value,
                        category='session',
                        source='header',
                        domain=domain,
                    )
    
    def _extract_body_tokens(self, body: str, domain: str):
        """Extract tokens from JSON response bodies"""
        if not body:
            return
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                token_keys = ['token', 'access_token', 'refresh_token', 'id_token',
                              'jwt', 'session_token', 'auth_token', 'csrf_token',
                              'xsrf_token', 'api_key']
                for key in token_keys:
                    if key in data and isinstance(data[key], str):
                        category = self.categorize_cookie(key, data[key])
                        self._store_token(
                            name=key,
                            value=data[key],
                            category=category,
                            source='body',
                            domain=domain,
                        )
        except (json.JSONDecodeError, ValueError):
            pass
    
    def _store_token(self, name: str, value: str, category: str, source: str,
                     domain: str, path: str = "/", secure: bool = False,
                     httponly: bool = False, samesite: str = "", expires: str = "",
                     raw_header: str = ""):
        """Store or update a harvested token"""
        token_key = f"{domain}:{name}"
        now = time.time()
        
        if token_key in self.tokens:
            # Update existing
            existing = self.tokens[token_key]
            existing.value = value
            existing.last_seen = now
            if secure:
                existing.secure = secure
            if httponly:
                existing.httponly = httponly
            if samesite:
                existing.samesite = samesite
            if expires:
                existing.expires = expires
            if raw_header:
                existing.raw_header = raw_header
        else:
            # New token
            self.tokens[token_key] = HarvestedToken(
                name=name,
                value=value,
                category=category,
                source=source,
                domain=domain,
                path=path,
                first_seen=now,
                last_seen=now,
                secure=secure,
                httponly=httponly,
                samesite=samesite,
                expires=expires,
                raw_header=raw_header,
            )
        
        self.token_harvested.emit(self.tokens[token_key].to_dict())
        self.tokens_updated.emit()
    
    def get_tokens_by_category(self) -> Dict[str, List[HarvestedToken]]:
        """Get all tokens grouped by category"""
        categorized = {
            'session': [],
            'jwt': [],
            'csrf': [],
            'remember_me': [],
            'analytics': [],
            'feature_role': [],
            'unknown': [],
        }
        for token in self.tokens.values():
            if token.category in categorized:
                categorized[token.category].append(token)
            else:
                categorized['unknown'].append(token)
        return categorized
    
    def get_tokens_by_domain(self) -> Dict[str, List[HarvestedToken]]:
        """Get all tokens grouped by domain"""
        by_domain = {}
        for token in self.tokens.values():
            if token.domain not in by_domain:
                by_domain[token.domain] = []
            by_domain[token.domain].append(token)
        return by_domain
    
    def get_all_tokens(self) -> List[Dict]:
        """Get all tokens as a list of dicts"""
        return [t.to_dict() for t in self.tokens.values()]
    
    def get_security_findings(self) -> List[Dict]:
        """Analyze tokens for security issues useful in pentesting"""
        findings = []
        
        for token in self.tokens.values():
            # Session cookie without Secure flag
            if token.category == 'session' and not token.secure:
                findings.append({
                    'severity': 'Medium',
                    'title': f'Session cookie "{token.name}" missing Secure flag',
                    'domain': token.domain,
                    'detail': 'Cookie can be transmitted over unencrypted HTTP connections.',
                })
            
            # Session cookie without HttpOnly flag
            if token.category == 'session' and not token.httponly:
                findings.append({
                    'severity': 'Medium',
                    'title': f'Session cookie "{token.name}" missing HttpOnly flag',
                    'domain': token.domain,
                    'detail': 'Cookie accessible via JavaScript (XSS risk).',
                })
            
            # Missing SameSite attribute
            if token.category in ('session', 'csrf') and not token.samesite:
                findings.append({
                    'severity': 'Low',
                    'title': f'Cookie "{token.name}" missing SameSite attribute',
                    'domain': token.domain,
                    'detail': 'Cookie may be vulnerable to CSRF attacks.',
                })
            
            # JWT without expiration
            if token.category == 'jwt' and self._is_jwt(token.value):
                decoded = self.decode_jwt(token.value)
                if decoded and 'exp' not in decoded.get('payload', {}):
                    findings.append({
                        'severity': 'High',
                        'title': f'JWT "{token.name}" has no expiration',
                        'domain': token.domain,
                        'detail': 'Token never expires, increasing risk if compromised.',
                    })
                # Check for weak algorithm
                if decoded and decoded.get('header', {}).get('alg') == 'none':
                    findings.append({
                        'severity': 'Critical',
                        'title': f'JWT "{token.name}" uses "none" algorithm',
                        'domain': token.domain,
                        'detail': 'Token has no signature verification - can be forged.',
                    })
        
        return findings
    
    def export_for_replay(self) -> str:
        """Export session tokens in a format useful for request replay/injection"""
        lines = []
        for token in self.tokens.values():
            if token.category in ('session', 'jwt', 'csrf'):
                if token.source == 'cookie':
                    lines.append(f"Cookie: {token.name}={token.value}")
                elif token.source == 'header':
                    if 'bearer' in token.name.lower():
                        lines.append(f"Authorization: Bearer {token.value}")
                    else:
                        lines.append(f"{token.name}: {token.value}")
        return '\n'.join(lines)
    
    def clear(self):
        """Clear all harvested tokens"""
        self.tokens.clear()
        self.tokens_updated.emit()
