# app/core/auth_token_analyzer.py
import json
import base64
import time
import hashlib
import re
from typing import Dict, List, Optional, Any
from urllib.parse import parse_qs, unquote
from PyQt6.QtCore import QObject, pyqtSignal
from app.core.logger import logger

class AuthTokenAnalyzer(QObject):
    """Analyzes authentication tokens and cookies"""
    
    token_analyzed = pyqtSignal(dict)  # token analysis results
    vulnerability_found = pyqtSignal(dict)  # token vulnerability
    
    def __init__(self):
        super().__init__()
        self.jwt_algorithms = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'none']
        self.weak_secrets = ['secret', 'key', 'password', '123456', 'admin', 'test']
    
    def analyze_token(self, token_name: str, token_value: str, source: str = "unknown") -> dict:
        """Analyze a token and return detailed information"""
        analysis = {
            'name': token_name,
            'value': token_value[:100] + '...' if len(token_value) > 100 else token_value,
            'source': source,
            'type': self._identify_token_type(token_value),
            'length': len(token_value),
            'entropy': self._calculate_entropy(token_value),
            'timestamp': time.time(),
            'vulnerabilities': [],
            'properties': {}
        }
        
        # Analyze based on token type
        if analysis['type'] == 'jwt':
            analysis.update(self._analyze_jwt(token_value))
        elif analysis['type'] == 'oauth_access_token':
            analysis.update(self._analyze_oauth_token(token_value))
        elif analysis['type'] == 'session_cookie':
            analysis.update(self._analyze_session_cookie(token_value))
        elif analysis['type'] == 'csrf_token':
            analysis.update(self._analyze_csrf_token(token_value))
        else:
            analysis.update(self._analyze_generic_token(token_value))
        
        # Check for common vulnerabilities
        self._check_token_vulnerabilities(analysis)
        
        # Emit signals
        self.token_analyzed.emit(analysis)
        for vuln in analysis['vulnerabilities']:
            self.vulnerability_found.emit(vuln)
        
        return analysis
    
    def _identify_token_type(self, token_value: str) -> str:
        """Identify the type of token"""
        # JWT tokens have 3 parts separated by dots
        if token_value.count('.') == 2:
            try:
                parts = token_value.split('.')
                # Try to decode header
                header = self._safe_base64_decode(parts[0])
                if header and 'alg' in header:
                    return 'jwt'
            except Exception as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        
        # OAuth access tokens are often long and random
        if len(token_value) > 20 and re.match(r'^[A-Za-z0-9_-]+$', token_value):
            return 'oauth_access_token'
        
        # Session cookies are often shorter and may have specific patterns
        if len(token_value) < 50 and any(pattern in token_value.lower() for pattern in ['sess', 'phpsessid', 'jsessionid']):
            return 'session_cookie'
        
        # CSRF tokens are often 32-64 characters
        if 20 <= len(token_value) <= 64 and re.match(r'^[A-Za-z0-9+/=_-]+$', token_value):
            return 'csrf_token'
        
        return 'unknown'
    
    def _analyze_jwt(self, token_value: str) -> dict:
        """Analyze JWT token"""
        analysis = {'jwt_data': {}}
        
        try:
            parts = token_value.split('.')
            if len(parts) != 3:
                return analysis
            
            # Decode header
            header = self._safe_base64_decode(parts[0])
            if header:
                analysis['jwt_data']['header'] = header
                analysis['properties']['algorithm'] = header.get('alg', 'unknown')
                analysis['properties']['type'] = header.get('typ', 'unknown')
            
            # Decode payload
            payload = self._safe_base64_decode(parts[1])
            if payload:
                analysis['jwt_data']['payload'] = payload
                
                # Extract standard claims
                if 'exp' in payload:
                    analysis['properties']['expires_at'] = payload['exp']
                    analysis['properties']['is_expired'] = payload['exp'] < time.time()
                
                if 'iat' in payload:
                    analysis['properties']['issued_at'] = payload['iat']
                
                if 'nbf' in payload:
                    analysis['properties']['not_before'] = payload['nbf']
                
                if 'iss' in payload:
                    analysis['properties']['issuer'] = payload['iss']
                
                if 'aud' in payload:
                    analysis['properties']['audience'] = payload['aud']
                
                if 'sub' in payload:
                    analysis['properties']['subject'] = payload['sub']
                
                if 'scope' in payload:
                    analysis['properties']['scope'] = payload['scope']
                
                if 'roles' in payload:
                    analysis['properties']['roles'] = payload['roles']
            
            # Signature (don't decode, just note presence)
            analysis['properties']['has_signature'] = len(parts[2]) > 0
            
        except Exception as e:
            analysis['jwt_data']['error'] = str(e)
        
        return analysis
    
    def _analyze_oauth_token(self, token_value: str) -> dict:
        """Analyze OAuth access token"""
        analysis = {}
        
        # Check if it's a structured token (like Microsoft Graph tokens)
        if token_value.startswith('eyJ'):  # Base64 encoded JSON
            try:
                decoded = base64.b64decode(token_value + '==')
                data = json.loads(decoded)
                analysis['oauth_data'] = data
            except Exception as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        
        # Analyze token characteristics
        analysis['properties'] = {
            'is_bearer_token': True,
            'character_set': self._analyze_character_set(token_value),
            'possible_encoding': self._detect_encoding(token_value)
        }
        
        return analysis
    
    def _analyze_session_cookie(self, token_value: str) -> dict:
        """Analyze session cookie"""
        analysis = {}
        
        # Check for common session cookie patterns
        if token_value.isdigit():
            analysis['properties'] = {
                'type': 'numeric_session_id',
                'predictable': True,
                'sequential_risk': True
            }
        elif re.match(r'^[a-f0-9]+$', token_value.lower()):
            analysis['properties'] = {
                'type': 'hex_session_id',
                'predictable': len(token_value) < 32
            }
        else:
            analysis['properties'] = {
                'type': 'random_session_id',
                'character_set': self._analyze_character_set(token_value)
            }
        
        return analysis
    
    def _analyze_csrf_token(self, token_value: str) -> dict:
        """Analyze CSRF token"""
        analysis = {}
        
        analysis['properties'] = {
            'character_set': self._analyze_character_set(token_value),
            'possible_encoding': self._detect_encoding(token_value),
            'sufficient_length': len(token_value) >= 32
        }
        
        return analysis
    
    def _analyze_generic_token(self, token_value: str) -> dict:
        """Analyze unknown token type"""
        analysis = {}
        
        analysis['properties'] = {
            'character_set': self._analyze_character_set(token_value),
            'possible_encoding': self._detect_encoding(token_value),
            'patterns': self._find_patterns(token_value)
        }
        
        return analysis
    
    def _safe_base64_decode(self, data: str) -> Optional[dict]:
        """Safely decode base64 JWT part"""
        try:
            # Add padding if needed
            data += '=' * (4 - len(data) % 4)
            decoded = base64.urlsafe_b64decode(data)
            return json.loads(decoded)
        except:
            return None
    
    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of the token"""
        if not data:
            return 0
        
        # Count character frequencies
        char_counts = {}
        for char in data:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0
        data_len = len(data)
        for count in char_counts.values():
            probability = count / data_len
            entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    def _analyze_character_set(self, token_value: str) -> dict:
        """Analyze character set used in token"""
        has_upper = any(c.isupper() for c in token_value)
        has_lower = any(c.islower() for c in token_value)
        has_digits = any(c.isdigit() for c in token_value)
        has_special = any(not c.isalnum() for c in token_value)
        
        return {
            'uppercase': has_upper,
            'lowercase': has_lower,
            'digits': has_digits,
            'special_chars': has_special,
            'unique_chars': len(set(token_value)),
            'total_chars': len(token_value)
        }
    
    def _detect_encoding(self, token_value: str) -> str:
        """Detect possible encoding of the token"""
        # Check for base64
        if re.match(r'^[A-Za-z0-9+/]*={0,2}$', token_value):
            return 'base64'
        
        # Check for base64url
        if re.match(r'^[A-Za-z0-9_-]*$', token_value):
            return 'base64url'
        
        # Check for hex
        if re.match(r'^[a-fA-F0-9]+$', token_value):
            return 'hex'
        
        # Check for URL encoding
        if '%' in token_value:
            return 'url_encoded'
        
        return 'unknown'
    
    def _find_patterns(self, token_value: str) -> List[str]:
        """Find patterns in the token"""
        patterns = []
        
        # Check for timestamp patterns
        if re.search(r'\d{10}', token_value):  # Unix timestamp
            patterns.append('unix_timestamp')
        
        # Check for UUID patterns
        if re.search(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', token_value, re.I):
            patterns.append('uuid')
        
        # Check for repeated patterns
        if len(set(token_value)) < len(token_value) * 0.5:
            patterns.append('high_repetition')
        
        return patterns
    
    def _check_token_vulnerabilities(self, analysis: dict):
        """Check for token vulnerabilities"""
        vulnerabilities = []
        
        # Check JWT vulnerabilities
        if analysis['type'] == 'jwt':
            jwt_data = analysis.get('jwt_data', {})
            header = jwt_data.get('header', {})
            payload = jwt_data.get('payload', {})
            
            # Check for none algorithm
            if header.get('alg') == 'none':
                vulnerabilities.append({
                    'type': 'jwt_none_algorithm',
                    'severity': 'critical',
                    'description': 'JWT uses "none" algorithm - signature verification bypassed',
                    'token_name': analysis['name']
                })
            
            # Check for expired tokens
            if analysis['properties'].get('is_expired'):
                vulnerabilities.append({
                    'type': 'expired_token',
                    'severity': 'medium',
                    'description': 'JWT token is expired',
                    'token_name': analysis['name']
                })
            
            # Check for missing expiration
            if 'exp' not in payload:
                vulnerabilities.append({
                    'type': 'jwt_no_expiration',
                    'severity': 'medium',
                    'description': 'JWT token has no expiration claim',
                    'token_name': analysis['name']
                })
            
            # Check for overly broad scope
            scope = analysis['properties'].get('scope', '')
            if isinstance(scope, str) and ('*' in scope or 'admin' in scope.lower()):
                vulnerabilities.append({
                    'type': 'overly_broad_scope',
                    'severity': 'medium',
                    'description': 'JWT token has overly broad scope',
                    'token_name': analysis['name'],
                    'scope': scope
                })
        
        # Check for low entropy tokens
        if analysis['entropy'] < 3.0:
            vulnerabilities.append({
                'type': 'low_entropy_token',
                'severity': 'medium',
                'description': f'Token has low entropy ({analysis["entropy"]:.2f}) - may be predictable',
                'token_name': analysis['name']
            })
        
        # Check for short tokens
        if analysis['length'] < 16:
            vulnerabilities.append({
                'type': 'short_token',
                'severity': 'medium',
                'description': f'Token is too short ({analysis["length"]} chars) - may be brute-forceable',
                'token_name': analysis['name']
            })
        
        # Check for predictable session IDs
        if analysis['type'] == 'session_cookie':
            props = analysis.get('properties', {})
            if props.get('predictable') or props.get('sequential_risk'):
                vulnerabilities.append({
                    'type': 'predictable_session_id',
                    'severity': 'high',
                    'description': 'Session ID appears to be predictable or sequential',
                    'token_name': analysis['name']
                })
        
        analysis['vulnerabilities'] = vulnerabilities
    
    def analyze_multiple_tokens(self, tokens: Dict[str, dict]) -> dict:
        """Analyze multiple tokens and find relationships"""
        results = {
            'individual_analyses': {},
            'relationships': [],
            'summary': {
                'total_tokens': len(tokens),
                'token_types': {},
                'total_vulnerabilities': 0,
                'high_risk_tokens': []
            }
        }
        
        # Analyze each token individually
        for token_name, token_info in tokens.items():
            token_value = token_info.get('value', '')
            source = token_info.get('source', 'unknown')
            
            analysis = self.analyze_token(token_name, token_value, source)
            results['individual_analyses'][token_name] = analysis
            
            # Update summary
            token_type = analysis['type']
            results['summary']['token_types'][token_type] = results['summary']['token_types'].get(token_type, 0) + 1
            results['summary']['total_vulnerabilities'] += len(analysis['vulnerabilities'])
            
            # Check for high-risk tokens
            high_risk_vulns = ['jwt_none_algorithm', 'predictable_session_id']
            if any(v['type'] in high_risk_vulns for v in analysis['vulnerabilities']):
                results['summary']['high_risk_tokens'].append(token_name)
        
        # Find token relationships
        results['relationships'] = self._find_token_relationships(results['individual_analyses'])
        
        return results
    
    def _find_token_relationships(self, analyses: Dict[str, dict]) -> List[dict]:
        """Find relationships between tokens"""
        relationships = []
        
        token_names = list(analyses.keys())
        
        # Check for token reuse
        values_seen = {}
        for name, analysis in analyses.items():
            value = analysis['value']
            if value in values_seen:
                relationships.append({
                    'type': 'token_reuse',
                    'tokens': [values_seen[value], name],
                    'description': 'Same token value used in multiple contexts'
                })
            else:
                values_seen[value] = name
        
        # Check for related JWT tokens (same issuer, similar claims)
        jwt_tokens = {name: analysis for name, analysis in analyses.items() if analysis['type'] == 'jwt'}
        
        for name1, analysis1 in jwt_tokens.items():
            for name2, analysis2 in jwt_tokens.items():
                if name1 >= name2:  # Avoid duplicate comparisons
                    continue
                
                payload1 = analysis1.get('jwt_data', {}).get('payload', {})
                payload2 = analysis2.get('jwt_data', {}).get('payload', {})
                
                # Check for same issuer
                if payload1.get('iss') == payload2.get('iss') and payload1.get('iss'):
                    relationships.append({
                        'type': 'same_issuer',
                        'tokens': [name1, name2],
                        'description': f'JWT tokens from same issuer: {payload1["iss"]}'
                    })
                
                # Check for same subject
                if payload1.get('sub') == payload2.get('sub') and payload1.get('sub'):
                    relationships.append({
                        'type': 'same_subject',
                        'tokens': [name1, name2],
                        'description': f'JWT tokens for same subject: {payload1["sub"]}'
                    })
        
        return relationships
    
    def generate_token_report(self, analyses: dict) -> str:
        """Generate a human-readable token analysis report"""
        report = []
        report.append("=== TOKEN ANALYSIS REPORT ===\n")
        
        summary = analyses['summary']
        report.append(f"Total Tokens Analyzed: {summary['total_tokens']}")
        report.append(f"Total Vulnerabilities: {summary['total_vulnerabilities']}")
        report.append(f"High-Risk Tokens: {len(summary['high_risk_tokens'])}")
        report.append("")
        
        # Token type breakdown
        report.append("Token Types:")
        for token_type, count in summary['token_types'].items():
            report.append(f"  - {token_type}: {count}")
        report.append("")
        
        # Individual token details
        for token_name, analysis in analyses['individual_analyses'].items():
            report.append(f"=== {token_name.upper()} ===")
            report.append(f"Type: {analysis['type']}")
            report.append(f"Length: {analysis['length']} characters")
            report.append(f"Entropy: {analysis['entropy']:.2f}")
            report.append(f"Source: {analysis['source']}")
            
            if analysis['vulnerabilities']:
                report.append("Vulnerabilities:")
                for vuln in analysis['vulnerabilities']:
                    report.append(f"  - [{vuln['severity'].upper()}] {vuln['description']}")
            else:
                report.append("No vulnerabilities found")
            
            report.append("")
        
        # Relationships
        if analyses['relationships']:
            report.append("=== TOKEN RELATIONSHIPS ===")
            for rel in analyses['relationships']:
                report.append(f"{rel['type']}: {' <-> '.join(rel['tokens'])}")
                report.append(f"  {rel['description']}")
            report.append("")
        
        return "\n".join(report)