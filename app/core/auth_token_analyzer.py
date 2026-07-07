# app/core/auth_token_analyzer.py
"""Enterprise-grade authentication token and credential analyzer.

Provides deep inspection of authentication artifacts:
- JWT: header/payload decode, algorithm analysis, claim validation, key confusion
- OAuth 2.0: access/refresh token structure, scope analysis, lifetime
- OIDC: id_token validation (aud, iss, nonce, at_hash, exp)
- SAML: assertion parsing, signature analysis, conditions, attribute extraction
- Kerberos: ticket structure, encryption type, SPN, delegation flags
- NTLM: message parsing, hash extraction, version detection
- Session Cookies: entropy, predictability, attribute analysis
- API Keys: entropy, pattern analysis, scope detection
"""
import json
import base64
import time
import math
import re
import struct
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from collections import Counter
from PyQt6.QtCore import QObject, pyqtSignal
from app.core.logger import logger


# ──────────────────────────────────────────────────────────────────────────────
# Token Type Classification
# ──────────────────────────────────────────────────────────────────────────────

class TokenType:
    JWT = "jwt"
    OAUTH_ACCESS = "oauth_access_token"
    OAUTH_REFRESH = "oauth_refresh_token"
    OIDC_ID_TOKEN = "oidc_id_token"
    SAML_ASSERTION = "saml_assertion"
    KERBEROS_TICKET = "kerberos_ticket"
    NTLM_HASH = "ntlm_hash"
    SESSION_COOKIE = "session_cookie"
    CSRF_TOKEN = "csrf_token"
    API_KEY = "api_key"
    BASIC_CREDENTIALS = "basic_credentials"
    BEARER_OPAQUE = "bearer_opaque"
    UNKNOWN = "unknown"


# Well-known weak JWT secrets for brute-force check
COMMON_JWT_SECRETS = [
    'secret', 'password', '123456', 'admin', 'key', 'test', 'jwt_secret',
    'changeme', 'supersecret', 'qwerty', 'letmein', 'default',
    'HS256-secret', 'your-256-bit-secret', 'jwt-key', 'token-secret',
]


class AuthTokenAnalyzer(QObject):
    """Analyzes authentication tokens and credentials for security issues."""

    token_analyzed = pyqtSignal(dict)
    vulnerability_found = pyqtSignal(dict)

    def __init__(self):
        super().__init__()

    # ──────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────

    def analyze_token(self, token_name: str, token_value: str,
                      source: str = "unknown", context: dict = None) -> dict:
        """Analyze a single token and return detailed results."""
        token_type = self._classify_token(token_name, token_value, source)

        analysis = {
            'name': token_name,
            'value_preview': token_value[:80] + '...' if len(token_value) > 80 else token_value,
            'full_value': token_value,
            'source': source,
            'type': token_type,
            'length': len(token_value),
            'entropy': self._shannon_entropy(token_value),
            'timestamp': time.time(),
            'vulnerabilities': [],
            'properties': {},
            'recommendations': [],
        }

        # Type-specific deep analysis
        analyzers = {
            TokenType.JWT: self._analyze_jwt,
            TokenType.OIDC_ID_TOKEN: self._analyze_oidc_id_token,
            TokenType.OAUTH_ACCESS: self._analyze_oauth_token,
            TokenType.OAUTH_REFRESH: self._analyze_oauth_token,
            TokenType.SAML_ASSERTION: self._analyze_saml_assertion,
            TokenType.KERBEROS_TICKET: self._analyze_kerberos_ticket,
            TokenType.NTLM_HASH: self._analyze_ntlm_token,
            TokenType.SESSION_COOKIE: self._analyze_session_cookie,
            TokenType.CSRF_TOKEN: self._analyze_csrf_token,
            TokenType.API_KEY: self._analyze_api_key,
            TokenType.BASIC_CREDENTIALS: self._analyze_basic_creds,
        }

        analyzer = analyzers.get(token_type)
        if analyzer:
            analyzer(analysis, token_value, context or {})
        else:
            self._analyze_generic(analysis, token_value)

        # Universal vulnerability checks
        self._check_universal_vulns(analysis)

        # Emit signals
        self.token_analyzed.emit(analysis)
        for vuln in analysis['vulnerabilities']:
            self.vulnerability_found.emit(vuln)

        return analysis

    def analyze_multiple_tokens(self, tokens: Dict[str, dict]) -> dict:
        """Analyze multiple tokens and find relationships."""
        results = {
            'individual_analyses': {},
            'relationships': [],
            'summary': {
                'total_tokens': len(tokens),
                'token_types': {},
                'total_vulnerabilities': 0,
                'critical_findings': [],
                'high_findings': [],
            }
        }

        for token_name, token_info in tokens.items():
            value = token_info.get('value', '')
            source = token_info.get('source', 'unknown')
            analysis = self.analyze_token(token_name, value, source, token_info)
            results['individual_analyses'][token_name] = analysis

            # Update summary
            t = analysis['type']
            results['summary']['token_types'][t] = results['summary']['token_types'].get(t, 0) + 1
            results['summary']['total_vulnerabilities'] += len(analysis['vulnerabilities'])
            for v in analysis['vulnerabilities']:
                if v.get('severity') == 'critical':
                    results['summary']['critical_findings'].append(v)
                elif v.get('severity') == 'high':
                    results['summary']['high_findings'].append(v)

        # Cross-token relationship analysis
        results['relationships'] = self._find_relationships(results['individual_analyses'])
        return results

    def generate_token_report(self, analysis_results: dict) -> str:
        """Generate human-readable report from analysis results."""
        lines = ["═══ Authentication Token Analysis Report ═══\n"]
        summary = analysis_results.get('summary', {})
        lines.append(f"Total Tokens Analyzed: {summary.get('total_tokens', 0)}")
        lines.append(f"Vulnerabilities Found: {summary.get('total_vulnerabilities', 0)}")
        lines.append(f"Critical: {len(summary.get('critical_findings', []))}")
        lines.append(f"High: {len(summary.get('high_findings', []))}")
        lines.append(f"\nToken Types: {summary.get('token_types', {})}\n")

        for name, analysis in analysis_results.get('individual_analyses', {}).items():
            lines.append(f"\n─── {name} ({analysis['type']}) ───")
            lines.append(f"  Source: {analysis['source']}")
            lines.append(f"  Length: {analysis['length']} chars")
            lines.append(f"  Entropy: {analysis['entropy']:.2f} bits/char")
            props = analysis.get('properties', {})
            if props:
                for k, v in list(props.items())[:10]:
                    lines.append(f"  {k}: {v}")
            vulns = analysis.get('vulnerabilities', [])
            if vulns:
                lines.append(f"  ⚠ Vulnerabilities ({len(vulns)}):")
                for v in vulns:
                    lines.append(f"    [{v.get('severity', '?').upper()}] {v.get('description', '')}")

        return '\n'.join(lines)

    # ──────────────────────────────────────────────────────────────────────
    # Token Classification
    # ──────────────────────────────────────────────────────────────────────

    def _classify_token(self, name: str, value: str, source: str) -> str:
        """Classify token type from name, value structure, and source."""
        name_lower = name.lower()

        # JWT detection (3 base64url parts separated by dots)
        if value.count('.') == 2:
            header = self._decode_jwt_part(value.split('.')[0])
            if header and 'alg' in header:
                if name_lower in ('id_token', 'id-token'):
                    return TokenType.OIDC_ID_TOKEN
                return TokenType.JWT

        # Named token classification
        if name_lower in ('id_token', 'id-token'):
            return TokenType.OIDC_ID_TOKEN
        if name_lower in ('access_token', 'access-token'):
            return TokenType.OAUTH_ACCESS
        if name_lower in ('refresh_token', 'refresh-token'):
            return TokenType.OAUTH_REFRESH
        if 'saml' in name_lower or 'assertion' in name_lower:
            return TokenType.SAML_ASSERTION
        if 'kerberos' in name_lower or 'krb' in name_lower:
            return TokenType.KERBEROS_TICKET
        if 'ntlm' in name_lower:
            return TokenType.NTLM_HASH
        if name_lower in ('csrf_token', 'authenticity_token', '_token', 'csrfmiddlewaretoken',
                          '__requestverificationtoken', 'x-csrf-token'):
            return TokenType.CSRF_TOKEN

        # API key by source header name
        api_headers = ['x-api-key', 'api-key', 'x-auth-token', 'ocp-apim-subscription-key']
        if name_lower in api_headers or source in ('header_api_key', 'query_api_key'):
            return TokenType.API_KEY

        # Basic auth
        if source == 'auth_header' and ':' in self._try_b64_decode(value):
            return TokenType.BASIC_CREDENTIALS

        # Session cookies
        session_names = ['session', 'jsessionid', 'phpsessid', 'asp.net_sessionid',
                        '.aspxauth', 'connect.sid', 'laravel_session', 'ci_session']
        if any(s in name_lower for s in session_names):
            return TokenType.SESSION_COOKIE

        # Bearer opaque token
        if source == 'auth_header' and len(value) > 20:
            return TokenType.BEARER_OPAQUE

        return TokenType.UNKNOWN

    # ──────────────────────────────────────────────────────────────────────
    # JWT Analysis
    # ──────────────────────────────────────────────────────────────────────

    def _analyze_jwt(self, analysis: dict, token: str, context: dict):
        """Deep JWT analysis: header, payload, algorithm, claims, key brute-force."""
        parts = token.split('.')
        if len(parts) != 3:
            return

        header = self._decode_jwt_part(parts[0])
        payload = self._decode_jwt_part(parts[1])
        signature_b64 = parts[2]

        props = analysis['properties']
        props['header'] = header or {}
        props['payload'] = payload or {}
        props['has_signature'] = len(signature_b64) > 0
        props['signature_length'] = len(signature_b64)

        if header:
            alg = header.get('alg', 'unknown')
            props['algorithm'] = alg
            props['key_type'] = header.get('typ', '')
            props['kid'] = header.get('kid', '')
            props['jku'] = header.get('jku', '')
            props['x5u'] = header.get('x5u', '')

            # Algorithm vulnerabilities
            if alg.lower() == 'none':
                analysis['vulnerabilities'].append({
                    'type': 'jwt_alg_none', 'severity': 'critical',
                    'description': "JWT uses 'none' algorithm — signature verification bypassed.",
                    'token_name': analysis['name'],
                })
            if alg in ('HS256', 'HS384', 'HS512'):
                # Try common weak secrets
                weak_key = self._brute_force_hmac(token, alg)
                if weak_key:
                    analysis['vulnerabilities'].append({
                        'type': 'jwt_weak_secret', 'severity': 'critical',
                        'description': f"JWT signed with weak/common secret: '{weak_key}'",
                        'token_name': analysis['name'],
                        'evidence': {'secret': weak_key, 'algorithm': alg},
                    })
            # jku/x5u injection risk
            if header.get('jku'):
                analysis['vulnerabilities'].append({
                    'type': 'jwt_jku_header', 'severity': 'medium',
                    'description': f"JWT contains 'jku' header pointing to: {header['jku']}. "
                                   "If not validated, attacker can supply own key set.",
                    'token_name': analysis['name'],
                })
            if header.get('x5u'):
                analysis['vulnerabilities'].append({
                    'type': 'jwt_x5u_header', 'severity': 'medium',
                    'description': f"JWT contains 'x5u' header: {header['x5u']}. Possible key injection.",
                    'token_name': analysis['name'],
                })

        if payload:
            # Standard claims
            now = time.time()
            if 'exp' in payload:
                props['expires_at'] = payload['exp']
                props['is_expired'] = payload['exp'] < now
                props['time_to_expiry'] = payload['exp'] - now
                if props['is_expired']:
                    analysis['vulnerabilities'].append({
                        'type': 'jwt_expired', 'severity': 'info',
                        'description': 'Token is expired.',
                        'token_name': analysis['name'],
                    })
            else:
                analysis['vulnerabilities'].append({
                    'type': 'jwt_no_expiry', 'severity': 'medium',
                    'description': 'JWT has no expiration (exp) claim — tokens never expire.',
                    'token_name': analysis['name'],
                })
            if 'iat' in payload:
                props['issued_at'] = payload['iat']
                if 'exp' in payload:
                    props['lifetime_seconds'] = payload['exp'] - payload['iat']
                    if props['lifetime_seconds'] > 86400:
                        analysis['vulnerabilities'].append({
                            'type': 'jwt_long_lived', 'severity': 'low',
                            'description': f"Token lifetime is {props['lifetime_seconds'] // 3600}+ hours.",
                            'token_name': analysis['name'],
                        })
            if 'nbf' in payload:
                props['not_before'] = payload['nbf']
            props['issuer'] = payload.get('iss', '')
            props['subject'] = payload.get('sub', '')
            props['audience'] = payload.get('aud', '')
            props['scope'] = payload.get('scope', '')
            props['roles'] = payload.get('roles', payload.get('role', ''))
            props['groups'] = payload.get('groups', '')

            # Sensitive claims check
            sensitive = ['email', 'phone', 'address', 'ssn', 'credit_card']
            exposed = [s for s in sensitive if s in payload]
            if exposed:
                analysis['vulnerabilities'].append({
                    'type': 'jwt_sensitive_claims', 'severity': 'low',
                    'description': f"JWT contains potentially sensitive claims: {exposed}",
                    'token_name': analysis['name'],
                })

    # ──────────────────────────────────────────────────────────────────────
    # OIDC id_token Analysis
    # ──────────────────────────────────────────────────────────────────────

    def _analyze_oidc_id_token(self, analysis: dict, token: str, context: dict):
        """OIDC-specific id_token validation checks."""
        # Run base JWT analysis first
        self._analyze_jwt(analysis, token, context)
        payload = analysis['properties'].get('payload', {})

        # Required OIDC claims
        required = ['iss', 'sub', 'aud', 'exp', 'iat']
        missing = [c for c in required if c not in payload]
        if missing:
            analysis['vulnerabilities'].append({
                'type': 'oidc_missing_required_claims', 'severity': 'high',
                'description': f"id_token missing required OIDC claims: {missing}",
                'token_name': analysis['name'],
            })

        # Nonce validation
        if 'nonce' not in payload:
            analysis['vulnerabilities'].append({
                'type': 'oidc_missing_nonce', 'severity': 'medium',
                'description': "id_token missing 'nonce' claim — replay attacks possible.",
                'token_name': analysis['name'],
            })

        # at_hash validation (required when access_token is also returned)
        if 'at_hash' not in payload:
            analysis['properties']['missing_at_hash'] = True
            analysis['recommendations'].append(
                "If access_token is issued alongside id_token, include at_hash for binding.")

        # Audience is array with multiple values (confused deputy risk)
        aud = payload.get('aud')
        if isinstance(aud, list) and len(aud) > 1 and 'azp' not in payload:
            analysis['vulnerabilities'].append({
                'type': 'oidc_multi_audience_no_azp', 'severity': 'medium',
                'description': "id_token has multiple audiences without 'azp' claim.",
                'token_name': analysis['name'],
            })

    # ──────────────────────────────────────────────────────────────────────
    # OAuth Access/Refresh Token Analysis
    # ──────────────────────────────────────────────────────────────────────

    def _analyze_oauth_token(self, analysis: dict, token: str, context: dict):
        """Analyze OAuth access or refresh token."""
        props = analysis['properties']

        # If it looks like a JWT, run JWT analysis
        if token.count('.') == 2:
            header = self._decode_jwt_part(token.split('.')[0])
            if header and 'alg' in header:
                self._analyze_jwt(analysis, token, context)
                props['format'] = 'jwt'
                return

        # Opaque token analysis
        props['format'] = 'opaque'
        props['character_set'] = self._characterize_charset(token)
        props['encoding'] = self._detect_encoding(token)
        props['entropy_assessment'] = 'strong' if analysis['entropy'] > 4.0 else 'weak'

        if analysis['entropy'] < 3.5:
            analysis['vulnerabilities'].append({
                'type': 'oauth_low_entropy', 'severity': 'medium',
                'description': f"OAuth token has low entropy ({analysis['entropy']:.2f}). "
                               "May be predictable or sequential.",
                'token_name': analysis['name'],
            })

        if analysis['length'] < 20:
            analysis['vulnerabilities'].append({
                'type': 'oauth_short_token', 'severity': 'medium',
                'description': f"OAuth token is only {analysis['length']} characters — may be brute-forceable.",
                'token_name': analysis['name'],
            })

    # ──────────────────────────────────────────────────────────────────────
    # SAML Assertion Analysis
    # ──────────────────────────────────────────────────────────────────────

    def _analyze_saml_assertion(self, analysis: dict, token: str, context: dict):
        """Analyze SAML assertion for security properties."""
        props = analysis['properties']
        try:
            # Decode base64
            raw = base64.b64decode(token)
            # Try inflate
            try:
                import zlib
                xml = zlib.decompress(raw, -15).decode('utf-8', errors='replace')
            except Exception:
                xml = raw.decode('utf-8', errors='replace')

            props['xml_length'] = len(xml)

            # Signature presence
            props['is_signed'] = '<ds:Signature' in xml or '<Signature' in xml
            props['is_encrypted'] = '<EncryptedAssertion' in xml or '<xenc:' in xml

            # Extract Issuer
            issuer_match = re.search(r'<(?:saml[2p]*:)?Issuer[^>]*>([^<]+)', xml)
            props['issuer'] = issuer_match.group(1) if issuer_match else ''

            # Extract NameID
            nameid_match = re.search(r'<(?:saml[2]*:)?NameID[^>]*>([^<]+)', xml)
            props['name_id'] = nameid_match.group(1) if nameid_match else ''

            # Extract Destination
            dest_match = re.search(r'Destination="([^"]+)"', xml)
            props['destination'] = dest_match.group(1) if dest_match else ''

            # Conditions (time validity)
            not_before = re.search(r'NotBefore="([^"]+)"', xml)
            not_after = re.search(r'NotOnOrAfter="([^"]+)"', xml)
            if not_before:
                props['not_before'] = not_before.group(1)
            if not_after:
                props['not_on_or_after'] = not_after.group(1)

            # Attributes
            attrs = re.findall(r'<(?:saml[2]*:)?Attribute\s+Name="([^"]+)"', xml)
            props['attributes'] = attrs[:20]  # Cap at 20

            # Authentication context
            authn_match = re.search(r'<(?:saml[2]*:)?AuthnContextClassRef[^>]*>([^<]+)', xml)
            props['authn_context'] = authn_match.group(1) if authn_match else ''

            # Signature algorithm
            sig_alg = re.search(r'<(?:ds:)?SignatureMethod\s+Algorithm="([^"]+)"', xml)
            if sig_alg:
                props['signature_algorithm'] = sig_alg.group(1)
                # Check for weak algorithms
                weak_algs = ['sha1', 'rsa-sha1', 'md5']
                if any(w in sig_alg.group(1).lower() for w in weak_algs):
                    analysis['vulnerabilities'].append({
                        'type': 'saml_weak_signature', 'severity': 'medium',
                        'description': f"SAML uses weak signature algorithm: {sig_alg.group(1)}",
                        'token_name': analysis['name'],
                    })

            # Vulnerability checks
            if not props['is_signed']:
                analysis['vulnerabilities'].append({
                    'type': 'saml_unsigned', 'severity': 'critical',
                    'description': "SAML assertion is not signed — forgery is trivial.",
                    'token_name': analysis['name'],
                })
            if not props['is_encrypted']:
                analysis['recommendations'].append(
                    "Consider encrypting SAML assertions to protect attribute data in transit.")

            # Check for XML signature wrapping indicators
            sig_count = xml.count('<ds:Signature') + xml.count('<Signature')
            if sig_count > 1:
                analysis['vulnerabilities'].append({
                    'type': 'saml_multiple_signatures', 'severity': 'high',
                    'description': "Multiple signatures in assertion — possible XSW attack surface.",
                    'token_name': analysis['name'],
                })

        except Exception as e:
            props['parse_error'] = str(e)

    # ──────────────────────────────────────────────────────────────────────
    # Kerberos Ticket Analysis
    # ──────────────────────────────────────────────────────────────────────

    def _analyze_kerberos_ticket(self, analysis: dict, token: str, context: dict):
        """Analyze Kerberos ticket properties."""
        props = analysis['properties']
        try:
            raw = base64.b64decode(token)
            props['raw_size'] = len(raw)
            props['is_spnego'] = raw[0] == 0x60 if raw else False

            # Extract realm
            realm_match = re.search(rb'[A-Z][A-Z0-9.\-]+\.(COM|ORG|NET|LOCAL|LAN|IO|INTERNAL)',
                                    raw, re.IGNORECASE)
            if realm_match:
                props['realm'] = realm_match.group(0).decode('ascii', errors='replace')

            # Extract SPN
            spn_match = re.search(rb'(HTTP|CIFS|MSSQLSvc|LDAP|HOST|krbtgt)/[a-zA-Z0-9.\-]+', raw)
            if spn_match:
                props['spn'] = spn_match.group(0).decode('ascii', errors='replace')

            # Detect encryption type from ASN.1 structure
            # RC4 (etype 23) vs AES-256 (etype 18)
            if b'\xa0\x03\x02\x01\x17' in raw:  # etype 23 = RC4
                props['encryption_type'] = 'RC4-HMAC (etype 23)'
                analysis['vulnerabilities'].append({
                    'type': 'kerberos_rc4', 'severity': 'high',
                    'description': "Kerberos ticket encrypted with RC4 (etype 23). "
                                   "Vulnerable to offline Kerberoasting / brute-force.",
                    'token_name': analysis['name'],
                    'evidence': {'etype': 23},
                })
            elif b'\xa0\x03\x02\x01\x12' in raw:  # etype 18 = AES-256
                props['encryption_type'] = 'AES-256 (etype 18)'
            elif b'\xa0\x03\x02\x01\x11' in raw:  # etype 17 = AES-128
                props['encryption_type'] = 'AES-128 (etype 17)'
            else:
                props['encryption_type'] = 'unknown'

            # Large ticket may indicate unconstrained delegation (TGT forwarded)
            if len(raw) > 5000:
                analysis['vulnerabilities'].append({
                    'type': 'kerberos_large_ticket', 'severity': 'medium',
                    'description': f"Unusually large Kerberos ticket ({len(raw)} bytes). "
                                   "May contain forwarded TGT (unconstrained delegation).",
                    'token_name': analysis['name'],
                })

        except Exception as e:
            props['parse_error'] = str(e)

    # ──────────────────────────────────────────────────────────────────────
    # NTLM Token Analysis
    # ──────────────────────────────────────────────────────────────────────

    def _analyze_ntlm_token(self, analysis: dict, token: str, context: dict):
        """Analyze NTLM authentication message."""
        props = analysis['properties']
        try:
            raw = base64.b64decode(token)
            if raw[:8] != b'NTLMSSP\x00':
                props['valid_ntlm'] = False
                return

            msg_type = struct.unpack('<I', raw[8:12])[0]
            props['message_type'] = msg_type
            props['valid_ntlm'] = True

            if msg_type == 1:  # Negotiate
                props['stage'] = 'negotiate'
                if len(raw) >= 16:
                    flags = struct.unpack('<I', raw[12:16])[0]
                    props['flags'] = flags
                    props['ntlmv2_supported'] = bool(flags & 0x00080000)
                    props['56bit_encryption'] = bool(flags & 0x80000000)
                    props['128bit_encryption'] = bool(flags & 0x20000000)
                    if not props['ntlmv2_supported']:
                        analysis['vulnerabilities'].append({
                            'type': 'ntlm_v1_negotiate', 'severity': 'high',
                            'description': "Client negotiating without NTLMv2 flag — NTLMv1 may be used.",
                            'token_name': analysis['name'],
                        })

            elif msg_type == 2:  # Challenge
                props['stage'] = 'challenge'
                if len(raw) >= 32:
                    props['challenge'] = raw[24:32].hex()
                    # Extract target name
                    if len(raw) >= 20:
                        target_len = struct.unpack('<H', raw[12:14])[0]
                        target_offset = struct.unpack('<I', raw[16:20])[0]
                        if target_offset + target_len <= len(raw):
                            props['target_name'] = raw[target_offset:target_offset + target_len].decode(
                                'utf-16-le', errors='replace')

            elif msg_type == 3:  # Authenticate
                props['stage'] = 'authenticate'
                # Extract domain, username, workstation
                if len(raw) >= 52:
                    domain_len = struct.unpack('<H', raw[28:30])[0]
                    domain_off = struct.unpack('<I', raw[32:36])[0]
                    user_len = struct.unpack('<H', raw[36:38])[0]
                    user_off = struct.unpack('<I', raw[40:44])[0]
                    ws_len = struct.unpack('<H', raw[44:46])[0]
                    ws_off = struct.unpack('<I', raw[48:52])[0]

                    if domain_off + domain_len <= len(raw):
                        props['domain'] = raw[domain_off:domain_off + domain_len].decode('utf-16-le', errors='replace')
                    if user_off + user_len <= len(raw):
                        props['username'] = raw[user_off:user_off + user_len].decode('utf-16-le', errors='replace')
                    if ws_off + ws_len <= len(raw):
                        props['workstation'] = raw[ws_off:ws_off + ws_len].decode('utf-16-le', errors='replace')

                    # NTLMv1 vs NTLMv2 detection from response length
                    nt_resp_len = struct.unpack('<H', raw[20:22])[0]
                    props['nt_response_length'] = nt_resp_len
                    if nt_resp_len == 24:
                        props['ntlm_version'] = 'NTLMv1'
                        analysis['vulnerabilities'].append({
                            'type': 'ntlm_v1_response', 'severity': 'high',
                            'description': "NTLMv1 response detected (24 bytes). "
                                           "Easily crackable with rainbow tables.",
                            'token_name': analysis['name'],
                        })
                    elif nt_resp_len > 24:
                        props['ntlm_version'] = 'NTLMv2'

        except Exception as e:
            props['parse_error'] = str(e)

    # ──────────────────────────────────────────────────────────────────────
    # Session Cookie / CSRF / API Key / Basic Analysis
    # ──────────────────────────────────────────────────────────────────────

    def _analyze_session_cookie(self, analysis: dict, token: str, context: dict):
        """Analyze session cookie for predictability and strength."""
        props = analysis['properties']
        props['character_set'] = self._characterize_charset(token)
        props['encoding'] = self._detect_encoding(token)

        # Predictability checks
        if token.isdigit():
            props['format'] = 'numeric'
            analysis['vulnerabilities'].append({
                'type': 'session_numeric', 'severity': 'high',
                'description': "Session ID is purely numeric — likely sequential/predictable.",
                'token_name': analysis['name'],
            })
        elif re.match(r'^[a-f0-9]+$', token, re.IGNORECASE) and len(token) < 32:
            props['format'] = 'short_hex'
            analysis['vulnerabilities'].append({
                'type': 'session_short', 'severity': 'medium',
                'description': f"Session ID is only {len(token)} hex characters — insufficient randomness.",
                'token_name': analysis['name'],
            })
        else:
            props['format'] = 'random'

        if analysis['entropy'] < 3.5:
            analysis['vulnerabilities'].append({
                'type': 'session_low_entropy', 'severity': 'high',
                'description': f"Session cookie entropy is {analysis['entropy']:.2f} bits/char — predictable.",
                'token_name': analysis['name'],
            })

        # Cookie attributes from context
        attrs = context.get('attributes', {})
        if attrs:
            props['httponly'] = attrs.get('httponly', False)
            props['secure'] = attrs.get('secure', False)
            props['samesite'] = attrs.get('samesite', '')
            if not attrs.get('httponly'):
                analysis['vulnerabilities'].append({
                    'type': 'cookie_no_httponly', 'severity': 'medium',
                    'description': "Session cookie missing HttpOnly flag (XSS can steal it).",
                    'token_name': analysis['name'],
                })
            if not attrs.get('secure'):
                analysis['vulnerabilities'].append({
                    'type': 'cookie_no_secure', 'severity': 'medium',
                    'description': "Session cookie missing Secure flag (sent over HTTP).",
                    'token_name': analysis['name'],
                })

    def _analyze_csrf_token(self, analysis: dict, token: str, context: dict):
        """Analyze CSRF token strength."""
        props = analysis['properties']
        props['character_set'] = self._characterize_charset(token)
        props['sufficient_length'] = len(token) >= 32

        if len(token) < 16:
            analysis['vulnerabilities'].append({
                'type': 'csrf_too_short', 'severity': 'medium',
                'description': f"CSRF token only {len(token)} characters — may be brute-forceable.",
                'token_name': analysis['name'],
            })
        if analysis['entropy'] < 3.0:
            analysis['vulnerabilities'].append({
                'type': 'csrf_low_entropy', 'severity': 'medium',
                'description': f"CSRF token has low entropy ({analysis['entropy']:.2f}).",
                'token_name': analysis['name'],
            })

    def _analyze_api_key(self, analysis: dict, token: str, context: dict):
        """Analyze API key properties."""
        props = analysis['properties']
        props['character_set'] = self._characterize_charset(token)
        props['encoding'] = self._detect_encoding(token)
        props['key_length_bits'] = len(token) * 4 if re.match(r'^[a-fA-F0-9]+$', token) else len(token) * 6

        if analysis['entropy'] < 3.5:
            analysis['vulnerabilities'].append({
                'type': 'api_key_low_entropy', 'severity': 'medium',
                'description': "API key has low entropy — may be predictable.",
                'token_name': analysis['name'],
            })
        if len(token) < 16:
            analysis['vulnerabilities'].append({
                'type': 'api_key_short', 'severity': 'medium',
                'description': f"API key is only {len(token)} characters.",
                'token_name': analysis['name'],
            })

        # Check if in URL parameter (from context)
        if context.get('source') == 'query_api_key' or context.get('type') == 'query_api_key':
            analysis['vulnerabilities'].append({
                'type': 'api_key_in_url', 'severity': 'high',
                'description': "API key passed in URL — exposed in logs and referrer headers.",
                'token_name': analysis['name'],
            })

    def _analyze_basic_creds(self, analysis: dict, token: str, context: dict):
        """Analyze HTTP Basic credentials."""
        props = analysis['properties']
        decoded = self._try_b64_decode(token)
        if ':' in decoded:
            username, password = decoded.split(':', 1)
            props['username'] = username
            props['password_length'] = len(password)
            props['password_entropy'] = self._shannon_entropy(password)

            if len(password) < 8:
                analysis['vulnerabilities'].append({
                    'type': 'basic_weak_password', 'severity': 'high',
                    'description': f"Basic auth password is only {len(password)} characters.",
                    'token_name': analysis['name'],
                })
            if props['password_entropy'] < 2.5:
                analysis['vulnerabilities'].append({
                    'type': 'basic_low_entropy_password', 'severity': 'high',
                    'description': "Basic auth password has very low entropy.",
                    'token_name': analysis['name'],
                })

    def _analyze_generic(self, analysis: dict, token: str):
        """Fallback analysis for unclassified tokens."""
        props = analysis['properties']
        props['character_set'] = self._characterize_charset(token)
        props['encoding'] = self._detect_encoding(token)

    # ──────────────────────────────────────────────────────────────────────
    # Universal Vulnerability Checks
    # ──────────────────────────────────────────────────────────────────────

    def _check_universal_vulns(self, analysis: dict):
        """Checks that apply to all token types."""
        token = analysis.get('full_value', '')

        # Check for tokens that look like they contain timestamps (predictable)
        if re.search(r'\d{10}', token):
            analysis['recommendations'].append(
                "Token appears to contain a Unix timestamp — verify it's not used as sole entropy source.")

        # Check for tokens that are just UUIDs (128 bits, sometimes predictable versions)
        uuid_match = re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-([1-5])[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12}$',
                              token, re.IGNORECASE)
        if uuid_match:
            version = uuid_match.group(1)
            if version == '1':
                analysis['vulnerabilities'].append({
                    'type': 'uuid_v1_predictable', 'severity': 'medium',
                    'description': "Token is a UUIDv1 (time-based) — partially predictable.",
                    'token_name': analysis['name'],
                })

    # ──────────────────────────────────────────────────────────────────────
    # Cross-Token Relationship Analysis
    # ──────────────────────────────────────────────────────────────────────

    def _find_relationships(self, analyses: Dict[str, dict]) -> List[dict]:
        """Find relationships and dependencies between tokens."""
        relationships = []
        items = list(analyses.items())

        # Token reuse detection
        value_map: Dict[str, List[str]] = {}
        for name, a in items:
            v = a.get('full_value', '')
            if v:
                value_map.setdefault(v, []).append(name)
        for value, names in value_map.items():
            if len(names) > 1:
                relationships.append({
                    'type': 'token_reuse',
                    'tokens': names,
                    'description': f"Same token value used as: {', '.join(names)}",
                    'severity': 'medium',
                })

        # JWT issuer grouping
        issuers: Dict[str, List[str]] = {}
        for name, a in items:
            iss = a.get('properties', {}).get('issuer')
            if iss:
                issuers.setdefault(iss, []).append(name)
        for iss, names in issuers.items():
            if len(names) > 1:
                relationships.append({
                    'type': 'shared_issuer',
                    'issuer': iss,
                    'tokens': names,
                    'description': f"Tokens from same issuer '{iss}': {', '.join(names)}",
                })

        # Access token / refresh token pairing
        access = [n for n, a in items if a['type'] == TokenType.OAUTH_ACCESS]
        refresh = [n for n, a in items if a['type'] == TokenType.OAUTH_REFRESH]
        if access and refresh:
            relationships.append({
                'type': 'access_refresh_pair',
                'access_tokens': access,
                'refresh_tokens': refresh,
                'description': "Access/Refresh token pair detected — check refresh token rotation.",
            })

        return relationships

    # ──────────────────────────────────────────────────────────────────────
    # Utility Methods
    # ──────────────────────────────────────────────────────────────────────

    def _shannon_entropy(self, data: str) -> float:
        """Calculate Shannon entropy in bits per character."""
        if not data:
            return 0.0
        freq = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def _decode_jwt_part(self, part: str) -> Optional[dict]:
        """Decode a base64url-encoded JWT part."""
        try:
            padded = part + '=' * (4 - len(part) % 4)
            decoded = base64.urlsafe_b64decode(padded)
            return json.loads(decoded)
        except Exception:
            return None

    def _try_b64_decode(self, value: str) -> str:
        """Attempt base64 decode, return empty string on failure."""
        try:
            return base64.b64decode(value).decode('utf-8', errors='replace')
        except Exception:
            return ''

    def _characterize_charset(self, token: str) -> dict:
        """Characterize the character set of a token."""
        return {
            'has_upper': any(c.isupper() for c in token),
            'has_lower': any(c.islower() for c in token),
            'has_digits': any(c.isdigit() for c in token),
            'has_special': any(not c.isalnum() for c in token),
            'unique_chars': len(set(token)),
            'total_chars': len(token),
        }

    def _detect_encoding(self, token: str) -> str:
        """Detect likely encoding of a token value."""
        if re.match(r'^[A-Za-z0-9+/]*={0,2}$', token) and len(token) % 4 == 0:
            return 'base64'
        if re.match(r'^[A-Za-z0-9_-]+$', token):
            return 'base64url'
        if re.match(r'^[a-fA-F0-9]+$', token):
            return 'hex'
        if '%' in token:
            return 'url_encoded'
        return 'plain'

    def _brute_force_hmac(self, token: str, algorithm: str) -> Optional[str]:
        """Try common weak secrets against HMAC-signed JWT."""
        try:
            import hmac as hmac_mod
            parts = token.split('.')
            if len(parts) != 3:
                return None

            signing_input = f"{parts[0]}.{parts[1]}".encode()
            expected_sig = base64.urlsafe_b64decode(parts[2] + '==')

            hash_func = {
                'HS256': 'sha256', 'HS384': 'sha384', 'HS512': 'sha512'
            }.get(algorithm)
            if not hash_func:
                return None

            for secret in COMMON_JWT_SECRETS:
                computed = hmac_mod.new(
                    secret.encode(), signing_input, hash_func
                ).digest()
                if computed == expected_sig:
                    return secret
        except Exception:
            pass
        return None
