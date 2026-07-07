# app/core/auth_flow_recorder.py
"""Enterprise-grade authentication flow recorder.

Captures and classifies authentication sequences from HTTP proxy traffic,
with protocol-aware detection for:
- OAuth 2.0 / OIDC (Authorization Code, Implicit, Client Credentials, PKCE)
- NTLM (Challenge-Response, NTLMv1/v2)
- Kerberos (TGT/TGS, Negotiate, SPNego)
- SAML 2.0 (POST Binding, Redirect Binding, Artifact)
- Forms-Based Authentication (Windows FBA, custom login forms)
- Certificate-Based (mTLS, client certificates)
- JWT (Bearer tokens, refresh flows)
- API Keys (header, query param, custom schemes)
"""
import json
import time
import base64
import re
import struct
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
from urllib.parse import urlparse, parse_qs, unquote
from PyQt6.QtCore import QObject, pyqtSignal
from app.core.logger import logger


class AuthProtocol(Enum):
    """Supported authentication protocols."""
    UNKNOWN = "unknown"
    OAUTH2 = "oauth2"
    OIDC = "oidc"
    NTLM = "ntlm"
    KERBEROS = "kerberos"
    SAML = "saml"
    FBA = "fba"
    CERTIFICATE = "certificate"
    JWT = "jwt"
    API_KEY = "api_key"
    BASIC = "basic"
    DIGEST = "digest"
    BEARER = "bearer"


class OAuthGrantType(Enum):
    """OAuth 2.0 grant types."""
    AUTHORIZATION_CODE = "authorization_code"
    IMPLICIT = "implicit"
    CLIENT_CREDENTIALS = "client_credentials"
    RESOURCE_OWNER = "resource_owner_password"
    DEVICE_CODE = "device_code"
    PKCE = "authorization_code_pkce"
    REFRESH_TOKEN = "refresh_token"


class NTLMMessageType(Enum):
    """NTLM message types."""
    NEGOTIATE = 1
    CHALLENGE = 2
    AUTHENTICATE = 3


class AuthFlowRecorder(QObject):
    """Records authentication flows from proxy traffic with protocol-aware detection."""

    flow_recorded = pyqtSignal(dict)
    session_started = pyqtSignal(str)
    session_ended = pyqtSignal(str)
    protocol_detected = pyqtSignal(str, str)  # session_id, protocol_name

    def __init__(self):
        super().__init__()
        self.recording = False
        self.current_session = None
        self.flows: Dict[str, dict] = {}
        self.request_sequence: List[dict] = []

        # Protocol-specific detectors
        self._protocol_detectors = [
            self._detect_ntlm,
            self._detect_kerberos,
            self._detect_saml,
            self._detect_oauth2_oidc,
            self._detect_certificate,
            self._detect_jwt_bearer,
            self._detect_basic_digest,
            self._detect_api_key,
            self._detect_fba,
        ]

    # ──────────────────────────────────────────────────────────────────────
    # Session Management
    # ──────────────────────────────────────────────────────────────────────

    def start_recording(self, session_name: str = None) -> str:
        """Start recording an authentication flow."""
        session_id = session_name or f"auth_session_{int(time.time())}"
        self.current_session = session_id
        self.recording = True
        self.request_sequence = []

        self.flows[session_id] = {
            'session_id': session_id,
            'start_time': time.time(),
            'requests': [],
            'tokens': {},
            'cookies': {},
            'redirects': [],
            'endpoints': set(),
            'parameters': {},
            'detected_protocols': [],
            'protocol_details': {},
            'ntlm_exchanges': [],
            'kerberos_tickets': [],
            'saml_assertions': [],
            'oauth_flows': [],
            'certificates': [],
            'vulnerabilities': [],
        }

        self.session_started.emit(session_id)
        return session_id

    def stop_recording(self) -> Optional[dict]:
        """Stop recording and return flow data."""
        if not self.recording or not self.current_session:
            return None

        self.recording = False
        flow_data = self.flows.get(self.current_session)

        if flow_data:
            flow_data['end_time'] = time.time()
            flow_data['duration'] = flow_data['end_time'] - flow_data['start_time']
            flow_data['endpoints'] = list(flow_data['endpoints'])
            # Deduplicate detected protocols
            flow_data['detected_protocols'] = list(set(flow_data['detected_protocols']))
            self.session_ended.emit(self.current_session)
            self.flow_recorded.emit(flow_data)

        session_id = self.current_session
        self.current_session = None
        return flow_data

    # ──────────────────────────────────────────────────────────────────────
    # Request Processing
    # ──────────────────────────────────────────────────────────────────────

    def process_request(self, http_request, http_response=None):
        """Process an HTTP request/response pair and classify it."""
        if not self.recording or not self.current_session:
            return

        flow_data = self.flows[self.current_session]
        parsed_url = urlparse(http_request.url)

        # Build request record
        request_data = {
            'timestamp': time.time(),
            'method': http_request.method,
            'url': http_request.url,
            'host': parsed_url.netloc,
            'path': parsed_url.path,
            'headers': dict(http_request.headers) if http_request.headers else {},
            'data': http_request.data or '',
            'params': dict(http_request.params) if http_request.params else {},
            'cookies': dict(http_request.cookies) if http_request.cookies else {},
            'sequence_number': len(flow_data['requests']),
            'detected_protocol': None,
            'protocol_metadata': {},
            'is_auth_related': False,
        }

        # Add response data
        if http_response:
            request_data.update({
                'response_status': http_response.status_code,
                'response_headers': dict(http_response.headers) if http_response.headers else {},
                'response_body': (http_response.text or '')[:10000],
                'response_time': getattr(http_response, 'elapsed_time', 0),
            })
            # Track redirects
            if 300 <= http_response.status_code < 400:
                location = (http_response.headers or {}).get('Location', '')
                if location:
                    flow_data['redirects'].append({
                        'from': http_request.url,
                        'to': location,
                        'status': http_response.status_code,
                        'timestamp': time.time(),
                    })

        # Run protocol detection
        detected = self._detect_protocol(request_data, http_request, http_response)
        if detected:
            request_data['detected_protocol'] = detected.value
            request_data['is_auth_related'] = True
            if detected.value not in flow_data['detected_protocols']:
                flow_data['detected_protocols'].append(detected.value)
                self.protocol_detected.emit(self.current_session, detected.value)

        flow_data['requests'].append(request_data)
        flow_data['endpoints'].add(parsed_url.netloc)

        # Extract tokens, cookies, parameters
        self._extract_tokens(http_request, http_response, flow_data)
        self._extract_cookies(http_request, http_response, flow_data)
        self._extract_parameters(http_request, flow_data)

    # ──────────────────────────────────────────────────────────────────────
    # Protocol Detection Engine
    # ──────────────────────────────────────────────────────────────────────

    def _detect_protocol(self, request_data: dict, http_request, http_response) -> Optional[AuthProtocol]:
        """Run all protocol detectors and return the first match."""
        for detector in self._protocol_detectors:
            try:
                result = detector(request_data, http_request, http_response)
                if result:
                    return result
            except Exception as e:
                logger.debug(f"Protocol detector error: {e}")
        return None

    def _detect_ntlm(self, request_data: dict, http_request, http_response) -> Optional[AuthProtocol]:
        """Detect NTLM challenge-response authentication."""
        headers = request_data.get('headers', {})
        resp_headers = request_data.get('response_headers', {})

        # Check Authorization header for NTLM
        auth_header = headers.get('Authorization', '')
        if auth_header.startswith('NTLM ') or auth_header.startswith('Negotiate '):
            token_b64 = auth_header.split(' ', 1)[1]
            ntlm_info = self._parse_ntlm_token(token_b64)
            if ntlm_info:
                request_data['protocol_metadata'] = ntlm_info
                flow_data = self.flows[self.current_session]
                flow_data['ntlm_exchanges'].append({
                    'timestamp': time.time(),
                    'url': request_data['url'],
                    'message_type': ntlm_info.get('message_type'),
                    'ntlm_version': ntlm_info.get('ntlm_version', 'unknown'),
                    'domain': ntlm_info.get('domain', ''),
                    'workstation': ntlm_info.get('workstation', ''),
                    'target_name': ntlm_info.get('target_name', ''),
                    'flags': ntlm_info.get('flags', 0),
                })
                return AuthProtocol.NTLM

        # Check WWW-Authenticate response header for NTLM challenge
        www_auth = resp_headers.get('WWW-Authenticate', '')
        if 'NTLM' in www_auth or ('Negotiate' in www_auth and 'NTLM' in www_auth):
            if www_auth.startswith('NTLM ') or www_auth.startswith('Negotiate '):
                token_b64 = www_auth.split(' ', 1)[1] if ' ' in www_auth else ''
                if token_b64:
                    ntlm_info = self._parse_ntlm_token(token_b64)
                    if ntlm_info:
                        request_data['protocol_metadata'] = ntlm_info
                        flow_data = self.flows[self.current_session]
                        flow_data['ntlm_exchanges'].append({
                            'timestamp': time.time(),
                            'url': request_data['url'],
                            'message_type': ntlm_info.get('message_type'),
                            'direction': 'challenge',
                            'target_name': ntlm_info.get('target_name', ''),
                        })
                return AuthProtocol.NTLM
        return None

    def _detect_kerberos(self, request_data: dict, http_request, http_response) -> Optional[AuthProtocol]:
        """Detect Kerberos / SPNego authentication."""
        headers = request_data.get('headers', {})
        resp_headers = request_data.get('response_headers', {})

        auth_header = headers.get('Authorization', '')
        www_auth = resp_headers.get('WWW-Authenticate', '')

        # Kerberos tokens start with specific OID after Negotiate prefix
        if auth_header.startswith('Negotiate '):
            token_b64 = auth_header.split(' ', 1)[1]
            if self._is_kerberos_token(token_b64):
                krb_info = self._parse_kerberos_token(token_b64)
                request_data['protocol_metadata'] = krb_info
                flow_data = self.flows[self.current_session]
                flow_data['kerberos_tickets'].append({
                    'timestamp': time.time(),
                    'url': request_data['url'],
                    'direction': 'request',
                    'spn': krb_info.get('spn', ''),
                    'realm': krb_info.get('realm', ''),
                    'enc_type': krb_info.get('enc_type', ''),
                    'ticket_size': len(token_b64),
                })
                return AuthProtocol.KERBEROS

        # Response Negotiate with Kerberos
        if 'Negotiate' in www_auth and not ('NTLM' in www_auth):
            if www_auth.startswith('Negotiate '):
                token_b64 = www_auth.split(' ', 1)[1]
                if self._is_kerberos_token(token_b64):
                    return AuthProtocol.KERBEROS
            elif www_auth.strip() == 'Negotiate':
                # Server requesting Negotiate — could be Kerberos
                request_data['protocol_metadata'] = {'stage': 'server_challenge'}
                return AuthProtocol.KERBEROS
        return None

    def _detect_saml(self, request_data: dict, http_request, http_response) -> Optional[AuthProtocol]:
        """Detect SAML 2.0 SSO flows (POST binding, redirect binding, artifact)."""
        url_lower = request_data['url'].lower()
        data = request_data.get('data', '')
        params = request_data.get('params', {})
        resp_body = request_data.get('response_body', '')

        # SAML POST binding — SAMLRequest/SAMLResponse in form data
        saml_params = ['SAMLRequest', 'SAMLResponse', 'SAMLArt']
        for param in saml_params:
            if param in params or param in data:
                saml_value = params.get(param, '')
                if not saml_value and param + '=' in data:
                    # Extract from form-encoded data
                    parsed = parse_qs(data)
                    saml_value = parsed.get(param, [''])[0]
                assertion_info = self._parse_saml_message(param, saml_value)
                request_data['protocol_metadata'] = assertion_info
                flow_data = self.flows[self.current_session]
                flow_data['saml_assertions'].append({
                    'timestamp': time.time(),
                    'url': request_data['url'],
                    'type': param,
                    'binding': 'POST' if request_data['method'] == 'POST' else 'Redirect',
                    'issuer': assertion_info.get('issuer', ''),
                    'destination': assertion_info.get('destination', ''),
                    'signed': assertion_info.get('is_signed', False),
                    'encrypted': assertion_info.get('is_encrypted', False),
                })
                return AuthProtocol.SAML

        # SAML redirect binding — SAMLRequest in URL query
        if 'samlrequest' in url_lower or 'samlresponse' in url_lower:
            return AuthProtocol.SAML

        # SAML metadata or IdP/SP endpoints
        saml_indicators = ['/saml/', '/sso/', '/adfs/', '/simplesaml/',
                          'saml2', '/metadata', 'SingleSignOn', 'AssertionConsumer']
        if any(ind.lower() in url_lower for ind in saml_indicators):
            if resp_body and ('saml' in resp_body.lower() or 'Assertion' in resp_body):
                return AuthProtocol.SAML
        return None

    def _detect_oauth2_oidc(self, request_data: dict, http_request, http_response) -> Optional[AuthProtocol]:
        """Detect OAuth 2.0 and OpenID Connect flows."""
        url_lower = request_data['url'].lower()
        params = request_data.get('params', {})
        data = request_data.get('data', '')
        resp_body = request_data.get('response_body', '')

        # Parse form data if present
        form_params = {}
        if data and 'application/x-www-form-urlencoded' in request_data.get('headers', {}).get('Content-Type', ''):
            form_params = parse_qs(data)

        # OAuth authorize endpoint
        oauth_url_indicators = ['/authorize', '/oauth/', '/oauth2/', '/token',
                                '/connect/', '/.well-known/openid', '/userinfo']
        is_oauth_url = any(ind in url_lower for ind in oauth_url_indicators)

        # Check for OAuth parameters
        oauth_params = ['client_id', 'response_type', 'redirect_uri', 'scope',
                       'code', 'grant_type', 'code_verifier', 'code_challenge']
        has_oauth_params = any(p in params or p in form_params for p in oauth_params)

        if is_oauth_url or has_oauth_params:
            flow_info = self._classify_oauth_flow(params, form_params, url_lower, resp_body)
            request_data['protocol_metadata'] = flow_info
            flow_data = self.flows[self.current_session]
            flow_data['oauth_flows'].append({
                'timestamp': time.time(),
                'url': request_data['url'],
                'grant_type': flow_info.get('grant_type', 'unknown'),
                'has_pkce': flow_info.get('has_pkce', False),
                'has_state': flow_info.get('has_state', False),
                'has_nonce': flow_info.get('has_nonce', False),
                'scopes': flow_info.get('scopes', []),
                'redirect_uri': flow_info.get('redirect_uri', ''),
                'client_id': flow_info.get('client_id', ''),
            })

            # OIDC if openid scope or id_token present
            if flow_info.get('is_oidc'):
                return AuthProtocol.OIDC
            return AuthProtocol.OAUTH2
        return None

    def _detect_certificate(self, request_data: dict, http_request, http_response) -> Optional[AuthProtocol]:
        """Detect certificate-based (mTLS) authentication."""
        resp_headers = request_data.get('response_headers', {})
        headers = request_data.get('headers', {})

        # Client certificate indicators
        cert_indicators = [
            'X-SSL-Client-Cert', 'X-Client-Certificate', 'SSL-Client-S-DN',
            'X-SSL-Client-Verify', 'X-SSL-Client-Serial',
            'X-ARR-ClientCert',  # IIS ARR
        ]
        for ind in cert_indicators:
            if ind in headers or ind in resp_headers:
                request_data['protocol_metadata'] = {
                    'type': 'mtls',
                    'header': ind,
                    'value_present': True,
                }
                flow_data = self.flows[self.current_session]
                flow_data['certificates'].append({
                    'timestamp': time.time(),
                    'url': request_data['url'],
                    'header': ind,
                    'direction': 'request' if ind in headers else 'response',
                })
                return AuthProtocol.CERTIFICATE

        # 403 with certificate request
        status = request_data.get('response_status', 0)
        if status == 403:
            www_auth = resp_headers.get('WWW-Authenticate', '')
            if 'certificate' in www_auth.lower() or 'mutual' in www_auth.lower():
                return AuthProtocol.CERTIFICATE
        return None

    def _detect_jwt_bearer(self, request_data: dict, http_request, http_response) -> Optional[AuthProtocol]:
        """Detect JWT Bearer token authentication."""
        auth_header = request_data.get('headers', {}).get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
            if token.count('.') == 2:
                # Likely JWT
                request_data['protocol_metadata'] = {'token_preview': token[:50] + '...'}
                return AuthProtocol.JWT
            else:
                return AuthProtocol.BEARER
        return None

    def _detect_basic_digest(self, request_data: dict, http_request, http_response) -> Optional[AuthProtocol]:
        """Detect HTTP Basic and Digest authentication."""
        auth_header = request_data.get('headers', {}).get('Authorization', '')
        resp_headers = request_data.get('response_headers', {})
        www_auth = resp_headers.get('WWW-Authenticate', '')

        if auth_header.startswith('Basic '):
            creds_b64 = auth_header[6:]
            try:
                decoded = base64.b64decode(creds_b64).decode('utf-8', errors='replace')
                username = decoded.split(':')[0] if ':' in decoded else ''
                request_data['protocol_metadata'] = {
                    'type': 'basic',
                    'username': username,
                    'credential_length': len(decoded),
                }
            except Exception:
                pass
            return AuthProtocol.BASIC

        if auth_header.startswith('Digest '):
            request_data['protocol_metadata'] = self._parse_digest_header(auth_header)
            return AuthProtocol.DIGEST

        # Server requesting Basic/Digest
        if www_auth.startswith('Basic') or www_auth.startswith('Digest'):
            request_data['protocol_metadata'] = {'stage': 'server_challenge', 'scheme': www_auth.split(' ')[0]}
            return AuthProtocol.BASIC if www_auth.startswith('Basic') else AuthProtocol.DIGEST
        return None

    def _detect_api_key(self, request_data: dict, http_request, http_response) -> Optional[AuthProtocol]:
        """Detect API key authentication (headers and query params)."""
        headers = request_data.get('headers', {})
        params = request_data.get('params', {})

        api_key_headers = ['X-API-Key', 'X-Api-Key', 'x-api-key', 'Api-Key',
                          'X-Auth-Token', 'X-Access-Token', 'Ocp-Apim-Subscription-Key']
        for hdr in api_key_headers:
            if hdr in headers:
                request_data['protocol_metadata'] = {
                    'type': 'header_api_key',
                    'header_name': hdr,
                    'key_length': len(headers[hdr]),
                }
                return AuthProtocol.API_KEY

        api_key_params = ['api_key', 'apikey', 'key', 'api-key', 'access_key',
                         'subscription-key', 'token']
        for param in api_key_params:
            if param in params:
                request_data['protocol_metadata'] = {
                    'type': 'query_api_key',
                    'param_name': param,
                    'key_length': len(str(params[param])),
                }
                return AuthProtocol.API_KEY
        return None

    def _detect_fba(self, request_data: dict, http_request, http_response) -> Optional[AuthProtocol]:
        """Detect Forms-Based Authentication (including Windows FBA)."""
        method = request_data.get('method', '')
        url_lower = request_data['url'].lower()
        data = request_data.get('data', '')
        content_type = request_data.get('headers', {}).get('Content-Type', '')

        if method != 'POST':
            return None
        if 'application/x-www-form-urlencoded' not in content_type:
            return None

        # Common login form indicators
        login_indicators = ['/login', '/signin', '/auth', '/account/login',
                           '/j_security_check', '/wp-login', '/_forms/default',
                           '/CookieAuth.dll', '/Authentication.asmx']
        is_login_url = any(ind in url_lower for ind in login_indicators)

        # Check form fields for credentials
        cred_fields = ['username', 'password', 'user', 'pass', 'email',
                      'j_username', 'j_password', 'credential', 'passwd',
                      'log', 'pwd']  # WordPress
        data_lower = data.lower()
        has_cred_fields = any(f + '=' in data_lower for f in cred_fields)

        if is_login_url and has_cred_fields:
            form_params = parse_qs(data)
            request_data['protocol_metadata'] = {
                'type': 'form_login',
                'url': request_data['url'],
                'fields': list(form_params.keys()),
                'has_csrf': any(
                    csrf in data_lower for csrf in
                    ['csrf', 'token', 'authenticity', '__requestverificationtoken']
                ),
            }
            return AuthProtocol.FBA
        return None

    # ──────────────────────────────────────────────────────────────────────
    # Protocol Parsers
    # ──────────────────────────────────────────────────────────────────────

    def _parse_ntlm_token(self, token_b64: str) -> Optional[dict]:
        """Parse an NTLM message (Type 1, 2, or 3) from base64."""
        try:
            raw = base64.b64decode(token_b64)
            if len(raw) < 12:
                return None
            signature = raw[:8]
            if signature != b'NTLMSSP\x00':
                return None
            msg_type = struct.unpack('<I', raw[8:12])[0]
            info = {'message_type': msg_type, 'raw_length': len(raw)}

            if msg_type == NTLMMessageType.NEGOTIATE.value:
                info['ntlm_version'] = 'negotiate'
                if len(raw) >= 16:
                    info['flags'] = struct.unpack('<I', raw[12:16])[0]
                    info['ntlmv2_supported'] = bool(info['flags'] & 0x00080000)
            elif msg_type == NTLMMessageType.CHALLENGE.value:
                info['ntlm_version'] = 'challenge'
                if len(raw) >= 24:
                    info['flags'] = struct.unpack('<I', raw[20:24])[0]
                # Extract target name
                if len(raw) >= 20:
                    target_len = struct.unpack('<H', raw[12:14])[0]
                    target_offset = struct.unpack('<I', raw[16:20])[0]
                    if target_offset + target_len <= len(raw):
                        info['target_name'] = raw[target_offset:target_offset + target_len].decode('utf-16-le', errors='replace')
            elif msg_type == NTLMMessageType.AUTHENTICATE.value:
                info['ntlm_version'] = 'authenticate'
                # Extract domain and username offsets
                if len(raw) >= 36:
                    domain_len = struct.unpack('<H', raw[28:30])[0]
                    domain_offset = struct.unpack('<I', raw[32:36])[0]
                    if domain_offset + domain_len <= len(raw):
                        info['domain'] = raw[domain_offset:domain_offset + domain_len].decode('utf-16-le', errors='replace')
                if len(raw) >= 44:
                    user_len = struct.unpack('<H', raw[36:38])[0]
                    user_offset = struct.unpack('<I', raw[40:44])[0]
                    if user_offset + user_len <= len(raw):
                        info['username'] = raw[user_offset:user_offset + user_len].decode('utf-16-le', errors='replace')
                if len(raw) >= 52:
                    ws_len = struct.unpack('<H', raw[44:46])[0]
                    ws_offset = struct.unpack('<I', raw[48:52])[0]
                    if ws_offset + ws_len <= len(raw):
                        info['workstation'] = raw[ws_offset:ws_offset + ws_len].decode('utf-16-le', errors='replace')
            return info
        except Exception as e:
            logger.debug(f"NTLM parse error: {e}")
            return None

    def _is_kerberos_token(self, token_b64: str) -> bool:
        """Check if a Negotiate token is Kerberos (vs NTLM)."""
        try:
            raw = base64.b64decode(token_b64)
            # Kerberos tokens wrapped in SPNEGO start with ASN.1 Application tag 0x60
            # NTLM tokens start with 'NTLMSSP\x00'
            if raw[:8] == b'NTLMSSP\x00':
                return False
            if len(raw) > 0 and raw[0] == 0x60:
                return True
            # Also check for Kerberos AP-REQ tag (0x6E)
            if len(raw) > 0 and raw[0] in (0x6E, 0x6F):
                return True
            return False
        except Exception:
            return False

    def _parse_kerberos_token(self, token_b64: str) -> dict:
        """Parse basic information from a Kerberos/SPNEGO token."""
        info = {'type': 'kerberos_spnego', 'token_size': len(token_b64)}
        try:
            raw = base64.b64decode(token_b64)
            info['raw_length'] = len(raw)
            # Look for realm in the raw bytes (realm is typically ASCII text)
            realm_match = re.search(rb'[A-Z][A-Z0-9\.\-]+\.(COM|ORG|NET|LOCAL|LAN|IO|INTERNAL)', raw)
            if realm_match:
                info['realm'] = realm_match.group(0).decode('ascii', errors='replace')
            # Look for SPN patterns
            spn_match = re.search(rb'(HTTP|CIFS|MSSQLSvc|LDAP|HOST)/[a-zA-Z0-9\.\-]+', raw)
            if spn_match:
                info['spn'] = spn_match.group(0).decode('ascii', errors='replace')
        except Exception as e:
            logger.debug(f"Kerberos parse error: {e}")
        return info

    def _parse_saml_message(self, msg_type: str, value: str) -> dict:
        """Parse a SAML message (request or response)."""
        info = {'message_type': msg_type, 'raw_length': len(value)}
        try:
            # SAML messages are base64-encoded XML (may also be deflated)
            decoded = base64.b64decode(value)
            # Try inflate (deflate compression used in redirect binding)
            try:
                import zlib
                xml_data = zlib.decompress(decoded, -15).decode('utf-8', errors='replace')
            except Exception:
                xml_data = decoded.decode('utf-8', errors='replace')

            info['xml_preview'] = xml_data[:500]

            # Extract key fields with regex (avoid full XML parser dependency)
            issuer_match = re.search(r'<(?:saml[2p]*:)?Issuer[^>]*>([^<]+)</(?:saml[2p]*:)?Issuer>', xml_data)
            if issuer_match:
                info['issuer'] = issuer_match.group(1)

            dest_match = re.search(r'Destination="([^"]+)"', xml_data)
            if dest_match:
                info['destination'] = dest_match.group(1)

            info['is_signed'] = '<ds:Signature' in xml_data or '<Signature' in xml_data
            info['is_encrypted'] = '<EncryptedAssertion' in xml_data or '<xenc:EncryptedData' in xml_data

            # Extract NameID
            nameid_match = re.search(r'<(?:saml[2]*:)?NameID[^>]*>([^<]+)</(?:saml[2]*:)?NameID>', xml_data)
            if nameid_match:
                info['name_id'] = nameid_match.group(1)

            # Check for conditions (NotBefore, NotOnOrAfter)
            conditions_match = re.search(r'NotBefore="([^"]+)".*?NotOnOrAfter="([^"]+)"', xml_data, re.DOTALL)
            if conditions_match:
                info['not_before'] = conditions_match.group(1)
                info['not_on_or_after'] = conditions_match.group(2)

            # Extract authentication context
            authn_match = re.search(r'<(?:saml[2]*:)?AuthnContextClassRef[^>]*>([^<]+)', xml_data)
            if authn_match:
                info['authn_context'] = authn_match.group(1)

        except Exception as e:
            logger.debug(f"SAML parse error: {e}")
        return info

    def _classify_oauth_flow(self, params: dict, form_params: dict, url_lower: str, resp_body: str) -> dict:
        """Classify OAuth 2.0 flow type and extract metadata."""
        info = {}

        # Merge all parameter sources
        all_params = dict(params)
        for k, v in form_params.items():
            all_params[k] = v[0] if isinstance(v, list) else v

        # Determine grant type
        grant_type = all_params.get('grant_type', '')
        response_type = all_params.get('response_type', '')

        if grant_type == 'authorization_code' or 'code' in all_params:
            info['grant_type'] = OAuthGrantType.AUTHORIZATION_CODE.value
        elif grant_type == 'client_credentials':
            info['grant_type'] = OAuthGrantType.CLIENT_CREDENTIALS.value
        elif grant_type == 'password':
            info['grant_type'] = OAuthGrantType.RESOURCE_OWNER.value
        elif grant_type == 'refresh_token':
            info['grant_type'] = OAuthGrantType.REFRESH_TOKEN.value
        elif 'urn:ietf:params:oauth:grant-type:device_code' in grant_type:
            info['grant_type'] = OAuthGrantType.DEVICE_CODE.value
        elif response_type == 'token' or response_type == 'id_token token':
            info['grant_type'] = OAuthGrantType.IMPLICIT.value
        elif response_type == 'code':
            info['grant_type'] = OAuthGrantType.AUTHORIZATION_CODE.value
        else:
            info['grant_type'] = 'unknown'

        # PKCE detection
        info['has_pkce'] = 'code_challenge' in all_params or 'code_verifier' in all_params
        if info['has_pkce']:
            info['pkce_method'] = all_params.get('code_challenge_method', 'plain')
            info['grant_type'] = OAuthGrantType.PKCE.value

        # State and nonce
        info['has_state'] = 'state' in all_params
        info['has_nonce'] = 'nonce' in all_params
        info['state_value'] = all_params.get('state', '')
        info['nonce_value'] = all_params.get('nonce', '')

        # Scopes
        scope_str = all_params.get('scope', '')
        info['scopes'] = scope_str.split() if scope_str else []

        # OIDC detection
        info['is_oidc'] = (
            'openid' in info['scopes'] or
            response_type in ('id_token', 'id_token token', 'code id_token') or
            '/openid' in url_lower or
            '/connect/' in url_lower
        )

        # Other metadata
        info['redirect_uri'] = all_params.get('redirect_uri', '')
        info['client_id'] = all_params.get('client_id', '')
        info['response_mode'] = all_params.get('response_mode', '')

        return info

    def _parse_digest_header(self, auth_header: str) -> dict:
        """Parse Digest authentication header fields."""
        info = {'type': 'digest'}
        # Extract key-value pairs from Digest header
        fields = ['username', 'realm', 'nonce', 'uri', 'qop', 'nc', 'cnonce', 'response', 'algorithm', 'opaque']
        for field in fields:
            match = re.search(rf'{field}="?([^",\s]+)"?', auth_header)
            if match:
                info[field] = match.group(1)
        return info

    # ──────────────────────────────────────────────────────────────────────
    # Token / Cookie / Parameter Extraction
    # ──────────────────────────────────────────────────────────────────────

    def _extract_tokens(self, http_request, http_response, flow_data: dict):
        """Extract authentication tokens from request/response."""
        tokens = flow_data['tokens']
        parsed_url = urlparse(http_request.url)
        url_params = parse_qs(parsed_url.query)

        token_params = ['access_token', 'refresh_token', 'id_token', 'code',
                       'state', 'nonce', 'assertion', 'client_assertion',
                       'device_code', 'user_code']

        # From URL parameters
        for param in token_params:
            if param in url_params:
                tokens[param] = {
                    'value': url_params[param][0],
                    'source': 'url_param',
                    'timestamp': time.time(),
                    'url': http_request.url,
                }

        # From request body
        if http_request.data:
            try:
                ct = (http_request.headers or {}).get('Content-Type', '')
                if 'application/json' in ct:
                    data = json.loads(http_request.data)
                    for param in token_params:
                        if param in data:
                            tokens[param] = {
                                'value': data[param],
                                'source': 'request_body_json',
                                'timestamp': time.time(),
                                'url': http_request.url,
                            }
                elif 'application/x-www-form-urlencoded' in ct:
                    data = parse_qs(http_request.data)
                    for param in token_params:
                        if param in data:
                            tokens[param] = {
                                'value': data[param][0],
                                'source': 'request_body_form',
                                'timestamp': time.time(),
                                'url': http_request.url,
                            }
            except Exception:
                pass

        # From response body
        if http_response and http_response.text:
            try:
                resp_ct = (http_response.headers or {}).get('content-type', '')
                if 'application/json' in resp_ct:
                    data = json.loads(http_response.text)
                    for param in token_params + ['token_type', 'expires_in', 'scope']:
                        if param in data:
                            tokens[param] = {
                                'value': str(data[param]),
                                'source': 'response_body',
                                'timestamp': time.time(),
                                'url': http_request.url,
                            }
            except Exception:
                pass

        # Bearer token from Authorization header
        auth_header = (http_request.headers or {}).get('Authorization', '')
        if auth_header.startswith('Bearer '):
            tokens['bearer_token'] = {
                'value': auth_header[7:],
                'source': 'auth_header',
                'timestamp': time.time(),
                'url': http_request.url,
            }

    def _extract_cookies(self, http_request, http_response, flow_data: dict):
        """Extract cookies from request/response."""
        cookies = flow_data['cookies']
        if http_request.cookies:
            for name, value in http_request.cookies.items():
                cookies[name] = {
                    'value': value,
                    'source': 'request',
                    'timestamp': time.time(),
                    'url': http_request.url,
                }
        if http_response:
            set_cookie = (http_response.headers or {}).get('Set-Cookie', '')
            if set_cookie:
                for cookie_str in set_cookie.split(','):
                    if '=' in cookie_str:
                        name, value = cookie_str.split('=', 1)
                        name = name.strip()
                        value = value.split(';')[0].strip()
                        cookies[name] = {
                            'value': value,
                            'source': 'response',
                            'timestamp': time.time(),
                            'url': http_request.url,
                            'attributes': self._parse_cookie_attributes(cookie_str),
                        }

    def _parse_cookie_attributes(self, cookie_str: str) -> dict:
        """Parse cookie attributes (Secure, HttpOnly, SameSite, etc.)."""
        attrs = {}
        parts = cookie_str.split(';')[1:]  # Skip name=value
        for part in parts:
            part = part.strip().lower()
            if part == 'secure':
                attrs['secure'] = True
            elif part == 'httponly':
                attrs['httponly'] = True
            elif part.startswith('samesite='):
                attrs['samesite'] = part.split('=', 1)[1]
            elif part.startswith('max-age='):
                attrs['max_age'] = part.split('=', 1)[1]
            elif part.startswith('domain='):
                attrs['domain'] = part.split('=', 1)[1]
            elif part.startswith('path='):
                attrs['path'] = part.split('=', 1)[1]
        return attrs

    def _extract_parameters(self, http_request, flow_data: dict):
        """Extract security-sensitive parameters."""
        parameters = flow_data['parameters']
        parsed_url = urlparse(http_request.url)
        params = parse_qs(parsed_url.query)

        sensitive_params = [
            'redirect_uri', 'client_id', 'response_type', 'scope',
            'state', 'nonce', 'csrf_token', 'authenticity_token',
            'code_challenge', 'code_challenge_method', 'code_verifier',
            'RelayState', 'SAMLRequest', 'SAMLResponse',
        ]
        for param in sensitive_params:
            if param in params:
                parameters[param] = {
                    'value': params[param][0],
                    'source': 'url_param',
                    'timestamp': time.time(),
                    'url': http_request.url,
                }

    # ──────────────────────────────────────────────────────────────────────
    # Utility / Export
    # ──────────────────────────────────────────────────────────────────────

    def get_flow_data(self, session_id: str) -> Optional[dict]:
        """Get recorded flow data by session ID."""
        return self.flows.get(session_id)

    def get_all_flows(self) -> Dict[str, dict]:
        """Get all recorded flows."""
        return self.flows.copy()

    def clear_flows(self):
        """Clear all recorded flows."""
        self.flows.clear()

    def export_flow(self, session_id: str, filepath: str):
        """Export flow to JSON file."""
        flow_data = self.flows.get(session_id)
        if flow_data:
            export_data = dict(flow_data)
            # Convert sets to lists for JSON serialization
            if isinstance(export_data.get('endpoints'), set):
                export_data['endpoints'] = list(export_data['endpoints'])
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, default=str)

    def import_flow(self, filepath: str) -> Optional[str]:
        """Import flow from JSON file."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                flow_data = json.load(f)
            session_id = flow_data.get('session_id', f"imported_{int(time.time())}")
            self.flows[session_id] = flow_data
            return session_id
        except Exception as e:
            logger.error(f"Failed to import flow: {e}")
            return None

    def get_detected_protocols(self, session_id: str) -> List[str]:
        """Get list of detected protocols for a session."""
        flow = self.flows.get(session_id)
        return flow.get('detected_protocols', []) if flow else []

    def get_protocol_summary(self, session_id: str) -> dict:
        """Get a summary of protocol-specific data for a session."""
        flow = self.flows.get(session_id)
        if not flow:
            return {}
        return {
            'protocols': flow.get('detected_protocols', []),
            'ntlm_exchanges': len(flow.get('ntlm_exchanges', [])),
            'kerberos_tickets': len(flow.get('kerberos_tickets', [])),
            'saml_assertions': len(flow.get('saml_assertions', [])),
            'oauth_flows': len(flow.get('oauth_flows', [])),
            'certificates': len(flow.get('certificates', [])),
            'tokens_found': len(flow.get('tokens', {})),
            'cookies_found': len(flow.get('cookies', {})),
            'total_requests': len(flow.get('requests', [])),
            'auth_requests': sum(1 for r in flow.get('requests', []) if r.get('is_auth_related')),
        }
