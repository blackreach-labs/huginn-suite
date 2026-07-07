# app/core/auth_state_model.py
"""Protocol-aware authentication state model.

Builds directed-graph representations of authentication flows with
protocol-specific state machines and security analysis for:
- OAuth 2.0 / OIDC (Authorization Code, Implicit, PKCE, Client Credentials)
- NTLM (3-leg challenge-response)
- Kerberos (TGT → TGS → Service)
- SAML 2.0 (SP-initiated, IdP-initiated)
- Forms-Based Authentication
- Certificate / mTLS
- JWT lifecycle
- API Key usage patterns
"""
import json
import time
import re
from typing import Dict, List, Optional, Set, Tuple, Any
from enum import Enum
from urllib.parse import urlparse
from dataclasses import dataclass, field, asdict
from app.core.logger import logger


# ──────────────────────────────────────────────────────────────────────────────
# Data Classes
# ──────────────────────────────────────────────────────────────────────────────

class NodeType(Enum):
    """Types of nodes in the auth flow graph."""
    REQUEST = "request"
    REDIRECT = "redirect"
    TOKEN_MINT = "token_mint"
    TOKEN_REFRESH = "token_refresh"
    CALLBACK = "callback"
    LOGIN = "login"
    LOGOUT = "logout"
    CHALLENGE = "challenge"
    RESPONSE_AUTH = "response_auth"
    ASSERTION_CONSUMER = "assertion_consumer"
    IDP_REDIRECT = "idp_redirect"
    CONSENT = "consent"
    MFA_CHALLENGE = "mfa_challenge"


class SecuritySeverity(Enum):
    """Severity levels for security findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class AuthNode:
    """A node in the authentication flow graph."""
    id: str
    url: str
    method: str
    endpoint: str
    node_type: str = NodeType.REQUEST.value
    protocol: str = "unknown"
    requires_auth: bool = False
    requires_token: bool = False
    requires_cookie: bool = False
    is_anonymous: bool = True
    parameters: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    response_status: int = 0
    timestamp: float = 0
    protocol_metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.timestamp == 0:
            self.timestamp = time.time()


@dataclass
class AuthEdge:
    """A transition between nodes in the flow graph."""
    from_node: str
    to_node: str
    trigger: str  # redirect, form_submit, token_exchange, challenge_response, etc.
    condition: str = ""
    parameters_passed: List[str] = field(default_factory=list)
    protocol: str = "unknown"


@dataclass
class SecurityIssue:
    """A security finding from flow analysis."""
    issue_id: str
    issue_type: str
    severity: str
    protocol: str
    node_id: str = ""
    url: str = ""
    description: str = ""
    recommendation: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    cwe_id: str = ""
    owasp_ref: str = ""


# ──────────────────────────────────────────────────────────────────────────────
# Main State Model Class
# ──────────────────────────────────────────────────────────────────────────────

class AuthStateModel:
    """Builds and manages protocol-aware authentication flow state models."""

    def __init__(self):
        self.nodes: Dict[str, AuthNode] = {}
        self.edges: List[AuthEdge] = []
        self.flow_data: Optional[dict] = None
        self.token_lifecycle: Dict[str, dict] = {}
        self.security_issues: List[SecurityIssue] = []
        self._issue_counter = 0

        # Protocol-specific analyzers
        self._protocol_analyzers = {
            'oauth2': self._analyze_oauth2_security,
            'oidc': self._analyze_oidc_security,
            'ntlm': self._analyze_ntlm_security,
            'kerberos': self._analyze_kerberos_security,
            'saml': self._analyze_saml_security,
            'fba': self._analyze_fba_security,
            'jwt': self._analyze_jwt_security,
            'certificate': self._analyze_certificate_security,
            'api_key': self._analyze_api_key_security,
            'basic': self._analyze_basic_auth_security,
            'bearer': self._analyze_jwt_security,
        }

    def build_model(self, flow_data: dict):
        """Build state model from recorded flow data."""
        self.flow_data = flow_data
        self.nodes.clear()
        self.edges.clear()
        self.security_issues.clear()
        self.token_lifecycle.clear()
        self._issue_counter = 0

        requests = flow_data.get('requests', [])
        if not requests:
            return

        # Phase 1: Create nodes
        for i, request in enumerate(requests):
            node = self._create_node(i, request)
            self.nodes[node.id] = node

        # Phase 2: Create edges
        for i in range(len(requests) - 1):
            edge = self._create_edge(i, requests[i], requests[i + 1])
            self.edges.append(edge)

        # Phase 3: Analyze token lifecycle
        self._analyze_token_lifecycle()

        # Phase 4: Run protocol-specific security analysis
        self._run_security_analysis()

    def _create_node(self, index: int, request: dict) -> AuthNode:
        """Create a graph node from a request record."""
        node_id = f"node_{index}"
        parsed_url = urlparse(request.get('url', ''))

        node = AuthNode(
            id=node_id,
            url=request.get('url', ''),
            method=request.get('method', 'GET'),
            endpoint=f"{parsed_url.netloc}{parsed_url.path}",
            response_status=request.get('response_status', 0),
            timestamp=request.get('timestamp', 0),
            protocol=request.get('detected_protocol', 'unknown'),
            protocol_metadata=request.get('protocol_metadata', {}),
        )

        # Classify node type
        self._classify_node(node, request)
        # Determine auth requirements
        self._analyze_requirements(node, request)

        return node

    def _classify_node(self, node: AuthNode, request: dict):
        """Classify node type based on URL, response, and protocol metadata."""
        url_lower = node.url.lower()
        path_lower = urlparse(node.url).path.lower()
        status = node.response_status
        protocol = node.protocol

        # Protocol-specific classification
        if protocol == 'ntlm':
            msg_type = node.protocol_metadata.get('message_type')
            if msg_type == 1:
                node.node_type = NodeType.REQUEST.value
            elif msg_type == 2:
                node.node_type = NodeType.CHALLENGE.value
            elif msg_type == 3:
                node.node_type = NodeType.RESPONSE_AUTH.value
            return

        if protocol == 'kerberos':
            stage = node.protocol_metadata.get('stage', '')
            if stage == 'server_challenge':
                node.node_type = NodeType.CHALLENGE.value
            else:
                node.node_type = NodeType.RESPONSE_AUTH.value
            return

        if protocol == 'saml':
            msg_type = node.protocol_metadata.get('message_type', '')
            if 'SAMLRequest' in msg_type:
                node.node_type = NodeType.IDP_REDIRECT.value
            elif 'SAMLResponse' in msg_type:
                node.node_type = NodeType.ASSERTION_CONSUMER.value
            return

        # Generic URL-based classification
        if any(ind in url_lower for ind in ['/token', '/oauth/token', '/connect/token']):
            node.node_type = NodeType.TOKEN_MINT.value
        elif any(ind in url_lower for ind in ['callback', '/redirect', 'return_url']):
            node.node_type = NodeType.CALLBACK.value
        elif any(ind in path_lower for ind in ['login', 'signin', '/auth']):
            node.node_type = NodeType.LOGIN.value
        elif any(ind in path_lower for ind in ['logout', 'signout']):
            node.node_type = NodeType.LOGOUT.value
        elif any(ind in path_lower for ind in ['consent', 'approve', 'authorize']):
            node.node_type = NodeType.CONSENT.value
        elif any(ind in path_lower for ind in ['mfa', 'otp', '2fa', 'verify']):
            node.node_type = NodeType.MFA_CHALLENGE.value
        elif status in (301, 302, 303, 307, 308):
            node.node_type = NodeType.REDIRECT.value
        elif 'refresh' in url_lower and 'token' in url_lower:
            node.node_type = NodeType.TOKEN_REFRESH.value

    def _analyze_requirements(self, node: AuthNode, request: dict):
        """Determine authentication requirements for a node."""
        headers = request.get('headers', {})
        cookies = request.get('cookies', {})

        if 'Authorization' in headers:
            node.requires_auth = True
            node.is_anonymous = False
            auth_val = headers['Authorization']
            if 'Bearer' in auth_val:
                node.requires_token = True

        session_indicators = ['session', 'JSESSIONID', 'PHPSESSID', 'ASP.NET_SessionId',
                             '.ASPXAUTH', 'connect.sid']
        for cookie_name in cookies:
            if any(ind.lower() in cookie_name.lower() for ind in session_indicators):
                node.requires_cookie = True
                node.is_anonymous = False
                break

        node.parameters = request.get('params', {})
        # Store auth-relevant headers only
        auth_headers = {k: v for k, v in headers.items()
                       if k.lower() in ('authorization', 'x-csrf-token', 'x-api-key',
                                        'x-auth-token', 'cookie')}
        node.headers = auth_headers

    def _create_edge(self, index: int, current: dict, next_req: dict) -> AuthEdge:
        """Create a graph edge between two sequential requests."""
        from_node = f"node_{index}"
        to_node = f"node_{index + 1}"

        trigger = self._determine_trigger(current, next_req)
        params_passed = self._find_passed_parameters(current, next_req)
        protocol = next_req.get('detected_protocol', current.get('detected_protocol', 'unknown'))

        return AuthEdge(
            from_node=from_node,
            to_node=to_node,
            trigger=trigger,
            parameters_passed=params_passed,
            protocol=protocol or 'unknown',
        )

    def _determine_trigger(self, current: dict, next_req: dict) -> str:
        """Determine transition trigger between two requests."""
        status = current.get('response_status', 200)
        curr_protocol = current.get('detected_protocol', '')
        next_protocol = next_req.get('detected_protocol', '')

        # NTLM challenge-response sequence
        if curr_protocol == 'ntlm' or next_protocol == 'ntlm':
            curr_type = current.get('protocol_metadata', {}).get('message_type')
            next_type = next_req.get('protocol_metadata', {}).get('message_type')
            if curr_type == 2 and next_type == 3:
                return "ntlm_challenge_response"
            if status == 401:
                return "ntlm_negotiate"

        # SAML redirect
        if next_protocol == 'saml':
            msg_type = next_req.get('protocol_metadata', {}).get('message_type', '')
            if 'SAMLRequest' in msg_type:
                return "saml_authn_request"
            if 'SAMLResponse' in msg_type:
                return "saml_assertion_post"

        # OAuth token exchange
        if 'token' in next_req.get('url', '').lower() and next_req.get('method') == 'POST':
            return "token_exchange"

        # Standard HTTP triggers
        if status in (301, 302, 303, 307, 308):
            return "redirect"
        if next_req.get('method') == 'POST' and current.get('method') == 'GET':
            return "form_submit"
        if 'application/json' in next_req.get('headers', {}).get('Content-Type', ''):
            return "api_call"

        return "sequential"

    def _find_passed_parameters(self, current: dict, next_req: dict) -> List[str]:
        """Find parameters passed between sequential requests."""
        passed = []
        sensitive_params = {'code', 'state', 'nonce', 'access_token', 'id_token',
                           'refresh_token', 'SAMLResponse', 'SAMLRequest', 'RelayState',
                           'csrf_token', 'redirect_uri', 'code_verifier'}

        # Parameters in next request that could have come from current response
        next_params = set(next_req.get('params', {}).keys())
        next_data = next_req.get('data', '')
        for param in sensitive_params:
            if param in next_params or (next_data and param in next_data):
                passed.append(param)
        return passed

    # ──────────────────────────────────────────────────────────────────────
    # Token Lifecycle Analysis
    # ──────────────────────────────────────────────────────────────────────

    def _analyze_token_lifecycle(self):
        """Track token creation, usage, and expiry across the flow."""
        if not self.flow_data:
            return
        tokens = self.flow_data.get('tokens', {})
        for token_name, token_info in tokens.items():
            lifecycle = {
                'name': token_name,
                'created_at': token_info.get('timestamp'),
                'created_by': token_info.get('url'),
                'source': token_info.get('source'),
                'value_preview': (token_info.get('value', '') or '')[:50] + '...',
                'used_in': [],
                'expires_at': None,
                'scope': None,
                'is_jwt': False,
            }

            # Check if token is JWT
            value = token_info.get('value', '')
            if value and value.count('.') == 2:
                lifecycle['is_jwt'] = True
                jwt_info = self._decode_jwt_claims(value)
                if jwt_info:
                    lifecycle['expires_at'] = jwt_info.get('exp')
                    lifecycle['scope'] = jwt_info.get('scope')
                    lifecycle['issuer'] = jwt_info.get('iss')
                    lifecycle['subject'] = jwt_info.get('sub')

            # Find where token is used in subsequent requests
            for node_id, node in self.nodes.items():
                node_headers = str(node.headers)
                node_params = str(node.parameters)
                if token_name in node_headers or token_name in node_params:
                    lifecycle['used_in'].append({'node_id': node_id, 'url': node.url})
                elif value and len(value) > 10 and value[:20] in node_headers:
                    lifecycle['used_in'].append({'node_id': node_id, 'url': node.url})

            self.token_lifecycle[token_name] = lifecycle

    def _decode_jwt_claims(self, token: str) -> Optional[dict]:
        """Decode JWT payload claims (without verification)."""
        try:
            import base64
            parts = token.split('.')
            if len(parts) < 2:
                return None
            payload = parts[1]
            payload += '=' * (4 - len(payload) % 4)
            decoded = base64.urlsafe_b64decode(payload)
            return json.loads(decoded)
        except Exception:
            return None

    # ──────────────────────────────────────────────────────────────────────
    # Security Analysis Engine
    # ──────────────────────────────────────────────────────────────────────

    def _run_security_analysis(self):
        """Run all protocol-specific security analyzers."""
        if not self.flow_data:
            return
        detected_protocols = self.flow_data.get('detected_protocols', [])
        for protocol in detected_protocols:
            analyzer = self._protocol_analyzers.get(protocol)
            if analyzer:
                try:
                    analyzer()
                except Exception as e:
                    logger.debug(f"Security analyzer error for {protocol}: {e}")

        # Always run generic checks
        self._analyze_generic_security()

    def _add_issue(self, issue_type: str, severity: str, protocol: str,
                   description: str, recommendation: str = "",
                   node_id: str = "", url: str = "",
                   evidence: dict = None, cwe_id: str = "", owasp_ref: str = ""):
        """Add a security issue to the findings list."""
        self._issue_counter += 1
        issue = SecurityIssue(
            issue_id=f"AUTH-{self._issue_counter:04d}",
            issue_type=issue_type,
            severity=severity,
            protocol=protocol,
            node_id=node_id,
            url=url,
            description=description,
            recommendation=recommendation,
            evidence=evidence or {},
            cwe_id=cwe_id,
            owasp_ref=owasp_ref,
        )
        self.security_issues.append(issue)

    # ──── OAuth 2.0 Security Analysis ─────────────────────────────────────

    def _analyze_oauth2_security(self):
        """Analyze OAuth 2.0 flows for common vulnerabilities."""
        oauth_flows = self.flow_data.get('oauth_flows', [])
        for flow in oauth_flows:
            # Missing state parameter (CSRF)
            if not flow.get('has_state'):
                self._add_issue(
                    "oauth_missing_state", SecuritySeverity.HIGH.value, "oauth2",
                    "OAuth authorization request missing 'state' parameter. "
                    "This exposes the flow to CSRF attacks where an attacker can "
                    "inject their authorization code into the victim's session.",
                    "Add a cryptographically random state parameter tied to the user's session.",
                    url=flow.get('url', ''),
                    cwe_id="CWE-352",
                    owasp_ref="WSTG-ATHN-04",
                )

            # Missing PKCE on authorization code flow
            grant = flow.get('grant_type', '')
            if grant == 'authorization_code' and not flow.get('has_pkce'):
                self._add_issue(
                    "oauth_missing_pkce", SecuritySeverity.MEDIUM.value, "oauth2",
                    "Authorization code flow without PKCE (Proof Key for Code Exchange). "
                    "Public clients are vulnerable to authorization code interception.",
                    "Implement PKCE with S256 code_challenge_method for all public clients.",
                    url=flow.get('url', ''),
                    cwe_id="CWE-300",
                    owasp_ref="WSTG-ATHN-04",
                )

            # PKCE with plain method
            if flow.get('has_pkce') and flow.get('pkce_method', '') == 'plain':
                self._add_issue(
                    "oauth_pkce_plain", SecuritySeverity.MEDIUM.value, "oauth2",
                    "PKCE uses 'plain' code_challenge_method which provides no security "
                    "against code interception attacks.",
                    "Use 'S256' code_challenge_method instead of 'plain'.",
                    url=flow.get('url', ''),
                    cwe_id="CWE-327",
                )

            # Implicit grant (token in URL fragment)
            if grant == 'implicit':
                self._add_issue(
                    "oauth_implicit_grant", SecuritySeverity.HIGH.value, "oauth2",
                    "OAuth Implicit grant type detected. Tokens are exposed in URL fragments, "
                    "browser history, and referrer headers. This grant type is deprecated.",
                    "Migrate to Authorization Code flow with PKCE.",
                    url=flow.get('url', ''),
                    cwe_id="CWE-598",
                    owasp_ref="WSTG-ATHN-04",
                )

            # Insecure redirect_uri
            redirect_uri = flow.get('redirect_uri', '')
            if redirect_uri and redirect_uri.startswith('http://'):
                self._add_issue(
                    "oauth_insecure_redirect", SecuritySeverity.HIGH.value, "oauth2",
                    f"OAuth redirect_uri uses insecure HTTP: {redirect_uri}. "
                    "Authorization codes and tokens may be intercepted.",
                    "Use HTTPS for all redirect URIs.",
                    url=flow.get('url', ''),
                    evidence={'redirect_uri': redirect_uri},
                    cwe_id="CWE-319",
                )

            # Overly broad scope
            scopes = flow.get('scopes', [])
            broad_scopes = ['*', 'all', 'admin', 'root', 'full_access']
            for scope in scopes:
                if scope.lower() in broad_scopes:
                    self._add_issue(
                        "oauth_broad_scope", SecuritySeverity.MEDIUM.value, "oauth2",
                        f"OAuth flow requests overly broad scope: '{scope}'. "
                        "Principle of least privilege should be applied.",
                        "Request minimum necessary scopes for the operation.",
                        url=flow.get('url', ''),
                        evidence={'scope': scope},
                    )

    # ──── OIDC Security Analysis ──────────────────────────────────────────

    def _analyze_oidc_security(self):
        """Analyze OpenID Connect flows for vulnerabilities."""
        # Run base OAuth2 checks first
        self._analyze_oauth2_security()

        oauth_flows = self.flow_data.get('oauth_flows', [])
        for flow in oauth_flows:
            # Missing nonce (replay protection)
            if not flow.get('has_nonce'):
                self._add_issue(
                    "oidc_missing_nonce", SecuritySeverity.MEDIUM.value, "oidc",
                    "OIDC authentication request missing 'nonce' parameter. "
                    "id_token replay attacks are possible.",
                    "Include a cryptographically random nonce in authentication requests "
                    "and validate it in the id_token.",
                    url=flow.get('url', ''),
                    cwe_id="CWE-294",
                )

        # Check id_token in tokens
        tokens = self.flow_data.get('tokens', {})
        id_token_info = tokens.get('id_token')
        if id_token_info:
            value = id_token_info.get('value', '')
            claims = self._decode_jwt_claims(value)
            if claims:
                # Missing 'at_hash' when access_token also issued
                if 'access_token' in tokens and 'at_hash' not in claims:
                    self._add_issue(
                        "oidc_missing_at_hash", SecuritySeverity.MEDIUM.value, "oidc",
                        "id_token missing 'at_hash' claim while access_token was also issued. "
                        "Token substitution attacks are possible.",
                        "Include at_hash claim in id_token when issuing alongside access_token.",
                        cwe_id="CWE-345",
                    )
                # Check audience
                aud = claims.get('aud')
                if not aud:
                    self._add_issue(
                        "oidc_missing_audience", SecuritySeverity.HIGH.value, "oidc",
                        "id_token missing 'aud' (audience) claim. "
                        "Token may be accepted by unintended relying parties.",
                        "Always include and validate the audience claim.",
                        cwe_id="CWE-284",
                    )

    # ──── NTLM Security Analysis ─────────────────────────────────────────

    def _analyze_ntlm_security(self):
        """Analyze NTLM authentication for vulnerabilities."""
        exchanges = self.flow_data.get('ntlm_exchanges', [])
        if not exchanges:
            return

        # NTLM over HTTP (not HTTPS)
        for exchange in exchanges:
            url = exchange.get('url', '')
            if url.startswith('http://'):
                self._add_issue(
                    "ntlm_over_http", SecuritySeverity.CRITICAL.value, "ntlm",
                    f"NTLM authentication over unencrypted HTTP: {url}. "
                    "NTLM hashes can be captured and relayed or cracked offline.",
                    "Enforce HTTPS for all NTLM-authenticated endpoints. "
                    "Consider migrating to Kerberos or modern protocols.",
                    url=url,
                    cwe_id="CWE-319",
                )

        # Check for NTLMv1 (weaker than NTLMv2)
        for exchange in exchanges:
            flags = exchange.get('flags', 0)
            # NTLMSSP_NEGOTIATE_NTLM2 (0x00080000) indicates NTLMv2 support
            if flags and not (flags & 0x00080000):
                self._add_issue(
                    "ntlm_v1_detected", SecuritySeverity.HIGH.value, "ntlm",
                    "NTLMv1 authentication detected. NTLMv1 hashes are significantly "
                    "easier to crack than NTLMv2 and are vulnerable to relay attacks.",
                    "Disable NTLMv1 via Group Policy (LmCompatibilityLevel >= 3). "
                    "Migrate to Kerberos authentication.",
                    url=exchange.get('url', ''),
                    cwe_id="CWE-328",
                )
                break  # Report once

        # NTLM relay risk (any NTLM without EPA/CBT)
        self._add_issue(
            "ntlm_relay_risk", SecuritySeverity.HIGH.value, "ntlm",
            "NTLM authentication detected. Without Extended Protection for Authentication "
            "(EPA/Channel Binding), NTLM hashes may be relayed to other services.",
            "Enable EPA (Channel Binding Tokens) on all NTLM-enabled services. "
            "Require SMB/LDAP signing. Consider disabling NTLM entirely.",
            cwe_id="CWE-294",
            evidence={'exchanges_count': len(exchanges)},
        )

    # ──── Kerberos Security Analysis ─────────────────────────────────────

    def _analyze_kerberos_security(self):
        """Analyze Kerberos authentication for vulnerabilities."""
        tickets = self.flow_data.get('kerberos_tickets', [])
        if not tickets:
            return

        for ticket in tickets:
            # Weak encryption types
            enc_type = ticket.get('enc_type', '')
            weak_enctypes = ['rc4', 'des', 'arcfour']
            if any(w in enc_type.lower() for w in weak_enctypes):
                self._add_issue(
                    "kerberos_weak_encryption", SecuritySeverity.HIGH.value, "kerberos",
                    f"Kerberos ticket using weak encryption: {enc_type}. "
                    "RC4 (ARCFOUR) encryption is vulnerable to Kerberoasting attacks.",
                    "Disable RC4/DES encryption. Enforce AES-256 for Kerberos.",
                    url=ticket.get('url', ''),
                    evidence={'enc_type': enc_type},
                    cwe_id="CWE-327",
                )

            # Large ticket size may indicate delegation
            ticket_size = ticket.get('ticket_size', 0)
            if ticket_size > 5000:
                self._add_issue(
                    "kerberos_delegation_risk", SecuritySeverity.MEDIUM.value, "kerberos",
                    "Large Kerberos ticket detected (possible unconstrained delegation). "
                    "Unconstrained delegation allows service to impersonate any user.",
                    "Use constrained delegation or resource-based constrained delegation. "
                    "Audit delegation settings in Active Directory.",
                    url=ticket.get('url', ''),
                    evidence={'ticket_size': ticket_size},
                    cwe_id="CWE-269",
                )

    # ──── SAML Security Analysis ──────────────────────────────────────────

    def _analyze_saml_security(self):
        """Analyze SAML 2.0 flows for vulnerabilities."""
        assertions = self.flow_data.get('saml_assertions', [])
        for assertion in assertions:
            # Unsigned assertions
            if assertion.get('type') == 'SAMLResponse' and not assertion.get('signed'):
                self._add_issue(
                    "saml_unsigned_assertion", SecuritySeverity.CRITICAL.value, "saml",
                    "SAML Response/Assertion is not digitally signed. "
                    "An attacker can forge assertions to impersonate any user.",
                    "Require signed assertions and validate signatures against trusted IdP certificates.",
                    url=assertion.get('url', ''),
                    cwe_id="CWE-345",
                    owasp_ref="WSTG-ATHN-04",
                )

            # Unencrypted assertions containing sensitive attributes
            if assertion.get('type') == 'SAMLResponse' and not assertion.get('encrypted'):
                self._add_issue(
                    "saml_unencrypted_assertion", SecuritySeverity.MEDIUM.value, "saml",
                    "SAML Assertion is not encrypted. Sensitive attributes (email, roles, "
                    "group memberships) are visible in transit.",
                    "Enable assertion encryption using the SP's public key.",
                    url=assertion.get('url', ''),
                    cwe_id="CWE-311",
                )

            # SAML over HTTP POST without TLS
            url = assertion.get('url', '')
            if url.startswith('http://'):
                self._add_issue(
                    "saml_over_http", SecuritySeverity.CRITICAL.value, "saml",
                    f"SAML assertion transmitted over unencrypted HTTP: {url}. "
                    "Assertions can be intercepted and replayed.",
                    "Enforce HTTPS on all SAML endpoints (ACS, SLO, IdP).",
                    url=url,
                    cwe_id="CWE-319",
                )

    # ──── FBA Security Analysis ───────────────────────────────────────────

    def _analyze_fba_security(self):
        """Analyze Forms-Based Authentication for vulnerabilities."""
        for node_id, node in self.nodes.items():
            if node.protocol != 'fba':
                continue
            metadata = node.protocol_metadata

            # Missing CSRF protection on login form
            if not metadata.get('has_csrf'):
                self._add_issue(
                    "fba_missing_csrf", SecuritySeverity.MEDIUM.value, "fba",
                    "Login form does not include CSRF protection token. "
                    "Login CSRF attacks can force a victim into an attacker's session.",
                    "Add CSRF token validation to login forms.",
                    node_id=node_id, url=node.url,
                    cwe_id="CWE-352",
                )

            # Login over HTTP
            if node.url.startswith('http://'):
                self._add_issue(
                    "fba_login_over_http", SecuritySeverity.CRITICAL.value, "fba",
                    f"Login form submits credentials over unencrypted HTTP: {node.url}",
                    "Enforce HTTPS on all login endpoints.",
                    node_id=node_id, url=node.url,
                    cwe_id="CWE-319",
                    owasp_ref="WSTG-ATHN-01",
                )

    # ──── JWT Security Analysis ───────────────────────────────────────────

    def _analyze_jwt_security(self):
        """Analyze JWT tokens for vulnerabilities."""
        tokens = self.flow_data.get('tokens', {})
        for name, info in tokens.items():
            value = info.get('value', '')
            if not value or value.count('.') != 2:
                continue

            claims = self._decode_jwt_claims(value)
            if not claims:
                continue

            # Decode header
            try:
                import base64
                header_b64 = value.split('.')[0]
                header_b64 += '=' * (4 - len(header_b64) % 4)
                header = json.loads(base64.urlsafe_b64decode(header_b64))
            except Exception:
                header = {}

            alg = header.get('alg', '')

            # Algorithm 'none'
            if alg.lower() == 'none':
                self._add_issue(
                    "jwt_alg_none", SecuritySeverity.CRITICAL.value, "jwt",
                    f"JWT token '{name}' uses 'none' algorithm. Signature verification is bypassed.",
                    "Reject tokens with alg=none. Whitelist allowed algorithms server-side.",
                    evidence={'token_name': name, 'algorithm': alg},
                    cwe_id="CWE-327",
                )

            # Weak symmetric algorithms
            if alg in ('HS256', 'HS384', 'HS512'):
                self._add_issue(
                    "jwt_symmetric_alg", SecuritySeverity.LOW.value, "jwt",
                    f"JWT '{name}' uses symmetric algorithm ({alg}). If the signing key is weak "
                    "or shared with clients, tokens can be forged.",
                    "Use asymmetric algorithms (RS256, ES256) for multi-party systems. "
                    "Ensure HMAC keys have sufficient entropy (>256 bits).",
                    evidence={'token_name': name, 'algorithm': alg},
                    cwe_id="CWE-327",
                )

            # Missing expiration
            if 'exp' not in claims:
                self._add_issue(
                    "jwt_no_expiry", SecuritySeverity.MEDIUM.value, "jwt",
                    f"JWT '{name}' has no expiration (exp) claim. "
                    "Compromised tokens remain valid indefinitely.",
                    "Include exp claim with reasonable lifetime (e.g. 15 minutes for access tokens).",
                    evidence={'token_name': name},
                    cwe_id="CWE-613",
                )

            # Very long expiration (>24h)
            exp = claims.get('exp')
            iat = claims.get('iat')
            if exp and iat and (exp - iat) > 86400:
                self._add_issue(
                    "jwt_long_expiry", SecuritySeverity.LOW.value, "jwt",
                    f"JWT '{name}' has long lifetime ({(exp - iat) // 3600}+ hours). "
                    "Long-lived tokens increase the window for token theft.",
                    "Reduce token lifetime. Use refresh tokens for long sessions.",
                    evidence={'token_name': name, 'lifetime_hours': (exp - iat) / 3600},
                )

    # ──── Certificate Security Analysis ──────────────────────────────────

    def _analyze_certificate_security(self):
        """Analyze certificate-based authentication."""
        certs = self.flow_data.get('certificates', [])
        for cert in certs:
            url = cert.get('url', '')
            if url.startswith('http://'):
                self._add_issue(
                    "cert_over_http", SecuritySeverity.CRITICAL.value, "certificate",
                    "Certificate authentication indicator found on HTTP (non-TLS) connection. "
                    "Client certificates require TLS.",
                    "Ensure mTLS endpoints are only accessible over HTTPS.",
                    url=url,
                    cwe_id="CWE-319",
                )

    # ──── API Key Security Analysis ──────────────────────────────────────

    def _analyze_api_key_security(self):
        """Analyze API key usage for vulnerabilities."""
        for node_id, node in self.nodes.items():
            if node.protocol != 'api_key':
                continue
            metadata = node.protocol_metadata

            # API key in query parameter (exposed in logs, referrer headers)
            if metadata.get('type') == 'query_api_key':
                self._add_issue(
                    "api_key_in_url", SecuritySeverity.HIGH.value, "api_key",
                    f"API key passed in URL query parameter '{metadata.get('param_name')}'. "
                    "Keys in URLs are logged in server logs, browser history, and referrer headers.",
                    "Pass API keys in request headers (e.g., X-API-Key) instead of URL parameters.",
                    node_id=node_id, url=node.url,
                    cwe_id="CWE-598",
                )

            # API key over HTTP
            if node.url.startswith('http://'):
                self._add_issue(
                    "api_key_over_http", SecuritySeverity.HIGH.value, "api_key",
                    f"API key transmitted over unencrypted HTTP: {node.url}",
                    "Enforce HTTPS for all API endpoints requiring authentication.",
                    node_id=node_id, url=node.url,
                    cwe_id="CWE-319",
                )

    # ──── Basic Auth Security Analysis ───────────────────────────────────

    def _analyze_basic_auth_security(self):
        """Analyze HTTP Basic authentication for vulnerabilities."""
        for node_id, node in self.nodes.items():
            if node.protocol != 'basic':
                continue
            if node.url.startswith('http://'):
                self._add_issue(
                    "basic_auth_over_http", SecuritySeverity.CRITICAL.value, "basic",
                    f"HTTP Basic authentication over unencrypted connection: {node.url}. "
                    "Base64-encoded credentials are trivially decoded.",
                    "Enforce HTTPS. Consider upgrading to token-based authentication.",
                    node_id=node_id, url=node.url,
                    cwe_id="CWE-319",
                    owasp_ref="WSTG-ATHN-01",
                )

    # ──── Generic Security Analysis ──────────────────────────────────────

    def _analyze_generic_security(self):
        """Protocol-agnostic security checks."""
        if not self.flow_data:
            return

        # Check for tokens in URL parameters
        tokens = self.flow_data.get('tokens', {})
        for name, info in tokens.items():
            if info.get('source') == 'url_param' and name in ('access_token', 'refresh_token', 'id_token'):
                self._add_issue(
                    "token_in_url", SecuritySeverity.HIGH.value, "generic",
                    f"Sensitive token '{name}' found in URL parameter. "
                    "Tokens in URLs leak via referrer headers, server logs, and browser history.",
                    "Transmit tokens in Authorization headers or POST body only.",
                    evidence={'token_name': name, 'url': info.get('url', '')},
                    cwe_id="CWE-598",
                )

        # Check cookie security attributes
        cookies = self.flow_data.get('cookies', {})
        session_cookies = ['session', 'JSESSIONID', 'PHPSESSID', 'ASP.NET_SessionId',
                          '.ASPXAUTH', 'connect.sid', 'auth', 'token']
        for name, info in cookies.items():
            is_session = any(ind.lower() in name.lower() for ind in session_cookies)
            if not is_session:
                continue
            attrs = info.get('attributes', {})
            if not attrs.get('httponly'):
                self._add_issue(
                    "cookie_missing_httponly", SecuritySeverity.MEDIUM.value, "generic",
                    f"Session cookie '{name}' missing HttpOnly flag. "
                    "Cookie can be accessed by JavaScript (XSS exposure).",
                    "Set HttpOnly flag on all session/authentication cookies.",
                    evidence={'cookie_name': name},
                    cwe_id="CWE-1004",
                )
            if not attrs.get('secure'):
                self._add_issue(
                    "cookie_missing_secure", SecuritySeverity.MEDIUM.value, "generic",
                    f"Session cookie '{name}' missing Secure flag. "
                    "Cookie may be sent over unencrypted HTTP.",
                    "Set Secure flag on all authentication cookies.",
                    evidence={'cookie_name': name},
                    cwe_id="CWE-614",
                )
            samesite = attrs.get('samesite', '')
            if not samesite or samesite.lower() == 'none':
                self._add_issue(
                    "cookie_samesite_none", SecuritySeverity.LOW.value, "generic",
                    f"Session cookie '{name}' has SameSite=None or missing SameSite attribute. "
                    "Cookie is sent on cross-site requests (CSRF risk).",
                    "Set SameSite=Lax or SameSite=Strict on session cookies.",
                    evidence={'cookie_name': name, 'samesite': samesite},
                    cwe_id="CWE-1275",
                )

        # Check for missing authentication on protected resources
        auth_nodes = [n for n in self.nodes.values() if n.requires_auth]
        anon_nodes = [n for n in self.nodes.values() if n.is_anonymous and n.response_status == 200]
        # If the flow has auth-protected resources followed by same endpoint without auth returning 200
        auth_urls = {urlparse(n.url).path for n in auth_nodes}
        for anon_node in anon_nodes:
            if urlparse(anon_node.url).path in auth_urls:
                self._add_issue(
                    "inconsistent_auth_enforcement", SecuritySeverity.HIGH.value, "generic",
                    f"Endpoint '{anon_node.endpoint}' returns 200 both with and without authentication. "
                    "Authentication may not be properly enforced.",
                    "Ensure all protected endpoints validate authentication before processing requests.",
                    node_id=anon_node.id, url=anon_node.url,
                    cwe_id="CWE-306",
                )

    # ──────────────────────────────────────────────────────────────────────
    # Public Query / Export API
    # ──────────────────────────────────────────────────────────────────────

    def find_security_issues(self, severity_filter: str = None, protocol_filter: str = None) -> List[dict]:
        """Return security issues, optionally filtered."""
        issues = self.security_issues
        if severity_filter:
            issues = [i for i in issues if i.severity == severity_filter]
        if protocol_filter:
            issues = [i for i in issues if i.protocol == protocol_filter]
        return [asdict(i) for i in issues]

    def get_graph_data(self) -> dict:
        """Get graph data for visualization."""
        nodes_data = []
        for node in self.nodes.values():
            nd = asdict(node)
            nd['label'] = f"{node.method} {urlparse(node.url).path}"
            nd['color'] = self._get_node_color(node)
            nodes_data.append(nd)

        edges_data = [asdict(e) for e in self.edges]

        return {
            'nodes': nodes_data,
            'edges': edges_data,
            'token_lifecycle': self.token_lifecycle,
            'security_issues': [asdict(i) for i in self.security_issues],
        }

    def get_protocol_state_summary(self) -> Dict[str, Any]:
        """Get a summary of the protocol state machine for each detected protocol."""
        summary = {}
        if not self.flow_data:
            return summary

        for protocol in self.flow_data.get('detected_protocols', []):
            protocol_nodes = [n for n in self.nodes.values() if n.protocol == protocol]
            protocol_edges = [e for e in self.edges if e.protocol == protocol]
            protocol_issues = [i for i in self.security_issues if i.protocol == protocol]

            summary[protocol] = {
                'nodes': len(protocol_nodes),
                'edges': len(protocol_edges),
                'issues': len(protocol_issues),
                'critical_issues': sum(1 for i in protocol_issues if i.severity == 'critical'),
                'high_issues': sum(1 for i in protocol_issues if i.severity == 'high'),
                'node_types': list(set(n.node_type for n in protocol_nodes)),
            }
        return summary

    def _get_node_color(self, node: AuthNode) -> str:
        """Get color for node based on type and protocol."""
        type_colors = {
            NodeType.TOKEN_MINT.value: "#FF6B6B",
            NodeType.TOKEN_REFRESH.value: "#FF9F43",
            NodeType.CALLBACK.value: "#4ECDC4",
            NodeType.LOGIN.value: "#45B7D1",
            NodeType.LOGOUT.value: "#96CEB4",
            NodeType.CHALLENGE.value: "#FECA57",
            NodeType.RESPONSE_AUTH.value: "#A29BFE",
            NodeType.IDP_REDIRECT.value: "#FD79A8",
            NodeType.ASSERTION_CONSUMER.value: "#00CEC9",
            NodeType.CONSENT.value: "#E17055",
            NodeType.MFA_CHALLENGE.value: "#D63031",
            NodeType.REDIRECT.value: "#74B9FF",
        }
        return type_colors.get(node.node_type, "#95A5A6")

    def export_model(self, filepath: str):
        """Export the full model to JSON."""
        data = {
            'graph': self.get_graph_data(),
            'protocol_summary': self.get_protocol_state_summary(),
            'token_lifecycle': self.token_lifecycle,
            'timestamp': time.time(),
        }
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
