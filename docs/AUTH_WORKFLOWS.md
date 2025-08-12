# Auth Workflows - Authentication Flow Analysis

The Auth Workflows feature provides comprehensive analysis of complex authentication flows, including OAuth, multi-step authentication, and session management. It helps identify authentication bypasses, privilege escalation vulnerabilities, and IDOR (Insecure Direct Object Reference) issues.

## 🎯 Overview

Auth Workflows automatically learns, visualizes, and replays complex authentication flows to detect inconsistent auth checks and security vulnerabilities.

### Key Features

- **Flow Recording**: Capture authentication sequences from HTTP proxy traffic
- **State Modeling**: Build graph representations of authentication flows
- **Replay & Mutation**: Test flows with various mutations to find bypasses
- **Token Analysis**: Deep analysis of JWT, OAuth, and session tokens
- **Differential Testing**: Compare authenticated vs unauthenticated responses
- **Vulnerability Detection**: Automated detection of auth-related vulnerabilities

## 🧩 Core Components

### 1. Flow Recorder (`auth_flow_recorder.py`)
Hooks into the HTTP proxy to capture authentication sequences:
- Tracks request/response pairs
- Identifies auth-related requests
- Extracts tokens, cookies, and parameters
- Builds redirect chains
- Records session state changes

### 2. State Model Builder (`auth_state_model.py`)
Represents authentication flows as directed graphs:
- **Nodes**: Endpoints/requests with auth requirements
- **Edges**: Transitions between requests
- **Token Lifecycle**: Track token creation, usage, and expiry
- **Security Analysis**: Identify missing protections

### 3. Replay & Mutation Engine (`auth_replay_engine.py`)
Tests authentication flows with various mutations:
- Remove authentication tokens
- Use expired tokens
- Swap user tokens
- Remove state parameters
- Modify redirect URIs
- Remove CSRF tokens
- Test privilege escalation

### 4. Token Analyzer (`auth_token_analyzer.py`)
Analyzes authentication tokens:
- **JWT Analysis**: Decode headers/payloads, check algorithms
- **OAuth Tokens**: Analyze structure and scope
- **Session Cookies**: Check predictability and entropy
- **Vulnerability Detection**: Find weak tokens and misconfigurations

### 5. Differential Tester (`auth_differential_tester.py`)
Compares responses between different authentication states:
- Authenticated vs unauthenticated
- Admin vs standard user
- Different users
- Identifies access control bypasses

## 🚀 Usage

### Basic Workflow

1. **Start Recording**
   - Navigate to Web & App Exploits → Auth Workflows
   - Click "🔴 Start Recording"
   - Perform authentication flow in browser (login, OAuth, etc.)
   - Click "⏹️ Stop Recording"

2. **Analyze Flow**
   - Select recorded flow
   - Click "📊 Analyze Flow" to build state model
   - Review flow graph and security issues

3. **Test for Vulnerabilities**
   - Go to "Replay & Testing" tab
   - Select mutations to test
   - Click "🧪 Run Selected Mutations"
   - Review results for vulnerabilities

4. **Analyze Tokens**
   - Go to "Token Analysis" tab
   - Click "🔍 Analyze Tokens"
   - Review token security and vulnerabilities

### Advanced Testing

#### Security Test Mutations

| Mutation | Purpose | Detects |
|----------|---------|---------|
| Remove Tokens | Remove auth tokens | Authentication bypass |
| Remove State | Remove OAuth state param | CSRF on OAuth callback |
| Modify Redirect URI | Change redirect destination | Open redirect vulnerabilities |
| Remove CSRF | Remove CSRF tokens | CSRF vulnerabilities |
| Privilege Escalation | Modify user IDs | Vertical privilege escalation |

#### Differential Testing

```python
# Compare authenticated vs unauthenticated
differential_tester.compare_auth_vs_unauth(flow_data)

# Compare admin vs user
differential_tester.compare_admin_vs_user(flow_data, admin_token, user_token)

# Compare different users
differential_tester.compare_different_users(flow_data, user1_token, user2_token)
```

## 🔍 Vulnerability Detection

### Automatically Detected Issues

1. **Missing State Parameter**
   - OAuth flows without state parameter
   - Risk: CSRF attacks on OAuth callback

2. **Insecure Redirect URI**
   - Non-HTTPS redirect URIs
   - Risk: Token interception

3. **Tokens in URL Parameters**
   - Sensitive tokens in query strings
   - Risk: Token leakage in logs/referrers

4. **Missing CSRF Protection**
   - POST requests without CSRF tokens
   - Risk: Cross-site request forgery

5. **JWT Vulnerabilities**
   - `alg=none` algorithm
   - Missing expiration claims
   - Overly broad scopes

6. **Predictable Session IDs**
   - Sequential or low-entropy session IDs
   - Risk: Session hijacking

7. **Authentication Bypass**
   - Requests succeed without tokens
   - Risk: Unauthorized access

8. **Privilege Escalation**
   - User ID manipulation succeeds
   - Risk: Horizontal/vertical privilege escalation

## 📊 State Model Visualization

The state model represents authentication flows as graphs:

```
[Login Form] --form_submit--> [POST /login] --redirect--> [OAuth Authorize]
     |                            |                           |
     v                            v                           v
[Anonymous]                  [Requires CSRF]            [Requires state]
                                  |                           |
                                  v                           v
                            [Token Created]              [Code Exchange]
                                  |                           |
                                  v                           v
                            [Session Cookie]            [Access Token]
```

### Node Properties
- **Auth Required**: Whether authentication is needed
- **Token Required**: Whether tokens are required
- **Anonymous**: Whether anonymous access is allowed
- **Node Type**: login, callback, token_mint, redirect

### Edge Properties
- **Trigger**: What causes the transition (redirect, form_submit, etc.)
- **Parameters Passed**: Which parameters flow between requests

## 🔐 Token Analysis

### JWT Token Analysis
```json
{
  "header": {
    "alg": "RS256",
    "typ": "JWT"
  },
  "payload": {
    "sub": "user123",
    "exp": 1640995200,
    "iat": 1640908800,
    "scope": "read write"
  },
  "vulnerabilities": [
    {
      "type": "overly_broad_scope",
      "severity": "medium",
      "description": "JWT token has overly broad scope"
    }
  ]
}
```

### Token Lifecycle Tracking
- **Creation**: Where and when tokens are minted
- **Usage**: Which endpoints consume tokens
- **Expiry**: Token expiration and refresh patterns
- **Scope**: Token permissions and limitations

## 🧪 Testing Strategies

### 1. OAuth Flow Testing
```python
# Test OAuth state parameter bypass
mutations = ['remove_state']
replay_engine.test_mutations(oauth_flow, mutations)

# Test redirect URI manipulation
mutations = ['modify_redirect_uri']
replay_engine.test_mutations(oauth_flow, mutations)
```

### 2. Session Management Testing
```python
# Test session fixation
mutations = ['remove_token', 'privilege_escalation']
replay_engine.test_mutations(session_flow, mutations)
```

### 3. API Authentication Testing
```python
# Test JWT bypass
mutations = ['remove_token', 'expired_token']
replay_engine.test_mutations(api_flow, mutations)
```

## 📈 Reporting

### Vulnerability Report Format
```json
{
  "type": "authentication_bypass",
  "severity": "high",
  "description": "Request succeeded without authentication token",
  "url": "https://api.example.com/user/profile",
  "evidence": {
    "original_status": 200,
    "mutated_status": 200,
    "mutation": "remove_token"
  },
  "recommendation": "Implement proper authentication checks"
}
```

### Export Options
- **JSON**: Raw data for integration
- **HTML**: Interactive report with flow diagrams
- **Database**: Persistent storage for historical analysis

## 🔧 Configuration

### Recording Settings
```python
# Configure auth indicators
auth_indicators = [
    'login', 'auth', 'oauth', 'token', 'callback',
    'redirect_uri', 'code', 'state', 'access_token'
]

# Configure sensitive parameters
sensitive_params = {
    'oauth': ['code', 'state', 'redirect_uri', 'client_id'],
    'csrf': ['csrf_token', 'authenticity_token', '_token'],
    'session': ['session_id', 'JSESSIONID', 'PHPSESSID']
}
```

### Mutation Settings
```python
# Configure mutation strategies
mutations = {
    'remove_token': remove_token_mutation,
    'expired_token': expired_token_mutation,
    'swap_user_token': swap_user_token_mutation,
    'remove_state': remove_state_mutation,
    'modify_redirect_uri': modify_redirect_uri_mutation
}
```

## 🎯 Best Practices

### 1. Recording Flows
- Start recording before beginning authentication
- Perform complete authentication flow (login → callback → resource access)
- Include both successful and failed authentication attempts
- Test different user roles (admin, user, guest)

### 2. Analyzing Results
- Focus on high-severity vulnerabilities first
- Verify findings manually before reporting
- Consider business logic context
- Document reproduction steps

### 3. Testing Mutations
- Start with basic replay to ensure flow works
- Test one mutation at a time initially
- Combine mutations for advanced testing
- Monitor for rate limiting and blocking

## 🚨 Common Vulnerabilities Found

### 1. OAuth Implementation Issues
- Missing or weak state parameter validation
- Insecure redirect URI validation
- Authorization code reuse
- Implicit flow vulnerabilities

### 2. Session Management Issues
- Predictable session IDs
- Session fixation vulnerabilities
- Insufficient session timeout
- Missing secure/httponly flags

### 3. JWT Implementation Issues
- Algorithm confusion attacks (alg=none)
- Weak signing keys
- Missing expiration validation
- Overly broad token scope

### 4. Access Control Issues
- Horizontal privilege escalation (IDOR)
- Vertical privilege escalation
- Missing authentication checks
- Inconsistent authorization enforcement

## 🔗 Integration

### With Proxy Engine
```python
# Connect to proxy for traffic capture
proxy_engine.request_logged.connect(flow_recorder.process_request)
proxy_engine.response_received.connect(flow_recorder.process_request)
```

### With Vulnerability Scanner
```python
# Feed findings to main vulnerability database
vuln_scanner.add_finding(vulnerability_data)
```

### With Reporting System
```python
# Generate comprehensive reports
report_generator.add_auth_findings(auth_vulnerabilities)
```

## 📚 References

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OAuth 2.0 Security Best Practices](https://tools.ietf.org/html/draft-ietf-oauth-security-topics)
- [JWT Security Best Practices](https://tools.ietf.org/html/rfc8725)
- [OWASP Top 10 - Broken Authentication](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)

## 🛠️ Development

### Adding New Mutations
```python
def custom_mutation(self, request: HttpRequest) -> HttpRequest:
    """Custom mutation logic"""
    mutated = self._copy_request(request)
    # Implement mutation logic
    return mutated

# Register mutation
replay_engine.mutations['custom_mutation'] = custom_mutation
```

### Adding New Token Types
```python
def analyze_custom_token(self, token_value: str) -> dict:
    """Analyze custom token format"""
    analysis = {}
    # Implement analysis logic
    return analysis

# Register analyzer
token_analyzer.token_analyzers['custom'] = analyze_custom_token
```

This comprehensive authentication workflow analysis system provides deep insights into authentication security and helps identify critical vulnerabilities that traditional scanners might miss.