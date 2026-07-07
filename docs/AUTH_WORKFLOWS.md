# Auth Workflows — Authentication Flow Analysis & Testing

## Overview

Auth Workflows is an enterprise-grade authentication security testing module that captures, models, and tests authentication flows across all major protocols. It automatically detects the authentication mechanism in use, builds a visual state model, and runs protocol-specific security tests to identify vulnerabilities.

**Location:** Exploits > Auth Workflows

## Supported Protocols

| Protocol | Detection | Token Analysis | Attack Mutations |
|----------|-----------|----------------|------------------|
| OAuth 2.0 | Authorization Code, Implicit, Client Credentials, PKCE, Refresh | Scope, lifetime, entropy | 7 mutations |
| OpenID Connect | id_token, nonce, at_hash, audience | Full OIDC claim validation | 3 mutations |
| NTLM | Type 1/2/3 messages, NTLMv1/v2, domain/user extraction | Hash analysis, version detection | 3 mutations |
| Kerberos | SPNEGO, realm/SPN extraction, encryption type | RC4/AES detection, ticket size | Delegation/encryption tests |
| SAML 2.0 | POST/Redirect binding, assertion parsing | Signature, encryption, conditions | 5 mutations |
| Forms-Based Auth | Login form detection, CSRF awareness | Session cookie analysis | 3 mutations |
| Certificate/mTLS | Client cert headers, mutual TLS indicators | Certificate presence validation | Transport checks |
| JWT | Bearer tokens, header/payload/signature decode | Algorithm, claims, weak secret brute-force | 5 mutations |
| API Keys | Header and query parameter detection | Entropy, length, exposure | 3 mutations |
| HTTP Basic/Digest | Authorization header parsing | Credential strength | Transport checks |

## Getting Started

### 1. Record an Authentication Flow

1. Navigate to **Exploits > Auth Workflows**
2. In the **Flow Recording** tab, enter a session name (optional)
3. Click **Start Recording**
4. Perform the authentication flow in your browser (configure browser to use the proxy)
5. Click **Stop Recording**

The recorder automatically detects the authentication protocol in use and classifies each request.

### 2. Analyze the Flow

1. Select the recorded flow and click **Analyze Flow** (or go to the **State Model** tab)
2. Click **Build Model** to generate the authentication state graph
3. Review the **Flow Graph** — nodes are color-coded by type:
   - Red: Token minting endpoints
   - Blue: Login endpoints
   - Teal: Callbacks
   - Yellow: Challenge (NTLM/Kerberos)
   - Purple: Authentication responses
   - Pink: IdP redirects (SAML)
4. Review the **Security Issues** table for automatically detected vulnerabilities

### 3. Run Security Tests

1. Go to the **Replay & Testing** tab
2. Select the flow to test
3. Choose a testing approach:
   - **Baseline Replay** — Replays the flow without changes (verifies it works)
   - **Auto Security Test** — Runs protocol-appropriate mutations based on detected protocols
   - **Full Audit** — Runs all 30+ mutations across all protocols
   - **Selected Mutations** — Choose specific attacks from the checkbox grid
4. Monitor results in the output panel and progress bar

### 4. Analyze Tokens

1. Go to the **Token Analysis** tab
2. Select a flow and click **Analyze Tokens**
3. Review the token table (type, entropy, algorithm, vulnerabilities)
4. Click a token row to see full analysis details

## Security Tests Reference

### Generic Mutations (All Protocols)

| Mutation | Purpose | Detects |
|----------|---------|---------|
| Remove Auth Token | Strip all authentication from request | Missing auth enforcement (CWE-306) |
| Use Expired Token | Replace token with invalid/expired value | Token validation bypass |
| Swap User Token | Use a different user's token | Horizontal privilege escalation |
| Remove CSRF | Strip CSRF protection tokens | CSRF vulnerabilities (CWE-352) |
| Privilege Escalation | Modify user IDs to admin values | IDOR / vertical escalation |
| Method Tampering | Change HTTP method (GET/POST swap) | Method-based access control bypass |

### OAuth 2.0 Mutations

| Mutation | Purpose | Detects |
|----------|---------|---------|
| Remove State | Strip state parameter from authorize request | CSRF on OAuth callback (CWE-352) |
| Modify Redirect URI | Change redirect_uri to attacker-controlled URL | Open redirect / token theft (CWE-601) |
| Code Reuse | Replay authorization code | Single-use code enforcement |
| Scope Escalation | Add elevated scopes (admin, write:all) | Scope validation bypass |
| PKCE Bypass | Remove code_verifier/code_challenge | PKCE enforcement (CWE-300) |
| Implicit Token Leak | Force response_type=token | Implicit grant downgrade |
| Client ID Swap | Replace client_id with different client | Client isolation failure |

### OIDC Mutations

| Mutation | Purpose | Detects |
|----------|---------|---------|
| Nonce Replay | Reuse a previously used nonce | id_token replay attacks (CWE-294) |
| Audience Confusion | Change aud claim to different client | Audience validation bypass (CWE-284) |
| id_token Swap | Replace id_token with forged one | Token verification bypass |

### JWT Mutations

| Mutation | Purpose | Detects |
|----------|---------|---------|
| Algorithm None | Set alg=none, empty signature | Signature bypass (CWE-327) |
| Signature Strip | Remove signature entirely | Missing verification |
| Claim Tamper | Modify role/admin claims | Claim-based authz bypass |
| Expiry Bypass | Set exp far in the future | Expiration validation bypass (CWE-613) |
| KID Injection | Inject path traversal in kid header | Key confusion / file read |

### SAML Mutations

| Mutation | Purpose | Detects |
|----------|---------|---------|
| Assertion Replay | Replay SAML assertion unchanged | Replay protection (CWE-294) |
| Signature Strip | Remove XML digital signature | Signature validation bypass (CWE-345) |
| Attribute Injection | Inject admin role attribute | Attribute validation bypass |
| XXE Injection | Inject XML External Entity payload | XXE in SAML parser (CWE-611) |
| Recipient Mismatch | Modify Destination/Recipient | Destination validation bypass |

### NTLM Mutations

| Mutation | Purpose | Detects |
|----------|---------|---------|
| Remove Auth | Strip NTLM Authorization header | Auth enforcement |
| Downgrade to NTLMv1 | Send negotiate without NTLMv2 flag | Protocol downgrade acceptance |
| Empty Challenge | Send empty NTLM token | Error handling / crash |

### FBA Mutations

| Mutation | Purpose | Detects |
|----------|---------|---------|
| Remove CSRF | Strip CSRF from login form | Login CSRF (CWE-352) |
| Session Fixation | Send pre-set session cookie | Session fixation (CWE-384) |
| Empty Credentials | Submit form with blank password | Empty password acceptance |

### API Key Mutations

| Mutation | Purpose | Detects |
|----------|---------|---------|
| Remove Key | Strip API key from request | Key enforcement |
| Invalid Key | Replace with garbage value | Key validation |
| Other User Key | Replace with different user's key | Key isolation |

## Automatic Vulnerability Detection

The State Model analyzer automatically checks for these issues when you build a model:

### OAuth 2.0 / OIDC
- Missing state parameter (CSRF risk)
- Missing PKCE on authorization code flow
- PKCE with plain method (no security benefit)
- Implicit grant usage (deprecated, token exposure)
- HTTP redirect_uri (token interception)
- Overly broad scope requests
- Missing nonce in OIDC (replay risk)
- Missing at_hash (token substitution)
- Missing/invalid audience

### NTLM
- NTLM over unencrypted HTTP (hash capture)
- NTLMv1 negotiation/response (weak, crackable)
- NTLM relay risk (no EPA/Channel Binding)

### Kerberos
- RC4 encryption (Kerberoasting vulnerable)
- Large tickets (unconstrained delegation indicator)

### SAML
- Unsigned assertions (forgery trivial)
- Unencrypted assertions (attribute exposure)
- SAML over HTTP (interception)
- Weak signature algorithms (SHA-1, MD5)
- Multiple signatures (XSW attack surface)

### JWT
- Algorithm none (signature bypass)
- Symmetric algorithms with weak secrets (brute-forced)
- jku/x5u headers (key injection)
- Missing expiration claim
- Long token lifetime (>24h)
- Sensitive data in claims

### Generic (All Protocols)
- Tokens in URL parameters (CWE-598)
- Session cookies without HttpOnly (CWE-1004)
- Session cookies without Secure flag (CWE-614)
- SameSite=None on session cookies (CWE-1275)
- Inconsistent authentication enforcement (CWE-306)

## Token Analysis Deep Dive

### JWT Analysis
- **Header decode:** algorithm, type, kid, jku, x5u
- **Payload decode:** all standard claims (iss, sub, aud, exp, iat, nbf, scope, roles)
- **Weak secret brute-force:** Tests against 16 common secrets for HMAC-signed tokens
- **Vulnerability detection:** alg=none, missing exp, long lifetime, sensitive claims, jku/x5u injection

### SAML Assertion Analysis
- **Structure:** issuer, NameID, destination, conditions (NotBefore/NotOnOrAfter)
- **Security:** signature presence, encryption, signature algorithm strength
- **Attributes:** extracted attribute names
- **Attack surface:** multiple signatures (XSW), weak algorithms

### Kerberos Ticket Analysis
- **Encryption type:** RC4-HMAC (etype 23 — vulnerable), AES-128 (17), AES-256 (18)
- **Metadata:** realm, SPN, ticket size
- **Delegation:** large ticket detection (possible TGT forwarding)

### NTLM Message Analysis
- **Type 1 (Negotiate):** flags, NTLMv2 support
- **Type 2 (Challenge):** target name, server challenge
- **Type 3 (Authenticate):** domain, username, workstation, NTLMv1 vs v2 (response length)

### Session Cookie Analysis
- **Entropy:** Shannon entropy calculation
- **Format:** numeric (predictable), short hex, random
- **Attributes:** HttpOnly, Secure, SameSite

## Export Options

### JSON Export
Exports all data including flows, tokens, vulnerabilities, and test results in machine-readable JSON format for integration with other tools.

### HTML Report
Generates a styled HTML report with:
- Summary statistics (flows, vulnerabilities, protocols)
- Severity-colored vulnerability table
- Suitable for client deliverables

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  Auth Workflows Widget                    │
│  ┌─────────┬──────────┬──────────┬────────┬──────────┐ │
│  │Recording│  Model   │ Testing  │ Tokens │ Results  │ │
│  └────┬────┴────┬─────┴────┬─────┴───┬────┴────┬─────┘ │
└───────┼─────────┼──────────┼─────────┼─────────┼────────┘
        │         │          │         │         │
   ┌────▼────┐┌───▼───┐┌────▼────┐┌───▼───┐    │
   │  Flow   ││ State ││ Replay  ││ Token │    │
   │Recorder ││ Model ││ Engine  ││Analyzer│    │
   └────┬────┘└───┬───┘└────┬────┘└───┬───┘    │
        │         │          │         │         │
        └─────────┴──────────┴─────────┴─────────┘
                    HTTP Proxy Engine
```

### Core Modules
- **auth_flow_recorder.py** — Protocol-aware traffic capture with automatic classification
- **auth_state_model.py** — Directed graph builder with protocol-specific security analyzers
- **auth_replay_engine.py** — 30+ mutation attacks with threaded execution and vulnerability detection
- **auth_token_analyzer.py** — Deep token inspection with entropy, structure, and weakness analysis

## Tips for Effective Testing

1. **Record complete flows** — Include the full sequence from unauthenticated to authenticated
2. **Test multiple roles** — Record flows for admin, user, and guest to enable differential analysis
3. **Use Auto Security Test first** — It selects mutations based on detected protocols
4. **Review false positives** — Some mutations may trigger WAF blocks that look like "success"
5. **Check token entropy** — Low entropy tokens (<3.5 bits/char) are almost always exploitable
6. **Look for NTLMv1** — If detected, it's a critical finding for any internal pentest
7. **Verify PKCE** — Modern OAuth implementations without PKCE are vulnerable to code interception
8. **Export for reporting** — Use HTML export for client deliverables, JSON for tool integration
