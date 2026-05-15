# Authenticated Web Crawler

The Huginn framework now includes an advanced authenticated web crawler that can perform comprehensive website crawling with various authentication methods. This feature enables security assessments of authenticated areas of web applications.

## 🔐 Authentication Methods Supported

### 1. Session Replay
- **Use Case**: Reuse existing session cookies from browser or proxy tools
- **Artifacts Collected**: Session cookies, CSRF tokens, persistent tokens
- **Configuration**: 
  - Manual cookie entry (name=value format or JSON)
  - HAR file import
  - Browser cookie import (planned)

### 2. Form-Based Login
- **Use Case**: Automatically detect and submit login forms
- **Artifacts Collected**: Session cookies, authentication tokens, CSRF tokens
- **Features**:
  - Auto-detection of login forms
  - CSRF token handling
  - Credential management integration
  - Follow login redirects

### 3. Header Authentication
- **Use Case**: API keys, Bearer tokens, JWT tokens, OAuth2
- **Artifacts Collected**: Authorization headers, API keys, custom headers
- **Supported Types**:
  - Bearer Token (`Authorization: Bearer <token>`)
  - API Key (`X-API-Key: <key>`)
  - JWT Token
  - Custom headers

### 4. HTTP Basic Authentication
- **Use Case**: RFC 7617 Basic Authentication
- **Artifacts Collected**: Base64 encoded credentials
- **Features**: Automatic credential encoding and header generation

## 🕵️ Authentication Artifacts Collection

The crawler automatically extracts and analyzes authentication-related data:

### Session Tokens
- **Cookies**: PHPSESSID, JSESSIONID, ASP.NET_SessionId, custom session cookies
- **JWT Tokens**: Found in headers, cookies, or JavaScript variables
- **SAML/OAuth2 Tokens**: id_token, access_token, refresh_token

### Browser Storage Data
- **localStorage**: Persistent client-side storage
- **sessionStorage**: Session-specific storage
- **JavaScript Variables**: Tokens embedded in page scripts

### Security Headers
- **Authorization Headers**: Bearer, Basic, custom authentication
- **CSRF Tokens**: Anti-CSRF protection tokens
- **API Keys**: Various API authentication methods

## 🚀 Usage Instructions

### Via HTTP Enumeration Tool

1. **Open HTTP Enumeration**
   - Navigate to Enumeration → HTTP Enum
   - Enter your target URL

2. **Configure Authentication**
   - Click "🔐 Configure Authentication" button
   - Select authentication method from tabs:
     - 🍪 Session Replay
     - 📝 Form Login  
     - 🔑 Header Auth
     - 🔐 Basic Auth
     - ⚙️ Advanced

3. **Set Authentication Parameters**
   - **Session Replay**: Enter cookies manually or import from HAR
   - **Form Login**: Enter username/password, enable auto-detection
   - **Header Auth**: Select token type, enter token/API key
   - **Basic Auth**: Enter username/password (auto-encoded)

4. **Apply Configuration**
   - Click "✅ Apply Authentication"
   - Button will show configured method

5. **Run Authenticated Scan**
   - Select "Crawler" scan type
   - Click "Run" to start authenticated crawling
   - Monitor real-time authentication artifacts

### Programmatic Usage

```python
from app.core.authenticated_crawler import AuthenticatedCrawler

# Initialize crawler
crawler = AuthenticatedCrawler()

# Method 1: Session Replay
cookies = {"PHPSESSID": "abc123", "csrftoken": "xyz789"}
success = crawler.authenticate(
    target_url="https://example.com",
    auth_method="session_replay",
    cookies=cookies
)

# Method 2: Form Login
success = crawler.authenticate(
    target_url="https://example.com/login",
    auth_method="form_login",
    username="admin",
    password="password123"
)

# Method 3: Header Authentication
headers = {"Authorization": "Bearer your_token_here"}
success = crawler.authenticate(
    target_url="https://api.example.com",
    auth_method="header_auth",
    custom_headers=headers
)

# Perform authenticated crawling
if success:
    results = crawler.crawl_authenticated(
        target_url="https://example.com",
        max_depth=3,
        max_pages=100
    )
```

## 📊 Real-Time Monitoring

The authenticated crawler provides real-time feedback:

### Authentication Status
- ✅ Authentication successful notifications
- ❌ Authentication failure alerts with error details
- 🔑 Token extraction notifications

### Crawling Progress
- 🔍 Page crawling status with authentication context
- 📄 Page titles and status codes
- 🎯 Authentication artifacts discovered per page

### Artifact Discovery
- **Tokens**: JWT, API keys, session tokens with masked values
- **Storage Data**: localStorage/sessionStorage item counts
- **Cookies**: Session and persistent cookie discovery

## 🛡️ Security Features

### Credential Protection
- **Masked Display**: Sensitive tokens shown with partial masking
- **Secure Storage**: Integration with credential manager
- **Session Export**: Save/load authentication sessions

### Scope Validation
- **Domain Restriction**: Only crawl same-domain URLs
- **Depth Limiting**: Configurable crawl depth limits
- **Rate Limiting**: Respectful crawling with delays

### Error Handling
- **Graceful Failures**: Continue crawling on individual page errors
- **Authentication Refresh**: Automatic token refresh (planned)
- **Session Validation**: Verify authentication status

## 📁 Session Management

### Export Authentication Session
```python
session_data = crawler.export_auth_session()
# Contains: cookies, tokens, headers, authentication status
```

### Import Authentication Session
```python
success = crawler.import_auth_session(session_data)
# Restore previous authentication state
```

### Session Persistence
- Save authentication configurations to JSON files
- Load previous authentication setups
- Share authentication configs between team members

## 🔧 Advanced Configuration

### Session Management
- **Timeout**: Configure session timeout (30-3600 seconds)
- **Keep Alive**: Maintain session during long crawls
- **Auto Refresh**: Automatic token refresh (planned)

### Proxy Integration
- **Proxy Support**: Route authentication through proxy
- **Traffic Analysis**: Integration with proxy database
- **Certificate Handling**: Custom SSL certificate management

### Performance Tuning
- **Concurrent Requests**: Configurable thread limits
- **Request Delays**: Respectful crawling intervals
- **Memory Management**: Efficient handling of large sites

## 🎯 Use Cases

### Penetration Testing
- **Authenticated Enumeration**: Discover protected resources
- **Session Analysis**: Analyze authentication mechanisms
- **Privilege Escalation**: Test different user privilege levels

### Bug Bounty Hunting
- **Hidden Endpoints**: Find authenticated-only endpoints
- **API Discovery**: Enumerate authenticated API endpoints
- **Token Analysis**: Analyze JWT and session tokens

### Security Assessments
- **Authentication Review**: Assess authentication implementations
- **Session Security**: Evaluate session management
- **Access Control**: Test authorization mechanisms

## 🚨 Important Notes

### Ethical Usage
- Only test applications you own or have explicit permission to test
- Respect rate limits and server resources
- Follow responsible disclosure practices

### Legal Compliance
- Ensure compliance with local laws and regulations
- Obtain proper authorization before testing
- Document testing scope and permissions

### Best Practices
- Use test credentials when possible
- Monitor for detection/blocking
- Implement proper cleanup procedures
- Document findings and remediation steps

## 🔄 Integration Points

### Credential Manager
- Store and retrieve authentication credentials
- Organize credentials by service/application
- Track credential sources and usage

### Proxy Engine
- Capture authentication traffic
- Analyze request/response patterns
- Extract authentication artifacts from traffic

### Reporting System
- Include authentication context in reports
- Document discovered authentication mechanisms
- Generate executive summaries with authentication findings

## 📈 Future Enhancements

### Planned Features
- **Multi-Factor Authentication**: Support for MFA workflows
- **OAuth2 Flows**: Complete OAuth2 authentication flows
- **Certificate Authentication**: Client certificate support
- **Kerberos/NTLM**: Windows authentication protocols

### Advanced Capabilities
- **Machine Learning**: Intelligent authentication detection
- **Behavioral Analysis**: User behavior simulation
- **Custom Plugins**: Extensible authentication modules
- **Cloud Integration**: Cloud service authentication

## 🐛 Troubleshooting

### Common Issues

**Authentication Fails**
- Verify credentials are correct
- Check for CSRF token requirements
- Ensure target URL is accessible
- Review authentication method selection

**Crawling Stops Early**
- Check authentication session validity
- Verify crawl depth and page limits
- Monitor for rate limiting or blocking
- Review error logs for specific issues

**Missing Artifacts**
- Ensure JavaScript execution is enabled
- Check for dynamic token generation
- Verify storage access permissions
- Review page content for embedded tokens

### Debug Mode
Enable detailed logging for troubleshooting:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## 📞 Support

For issues, questions, or feature requests related to the authenticated crawler:

1. Check the troubleshooting section above
2. Review the example scripts in `/examples/`
3. Consult the main Huginn documentation
4. Report bugs through the project issue tracker

---

**Remember**: Always use authentication features responsibly and in compliance with applicable laws and regulations. Only test applications you own or have explicit permission to assess.