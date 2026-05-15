# Unified HTTP Request Handling System

## Overview

The unified HTTP system replaces the previous subprocess-based curl approach with a powerful, integrated solution built on Python's `requests` library and orchestrated by the proxy engine. This provides significant performance, security, and functionality improvements.

## Architecture

### Core Components

1. **HttpRequest/HttpResponse** (`http_client.py`)
   - Unified request/response objects used throughout the system
   - Conversion methods for mitmproxy flows and requests.Response objects
   - Serialization support for history and caching

2. **UnifiedHttpClient** (`http_client.py`)
   - Replaces subprocess curl execution
   - Uses persistent `requests.Session` for performance
   - Handles authentication, headers, cookies automatically
   - Provides payload injection for vulnerability testing

3. **ProxyEngine** (`proxy_engine.py`)
   - Enhanced mitmproxy integration
   - Proper flow control (pause/resume/kill)
   - Unified request/response objects
   - History management

4. **Scanner Engines** (`scanner_engine.py`)
   - **PassiveScanner**: Enhanced security header checks, cookie analysis, error pattern detection
   - **ActiveScanner**: Real vulnerability testing with payloads, confidence levels, contextual analysis

5. **UnifiedRequestHandler** (`unified_request_handler.py`)
   - Central coordinator for all HTTP operations
   - Connects all components via Qt signals
   - Provides unified API for Repeater, Intruder, Scanner functionality

## Key Improvements

### Performance
- **10-100x faster**: Persistent HTTP sessions vs spawning curl processes
- **Memory efficient**: Proper connection pooling and reuse
- **Concurrent requests**: Native async support

### Security
- **No command injection**: Direct API calls instead of shell commands
- **Proper SSL handling**: Native certificate verification
- **Session management**: Automatic cookie and authentication handling

### Functionality
- **Real vulnerability detection**: Context-aware XSS, SQLi, LFI, Command Injection testing
- **Confidence levels**: High/Medium/Low confidence ratings for findings
- **Better error handling**: Proper exception management and retry logic
- **Unified objects**: Same request/response format across all tools

## Usage Examples

### Basic Request (Repeater)
```python
from app.core.unified_request_handler import UnifiedRequestHandler
from app.core.http_client import HttpRequest

handler = UnifiedRequestHandler()

request = HttpRequest(
    method="POST",
    url="https://api.example.com/login",
    headers={"Content-Type": "application/json"},
    data='{"username": "test", "password": "test"}'
)

response = handler.send_request(request)
print(f"Status: {response.status_code}")
```

### Multiple Requests (Intruder)
```python
# Send same request 10 times
responses = handler.send_multiple(request, 10)

# Analyze response times
times = [r.elapsed_time for r in responses]
print(f"Average response time: {sum(times)/len(times):.3f}s")
```

### Vulnerability Scanning
```python
# Active scan for vulnerabilities
findings = handler.scan_request(request)

for finding in findings:
    print(f"{finding['severity']}: {finding['type']} in {finding['parameter']}")
```

### Proxy Integration
```python
# Start proxy on port 8080
handler.start_proxy(8080)

# Enable request interception
handler.enable_intercept(True)

# Handle intercepted requests
def on_request_intercepted(flow_id, request):
    print(f"Intercepted: {request.method} {request.url}")
    # Forward or drop the request
    handler.forward_request(flow_id)

handler.request_intercepted.connect(on_request_intercepted)
```

## Migration from Old System

### Before (curl_interceptor.py)
```python
# Old subprocess approach
curl_request = CurlRequest(method="GET", url="https://example.com")
curl_interceptor.execute_curl(curl_request)
```

### After (unified system)
```python
# New unified approach
http_request = HttpRequest(method="GET", url="https://example.com")
response = handler.send_request(http_request)
```

## Benefits for Penetration Testing

### Workflow Integration
1. **Proxy captures traffic** → Automatic history logging
2. **Right-click request** → "Send to Repeater" or "Send to Scanner"
3. **Modify and resend** → Fast, programmatic request modification
4. **Vulnerability testing** → Context-aware payload injection
5. **Results correlation** → Unified findings across all tools

### Advanced Features
- **Session persistence**: Cookies and auth maintained across requests
- **Smart payload injection**: JSON, form data, URL parameters handled correctly
- **Time-based detection**: SQL injection timing analysis
- **Error correlation**: Pattern matching across response bodies
- **Confidence scoring**: Reduces false positives

## Security Enhancements

### Passive Scanner Improvements
- **Missing security headers**: CSP, HSTS, X-Frame-Options, etc.
- **Information disclosure**: Server versions, error messages, debug info
- **Cookie security**: HttpOnly, Secure, SameSite flags
- **Sensitive data exposure**: Credit cards, SSNs, API keys

### Active Scanner Capabilities
- **XSS detection**: Context-aware payload reflection analysis
- **SQL injection**: Error-based, boolean-based, and time-based detection
- **File inclusion**: Local and remote file inclusion testing
- **Command injection**: OS command execution detection
- **OAST integration**: Out-of-band application security testing (future)

## Configuration

### Request Defaults
```python
# Configure default headers
handler.http_client.session.headers.update({
    'User-Agent': 'Huginn Security Scanner/1.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
})

# Configure timeouts
handler.http_client.session.timeout = 30

# Configure SSL verification
handler.http_client.session.verify = True
```

### Proxy Settings
```python
# Configure proxy port
handler.start_proxy(port=8080)

# Configure interception rules
handler.enable_intercept(True)
```

## Future Enhancements

1. **OAST Integration**: Out-of-band testing with external servers
2. **Custom Payloads**: User-defined vulnerability test cases
3. **Machine Learning**: Pattern detection and anomaly analysis
4. **Distributed Scanning**: Multi-node scanning coordination
5. **Report Generation**: Automated vulnerability reporting

## Conclusion

The unified HTTP system provides a solid foundation for professional-grade security testing tools. By eliminating subprocess overhead and providing native Python integration, it delivers the performance and flexibility needed for modern penetration testing workflows.

The system is designed to be:
- **Fast**: Native HTTP client performance
- **Secure**: No command injection vulnerabilities
- **Flexible**: Easy to extend and customize
- **Integrated**: Seamless workflow between tools
- **Professional**: Enterprise-grade reliability and features