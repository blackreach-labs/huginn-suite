# HTTP Interceptor & Proxy System

## Overview

The HTTP Interceptor & Proxy System provides comprehensive HTTP traffic analysis, interception, and manipulation capabilities for web application security testing. Built on mitmproxy, it offers professional-grade proxy functionality with seamless integration into the Huginn platform.

## Architecture

### Core Components

1. **ProxyEngine** (`app/core/proxy_engine.py`)
   - Main proxy controller and Qt signal interface
   - Manages proxy lifecycle (start/stop)
   - Handles request interception and forwarding
   - Provides history and statistics access

2. **ProxyAddon** (`app/core/proxy_engine.py`)
   - mitmproxy addon for request/response handling
   - Converts mitmproxy flows to unified HttpRequest/HttpResponse objects
   - Manages paused flows for interception
   - Stores traffic data in proxy database

3. **ProxyDatabase** (`app/core/proxy_database.py`)
   - SQLite database for HTTP traffic storage
   - Located at `resources/proxy.db`
   - Stores request/response pairs with metadata
   - Provides history, statistics, and search capabilities

4. **HttpRequest/HttpResponse** (`app/core/http_client.py`)
   - Unified request/response objects
   - Conversion methods for mitmproxy flows
   - Serialization support for storage and analysis

## Features

### Traffic Interception
- **Real-time HTTP/HTTPS traffic capture**
- **Request/Response logging** with full headers and body
- **Automatic SSL certificate handling**
- **WebSocket traffic support**
- **Request timing and size metrics**

### Request Manipulation
- **Pause and modify requests** before forwarding
- **Drop unwanted requests**
- **Custom request forwarding**
- **Header and body modification**

### Traffic Analysis
- **Comprehensive request history**
- **Response time analysis**
- **Traffic statistics and metrics**
- **Content-type categorization**
- **Error rate monitoring**

### Database Storage
- **Persistent traffic history** in SQLite database
- **Full request/response storage** including headers and body
- **Indexed searches** by URL, method, timestamp
- **Statistics aggregation** for performance analysis

## Usage

### Starting the Proxy

```python
from app.core.proxy_engine import ProxyEngine

# Create proxy engine
proxy = ProxyEngine()

# Start proxy on port 8080
success = proxy.start_proxy(8080)

if success:
    print("Proxy started on http://127.0.0.1:8080")
else:
    print("Failed to start proxy")
```

### Request Interception

```python
# Enable request interception
proxy.enable_intercept(True)

# Connect to interception signals
proxy.request_intercepted.connect(handle_intercepted_request)

def handle_intercepted_request(flow_id, http_request):
    print(f"Intercepted: {http_request.method} {http_request.url}")
    
    # Forward the request
    proxy.forward_request(flow_id)
    
    # Or drop the request
    # proxy.drop_request(flow_id)
```

### Traffic History

```python
# Get recent traffic history
history = proxy.get_history(limit=100)

for request in history:
    print(f"{request['method']} {request['url']} - {request['status_code']}")

# Get detailed request information
details = proxy.get_request_details(request_id)
print(f"Request headers: {details['request_headers']}")
print(f"Response body: {details['response_body']}")
```

### Database Operations

```python
from app.core.proxy_database import ProxyDatabase

# Database automatically uses resources/proxy.db
db = ProxyDatabase()

# Get traffic statistics
stats = db.get_stats()
print(f"Total requests: {stats['total_requests']}")
print(f"Average response time: {stats['avg_response_time']}ms")

# Clear history
db.clear_history()
```

## Database Schema

### Requests Table

```sql
CREATE TABLE requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    host TEXT NOT NULL,
    path TEXT NOT NULL,
    status_code INTEGER,
    response_time REAL,
    request_size INTEGER,
    response_size INTEGER,
    request_headers TEXT,      -- JSON
    response_headers TEXT,     -- JSON
    request_body TEXT,
    response_body TEXT,
    content_type TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
```

### Indexes
- `idx_timestamp` - Fast timestamp-based queries
- `idx_url` - URL-based searches
- `idx_method` - HTTP method filtering

## Configuration

### Proxy Settings
- **Default Port**: 8080
- **SSL Certificate**: Auto-generated for HTTPS interception
- **Database Location**: `resources/proxy.db`
- **History Limit**: 1000 requests (configurable)

### Performance Tuning
- **Request Timeout**: 30 seconds
- **Database Connection Pool**: SQLite with WAL mode
- **Memory Usage**: Configurable body size limits
- **Concurrent Connections**: mitmproxy default (500)

## Integration Points

### Web Application Testing
- **Burp Suite Alternative**: Professional proxy functionality
- **Request Modification**: Real-time request manipulation
- **Response Analysis**: Automated response parsing
- **Session Management**: Cookie and authentication tracking

### Security Testing
- **SQL Injection Testing**: Request parameter manipulation
- **XSS Testing**: Response content analysis
- **Authentication Bypass**: Session token manipulation
- **API Testing**: REST/GraphQL request analysis

### Automation
- **Scripted Testing**: Programmatic request manipulation
- **Bulk Operations**: Batch request processing
- **Custom Analysis**: Plugin-based traffic analysis
- **Report Generation**: Traffic-based security reports

## Qt Signals

### ProxyEngine Signals
```python
request_intercepted = pyqtSignal(int, object)    # flow_id, HttpRequest
request_logged = pyqtSignal(object)              # HttpRequest
response_received = pyqtSignal(object)           # HttpResponse
passive_scan_request = pyqtSignal(object)        # HttpResponse for scanning
proxy_started = pyqtSignal(int)                  # port
proxy_stopped = pyqtSignal()
history_updated = pyqtSignal(int)                # request_id
```

### Signal Usage
```python
# Connect to proxy signals
proxy.request_logged.connect(log_request)
proxy.response_received.connect(analyze_response)
proxy.history_updated.connect(refresh_history_display)

def log_request(http_request):
    print(f"Request: {http_request.method} {http_request.url}")

def analyze_response(http_response):
    if http_response.status_code >= 400:
        print(f"Error response: {http_response.status_code}")
```

## Error Handling

### Common Issues
1. **Port Already in Use**
   ```python
   if not proxy.start_proxy(8080):
       # Try alternative port
       proxy.start_proxy(8081)
   ```

2. **mitmproxy Not Available**
   ```python
   if not proxy.proxy_available:
       print("Install mitmproxy: pip install mitmproxy")
   ```

3. **Database Lock**
   ```python
   try:
       db.store_request(request_data)
   except sqlite3.OperationalError:
       # Database locked, retry or skip
       pass
   ```

### Debugging
- **Enable Debug Logging**: Set logging level to DEBUG
- **Check Proxy Status**: Monitor proxy_started/proxy_stopped signals
- **Database Integrity**: Use SQLite PRAGMA commands
- **Network Connectivity**: Test with curl/browser

## Security Considerations

### Certificate Management
- **Auto-generated CA**: mitmproxy creates root certificate
- **Certificate Installation**: Required for HTTPS interception
- **Certificate Storage**: Secure certificate handling

### Data Protection
- **Local Storage**: All data stored locally in SQLite
- **No External Transmission**: Traffic data never leaves local system
- **Secure Deletion**: Proper cleanup of sensitive data
- **Access Control**: Database file permissions

### Legal Compliance
- **Authorized Testing Only**: Use only on owned/authorized systems
- **Data Retention**: Implement appropriate data retention policies
- **Privacy Protection**: Handle personal data appropriately
- **Audit Logging**: Maintain logs of proxy usage

## Performance Optimization

### Database Performance
```python
# Use connection pooling
db = ProxyDatabase()

# Batch operations
with sqlite3.connect(db.db_path) as conn:
    conn.executemany("INSERT INTO requests ...", batch_data)
```

### Memory Management
```python
# Limit response body storage
MAX_BODY_SIZE = 1024 * 1024  # 1MB
if len(response_body) > MAX_BODY_SIZE:
    response_body = response_body[:MAX_BODY_SIZE] + "... [truncated]"
```

### Network Performance
- **Connection Reuse**: mitmproxy handles connection pooling
- **Compression**: Automatic gzip/deflate handling
- **Keep-Alive**: HTTP/1.1 connection persistence
- **HTTP/2 Support**: Modern protocol support

## Troubleshooting

### Proxy Won't Start
1. Check if port is available: `netstat -an | findstr :8080`
2. Verify mitmproxy installation: `python -c "import mitmproxy"`
3. Check firewall settings
4. Try alternative port

### No Traffic Captured
1. Configure browser proxy settings (127.0.0.1:8080)
2. Install mitmproxy certificate for HTTPS
3. Check proxy enable status
4. Verify target application proxy settings

### Database Issues
1. Check file permissions on `resources/proxy.db`
2. Verify SQLite installation
3. Check disk space
4. Test database integrity: `sqlite3 proxy.db "PRAGMA integrity_check;"`

### Performance Issues
1. Limit history size: `proxy.get_history(limit=100)`
2. Clear old data: `db.clear_history()`
3. Monitor memory usage
4. Check database size and optimize

## Advanced Usage

### Custom Request Analysis
```python
class CustomAnalyzer:
    def __init__(self, proxy_engine):
        proxy_engine.response_received.connect(self.analyze_response)
    
    def analyze_response(self, http_response):
        # Custom security analysis
        if 'Set-Cookie' in http_response.headers:
            self.check_cookie_security(http_response.headers['Set-Cookie'])
        
        # Check for sensitive data exposure
        if self.contains_sensitive_data(http_response.body):
            self.log_security_issue(http_response)
```

### Automated Testing
```python
class AutomatedTester:
    def __init__(self, proxy_engine):
        self.proxy = proxy_engine
        self.proxy.request_intercepted.connect(self.modify_request)
    
    def modify_request(self, flow_id, http_request):
        # Inject SQL injection payloads
        if 'id=' in http_request.url:
            modified_url = http_request.url.replace('id=1', "id=1' OR '1'='1")
            # Modify and forward request
            self.proxy.forward_request(flow_id)
```

### Integration with Testing Frameworks
```python
# Selenium integration
from selenium import webdriver
from selenium.webdriver.common.proxy import Proxy, ProxyType

# Configure Selenium to use Huginn proxy
proxy = Proxy()
proxy.proxy_type = ProxyType.MANUAL
proxy.http_proxy = "127.0.0.1:8080"
proxy.ssl_proxy = "127.0.0.1:8080"

capabilities = webdriver.DesiredCapabilities.CHROME
proxy.add_to_capabilities(capabilities)

driver = webdriver.Chrome(desired_capabilities=capabilities)
```

## Future Enhancements

### Planned Features
- **WebSocket Interception**: Full WebSocket traffic analysis
- **GraphQL Support**: Specialized GraphQL query analysis
- **API Documentation**: Automatic API endpoint documentation
- **Machine Learning**: Anomaly detection in traffic patterns
- **Cloud Integration**: Remote proxy deployment options

### Advanced Analysis
- **Behavioral Analysis**: User interaction pattern analysis
- **Performance Monitoring**: Application performance metrics
- **Security Scanning**: Automated vulnerability detection
- **Compliance Checking**: OWASP/security standard validation

## Conclusion

The HTTP Interceptor & Proxy System provides enterprise-grade HTTP traffic analysis capabilities essential for modern web application security testing. With its comprehensive feature set, professional database storage, and seamless integration with the Huginn platform, it serves as a powerful foundation for security assessment workflows.

The system's architecture ensures scalability, performance, and reliability while maintaining the flexibility needed for diverse testing scenarios. Whether used for manual security testing, automated vulnerability assessment, or traffic analysis, the HTTP Interceptor provides the tools necessary for thorough web application security evaluation.