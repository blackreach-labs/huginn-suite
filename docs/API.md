# Huggin API Documentation

## Core Components

### InputValidator
```python
from app.core.validators import InputValidator

validator = InputValidator()
validator.validate_ip("192.168.1.1")      # Returns True
validator.validate_domain("example.com")   # Returns True
```

### CacheManager
```python
from app.core.cache_manager import cache_manager

# Store results
cache_manager.set("dns", "example.com", {"A": ["1.2.3.4"]})

# Retrieve results
results = cache_manager.get("dns", "example.com")

# Clear cache
cache_manager.clear()
```

### AdvancedThemeManager
```python
from app.core.advanced_theme_manager import AdvancedThemeManager

theme_manager = AdvancedThemeManager(project_root)
theme_manager.apply_theme("cyberpunk")
themes = theme_manager.get_available_themes()
```

### ContextMenuManager
```python
from app.core.context_menu_manager import ContextMenuManager

context_manager = ContextMenuManager()
menu = context_manager.create_terminal_menu(widget, selected_text)
```

## Enumeration Tools

### DNS Enumeration
```python
import custom_scripts

custom_scripts.enumerate_hostnames(
    target="example.com",
    wordlist_path="wordlist.txt",
    record_types=["A", "CNAME"],
    output_callback=print_output,
    finished_callback=on_complete
)
```

## Export System

### Basic Export
```python
from app.core.exporter import exporter

success, filepath, message = exporter.export_results(
    results, target, "json"
)
```

## Database Operations

### Scan Database
```python
from app.core.scan_database import scan_db

# Save scan
scan_id = scan_db.save_scan(target, scan_type, results)

# Retrieve scan
scan = scan_db.get_scan(scan_id)
```

## HTTP Interceptor & Proxy

### ProxyEngine
```python
from app.core.proxy_engine import ProxyEngine

proxy = ProxyEngine()

# Start proxy on port 8080
proxy.start_proxy(8080)

# Enable request interception
proxy.enable_intercept(True)

# Get request history
history = proxy.get_history(limit=100)

# Stop proxy
proxy.stop_proxy()
```

### ProxyDatabase
```python
from app.core.proxy_database import ProxyDatabase

# Database automatically stored in resources/proxy.db
db = ProxyDatabase()

# Get request statistics
stats = db.get_stats()

# Clear history
db.clear_history()
```

### HTTP Client
```python
from app.core.http_client import HttpRequest, HttpResponse

# Create HTTP request
request = HttpRequest(
    method="POST",
    url="https://api.example.com/login",
    headers={"Content-Type": "application/json"},
    data='{"username": "test"}'
)

# Convert from mitmproxy flow
http_request = HttpRequest.from_mitmproxy_flow(flow)
```