# Python Plugin System with WHOIS Lookup Functionality

A flexible Python plugin architecture that enables dynamic loading and execution of plugins, featuring a WHOIS lookup capability. This system allows developers to easily extend functionality through a standardized plugin interface while providing built-in network reconnaissance tools.

The system implements a plugin-based architecture where each plugin inherits from a common base class and can be dynamically loaded at runtime. The current implementation includes a WHOIS lookup plugin for domain reconnaissance and an example plugin that demonstrates the plugin development pattern. The architecture ensures consistent plugin behavior and error handling while maintaining extensibility.

## Repository Structure
```
plugins/                     # Main plugin directory containing all plugin implementations
├── __init__.py            # Python package marker for plugin directory
├── example_plugin.py      # Example implementation demonstrating plugin architecture
└── whois_plugin.py       # WHOIS lookup plugin for domain reconnaissance
```

## Usage Instructions
### Prerequisites
- Python 3.6 or higher
- Network connectivity for WHOIS lookups
- `nslookup` command-line tool installed on the system

### Installation
1. Clone the repository:
```bash
git clone <repository-url>
cd <repository-name>
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

### Quick Start
1. Import and initialize a plugin:
```python
from plugins.whois_plugin import WhoisPlugin

# Create plugin instance
whois_plugin = WhoisPlugin()

# Execute WHOIS lookup
result = whois_plugin.execute("example.com")
print(result)
```

### More Detailed Examples
1. Using the WHOIS Plugin:
```python
from plugins.whois_plugin import WhoisPlugin

whois_plugin = WhoisPlugin()
result = whois_plugin.execute("google.com")

if result["success"]:
    print(f"WHOIS lookup for {result['target']}:")
    print(result["result"])
else:
    print(f"Error: {result['result']}")
```

2. Creating a Custom Plugin:
```python
from app.core.plugin_manager import PluginBase

class CustomPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "Custom Plugin"
        self.version = "1.0.0"
        self.description = "Custom plugin implementation"
    
    def execute(self, target, **kwargs):
        return {
            "plugin": self.name,
            "target": target,
            "result": "Custom operation completed",
            "success": True
        }
```

### Troubleshooting
Common issues and solutions:

1. WHOIS Lookup Fails
- Problem: WHOIS lookup returns "Lookup failed"
- Diagnosis:
  * Verify network connectivity
  * Check if nslookup is installed: `which nslookup`
  * Ensure target domain is valid
- Solution:
```bash
# Install nslookup if missing
# For Debian/Ubuntu:
sudo apt-get install dnsutils
# For CentOS/RHEL:
sudo yum install bind-utils
```

2. Plugin Import Errors
- Problem: Unable to import plugins
- Diagnosis:
  * Check Python path includes plugin directory
  * Verify __init__.py exists in plugins directory
- Solution:
```python
import sys
sys.path.append('/path/to/plugin/directory')
```

## Data Flow
The plugin system processes requests through a standardized flow from plugin initialization to result delivery.

```ascii
[Client] -> [Plugin Manager] -> [Plugin Instance]
     |           |                    |
     |           |                    v
     |           |             [Execute Method]
     |           |                    |
     |           v                    v
     |     [Result Processing] <- [Raw Output]
     v
[Formatted Response]
```

Key component interactions:
1. Plugin Manager loads plugin classes from the plugins directory
2. Each plugin inherits from PluginBase ensuring consistent interface
3. Execute method processes the target parameter
4. Results are formatted as standardized dictionaries
5. Error handling occurs at both plugin and manager levels
6. Plugins operate independently but share common response structure
7. Timeout mechanisms prevent hanging operations