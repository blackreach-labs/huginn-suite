# Plugin Development Guide

## Overview

Huginn's plugin architecture allows developers to extend functionality with custom tools and scripts.

## Plugin Structure

### Base Plugin Class

```python
from app.core.plugin_manager import PluginBase

class MyPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "Plugin Name"
        self.version = "1.0.0"
        self.description = "Plugin description"
    
    def execute(self, target, **kwargs):
        """Execute plugin functionality."""
        return {
            "plugin": self.name,
            "target": target,
            "result": "Execution result",
            "data": ["result1", "result2"]
        }
```

## Plugin Requirements

### Required Methods
- `__init__()`: Initialize plugin metadata
- `execute(target, **kwargs)`: Main plugin functionality

### Required Attributes
- `name`: Plugin display name
- `version`: Plugin version string
- `description`: Brief description

### Return Format
```python
{
    "plugin": "Plugin Name",
    "target": "target.com",
    "result": "Human readable result",
    "data": ["structured", "data"],
    "success": True,  # Optional
    "error": "Error message"  # If error occurred
}
```

## Plugin Examples

### Simple Information Plugin
```python
class InfoPlugin(PluginBase):
    def execute(self, target, **kwargs):
        return {
            "plugin": self.name,
            "target": target,
            "result": f"Information gathered for {target}",
            "data": {"ip": "1.2.3.4", "status": "active"}
        }
```

### Command Execution Plugin
```python
import subprocess

class CommandPlugin(PluginBase):
    def execute(self, target, **kwargs):
        try:
            result = subprocess.run(['ping', '-c', '1', target], 
                                  capture_output=True, text=True)
            return {
                "plugin": self.name,
                "target": target,
                "result": "Ping successful" if result.returncode == 0 else "Ping failed",
                "success": result.returncode == 0
            }
        except Exception as e:
            return {"error": str(e)}
```

## Installation

1. Create plugin file in `plugins/` directory
2. Follow naming convention: `*_plugin.py`
3. Plugin will be automatically loaded on application start
4. Access via Plugin Manager in the UI

## Best Practices

- Handle exceptions gracefully
- Return meaningful error messages
- Use timeouts for network operations
- Validate input parameters
- Follow consistent return format