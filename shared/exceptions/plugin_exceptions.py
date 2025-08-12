"""Plugin-specific exceptions"""

class PluginException(Exception):
    """Base exception for plugin-related errors"""
    pass

class PluginLoadError(PluginException):
    """Raised when plugin fails to load"""
    pass

class PluginExecutionError(PluginException):
    """Raised when plugin execution fails"""
    pass

class PluginDependencyError(PluginException):
    """Raised when plugin dependencies are not met"""
    pass

class PluginConfigurationError(PluginException):
    """Raised when plugin configuration is invalid"""
    pass