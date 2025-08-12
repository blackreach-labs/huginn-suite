"""Custom exceptions for the Huggin scanner framework."""


class HugginException(Exception):
    """Base exception for Huggin framework."""
    pass


class ScannerException(HugginException):
    """Base exception for scanner operations."""
    pass


class ConfigurationException(HugginException):
    """Exception for configuration-related errors."""
    pass


class DatabaseException(HugginException):
    """Exception for database-related errors."""
    pass


class NetworkException(ScannerException):
    """Exception for network-related errors."""
    pass


class AuthenticationException(ScannerException):
    """Exception for authentication-related errors."""
    pass


class ValidationException(HugginException):
    """Exception for validation errors."""
    pass


class ScannerConfigError(ScannerException):
    """Exception for scanner configuration errors."""
    pass


class ScannerTimeoutError(ScannerException):
    """Exception for scanner timeout errors."""
    pass