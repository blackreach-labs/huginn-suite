"""Custom exceptions for the Huginn scanner framework."""


class HuginnException(Exception):
    """Base exception for Huginn framework."""
    pass


class ScannerException(HuginnException):
    """Base exception for scanner operations."""
    pass


class ConfigurationException(HuginnException):
    """Exception for configuration-related errors."""
    pass


class DatabaseException(HuginnException):
    """Exception for database-related errors."""
    pass


class NetworkException(ScannerException):
    """Exception for network-related errors."""
    pass


class AuthenticationException(ScannerException):
    """Exception for authentication-related errors."""
    pass


class ValidationException(HuginnException):
    """Exception for validation errors."""
    pass


class ScannerConfigError(ScannerException):
    """Exception for scanner configuration errors."""
    pass


class ScannerTimeoutError(ScannerException):
    """Exception for scanner timeout errors."""
    pass