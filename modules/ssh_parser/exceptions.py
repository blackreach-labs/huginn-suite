"""Custom exceptions for the SSH key parser module."""


class SSHParserError(Exception):
    """Base exception for SSH parser errors."""
    pass


class InvalidKeyError(SSHParserError):
    """Raised when the input is not a valid SSH key."""
    pass


class UnsupportedFormatError(SSHParserError):
    """Raised when the key format is recognized but not supported for parsing."""
    pass
