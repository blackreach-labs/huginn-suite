"""Main SSH key parser - detects format and delegates to specialized parsers."""

from pathlib import Path
from typing import Union

from .models import SSHKeyInfo, KeyFormat, KeyState
from .openssh import is_openssh_key, parse_openssh_key
from .pem import is_pem_key, parse_pem_key
from .exceptions import SSHParserError, InvalidKeyError

# Defensive limits for processing attacker-controlled input
MAX_FILE_SIZE = 10 * 1024 * 1024   # 10 MB
MAX_KEY_STRING = 1 * 1024 * 1024   # 1 MB text input


class SSHKeyParser:
    """
    Unified SSH private key parser.

    Detects the key format (OpenSSH v1 or legacy PEM) and extracts
    encryption metadata for security assessment workflows.

    Usage:
        parser = SSHKeyParser()
        info = parser.parse_file("/path/to/id_rsa")
        print(info.to_dict())
    """

    def parse_file(self, filepath: Union[str, Path]) -> SSHKeyInfo:
        """
        Parse an SSH private key from a file path.

        Args:
            filepath: Path to the SSH private key file.

        Returns:
            SSHKeyInfo with parsed metadata.

        Raises:
            SSHParserError: If the file cannot be read or exceeds size limits.
            InvalidKeyError: If the file does not contain a valid SSH key.
        """
        filepath = Path(filepath)

        if not filepath.exists():
            raise SSHParserError(f"File not found: {filepath}")

        if not filepath.is_file():
            raise SSHParserError(f"Not a file: {filepath}")

        # Defensive size check
        size = filepath.stat().st_size
        if size > MAX_FILE_SIZE:
            raise SSHParserError(
                f"File too large ({size} bytes, limit {MAX_FILE_SIZE}). "
                "Refusing to parse — unlikely to be an SSH key."
            )

        if size == 0:
            raise InvalidKeyError("File is empty")

        try:
            data = filepath.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            raise SSHParserError(f"Cannot read file: {e}")

        info = self.parse_string(data)
        info.comment = info.comment or filepath.stem
        return info

    def parse_string(self, data: str) -> SSHKeyInfo:
        """
        Parse an SSH private key from a string.

        Args:
            data: The full text content of the key.

        Returns:
            SSHKeyInfo with parsed metadata.

        Raises:
            InvalidKeyError: If the data does not contain a valid SSH key.
            SSHParserError: If the input exceeds size limits.
        """
        if not data or not data.strip():
            raise InvalidKeyError("Empty key data")

        if len(data) > MAX_KEY_STRING:
            raise SSHParserError(
                f"Input too large ({len(data)} chars, limit {MAX_KEY_STRING}). "
                "Refusing to parse."
            )

        # Detect format and delegate
        fmt = self.identify_format(data)

        match fmt:
            case KeyFormat.OPENSSH:
                return parse_openssh_key(data)
            case KeyFormat.PEM_RSA | KeyFormat.PEM_DSA | KeyFormat.PEM_EC | KeyFormat.PKCS8:
                return parse_pem_key(data)
            case _:
                raise InvalidKeyError(
                    "Unrecognized key format. Expected OpenSSH v1 or PEM private key."
                )

    def parse_bytes(self, data: bytes) -> SSHKeyInfo:
        """
        Parse an SSH private key from raw bytes.

        Args:
            data: Raw bytes of the key file.

        Returns:
            SSHKeyInfo with parsed metadata.
        """
        if len(data) > MAX_FILE_SIZE:
            raise SSHParserError(
                f"Input too large ({len(data)} bytes, limit {MAX_FILE_SIZE})."
            )

        try:
            text = data.decode("utf-8", errors="replace")
        except Exception as e:
            raise InvalidKeyError(f"Cannot decode key data: {e}")

        return self.parse_string(text)

    def identify_format(self, data: str) -> KeyFormat:
        """
        Quickly identify the key format without full parsing.

        Args:
            data: The full text content of the key.

        Returns:
            KeyFormat enum value.
        """
        if is_openssh_key(data):
            return KeyFormat.OPENSSH
        elif is_pem_key(data):
            if "RSA PRIVATE KEY" in data:
                return KeyFormat.PEM_RSA
            elif "DSA PRIVATE KEY" in data:
                return KeyFormat.PEM_DSA
            elif "EC PRIVATE KEY" in data:
                return KeyFormat.PEM_EC
            elif "ENCRYPTED PRIVATE KEY" in data:
                return KeyFormat.PKCS8
            else:
                return KeyFormat.UNKNOWN
        return KeyFormat.UNKNOWN
