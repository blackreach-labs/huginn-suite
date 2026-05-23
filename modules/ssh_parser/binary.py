"""Binary data parsing utilities for SSH key structures."""

import struct
from typing import Tuple

from .exceptions import InvalidKeyError, SSHParserError

# Defensive limits for binary parsing
MAX_SSH_STRING = 65535  # 64 KB max for any single length-prefixed string
MAX_KDF_ROUNDS = 10_000_000  # Sanity cap on bcrypt rounds


class BinaryReader:
    """
    Reads binary SSH key data with position tracking and bounds checking.

    Designed for safe traversal of attacker-controlled input — all reads
    are bounds-checked and string lengths are capped.
    """

    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0

    @property
    def remaining(self) -> int:
        return len(self._data) - self._pos

    @property
    def position(self) -> int:
        return self._pos

    def read(self, n: int) -> bytes:
        """Read exactly n bytes from the buffer."""
        if n < 0:
            raise SSHParserError(f"Negative read length: {n}")
        if self._pos + n > len(self._data):
            raise InvalidKeyError(
                f"Unexpected end of data: wanted {n} bytes at offset {self._pos}, "
                f"only {self.remaining} available"
            )
        result = self._data[self._pos:self._pos + n]
        self._pos += n
        return result

    def read_uint32(self) -> int:
        """Read a big-endian 32-bit unsigned integer."""
        raw = self.read(4)
        return struct.unpack(">I", raw)[0]

    def read_string(self) -> bytes:
        """Read a length-prefixed string (uint32 length + data)."""
        length = self.read_uint32()
        if length > MAX_SSH_STRING:
            raise InvalidKeyError(
                f"String length {length} exceeds maximum allowed ({MAX_SSH_STRING})"
            )
        return self.read(length)

    def read_string_utf8(self) -> str:
        """Read a length-prefixed string and decode as UTF-8."""
        return self.read_string().decode("utf-8", errors="replace")

    def peek(self, n: int) -> bytes:
        """Peek at the next n bytes without advancing position."""
        end = min(self._pos + n, len(self._data))
        return self._data[self._pos:end]

    def skip(self, n: int) -> None:
        """Skip n bytes."""
        if self._pos + n > len(self._data):
            raise InvalidKeyError(
                f"Cannot skip {n} bytes, only {self.remaining} remaining"
            )
        self._pos += n


def decode_openssh_binary(data: bytes) -> Tuple[str, str, int, bytes, int]:
    """
    Parse the binary portion of an OpenSSH v1 private key (after magic header).

    Returns:
        (cipher_name, kdf_name, kdf_rounds, kdf_salt, num_keys)

    Raises:
        InvalidKeyError: On malformed binary structure.
    """
    reader = BinaryReader(data)

    cipher_name = reader.read_string_utf8()
    kdf_name = reader.read_string_utf8()

    # KDF options is itself a length-prefixed blob
    kdf_options_blob = reader.read_string()

    salt = b""
    rounds = 0

    if kdf_name == "bcrypt" and len(kdf_options_blob) > 0:
        kdf_reader = BinaryReader(kdf_options_blob)
        salt = kdf_reader.read_string()
        rounds = kdf_reader.read_uint32()

        if rounds > MAX_KDF_ROUNDS:
            raise InvalidKeyError(
                f"KDF rounds value {rounds} exceeds sanity limit ({MAX_KDF_ROUNDS})"
            )

    num_keys = reader.read_uint32()

    return cipher_name, kdf_name, rounds, salt, num_keys
