"""Data models for SSH key metadata."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class KeyFormat(Enum):
    """SSH key format types."""
    OPENSSH = "openssh"
    PEM_RSA = "pem_rsa"
    PEM_DSA = "pem_dsa"
    PEM_EC = "pem_ec"
    PKCS8 = "pkcs8"
    UNKNOWN = "unknown"


class KeyState(Enum):
    """Whether the key is encrypted or plaintext."""
    ENCRYPTED = "encrypted"
    UNENCRYPTED = "unencrypted"
    UNKNOWN = "unknown"


@dataclass
class SSHKeyInfo:
    """Normalized structure containing parsed SSH key metadata."""

    format: KeyFormat = KeyFormat.UNKNOWN
    state: KeyState = KeyState.UNKNOWN
    cipher: Optional[str] = None
    kdf: Optional[str] = None
    salt: Optional[bytes] = None
    rounds: Optional[int] = None
    iv: Optional[bytes] = None
    key_type: Optional[str] = None
    comment: Optional[str] = None
    hash_line: Optional[str] = None
    errors: list = field(default_factory=list)

    @property
    def is_encrypted(self) -> bool:
        return self.state == KeyState.ENCRYPTED

    @property
    def salt_hex(self) -> Optional[str]:
        return self.salt.hex() if self.salt else None

    @property
    def iv_hex(self) -> Optional[str]:
        return self.iv.hex() if self.iv else None

    def to_dict(self) -> dict:
        """Serialize key info to a dictionary."""
        return {
            "format": self.format.value,
            "state": self.state.value,
            "cipher": self.cipher,
            "kdf": self.kdf,
            "salt": self.salt_hex,
            "rounds": self.rounds,
            "iv": self.iv_hex,
            "key_type": self.key_type,
            "comment": self.comment,
            "hash_line": self.hash_line,
            "is_encrypted": self.is_encrypted,
            "errors": self.errors,
        }
