"""Parser for OpenSSH v1 format private keys (openssh-key-v1)."""

import base64
import binascii
import struct
from typing import Optional

from .binary import decode_openssh_binary
from .models import SSHKeyInfo, KeyFormat, KeyState
from .exceptions import InvalidKeyError

# Magic bytes that identify the OpenSSH v1 format
OPENSSH_MAGIC = b"openssh-key-v1\x00"
OPENSSH_BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----"
OPENSSH_END = "-----END OPENSSH PRIVATE KEY-----"

# sshng cipher type codes (matches hashcat/john expectations)
_SSHNG_TYPE_AES256_CBC_BCRYPT = 2
_SSHNG_TYPE_AES256_CTR_BCRYPT = 6


def is_openssh_key(data: str) -> bool:
    """Check if the key data is in OpenSSH v1 format."""
    return OPENSSH_BEGIN in data


def parse_openssh_key(data: str) -> SSHKeyInfo:
    """
    Parse an OpenSSH v1 private key and extract metadata + crackable hash.

    Args:
        data: The full text content of the key file.

    Returns:
        SSHKeyInfo with cipher, kdf, salt, rounds, hash_line populated.
    """
    info = SSHKeyInfo(format=KeyFormat.OPENSSH)

    try:
        # Extract the base64 body between the markers
        body = _extract_body(data)
        raw = base64.b64decode(body)

        # Verify magic header
        if not raw.startswith(OPENSSH_MAGIC):
            raise InvalidKeyError("Missing openssh-key-v1 magic header")

        # Strip magic and parse binary structure
        binary_data = raw[len(OPENSSH_MAGIC):]
        cipher_name, kdf_name, rounds, salt, num_keys = decode_openssh_binary(binary_data)

        info.cipher = cipher_name
        info.kdf = kdf_name
        info.rounds = rounds if rounds > 0 else None
        info.salt = salt if salt else None

        # Determine encryption state
        if cipher_name == "none":
            info.state = KeyState.UNENCRYPTED
        else:
            info.state = KeyState.ENCRYPTED
            # Generate the $sshng$ hash line
            info.hash_line = _build_hash_line(raw, cipher_name, salt, rounds)

        # Try to extract key type from public key section
        header_size = _skip_header_size(cipher_name, kdf_name, salt, rounds)
        info.key_type = _extract_key_type(raw, len(OPENSSH_MAGIC) + header_size)

    except InvalidKeyError:
        raise
    except Exception as e:
        info.errors.append(f"OpenSSH parse error: {str(e)}")
        info.state = KeyState.UNKNOWN

    return info


def _build_hash_line(raw: bytes, cipher_name: str, salt: bytes, rounds: int) -> Optional[str]:
    """
    Build the $sshng$ hash line compatible with hashcat/john.

    Format: $sshng$<type>$<salt_len>$<salt_hex>$<data_len>$<data_hex>$<rounds>$<ciphertext_offset>
    """
    try:
        # Determine sshng type code based on cipher
        if cipher_name == "aes256-cbc":
            sshng_type = _SSHNG_TYPE_AES256_CBC_BCRYPT
        elif cipher_name == "aes256-ctr":
            sshng_type = _SSHNG_TYPE_AES256_CTR_BCRYPT
        else:
            return None  # Unsupported cipher for hash extraction

        salt_hex = binascii.hexlify(salt).decode("ascii")
        salt_len = len(salt)

        # Calculate ciphertext begin offset by walking the binary structure
        ciphertext_offset = _find_ciphertext_offset(raw)

        # Full key data as hex
        data_hex = binascii.hexlify(raw).decode("ascii")
        data_len = len(raw)

        return (
            f"$sshng${sshng_type}${salt_len}${salt_hex}"
            f"${data_len}${data_hex}${rounds}${ciphertext_offset}"
        )

    except Exception:
        return None


def _find_ciphertext_offset(raw: bytes) -> int:
    """
    Walk the OpenSSH v1 binary structure to find where the encrypted
    private key blob begins.
    """
    offset = len(OPENSSH_MAGIC)

    # cipher name (length-prefixed string)
    length = struct.unpack(">I", raw[offset:offset + 4])[0]
    offset += 4 + length

    # kdf name (length-prefixed string)
    length = struct.unpack(">I", raw[offset:offset + 4])[0]
    offset += 4 + length

    # kdf options blob (length-prefixed string)
    length = struct.unpack(">I", raw[offset:offset + 4])[0]
    offset += 4 + length

    # number of keys (uint32)
    offset += 4

    # public key blob (length-prefixed string)
    length = struct.unpack(">I", raw[offset:offset + 4])[0]
    offset += 4 + length

    # private key blob length (uint32) — skip the length field itself
    offset += 4

    return offset


def _extract_body(data: str) -> str:
    """Extract the base64-encoded body from PEM-style markers."""
    lines = data.strip().splitlines()
    body_lines = []
    in_body = False

    for line in lines:
        stripped = line.strip()
        if stripped == OPENSSH_BEGIN:
            in_body = True
            continue
        if stripped == OPENSSH_END:
            break
        if in_body:
            body_lines.append(stripped)

    if not body_lines:
        raise InvalidKeyError("No key data found between OpenSSH markers")

    return "".join(body_lines)


def _skip_header_size(cipher: str, kdf: str, salt: bytes, rounds: int) -> int:
    """Calculate approximate byte offset past the header fields for key type extraction."""
    # 4 bytes length + cipher string
    size = 4 + len(cipher.encode())
    # 4 bytes length + kdf string
    size += 4 + len(kdf.encode())
    # 4 bytes kdf options length + kdf options content
    if kdf == "bcrypt" and salt:
        kdf_opts_size = 4 + len(salt) + 4  # string(salt) + uint32(rounds)
        size += 4 + kdf_opts_size
    else:
        size += 4  # empty kdf options
    # 4 bytes num_keys
    size += 4
    return size


def _extract_key_type(raw: bytes, offset: int) -> Optional[str]:
    """Try to extract the key type from the public key section."""
    try:
        if offset + 4 > len(raw):
            return None
        pub_len = struct.unpack(">I", raw[offset:offset + 4])[0]
        if pub_len > 0x10000 or offset + 4 + pub_len > len(raw):
            return None
        pub_blob = raw[offset + 4:offset + 4 + pub_len]
        if len(pub_blob) < 4:
            return None
        type_len = struct.unpack(">I", pub_blob[0:4])[0]
        if type_len > 64 or 4 + type_len > len(pub_blob):
            return None
        return pub_blob[4:4 + type_len].decode("utf-8", errors="replace")
    except Exception:
        return None
