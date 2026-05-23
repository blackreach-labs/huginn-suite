"""Parser for legacy PEM-format SSH private keys (RSA, DSA, EC, PKCS#8)."""

import base64
import binascii
import re
from typing import Optional, Tuple

from .models import SSHKeyInfo, KeyFormat, KeyState
from .exceptions import InvalidKeyError

# PEM header patterns
PEM_HEADER_RE = re.compile(
    r"-----BEGIN (RSA|DSA|EC|ENCRYPTED)?\s*PRIVATE KEY-----"
)
PEM_END_RE = re.compile(
    r"-----END (RSA|DSA|EC|ENCRYPTED)?\s*PRIVATE KEY-----"
)
PEM_ENCRYPTED_HEADER = "Proc-Type: 4,ENCRYPTED"
PEM_DEK_INFO_RE = re.compile(
    r"DEK-Info:\s*([A-Za-z0-9-]+)\s*,\s*([0-9A-Fa-f]+)",
    re.IGNORECASE,
)

# Map PEM header type to KeyFormat
_FORMAT_MAP = {
    "RSA": KeyFormat.PEM_RSA,
    "DSA": KeyFormat.PEM_DSA,
    "EC": KeyFormat.PEM_EC,
    "ENCRYPTED": KeyFormat.PKCS8,
    None: KeyFormat.UNKNOWN,
}

# sshng cipher type codes for legacy PEM keys
_SSHNG_CIPHER_CODES = {
    # (cipher, ktype) -> sshng_type
    ("DES-EDE3-CBC", "RSA"): 0,
    ("DES-EDE3-CBC", "DSA"): 0,
    ("AES-128-CBC", "RSA"): 1,
    ("AES-128-CBC", "DSA"): 1,
    ("AES-128-CBC", "EC"): 3,
    ("AES-192-CBC", "RSA"): 4,
    ("AES-192-CBC", "DSA"): 4,
    ("AES-256-CBC", "RSA"): 5,
    ("AES-256-CBC", "DSA"): 5,
    ("AES-256-CBC", "EC"): 5,
    ("DES-CBC", "RSA"): 6,
    ("DES-CBC", "DSA"): 6,
}


def is_pem_key(data: str) -> bool:
    """Check if the key data is in legacy PEM format."""
    return bool(PEM_HEADER_RE.search(data))


def parse_pem_key(data: str) -> SSHKeyInfo:
    """
    Parse a legacy PEM private key and extract encryption metadata + hash.

    Handles:
        - RSA PRIVATE KEY
        - DSA PRIVATE KEY
        - EC PRIVATE KEY
        - ENCRYPTED PRIVATE KEY (PKCS#8)

    Args:
        data: The full text content of the key file.

    Returns:
        SSHKeyInfo with cipher, iv, format, and hash_line populated.
    """
    info = SSHKeyInfo()

    try:
        # Identify key type from header
        header_match = PEM_HEADER_RE.search(data)
        if not header_match:
            raise InvalidKeyError("No PEM private key header found")

        key_type_str = header_match.group(1)
        info.format = _FORMAT_MAP.get(key_type_str, KeyFormat.UNKNOWN)

        # Check for PKCS#8 encrypted wrapper
        if key_type_str == "ENCRYPTED":
            info.state = KeyState.ENCRYPTED
            info.cipher = "pkcs8-wrapped"
            info.kdf = "pkcs8"
            return info

        # Check for Proc-Type / DEK-Info encryption headers
        cipher, iv = _parse_dek_info(data)

        if cipher:
            info.state = KeyState.ENCRYPTED
            info.cipher = cipher
            info.iv = iv
            info.kdf = "md5"  # Legacy PEM uses MD5-based key derivation (EVP_BytesToKey)

            # Build hash line for legacy PEM keys
            info.hash_line = _build_pem_hash_line(data, cipher, iv, key_type_str)
        else:
            info.state = KeyState.UNENCRYPTED

        # Set key_type based on format
        if info.format == KeyFormat.PEM_RSA:
            info.key_type = "ssh-rsa"
        elif info.format == KeyFormat.PEM_DSA:
            info.key_type = "ssh-dss"
        elif info.format == KeyFormat.PEM_EC:
            info.key_type = "ecdsa"

    except InvalidKeyError:
        raise
    except Exception as e:
        info.errors.append(f"PEM parse error: {str(e)}")
        info.state = KeyState.UNKNOWN

    return info


def _build_pem_hash_line(data: str, cipher: str, iv: Optional[bytes], key_type_str: str) -> Optional[str]:
    """
    Build the $sshng$ hash line for legacy PEM keys.

    Format: $sshng$<type>$<salt_len>$<salt_hex>$<data_len>$<data_hex>
    """
    try:
        if not iv:
            return None

        # Determine sshng type code
        lookup_key = (cipher, key_type_str)
        sshng_type = _SSHNG_CIPHER_CODES.get(lookup_key)
        if sshng_type is None:
            return None

        # Extract the base64 body (skip headers)
        key_data = _extract_pem_body(data)
        if not key_data:
            return None

        salt_hex = binascii.hexlify(iv).decode("ascii")
        salt_len = len(iv)
        data_hex = binascii.hexlify(key_data).decode("ascii")
        data_len = len(key_data)

        return f"$sshng${sshng_type}${salt_len}${salt_hex}${data_len}${data_hex}"

    except Exception:
        return None


def _extract_pem_body(data: str) -> Optional[bytes]:
    """Extract and decode the base64 body from a PEM key, skipping headers."""
    lines = data.strip().splitlines()
    body_lines = []
    in_body = False
    past_headers = False

    for line in lines:
        stripped = line.strip()
        if PEM_HEADER_RE.match(stripped):
            in_body = True
            past_headers = False
            continue
        if PEM_END_RE.match(stripped):
            break
        if in_body:
            # Skip Proc-Type / DEK-Info headers and blank line after them
            if not past_headers:
                if ":" in stripped:
                    continue
                if stripped == "":
                    past_headers = True
                    continue
                past_headers = True
            body_lines.append(stripped)

    if not body_lines:
        return None

    try:
        return base64.b64decode("".join(body_lines))
    except Exception:
        return None


def _parse_dek_info(data: str) -> Tuple[Optional[str], Optional[bytes]]:
    """
    Extract cipher and IV from DEK-Info header.

    Returns:
        (cipher_name, iv_bytes) or (None, None) if not encrypted.
    """
    if PEM_ENCRYPTED_HEADER not in data:
        return None, None

    dek_match = PEM_DEK_INFO_RE.search(data)
    if not dek_match:
        # Has Proc-Type but no DEK-Info — malformed but still encrypted
        return "unknown", None

    cipher_name = dek_match.group(1).upper()
    iv_hex = dek_match.group(2)

    try:
        iv_bytes = bytes.fromhex(iv_hex)
    except ValueError:
        iv_bytes = None

    return cipher_name, iv_bytes
