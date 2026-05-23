# SSH Key Parser Module

A Python module for identifying and parsing encrypted SSH private keys, extracting key metadata for security assessment workflows. Designed as a component of the Huginn penetration testing suite.

## Purpose

This module provides `ssh2john`-style functionality for:

- **Password auditing workflows** — extract hashes/parameters needed for offline cracking
- **Key inventory analysis** — catalog SSH keys across an environment and flag weak configurations
- **SSH exposure assessment** — identify unencrypted keys or keys using deprecated ciphers
- **Credential recovery labs** — parse key metadata for structured brute-force operations
- **Forensic workflows** — non-destructive key inspection without modifying source material

## Supported Formats

| Format | Detection | Metadata Extracted |
|--------|-----------|-------------------|
| OpenSSH v1 (`openssh-key-v1`) | `-----BEGIN OPENSSH PRIVATE KEY-----` | cipher, KDF (bcrypt), salt, rounds, key type |
| PEM RSA | `-----BEGIN RSA PRIVATE KEY-----` | cipher, IV, key type |
| PEM DSA | `-----BEGIN DSA PRIVATE KEY-----` | cipher, IV, key type |
| PEM EC | `-----BEGIN EC PRIVATE KEY-----` | cipher, IV, key type |
| PKCS#8 Encrypted | `-----BEGIN ENCRYPTED PRIVATE KEY-----` | wrapper detection |

## Installation

No external dependencies. The module uses only the Python standard library (`base64`, `struct`, `re`, `dataclasses`, `pathlib`, `argparse`, `json`).

Requires Python 3.7+.

## Usage

### As a Library

```python
from modules.ssh_parser import SSHKeyParser, KeyFormat, KeyState

parser = SSHKeyParser()

# Parse from file
info = parser.parse_file("/home/user/.ssh/id_rsa")

# Parse from string
info = parser.parse_string(key_data)

# Parse from bytes
info = parser.parse_bytes(raw_bytes)

# Quick format identification (no full parse)
fmt = parser.identify_format(key_data)
```

### Inspecting Results

```python
info = parser.parse_file("/path/to/id_ed25519")

print(info.format)        # KeyFormat.OPENSSH
print(info.state)         # KeyState.ENCRYPTED
print(info.is_encrypted)  # True
print(info.cipher)        # "aes256-ctr"
print(info.kdf)           # "bcrypt"
print(info.rounds)        # 16
print(info.salt_hex)      # "abababab..."
print(info.key_type)      # "ssh-ed25519"

# Serialize to dict for JSON output or downstream processing
print(info.to_dict())
```

### CLI

```bash
# Human-readable output
python -m modules.ssh_parser.cli /path/to/id_rsa

# JSON output (single file)
python -m modules.ssh_parser.cli --json /path/to/id_rsa

# Multiple files
python -m modules.ssh_parser.cli --json ~/.ssh/id_rsa ~/.ssh/id_ed25519
```

**Example CLI output:**

```
============================================================
  File:       /home/user/.ssh/id_ed25519
  Format:     openssh
  State:      encrypted
  Key Type:   ssh-ed25519
  Cipher:     aes256-ctr
  KDF:        bcrypt
  Salt:       abcdef0123456789abcdef0123456789
  Rounds:     16
============================================================
```

**Example JSON output:**

```json
{
  "file": "/home/user/.ssh/id_ed25519",
  "format": "openssh",
  "state": "encrypted",
  "cipher": "aes256-ctr",
  "kdf": "bcrypt",
  "salt": "abcdef0123456789abcdef0123456789",
  "rounds": 16,
  "iv": null,
  "key_type": "ssh-ed25519",
  "comment": "id_ed25519",
  "is_encrypted": true,
  "errors": []
}
```

## Module Structure

```
modules/ssh_parser/
├── __init__.py        Public API exports
├── parser.py          SSHKeyParser class — format detection and dispatch
├── openssh.py         OpenSSH v1 binary format parser
├── pem.py             Legacy PEM format parser (Proc-Type/DEK-Info)
├── binary.py          BinaryReader utility + OpenSSH structure decoder
├── models.py          SSHKeyInfo dataclass, KeyFormat/KeyState enums
├── exceptions.py      Custom exception hierarchy
└── cli.py             Command-line interface
```

## Architecture

### Parse Flow

```
Input (file/string/bytes)
    │
    ▼
SSHKeyParser.parse_*()
    │
    ├─ is_openssh_key()? ──► parse_openssh_key()
    │                              │
    │                              ├─ base64 decode
    │                              ├─ verify magic header
    │                              └─ BinaryReader → cipher, kdf, salt, rounds
    │
    └─ is_pem_key()? ─────► parse_pem_key()
                                   │
                                   ├─ identify key type (RSA/DSA/EC/PKCS#8)
                                   ├─ check Proc-Type header
                                   └─ parse DEK-Info → cipher, IV
    │
    ▼
SSHKeyInfo (normalized output)
```

### Data Model

**`SSHKeyInfo`** — the normalized output structure:

| Field | Type | Description |
|-------|------|-------------|
| `format` | `KeyFormat` | Detected key format enum |
| `state` | `KeyState` | `ENCRYPTED`, `UNENCRYPTED`, or `UNKNOWN` |
| `cipher` | `str \| None` | Encryption cipher (e.g., `aes256-ctr`, `AES-128-CBC`) |
| `kdf` | `str \| None` | Key derivation function (`bcrypt`, `md5`, `pkcs8`) |
| `salt` | `bytes \| None` | KDF salt (raw bytes) |
| `rounds` | `int \| None` | KDF iteration count |
| `iv` | `bytes \| None` | Initialization vector (PEM keys) |
| `key_type` | `str \| None` | SSH key algorithm (`ssh-rsa`, `ssh-ed25519`, etc.) |
| `comment` | `str \| None` | Key comment or filename stem |
| `errors` | `list[str]` | Non-fatal warnings encountered during parsing |

**Properties:**
- `is_encrypted` — boolean shorthand for `state == ENCRYPTED`
- `salt_hex` — hex-encoded salt string
- `iv_hex` — hex-encoded IV string
- `to_dict()` — serialize to a plain dictionary

### Exceptions

| Exception | When |
|-----------|------|
| `SSHParserError` | Base class; file I/O errors, size limits |
| `InvalidKeyError` | Input is not a recognizable SSH key |
| `UnsupportedFormatError` | Format recognized but not yet supported |

## Integration with Huginn

The module is designed to slot into the broader suite's workflows:

```python
# Example: scan a directory for encrypted keys
from pathlib import Path
from modules.ssh_parser import SSHKeyParser

parser = SSHKeyParser()
ssh_dir = Path("/target/.ssh")

for key_file in ssh_dir.glob("id_*"):
    if key_file.suffix == ".pub":
        continue
    try:
        info = parser.parse_file(key_file)
        if info.is_encrypted:
            print(f"[*] {key_file.name}: {info.cipher} / {info.kdf} / {info.rounds} rounds")
        else:
            print(f"[!] {key_file.name}: UNENCRYPTED — high risk")
    except Exception as e:
        print(f"[-] {key_file.name}: {e}")
```

## Technical Notes

- **No external dependencies** — pure stdlib implementation for portability
- **Non-destructive** — read-only operations, never modifies key files
- **Defensive parsing** — sanity limits on string lengths and file sizes prevent memory exhaustion on malformed input
- **OpenSSH binary format** — uses a `BinaryReader` class with position tracking and bounds checking for safe traversal of the packed binary structure
- **Legacy PEM KDF** — legacy PEM keys use MD5-based key derivation (EVP_BytesToKey), noted in the `kdf` field as `"md5"`
