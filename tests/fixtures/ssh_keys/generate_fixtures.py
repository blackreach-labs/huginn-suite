"""
Generate test fixture SSH keys for the ssh_parser module tests.

Run this script once to create the fixture files. Requires no external dependencies
beyond the standard library — builds synthetic key blobs directly.
"""

import base64
import struct
import os
from pathlib import Path

FIXTURE_DIR = Path(__file__).parent


def pack_string(s):
    """Pack a length-prefixed string (OpenSSH binary format)."""
    if isinstance(s, str):
        s = s.encode()
    return struct.pack(">I", len(s)) + s


def build_openssh_key(cipher="aes256-ctr", kdf="bcrypt", rounds=16, salt=None, key_type="ssh-ed25519"):
    """Build a synthetic OpenSSH v1 key blob."""
    if salt is None:
        salt = os.urandom(16)

    magic = b"openssh-key-v1\x00"

    body = pack_string(cipher)
    body += pack_string(kdf)

    # KDF options
    if kdf == "bcrypt":
        kdf_opts = pack_string(salt) + struct.pack(">I", rounds)
    else:
        kdf_opts = b""
    body += pack_string(kdf_opts)

    # num_keys = 1
    body += struct.pack(">I", 1)

    # Fake public key blob
    pub_key = pack_string(key_type) + pack_string(os.urandom(32))
    body += pack_string(pub_key)

    # Fake encrypted private key blob
    body += pack_string(os.urandom(128))

    raw = magic + body
    b64 = base64.b64encode(raw).decode()
    lines = [b64[i:i+70] for i in range(0, len(b64), 70)]

    return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "\n".join(lines) + "\n-----END OPENSSH PRIVATE KEY-----\n"


def main():
    # 1. Encrypted OpenSSH ed25519 key (bcrypt KDF)
    content = build_openssh_key(
        cipher="aes256-ctr",
        kdf="bcrypt",
        rounds=16,
        salt=bytes.fromhex("abcdef0123456789abcdef0123456789"),
        key_type="ssh-ed25519",
    )
    (FIXTURE_DIR / "encrypted_ed25519").write_text(content)
    print("[+] encrypted_ed25519")

    # 2. Unencrypted OpenSSH RSA key
    content = build_openssh_key(
        cipher="none",
        kdf="none",
        rounds=0,
        salt=b"",
        key_type="ssh-rsa",
    )
    (FIXTURE_DIR / "unencrypted_id_rsa").write_text(content)
    print("[+] unencrypted_id_rsa")

    # 3. Encrypted PEM RSA key
    content = """-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,D5B6F6F4C3E2A1B0C9D8E7F6A5B4C3D2

MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB
aFDrBz9vFqU7X0hDCjSEFRI3E5Mn1TgGEEhP+HZv0aBfY3NjYlKA7MhRkP1Cjd3
vQ0KXPFAX8rkMODqVHPMNALI6MBFz8kDwUJdEkPOSaOx5MmGvYbElNBKRmBEMnSq
RvBYFokaJEqGRQ4wLKddMFOZBwXkNqf7HKBE+GHmPH4JFMlBnKYBPnEO3KJqHCDV
-----END RSA PRIVATE KEY-----
"""
    (FIXTURE_DIR / "encrypted_id_rsa").write_text(content)
    print("[+] encrypted_id_rsa")

    # 4. Unencrypted PEM RSA key
    content = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB
aFDrBz9vFqU7X0hDCjSEFRI3E5Mn1TgGEEhP+HZv0aBfY3NjYlKA7MhRkP1Cjd3
vQ0KXPFAX8rkMODqVHPMNALI6MBFz8kDwUJdEkPOSaOx5MmGvYbElNBKRmBEMnSq
RvBYFokaJEqGRQ4wLKddMFOZBwXkNqf7HKBE+GHmPH4JFMlBnKYBPnEO3KJqHCDV
-----END RSA PRIVATE KEY-----
"""
    (FIXTURE_DIR / "pem_rsa").write_text(content)
    print("[+] pem_rsa")

    # 5. Malformed key (looks like a key but has bad structure)
    content = """-----BEGIN OPENSSH PRIVATE KEY-----
dGhpcyBpcyBub3QgYSB2YWxpZCBrZXk=
-----END OPENSSH PRIVATE KEY-----
"""
    (FIXTURE_DIR / "malformed_key").write_text(content)
    print("[+] malformed_key")

    # 6. Encrypted PEM DSA key
    content = """-----BEGIN DSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,A1B2C3D4E5F6A7B8

MIIBuwIBAAKBgQDHUigyzTMhn1S+SFCEbS0MdBWPz+GFE/MBSVCaFs0wMzKfHMjR
cNKgFgMGLxQ7KERZ5sBj3ENRfSbMkdq/HjBgI3GkFPMXRfLOUfHT0uMZhiF2LJBP
-----END DSA PRIVATE KEY-----
"""
    (FIXTURE_DIR / "encrypted_dsa").write_text(content)
    print("[+] encrypted_dsa")

    # 7. Encrypted PEM EC key
    content = """-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,AABBCCDD11223344AABBCCDD11223344

MHQCAQEEIBkg0DgGAjIuVMxSJMFgpPBkz0HBVKXG7Gj3cGVMPONoAcGBSuBBAAi
oWQDYgAEY1GlPyRPrzIhfA3qJxGPAMBh0BD1FOD/JMBBLjlGEBDqNu0MNODAFDiE
-----END EC PRIVATE KEY-----
"""
    (FIXTURE_DIR / "encrypted_ec").write_text(content)
    print("[+] encrypted_ec")

    # 8. PKCS#8 encrypted key
    content = """-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQIpOXFb8JhEBgCAggA
MAwGCCqGSIb3DQIJBQAwFAYIKoZIhvcNAwcECLJ1aBQzFJJgBIIEyA3M8V0AAAAA
-----END ENCRYPTED PRIVATE KEY-----
"""
    (FIXTURE_DIR / "pkcs8_encrypted").write_text(content)
    print("[+] pkcs8_encrypted")

    # 9. Not a key at all
    content = "This is just a regular text file, not an SSH key.\n"
    (FIXTURE_DIR / "not_a_key.txt").write_text(content)
    print("[+] not_a_key.txt")

    print("\nAll fixtures generated.")


if __name__ == "__main__":
    main()
