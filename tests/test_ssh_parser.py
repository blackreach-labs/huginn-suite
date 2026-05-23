"""Unit tests for the ssh_parser module."""

import struct
import base64
import pytest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.ssh_parser import (
    SSHKeyParser,
    SSHKeyInfo,
    KeyFormat,
    KeyState,
    SSHParserError,
    InvalidKeyError,
)
from modules.ssh_parser.binary import BinaryReader, MAX_SSH_STRING
from modules.ssh_parser.scanner import SSHKeyScanner, ScanResult

FIXTURES = Path(__file__).parent / "fixtures" / "ssh_keys"


# ---------------------------------------------------------------------------
# Helper to build synthetic OpenSSH keys
# ---------------------------------------------------------------------------

def _pack_string(s):
    if isinstance(s, str):
        s = s.encode()
    return struct.pack(">I", len(s)) + s


def _build_openssh(cipher="aes256-ctr", kdf="bcrypt", rounds=16, salt=b"\xAB" * 16, key_type="ssh-ed25519"):
    magic = b"openssh-key-v1\x00"
    body = _pack_string(cipher)
    body += _pack_string(kdf)
    if kdf == "bcrypt":
        kdf_opts = _pack_string(salt) + struct.pack(">I", rounds)
    else:
        kdf_opts = b""
    body += _pack_string(kdf_opts)
    body += struct.pack(">I", 1)
    pub_key = _pack_string(key_type) + _pack_string(b"\x00" * 32)
    body += _pack_string(pub_key)
    body += _pack_string(b"\x00" * 64)
    raw = magic + body
    b64 = base64.b64encode(raw).decode()
    lines = [b64[i:i+70] for i in range(0, len(b64), 70)]
    return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "\n".join(lines) + "\n-----END OPENSSH PRIVATE KEY-----\n"


# ---------------------------------------------------------------------------
# Format Detection Tests
# ---------------------------------------------------------------------------

class TestFormatDetection:
    def setup_method(self):
        self.parser = SSHKeyParser()

    def test_openssh_detect(self):
        data = _build_openssh()
        assert self.parser.identify_format(data) == KeyFormat.OPENSSH

    def test_pem_rsa_detect(self):
        data = "-----BEGIN RSA PRIVATE KEY-----\ndata\n-----END RSA PRIVATE KEY-----"
        assert self.parser.identify_format(data) == KeyFormat.PEM_RSA

    def test_pem_dsa_detect(self):
        data = "-----BEGIN DSA PRIVATE KEY-----\ndata\n-----END DSA PRIVATE KEY-----"
        assert self.parser.identify_format(data) == KeyFormat.PEM_DSA

    def test_pem_ec_detect(self):
        data = "-----BEGIN EC PRIVATE KEY-----\ndata\n-----END EC PRIVATE KEY-----"
        assert self.parser.identify_format(data) == KeyFormat.PEM_EC

    def test_pkcs8_detect(self):
        data = "-----BEGIN ENCRYPTED PRIVATE KEY-----\ndata\n-----END ENCRYPTED PRIVATE KEY-----"
        assert self.parser.identify_format(data) == KeyFormat.PKCS8

    def test_unknown_format(self):
        data = "not a key at all"
        assert self.parser.identify_format(data) == KeyFormat.UNKNOWN


# ---------------------------------------------------------------------------
# OpenSSH Parsing Tests
# ---------------------------------------------------------------------------

class TestOpenSSHParsing:
    def setup_method(self):
        self.parser = SSHKeyParser()

    def test_encrypted_openssh(self):
        data = _build_openssh(cipher="aes256-ctr", kdf="bcrypt", rounds=16, salt=b"\xAB" * 16)
        info = self.parser.parse_string(data)
        assert info.format == KeyFormat.OPENSSH
        assert info.state == KeyState.ENCRYPTED
        assert info.cipher == "aes256-ctr"
        assert info.kdf == "bcrypt"
        assert info.rounds == 16
        assert info.salt == b"\xAB" * 16
        assert info.is_encrypted is True

    def test_unencrypted_openssh(self):
        data = _build_openssh(cipher="none", kdf="none", rounds=0, salt=b"")
        info = self.parser.parse_string(data)
        assert info.format == KeyFormat.OPENSSH
        assert info.state == KeyState.UNENCRYPTED
        assert info.cipher == "none"
        assert info.is_encrypted is False

    def test_bcrypt_rounds(self):
        data = _build_openssh(rounds=100)
        info = self.parser.parse_string(data)
        assert info.rounds == 100

    def test_bcrypt_high_rounds(self):
        data = _build_openssh(rounds=1000)
        info = self.parser.parse_string(data)
        assert info.rounds == 1000

    def test_key_type_extraction(self):
        data = _build_openssh(key_type="ssh-ed25519")
        info = self.parser.parse_string(data)
        assert info.key_type == "ssh-ed25519"

    def test_rsa_key_type(self):
        data = _build_openssh(key_type="ssh-rsa")
        info = self.parser.parse_string(data)
        assert info.key_type == "ssh-rsa"

    def test_invalid_magic(self):
        """Key with valid PEM markers but invalid magic bytes inside."""
        bad_data = base64.b64encode(b"not-openssh-key-v1\x00garbage").decode()
        key = f"-----BEGIN OPENSSH PRIVATE KEY-----\n{bad_data}\n-----END OPENSSH PRIVATE KEY-----\n"
        with pytest.raises(InvalidKeyError, match="magic"):
            self.parser.parse_string(key)

    def test_empty_body(self):
        key = "-----BEGIN OPENSSH PRIVATE KEY-----\n-----END OPENSSH PRIVATE KEY-----\n"
        with pytest.raises(InvalidKeyError):
            self.parser.parse_string(key)


# ---------------------------------------------------------------------------
# PEM Parsing Tests
# ---------------------------------------------------------------------------

class TestPEMParsing:
    def setup_method(self):
        self.parser = SSHKeyParser()

    def test_encrypted_rsa(self):
        data = (FIXTURES / "encrypted_id_rsa").read_text()
        info = self.parser.parse_string(data)
        assert info.format == KeyFormat.PEM_RSA
        assert info.state == KeyState.ENCRYPTED
        assert info.cipher == "AES-128-CBC"
        assert info.kdf == "md5"
        assert info.iv is not None
        assert info.key_type == "ssh-rsa"

    def test_unencrypted_rsa(self):
        data = (FIXTURES / "pem_rsa").read_text()
        info = self.parser.parse_string(data)
        assert info.format == KeyFormat.PEM_RSA
        assert info.state == KeyState.UNENCRYPTED
        assert info.cipher is None
        assert info.iv is None

    def test_encrypted_dsa(self):
        data = (FIXTURES / "encrypted_dsa").read_text()
        info = self.parser.parse_string(data)
        assert info.format == KeyFormat.PEM_DSA
        assert info.state == KeyState.ENCRYPTED
        assert info.cipher == "DES-EDE3-CBC"
        assert info.key_type == "ssh-dss"

    def test_encrypted_ec(self):
        data = (FIXTURES / "encrypted_ec").read_text()
        info = self.parser.parse_string(data)
        assert info.format == KeyFormat.PEM_EC
        assert info.state == KeyState.ENCRYPTED
        assert info.cipher == "AES-256-CBC"
        assert info.key_type == "ecdsa"

    def test_pkcs8_encrypted(self):
        data = (FIXTURES / "pkcs8_encrypted").read_text()
        info = self.parser.parse_string(data)
        assert info.format == KeyFormat.PKCS8
        assert info.state == KeyState.ENCRYPTED
        assert info.cipher == "pkcs8-wrapped"
        assert info.kdf == "pkcs8"


# ---------------------------------------------------------------------------
# Malformed / Error Handling Tests
# ---------------------------------------------------------------------------

class TestErrorHandling:
    def setup_method(self):
        self.parser = SSHKeyParser()

    def test_malformed_key(self):
        """OpenSSH markers but garbage base64 content."""
        data = (FIXTURES / "malformed_key").read_text()
        # Should raise or return with errors (missing magic)
        with pytest.raises(InvalidKeyError):
            self.parser.parse_string(data)

    def test_not_a_key(self):
        with pytest.raises(InvalidKeyError):
            self.parser.parse_string("This is just a regular text file.")

    def test_empty_string(self):
        with pytest.raises(InvalidKeyError):
            self.parser.parse_string("")

    def test_whitespace_only(self):
        with pytest.raises(InvalidKeyError):
            self.parser.parse_string("   \n\n  ")

    def test_file_not_found(self):
        with pytest.raises(SSHParserError, match="not found"):
            self.parser.parse_file("/nonexistent/path/id_rsa")

    def test_oversized_input(self):
        huge = "-----BEGIN RSA PRIVATE KEY-----\n" + "A" * 2_000_000 + "\n-----END RSA PRIVATE KEY-----"
        with pytest.raises(SSHParserError, match="too large"):
            self.parser.parse_string(huge)


# ---------------------------------------------------------------------------
# BinaryReader Tests
# ---------------------------------------------------------------------------

class TestBinaryReader:
    def test_read_uint32(self):
        data = struct.pack(">I", 42)
        reader = BinaryReader(data)
        assert reader.read_uint32() == 42

    def test_read_string(self):
        payload = b"hello"
        data = struct.pack(">I", len(payload)) + payload
        reader = BinaryReader(data)
        assert reader.read_string() == b"hello"

    def test_out_of_bounds(self):
        reader = BinaryReader(b"\x00\x01")
        with pytest.raises(InvalidKeyError, match="end of data"):
            reader.read(10)

    def test_oversized_string_rejected(self):
        # String length exceeds MAX_SSH_STRING
        data = struct.pack(">I", MAX_SSH_STRING + 1)
        reader = BinaryReader(data)
        with pytest.raises(InvalidKeyError, match="exceeds maximum"):
            reader.read_string()

    def test_negative_read(self):
        reader = BinaryReader(b"\x00" * 10)
        with pytest.raises(SSHParserError, match="Negative"):
            reader.read(-1)

    def test_position_tracking(self):
        reader = BinaryReader(b"\x00" * 20)
        assert reader.position == 0
        reader.read(5)
        assert reader.position == 5
        assert reader.remaining == 15


# ---------------------------------------------------------------------------
# Serialization Tests
# ---------------------------------------------------------------------------

class TestSerialization:
    def setup_method(self):
        self.parser = SSHKeyParser()

    def test_to_dict_encrypted(self):
        data = _build_openssh()
        info = self.parser.parse_string(data)
        d = info.to_dict()
        assert isinstance(d, dict)
        assert d["format"] == "openssh"
        assert d["state"] == "encrypted"
        assert d["is_encrypted"] is True
        assert d["cipher"] == "aes256-ctr"
        assert d["kdf"] == "bcrypt"
        assert d["rounds"] == 16
        assert d["salt"] is not None

    def test_to_dict_unencrypted(self):
        data = _build_openssh(cipher="none", kdf="none", rounds=0, salt=b"")
        info = self.parser.parse_string(data)
        d = info.to_dict()
        assert d["is_encrypted"] is False
        assert d["salt"] is None


# ---------------------------------------------------------------------------
# Scanner Tests
# ---------------------------------------------------------------------------

class TestScanner:
    def test_scan_fixtures_directory(self):
        scanner = SSHKeyScanner()
        results = scanner.scan(FIXTURES)
        assert len(results) > 0
        # Should find at least the encrypted and unencrypted keys
        successful = [r for r in results if r.success]
        assert len(successful) >= 2

    def test_scan_single_file(self):
        scanner = SSHKeyScanner()
        results = scanner.scan(FIXTURES / "encrypted_ed25519")
        assert len(results) == 1
        assert results[0].success
        assert results[0].info.format == KeyFormat.OPENSSH

    def test_scan_result_to_dict(self):
        scanner = SSHKeyScanner()
        results = scanner.scan(FIXTURES / "encrypted_ed25519")
        d = results[0].to_dict()
        assert d["module"] == "ssh_parser"
        assert d["severity"] in ("critical", "high", "medium", "low", "info")
        assert d["artifact"] == "encrypted_key"
        assert "data" in d

    def test_scan_nonexistent_path(self):
        scanner = SSHKeyScanner()
        results = scanner.scan("/nonexistent/path")
        assert results == []

    def test_unencrypted_key_severity(self):
        scanner = SSHKeyScanner()
        results = scanner.scan(FIXTURES / "unencrypted_id_rsa")
        d = results[0].to_dict()
        assert d["severity"] == "critical"
        assert d["artifact"] == "unencrypted_key"


# ---------------------------------------------------------------------------
# File Parsing Tests (integration with fixtures)
# ---------------------------------------------------------------------------

class TestFileParsing:
    def setup_method(self):
        self.parser = SSHKeyParser()

    def test_parse_encrypted_ed25519_file(self):
        info = self.parser.parse_file(FIXTURES / "encrypted_ed25519")
        assert info.format == KeyFormat.OPENSSH
        assert info.state == KeyState.ENCRYPTED
        assert info.cipher == "aes256-ctr"
        assert info.kdf == "bcrypt"
        assert info.rounds == 16
        assert info.comment == "encrypted_ed25519"

    def test_parse_unencrypted_rsa_file(self):
        info = self.parser.parse_file(FIXTURES / "unencrypted_id_rsa")
        assert info.format == KeyFormat.OPENSSH
        assert info.state == KeyState.UNENCRYPTED

    def test_parse_pem_rsa_file(self):
        info = self.parser.parse_file(FIXTURES / "pem_rsa")
        assert info.format == KeyFormat.PEM_RSA
        assert info.state == KeyState.UNENCRYPTED
        assert info.comment == "pem_rsa"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
