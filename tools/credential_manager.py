# tools/credential_manager.py
"""
Standalone credential manager for tools/ scripts.

Storage
-------
Credentials are stored in ``~/.huggin/credentials.enc`` as a
Fernet-encrypted JSON blob.  The Fernet key is stored in
``~/.huggin/.key`` (owner-read-only).

Migration
---------
If a legacy ``~/.huggin/credentials.json`` (plaintext) is found on first
load it is automatically encrypted and the plaintext file is deleted.
"""

import os
import json
import base64
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
import logging


class CredentialManager:
    def __init__(self, config_dir=None):
        self.config_dir = Path(config_dir) if config_dir else Path.home() / '.huggin'
        self.config_dir.mkdir(exist_ok=True)
        self.enc_file = self.config_dir / 'credentials.enc'
        self.key_file = self.config_dir / '.key'
        self._legacy_file = self.config_dir / 'credentials.json'
        self._ensure_key()
        self._migrate_if_needed()

    # ------------------------------------------------------------------
    # Key management
    # ------------------------------------------------------------------

    def _ensure_key(self):
        """Generate or load the Fernet encryption key."""
        if not self.key_file.exists():
            key = Fernet.generate_key()
            self.key_file.write_bytes(key)
            try:
                os.chmod(self.key_file, 0o600)
            except OSError as _exc:
                pass
                logging.debug("Suppressed exception", exc_info=True)
        self.cipher = Fernet(self.key_file.read_bytes().strip())

    # ------------------------------------------------------------------
    # Migration
    # ------------------------------------------------------------------

    def _migrate_if_needed(self):
        """Encrypt a legacy plaintext credentials.json if present."""
        if not self._legacy_file.exists():
            return
        try:
            with open(self._legacy_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            # Passwords in the legacy file were already Fernet-encrypted
            # per-field — re-wrap the whole blob.
            self._write_encrypted(data)
            # Overwrite plaintext before deletion
            try:
                size = self._legacy_file.stat().st_size
                with open(self._legacy_file, 'r+b') as f:
                    f.write(b'\x00' * size)
            except Exception as _exc:
                pass
                logging.debug("Suppressed exception", exc_info=True)
            self._legacy_file.unlink()
        except Exception as e:
            print(f"[credential_manager] Migration failed: {e}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def store_credential(self, service: str, username: str, password: str):
        """Store an encrypted credential."""
        credentials = self._load_decrypted()
        encrypted_password = self.cipher.encrypt(password.encode()).decode()
        credentials[service] = {
            'username': username,
            'password': encrypted_password,
        }
        self._write_encrypted(credentials)

    def get_credential(self, service: str):
        """Retrieve and decrypt a credential.  Returns (username, password) or (None, None)."""
        credentials = self._load_decrypted()
        if service not in credentials:
            return None, None
        username = credentials[service]['username']
        try:
            password = self.cipher.decrypt(
                credentials[service]['password'].encode()
            ).decode()
        except (InvalidToken, Exception):
            return username, None
        return username, password

    @staticmethod
    def get_env_credential(service: str):
        """Get credentials from environment variables."""
        username = os.getenv(f'{service.upper()}_USERNAME')
        password = os.getenv(f'{service.upper()}_PASSWORD')
        return username, password

    def get_safe_credential(self, service: str):
        """Return credentials: env vars take priority over stored."""
        username, password = self.get_env_credential(service)
        if username and password:
            return username, password
        return self.get_credential(service)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_decrypted(self) -> dict:
        """Load and decrypt the credential store.  Returns {} on any error."""
        if not self.enc_file.exists():
            return {}
        try:
            encrypted = self.enc_file.read_bytes()
            decrypted = self.cipher.decrypt(encrypted)
            return json.loads(decrypted.decode('utf-8'))
        except (InvalidToken, Exception):
            return {}

    def _write_encrypted(self, data: dict):
        """Encrypt and persist the credential store."""
        json_bytes = json.dumps(data, indent=2).encode('utf-8')
        encrypted = self.cipher.encrypt(json_bytes)
        self.enc_file.write_bytes(encrypted)
        try:
            os.chmod(self.enc_file, 0o600)
        except OSError as _exc:
            pass
            logging.debug("Suppressed exception", exc_info=True)
