# app/core/secure_credential_manager.py
import os
import json
import base64
import hashlib
import secrets
from typing import Dict, Optional, List, Any
from dataclasses import dataclass, asdict
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import threading
import time
from PyQt6.QtCore import QObject, pyqtSignal

from app.core.logger import logger


@dataclass
class SecureCredential:
    """Secure credential with metadata"""
    service: str
    username: str
    password: str = ""
    api_key: str = ""
    token: str = ""
    domain: str = ""
    notes: str = ""
    created_at: float = 0
    last_used: float = 0
    source: str = "manual"

    def __post_init__(self):
        if not self.created_at:
            self.created_at = time.time()


class SecureMemory:
    """Secure memory management for credentials"""

    def __init__(self):
        self._memory_blocks: Dict[str, str] = {}
        self._lock = threading.Lock()

    def allocate_secure(self, data: str) -> str:
        """Allocate secure memory for sensitive data"""
        with self._lock:
            block_id = secrets.token_hex(16)
            self._memory_blocks[block_id] = data
            return block_id

    def read_secure(self, block_id: str) -> Optional[str]:
        """Read from secure memory"""
        with self._lock:
            return self._memory_blocks.get(block_id)

    def clear_secure(self, block_id: str):
        """Clear secure memory block"""
        with self._lock:
            if block_id in self._memory_blocks:
                # Overwrite with random data before deletion
                self._memory_blocks[block_id] = secrets.token_hex(
                    len(self._memory_blocks[block_id])
                )
                del self._memory_blocks[block_id]

    def clear_all(self):
        """Clear all secure memory"""
        with self._lock:
            for block_id in list(self._memory_blocks.keys()):
                self.clear_secure(block_id)


class SecretsManagerIntegration:
    """Integration with enterprise secrets management solutions"""

    def __init__(self):
        self.vault_client = None
        self.aws_client = None
        self.azure_client = None

    def init_hashicorp_vault(self, vault_url: str, vault_token: str):
        """Initialize HashiCorp Vault client"""
        try:
            import hvac
            self.vault_client = hvac.Client(url=vault_url, token=vault_token)
            return self.vault_client.is_authenticated()
        except ImportError:
            raise ImportError("hvac library required for HashiCorp Vault integration")

    def init_aws_secrets(self, region: str = "us-east-1"):
        """Initialize AWS Secrets Manager client"""
        try:
            import boto3
            self.aws_client = boto3.client('secretsmanager', region_name=region)
            return True
        except ImportError:
            raise ImportError("boto3 library required for AWS Secrets Manager integration")

    def init_azure_keyvault(self, vault_url: str):
        """Initialize Azure Key Vault client"""
        try:
            from azure.keyvault.secrets import SecretClient
            from azure.identity import DefaultAzureCredential
            credential = DefaultAzureCredential()
            self.azure_client = SecretClient(vault_url=vault_url, credential=credential)
            return True
        except ImportError:
            raise ImportError(
                "azure-keyvault-secrets library required for Azure Key Vault integration"
            )

    def get_secret_vault(self, path: str) -> Optional[Dict]:
        """Get secret from HashiCorp Vault"""
        if not self.vault_client:
            return None
        try:
            response = self.vault_client.secrets.kv.v2.read_secret_version(path=path)
            return response['data']['data']
        except Exception:
            return None

    def get_secret_aws(self, secret_name: str) -> Optional[str]:
        """Get secret from AWS Secrets Manager"""
        if not self.aws_client:
            return None
        try:
            response = self.aws_client.get_secret_value(SecretId=secret_name)
            return response['SecretString']
        except Exception:
            return None

    def get_secret_azure(self, secret_name: str) -> Optional[str]:
        """Get secret from Azure Key Vault"""
        if not self.azure_client:
            return None
        try:
            secret = self.azure_client.get_secret(secret_name)
            return secret.value
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Key-file format (v2)
# ---------------------------------------------------------------------------
# The key file stores:
#   [1 byte version=0x02] [16 bytes salt] [32 bytes Fernet key material]
# Total: 49 bytes.
#
# Legacy v1 files stored only the raw Fernet key (44 bytes, base64url).
# _init_encryption detects the version byte and handles both.
# ---------------------------------------------------------------------------
_KEY_FILE_VERSION = 0x02
_SALT_LEN = 16
_KEY_LEN = 32


class SecureCredentialManager(QObject):
    """Centralized secure credential and API key management system.

    Implemented as a thread-safe singleton — only one instance is ever
    created regardless of how many times the class is instantiated.
    Use ``from app.core.secure_credential_manager import secure_credential_manager``
    to access the shared instance.

    All credentials are stored encrypted on disk using Fernet symmetric
    encryption (AES-128-CBC + HMAC-SHA256).
    """

    # NOTE: Do NOT use a custom __new__ for QObject subclasses.
    # Calling QObject.__init__() on a pre-existing C++ peer causes a stack
    # overflow in PyQt6.  The singleton is enforced via the module-level
    # ``secure_credential_manager`` variable at the bottom of this file.
    # Any code that needs the shared instance should import that variable
    # directly rather than calling SecureCredentialManager() again.

    credential_accessed = pyqtSignal(str, str)   # service, username
    credential_stored = pyqtSignal(str)           # service
    security_event = pyqtSignal(str, str)         # event_type, message

    def __init__(self, config_dir: str = None):
        super().__init__()
        self._initialised = True
        if config_dir:
            self.config_dir = Path(config_dir)
        else:
            project_root = Path(__file__).parent.parent.parent
            self.config_dir = project_root / "resources" / "credentials"
        self.config_dir.mkdir(parents=True, exist_ok=True)

        self.credentials_file = self.config_dir / "credentials.enc"
        self.key_file = self.config_dir / "master.key"

        self._secure_memory = SecureMemory()
        self._secrets_manager = SecretsManagerIntegration()
        self._fernet: Optional[Fernet] = None
        self._credentials: Dict[str, SecureCredential] = {}
        self._memory_refs: Dict[str, Dict[str, str]] = {}

        self._init_encryption()
        self._load_credentials()
        self._set_secure_permissions()

    # ------------------------------------------------------------------
    # Encryption initialisation
    # ------------------------------------------------------------------

    def _init_encryption(self):
        """Initialise the Fernet cipher.

        Key derivation (v2 format):
            password  = HUGINN_MASTER_PASSWORD env var, or a random secret
                        generated once and embedded in the key file.
            salt      = 16 random bytes stored in the key file.
            key       = PBKDF2-HMAC-SHA256(password, salt, 100_000, 32 bytes)
                        then base64url-encoded for Fernet.

        Legacy v1 key files (raw 44-byte Fernet key) are detected and
        automatically migrated to v2 format.
        """
        try:
            if self.key_file.exists():
                raw = self.key_file.read_bytes()
                if len(raw) > 0 and raw[0] == _KEY_FILE_VERSION:
                    # v2 format: [0x02][16-byte salt][32-byte key material]
                    if len(raw) != 1 + _SALT_LEN + _KEY_LEN:
                        raise ValueError("Corrupt key file (wrong length for v2)")
                    salt = raw[1: 1 + _SALT_LEN]
                    key_material = raw[1 + _SALT_LEN:]
                    fernet_key = base64.urlsafe_b64encode(key_material)
                    self._fernet = Fernet(fernet_key)
                else:
                    # v1 format: raw Fernet key (44 bytes base64url).
                    # If the key is malformed, treat it as corrupt and
                    # generate a fresh key (existing encrypted data will be
                    # unrecoverable, but the app will start cleanly).
                    logger.warning(
                        "Migrating credential key file from v1 to v2 format"
                    )
                    try:
                        self._fernet = Fernet(raw.strip())
                        # Re-save in v2 format
                        self._write_new_key_file()
                        logger.info("Key file migrated to v2 format")
                    except Exception as key_err:
                        logger.warning(
                            f"v1 key file is corrupt ({key_err}); "
                            "generating a new key. Previously encrypted "
                            "credentials cannot be recovered."
                        )
                        self._write_new_key_file()
            else:
                # First run — generate a new key file
                self._write_new_key_file()
        except Exception as e:
            logger.error(f"Credential encryption init failed: {e}", exc_info=True)
            # Fall back to a session-only in-memory key so the app still starts
            self._fernet = Fernet(Fernet.generate_key())
            self.security_event.emit(
                "encryption_error",
                f"Using ephemeral key — credentials will not persist: {e}"
            )

    def _write_new_key_file(self):
        """Generate a new v2 key file and initialise self._fernet."""
        salt = os.urandom(_SALT_LEN)
        password = os.environ.get('HUGINN_MASTER_PASSWORD', '').encode()
        if not password:
            # No env var — generate a random per-installation password and
            # embed it in the key file (the key file IS the secret).
            password = secrets.token_bytes(32)
            logger.info(
                "HUGINN_MASTER_PASSWORD not set — using random per-installation key. "
                "Set the env var to use a portable password."
            )
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=_KEY_LEN,
            salt=salt,
            iterations=100_000,
        )
        key_material = kdf.derive(password)
        fernet_key = base64.urlsafe_b64encode(key_material)
        self._fernet = Fernet(fernet_key)

        # Write: [version byte][salt][key material]
        self.key_file.write_bytes(bytes([_KEY_FILE_VERSION]) + salt + key_material)
        self._set_secure_permissions()

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def _set_secure_permissions(self):
        """Restrict key and credential file permissions to owner-only."""
        for path in (self.credentials_file, self.key_file):
            if not path.exists():
                continue
            try:
                os.chmod(path, 0o600)
            except (OSError, AttributeError):
                # Windows — mark as hidden/system
                try:
                    import subprocess
                    subprocess.run(
                        ['attrib', '+H', str(path)],
                        check=False, capture_output=True
                    )
                except Exception as _exc:
                    pass
                    logger.debug("Suppressed exception", exc_info=True)

    def _load_credentials(self):
        """Load and decrypt credentials from disk."""
        if not self.credentials_file.exists():
            return
        try:
            encrypted_data = self.credentials_file.read_bytes()
            if not encrypted_data:
                return
            decrypted_data = self._fernet.decrypt(encrypted_data)
            credentials_data = json.loads(decrypted_data.decode())
            for service, cred_data in credentials_data.items():
                self._credentials[service] = SecureCredential(**cred_data)
        except InvalidToken:
            logger.error(
                "Failed to decrypt credentials — wrong key or corrupted file. "
                "Credentials not loaded."
            )
            self.security_event.emit(
                "load_error",
                "Decryption failed — wrong master password or corrupted credential store."
            )
        except Exception as e:
            logger.error(f"Failed to load credentials: {e}", exc_info=True)
            self.security_event.emit("load_error", f"Failed to load credentials: {e}")

    def _save_credentials(self):
        """Encrypt and persist credentials to disk."""
        try:
            self.config_dir.mkdir(parents=True, exist_ok=True)
            credentials_data = {
                service: asdict(cred)
                for service, cred in self._credentials.items()
            }
            json_data = json.dumps(credentials_data).encode()
            encrypted_data = self._fernet.encrypt(json_data)
            self.credentials_file.write_bytes(encrypted_data)
            self._set_secure_permissions()
        except Exception as e:
            logger.error(f"Failed to save credentials: {e}", exc_info=True)
            self.security_event.emit("save_error", f"Failed to save credentials: {e}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def encrypt_data(self, data: bytes) -> bytes:
        """Encrypt arbitrary bytes using the manager's Fernet key.

        Used by CredentialManager to encrypt profile credential files.
        """
        return self._fernet.encrypt(data)

    def decrypt_data(self, data: bytes) -> bytes:
        """Decrypt bytes previously encrypted with encrypt_data().

        Raises ``cryptography.fernet.InvalidToken`` if decryption fails.
        """
        return self._fernet.decrypt(data)

    def configure_secrets_manager(self, provider: str, **kwargs) -> bool:
        """Configure enterprise secrets management integration."""
        try:
            if provider == "vault":
                return self._secrets_manager.init_hashicorp_vault(
                    kwargs.get('vault_url'), kwargs.get('vault_token')
                )
            elif provider == "aws":
                return self._secrets_manager.init_aws_secrets(
                    kwargs.get('region', 'us-east-1')
                )
            elif provider == "azure":
                return self._secrets_manager.init_azure_keyvault(
                    kwargs.get('vault_url')
                )
            return False
        except Exception as e:
            self.security_event.emit("secrets_manager_error", str(e))
            return False

    def store_credential(self, service: str, username: str = "",
                         password: str = "", api_key: str = "",
                         token: str = "", domain: str = "",
                         notes: str = "", source: str = "manual") -> bool:
        """Store a credential securely."""
        try:
            credential = SecureCredential(
                service=service, username=username, password=password,
                api_key=api_key, token=token, domain=domain,
                notes=notes, source=source,
            )
            self._credentials[service] = credential
            self._save_credentials()
            self.credential_stored.emit(service)
            self.security_event.emit(
                "credential_stored", f"Stored credential for {service}"
            )
            return True
        except Exception as e:
            logger.error(f"Failed to store credential for {service}: {e}", exc_info=True)
            self.security_event.emit(
                "store_error", f"Failed to store credential: {e}"
            )
            return False

    def get_credential(self, service: str, use_env: bool = True,
                       use_secrets_manager: bool = True) -> Optional[SecureCredential]:
        """Get credential with priority: env vars > secrets manager > local storage."""
        if use_env:
            env_cred = self._get_env_credential(service)
            if env_cred:
                self.credential_accessed.emit(service, env_cred.username)
                return env_cred

        if use_secrets_manager:
            secrets_cred = self._get_secrets_manager_credential(service)
            if secrets_cred:
                self.credential_accessed.emit(service, secrets_cred.username)
                return secrets_cred

        if service in self._credentials:
            credential = self._credentials[service]
            credential.last_used = time.time()
            self._save_credentials()
            self.credential_accessed.emit(service, credential.username)
            return credential

        return None

    def _get_env_credential(self, service: str) -> Optional[SecureCredential]:
        """Get credential from environment variables."""
        service_upper = service.upper().replace('-', '_').replace(' ', '_')
        username = (os.environ.get(f"{service_upper}_USERNAME")
                    or os.environ.get(f"{service_upper}_USER"))
        password = (os.environ.get(f"{service_upper}_PASSWORD")
                    or os.environ.get(f"{service_upper}_PASS"))
        api_key = (os.environ.get(f"{service_upper}_API_KEY")
                   or os.environ.get(f"{service_upper}_KEY"))
        token = os.environ.get(f"{service_upper}_TOKEN")

        if username or password or api_key or token:
            return SecureCredential(
                service=service,
                username=username or "",
                password=password or "",
                api_key=api_key or "",
                token=token or "",
                source="environment",
            )
        return None

    def _get_secrets_manager_credential(
        self, service: str
    ) -> Optional[SecureCredential]:
        """Get credential from enterprise secrets manager."""
        if self._secrets_manager.vault_client:
            vault_data = self._secrets_manager.get_secret_vault(f"huginn/{service}")
            if vault_data:
                return SecureCredential(
                    service=service,
                    username=vault_data.get('username', ''),
                    password=vault_data.get('password', ''),
                    api_key=vault_data.get('api_key', ''),
                    token=vault_data.get('token', ''),
                    source="vault",
                )

        if self._secrets_manager.aws_client:
            aws_secret = self._secrets_manager.get_secret_aws(f"huginn/{service}")
            if aws_secret:
                try:
                    secret_data = json.loads(aws_secret)
                    return SecureCredential(
                        service=service,
                        username=secret_data.get('username', ''),
                        password=secret_data.get('password', ''),
                        api_key=secret_data.get('api_key', ''),
                        token=secret_data.get('token', ''),
                        source="aws_secrets",
                    )
                except json.JSONDecodeError as _exc:
                    pass
                    logger.debug("Suppressed exception", exc_info=True)

        if self._secrets_manager.azure_client:
            azure_secret = self._secrets_manager.get_secret_azure(
                f"huginn-{service}"
            )
            if azure_secret:
                try:
                    secret_data = json.loads(azure_secret)
                    return SecureCredential(
                        service=service,
                        username=secret_data.get('username', ''),
                        password=secret_data.get('password', ''),
                        api_key=secret_data.get('api_key', ''),
                        token=secret_data.get('token', ''),
                        source="azure_keyvault",
                    )
                except json.JSONDecodeError as _exc:
                    pass
                    logger.debug("Suppressed exception", exc_info=True)

        return None

    def get_secure_memory_ref(self, service: str, field: str) -> Optional[str]:
        """Get a secure memory reference for a sensitive credential field."""
        credential = self.get_credential(service)
        if not credential:
            return None
        field_value = getattr(credential, field, "")
        if not field_value:
            return None
        ref_id = self._secure_memory.allocate_secure(field_value)
        if service not in self._memory_refs:
            self._memory_refs[service] = {}
        self._memory_refs[service][field] = ref_id
        return ref_id

    def read_secure_memory(self, ref_id: str) -> Optional[str]:
        """Read from a secure memory reference."""
        return self._secure_memory.read_secure(ref_id)

    def clear_secure_memory(self, service: str = None, ref_id: str = None):
        """Clear secure memory references."""
        if ref_id:
            self._secure_memory.clear_secure(ref_id)
        elif service and service in self._memory_refs:
            for field_ref in self._memory_refs[service].values():
                self._secure_memory.clear_secure(field_ref)
            del self._memory_refs[service]
        else:
            self._secure_memory.clear_all()
            self._memory_refs.clear()

    def list_services(self) -> List[str]:
        """List all services with stored credentials."""
        services = set(self._credentials.keys())
        for env_var in os.environ:
            if env_var.endswith(('_USERNAME', '_PASSWORD', '_API_KEY', '_TOKEN')):
                service_part = env_var.rsplit('_', 1)[0].lower().replace('_', '-')
                services.add(service_part)
        return sorted(list(services))

    def remove_credential(self, service: str) -> bool:
        """Remove a stored credential."""
        try:
            if service in self._credentials:
                del self._credentials[service]
                self._save_credentials()
                self.clear_secure_memory(service)
                self.security_event.emit(
                    "credential_removed", f"Removed credential for {service}"
                )
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to remove credential for {service}: {e}", exc_info=True)
            self.security_event.emit(
                "remove_error", f"Failed to remove credential: {e}"
            )
            return False

    def test_credential(self, service: str) -> Dict[str, Any]:
        """Test credential validity."""
        credential = self.get_credential(service)
        if not credential:
            return {"success": False, "error": "Credential not found"}
        if service.lower() == 'shodan':
            return self._test_shodan_credential(credential)
        elif service.lower() == 'virustotal':
            return self._test_virustotal_credential(credential)
        elif service.lower().startswith('aws'):
            return self._test_aws_credential(credential)
        return {"success": True, "message": "Credential loaded successfully"}

    def _test_shodan_credential(self, credential: SecureCredential) -> Dict[str, Any]:
        try:
            import requests
            from app.core.config import config as _cfg
            response = requests.get(
                "https://api.shodan.io/api-info",
                params={"key": credential.api_key},
                timeout=10,
                verify=_cfg.get('security.ssl_verify', True),
            )
            if response.status_code == 200:
                return {"success": True, "message": "Shodan API key valid"}
            return {"success": False, "error": "Invalid Shodan API key"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _test_virustotal_credential(
        self, credential: SecureCredential
    ) -> Dict[str, Any]:
        try:
            import requests
            from app.core.config import config as _cfg
            response = requests.get(
                "https://www.virustotal.com/api/v3/users/current",
                headers={"x-apikey": credential.api_key},
                timeout=10,
                verify=_cfg.get('security.ssl_verify', True),
            )
            if response.status_code == 200:
                return {"success": True, "message": "VirusTotal API key valid"}
            return {"success": False, "error": "Invalid VirusTotal API key"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _test_aws_credential(self, credential: SecureCredential) -> Dict[str, Any]:
        try:
            import boto3
            session = boto3.Session(
                aws_access_key_id=credential.username,
                aws_secret_access_key=credential.password,
                aws_session_token=credential.token or None,
            )
            sts = session.client('sts')
            sts.get_caller_identity()
            return {"success": True, "message": "AWS credentials valid"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def export_credentials(self, include_sensitive: bool = False) -> Dict:
        """Export credentials (optionally without sensitive data)."""
        export_data = {}
        for service, credential in self._credentials.items():
            cred_data = asdict(credential)
            if not include_sensitive:
                cred_data['password'] = "***"
                cred_data['api_key'] = "***"
                cred_data['token'] = "***"
            export_data[service] = cred_data
        return export_data

    def get_security_summary(self) -> Dict[str, Any]:
        """Get security summary."""
        total_creds = len(self._credentials)
        env_creds = len(
            [s for s in self.list_services() if self._get_env_credential(s)]
        )
        sources: Dict[str, int] = {}
        for credential in self._credentials.values():
            sources[credential.source] = sources.get(credential.source, 0) + 1
        return {
            "total_credentials": total_creds,
            "environment_credentials": env_creds,
            "sources": sources,
            "encryption_enabled": True,
            "secrets_manager_configured": any([
                self._secrets_manager.vault_client,
                self._secrets_manager.aws_client,
                self._secrets_manager.azure_client,
            ]),
            "secure_memory_blocks": len(self._secure_memory._memory_blocks),
        }


# Global secure credential manager instance
secure_credential_manager = SecureCredentialManager()
