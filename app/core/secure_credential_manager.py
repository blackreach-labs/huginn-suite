# app/core/secure_credential_manager.py
import os
import json
import base64
import hashlib
import secrets
from typing import Dict, Optional, List, Any, Union
from dataclasses import dataclass, asdict
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import ctypes
import threading
import time
from PyQt6.QtCore import QObject, pyqtSignal

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
        self._memory_blocks = {}
        self._lock = threading.Lock()
    
    def allocate_secure(self, data: str) -> str:
        """Allocate secure memory for sensitive data"""
        with self._lock:
            block_id = secrets.token_hex(16)
            # In production, use mlock() on Unix or VirtualLock() on Windows
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
                self._memory_blocks[block_id] = secrets.token_hex(len(self._memory_blocks[block_id]))
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
            raise ImportError("azure-keyvault-secrets library required for Azure Key Vault integration")
    
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

class SecureCredentialManager(QObject):
    """Centralized secure credential and API key management system"""
    
    credential_accessed = pyqtSignal(str, str)  # service, username
    credential_stored = pyqtSignal(str)  # service
    security_event = pyqtSignal(str, str)  # event_type, message
    
    def __init__(self, config_dir: str = None):
        super().__init__()
        if config_dir:
            self.config_dir = Path(config_dir)
        else:
            # Use resources/credentials directory in project
            project_root = Path(__file__).parent.parent.parent
            self.config_dir = project_root / "resources" / "credentials"
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        self.credentials_file = self.config_dir / "credentials.enc"
        self.key_file = self.config_dir / "master.key"
        
        self._secure_memory = SecureMemory()
        self._secrets_manager = SecretsManagerIntegration()
        self._fernet = None
        self._credentials = {}
        self._memory_refs = {}
        
        self._init_encryption()
        self._load_credentials()
        
        # Set restrictive permissions
        self._set_secure_permissions()
    
    def _init_encryption(self):
        """Initialize encryption system"""
        if self.key_file.exists():
            with open(self.key_file, 'rb') as f:
                key = f.read()
        else:
            # Generate new key
            password = os.environ.get('HUGGIN_MASTER_PASSWORD', 'default_password').encode()
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            
            with open(self.key_file, 'wb') as f:
                f.write(salt + key)
            key = salt + key
        
        if len(key) > 32:
            # Extract salt and derive key
            salt = key[:16]
            stored_key = key[16:]
            self._fernet = Fernet(stored_key)
        else:
            self._fernet = Fernet(key)
    
    def _set_secure_permissions(self):
        """Set secure file permissions"""
        try:
            # Unix-like systems
            if self.credentials_file.exists():
                os.chmod(self.credentials_file, 0o600)
            if self.key_file.exists():
                os.chmod(self.key_file, 0o600)
        except (OSError, AttributeError):
            # Windows - use attrib command
            try:
                import subprocess
                if self.credentials_file.exists():
                    subprocess.run(['attrib', '+H', str(self.credentials_file)], check=False)
                if self.key_file.exists():
                    subprocess.run(['attrib', '+H', str(self.key_file)], check=False)
            except:
                pass
    
    def _load_credentials(self):
        """Load encrypted credentials from disk"""
        if not self.credentials_file.exists():
            return
        
        try:
            with open(self.credentials_file, 'rb') as f:
                encrypted_data = f.read()
            
            if not encrypted_data:
                return
                
            decrypted_data = self._fernet.decrypt(encrypted_data)
            credentials_data = json.loads(decrypted_data.decode())
            
            for service, cred_data in credentials_data.items():
                credential = SecureCredential(**cred_data)
                self._credentials[service] = credential
                
        except Exception as e:
            self.security_event.emit("load_error", f"Failed to load credentials: {str(e)}")
    
    def _save_credentials(self):
        """Save encrypted credentials to disk"""
        try:
            # Ensure directory exists
            self.config_dir.mkdir(parents=True, exist_ok=True)
            
            credentials_data = {}
            for service, credential in self._credentials.items():
                credentials_data[service] = asdict(credential)
            
            json_data = json.dumps(credentials_data).encode()
            encrypted_data = self._fernet.encrypt(json_data)
            
            with open(self.credentials_file, 'wb') as f:
                f.write(encrypted_data)
            
            self._set_secure_permissions()
            
        except Exception as e:
            self.security_event.emit("save_error", f"Failed to save credentials: {str(e)}")
    
    def configure_secrets_manager(self, provider: str, **kwargs) -> bool:
        """Configure enterprise secrets management integration"""
        try:
            if provider == "vault":
                return self._secrets_manager.init_hashicorp_vault(
                    kwargs.get('vault_url'), kwargs.get('vault_token')
                )
            elif provider == "aws":
                return self._secrets_manager.init_aws_secrets(kwargs.get('region', 'us-east-1'))
            elif provider == "azure":
                return self._secrets_manager.init_azure_keyvault(kwargs.get('vault_url'))
            return False
        except Exception as e:
            self.security_event.emit("secrets_manager_error", str(e))
            return False
    
    def store_credential(self, service: str, username: str = "", password: str = "", 
                        api_key: str = "", token: str = "", domain: str = "", 
                        notes: str = "", source: str = "manual") -> bool:
        """Store credential securely"""
        try:
            credential = SecureCredential(
                service=service,
                username=username,
                password=password,
                api_key=api_key,
                token=token,
                domain=domain,
                notes=notes,
                source=source
            )
            
            self._credentials[service] = credential
            self._save_credentials()
            
            self.credential_stored.emit(service)
            self.security_event.emit("credential_stored", f"Stored credential for {service}")
            return True
            
        except Exception as e:
            self.security_event.emit("store_error", f"Failed to store credential: {str(e)}")
            return False
    
    def get_credential(self, service: str, use_env: bool = True, 
                      use_secrets_manager: bool = True) -> Optional[SecureCredential]:
        """Get credential with priority: env vars > secrets manager > local storage"""
        
        # Priority 1: Environment variables
        if use_env:
            env_cred = self._get_env_credential(service)
            if env_cred:
                self.credential_accessed.emit(service, env_cred.username)
                return env_cred
        
        # Priority 2: Enterprise secrets manager
        if use_secrets_manager:
            secrets_cred = self._get_secrets_manager_credential(service)
            if secrets_cred:
                self.credential_accessed.emit(service, secrets_cred.username)
                return secrets_cred
        
        # Priority 3: Local encrypted storage
        if service in self._credentials:
            credential = self._credentials[service]
            credential.last_used = time.time()
            self._save_credentials()
            self.credential_accessed.emit(service, credential.username)
            return credential
        
        return None
    
    def _get_env_credential(self, service: str) -> Optional[SecureCredential]:
        """Get credential from environment variables"""
        service_upper = service.upper().replace('-', '_').replace(' ', '_')
        
        username = os.environ.get(f"{service_upper}_USERNAME") or os.environ.get(f"{service_upper}_USER")
        password = os.environ.get(f"{service_upper}_PASSWORD") or os.environ.get(f"{service_upper}_PASS")
        api_key = os.environ.get(f"{service_upper}_API_KEY") or os.environ.get(f"{service_upper}_KEY")
        token = os.environ.get(f"{service_upper}_TOKEN")
        
        if username or password or api_key or token:
            return SecureCredential(
                service=service,
                username=username or "",
                password=password or "",
                api_key=api_key or "",
                token=token or "",
                source="environment"
            )
        
        return None
    
    def _get_secrets_manager_credential(self, service: str) -> Optional[SecureCredential]:
        """Get credential from enterprise secrets manager"""
        
        # Try HashiCorp Vault
        if self._secrets_manager.vault_client:
            vault_data = self._secrets_manager.get_secret_vault(f"huggin/{service}")
            if vault_data:
                return SecureCredential(
                    service=service,
                    username=vault_data.get('username', ''),
                    password=vault_data.get('password', ''),
                    api_key=vault_data.get('api_key', ''),
                    token=vault_data.get('token', ''),
                    source="vault"
                )
        
        # Try AWS Secrets Manager
        if self._secrets_manager.aws_client:
            aws_secret = self._secrets_manager.get_secret_aws(f"huggin/{service}")
            if aws_secret:
                try:
                    secret_data = json.loads(aws_secret)
                    return SecureCredential(
                        service=service,
                        username=secret_data.get('username', ''),
                        password=secret_data.get('password', ''),
                        api_key=secret_data.get('api_key', ''),
                        token=secret_data.get('token', ''),
                        source="aws_secrets"
                    )
                except json.JSONDecodeError:
                    pass
        
        # Try Azure Key Vault
        if self._secrets_manager.azure_client:
            azure_secret = self._secrets_manager.get_secret_azure(f"huggin-{service}")
            if azure_secret:
                try:
                    secret_data = json.loads(azure_secret)
                    return SecureCredential(
                        service=service,
                        username=secret_data.get('username', ''),
                        password=secret_data.get('password', ''),
                        api_key=secret_data.get('api_key', ''),
                        token=secret_data.get('token', ''),
                        source="azure_keyvault"
                    )
                except json.JSONDecodeError:
                    pass
        
        return None
    
    def get_secure_memory_ref(self, service: str, field: str) -> Optional[str]:
        """Get secure memory reference for sensitive data"""
        credential = self.get_credential(service)
        if not credential:
            return None
        
        field_value = getattr(credential, field, "")
        if not field_value:
            return None
        
        # Store in secure memory
        ref_id = self._secure_memory.allocate_secure(field_value)
        
        # Track reference for cleanup
        if service not in self._memory_refs:
            self._memory_refs[service] = {}
        self._memory_refs[service][field] = ref_id
        
        return ref_id
    
    def read_secure_memory(self, ref_id: str) -> Optional[str]:
        """Read from secure memory reference"""
        return self._secure_memory.read_secure(ref_id)
    
    def clear_secure_memory(self, service: str = None, ref_id: str = None):
        """Clear secure memory references"""
        if ref_id:
            self._secure_memory.clear_secure(ref_id)
        elif service and service in self._memory_refs:
            for field_ref in self._memory_refs[service].values():
                self._secure_memory.clear_secure(field_ref)
            del self._memory_refs[service]
        else:
            # Clear all
            self._secure_memory.clear_all()
            self._memory_refs.clear()
    
    def list_services(self) -> List[str]:
        """List all services with stored credentials"""
        services = set(self._credentials.keys())
        
        # Add services from environment variables
        for env_var in os.environ:
            if env_var.endswith(('_USERNAME', '_PASSWORD', '_API_KEY', '_TOKEN')):
                service_part = env_var.rsplit('_', 1)[0].lower().replace('_', '-')
                services.add(service_part)
        
        return sorted(list(services))
    
    def remove_credential(self, service: str) -> bool:
        """Remove stored credential"""
        try:
            if service in self._credentials:
                del self._credentials[service]
                self._save_credentials()
                
                # Clear any secure memory references
                self.clear_secure_memory(service)
                
                self.security_event.emit("credential_removed", f"Removed credential for {service}")
                return True
            return False
        except Exception as e:
            self.security_event.emit("remove_error", f"Failed to remove credential: {str(e)}")
            return False
    
    def test_credential(self, service: str) -> Dict[str, Any]:
        """Test credential validity"""
        credential = self.get_credential(service)
        if not credential:
            return {"success": False, "error": "Credential not found"}
        
        # Service-specific validation
        if service.lower() in ['shodan']:
            return self._test_shodan_credential(credential)
        elif service.lower() in ['virustotal']:
            return self._test_virustotal_credential(credential)
        elif service.lower().startswith('aws'):
            return self._test_aws_credential(credential)
        else:
            return {"success": True, "message": "Credential loaded successfully"}
    
    def _test_shodan_credential(self, credential: SecureCredential) -> Dict[str, Any]:
        """Test Shodan API key"""
        try:
            import requests
            response = requests.get(
                "https://api.shodan.io/api-info",
                params={"key": credential.api_key},
                timeout=10
            )
            if response.status_code == 200:
                return {"success": True, "message": "Shodan API key valid"}
            else:
                return {"success": False, "error": "Invalid Shodan API key"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _test_virustotal_credential(self, credential: SecureCredential) -> Dict[str, Any]:
        """Test VirusTotal API key"""
        try:
            import requests
            response = requests.get(
                "https://www.virustotal.com/api/v3/users/current",
                headers={"x-apikey": credential.api_key},
                timeout=10
            )
            if response.status_code == 200:
                return {"success": True, "message": "VirusTotal API key valid"}
            else:
                return {"success": False, "error": "Invalid VirusTotal API key"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _test_aws_credential(self, credential: SecureCredential) -> Dict[str, Any]:
        """Test AWS credentials"""
        try:
            import boto3
            session = boto3.Session(
                aws_access_key_id=credential.username,
                aws_secret_access_key=credential.password,
                aws_session_token=credential.token if credential.token else None
            )
            sts = session.client('sts')
            sts.get_caller_identity()
            return {"success": True, "message": "AWS credentials valid"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def export_credentials(self, include_sensitive: bool = False) -> Dict:
        """Export credentials (optionally without sensitive data)"""
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
        """Get security summary"""
        total_creds = len(self._credentials)
        env_creds = len([s for s in self.list_services() if self._get_env_credential(s)])
        
        sources = {}
        for credential in self._credentials.values():
            source = credential.source
            sources[source] = sources.get(source, 0) + 1
        
        return {
            "total_credentials": total_creds,
            "environment_credentials": env_creds,
            "sources": sources,
            "encryption_enabled": True,
            "secrets_manager_configured": any([
                self._secrets_manager.vault_client,
                self._secrets_manager.aws_client,
                self._secrets_manager.azure_client
            ]),
            "secure_memory_blocks": len(self._secure_memory._memory_blocks)
        }

# Global secure credential manager instance
secure_credential_manager = SecureCredentialManager()