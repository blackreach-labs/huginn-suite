"""Security management and credential handling"""
import os
import base64
import hashlib
import secrets
from typing import Dict, Optional, Tuple, List
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PyQt6.QtCore import QObject, pyqtSignal
from app.core.logger import logger

class SecurityManager(QObject):
    """Manage security features and credential storage"""
    
    security_event = pyqtSignal(str, str)  # event_type, message
    
    def __init__(self, credentials_file: str = "credentials.enc"):
        super().__init__()
        self.credentials_file = Path(credentials_file)
        self.master_key = None
        self.cipher_suite = None
        self.session_token = None
        
        # Security settings
        self.max_login_attempts = 3
        self.login_attempts = 0
        self.account_locked = False
        
        # Initialize session
        self._generate_session_token()
    
    def _generate_session_token(self):
        """Generate secure session token"""
        self.session_token = secrets.token_urlsafe(32)
        logger.debug("Session token generated")
    
    def initialize_encryption(self, password: str) -> bool:
        """Initialize encryption with master password"""
        try:
            # Generate salt
            salt = os.urandom(16)
            
            # Derive key from password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            
            # Create cipher suite
            self.cipher_suite = Fernet(key)
            self.master_key = key
            
            # Store salt for future use
            self._store_salt(salt)
            
            logger.info("Encryption initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error initializing encryption: {e}")
            return False
    
    def unlock_with_password(self, password: str) -> bool:
        """Unlock credential storage with password"""
        if self.account_locked:
            self.security_event.emit('account_locked', 'Account is locked due to too many failed attempts')
            return False
        
        try:
            # Load salt
            salt = self._load_salt()
            if not salt:
                logger.error("No salt found - encryption not initialized")
                return False
            
            # Derive key from password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            
            # Test decryption with a known value
            test_cipher = Fernet(key)
            if self._test_decryption(test_cipher):
                self.cipher_suite = test_cipher
                self.master_key = key
                self.login_attempts = 0
                logger.info("Credentials unlocked successfully")
                self.security_event.emit('unlock_success', 'Credentials unlocked')
                return True
            else:
                self.login_attempts += 1
                if self.login_attempts >= self.max_login_attempts:
                    self.account_locked = True
                    self.security_event.emit('account_locked', 'Account locked due to failed attempts')
                else:
                    remaining = self.max_login_attempts - self.login_attempts
                    self.security_event.emit('unlock_failed', f'Invalid password. {remaining} attempts remaining')
                return False
                
        except Exception as e:
            logger.error(f"Error unlocking credentials: {e}")
            self.login_attempts += 1
            return False
    
    def _store_salt(self, salt: bytes):
        """Store encryption salt securely"""
        try:
            salt_file = self.credentials_file.with_suffix('.salt')
            with open(salt_file, 'wb') as f:
                f.write(salt)
        except Exception as e:
            logger.error(f"Error storing salt: {e}")
    
    def _load_salt(self) -> Optional[bytes]:
        """Load encryption salt"""
        try:
            salt_file = self.credentials_file.with_suffix('.salt')
            if salt_file.exists():
                with open(salt_file, 'rb') as f:
                    return f.read()
        except Exception as e:
            logger.error(f"Error loading salt: {e}")
        return None
    
    def _test_decryption(self, cipher_suite: Fernet) -> bool:
        """Test if cipher suite can decrypt stored data"""
        try:
            if not self.credentials_file.exists():
                # No credentials file exists, so password is correct by default
                return True
            
            # Try to load and decrypt credentials
            with open(self.credentials_file, 'rb') as f:
                encrypted_data = f.read()
            
            if not encrypted_data:
                return True
            
            # Attempt decryption
            cipher_suite.decrypt(encrypted_data)
            return True
            
        except Exception:
            return False
    
    def store_credential(self, service: str, username: str, password: str) -> bool:
        """Store encrypted credential"""
        if not self.cipher_suite:
            logger.error("Encryption not initialized")
            return False
        
        try:
            # Load existing credentials
            credentials = self._load_credentials()
            
            # Add new credential
            credentials[service] = {
                'username': username,
                'password': password,
                'created': self._get_timestamp(),
                'last_used': None
            }
            
            # Save encrypted credentials
            return self._save_credentials(credentials)
            
        except Exception as e:
            logger.error(f"Error storing credential: {e}")
            return False
    
    def get_credential(self, service: str) -> Optional[Tuple[str, str]]:
        """Get decrypted credential"""
        if not self.cipher_suite:
            logger.error("Encryption not initialized")
            return None
        
        try:
            credentials = self._load_credentials()
            
            if service in credentials:
                cred = credentials[service]
                # Update last used timestamp
                cred['last_used'] = self._get_timestamp()
                self._save_credentials(credentials)
                
                return cred['username'], cred['password']
            
            return None
            
        except Exception as e:
            logger.error(f"Error retrieving credential: {e}")
            return None
    
    def delete_credential(self, service: str) -> bool:
        """Delete stored credential"""
        if not self.cipher_suite:
            logger.error("Encryption not initialized")
            return False
        
        try:
            credentials = self._load_credentials()
            
            if service in credentials:
                del credentials[service]
                return self._save_credentials(credentials)
            
            return True
            
        except Exception as e:
            logger.error(f"Error deleting credential: {e}")
            return False
    
    def list_services(self) -> List[str]:
        """List all stored services"""
        if not self.cipher_suite:
            return []
        
        try:
            credentials = self._load_credentials()
            return list(credentials.keys())
        except Exception as e:
            logger.error(f"Error listing services: {e}")
            return []
    
    def _load_credentials(self) -> Dict:
        """Load and decrypt credentials"""
        try:
            if not self.credentials_file.exists():
                return {}
            
            with open(self.credentials_file, 'rb') as f:
                encrypted_data = f.read()
            
            if not encrypted_data:
                return {}
            
            decrypted_data = self.cipher_suite.decrypt(encrypted_data)
            import json
            return json.loads(decrypted_data.decode())
            
        except Exception as e:
            logger.error(f"Error loading credentials: {e}")
            return {}
    
    def _save_credentials(self, credentials: Dict) -> bool:
        """Encrypt and save credentials"""
        try:
            import json
            json_data = json.dumps(credentials, indent=2)
            encrypted_data = self.cipher_suite.encrypt(json_data.encode())
            
            # Ensure directory exists
            self.credentials_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.credentials_file, 'wb') as f:
                f.write(encrypted_data)
            
            logger.debug("Credentials saved successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error saving credentials: {e}")
            return False
    
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        import datetime
        return datetime.datetime.now().isoformat()
    
    def sanitize_output(self, text: str) -> str:
        """Sanitize output text for security"""
        if not text:
            return ""
        
        # Remove potential credential leaks
        sensitive_patterns = [
            r'password[\s]*[:=][\s]*[^\s]+',
            r'pass[\s]*[:=][\s]*[^\s]+',
            r'secret[\s]*[:=][\s]*[^\s]+',
            r'token[\s]*[:=][\s]*[^\s]+',
            r'key[\s]*[:=][\s]*[^\s]+'
        ]
        
        import re
        sanitized = text
        for pattern in sensitive_patterns:
            sanitized = re.sub(pattern, '[REDACTED]', sanitized, flags=re.IGNORECASE)
        
        return sanitized
    
    def validate_secure_input(self, input_text: str) -> Tuple[bool, str]:
        """Validate input for security issues"""
        if not input_text:
            return True, "Input is empty"
        
        # Check for injection patterns
        dangerous_patterns = [
            r'[;&|`$(){}\\[\\]<>]',  # Command injection
            r'(union|select|insert|update|delete|drop)\s',  # SQL injection
            r'<script|javascript:|data:|vbscript:',  # XSS
            r'\.\.[\\/\\\\]',  # Path traversal
        ]
        
        import re
        for pattern in dangerous_patterns:
            if re.search(pattern, input_text, re.IGNORECASE):
                return False, f"Input contains potentially dangerous content: {pattern}"
        
        return True, "Input is safe"
    
    def generate_secure_password(self, length: int = 16) -> str:
        """Generate cryptographically secure password"""
        import string
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    def hash_sensitive_data(self, data: str) -> str:
        """Hash sensitive data for logging/storage"""
        return hashlib.sha256(data.encode()).hexdigest()[:16] + "..."
    
    def is_locked(self) -> bool:
        """Check if account is locked"""
        return self.account_locked
    
    def unlock_account(self, admin_password: str) -> bool:
        """Unlock account with admin password"""
        # This would typically verify against a separate admin credential
        # For now, we'll use a simple check
        admin_hash = "admin_unlock_key"  # In production, this would be properly secured
        
        if hashlib.sha256(admin_password.encode()).hexdigest().startswith(admin_hash[:8]):
            self.account_locked = False
            self.login_attempts = 0
            self.security_event.emit('account_unlocked', 'Account unlocked by administrator')
            return True
        
        return False
    
    def get_security_status(self) -> Dict:
        """Get current security status"""
        return {
            'encryption_initialized': self.cipher_suite is not None,
            'account_locked': self.account_locked,
            'login_attempts': self.login_attempts,
            'max_attempts': self.max_login_attempts,
            'session_active': self.session_token is not None,
            'credentials_file_exists': self.credentials_file.exists(),
            'stored_services': len(self.list_services())
        }

# Global security manager instance
security_manager = SecurityManager()