# tools/credential_manager.py
import os
import json
import base64
from cryptography.fernet import Fernet
from pathlib import Path

class CredentialManager:
    def __init__(self, config_dir=None):
        self.config_dir = config_dir or Path.home() / '.huggin'
        self.config_dir.mkdir(exist_ok=True)
        self.config_file = self.config_dir / 'credentials.json'
        self.key_file = self.config_dir / '.key'
        self._ensure_key()
    
    def _ensure_key(self):
        """Generate or load encryption key"""
        if not self.key_file.exists():
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
            os.chmod(self.key_file, 0o600)  # Restrict permissions
        
        with open(self.key_file, 'rb') as f:
            self.key = f.read()
        self.cipher = Fernet(self.key)
    
    def store_credential(self, service, username, password):
        """Store encrypted credentials"""
        credentials = self._load_credentials()
        
        encrypted_password = self.cipher.encrypt(password.encode()).decode()
        credentials[service] = {
            'username': username,
            'password': encrypted_password
        }
        
        self._save_credentials(credentials)
    
    def get_credential(self, service):
        """Retrieve and decrypt credentials"""
        credentials = self._load_credentials()
        
        if service not in credentials:
            return None, None
        
        username = credentials[service]['username']
        encrypted_password = credentials[service]['password']
        password = self.cipher.decrypt(encrypted_password.encode()).decode()
        
        return username, password
    
    def _load_credentials(self):
        """Load credentials from file"""
        if not self.config_file.exists():
            return {}
        
        with open(self.config_file, 'r') as f:
            return json.load(f)
    
    def _save_credentials(self, credentials):
        """Save credentials to file"""
        with open(self.config_file, 'w') as f:
            json.dump(credentials, f, indent=2)
        os.chmod(self.config_file, 0o600)  # Restrict permissions
    
    @staticmethod
    def get_env_credential(service):
        """Get credentials from environment variables"""
        username = os.getenv(f'{service.upper()}_USERNAME')
        password = os.getenv(f'{service.upper()}_PASSWORD')
        return username, password
    
    def get_safe_credential(self, service):
        """Get credentials safely - env vars first, then stored"""
        username, password = self.get_env_credential(service)
        if username and password:
            return username, password
        return self.get_credential(service)