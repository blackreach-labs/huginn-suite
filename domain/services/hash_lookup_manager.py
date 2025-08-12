"""Hash lookup business logic"""

import re
from typing import Optional
from domain.models.hash_record import HashRecord
from domain.repositories.hash_repository import HashRepository
from infrastructure.external.hash_api_client import HashAPIClient

class HashLookupManager:
    def __init__(self, repository: HashRepository):
        self.repository = repository
        self.api_client = HashAPIClient()
    
    def lookup_hash(self, hash_value: str, source_name: str = "Local", hash_type: str = None) -> Optional[HashRecord]:
        """Lookup hash using specified source (local or online)"""
        if not self._validate_hash(hash_value):
            return None
        
        # Normalize hash (lowercase, strip whitespace)
        normalized_hash = hash_value.strip().lower()
        
        # Auto-detect hash type if not provided
        if not hash_type:
            hash_type = self.get_hash_type(normalized_hash).lower()
        
        plaintext = None
        
        if source_name.startswith("Local:"):
            plaintext = self.repository.lookup(normalized_hash)
            source = "database"
        elif source_name.startswith("Online:"):
            provider = source_name.split(":")[1].strip()
            plaintext = self.api_client.query(provider, normalized_hash, hash_type)
            source = f"online_{provider}"
        else:
            # Default to local lookup
            plaintext = self.repository.lookup(normalized_hash)
            source = "database"
        
        if plaintext:
            return HashRecord(normalized_hash, plaintext, source)
        
        return None
    
    def _validate_hash(self, hash_value: str) -> bool:
        """Validate hash format"""
        if not hash_value or not isinstance(hash_value, str):
            return False
        
        # Remove whitespace
        hash_clean = hash_value.strip()
        
        # Check common hash lengths and hex format
        if re.match(r'^[a-fA-F0-9]{32}$', hash_clean):  # MD5
            return True
        elif re.match(r'^[a-fA-F0-9]{40}$', hash_clean):  # SHA1
            return True
        elif re.match(r'^[a-fA-F0-9]{64}$', hash_clean):  # SHA256
            return True
        elif re.match(r'^[a-fA-F0-9]{128}$', hash_clean):  # SHA512
            return True
        
        return False
    
    def get_hash_type(self, hash_value: str) -> str:
        """Determine hash type"""
        hash_clean = hash_value.strip()
        length = len(hash_clean)
        
        if length == 32:
            return "MD5"
        elif length == 40:
            return "SHA1"
        elif length == 64:
            return "SHA256"
        elif length == 128:
            return "SHA512"
        else:
            return "Unknown"