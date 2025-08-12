"""
Azure Authentication Layer
Handles authentication to Azure using various methods.
"""

from typing import List, Optional, Dict, Any
from azure.identity import DefaultAzureCredential, ClientSecretCredential, InteractiveBrowserCredential
from azure.core.exceptions import ClientAuthenticationError
import logging

logger = logging.getLogger(__name__)

class AzureAuthenticator:
    """Handles Azure authentication using official Azure SDK"""
    
    def __init__(self):
        self.credential = None
        self.token_cache = {}
        
    def get_default_credential(self) -> DefaultAzureCredential:
        """Get default Azure credential (managed identity, CLI, etc.)"""
        try:
            return DefaultAzureCredential()
        except Exception as e:
            logger.error(f"Failed to get default credential: {e}")
            raise
    
    def get_client_secret_credential(self, tenant_id: str, client_id: str, client_secret: str) -> ClientSecretCredential:
        """Get credential using client secret"""
        try:
            return ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret
            )
        except Exception as e:
            logger.error(f"Failed to create client secret credential: {e}")
            raise
    
    def get_interactive_credential(self) -> InteractiveBrowserCredential:
        """Get interactive browser credential"""
        try:
            return InteractiveBrowserCredential()
        except Exception as e:
            logger.error(f"Failed to create interactive credential: {e}")
            raise
    
    def get_token(self, scopes: List[str], credential=None) -> Dict[str, Any]:
        """Acquire access token for specified scopes"""
        if not credential:
            credential = self.get_default_credential()
        
        scope_key = ','.join(sorted(scopes))
        
        # Check cache first
        if scope_key in self.token_cache:
            cached_token = self.token_cache[scope_key]
            # Simple expiry check (tokens typically last 1 hour)
            import time
            if time.time() < cached_token.get('expires_at', 0):
                return cached_token
        
        try:
            token = credential.get_token(*scopes)
            token_data = {
                'token': token.token,
                'expires_at': token.expires_on,
                'scopes': scopes
            }
            
            # Cache the token
            self.token_cache[scope_key] = token_data
            return token_data
            
        except ClientAuthenticationError as e:
            logger.error(f"Authentication failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Token acquisition failed: {e}")
            raise
    
    def get_management_token(self, credential=None) -> str:
        """Get Azure Resource Manager token"""
        scopes = ["https://management.azure.com/.default"]
        token_data = self.get_token(scopes, credential)
        return token_data['token']
    
    def get_graph_token(self, credential=None) -> str:
        """Get Microsoft Graph token"""
        scopes = ["https://graph.microsoft.com/.default"]
        token_data = self.get_token(scopes, credential)
        return token_data['token']
    
    def get_storage_token(self, credential=None) -> str:
        """Get Azure Storage token"""
        scopes = ["https://storage.azure.com/.default"]
        token_data = self.get_token(scopes, credential)
        return token_data['token']
    
    def get_keyvault_token(self, credential=None) -> str:
        """Get Key Vault token"""
        scopes = ["https://vault.azure.net/.default"]
        token_data = self.get_token(scopes, credential)
        return token_data['token']
    
    def validate_token(self, token: str, scope: str) -> bool:
        """Validate if token is still valid"""
        try:
            import jwt
            import time
            
            # Decode without verification to check expiry
            decoded = jwt.decode(token, options={"verify_signature": False})
            exp = decoded.get('exp', 0)
            
            return time.time() < exp
        except Exception:
            return False
    
    def clear_cache(self):
        """Clear token cache"""
        self.token_cache.clear()