"""Hash API client for online lookups"""

import requests
import hashlib
from shared.configuration.hash_config import API_PROVIDERS, API_TIMEOUT
from shared.configuration.global_settings import global_settings

class HashAPIClient:
    def __init__(self):
        self.config = API_PROVIDERS
    
    def query(self, provider_name, hash_value, hash_type):
        """Query online API provider for hash lookup"""
        if provider_name not in self.config:
            return None
        
        cfg = self.config[provider_name]
        
        # Check if hash type is supported
        if hash_type not in cfg["supported"]:
            return None
        
        try:
            if provider_name == "HIBP":
                return self._query_hibp(hash_value)
            elif provider_name == "HashesAPI":
                return self._query_hashes_api(hash_value, cfg)
            elif provider_name == "MD5Decrypt":
                return self._query_md5decrypt(hash_value, hash_type, cfg)
        except Exception:
            return None
        
        return None
    
    def _query_hibp(self, hash_value):
        """Query Have I Been Pwned API"""
        if len(hash_value) != 40:  # SHA1 must be 40 chars
            return None
        
        prefix = hash_value[:5].upper()
        url = self.config["HIBP"]["url"] + prefix
        
        resp = requests.get(url, timeout=API_TIMEOUT)
        if resp.status_code != 200:
            return None
        
        for line in resp.text.splitlines():
            suffix, count = line.split(":")
            if prefix + suffix == hash_value.upper():
                return "<REDACTED>"  # HIBP does not return password
        
        return None
    
    def _query_hashes_api(self, hash_value, cfg):
        """Query hashes.com API"""
        # Get API key from global settings first, fallback to config
        api_key = global_settings.get("api_keys.hashes_com") or cfg["params"]["key"]
        
        # Try exact curl format with form data
        files = {
            'key': (None, api_key),
            'hashes[]': (None, hash_value)
        }
        
        try:
            resp = requests.post(cfg["url"], files=files, timeout=API_TIMEOUT)
            print(f"Hashes.com response: {resp.status_code} - {resp.text}")
            
            if resp.status_code == 200:
                result = resp.json()
                if result.get("success") and result.get("founds"):
                    founds = result["founds"]
                    if len(founds) > 0:
                        return founds[0].get("plaintext")
                elif not result.get("success"):
                    print(f"API Error: {result.get('message', 'Unknown error')}")
                    return f"API_ERROR: {result.get('message', 'Unknown error')}"
        except Exception as e:
            print(f"Hashes.com API error: {e}")
        
        return None
    
    def _query_md5decrypt(self, hash_value, hash_type, cfg):
        """Query MD5Decrypt API"""
        # Get API credentials from global settings first
        email = global_settings.get("api_keys.md5decrypt_email") or cfg["params"]["email"]
        api_key = global_settings.get("api_keys.md5decrypt_key") or cfg["params"]["code"]
        
        # Skip if no valid credentials
        if email == "your_email@example.com" or api_key == "your_api_key_here":
            return None
        
        params = {
            "hash": hash_value,
            "hash_type": hash_type,
            "email": email,
            "code": api_key
        }
        
        try:
            resp = requests.get(cfg["url"], params=params, timeout=API_TIMEOUT)
            if resp.status_code == 200 and resp.text.strip():
                result = resp.text.strip()
                # Check for error responses
                if result.startswith("CODE ERREUR") or "ERROR" in result.upper():
                    return None
                return result
        except Exception:
            pass
        
        return None