"""Hash API client for online lookups"""

import requests
import hashlib
from shared.configuration.hash_config import API_PROVIDERS, API_TIMEOUT
from shared.configuration.global_settings import global_settings
import logging

logger = logging.getLogger(__name__)


class HashAPIClient:
    def __init__(self):
        self.config = API_PROVIDERS

    def query(self, provider_name, hash_value, hash_type):
        """Query online API provider for hash lookup"""
        if provider_name not in self.config:
            return None

        cfg = self.config[provider_name]

        # Check if hash type is supported
        if hash_type and hash_type not in cfg.get("supported", []):
            return None

        try:
            if provider_name == "HIBP":
                return self._query_hibp(hash_value, hash_type)
            elif provider_name == "HashesAPI":
                return self._query_hashes_api(hash_value, cfg)
            elif provider_name == "MD5Decrypt":
                return self._query_md5decrypt(hash_value, hash_type, cfg)
        except Exception as e:
            logger.debug(f"API query error ({provider_name}): {e}")
            return None

        return None

    def _query_hibp(self, hash_value, hash_type):
        """
        Query Have I Been Pwned + free reverse lookup APIs.

        HIBP only confirms existence. We also try free reverse-lookup
        services to get the actual plaintext.
        """
        # First try free reverse lookup APIs that return plaintext
        plaintext = self._try_free_reverse_lookup(hash_value, hash_type)
        if plaintext:
            return plaintext

        # Fall back to HIBP existence check (SHA1 only)
        if len(hash_value) == 40:
            prefix = hash_value[:5].upper()
            url = self.config["HIBP"]["url"] + prefix

            try:
                resp = requests.get(url, timeout=API_TIMEOUT)
                if resp.status_code == 200:
                    for line in resp.text.splitlines():
                        parts = line.split(":")
                        if len(parts) == 2:
                            suffix = parts[0]
                            if prefix + suffix == hash_value.upper():
                                return "<REDACTED>"
            except Exception as e:
                logger.debug(f"HIBP query error: {e}")

        return None

    def _try_free_reverse_lookup(self, hash_value, hash_type):
        """
        Try multiple free hash reverse-lookup APIs that return plaintext.
        These don't require API keys.
        """
        # 1. nitrxgen.net (MD5, SHA1, SHA256)
        plaintext = self._query_nitrxgen(hash_value)
        if plaintext:
            return plaintext

        # 2. hashtoolkit.com
        plaintext = self._query_hashtoolkit(hash_value, hash_type)
        if plaintext:
            return plaintext

        return None

    def _query_nitrxgen(self, hash_value):
        """Query nitrxgen.net free hash lookup API."""
        try:
            url = "https://www.nitrxgen.net/md5db/" + hash_value
            resp = requests.get(url, timeout=API_TIMEOUT, headers={
                "User-Agent": "Mozilla/5.0"
            })
            if resp.status_code == 200 and resp.text.strip():
                result = resp.text.strip()
                # API returns empty string if not found
                if result and len(result) < 200:
                    return result
        except Exception as e:
            logger.debug(f"nitrxgen query error: {e}")
        return None

    def _query_hashtoolkit(self, hash_value, hash_type):
        """Query hashtoolkit.com for reverse hash lookup."""
        try:
            # hashtoolkit uses a simple GET API
            type_map = {"md5": "md5", "sha1": "sha1", "sha256": "sha256"}
            ht = type_map.get(hash_type, "md5")
            url = f"https://hashtoolkit.com/reverse-hash?hash={hash_value}"
            resp = requests.get(url, timeout=API_TIMEOUT, headers={
                "User-Agent": "Mozilla/5.0"
            })
            if resp.status_code == 200:
                # Parse the HTML response for the plaintext
                import re
                match = re.search(
                    r'<span class="res-text"[^>]*>([^<]+)</span>', resp.text
                )
                if match:
                    return match.group(1).strip()
        except Exception as e:
            logger.debug(f"hashtoolkit query error: {e}")
        return None

    def _query_hashes_api(self, hash_value, cfg):
        """Query hashes.com API"""
        api_key = global_settings.get("api_keys.hashes_com") or cfg["params"].get("key", "")

        if not api_key or api_key == "your_api_key_here":
            return "API_ERROR: API key not configured. Set 'hashes_com' in Global Settings → API Keys."

        files = {
            'key': (None, api_key),
            'hashes[]': (None, hash_value)
        }

        try:
            resp = requests.post(cfg["url"], files=files, timeout=API_TIMEOUT)

            if resp.status_code == 200:
                result = resp.json()
                if result.get("success") and result.get("founds"):
                    founds = result["founds"]
                    if len(founds) > 0:
                        return founds[0].get("plaintext")
                elif not result.get("success"):
                    msg = result.get("message", "Unknown error")
                    return f"API_ERROR: {msg}"
        except requests.exceptions.Timeout:
            return "API_ERROR: Request timed out"
        except Exception as e:
            logger.debug(f"hashes.com API error: {e}")

        return None

    def _query_md5decrypt(self, hash_value, hash_type, cfg):
        """Query MD5Decrypt API"""
        email = global_settings.get("api_keys.md5decrypt_email") or cfg["params"].get("email", "")
        api_key = global_settings.get("api_keys.md5decrypt_key") or cfg["params"].get("code", "")

        if not email or email == "your_email@example.com":
            return "API_ERROR: MD5Decrypt email not configured. Set in Global Settings → API Keys."
        if not api_key or api_key == "your_api_key_here":
            return "API_ERROR: MD5Decrypt API key not configured. Set in Global Settings → API Keys."

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
                if result.startswith("CODE ERREUR") or "ERROR" in result.upper():
                    return None
                return result
        except requests.exceptions.Timeout:
            return "API_ERROR: Request timed out"
        except Exception as e:
            logger.debug(f"MD5Decrypt API error: {e}")

        return None
