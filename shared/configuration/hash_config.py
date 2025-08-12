"""Hash lookup configuration"""

SOURCES = {
    "RockYou": {
        "url": "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt",
        "checksum": "6dfa76aa0e02303994fd1062d0ac983f0b69ece5474d85a5bba36362e19c1076",
        "format": "plaintext_list"
    },
    "SecLists_Passwords": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/main/Passwords/darkweb2017-top1000.txt",
        "checksum": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",  # Placeholder
        "format": "plaintext_list"
    }
}

API_PROVIDERS = {
    "HashesAPI": {
        "url": "https://hashes.com/api/search",
        "params": {"key": "4c654682b2af0433afb5369cf925d1a4"},
        "supported": ["md5", "sha1", "sha256", "sha512", "ntlm"]
    },
    "MD5Decrypt": {
        "url": "https://md5decrypt.net/Api/api.php",
        "params": {"hash": None, "hash_type": None, "email": "your_email@example.com", "code": "your_api_key_here"},
        "supported": ["md5", "sha1", "sha256", "ntlm"]
    },
    "HIBP": {
        "url": "https://api.pwnedpasswords.com/range/",
        "params": {},
        "supported": ["sha1"]
    }
}

DB_PATH = "resources/hash_lookup.db"
CHUNK_SIZE = 10000  # Bulk insert chunk size
MAX_DOWNLOAD_SIZE = 500 * 1024 * 1024  # 500MB max download
TIMEOUT = 30  # Download timeout in seconds
API_TIMEOUT = 10  # API request timeout