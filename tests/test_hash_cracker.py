#!/usr/bin/env python3
"""Test hash cracking functionality"""

import os
import sys
import tempfile
import hashlib

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from infrastructure.data.repositories.sqlite_hash_repository import SQLiteHashRepository
from infrastructure.external.hash_source_updater import HashSourceUpdater
from domain.services.hash_lookup_manager import HashLookupManager
from application.services.hash_lookup_service import HashLookupService

def test_hash_cracking():
    """Test basic hash cracking functionality"""
    
    # Create temporary database
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
        db_path = tmp.name
    
    try:
        # Initialize service
        repo = SQLiteHashRepository(db_path)
        updater = HashSourceUpdater(repo)
        manager = HashLookupManager(repo)
        service = HashLookupService(manager, updater)
        
        # Test data
        test_passwords = ["password", "admin", "123456", "test"]
        test_records = []
        
        # Generate test hashes
        for password in test_passwords:
            md5_hash = hashlib.md5(password.encode()).hexdigest()
            sha1_hash = hashlib.sha1(password.encode()).hexdigest()
            test_records.extend([
                (md5_hash, password, "test"),
                (sha1_hash, password, "test")
            ])
        
        # Insert test data
        repo.bulk_insert(test_records)
        
        # Test lookups
        print("Testing hash lookups...")
        
        # Test MD5
        md5_test = hashlib.md5("password".encode()).hexdigest()
        result = service.lookup_single_hash(md5_test)
        assert result is not None, "MD5 lookup failed"
        assert result.plaintext == "password", f"Expected 'password', got '{result.plaintext}'"
        print(f"[OK] MD5 lookup: {md5_test} -> {result.plaintext}")
        
        # Test SHA1
        sha1_test = hashlib.sha1("admin".encode()).hexdigest()
        result = service.lookup_single_hash(sha1_test)
        assert result is not None, "SHA1 lookup failed"
        assert result.plaintext == "admin", f"Expected 'admin', got '{result.plaintext}'"
        print(f"[OK] SHA1 lookup: {sha1_test} -> {result.plaintext}")
        
        # Test not found
        fake_hash = "a" * 32  # Fake MD5
        result = service.lookup_single_hash(fake_hash)
        assert result is None, "Should not find fake hash"
        print(f"[OK] Not found: {fake_hash} -> None")
        
        # Test invalid hash
        result = service.lookup_single_hash("invalid")
        assert result is None, "Should reject invalid hash"
        print("[OK] Invalid hash rejected")
        
        # Test stats
        stats = service.get_database_stats()
        assert stats['total'] == len(test_records), f"Expected {len(test_records)} records, got {stats['total']}"
        print(f"[OK] Stats: {stats['total']} total records")
        
        # Test hash info
        hash_info = service.get_hash_info(md5_test)
        assert hash_info['type'] == "MD5", f"Expected MD5, got {hash_info['type']}"
        assert hash_info['valid'] == True, "Hash should be valid"
        print(f"[OK] Hash info: {hash_info['type']}, valid={hash_info['valid']}")
        
        print("\nAll tests passed!")
        
    finally:
        # Cleanup
        try:
            if os.path.exists(db_path):
                os.unlink(db_path)
        except:
            pass  # Ignore cleanup errors

if __name__ == "__main__":
    test_hash_cracking()