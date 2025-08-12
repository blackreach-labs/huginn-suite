#!/usr/bin/env python3
"""Hash cracking tool - command line interface"""

import argparse
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from shared.configuration.hash_config import DB_PATH, SOURCES
from infrastructure.data.repositories.sqlite_hash_repository import SQLiteHashRepository
from infrastructure.external.hash_source_updater import HashSourceUpdater
from domain.services.hash_lookup_manager import HashLookupManager
from application.services.hash_lookup_service import HashLookupService

def main():
    parser = argparse.ArgumentParser(description='Hash Cracking Tool')
    parser.add_argument('hash', nargs='?', help='Hash to crack')
    parser.add_argument('--update', choices=list(SOURCES.keys()), help='Update database from source')
    parser.add_argument('--stats', action='store_true', help='Show database statistics')
    parser.add_argument('--file', help='File containing hashes (one per line)')
    
    args = parser.parse_args()
    
    # Initialize service
    repo = SQLiteHashRepository(DB_PATH)
    updater = HashSourceUpdater(repo)
    manager = HashLookupManager(repo)
    service = HashLookupService(manager, updater)
    
    if args.update:
        print(f"Updating database from {args.update}...")
        try:
            count = service.update_source(args.update)
            print(f"Successfully added {count} hash records")
        except Exception as e:
            print(f"Update failed: {e}")
            return 1
    
    elif args.stats:
        stats = service.get_database_stats()
        print("Database Statistics:")
        print(f"Total hashes: {stats['total']:,}")
        print("\nBy source:")
        for source, count in stats['sources'].items():
            print(f"  {source}: {count:,}")
    
    elif args.file:
        if not os.path.exists(args.file):
            print(f"File not found: {args.file}")
            return 1
        
        with open(args.file, 'r') as f:
            hashes = [line.strip() for line in f if line.strip()]
        
        print(f"Cracking {len(hashes)} hashes...")
        cracked = 0
        
        for hash_value in hashes:
            result = service.lookup_single_hash(hash_value)
            if result:
                print(f"{hash_value}:{result.plaintext}")
                cracked += 1
            else:
                print(f"{hash_value}:NOT_FOUND")
        
        print(f"\nCracked {cracked}/{len(hashes)} hashes ({cracked/len(hashes)*100:.1f}%)")
    
    elif args.hash:
        hash_info = service.get_hash_info(args.hash)
        if not hash_info["valid"]:
            print(f"Invalid hash format: {args.hash}")
            return 1
        
        print(f"Hash: {args.hash}")
        print(f"Type: {hash_info['type']}")
        
        
        result = service.lookup_single_hash(args.hash)
        if result:
            print(f"Plaintext: {result.plaintext}")
            print(f"Source: {result.source}")
            print("Status: CRACKED")
        else:
            print("Status: NOT FOUND")
    
    else:
        parser.print_help()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())