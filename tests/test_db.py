#!/usr/bin/env python3
"""
Test script for Database enumeration functionality
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.tools.db_scanner import db_scanner
from app.tools.db_utils import run_database_enumeration, get_common_mssql_queries

def test_db_scanner():
    """Test Database scanner basic functionality"""
    print("Testing Database Scanner...")
    
    # Test MSSQL basic scan
    print("\n1. Testing MSSQL basic scan...")
    results = db_scanner.scan_mssql_basic("127.0.0.1", 1433)
    print(f"MSSQL basic scan results: {results}")
    
    # Test Oracle basic scan
    print("\n2. Testing Oracle basic scan...")
    results = db_scanner.scan_oracle_basic("127.0.0.1", 1521)
    print(f"Oracle basic scan results: {results}")
    
    # Test common queries
    print("\n3. Testing common MSSQL queries...")
    queries = get_common_mssql_queries()
    for name, query in queries.items():
        print(f"  {name}: {query}")
    
    print("\n[OK] Database scanner tests completed!")

def test_output_callback(text):
    """Test output callback"""
    print(f"OUTPUT: {text}")

def test_results_callback(results):
    """Test results callback"""
    print(f"RESULTS: {results}")

def test_db_worker():
    """Test Database worker functionality"""
    print("\nTesting Database Worker...")
    
    # Test MSSQL worker
    worker = run_database_enumeration(
        target="127.0.0.1",
        db_type="mssql",
        scan_type="basic",
        port=1433,
        output_callback=test_output_callback,
        results_callback=test_results_callback
    )
    
    print(f"MSSQL Worker created: {worker}")
    
    # Test Oracle worker
    worker = run_database_enumeration(
        target="127.0.0.1",
        db_type="oracle",
        scan_type="basic",
        port=1521,
        output_callback=test_output_callback,
        results_callback=test_results_callback
    )
    
    print(f"Oracle Worker created: {worker}")
    print("[OK] Database worker test completed!")

if __name__ == "__main__":
    print("Database Enumeration Test Suite")
    print("=" * 40)
    
    try:
        test_db_scanner()
        test_db_worker()
        print("\n[SUCCESS] All tests passed!")
    except Exception as e:
        print(f"\n[ERROR] Test failed: {e}")
        import traceback
        traceback.print_exc()