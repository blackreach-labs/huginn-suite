#!/usr/bin/env python3
"""
Test script for LDAP enumeration functionality
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.tools.ldap_scanner import ldap_scanner
from app.tools.ldap_utils import run_ldap_enumeration, generate_base_dn_suggestions

def test_ldap_scanner():
    """Test LDAP scanner basic functionality"""
    print("Testing LDAP Scanner...")
    
    # Test basic scan
    print("\n1. Testing basic LDAP scan...")
    results = ldap_scanner.scan_ldap_basic("127.0.0.1", 389, False)
    print(f"Basic scan results: {results}")
    
    # Test anonymous enumeration
    print("\n2. Testing anonymous enumeration...")
    results = ldap_scanner.anonymous_bind_enum("127.0.0.1", 389, "DC=test,DC=com", False)
    print(f"Anonymous enum results: {results}")
    
    # Test base DN suggestions
    print("\n3. Testing base DN suggestions...")
    suggestions = generate_base_dn_suggestions("example.com")
    print(f"Base DN suggestions for 'example.com': {suggestions}")
    
    print("\n[OK] LDAP scanner tests completed!")

def test_output_callback(text):
    """Test output callback"""
    print(f"OUTPUT: {text}")

def test_results_callback(results):
    """Test results callback"""
    print(f"RESULTS: {results}")

def test_ldap_worker():
    """Test LDAP worker functionality"""
    print("\nTesting LDAP Worker...")
    
    worker = run_ldap_enumeration(
        target="127.0.0.1",
        scan_type="basic",
        port=389,
        use_ssl=False,
        output_callback=test_output_callback,
        results_callback=test_results_callback
    )
    
    print(f"Worker created: {worker}")
    print("[OK] LDAP worker test completed!")

if __name__ == "__main__":
    print("LDAP Enumeration Test Suite")
    print("=" * 40)
    
    try:
        test_ldap_scanner()
        test_ldap_worker()
        print("\n[SUCCESS] All tests passed!")
    except Exception as e:
        print(f"\n[ERROR] Test failed: {e}")
        import traceback
        traceback.print_exc()