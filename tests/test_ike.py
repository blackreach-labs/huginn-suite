#!/usr/bin/env python3
"""
Test script for IKE enumeration functionality
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.tools.ike_scanner import ike_scanner
from app.tools.ike_utils import run_ike_enumeration, get_ike_scan_commands, get_ipsec_config_info

def test_ike_scanner():
    """Test IKE scanner basic functionality"""
    print("Testing IKE Scanner...")
    
    # Test basic IKE scan
    print("\n1. Testing IKE basic scan...")
    results = ike_scanner.scan_ike_basic("127.0.0.1", 500)
    print(f"IKE basic scan results: {results}")
    
    # Test detailed IKE scan
    print("\n2. Testing IKE detailed scan...")
    results = ike_scanner.scan_ike_detailed("127.0.0.1", 500, True)
    print(f"IKE detailed scan results: {results}")
    
    # Test IKE scan commands
    print("\n3. Testing IKE scan commands...")
    commands = get_ike_scan_commands()
    for name, cmd in commands.items():
        print(f"  {name}: {cmd}")
    
    # Test IPSec config info
    print("\n4. Testing IPSec config info...")
    config_info = get_ipsec_config_info()
    for name, desc in config_info.items():
        print(f"  {name}: {desc}")
    
    print("\n[OK] IKE scanner tests completed!")

def test_output_callback(text):
    """Test output callback"""
    print(f"OUTPUT: {text}")

def test_results_callback(results):
    """Test results callback"""
    print(f"RESULTS: {results}")

def test_ike_worker():
    """Test IKE worker functionality"""
    print("\nTesting IKE Worker...")
    
    # Test basic worker
    worker = run_ike_enumeration(
        target="127.0.0.1",
        scan_type="basic",
        port=500,
        aggressive_mode=True,
        output_callback=test_output_callback,
        results_callback=test_results_callback
    )
    
    print(f"IKE Worker created: {worker}")
    print("[OK] IKE worker test completed!")

if __name__ == "__main__":
    print("IKE Enumeration Test Suite")
    print("=" * 40)
    
    try:
        test_ike_scanner()
        test_ike_worker()
        print("\n[SUCCESS] All tests passed!")
    except Exception as e:
        print(f"\n[ERROR] Test failed: {e}")
        import traceback
        traceback.print_exc()