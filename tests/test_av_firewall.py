#!/usr/bin/env python3
"""
Test script for AV/Firewall enumeration functionality
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.tools.av_firewall_scanner import av_firewall_scanner
from app.tools.av_firewall_utils import run_av_firewall_detection, get_nmap_evasion_techniques

def test_av_firewall_scanner():
    """Test AV/Firewall scanner basic functionality"""
    print("Testing AV/Firewall Scanner...")
    
    # Test WAF detection
    print("\n1. Testing WAF detection...")
    results = av_firewall_scanner.detect_waf("example.com", 80)
    print(f"WAF detection results: {results}")
    
    # Test firewall detection
    print("\n2. Testing firewall detection...")
    results = av_firewall_scanner.detect_firewall_nmap("127.0.0.1")
    print(f"Firewall detection results: {results}")
    
    # Test payload generation
    print("\n3. Testing payload generation...")
    results = av_firewall_scanner.generate_av_test_payload("msfvenom")
    print(f"Payload generation results: {results}")
    
    # Test evasion techniques
    print("\n4. Testing evasion techniques...")
    techniques = get_nmap_evasion_techniques()
    for name, cmd in techniques.items():
        print(f"  {name}: {cmd}")
    
    print("\n[OK] AV/Firewall scanner tests completed!")

def test_output_callback(text):
    """Test output callback"""
    print(f"OUTPUT: {text}")

def test_results_callback(results):
    """Test results callback"""
    print(f"RESULTS: {results}")

def test_av_firewall_worker():
    """Test AV/Firewall worker functionality"""
    print("\nTesting AV/Firewall Worker...")
    
    # Test WAF detection worker
    worker = run_av_firewall_detection(
        target="example.com",
        scan_type="waf",
        port=80,
        output_callback=test_output_callback,
        results_callback=test_results_callback
    )
    
    print(f"WAF Detection Worker created: {worker}")
    
    # Test payload generation worker
    worker = run_av_firewall_detection(
        target="example.com",
        scan_type="payload",
        payload_type="msfvenom",
        output_callback=test_output_callback,
        results_callback=test_results_callback
    )
    
    print(f"Payload Generation Worker created: {worker}")
    print("[OK] AV/Firewall worker test completed!")

if __name__ == "__main__":
    print("AV/Firewall Detection Test Suite")
    print("=" * 40)
    
    try:
        test_av_firewall_scanner()
        test_av_firewall_worker()
        print("\n[SUCCESS] All tests passed!")
    except Exception as e:
        print(f"\n[ERROR] Test failed: {e}")
        import traceback
        traceback.print_exc()