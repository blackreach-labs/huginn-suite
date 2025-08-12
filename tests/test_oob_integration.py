#!/usr/bin/env python3
"""
Test script for OOB integration with HTTP fingerprinting
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

from app.tools.http_fingerprint import HTTPFingerprinter
from app.core.listener_manager import listener_manager

def test_oob_integration():
    """Test the OOB integration"""
    
    print("[TEST] Testing OOB integration with HTTP fingerprinting")
    
    # Create a mock listener for testing
    listener_id = listener_manager.create_listener(8080, 'http', '127.0.0.1')
    print(f"[TEST] Created test listener: {listener_id}")
    
    # Start the listener
    if listener_manager.start_listener(listener_id):
        print("[TEST] Listener started successfully")
    else:
        print("[TEST] Failed to start listener")
        return
    
    # Create fingerprinter with listener manager
    fingerprinter = HTTPFingerprinter()
    fingerprinter.listener_manager = listener_manager
    
    # Test the _get_attacker_ip method
    attacker_ip = fingerprinter._get_attacker_ip()
    print(f"[TEST] Detected attacker IP: {attacker_ip}")
    
    # Test sandbox detection (this would normally be called during fingerprinting)
    print("[TEST] Testing sandbox detection logic...")
    
    # Mock a sandbox detection result
    dangerous_classes = [(59, 'subprocess.Popen'), (104, 'os._wrap_close')]
    
    # This would normally be called internally
    try:
        from app.tools.oob_tester import multi_channel_oob_test
        
        print("[TEST] Testing multi-channel OOB...")
        results = multi_channel_oob_test(
            target_url="http://httpbin.org/post",  # Safe test target
            attacker_ip=attacker_ip,
            dns_domain="test.interact.sh",
            dangerous_classes=dangerous_classes,
            listener_manager=listener_manager
        )
        
        print(f"[TEST] OOB test results:")
        print(f"  - Payloads sent: {results.get('payloads_sent', 0)}")
        print(f"  - Success: {results.get('success', False)}")
        print(f"  - HTTP callbacks: {len(results.get('http_callbacks', []))}")
        print(f"  - Netcat callbacks: {len(results.get('netcat_callbacks', []))}")
        print(f"  - DNS callbacks: {len(results.get('dns_callbacks', []))}")
        
        if results.get('error'):
            print(f"  - Error: {results['error']}")
        
    except Exception as e:
        print(f"[TEST] OOB test failed: {e}")
    
    # Stop the listener
    listener_manager.stop_listener(listener_id)
    print("[TEST] Test completed")

if __name__ == "__main__":
    test_oob_integration()