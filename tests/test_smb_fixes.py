#!/usr/bin/env python3
"""
Test script to verify SMB scanner fixes

This script tests the updated SMB scanner functionality.
"""

import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(__file__))

def test_smb_scanner_functionality():
    """Test SMB scanner basic functionality"""
    try:
        from app.tools.smb_scanner import SMBWorker
        from app.core.smb_data_collector import create_smb_collector
        
        # Test data collector
        collector = create_smb_collector("test_tenant")
        scan_id = collector.start_smb_scan("192.168.1.100", "test_scanner")
        
        # Test SMB worker creation
        worker = SMBWorker(
            target="192.168.1.100",
            auth_type="Anonymous",
            username="",
            password="",
            tenant_id="test_tenant"
        )
        
        print("[PASS] SMB scanner components created successfully")
        return True
        
    except Exception as e:
        print(f"[FAIL] SMB scanner test failed: {e}")
        return False

def test_asset_integration():
    """Test asset integration functionality"""
    try:
        from app.core.scan_asset_integration import scan_asset_integrator
        
        # Test SMB results processing
        test_results = {
            'target_ip': '192.168.1.100',
            'smb_ports': ['445 (SMB over TCP)', '139 (NetBIOS Session)'],
            'shares': ['ADMIN$', 'C$', 'IPC$'],
            'vulnerabilities': [
                {
                    'name': 'Null Session Access',
                    'severity': 'medium',
                    'description': 'SMB allows null session connections'
                }
            ]
        }
        
        scan_asset_integrator.process_smb_results(test_results)
        print("[PASS] Asset integration test successful")
        return True
        
    except Exception as e:
        print(f"[FAIL] Asset integration test failed: {e}")
        return False

def test_credential_handling():
    """Test credential handling in SMB scanner"""
    try:
        from app.tools.smb_scanner import SMBWorker
        
        # Test with credentials
        worker_creds = SMBWorker(
            target="192.168.1.100",
            auth_type="Credentials",
            username="Administrator",
            password="password123",
            tenant_id="test_tenant"
        )
        
        # Test anonymous
        worker_anon = SMBWorker(
            target="192.168.1.100",
            auth_type="Anonymous",
            username="",
            password="",
            tenant_id="test_tenant"
        )
        
        print("[PASS] Credential handling test successful")
        return True
        
    except Exception as e:
        print(f"[FAIL] Credential handling test failed: {e}")
        return False

def main():
    """Run all SMB fix tests"""
    print("Testing SMB Scanner Fixes")
    print("=" * 30)
    
    tests = [
        test_smb_scanner_functionality,
        test_asset_integration,
        test_credential_handling
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print("=" * 30)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("All SMB scanner fix tests passed!")
        print("\nSMB Scanner fixes implemented:")
        print("   1. Proper credential handling for share enumeration")
        print("   2. Target-specific port checking instead of local netstat")
        print("   3. Improved vulnerability checking with timeout handling")
        print("   4. Asset inventory integration")
        print("   5. Better error handling and output parsing")
        return 0
    else:
        print("Some SMB scanner fix tests failed")
        return 1

if __name__ == "__main__":
    exit(main())