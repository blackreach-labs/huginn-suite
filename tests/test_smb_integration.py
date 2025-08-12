#!/usr/bin/env python3
"""
Test script to verify SMB scanner integration with centralized data collection

This script tests that the SMB scanner properly integrates with the
centralized data collection system and reconnaissance page.
"""

import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(__file__))

def test_smb_data_collector():
    """Test SMB data collector functionality"""
    try:
        from app.core.smb_data_collector import create_smb_collector
        
        collector = create_smb_collector("test_tenant")
        
        # Test scan lifecycle
        scan_id = collector.start_smb_scan("192.168.1.100", "test_scanner")
        print(f"[PASS] SMB scan started with ID: {scan_id}")
        
        # Test data collection
        collector.collect_shares("192.168.1.100", ["ADMIN$", "C$", "IPC$"])
        collector.collect_ports("192.168.1.100", ["445 (SMB over TCP)", "139 (NetBIOS Session)"])
        
        # Test vulnerability collection
        vulns = [
            {"name": "Null Session Access", "severity": "medium", "description": "SMB allows null session connections"}
        ]
        collector.collect_vulnerabilities("192.168.1.100", vulns)
        
        # Complete scan
        collector.complete_smb_scan(5)
        
        # Retrieve data
        data = collector.get_smb_data("192.168.1.100")
        
        if data['shares'] and data['ports'] and data['vulnerabilities']:
            print("[PASS] SMB data collection successful")
            return True
        else:
            print("[FAIL] SMB data collection incomplete")
            return False
            
    except Exception as e:
        print(f"[FAIL] SMB data collector test failed: {e}")
        return False

def test_smb_scanner_import():
    """Test SMB scanner import"""
    try:
        from app.tools.smb_scanner import SMBWorker
        print("[PASS] SMB scanner import successful")
        return True
    except ImportError as e:
        print(f"[FAIL] SMB scanner import failed: {e}")
        return False

def test_recon_page_integration():
    """Test reconnaissance page SMB integration"""
    try:
        # Read the recon enumeration page file
        with open('app/pages/recon_enumeration_page.py', 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check for SMB integration
        if 'run_smb_enumeration' in content and 'smb_enum' in content:
            print("[PASS] Reconnaissance page SMB integration found")
            return True
        else:
            print("[FAIL] Reconnaissance page SMB integration missing")
            return False
    except Exception as e:
        print(f"[FAIL] Reconnaissance page integration test failed: {e}")
        return False

def test_centralized_data_integration():
    """Test centralized data system integration"""
    try:
        from app.core.centralized_scan_data import create_centralized_scan_data
        
        db = create_centralized_scan_data()
        
        # Test SMB data storage
        import uuid
        scan_id = str(uuid.uuid4())
        db.start_scan(scan_id, "test_tenant", "smb_enum", "192.168.1.100", "test_scanner")
        
        db.add_scan_result(
            scan_id=scan_id,
            tenant_id="test_tenant",
            scan_type="smb_shares",
            target="192.168.1.100",
            scanner="test_scanner",
            result_data={"target": "192.168.1.100", "share_name": "ADMIN$"}
        )
        
        # Retrieve data
        shares_data = db.get_scan_data("test_tenant", "smb_shares")
        
        if shares_data:
            print("[PASS] Centralized data integration successful")
            return True
        else:
            print("[FAIL] Centralized data integration failed")
            return False
            
    except Exception as e:
        print(f"[FAIL] Centralized data integration test failed: {e}")
        return False

def main():
    """Run all SMB integration tests"""
    print("Testing SMB Scanner Integration with Centralized Data Collection")
    print("=" * 65)
    
    tests = [
        test_smb_scanner_import,
        test_smb_data_collector,
        test_recon_page_integration,
        test_centralized_data_integration
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print("=" * 65)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("All SMB integration tests passed!")
        print("\nSMB Scanner is ready to use:")
        print("   1. Launch Huggin application")
        print("   2. Go to Reconnaissance & Enumeration")
        print("   3. Click Service Enumeration tab")
        print("   4. Click SMB sub-tab")
        print("   5. Enter target and configure authentication")
        print("   6. Click Run to start SMB enumeration")
        print("\nData will be automatically collected in centralized database")
        print("with tenant isolation and real-time UI updates.")
        return 0
    else:
        print("Some SMB integration tests failed")
        return 1

if __name__ == "__main__":
    exit(main())