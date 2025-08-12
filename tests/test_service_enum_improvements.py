#!/usr/bin/env python3
"""
Test script to verify service enumeration improvements

This script tests the Enter key support and SMB authentication improvements.
"""

import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(__file__))

def test_smb_config_update():
    """Test SMB configuration has been updated with proper fields"""
    try:
        import json
        
        with open('resources/config/tool_configs.json', 'r') as f:
            config = json.load(f)
        
        smb_config = config.get('smb', {})
        
        # Check for required fields
        required_fields = ['smb_domain', 'smb_username', 'smb_password', 'cred_manager_btn']
        found_fields = []
        
        for row in smb_config.get('rows', []):
            for control in row.get('controls', []):
                if control.get('name') in required_fields:
                    found_fields.append(control.get('name'))
        
        if all(field in found_fields for field in required_fields):
            print("[PASS] SMB configuration updated with all required fields")
            return True
        else:
            missing = [f for f in required_fields if f not in found_fields]
            print(f"[FAIL] SMB configuration missing fields: {missing}")
            return False
            
    except Exception as e:
        print(f"[FAIL] SMB configuration test failed: {e}")
        return False

def test_smb_worker_domain_support():
    """Test SMB worker accepts domain parameter"""
    try:
        from app.tools.smb_scanner import SMBWorker
        
        # Test with domain
        worker = SMBWorker(
            target="192.168.1.100",
            auth_type="Credentials",
            domain="CONTOSO",
            username="Administrator",
            password="password123",
            tenant_id="test_tenant"
        )
        
        if hasattr(worker, 'domain') and worker.domain == "CONTOSO":
            print("[PASS] SMB worker supports domain parameter")
            return True
        else:
            print("[FAIL] SMB worker domain parameter not working")
            return False
            
    except Exception as e:
        print(f"[FAIL] SMB worker domain test failed: {e}")
        return False

def test_enter_key_support():
    """Test that Enter key support is added to service enumeration"""
    try:
        # Read the recon enumeration page file
        with open('app/pages/recon_enumeration_page.py', 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check for Enter key support
        if 'returnPressed.connect(lambda: self.run_service_scan(tool_key))' in content:
            print("[PASS] Enter key support added to service enumeration")
            return True
        else:
            print("[FAIL] Enter key support not found in service enumeration")
            return False
            
    except Exception as e:
        print(f"[FAIL] Enter key support test failed: {e}")
        return False

def test_credential_manager_integration():
    """Test credential manager integration for SMB"""
    try:
        # Read the recon enumeration page file
        with open('app/pages/recon_enumeration_page.py', 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check for SMB credential handling
        if "elif tool_key == 'smb_enum':" in content and 'smb_domain' in content:
            print("[PASS] SMB credential manager integration found")
            return True
        else:
            print("[FAIL] SMB credential manager integration missing")
            return False
            
    except Exception as e:
        print(f"[FAIL] Credential manager integration test failed: {e}")
        return False

def main():
    """Run all service enumeration improvement tests"""
    print("Testing Service Enumeration Improvements")
    print("=" * 40)
    
    tests = [
        test_smb_config_update,
        test_smb_worker_domain_support,
        test_enter_key_support,
        test_credential_manager_integration
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print("=" * 40)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("All service enumeration improvement tests passed!")
        print("\nImprovements implemented:")
        print("   1. Enter key support for all service enumeration tools")
        print("   2. SMB authentication fields match RPC (Domain, Username, Password)")
        print("   3. SMB credential manager integration")
        print("   4. Domain parameter support in SMB worker")
        print("\nUsage:")
        print("   - Press Enter in any service target field to start scan")
        print("   - SMB page now has Domain field and credential manager")
        print("   - Credential manager populates all SMB auth fields")
        return 0
    else:
        print("Some service enumeration improvement tests failed")
        return 1

if __name__ == "__main__":
    exit(main())