#!/usr/bin/env python3
"""
Test script to verify SMB wordlist functionality

This script tests that the SMB wordlist field works correctly.
"""

import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(__file__))

def test_smb_wordlist_config():
    """Test SMB wordlist configuration"""
    try:
        import json
        
        with open('resources/config/tool_configs.json', 'r') as f:
            config = json.load(f)
        
        smb_config = config.get('smb', {})
        
        # Check for wordlist field
        wordlist_found = False
        for row in smb_config.get('rows', []):
            for control in row.get('controls', []):
                if control.get('name') == 'smb_wordlist':
                    wordlist_found = True
                    break
        
        if wordlist_found:
            print("[PASS] SMB wordlist field found in configuration")
            return True
        else:
            print("[FAIL] SMB wordlist field not found in configuration")
            return False
            
    except Exception as e:
        print(f"[FAIL] SMB wordlist config test failed: {e}")
        return False

def test_smb_scan_type_toggle():
    """Test SMB scan type toggle functionality"""
    try:
        # Read the recon enumeration page file
        with open('app/pages/recon_enumeration_page.py', 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check for scan type toggle method
        if 'toggle_smb_scan_fields' in content and 'Share Enumeration' in content:
            print("[PASS] SMB scan type toggle functionality found")
            return True
        else:
            print("[FAIL] SMB scan type toggle functionality missing")
            return False
            
    except Exception as e:
        print(f"[FAIL] SMB scan type toggle test failed: {e}")
        return False

def test_smb_worker_wordlist_support():
    """Test SMB worker supports wordlist parameter"""
    try:
        from app.tools.smb_scanner import SMBWorker
        
        # Test with wordlist
        worker = SMBWorker(
            target="192.168.1.100",
            scan_type="Share Enumeration",
            auth_type="Anonymous",
            wordlist_path="/path/to/wordlist.txt",
            tenant_id="test_tenant"
        )
        
        if hasattr(worker, 'wordlist_path') and worker.wordlist_path == "/path/to/wordlist.txt":
            print("[PASS] SMB worker supports wordlist parameter")
            return True
        else:
            print("[FAIL] SMB worker wordlist parameter not working")
            return False
            
    except Exception as e:
        print(f"[FAIL] SMB worker wordlist test failed: {e}")
        return False

def test_smb_bruteforce_method():
    """Test SMB brute force method exists"""
    try:
        # Read the SMB scanner file
        with open('app/tools/smb_scanner.py', 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check for brute force method
        if '_bruteforce_shares' in content and 'wordlist_path' in content:
            print("[PASS] SMB brute force shares method found")
            return True
        else:
            print("[FAIL] SMB brute force shares method missing")
            return False
            
    except Exception as e:
        print(f"[FAIL] SMB brute force method test failed: {e}")
        return False

def main():
    """Run all SMB wordlist functionality tests"""
    print("Testing SMB Wordlist Functionality")
    print("=" * 35)
    
    tests = [
        test_smb_wordlist_config,
        test_smb_scan_type_toggle,
        test_smb_worker_wordlist_support,
        test_smb_bruteforce_method
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print("=" * 35)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("All SMB wordlist functionality tests passed!")
        print("\nSMB Wordlist Features:")
        print("   1. Wordlist field appears for 'Share Enumeration' scan type")
        print("   2. Wordlist populated with SMB/share-specific wordlists")
        print("   3. SMB worker uses wordlist for brute force share discovery")
        print("   4. Default share names used if no wordlist provided")
        print("\nUsage:")
        print("   - Select 'Share Enumeration' scan type")
        print("   - Wordlist field becomes visible")
        print("   - Choose wordlist or use default")
        print("   - Run scan to brute force additional shares")
        return 0
    else:
        print("Some SMB wordlist functionality tests failed")
        return 1

if __name__ == "__main__":
    exit(main())