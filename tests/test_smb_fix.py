#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script to verify SMB scanner functionality after architecture migration fixes
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_smb_imports():
    """Test that all SMB-related imports work correctly"""
    print("Testing SMB imports...")
    
    try:
        # Test SMBWorker import
        from app.tools.smb_scanner import SMBWorker, SMBWorkerSignals
        print("[PASS] SMBWorker and SMBWorkerSignals imported successfully")
        
        # Test SMBEnumWorker import (backward compatibility)
        from app.tools.smb_scanner import SMBEnumWorker
        print("[PASS] SMBEnumWorker imported successfully")
        
        # Test smb_utils import
        from app.tools.smb_utils import run_smb_enumeration
        print("[PASS] run_smb_enumeration imported successfully")
        
        # Test SMB data collector
        from app.core.smb_data_collector import create_smb_collector
        print("[PASS] SMB data collector imported successfully")
        
        return True
        
    except ImportError as e:
        print(f"[FAIL] Import error: {e}")
        return False
    except Exception as e:
        print(f"[FAIL] Unexpected error: {e}")
        return False

def test_smb_worker_creation():
    """Test SMBWorker creation with various parameters"""
    print("\nTesting SMBWorker creation...")
    
    try:
        from app.tools.smb_scanner import SMBWorker
        
        # Test basic creation
        worker = SMBWorker(
            target="192.168.1.100",
            scan_type="Basic Info",
            auth_type="Anonymous"
        )
        print("[PASS] Basic SMBWorker created successfully")
        
        # Test with credentials
        worker_creds = SMBWorker(
            target="192.168.1.100",
            scan_type="Share Enumeration",
            auth_type="Credentials",
            domain="TESTDOMAIN",
            username="testuser",
            password="testpass"
        )
        print("[PASS] SMBWorker with credentials created successfully")
        
        # Test signals
        signals = worker.signals
        required_signals = ['output', 'finished', 'results', 'status', 'results_ready']
        for signal_name in required_signals:
            if hasattr(signals, signal_name):
                print(f"[PASS] Signal '{signal_name}' exists")
            else:
                print(f"[FAIL] Signal '{signal_name}' missing")
                return False
        
        return True
        
    except Exception as e:
        print(f"[FAIL] Worker creation error: {e}")
        return False

def test_smb_enum_worker_compatibility():
    """Test SMBEnumWorker backward compatibility"""
    print("\nTesting SMBEnumWorker compatibility...")
    
    try:
        from app.tools.smb_scanner import SMBEnumWorker
        
        # Test old-style creation
        worker = SMBEnumWorker(
            target="192.168.1.100",
            username="testuser",
            password="testpass",
            scan_type="basic"
        )
        print("[PASS] SMBEnumWorker created with old-style parameters")
        
        # Test that it has the expected signals
        signals = worker.signals
        if hasattr(signals, 'results_ready'):
            print("[PASS] results_ready signal exists for compatibility")
        else:
            print("[FAIL] results_ready signal missing")
            return False
        
        return True
        
    except Exception as e:
        print(f"[FAIL] SMBEnumWorker compatibility error: {e}")
        return False

def test_smb_utils_function():
    """Test the run_smb_enumeration utility function"""
    print("\nTesting run_smb_enumeration function...")
    
    try:
        from app.tools.smb_utils import run_smb_enumeration
        
        # Test function signature (don't actually run it)
        import inspect
        sig = inspect.signature(run_smb_enumeration)
        expected_params = ['target', 'username', 'password', 'scan_type', 'output_callback', 'status_callback', 'finished_callback', 'results_callback']
        
        for param in expected_params:
            if param in sig.parameters:
                print(f"[PASS] Parameter '{param}' exists in function signature")
            else:
                print(f"[FAIL] Parameter '{param}' missing from function signature")
                return False
        
        print("[PASS] run_smb_enumeration function signature is correct")
        return True
        
    except Exception as e:
        print(f"[FAIL] SMB utils function error: {e}")
        return False

def test_smb_data_collector():
    """Test SMB data collector functionality"""
    print("\nTesting SMB data collector...")
    
    try:
        from app.core.smb_data_collector import create_smb_collector
        
        # Create collector
        collector = create_smb_collector("test_tenant")
        print("[PASS] SMB data collector created successfully")
        
        # Test methods exist
        required_methods = ['start_smb_scan', 'collect_shares', 'collect_ports', 'collect_vulnerabilities', 'complete_smb_scan']
        for method_name in required_methods:
            if hasattr(collector, method_name):
                print(f"[PASS] Method '{method_name}' exists")
            else:
                print(f"[FAIL] Method '{method_name}' missing")
                return False
        
        return True
        
    except Exception as e:
        print(f"[FAIL] SMB data collector error: {e}")
        return False

def main():
    """Run all SMB scanner tests"""
    print("SMB Scanner Architecture Migration Test")
    print("=" * 50)
    
    tests = [
        test_smb_imports,
        test_smb_worker_creation,
        test_smb_enum_worker_compatibility,
        test_smb_utils_function,
        test_smb_data_collector
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print("=" * 50)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("[SUCCESS] All SMB scanner tests PASSED! The architecture migration fixes are working correctly.")
        return True
    else:
        print(f"[ERROR] {total - passed} tests FAILED. SMB scanner needs additional fixes.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)