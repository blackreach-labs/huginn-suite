#!/usr/bin/env python3
"""
Test script to verify Advanced Analytics integration in Huggin UI

This script tests that the advanced analytics components are properly
integrated into the main application UI.
"""

import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(__file__))

def test_analytics_widget_import():
    """Test that the analytics widget can be imported"""
    try:
        from app.widgets.advanced_analytics_widget import create_advanced_analytics_widget
        print("[PASS] Advanced Analytics Widget import successful")
        return True
    except ImportError as e:
        print(f"[FAIL] Advanced Analytics Widget import failed: {e}")
        return False

def test_analytics_engine_import():
    """Test that the analytics engine can be imported"""
    try:
        from app.core.advanced_analytics_engine import create_advanced_analytics_engine
        print("[PASS] Advanced Analytics Engine import successful")
        return True
    except ImportError as e:
        print(f"[FAIL] Advanced Analytics Engine import failed: {e}")
        return False

def test_orchestrator_import():
    """Test that the intelligent orchestrator can be imported"""
    try:
        from app.core.intelligent_scan_orchestrator import create_intelligent_scan_orchestrator
        print("[PASS] Intelligent Scan Orchestrator import successful")
        return True
    except ImportError as e:
        print(f"[FAIL] Intelligent Scan Orchestrator import failed: {e}")
        return False

def test_attack_chain_home_integration():
    """Test that the attack chain home page includes analytics"""
    try:
        # Read the attack chain home file
        with open('app/pages/attack_chain_home.py', 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check for analytics integration
        if 'advanced_analytics_widget' in content and 'Analytics' in content:
            print("[PASS] Attack Chain Home integration successful")
            return True
        else:
            print("[FAIL] Attack Chain Home integration missing")
            return False
    except Exception as e:
        print(f"[FAIL] Attack Chain Home integration test failed: {e}")
        return False

def test_main_window_integration():
    """Test that the main window includes analytics menu"""
    try:
        # Read the main window file
        with open('app/main_window.py', 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check for analytics menu integration
        if 'Advanced Analytics' in content and 'open_advanced_analytics' in content:
            print("[PASS] Main Window integration successful")
            return True
        else:
            print("[FAIL] Main Window integration missing")
            return False
    except Exception as e:
        print(f"[FAIL] Main Window integration test failed: {e}")
        return False

def test_demo_files():
    """Test that demo files exist"""
    demo_files = [
        'examples/advanced_analytics_demo.py',
        'examples/enterprise_intelligence_demo.py'
    ]
    
    all_exist = True
    for demo_file in demo_files:
        if os.path.exists(demo_file):
            print(f"[PASS] Demo file exists: {demo_file}")
        else:
            print(f"[FAIL] Demo file missing: {demo_file}")
            all_exist = False
    
    return all_exist

def main():
    """Run all integration tests"""
    print("Testing Huggin Advanced Analytics Integration")
    print("=" * 50)
    
    tests = [
        test_analytics_widget_import,
        test_analytics_engine_import,
        test_orchestrator_import,
        test_attack_chain_home_integration,
        test_main_window_integration,
        test_demo_files
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
        print("All integration tests passed!")
        print("\nAdvanced Analytics is ready to use:")
        print("   1. Launch Huggin application")
        print("   2. Go to Attack Chain Home")
        print("   3. Click the 'Analytics' tab")
        print("   4. Or use View -> Professional Features -> Advanced Analytics")
        print("\nRun demos:")
        print("   python examples/advanced_analytics_demo.py")
        print("   python examples/enterprise_intelligence_demo.py")
        return 0
    else:
        print("Some integration tests failed")
        return 1

if __name__ == "__main__":
    exit(main())