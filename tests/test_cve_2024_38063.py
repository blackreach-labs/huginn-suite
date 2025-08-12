#!/usr/bin/env python3
"""
Test script for CVE-2024-38063 detection
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.advanced_nse_scanner import AdvancedNSEScanner

def test_cve_2024_38063():
    """Test CVE-2024-38063 detection"""
    print("Testing CVE-2024-38063 detection...")
    
    # Test with localhost
    scanner = AdvancedNSEScanner("127.0.0.1", timeout=5)
    
    # Test the specific CVE
    result = scanner.test_cve_2024_38063()
    
    if result:
        print(f"[+] Vulnerability detected: {result['name']}")
        print(f"    CVE: {result['cve']}")
        print(f"    Severity: {result['severity']}")
        print(f"    Evidence: {result['evidence']}")
    else:
        print("[-] No vulnerability detected")
    
    return result

if __name__ == "__main__":
    test_cve_2024_38063()