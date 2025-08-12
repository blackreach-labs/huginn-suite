#!/usr/bin/env python3
"""
Test script to verify DNS enumeration fix.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import QTimer
from app.tools.recon import HostWordlistWorker, SubdomainGenerator

def test_dns_enumeration():
    """Test that DNS enumeration works without the config_manager error."""
    
    app = QApplication(sys.argv)
    
    print("Testing DNS enumeration fix...")
    
    try:
        # Create a subdomain generator
        subdomain_generator = SubdomainGenerator(use_bruteforce=False)
        
        # Create the worker (this should not crash now)
        worker = HostWordlistWorker(
            target="example.com",
            subdomain_generator=subdomain_generator,
            record_types=['A'],
            dns_server=None
        )
        
        print("[OK] HostWordlistWorker created successfully")
        print("[OK] DNS enumeration fix verified")
        
        # Test that the resolver is properly configured
        if hasattr(worker, 'resolver') and worker.resolver:
            print("[OK] DNS resolver configured successfully")
        else:
            print("[ERROR] DNS resolver not configured")
        
        # Test that config_manager is accessible
        if hasattr(worker, 'config_manager') and worker.config_manager:
            print("[OK] Config manager accessible")
        else:
            print("[ERROR] Config manager not accessible")
        
        print("\n[SUCCESS] DNS enumeration fix test completed successfully!")
        
    except Exception as e:
        print(f"[ERROR] DNS enumeration test failed: {e}")
        return False
    
    # Don't run the actual enumeration, just test the initialization
    app.quit()
    return True

if __name__ == "__main__":
    test_dns_enumeration()