#!/usr/bin/env python3
"""
Simple test to verify scanner integration
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_integration():
    print("Testing Scanner Integration...")
    
    try:
        # Test LDAP collector
        from app.core.ldap_data_collector import create_ldap_collector
        ldap_collector = create_ldap_collector("test")
        print("[OK] LDAP collector created successfully")
        
        # Test SNMP collector  
        from app.core.snmp_data_collector import create_snmp_collector
        snmp_collector = create_snmp_collector("test")
        print("[OK] SNMP collector created successfully")
        
        # Test centralized data
        from app.core.centralized_scan_data import centralized_scan_data
        overview = centralized_scan_data.get_tenant_overview("test")
        print("[OK] Centralized data access working")
        
        # Test a simple scan simulation
        scan_id = ldap_collector.start_ldap_scan("test.com", "test_scanner")
        ldap_collector.complete_ldap_scan(0)
        print("[OK] LDAP scan simulation completed")
        
        scan_id = snmp_collector.start_snmp_scan("192.168.1.1", "test_scanner")
        snmp_collector.complete_snmp_scan(0)
        print("[OK] SNMP scan simulation completed")
        
        print("\nAll integration tests passed!")
        return True
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_integration()
    sys.exit(0 if success else 1)