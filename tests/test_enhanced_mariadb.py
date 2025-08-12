#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.tools.db_scanner import db_scanner

def test_enhanced_mariadb_basic():
    """Test the enhanced MariaDB basic scan"""
    target = "192.168.1.111"
    port = 3306
    
    print(f"Testing enhanced MariaDB basic scan against {target}:{port}")
    print("=" * 60)
    
    results = db_scanner.scan_mariadb_basic(target, port)
    
    print(f"Target: {results['target']}")
    print(f"Port: {results['port']}")
    print(f"Service: {results['service']}")
    print(f"Accessible: {results['accessible']}")
    
    if results.get('error'):
        print(f"Error: {results['error']}")
    
    if results.get('server_info'):
        print("\nServer Information:")
        for key, value in results['server_info'].items():
            print(f"  {key}: {value}")
    
    if results.get('security_findings'):
        print("\nSecurity Findings:")
        for finding in results['security_findings']:
            print(f"  [{finding['severity']}] {finding['finding']}")
            if finding.get('description'):
                print(f"    {finding['description']}")
    
    print("\nRaw Results:")
    print(results)

if __name__ == "__main__":
    test_enhanced_mariadb_basic()