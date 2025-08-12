#!/usr/bin/env python3
"""
Test Windows RPC enumeration
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from app.core.windows_rpc_client import enumerate_target_rpc

def main():
    if len(sys.argv) < 5:
        print("Usage: python test_windows_rpc.py <target> <domain> <username> <password>")
        sys.exit(1)
    
    target = sys.argv[1]
    domain = sys.argv[2]
    username = sys.argv[3]
    password = sys.argv[4]
    
    print(f"Windows RPC Enumeration: {target}")
    print(f"Domain: {domain}, Username: {username}")
    print("-" * 50)
    
    results = enumerate_target_rpc(target, domain, username, password)
    
    # Display results
    print(f"Network Endpoints: {len(results['endpoints'])}")
    for endpoint in results['endpoints']:
        print(f"  - Port {endpoint['port']}: {endpoint['service']}")
    
    print(f"\nServices: {len(results['services'])}")
    for service in results['services'][:10]:  # Show first 10
        name = service.get('name', 'Unknown')
        state = service.get('state', 'Unknown')
        print(f"  - {name}: {state}")
    
    if len(results['services']) > 10:
        print(f"  ... and {len(results['services']) - 10} more services")
    
    registry = results.get('registry', {})
    os_info = registry.get('os_info', {})
    if os_info:
        print(f"\nOS Information:")
        for key, value in list(os_info.items())[:5]:
            print(f"  - {key}: {value}")
    
    print(f"\nRPC Endpoints: {len(results['rpc_endpoints'])}")
    for rpc_endpoint in results['rpc_endpoints']:
        print(f"  - {rpc_endpoint.get('endpoint', 'Unknown')}: {rpc_endpoint.get('uuid', 'No UUID')}")
    
    if results['errors']:
        print(f"\nErrors:")
        for error in results['errors']:
            print(f"  - {error}")
    
    print(f"\nEnumeration completed successfully!")

if __name__ == "__main__":
    main()