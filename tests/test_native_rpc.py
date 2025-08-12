#!/usr/bin/env python3
"""
Test native RPC implementation
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from app.core.native_rpc_dump import dump_rpc_endpoints
from app.core.windows_rpc_client import enumerate_target_rpc

def test_native_rpc(target, domain, username, password):
    print(f"Native RPC Enumeration Test: {target}")
    print("=" * 60)
    
    # Test 1: Direct RPC endpoint mapper query
    print("1. Testing RPC endpoint discovery...")
    try:
        endpoints = dump_rpc_endpoints(target, 135, authenticated=True)
        if endpoints:
            print(f"   SUCCESS: Found {len(endpoints)} RPC endpoints")
            for endpoint in endpoints:
                port_info = f" (port {endpoint.get('port', 'unknown')})" if 'port' in endpoint else ""
                print(f"   - {endpoint['protocol']}: {endpoint['uuid']}{port_info}")
        else:
            print("   No endpoints found")
    except Exception as e:
        print(f"   ERROR: {e}")
    
    print()
    
    # Test 2: Complete RPC enumeration with authentication
    print("2. Testing authenticated RPC enumeration...")
    try:
        results = enumerate_target_rpc(target, domain, username, password)
        
        print(f"   Network endpoints: {len(results.get('endpoints', []))}")
        print(f"   Services: {len(results.get('services', []))}")
        print(f"   Registry access: {'Yes' if results.get('registry') else 'No'}")
        print(f"   RPC endpoints: {len(results.get('rpc_endpoints', []))}")
        
        # Show sample results
        services = results.get('services', [])
        if services:
            print(f"\n   Sample services:")
            for service in services[:3]:
                name = service.get('name', 'Unknown')
                state = service.get('state', 'Unknown')
                print(f"   - {name}: {state}")
        
        registry = results.get('registry', {})
        os_info = registry.get('os_info', {})
        if os_info:
            product_name = os_info.get('ProductName', 'Unknown')
            print(f"\n   OS: {product_name}")
        
        rpc_endpoints = results.get('rpc_endpoints', [])
        if rpc_endpoints:
            print(f"\n   RPC Endpoints:")
            for endpoint in rpc_endpoints:
                print(f"   - {endpoint.get('protocol', 'Unknown')}")
        
        if results.get('errors'):
            print(f"\n   Errors:")
            for error in results['errors']:
                print(f"   - {error}")
        
    except Exception as e:
        print(f"   ERROR: {e}")
    
    print("\nNative RPC test completed!")

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: python test_native_rpc.py <target> <domain> <username> <password>")
        print("Example: python test_native_rpc.py 192.168.1.106 LAB Administrator password")
        sys.exit(1)
    
    target = sys.argv[1]
    domain = sys.argv[2]
    username = sys.argv[3]
    password = sys.argv[4]
    
    test_native_rpc(target, domain, username, password)