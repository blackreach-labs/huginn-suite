#!/usr/bin/env python3
"""Simple test of RPC enumeration functionality"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

from app.core.windows_rpc_client import enumerate_target_rpc

def main():
    print("Testing RPC Enumeration - Complete Assessment (Anonymous)")
    print("=" * 55)
    
    # Test anonymous enumeration
    print("Running anonymous RPC enumeration...")
    result = enumerate_target_rpc('192.168.1.106', '', '', '')
    
    rpc_endpoints = result.get('rpc_endpoints', [])
    endpoints = result.get('endpoints', [])
    services = result.get('services', [])
    service_info = result.get('service_info', {})
    
    print(f"RPC Endpoints: {len(rpc_endpoints)}")
    for ep in rpc_endpoints:
        print(f"  - {ep.get('service', 'Unknown')}: {ep.get('uuid', 'N/A')[:8]}...")
    
    print(f"\nNetwork Endpoints: {len(endpoints)}")
    for ep in endpoints:
        print(f"  - Port {ep.get('port', 'Unknown')}: {ep.get('service', 'Unknown')}")
    
    print(f"\nServices: {len(services)}")
    print(f"Service Info: {len(service_info)}")
    for name, info in service_info.items():
        desc = info.get('description', 'Unknown')
        print(f"  - {name}: {desc}")
    
    if services:
        running = [s for s in services if s.get('state', '').startswith('4')]
        print(f"\nRunning Services ({len(running)}):")
        for svc in running[:10]:
            name = svc.get('name', 'Unknown')
            display = svc.get('display_name', '')
            print(f"  - {name}: {display}")
    
    registry = result.get('registry', {})
    if registry:
        os_info = registry.get('os_info', {})
        if os_info:
            print(f"\nOS Info:")
            for key, value in list(os_info.items())[:3]:
                print(f"  - {key}: {value}")
    
    # Show SAMR/LSA results if available
    samr_domains = result.get('samr_domains', [])
    if samr_domains:
        print(f"\nSAMR Domains: {len(samr_domains)}")
    
    lsa_policy = result.get('lsa_policy', {})
    if lsa_policy:
        domain_name = lsa_policy.get('domain_name', 'Unknown')
        print(f"\nLSA Domain: {domain_name}")
    
    errors = result.get('errors', [])
    if errors:
        print(f"\nErrors: {len(errors)}")
        for error in errors:
            print(f"  - {error}")
    else:
        print("\nNo errors - enumeration successful!")

if __name__ == "__main__":
    main()