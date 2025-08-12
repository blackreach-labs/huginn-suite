#!/usr/bin/env python3

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_rpc_enumeration():
    print("=== Testing RPC Enumeration ===")
    
    try:
        from app.core.windows_rpc_client import enumerate_target_rpc
        print("[OK] Successfully imported enumerate_target_rpc")
        
        target = '192.168.1.106'
        print(f"Testing target: {target}")
        
        # Test anonymous enumeration
        print("Running anonymous enumeration...")
        results = enumerate_target_rpc(target, '', '', '')
        
        print(f"Results type: {type(results)}")
        if isinstance(results, dict):
            print(f"Keys: {list(results.keys())}")
            print(f"Target: {results.get('target', 'N/A')}")
            print(f"Endpoints: {len(results.get('endpoints', []))}")
            print(f"Services: {len(results.get('services', []))}")
            print(f"RPC endpoints: {len(results.get('rpc_endpoints', []))}")
            print(f"Registry: {bool(results.get('registry'))}")
            print(f"Errors: {len(results.get('errors', []))}")
            
            if results.get('errors'):
                print("Errors found:")
                for error in results['errors']:
                    print(f"  - {error}")
            
            if results.get('endpoints'):
                print("Network endpoints:")
                for ep in results['endpoints']:
                    print(f"  - Port {ep.get('port')}: {ep.get('service')}")
            
            if results.get('services'):
                print(f"Services found ({len(results['services'])}):")
                for svc in results['services'][:5]:
                    print(f"  - {svc.get('name')}: {svc.get('state')}")
        else:
            print(f"Unexpected result type: {results}")
            
    except ImportError as e:
        print(f"[ERROR] Import failed: {e}")
    except Exception as e:
        print(f"[ERROR] Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_rpc_enumeration()