#!/usr/bin/env python3
# test_rpc_centralized.py - Test RPC centralized data collection

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.tools.rpc_scanner import RPCWorker
from app.core.rpc_data_collector import create_rpc_collector
from app.core.centralized_scan_data import centralized_scan_data

def test_rpc_collection():
    """Test RPC data collection with 192.168.1.106 and Anonymous auth"""
    print("Testing RPC Centralized Data Collection...")
    
    target = "192.168.1.106"
    
    print(f"\n1. Testing RPC scan for {target}...")
    print("   Using Anonymous authentication...")
    
    # Create RPC scanner worker with Full Enumeration to get services
    worker = RPCWorker(
        target=target,
        scan_type="Full Enumeration",
        auth_type="Anonymous",
        tenant_id="test_tenant"
    )
    
    # Capture results
    results = {}
    def capture_results(result_data):
        results.update(result_data)
    
    worker.signals.results.connect(capture_results)
    
    # Run scan
    worker.run()
    
    print(f"   Scan completed.")
    
    # Display results
    if results:
        print(f"   RPC endpoints: {len(results.get('rpc_endpoints', []))}")
        print(f"   Services: {len(results.get('services', []))}")
        print(f"   Network endpoints: {len(results.get('endpoints', []))}")
    
    # Test centralized data
    print("\n2. Checking centralized data...")
    rpc_endpoints = centralized_scan_data.get_scan_data("test_tenant", "rpc_endpoints")
    print(f"   RPC endpoints stored: {len(rpc_endpoints)}")
    
    rpc_services = centralized_scan_data.get_scan_data("test_tenant", "rpc_services")
    print(f"   RPC services stored: {len(rpc_services)}")
    
    network_endpoints = centralized_scan_data.get_scan_data("test_tenant", "rpc_network_endpoints")
    print(f"   Network endpoints stored: {len(network_endpoints)}")
    
    # Test UI data formatting
    print("\n3. Testing UI data formatting...")
    collector = create_rpc_collector("test_tenant")
    
    endpoints_ui = collector.get_rpc_data_for_ui("rpc_endpoints")
    print(f"   RPC endpoints table data: {len(endpoints_ui['table_data'])}")
    
    services_ui = collector.get_rpc_data_for_ui("rpc_services")
    print(f"   RPC services table data: {len(services_ui['table_data'])}")
    
    # Test summary
    print("\n4. Summary...")
    summary = centralized_scan_data.get_tenant_overview("test_tenant")
    scan_types = summary.get('scan_types', {})
    print(f"   Total scan types: {len(scan_types)}")
    for scan_type, data in scan_types.items():
        if scan_type.startswith('rpc_'):
            print(f"   - {scan_type}: {data.get('total_results', 0)} results")
    
    print("\nRPC centralized data collection test completed!")

if __name__ == "__main__":
    test_rpc_collection()