#!/usr/bin/env python3
# test_port_centralized.py - Test Port centralized data collection

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.tools.port_scanner import PortScanWorker, get_common_ports
from app.core.port_data_collector import create_port_collector
from app.core.centralized_scan_data import centralized_scan_data
from PyQt6.QtCore import QThreadPool
import time

def test_port_collection():
    """Test Port data collection with 192.168.1.106 and common ports"""
    print("Testing Port Centralized Data Collection...")
    
    target = "192.168.1.106"
    common_ports = get_common_ports()
    
    print(f"\n1. Testing port scan for {target}...")
    print(f"   Scanning {len(common_ports)} common ports...")
    
    # Create port scanner worker
    worker = PortScanWorker(
        target=target,
        ports=common_ports,
        scan_type="tcp",
        timeout=2,
        tenant_id="test_tenant"
    )
    
    # Capture results
    results = {}
    def capture_results(result_data):
        results.update(result_data)
    
    worker.signals.results_ready.connect(capture_results)
    
    # Run scan
    worker.run()
    
    print(f"   Scan completed. Found {len(results.get(target, {}).get('open_ports', []))} open ports")
    
    # Display open ports
    if target in results:
        for port_info in results[target]['open_ports']:
            print(f"   - Port {port_info['port']}: {port_info['service']}")
    
    # Test centralized data
    print("\n2. Checking centralized data...")
    port_data = centralized_scan_data.get_scan_data("test_tenant", "port_open_ports")
    print(f"   Open ports stored: {len(port_data)}")
    
    # Test UI data formatting
    print("\n3. Testing UI data formatting...")
    collector = create_port_collector("test_tenant")
    ui_data = collector.get_port_data_for_ui("port_open_ports")
    print(f"   Table data entries: {len(ui_data['table_data'])}")
    print(f"   Graph data categories: {len(ui_data['graph_data'])}")
    
    # Test summary
    print("\n4. Summary...")
    summary = centralized_scan_data.get_scan_summary("test_tenant", "port_open_ports")
    print(f"   Total results: {summary.get('total_results', 0)}")
    print(f"   Unique targets: {summary.get('unique_targets', 0)}")
    
    print("\nPort centralized data collection test completed!")

if __name__ == "__main__":
    test_port_collection()