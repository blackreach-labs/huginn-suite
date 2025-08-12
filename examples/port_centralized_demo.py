#!/usr/bin/env python3
"""
Port Scanner Centralized Data Collection Demo
Demonstrates Port scanner integration with centralized data collection system
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.core.port_data_collector import create_port_collector
from app.core.unified_ui_integration import create_unified_integration
import time

def demo_port_centralized_data():
    """Demonstrate Port scanner with centralized data collection"""
    
    print("Port Scanner Centralized Data Collection Demo")
    print("=" * 60)
    
    # Create tenant-specific collector
    tenant_id = "demo_company"
    port_collector = create_port_collector(tenant_id)
    
    print(f"Created Port collector for tenant: {tenant_id}")
    
    # Simulate Port scan data collection
    target = "192.168.1.100"
    
    # Start Port scan
    scan_id = port_collector.start_port_scan(target, "tcp_port_scanner", "tcp_scan")
    print(f"Started Port scan: {scan_id}")
    
    # Simulate collecting open ports
    open_ports = [
        {'port': 22, 'protocol': 'tcp', 'state': 'open', 'service': 'ssh', 'version': 'OpenSSH 8.0', 'banner': 'SSH-2.0-OpenSSH_8.0'},
        {'port': 80, 'protocol': 'tcp', 'state': 'open', 'service': 'http', 'version': 'Apache 2.4', 'banner': 'Apache/2.4.41'},
        {'port': 443, 'protocol': 'tcp', 'state': 'open', 'service': 'https', 'version': 'Apache 2.4', 'banner': 'Apache/2.4.41'},
        {'port': 3306, 'protocol': 'tcp', 'state': 'open', 'service': 'mysql', 'version': 'MySQL 8.0', 'banner': 'MySQL 8.0.25'},
        {'port': 5432, 'protocol': 'tcp', 'state': 'open', 'service': 'postgresql', 'version': 'PostgreSQL 13', 'banner': 'PostgreSQL 13.3'}
    ]
    port_collector.collect_open_ports(target, open_ports)
    print(f"Collected {len(open_ports)} open ports")
    
    # Simulate collecting service detection data
    services = [
        {'port': 22, 'service': 'ssh', 'version': 'OpenSSH 8.0', 'product': 'OpenSSH', 'confidence': 95},
        {'port': 80, 'service': 'http', 'version': 'Apache 2.4.41', 'product': 'Apache httpd', 'confidence': 90},
        {'port': 443, 'service': 'https', 'version': 'Apache 2.4.41', 'product': 'Apache httpd', 'confidence': 90},
        {'port': 3306, 'service': 'mysql', 'version': '8.0.25', 'product': 'MySQL', 'confidence': 85}
    ]
    port_collector.collect_service_detection(target, services)
    print(f"Collected {len(services)} service detections")
    
    # Simulate collecting OS detection data
    os_info = {
        'os_family': 'Linux',
        'os_version': 'Ubuntu 20.04',
        'accuracy': 85,
        'fingerprint': 'Linux 5.4.x (Ubuntu 20.04)'
    }
    port_collector.collect_os_detection(target, os_info)
    print(f"Collected OS detection data")
    
    # Complete scan
    total_results = len(open_ports) + len(services) + 1  # +1 for OS detection
    port_collector.complete_port_scan(total_results)
    print(f"Completed Port scan with {total_results} total results")
    
    print("\n" + "=" * 60)
    print("Data Retrieval and UI Integration")
    print("=" * 60)
    
    # Test UI data formatting
    ui_integration = create_unified_integration(tenant_id)
    
    # Get formatted data for different scan types
    scan_types = ["port_open_ports", "port_services"]
    
    for scan_type in scan_types:
        print(f"\n{scan_type.upper()} Data:")
        ui_data = ui_integration.get_data_for_scan_type(scan_type, target)
        
        print(f"  Table Data: {len(ui_data['table_data'])} rows")
        if ui_data['table_data']:
            print(f"     Headers: {list(ui_data['table_data'][0].keys())}")
        
        print(f"  Graph Data: {len(ui_data['graph_data'])} categories")
        for category, data in ui_data['graph_data'].items():
            print(f"     {category}: {data['count']} items - {data['details']}")
        
        print(f"  Summary: {ui_data['summary']}")
    
    print("\n" + "=" * 60)
    print("Tenant Data Overview")
    print("=" * 60)
    
    # Get all Port data for tenant
    all_port_data = {}
    for scan_type in scan_types:
        ui_data = port_collector.get_port_data_for_ui(scan_type)
        all_port_data[scan_type] = ui_data
    
    print(f"Total Open Ports: {len(all_port_data['port_open_ports']['table_data'])}")
    print(f"Total Services: {len(all_port_data['port_services']['table_data'])}")
    
    # Show sample data
    if all_port_data['port_open_ports']['table_data']:
        print(f"\nSample Open Port Data:")
        sample_port = all_port_data['port_open_ports']['table_data'][0]
        print(f"   Port: {sample_port['Port']}")
        print(f"   Protocol: {sample_port['Protocol']}")
        print(f"   Service: {sample_port['Service']}")
        print(f"   State: {sample_port['State']}")
        print(f"   Count: {sample_port['Count']}")
    
    if all_port_data['port_services']['table_data']:
        print(f"\nSample Service Data:")
        sample_service = all_port_data['port_services']['table_data'][0]
        print(f"   Port: {sample_service['Port']}")
        print(f"   Service: {sample_service['Service']}")
        print(f"   Product: {sample_service['Product']}")
        print(f"   Version: {sample_service['Version']}")
        print(f"   Confidence: {sample_service['Confidence']}")
    
    print("\n" + "=" * 60)
    print("Port Scanner Integration Complete!")
    print("=" * 60)
    print("Key Features Demonstrated:")
    print("   • Centralized data collection with tenant isolation")
    print("   • Smart deduplication with count tracking")
    print("   • UI-ready data formatting")
    print("   • Real-time data retrieval")
    print("   • Comprehensive scan metadata")
    print("   • Multi-format data export capability")

if __name__ == "__main__":
    demo_port_centralized_data()