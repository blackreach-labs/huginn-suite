#!/usr/bin/env python3
"""
SMB Scanner Centralized Data Collection Demo
Demonstrates SMB scanner integration with centralized data collection system
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.core.smb_data_collector import create_smb_collector
from app.core.unified_ui_integration import create_unified_integration
import time

def demo_smb_centralized_data():
    """Demonstrate SMB scanner with centralized data collection"""
    
    print("SMB Scanner Centralized Data Collection Demo")
    print("=" * 60)
    
    # Create tenant-specific collector
    tenant_id = "demo_company"
    smb_collector = create_smb_collector(tenant_id)
    
    print(f"Created SMB collector for tenant: {tenant_id}")
    
    # Simulate SMB scan data collection
    target = "192.168.1.100"
    
    # Start SMB scan
    scan_id = smb_collector.start_smb_scan(target, "smb_scanner")
    print(f"Started SMB scan: {scan_id}")
    
    # Simulate collecting SMB shares
    shares_data = ["ADMIN$", "C$", "IPC$", "Users", "Public"]
    smb_collector.collect_shares(target, shares_data)
    print(f"Collected {len(shares_data)} SMB shares")
    
    # Simulate collecting SMB ports
    ports_data = ["445 (SMB over TCP)", "139 (NetBIOS Session)"]
    smb_collector.collect_ports(target, ports_data)
    print(f"Collected {len(ports_data)} SMB ports")
    
    # Simulate collecting vulnerabilities
    vulns_data = [
        {
            'name': 'Null Session Access',
            'severity': 'medium',
            'description': 'SMB allows null session connections'
        },
        {
            'name': 'Guest Account Access',
            'severity': 'low',
            'description': 'SMB allows guest account access'
        }
    ]
    smb_collector.collect_vulnerabilities(target, vulns_data)
    print(f"Collected {len(vulns_data)} SMB vulnerabilities")
    
    # Complete scan
    total_results = len(shares_data) + len(ports_data) + len(vulns_data)
    smb_collector.complete_smb_scan(total_results)
    print(f"Completed SMB scan with {total_results} total results")
    
    print("\n" + "=" * 60)
    print("Data Retrieval and UI Integration")
    print("=" * 60)
    
    # Test UI data formatting
    ui_integration = create_unified_integration(tenant_id)
    
    # Get formatted data for different scan types
    scan_types = ["smb_shares", "smb_ports", "smb_vulnerabilities"]
    
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
    
    # Get all SMB data for tenant
    all_smb_data = smb_collector.get_smb_data()
    
    print(f"Total Shares: {len(all_smb_data['shares'])}")
    print(f"Total Ports: {len(all_smb_data['ports'])}")
    print(f"Total Vulnerabilities: {len(all_smb_data['vulnerabilities'])}")
    
    # Show sample data
    if all_smb_data['shares']:
        print(f"\nSample Share Data:")
        sample_share = all_smb_data['shares'][0]
        print(f"   Target: {sample_share['data']['target']}")
        print(f"   Share: {sample_share['data']['share_name']}")
        print(f"   Count: {sample_share['count']}")
        print(f"   First Seen: {sample_share['first_seen']}")
    
    if all_smb_data['vulnerabilities']:
        print(f"\nSample Vulnerability Data:")
        sample_vuln = all_smb_data['vulnerabilities'][0]
        print(f"   Target: {sample_vuln['data']['target']}")
        print(f"   Vulnerability: {sample_vuln['data']['vulnerability_name']}")
        print(f"   Severity: {sample_vuln['data']['severity']}")
        print(f"   Description: {sample_vuln['data']['description']}")
    
    print("\n" + "=" * 60)
    print("SMB Scanner Integration Complete!")
    print("=" * 60)
    print("Key Features Demonstrated:")
    print("   • Centralized data collection with tenant isolation")
    print("   • Smart deduplication with count tracking")
    print("   • UI-ready data formatting")
    print("   • Real-time data retrieval")
    print("   • Comprehensive scan metadata")
    print("   • Multi-format data export capability")

if __name__ == "__main__":
    demo_smb_centralized_data()