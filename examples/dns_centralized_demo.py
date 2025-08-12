#!/usr/bin/env python3
"""
DNS Scanner Centralized Data Collection Demo
Demonstrates DNS scanner integration with centralized data collection system
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.core.dns_data_collector import create_dns_collector
from app.core.unified_ui_integration import create_unified_integration
import time

def demo_dns_centralized_data():
    """Demonstrate DNS scanner with centralized data collection"""
    
    print("DNS Scanner Centralized Data Collection Demo")
    print("=" * 60)
    
    # Create tenant-specific collector
    tenant_id = "demo_company"
    dns_collector = create_dns_collector(tenant_id)
    
    print(f"Created DNS collector for tenant: {tenant_id}")
    
    # Simulate DNS scan data collection
    target = "example.com"
    
    # Start DNS scan
    scan_id = dns_collector.start_dns_scan(target, "dns_enumerator", "subdomain_enumeration")
    print(f"Started DNS scan: {scan_id}")
    
    # Simulate collecting subdomains
    subdomains = ["www.example.com", "mail.example.com", "ftp.example.com", "admin.example.com", "test.example.com"]
    dns_collector.collect_subdomains(target, subdomains)
    print(f"Collected {len(subdomains)} subdomains")
    
    # Simulate collecting DNS records
    dns_records = [
        {'type': 'A', 'name': 'example.com', 'value': '93.184.216.34', 'ttl': 3600},
        {'type': 'A', 'name': 'www.example.com', 'value': '93.184.216.34', 'ttl': 3600},
        {'type': 'MX', 'name': 'example.com', 'value': '10 mail.example.com', 'ttl': 3600},
        {'type': 'NS', 'name': 'example.com', 'value': 'ns1.example.com', 'ttl': 86400},
        {'type': 'NS', 'name': 'example.com', 'value': 'ns2.example.com', 'ttl': 86400},
        {'type': 'TXT', 'name': 'example.com', 'value': 'v=spf1 include:_spf.example.com ~all', 'ttl': 3600}
    ]
    dns_collector.collect_dns_records(target, dns_records)
    print(f"Collected {len(dns_records)} DNS records")
    
    # Complete scan
    total_results = len(subdomains) + len(dns_records)
    dns_collector.complete_dns_scan(total_results)
    print(f"Completed DNS scan with {total_results} total results")
    
    print("\n" + "=" * 60)
    print("Data Retrieval and UI Integration")
    print("=" * 60)
    
    # Test UI data formatting
    ui_integration = create_unified_integration(tenant_id)
    
    # Get formatted data for different scan types
    scan_types = ["dns_subdomains", "dns_records"]
    
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
    
    # Get all DNS data for tenant
    all_dns_data = {}
    for scan_type in scan_types:
        ui_data = dns_collector.get_dns_data_for_ui(scan_type)
        all_dns_data[scan_type] = ui_data
    
    print(f"Total Subdomains: {len(all_dns_data['dns_subdomains']['table_data'])}")
    print(f"Total DNS Records: {len(all_dns_data['dns_records']['table_data'])}")
    
    # Show sample data
    if all_dns_data['dns_subdomains']['table_data']:
        print(f"\nSample Subdomain Data:")
        sample_subdomain = all_dns_data['dns_subdomains']['table_data'][0]
        print(f"   Subdomain: {sample_subdomain['Subdomain']}")
        print(f"   Domain: {sample_subdomain['Domain']}")
        print(f"   Count: {sample_subdomain['Count']}")
        print(f"   First Seen: {sample_subdomain['First Seen']}")
    
    if all_dns_data['dns_records']['table_data']:
        print(f"\nSample DNS Record Data:")
        sample_record = all_dns_data['dns_records']['table_data'][0]
        print(f"   Name: {sample_record['Name']}")
        print(f"   Type: {sample_record['Type']}")
        print(f"   Value: {sample_record['Value']}")
        print(f"   TTL: {sample_record['TTL']}")
    
    print("\n" + "=" * 60)
    print("DNS Scanner Integration Complete!")
    print("=" * 60)
    print("Key Features Demonstrated:")
    print("   • Centralized data collection with tenant isolation")
    print("   • Smart deduplication with count tracking")
    print("   • UI-ready data formatting")
    print("   • Real-time data retrieval")
    print("   • Comprehensive scan metadata")
    print("   • Multi-format data export capability")

if __name__ == "__main__":
    demo_dns_centralized_data()