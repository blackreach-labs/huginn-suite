#!/usr/bin/env python3
# test_dns_centralized.py - Test DNS centralized data collection

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.tools.dns_scanner import run_dns_scan
from app.core.dns_data_collector import create_dns_collector
from app.core.centralized_scan_data import centralized_scan_data
import logging

def test_dns_collection():
    """Test DNS data collection with example.com and PTR lookups"""
    print("Testing DNS Centralized Data Collection...")
    
    # Test 1: Basic DNS scan for example.com
    print("\n1. Testing example.com DNS scan...")
    results = run_dns_scan(
        target="example.com",
        record_types=['A', 'MX', 'NS', 'TXT', 'CNAME'],
        tenant_id="test_tenant"
    )
    print(f"   Results: {len(results)} domains found")
    for domain, records in results.items():
        print(f"   - {domain}: {list(records.keys())}")
    
    # Test 2: PTR lookups for IP range
    print("\n2. Testing PTR lookups for 119.82.2.1-100...")
    ptr_results = {}
    collector = create_dns_collector("test_tenant")
    scan_id = collector.start_dns_scan("119.82.2.0/24", "ptr_scanner", "ptr_lookup")
    
    ptr_records = []
    for i in range(1, 101):
        ip = f"119.82.2.{i}"
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            # Reverse DNS lookup
            reversed_ip = '.'.join(reversed(ip.split('.'))) + '.in-addr.arpa'
            answers = resolver.resolve(reversed_ip, 'PTR')
            for answer in answers:
                hostname = answer.target.to_text().rstrip('.')
                ptr_records.append({
                    'type': 'PTR',
                    'name': reversed_ip,
                    'value': hostname,
                    'ttl': answers.rrset.ttl if hasattr(answers, 'rrset') else 0
                })
                print(f"   - {ip} -> {hostname}")
        except Exception:
            continue
    
    if ptr_records:
        collector.collect_dns_records("119.82.2.0/24", ptr_records)
    collector.complete_dns_scan(total_results=len(ptr_records))
    
    # Test 3: Check centralized data
    print("\n3. Checking centralized data...")
    dns_data = centralized_scan_data.get_scan_data("test_tenant", "dns_subdomains")
    print(f"   Subdomains stored: {len(dns_data)}")
    
    dns_records = centralized_scan_data.get_scan_data("test_tenant", "dns_records")
    print(f"   DNS records stored: {len(dns_records)}")
    
    # Test 4: UI data formatting
    print("\n4. Testing UI data formatting...")
    collector = create_dns_collector("test_tenant")
    ui_data = collector.get_dns_data_for_ui("dns_records")
    print(f"   Table data entries: {len(ui_data['table_data'])}")
    print(f"   Graph data categories: {len(ui_data['graph_data'])}")
    
    # Test 5: Summary
    print("\n5. Summary...")
    summary = centralized_scan_data.get_scan_summary("test_tenant", "dns_records")
    print(f"   Total results: {summary.get('total_results', 0)}")
    print(f"   Unique targets: {summary.get('unique_targets', 0)}")
    
    print("\nDNS centralized data collection test completed!")

if __name__ == "__main__":
    test_dns_collection()