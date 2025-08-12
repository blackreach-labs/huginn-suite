#!/usr/bin/env python3
"""
SNMP Scanner Centralized Data Collection Demo
Demonstrates SNMP scanner integration with centralized data collection system
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.core.snmp_data_collector import create_snmp_collector
from app.core.unified_ui_integration import create_unified_integration
import time

def demo_snmp_centralized_data():
    """Demonstrate SNMP scanner with centralized data collection"""
    
    print("SNMP Scanner Centralized Data Collection Demo")
    print("=" * 60)
    
    # Create tenant-specific collector
    tenant_id = "demo_company"
    snmp_collector = create_snmp_collector(tenant_id)
    
    print(f"Created SNMP collector for tenant: {tenant_id}")
    
    # Simulate SNMP scan data collection
    target = "192.168.1.1"
    
    # Start SNMP scan
    scan_id = snmp_collector.start_snmp_scan(target, "snmp_scanner", "enumeration")
    print(f"Started SNMP scan: {scan_id}")
    
    # Simulate collecting community strings
    communities = ["public", "private", "admin"]
    snmp_collector.collect_community_strings(target, communities)
    print(f"Collected {len(communities)} valid SNMP communities")
    
    # Simulate collecting system info
    system_info = {
        'system_description': 'Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE4',
        'system_uptime': '157 days, 14:32:18.00',
        'system_contact': 'Network Admin <admin@company.com>',
        'system_name': 'SW-CORE-01',
        'system_location': 'Server Room A, Rack 12'
    }
    snmp_collector.collect_system_info(target, system_info)
    print(f"Collected SNMP system information")
    
    # Simulate collecting users
    users = ["admin", "guest", "operator", "monitor"]
    snmp_collector.collect_users(target, users)
    print(f"Collected {len(users)} SNMP users")
    
    # Simulate collecting network interfaces
    interfaces = [
        "FastEthernet0/1",
        "FastEthernet0/2", 
        "FastEthernet0/3",
        "GigabitEthernet0/1",
        "GigabitEthernet0/2",
        "Vlan1"
    ]
    snmp_collector.collect_network_interfaces(target, interfaces)
    print(f"Collected {len(interfaces)} network interfaces")
    
    # Simulate collecting processes
    processes = [
        {'name': 'kernel_task', 'pid': 0, 'path': '/kernel', 'args': ''},
        {'name': 'snmpd', 'pid': 161, 'path': '/usr/sbin/snmpd', 'args': '-Lsd -Lf /dev/null -p /var/run/snmpd.pid'},
        {'name': 'httpd', 'pid': 443, 'path': '/usr/sbin/httpd', 'args': '-D FOREGROUND'},
        {'name': 'sshd', 'pid': 22, 'path': '/usr/sbin/sshd', 'args': '-D'}
    ]
    snmp_collector.collect_processes(target, processes)
    print(f"Collected {len(processes)} running processes")
    
    # Simulate collecting installed software
    software = [
        {'name': 'Cisco IOS', 'version': '15.0(2)SE4', 'install_date': '2023-01-15'},
        {'name': 'SNMP Agent', 'version': '2.1.4', 'install_date': '2023-01-15'},
        {'name': 'Web Management', 'version': '1.2.3', 'install_date': '2023-02-01'}
    ]
    snmp_collector.collect_installed_software(target, software)
    print(f"Collected {len(software)} installed software packages")
    
    # Complete scan
    total_results = len(communities) + 1 + len(users) + len(interfaces) + len(processes) + len(software)
    snmp_collector.complete_snmp_scan(total_results)
    print(f"Completed SNMP scan with {total_results} total results")
    
    print("\n" + "=" * 60)
    print("Data Retrieval and UI Integration")
    print("=" * 60)
    
    # Test UI data formatting
    ui_integration = create_unified_integration(tenant_id)
    
    # Get formatted data for different scan types
    scan_types = ["snmp_communities", "snmp_system_info", "snmp_users", "snmp_interfaces"]
    
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
    
    # Get all SNMP data for tenant
    all_snmp_data = {}
    for scan_type in scan_types:
        ui_data = snmp_collector.get_snmp_data_for_ui(scan_type)
        all_snmp_data[scan_type] = ui_data
    
    print(f"Total Communities: {len(all_snmp_data['snmp_communities']['table_data'])}")
    print(f"Total System Info: {len(all_snmp_data['snmp_system_info']['table_data'])}")
    print(f"Total Users: {len(all_snmp_data['snmp_users']['table_data'])}")
    print(f"Total Interfaces: {len(all_snmp_data['snmp_interfaces']['table_data'])}")
    
    # Show sample data
    if all_snmp_data['snmp_communities']['table_data']:
        print(f"\nSample Community Data:")
        sample_community = all_snmp_data['snmp_communities']['table_data'][0]
        print(f"   Community: {sample_community['Community']}")
        print(f"   Access Level: {sample_community['Access Level']}")
        print(f"   Count: {sample_community['Count']}")
    
    if all_snmp_data['snmp_system_info']['table_data']:
        print(f"\nSample System Info:")
        sample_system = all_snmp_data['snmp_system_info']['table_data'][0]
        print(f"   System Name: {sample_system['System Name']}")
        print(f"   Description: {sample_system['Description'][:50]}...")
        print(f"   Contact: {sample_system['Contact']}")
        print(f"   Location: {sample_system['Location']}")
    
    if all_snmp_data['snmp_users']['table_data']:
        print(f"\nSample User Data:")
        sample_user = all_snmp_data['snmp_users']['table_data'][0]
        print(f"   Username: {sample_user['Username']}")
        print(f"   Source: {sample_user['Source']}")
        print(f"   Count: {sample_user['Count']}")
    
    if all_snmp_data['snmp_interfaces']['table_data']:
        print(f"\nSample Interface Data:")
        sample_interface = all_snmp_data['snmp_interfaces']['table_data'][0]
        print(f"   Interface: {sample_interface['Interface']}")
        print(f"   Type: {sample_interface['Type']}")
        print(f"   Status: {sample_interface['Status']}")
    
    print("\n" + "=" * 60)
    print("SNMP Scanner Integration Complete!")
    print("=" * 60)
    print("Key Features Demonstrated:")
    print("   • Centralized data collection with tenant isolation")
    print("   • Smart deduplication with count tracking")
    print("   • UI-ready data formatting")
    print("   • Real-time data retrieval")
    print("   • Comprehensive scan metadata")
    print("   • Multi-format data export capability")

if __name__ == "__main__":
    demo_snmp_centralized_data()