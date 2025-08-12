#!/usr/bin/env python3
"""
LDAP Scanner Centralized Data Collection Demo
Demonstrates LDAP scanner integration with centralized data collection system
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.core.ldap_data_collector import create_ldap_collector
from app.core.unified_ui_integration import create_unified_integration
import time

def demo_ldap_centralized_data():
    """Demonstrate LDAP scanner with centralized data collection"""
    
    print("LDAP Scanner Centralized Data Collection Demo")
    print("=" * 60)
    
    # Create tenant-specific collector
    tenant_id = "demo_company"
    ldap_collector = create_ldap_collector(tenant_id)
    
    print(f"Created LDAP collector for tenant: {tenant_id}")
    
    # Simulate LDAP scan data collection
    target = "dc01.domain.com"
    
    # Start LDAP scan
    scan_id = ldap_collector.start_ldap_scan(target, "ldap_scanner", "enumeration")
    print(f"Started LDAP scan: {scan_id}")
    
    # Simulate collecting server info
    server_info = {
        'accessible': True,
        'port': 389,
        'ssl': False,
        'server_info': {
            'server_name': 'DC01.DOMAIN.COM',
            'supported_ldap_version': '3'
        },
        'naming_contexts': ['DC=domain,DC=com']
    }
    ldap_collector.collect_server_info(target, server_info)
    print(f"Collected LDAP server info")
    
    # Simulate collecting users
    users = [
        {
            'cn': 'Administrator',
            'sAMAccountName': 'Administrator',
            'userPrincipalName': 'Administrator@domain.com',
            'memberOf': ['CN=Domain Admins,CN=Users,DC=domain,DC=com'],
            'lastLogon': '2023-11-29',
            'pwdLastSet': '2023-10-15'
        },
        {
            'cn': 'John Doe',
            'sAMAccountName': 'jdoe',
            'userPrincipalName': 'jdoe@domain.com',
            'memberOf': ['CN=Domain Users,CN=Users,DC=domain,DC=com'],
            'lastLogon': '2023-11-28'
        },
        {
            'cn': 'Service Account SQL',
            'sAMAccountName': 'svc_sql',
            'userPrincipalName': 'svc_sql@domain.com',
            'servicePrincipalName': ['MSSQLSvc/server.domain.com:1433'],
            'memberOf': ['CN=Service Accounts,CN=Users,DC=domain,DC=com']
        }
    ]
    ldap_collector.collect_users(target, users)
    print(f"Collected {len(users)} LDAP users")
    
    # Simulate collecting groups
    groups = [
        {
            'cn': 'Domain Admins',
            'description': 'Domain Administrators',
            'members': ['CN=Administrator,CN=Users,DC=domain,DC=com'],
            'memberCount': 1
        },
        {
            'cn': 'Domain Users',
            'description': 'All domain users',
            'members': ['CN=jdoe,CN=Users,DC=domain,DC=com'],
            'memberCount': 25
        },
        {
            'cn': 'Enterprise Admins',
            'description': 'Enterprise Administrators',
            'members': ['CN=Administrator,CN=Users,DC=domain,DC=com'],
            'memberCount': 1
        }
    ]
    ldap_collector.collect_groups(target, groups)
    print(f"Collected {len(groups)} LDAP groups")
    
    # Simulate collecting computers
    computers = [
        {
            'cn': 'DC01',
            'dNSHostName': 'dc01.domain.com',
            'operatingSystem': 'Windows Server 2019',
            'operatingSystemVersion': '10.0 (17763)',
            'lastLogonTimestamp': '2023-11-29',
            'servicePrincipalName': ['HOST/dc01.domain.com', 'LDAP/dc01.domain.com']
        },
        {
            'cn': 'WS01',
            'dNSHostName': 'ws01.domain.com',
            'operatingSystem': 'Windows 10 Enterprise',
            'operatingSystemVersion': '10.0 (19044)',
            'lastLogonTimestamp': '2023-11-28'
        }
    ]
    ldap_collector.collect_computers(target, computers)
    print(f"Collected {len(computers)} LDAP computers")
    
    # Simulate collecting service accounts
    service_accounts = [users[2]]  # svc_sql
    ldap_collector.collect_service_accounts(target, service_accounts)
    print(f"Collected {len(service_accounts)} service accounts")
    
    # Simulate collecting privileged users
    privileged_users = [users[0]]  # Administrator
    ldap_collector.collect_privileged_users(target, privileged_users)
    print(f"Collected {len(privileged_users)} privileged users")
    
    # Complete scan
    total_results = 1 + len(users) + len(groups) + len(computers) + len(service_accounts) + len(privileged_users)
    ldap_collector.complete_ldap_scan(total_results)
    print(f"Completed LDAP scan with {total_results} total results")
    
    print("\n" + "=" * 60)
    print("Data Retrieval and UI Integration")
    print("=" * 60)
    
    # Test UI data formatting
    ui_integration = create_unified_integration(tenant_id)
    
    # Get formatted data for different scan types
    scan_types = ["ldap_users", "ldap_groups", "ldap_computers"]
    
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
    
    # Get all LDAP data for tenant
    all_ldap_data = {}
    for scan_type in scan_types:
        ui_data = ldap_collector.get_ldap_data_for_ui(scan_type)
        all_ldap_data[scan_type] = ui_data
    
    print(f"Total Users: {len(all_ldap_data['ldap_users']['table_data'])}")
    print(f"Total Groups: {len(all_ldap_data['ldap_groups']['table_data'])}")
    print(f"Total Computers: {len(all_ldap_data['ldap_computers']['table_data'])}")
    
    # Show sample data
    if all_ldap_data['ldap_users']['table_data']:
        print(f"\nSample User Data:")
        sample_user = all_ldap_data['ldap_users']['table_data'][0]
        print(f"   Username: {sample_user['Username']}")
        print(f"   Display Name: {sample_user['Display Name']}")
        print(f"   UPN: {sample_user['UPN']}")
        print(f"   Last Logon: {sample_user['Last Logon']}")
        print(f"   Count: {sample_user['Count']}")
    
    if all_ldap_data['ldap_groups']['table_data']:
        print(f"\nSample Group Data:")
        sample_group = all_ldap_data['ldap_groups']['table_data'][0]
        print(f"   Group Name: {sample_group['Group Name']}")
        print(f"   Description: {sample_group['Description']}")
        print(f"   Member Count: {sample_group['Member Count']}")
        print(f"   Count: {sample_group['Count']}")
    
    if all_ldap_data['ldap_computers']['table_data']:
        print(f"\nSample Computer Data:")
        sample_computer = all_ldap_data['ldap_computers']['table_data'][0]
        print(f"   Computer Name: {sample_computer['Computer Name']}")
        print(f"   DNS Name: {sample_computer['DNS Name']}")
        print(f"   Operating System: {sample_computer['Operating System']}")
        print(f"   Count: {sample_computer['Count']}")
    
    print("\n" + "=" * 60)
    print("LDAP Scanner Integration Complete!")
    print("=" * 60)
    print("Key Features Demonstrated:")
    print("   • Centralized data collection with tenant isolation")
    print("   • Smart deduplication with count tracking")
    print("   • UI-ready data formatting")
    print("   • Real-time data retrieval")
    print("   • Comprehensive scan metadata")
    print("   • Multi-format data export capability")

if __name__ == "__main__":
    demo_ldap_centralized_data()