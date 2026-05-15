# examples/inventory_demo.py
"""
Demonstration of the Asset Inventory system
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.asset_manager import asset_manager
from app.core.inventory_integration import *

def demo_ping_sweep():
    """Demonstrate ping sweep integration"""
    print("=== Ping Sweep Demo ===")
    
    # Simulate ping sweep results
    ping_results = {
        '192.168.1.1': {'status': 'up', 'response_time': '1.2ms'},
        '192.168.1.106': {'status': 'up', 'response_time': '0.8ms'},
        '192.168.1.130': {'status': 'up', 'response_time': '2.1ms'},
        '192.168.1.200': {'status': 'down'}
    }
    
    update_inventory_from_ping_sweep(ping_results)
    print(f"Added {len([r for r in ping_results.values() if r.get('status') == 'up'])} assets from ping sweep")

def demo_port_scan():
    """Demonstrate port scan integration"""
    print("\n=== Port Scan Demo ===")
    
    # Simulate port scan results
    port_results = {
        '192.168.1.1': {
            'open_ports': [
                {'port': 80, 'protocol': 'tcp', 'service': 'http'},
                {'port': 443, 'protocol': 'tcp', 'service': 'https'},
                {'port': 23, 'protocol': 'tcp', 'service': 'telnet'}
            ]
        },
        '192.168.1.106': {
            'open_ports': [
                {'port': 135, 'protocol': 'tcp', 'service': 'rpc'},
                {'port': 139, 'protocol': 'tcp', 'service': 'netbios'},
                {'port': 445, 'protocol': 'tcp', 'service': 'smb'},
                {'port': 3389, 'protocol': 'tcp', 'service': 'rdp'}
            ]
        },
        '192.168.1.130': {
            'open_ports': [
                {'port': 22, 'protocol': 'tcp', 'service': 'ssh'},
                {'port': 80, 'protocol': 'tcp', 'service': 'http'},
                {'port': 443, 'protocol': 'tcp', 'service': 'https'}
            ]
        }
    }
    
    update_inventory_from_port_scan(port_results)
    print("Updated assets with port scan information")

def demo_service_detection():
    """Demonstrate service detection integration"""
    print("\n=== Service Detection Demo ===")
    
    # Simulate service detection results
    service_results = {
        '192.168.1.106': {
            'services': [
                {'port': 135, 'name': 'rpc', 'version': 'Microsoft Windows RPC', 'protocol': 'tcp'},
                {'port': 445, 'name': 'smb', 'version': 'Microsoft Windows SMB', 'protocol': 'tcp'}
            ],
            'os_info': {
                'name': 'Windows',
                'version': 'Windows 10',
                'accuracy': 85
            }
        },
        '192.168.1.130': {
            'services': [
                {'port': 22, 'name': 'ssh', 'version': 'OpenSSH 8.2', 'protocol': 'tcp'},
                {'port': 80, 'name': 'http', 'version': 'Apache 2.4.41', 'protocol': 'tcp'}
            ],
            'os_info': {
                'name': 'Linux',
                'version': 'Ubuntu 20.04',
                'accuracy': 90
            }
        }
    }
    
    update_inventory_from_service_detection(service_results)
    print("Updated assets with service detection information")

def demo_vulnerability_scan():
    """Demonstrate vulnerability scan integration"""
    print("\n=== Vulnerability Scan Demo ===")
    
    # Simulate vulnerability scan results
    vuln_results = {
        '192.168.1.106': {
            'vulnerabilities': [
                {
                    'id': 'CVE-2021-34527',
                    'name': 'PrintNightmare',
                    'severity': 'critical',
                    'description': 'Windows Print Spooler Remote Code Execution Vulnerability',
                    'cvss': 8.8
                },
                {
                    'id': 'CVE-2020-1472',
                    'name': 'Zerologon',
                    'severity': 'critical',
                    'description': 'Netlogon Elevation of Privilege Vulnerability',
                    'cvss': 10.0
                }
            ]
        }
    }
    
    update_inventory_from_vulnerability_scan(vuln_results)
    print("Updated assets with vulnerability information")

def show_inventory():
    """Display current inventory"""
    print("\n=== Current Inventory ===")
    
    assets = asset_manager.get_assets("default")
    
    for asset in assets:
        print(f"\nAsset: {asset['ip_address']}")
        print(f"  Hostname: {asset.get('hostname', 'N/A')}")
        print(f"  OS Type: {asset.get('os_type', 'Unknown')}")
        print(f"  OS Version: {asset.get('os_version', 'N/A')}")
        print(f"  Status: {asset.get('status', 'DISCOVERED')}")
        print(f"  Confidence: {asset.get('confidence', 0)}%")
        print(f"  Open Ports: {len(asset.get('open_ports', []))}")
        print(f"  Services: {len(asset.get('services', []))}")
        print(f"  Vulnerabilities: {len(asset.get('vulnerabilities', []))}")
        
        # Show some details
        if asset.get('open_ports'):
            ports = [f"{p['port']}/{p.get('protocol', 'tcp')}" for p in asset['open_ports'][:5]]
            print(f"  Top Ports: {', '.join(ports)}")
        
        if asset.get('vulnerabilities'):
            vulns = [v.get('name', v.get('id', 'Unknown')) for v in asset['vulnerabilities'][:3]]
            print(f"  Top Vulnerabilities: {', '.join(vulns)}")

def show_statistics():
    """Display inventory statistics"""
    print("\n=== Inventory Statistics ===")
    
    stats = asset_manager.get_asset_statistics("default")
    
    print(f"Total Assets: {stats.get('total_assets', 0)}")
    print(f"Recent Activity: {stats.get('recent_activity', 0)}")
    
    status_breakdown = stats.get('status_breakdown', {})
    print(f"Status Breakdown:")
    for status, count in status_breakdown.items():
        print(f"  {status}: {count}")
    
    os_breakdown = stats.get('os_breakdown', {})
    print(f"OS Breakdown:")
    for os_type, count in os_breakdown.items():
        print(f"  {os_type}: {count}")

if __name__ == "__main__":
    print("Asset Inventory System Demo")
    print("=" * 40)
    
    # Run the demo sequence
    demo_ping_sweep()
    demo_port_scan()
    demo_service_detection()
    demo_vulnerability_scan()
    
    # Show results
    show_inventory()
    show_statistics()
    
    print("\n" + "=" * 40)
    print("Demo completed! The inventory now contains discovered assets.")
    print("You can view them in the Huginn application under View -> Inventory")