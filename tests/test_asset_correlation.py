#!/usr/bin/env python3
"""
Test script to verify IP-hostname correlation in asset inventory
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.core.asset_manager import asset_manager
import logging

def test_ip_hostname_correlation():
    """Test that IP addresses and hostnames are treated as the same asset"""
    
    tenant_id = "test_tenant"
    
    # Clear any existing test data
    try:
        asset_manager.remove_asset(tenant_id, "192.168.1.100")
    except Exception as _exc:
        pass
        logging.debug("Suppressed exception", exc_info=True)
    
    print("Testing IP-Hostname Correlation...")
    print("=" * 50)
    
    # Step 1: Add asset by IP address
    print("1. Adding asset by IP address (192.168.1.100)")
    asset_id1 = asset_manager.add_or_update_asset(
        tenant_id=tenant_id,
        ip_address="192.168.1.100",
        status="DISCOVERED",
        confidence=25,
        metadata={"discovery_method": "ping_sweep"}
    )
    print(f"   Asset ID: {asset_id1}")
    
    # Check current assets
    assets = asset_manager.get_assets(tenant_id)
    print(f"   Total assets: {len(assets)}")
    for asset in assets:
        print(f"   - IP: {asset['ip_address']}, Hostname: '{asset['hostname']}'")
    
    print()
    
    # Step 2: Add hostname that should correlate to same IP
    print("2. Adding hostname (server.local) via DNS enumeration")
    asset_id2 = asset_manager.add_or_update_asset(
        tenant_id=tenant_id,
        ip_address="192.168.1.100",  # Same IP
        hostname="server.local",
        status="DISCOVERED",
        confidence=30,
        metadata={"discovery_method": "dns_enum", "domain": "server.local"}
    )
    print(f"   Asset ID: {asset_id2}")
    
    # Check if they're the same asset
    print(f"   Same asset? {asset_id1 == asset_id2}")
    
    # Check current assets
    assets = asset_manager.get_assets(tenant_id)
    print(f"   Total assets: {len(assets)}")
    for asset in assets:
        print(f"   - IP: {asset['ip_address']}, Hostname: '{asset['hostname']}'")
    
    print()
    
    # Step 3: Try adding by hostname first (simulating reverse scenario)
    print("3. Testing reverse scenario - adding by hostname first")
    
    # Clear test data
    try:
        asset_manager.remove_asset(tenant_id, "192.168.1.101")
        asset_manager.remove_asset(tenant_id, "web.local")
    except Exception as _exc:
        pass
        logging.debug("Suppressed exception", exc_info=True)
    
    # Add by hostname first
    asset_id3 = asset_manager.add_or_update_asset(
        tenant_id=tenant_id,
        ip_address="web.local",  # Using hostname as identifier
        hostname="web.local",
        status="DISCOVERED",
        confidence=30,
        metadata={"discovery_method": "dns_enum"}
    )
    print(f"   Asset ID (hostname first): {asset_id3}")
    
    # Check assets after hostname addition
    assets = asset_manager.get_assets(tenant_id)
    print(f"   Assets after hostname: {len(assets)}")
    for asset in assets:
        if asset['hostname'] == 'web.local' or asset['ip_address'] == 'web.local':
            print(f"   - IP: {asset['ip_address']}, Hostname: '{asset['hostname']}'")
    
    # Then add by IP (simulating later port scan)
    asset_id4 = asset_manager.add_or_update_asset(
        tenant_id=tenant_id,
        ip_address="192.168.1.101",
        hostname="web.local",
        status="IDENTIFIED",
        confidence=50,
        open_ports=[{"port": 80, "protocol": "tcp"}, {"port": 443, "protocol": "tcp"}],
        metadata={"discovery_method": "port_scan"}
    )
    print(f"   Asset ID (IP later): {asset_id4}")
    print(f"   Same asset after IP update? {asset_id3 == asset_id4}")
    
    # Check current assets
    assets = asset_manager.get_assets(tenant_id)
    print(f"   Total assets: {len(assets)}")
    for asset in assets:
        print(f"   - IP: {asset['ip_address']}, Hostname: '{asset['hostname']}', Ports: {len(asset.get('open_ports', []))}, ID: {asset['asset_id'][:8]}")
    
    print()
    
    # Step 4: Test lookup methods
    print("4. Testing lookup methods")
    
    asset_by_ip = asset_manager.get_asset_by_ip(tenant_id, "192.168.1.100")
    asset_by_hostname = asset_manager.get_asset_by_hostname(tenant_id, "server.local")
    
    print(f"   Asset by IP (192.168.1.100): {asset_by_ip['asset_id'] if asset_by_ip else 'Not found'}")
    print(f"   Asset by hostname (server.local): {asset_by_hostname['asset_id'] if asset_by_hostname else 'Not found'}")
    print(f"   Same asset? {asset_by_ip['asset_id'] == asset_by_hostname['asset_id'] if asset_by_ip and asset_by_hostname else False}")
    
    print()
    print("Test completed!")
    
    # Cleanup
    try:
        asset_manager.remove_asset(tenant_id, "192.168.1.100")
        asset_manager.remove_asset(tenant_id, "192.168.1.101")
        asset_manager.remove_asset(tenant_id, "web.local")
    except Exception as _exc:
        pass
        logging.debug("Suppressed exception", exc_info=True)

if __name__ == "__main__":
    test_ip_hostname_correlation()