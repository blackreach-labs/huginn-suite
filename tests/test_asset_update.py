#!/usr/bin/env python3
"""
Test script for Asset Update functionality
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt6.QtWidgets import QApplication
from app.core.asset_manager import asset_manager
from app.widgets.asset_update_dialog import AssetUpdateDialog

def test_asset_update():
    """Test the asset update dialog"""
    app = QApplication(sys.argv)
    
    # Create a test asset
    tenant_id = "test_tenant"
    test_asset_data = {
        'ip_address': '192.168.1.100',
        'hostname': 'test-server',
        'os_type': 'Linux',
        'os_version': 'Ubuntu 20.04',
        'status': 'IDENTIFIED',
        'confidence': 75,
        'open_ports': [
            {'port': 22, 'protocol': 'tcp'},
            {'port': 80, 'protocol': 'tcp'},
            {'port': 443, 'protocol': 'tcp'}
        ],
        'services': [
            {'port': 22, 'service': 'ssh', 'version': 'OpenSSH 8.2', 'protocol': 'tcp'},
            {'port': 80, 'service': 'http', 'version': 'Apache 2.4', 'protocol': 'tcp'}
        ],
        'vulnerabilities': [
            {'id': 'CVE-2023-1234', 'name': 'Test Vulnerability', 'severity': 'medium', 'description': 'Test description'}
        ],
        'metadata': {
            'discovery_method': 'manual_test',
            'notes': 'This is a test asset'
        }
    }
    
    # Add the test asset to the database
    asset_id = asset_manager.add_or_update_asset(tenant_id, **test_asset_data)
    print(f"Created test asset with ID: {asset_id}")
    
    # Get the asset from database to ensure it has all fields
    asset_from_db = asset_manager.get_asset_by_ip(tenant_id, test_asset_data['ip_address'])
    
    if asset_from_db:
        print("Asset found in database, opening update dialog...")
        
        # Create and show the update dialog
        dialog = AssetUpdateDialog(asset_from_db)
        
        def on_asset_updated(updated_data):
            print("Asset updated with data:")
            for key, value in updated_data.items():
                print(f"  {key}: {value}")
            
            # Update in database
            asset_manager.add_or_update_asset(tenant_id, test_asset_data['ip_address'], **updated_data)
            print("Asset updated in database successfully!")
            
            # Verify the update
            updated_asset = asset_manager.get_asset_by_ip(tenant_id, test_asset_data['ip_address'])
            if updated_asset:
                print("\nUpdated asset from database:")
                for key, value in updated_asset.items():
                    if key not in ['id', 'created_at']:  # Skip internal fields
                        print(f"  {key}: {value}")
        
        dialog.asset_updated.connect(on_asset_updated)
        
        # Show the dialog
        result = dialog.exec()
        
        if result == dialog.DialogCode.Accepted:
            print("Dialog was accepted")
        else:
            print("Dialog was cancelled")
    else:
        print("Error: Could not retrieve asset from database")
    
    # Clean up - remove test asset
    asset_manager.remove_asset(tenant_id, test_asset_data['ip_address'])
    print("Test asset removed from database")

if __name__ == "__main__":
    test_asset_update()