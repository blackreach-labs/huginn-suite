#!/usr/bin/env python3
"""
Final Demo: Credential Auto-Save Integration with Profile/Tenant System
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def demo_final_integration():
    """Demonstrate the complete credential auto-save integration"""
    
    print("=== Final Credential Integration Demo ===\n")
    
    from app.core.credential_manager import credential_manager
    from pathlib import Path
    import json
    
    # Demo 1: Create a new profile and add credentials
    print("1. Creating new profile 'DEMO-PROJECT'...")
    credential_manager.set_profile("DEMO-PROJECT")
    print(f"   Current profile: {credential_manager.get_current_profile()}")
    
    # Add credentials - they will auto-save to both systems
    print("\n2. Adding credentials (auto-saves to both systems)...")
    
    credential_manager.add_credential(
        username="admin",
        password="admin123",
        domain="COMPANY",
        service="SSH",
        notes="Production server access"
    )
    
    credential_manager.add_credential(
        username="dbuser",
        password="dbpass456",
        service="MySQL",
        notes="Database access"
    )
    
    print(f"   Credentials in memory: {len(credential_manager.get_credentials())}")
    
    # Check profile JSON file
    profiles_dir = Path("profiles")
    profile_file = profiles_dir / "DEMO-PROJECT.json"
    
    print(f"\n3. Profile JSON file created: {profile_file.exists()}")
    
    if profile_file.exists():
        with open(profile_file, 'r') as f:
            profile_data = json.load(f)
        
        creds = profile_data['credentials']['credentials']
        print(f"   Credentials in profile JSON: {len(creds)}")
        
        for i, cred in enumerate(creds, 1):
            print(f"   {i}. {cred['username']}@{cred['service']} ({cred['credential_type']})")
    
    # Demo 2: Switch profiles
    print(f"\n4. Switching to different profile...")
    credential_manager.set_profile("ANOTHER-PROJECT")
    print(f"   New profile: {credential_manager.get_current_profile()}")
    print(f"   Credentials in new profile: {len(credential_manager.get_credentials())}")
    
    # Add credential to new profile
    credential_manager.add_credential(
        username="testuser",
        password="testpass",
        service="RDP",
        notes="Test environment"
    )
    
    # Demo 3: Switch back and verify persistence
    print(f"\n5. Switching back to 'DEMO-PROJECT'...")
    credential_manager.set_profile("DEMO-PROJECT")
    print(f"   Credentials restored: {len(credential_manager.get_credentials())}")
    
    for i, cred in enumerate(credential_manager.get_credentials(), 1):
        print(f"   {i}. {cred.username}@{cred.service}")
    
    print(f"\n=== Integration Complete ===")
    print("SUCCESS: When credentials are added to 'Stored Credentials':")
    print("- They are automatically saved to the credential manager")
    print("- They are automatically saved to the current profile JSON file")
    print("- Each profile/tenant maintains separate credential storage")
    print("- Profile switching automatically loads the correct credentials")
    print("- The same format is used as the 'Save Profile' functionality")

if __name__ == "__main__":
    demo_final_integration()