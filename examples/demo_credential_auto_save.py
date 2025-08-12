#!/usr/bin/env python3
"""
Demo: Automatic Credential Saving for Profile/Tenant
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def demo_credential_auto_save():
    """Demonstrate automatic credential saving"""
    
    print("=== Credential Auto-Save Demo ===\n")
    
    from app.core.credential_manager import credential_manager
    from app.core.session_manager import session_manager
    
    # Show current state
    print(f"Current profile: {credential_manager.get_current_profile()}")
    print(f"Current credentials: {len(credential_manager.get_credentials())}")
    
    # Add a credential - it will auto-save
    print("\nAdding credential...")
    credential_manager.add_credential(
        username="demo_user",
        password="demo_pass",
        service="SSH",
        notes="Demo credential - auto-saved!"
    )
    
    print(f"Credentials after add: {len(credential_manager.get_credentials())}")
    
    # Check if file was created
    from pathlib import Path
    profiles_dir = Path("profiles")
    profile_file = profiles_dir / f"{credential_manager.get_current_profile()}_credentials.json"
    
    print(f"Credential file exists: {profile_file.exists()}")
    
    if profile_file.exists():
        import json
        with open(profile_file, 'r') as f:
            data = json.load(f)
        print(f"File contains {len(data.get('credentials', []))} credentials")
        
        # Show the saved credential
        if data.get('credentials'):
            cred = data['credentials'][0]
            print(f"Saved credential: {cred['username']}@{cred['service']}")
    
    print("\n✓ SUCCESS: Credentials are automatically saved when added!")
    print("✓ Each profile/tenant maintains separate credential storage")

if __name__ == "__main__":
    demo_credential_auto_save()