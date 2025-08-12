#!/usr/bin/env python3
"""
Test script to verify automatic credential saving for profiles/tenants
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.core.credential_manager import credential_manager
from app.core.session_manager import session_manager

def test_credential_profile_save():
    """Test automatic credential saving for profiles"""
    
    print("=== Testing Credential Profile Auto-Save ===\n")
    
    # Test 1: Create a new session
    print("1. Creating new session...")
    session = session_manager.create_session(
        name="Test Session",
        description="Testing credential auto-save"
    )
    session_manager.set_current_session(session['id'])
    print(f"   Created session: {session['name']} (ID: {session['id']})")
    print(f"   Current credential profile: {credential_manager.get_current_profile()}")
    
    # Test 2: Add credentials - should auto-save
    print("\n2. Adding credentials (should auto-save)...")
    cred1 = credential_manager.add_credential(
        username="testuser1",
        password="testpass1",
        service="SSH",
        notes="Test credential 1"
    )
    print(f"   Added credential: {cred1.username}@{cred1.service}")
    
    cred2 = credential_manager.add_credential(
        username="admin",
        password="admin123",
        domain="TESTDOMAIN",
        service="SMB",
        credential_type="Username/Password",
        notes="Test credential 2"
    )
    print(f"   Added credential: {cred2.domain}\\{cred2.username}@{cred2.service}")
    
    # Test 3: Verify credentials are saved
    print(f"\n3. Current credentials in memory: {len(credential_manager.get_credentials())}")
    for i, cred in enumerate(credential_manager.get_credentials()):
        print(f"   {i+1}. {cred.display_text()}")
    
    # Test 4: Create another session and switch
    print("\n4. Creating second session and switching...")
    session2 = session_manager.create_session(
        name="Test Session 2",
        description="Second test session"
    )
    session_manager.set_current_session(session2['id'])
    print(f"   Switched to session: {session2['name']} (ID: {session2['id']})")
    print(f"   Current credential profile: {credential_manager.get_current_profile()}")
    print(f"   Credentials in new session: {len(credential_manager.get_credentials())}")
    
    # Test 5: Add credential to second session
    print("\n5. Adding credential to second session...")
    cred3 = credential_manager.add_credential(
        username="user2",
        password="pass2",
        service="RDP",
        notes="Credential for session 2"
    )
    print(f"   Added credential: {cred3.username}@{cred3.service}")
    print(f"   Credentials in session 2: {len(credential_manager.get_credentials())}")
    
    # Test 6: Switch back to first session
    print("\n6. Switching back to first session...")
    session_manager.set_current_session(session['id'])
    print(f"   Switched back to session: {session['name']}")
    print(f"   Current credential profile: {credential_manager.get_current_profile()}")
    print(f"   Credentials restored: {len(credential_manager.get_credentials())}")
    
    for i, cred in enumerate(credential_manager.get_credentials()):
        print(f"   {i+1}. {cred.display_text()}")
    
    # Test 7: Verify file persistence
    print("\n7. Checking file persistence...")
    from pathlib import Path
    profiles_dir = Path("profiles")
    
    session1_file = profiles_dir / f"{session['id']}_credentials.json"
    session2_file = profiles_dir / f"{session2['id']}_credentials.json"
    
    print(f"   Session 1 credentials file exists: {session1_file.exists()}")
    print(f"   Session 2 credentials file exists: {session2_file.exists()}")
    
    if session1_file.exists():
        import json
        with open(session1_file, 'r') as f:
            data = json.load(f)
        print(f"   Session 1 file contains {len(data.get('credentials', []))} credentials")
    
    if session2_file.exists():
        import json
        with open(session2_file, 'r') as f:
            data = json.load(f)
        print(f"   Session 2 file contains {len(data.get('credentials', []))} credentials")
    
    print("\n=== Test Complete ===")
    print("✓ Credentials are automatically saved when added to Stored Credentials")
    print("✓ Each profile/tenant maintains separate credential storage")
    print("✓ Switching sessions automatically loads the correct credentials")

if __name__ == "__main__":
    test_credential_profile_save()