#!/usr/bin/env python3
"""
Test script to verify Session Management integration
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.core.session_manager import session_manager
# from infrastructure.data.repositories.sqlite_scan_repository import SQLiteScanRepository

def test_session_management():
    """Test basic session management functionality"""
    print("Testing Session Management Integration...")
    
    # Test 1: Create a new session
    print("\n1. Creating new session...")
    session = session_manager.create_session(
        name="Test Session",
        description="Integration test session",
        targets=["example.com", "test.com"]
    )
    print(f"✅ Created session: {session['name']} (ID: {session['id']})")
    
    # Test 2: Set as current session
    print("\n2. Setting as current session...")
    success = session_manager.set_current_session(session['id'])
    if success:
        current = session_manager.get_current_session()
        print(f"✅ Current session: {current['name']}")
    else:
        print("❌ Failed to set current session")
    
    # Test 3: Add mock scan data
    print("\n3. Adding mock scan data...")
    mock_results = {
        "example.com": {
            "A": ["1.2.3.4"],
            "CNAME": ["www.example.com"]
        }
    }
    
    scan_id = scan_db.save_scan(
        target="example.com",
        scan_type="dns_enum",
        results=mock_results,
        duration=5.2
    )
    
    if scan_id:
        print(f"✅ Saved scan with ID: {scan_id}")
        
        # Associate with session
        success = session_manager.add_scan_to_session(session['id'], scan_id)
        if success:
            print("✅ Associated scan with session")
        else:
            print("❌ Failed to associate scan with session")
    else:
        print("❌ Failed to save scan")
    
    # Test 4: Get session statistics
    print("\n4. Getting session statistics...")
    stats = session_manager.get_session_statistics(session['id'])
    print(f"✅ Session stats: {stats['total_scans']} scans, {stats['targets_scanned']} targets")
    
    # Test 5: List all sessions
    print("\n5. Listing all sessions...")
    all_sessions = session_manager.get_all_sessions()
    print(f"✅ Total sessions: {len(all_sessions)}")
    for s in all_sessions:
        print(f"   - {s['name']} ({s['id']})")
    
    # Test 6: Export session
    print("\n6. Testing session export...")
    export_path = "test_session_export.json"
    success = session_manager.export_session(session['id'], export_path)
    if success:
        print(f"✅ Exported session to: {export_path}")
        # Clean up
        if os.path.exists(export_path):
            os.remove(export_path)
    else:
        print("❌ Failed to export session")
    
    # Cleanup
    print("\n7. Cleaning up...")
    session_manager.delete_session(session['id'])
    print("✅ Cleaned up test session")
    
    print("\n🎉 Session Management integration test completed!")

if __name__ == "__main__":
    test_session_management()