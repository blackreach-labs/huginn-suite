#!/usr/bin/env python3
"""
Simple SMB connection test
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from app.core.smb_client import SMBClient

def test_smb_connection(target, domain, username, password):
    print(f"Testing SMB connection to {target}")
    
    client = SMBClient()
    
    try:
        # Step 1: TCP Connection
        print("1. Connecting to TCP port 445...")
        if not client.connect(target, 445):
            print("   FAILED: Could not connect to port 445")
            return False
        print("   SUCCESS: TCP connection established")
        
        # Step 2: Protocol Negotiation
        print("2. Negotiating SMB protocol...")
        if not client.negotiate_protocol():
            print("   FAILED: Protocol negotiation failed")
            return False
        print("   SUCCESS: SMB protocol negotiated")
        
        # Step 3: Authentication
        print("3. Authenticating...")
        if not client.session_setup(domain, username, password):
            print("   FAILED: Authentication failed")
            return False
        print("   SUCCESS: Authentication completed")
        
        # Step 4: Tree Connect
        print("4. Connecting to IPC$ share...")
        if not client.tree_connect("IPC$"):
            print("   FAILED: Could not connect to IPC$")
            return False
        print("   SUCCESS: Connected to IPC$")
        
        print("\nAll tests passed! SMB connection is working.")
        return True
        
    except Exception as e:
        print(f"   ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    finally:
        client.close()

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: python test_smb_simple.py <target> <domain> <username> <password>")
        sys.exit(1)
    
    target = sys.argv[1]
    domain = sys.argv[2] 
    username = sys.argv[3]
    password = sys.argv[4]
    
    test_smb_connection(target, domain, username, password)