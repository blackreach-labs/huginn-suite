#!/usr/bin/env python3
"""
SMB Connection Test and Diagnostic Script
Run this to diagnose and fix SMB connection issues
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

from app.core.smb_diagnostics import diagnose_smb_connection
from app.core.smb_client import SMBClient
from app.core.rpc_transport import RPCTransport

def test_smb_connection(target: str, username: str = "", password: str = "", domain: str = ""):
    """Test SMB connection with diagnostics"""
    
    print(f"Testing SMB connection to {target}")
    print("=" * 50)
    
    # Step 1: Run comprehensive diagnostics
    print("STEP 1: Running comprehensive diagnostics...")
    results = diagnose_smb_connection(target)
    
    # Step 2: Test the fixed SMB client
    print("\nSTEP 2: Testing improved SMB client...")
    
    client = SMBClient(target)
    client.debug = True  # Enable debug output
    
    print(f"Attempting connection with credentials: {domain}\\{username}")
    success = client.connect(username, password, domain)
    
    if success:
        print("[+] SMB client connection successful!")
        
        # Test pipe operations
        print("\nSTEP 3: Testing named pipe operations...")
        
        pipe_handle = client.open_pipe("samr")
        if pipe_handle:
            print("[+] Named pipe 'samr' opened successfully")
            client.close_pipe(pipe_handle)
        else:
            print("[-] Failed to open named pipe 'samr'")
        
        client.disconnect()
        
    else:
        print("[-] SMB client connection failed")
        
        # Analyze diagnostic results for specific recommendations
        print("\nAnalyzing diagnostic results...")
        
        tcp_success = results['tests'].get('tcp_connectivity', {}).get('success', False)
        netbios_success = results['tests'].get('netbios_session', {}).get('success', False)
        smb_success = results['tests'].get('smb_negotiation', {}).get('success', False)
        
        if not tcp_success:
            print("[!] TCP connectivity failed - check network and firewall")
        elif not netbios_success:
            print("[!] NetBIOS session failed - trying direct SMB...")
            # Try direct SMB connection
            test_direct_smb(target, username, password, domain)
        elif not smb_success:
            print("[!] SMB negotiation failed - check SMB version compatibility")
        else:
            print("[!] Unknown connection issue - check credentials and permissions")
    
    return success

def test_direct_smb(target: str, username: str = "", password: str = "", domain: str = ""):
    """Test direct SMB connection without NetBIOS session"""
    print("\nTesting direct SMB connection (bypassing NetBIOS)...")
    
    # Create a modified SMB client that skips NetBIOS
    client = SMBClient(target)
    client.debug = True
    
    # Monkey patch to skip NetBIOS session
    original_establish = client._establish_netbios_session
    client._establish_netbios_session = lambda: True  # Always return True
    
    success = client.connect(username, password, domain)
    
    # Restore original method
    client._establish_netbios_session = original_establish
    
    if success:
        print("[+] Direct SMB connection successful!")
        client.disconnect()
        return True
    else:
        print("[-] Direct SMB connection also failed")
        return False

def test_rpc_transport(target: str, username: str = "", password: str = "", domain: str = ""):
    """Test RPC transport layer"""
    print(f"\nSTEP 4: Testing RPC transport to {target}...")
    
    transport = RPCTransport(target)
    transport.debug = True
    
    success = transport.connect(username, password, domain)
    
    if success:
        print("[+] RPC transport connection successful!")
        
        # Test interface binding
        import uuid
        samr_uuid = uuid.UUID('12345778-1234-ABCD-EF00-0123456789AC')
        
        if transport.bind_interface(samr_uuid, (1, 0)):
            print("[+] SAMR interface binding successful!")
        else:
            print("[-] SAMR interface binding failed")
        
        transport.disconnect()
        
    else:
        print("[-] RPC transport connection failed")
    
    return success

def main():
    """Main test function"""
    if len(sys.argv) < 2:
        print("Usage: python test_smb_connection.py <target> [username] [password] [domain]")
        print("Example: python test_smb_connection.py 192.168.1.106 admin password LAB")
        sys.exit(1)
    
    target = sys.argv[1]
    username = sys.argv[2] if len(sys.argv) > 2 else ""
    password = sys.argv[3] if len(sys.argv) > 3 else ""
    domain = sys.argv[4] if len(sys.argv) > 4 else ""
    
    print("SMB Connection Test and Diagnostic Tool")
    print("=" * 40)
    print(f"Target: {target}")
    print(f"Username: {username}")
    print(f"Domain: {domain}")
    print("=" * 40)
    
    # Test SMB connection
    smb_success = test_smb_connection(target, username, password, domain)
    
    # Test RPC transport if SMB works
    if smb_success:
        rpc_success = test_rpc_transport(target, username, password, domain)
        
        if rpc_success:
            print("\n[SUCCESS] All tests passed! RPC scanner should work now.")
        else:
            print("\n[WARNING] SMB works but RPC transport failed - check RPC configuration")
    else:
        print("\n[ERROR] SMB connection failed - RPC scanner will not work")
        print("\nTry these solutions:")
        print("1. Check network connectivity and firewall rules")
        print("2. Verify SMB service is running on target")
        print("3. Check credentials and permissions")
        print("4. Try different SMB versions or authentication methods")

if __name__ == "__main__":
    main()