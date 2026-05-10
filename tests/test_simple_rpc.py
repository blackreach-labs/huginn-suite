#!/usr/bin/env python3
"""
Simple RPC test using existing Windows tools
"""
import subprocess
import sys
import socket
import logging

def test_rpc_access(target, domain, username, password):
    print(f"Testing RPC access to {target}")
    print(f"Domain: {domain}, Username: {username}")
    print("-" * 50)
    
    # Test 1: Basic connectivity
    print("1. Testing basic connectivity...")
    try:
        result = subprocess.run(['ping', '-n', '1', target], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print("   SUCCESS: Target is reachable")
        else:
            print("   FAILED: Target unreachable")
            return False
    except Exception:
        print("   FAILED: Ping test failed")
        return False
    
    # Test 2: Check if we can authenticate with net use
    print("2. Testing authentication with net use...")
    try:
        cmd = ['net', 'use', f'\\\\{target}\\IPC$', f'/user:{domain}\\{username}', password]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            print("   SUCCESS: Authentication successful")
            # Clean up
            subprocess.run(['net', 'use', f'\\\\{target}\\IPC$', '/delete'], 
                         capture_output=True, text=True, timeout=5)
        else:
            print(f"   FAILED: Authentication failed - {result.stderr.strip()}")
    except Exception as e:
        print(f"   ERROR: Authentication test failed - {e}")
    
    # Test 3: Registry access
    print("3. Testing remote registry access...")
    try:
        cmd = ['reg', 'query', f'\\\\{target}\\HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion', 
               '/v', 'ProductName']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0 and 'ProductName' in result.stdout:
            print("   SUCCESS: Remote registry accessible")
            # Extract OS info
            for line in result.stdout.split('\n'):
                if 'ProductName' in line:
                    print(f"   OS: {line.split('REG_SZ')[-1].strip()}")
        else:
            print("   FAILED: Remote registry access denied")
    except Exception as e:
        print(f"   ERROR: Registry test failed - {e}")
    
    # Test 4: Service enumeration
    print("4. Testing service enumeration...")
    try:
        cmd = ['sc', f'\\\\{target}', 'query', 'state=', 'all']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        
        if result.returncode == 0:
            services = []
            lines = result.stdout.split('\n')
            for line in lines:
                if line.strip().startswith('SERVICE_NAME:'):
                    service_name = line.split(':', 1)[1].strip()
                    services.append(service_name)
            
            print(f"   SUCCESS: Found {len(services)} services")
            if services:
                print("   Sample services:")
                for svc in services[:5]:
                    print(f"     - {svc}")
        else:
            print("   FAILED: Service enumeration failed")
    except Exception as e:
        print(f"   ERROR: Service test failed - {e}")
    
    # Test 5: RPC endpoint mapper
    print("5. Testing RPC endpoint mapper...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((target, 135))
        sock.close()
        
        if result == 0:
            print("   SUCCESS: RPC endpoint mapper (port 135) is accessible")
        else:
            print("   FAILED: RPC endpoint mapper not accessible")
    except Exception as e:
        print(f"   ERROR: RPC test failed - {e}")
    
    # Test 6: SMB port check
    print("6. Testing SMB port 445...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((target, 445))
        sock.close()
        
        if result == 0:
            print("   SUCCESS: SMB port 445 is accessible")
        else:
            print("   FAILED: SMB port 445 not accessible")
    except Exception as e:
        print(f"   ERROR: SMB port test failed - {e}")
    
    print("\nRPC access test completed.")

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: python test_simple_rpc.py <target> <domain> <username> <password>")
        sys.exit(1)
    
    target = sys.argv[1]
    domain = sys.argv[2]
    username = sys.argv[3]
    password = sys.argv[4]
    
    test_rpc_access(target, domain, username, password)