#!/usr/bin/env python3

import socket
import struct
import sys
import time

def test_port_445(host):
    """Test if port 445 is open and responsive"""
    print(f"=== Testing port 445 connectivity to {host} ===")
    
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        
        print(f"[DEBUG] Attempting TCP connection to {host}:445...")
        start_time = time.time()
        result = sock.connect_ex((host, 445))
        connect_time = time.time() - start_time
        
        if result == 0:
            print(f"[SUCCESS] Port 445 is OPEN (connected in {connect_time:.3f}s)")
            print(f"[DEBUG] Local: {sock.getsockname()}")
            print(f"[DEBUG] Remote: {sock.getpeername()}")
            return True
        else:
            print(f"[ERROR] Port 445 is CLOSED (error code: {result})")
            return False
            
    except Exception as e:
        print(f"[ERROR] Connection failed: {type(e).__name__}: {e}")
        return False
    finally:
        if sock:
            try:
                sock.close()
            except:
                pass

def test_smb1_negotiate(host):
    """Test SMB1 negotiate to see if server only supports SMB1"""
    print(f"\n=== Testing SMB1 negotiate to {host} ===")
    
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect((host, 445))
        
        # SMB1 negotiate request
        smb1_negotiate = (
            b'\x00\x00\x00\x85' +           # NetBIOS header (length = 133)
            b'\xff\x53\x4d\x42' +           # SMB1 signature
            b'\x72' +                       # SMB_COM_NEGOTIATE
            b'\x00\x00\x00\x00' +           # Status
            b'\x18' +                       # Flags
            b'\x53\xc8' +                   # Flags2
            b'\x00\x00' +                   # PidHigh
            b'\x00\x00\x00\x00\x00\x00\x00\x00' + # Signature
            b'\x00\x00' +                   # Reserved
            b'\xff\xfe' +                   # TID
            b'\x00\x00' +                   # PID
            b'\x00\x00' +                   # UID
            b'\x00\x00' +                   # MID
            b'\x00' +                       # WordCount
            b'\x62\x00' +                   # ByteCount
            b'\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00' +  # PC NETWORK PROGRAM 1.0
            b'\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00' +  # LANMAN1.0
            b'\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00' +  # Windows for Workgroups 3.1a
            b'\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00' +  # LM1.2X002
            b'\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00' +  # LANMAN2.1
            b'\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00'  # NT LM 0.12
        )
        
        print(f"[DEBUG] Sending SMB1 negotiate ({len(smb1_negotiate)} bytes)...")
        print(f"[DEBUG] SMB1 packet: {smb1_negotiate[:32].hex()}...")
        
        sock.send(smb1_negotiate)
        
        print(f"[DEBUG] Waiting for SMB1 response...")
        response = sock.recv(4096)
        
        if response:
            print(f"[SUCCESS] Received SMB1 response ({len(response)} bytes)!")
            print(f"[DEBUG] Response: {response[:64].hex()}...")
            
            # Check for SMB1 signature
            if len(response) >= 8 and response[4:8] == b'\xff\x53\x4d\x42':
                print(f"[SUCCESS] Valid SMB1 response detected!")
                print(f"[WARNING] Server supports SMB1 - potential security risk!")
                return True
            else:
                print(f"[ERROR] Invalid SMB1 response signature")
        else:
            print(f"[ERROR] No SMB1 response received")
            
    except Exception as e:
        print(f"[ERROR] SMB1 test failed: {type(e).__name__}: {e}")
    finally:
        if sock:
            try:
                sock.close()
            except:
                pass
    
    return False

def test_raw_data_send(host):
    """Test sending raw data to see server behavior"""
    print(f"\n=== Testing raw data send to {host} ===")
    
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect((host, 445))
        
        # Send some random data
        test_data = b'\x00\x00\x00\x04ABCD'
        print(f"[DEBUG] Sending test data: {test_data.hex()}")
        
        sock.send(test_data)
        
        print(f"[DEBUG] Waiting for response...")
        sock.settimeout(2.0)
        
        try:
            response = sock.recv(1024)
            if response:
                print(f"[INFO] Server responded with {len(response)} bytes: {response.hex()}")
            else:
                print(f"[INFO] Server closed connection gracefully")
        except socket.timeout:
            print(f"[INFO] No response (timeout) - server may be filtering")
        
    except Exception as e:
        print(f"[ERROR] Raw data test failed: {type(e).__name__}: {e}")
    finally:
        if sock:
            try:
                sock.close()
            except:
                pass

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python test_smb_port_check.py <host>")
        sys.exit(1)
    
    host = sys.argv[1]
    
    # Test 1: Basic port connectivity
    port_open = test_port_445(host)
    
    if not port_open:
        print(f"\n❌ Port 445 is not accessible on {host}")
        sys.exit(1)
    
    # Test 2: SMB1 support
    smb1_works = test_smb1_negotiate(host)
    
    # Test 3: Raw data behavior
    test_raw_data_send(host)
    
    print(f"\n=== Summary ===")
    print(f"Port 445: {'✅ Open' if port_open else '❌ Closed'}")
    print(f"SMB1: {'✅ Supported' if smb1_works else '❌ Not supported'}")
    
    if smb1_works:
        print(f"\n⚠️  Server supports SMB1 - this is a security risk!")
        print(f"   SMB1 is vulnerable to EternalBlue (MS17-010)")
    else:
        print(f"\n🔒 Server appears to reject all SMB traffic")
        print(f"   This could indicate:")
        print(f"   - SMB is completely disabled")
        print(f"   - Firewall is blocking SMB")
        print(f"   - Server requires specific SMB configuration")