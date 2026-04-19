#!/usr/bin/env python3

import socket
import struct
import os
import sys

def build_smb21_negotiate():
    """Build simple SMB 2.1 negotiate without contexts"""
    client_guid = os.urandom(16)
    
    # SMB2 header
    smb2_header = struct.pack(
        "<4sHHIHHIIQIIQ16s",
        b"\xfeSMB",        # ProtocolId
        64,                # StructureSize
        1,                 # CreditCharge
        0,                 # Status
        0,                 # Command (NEGOTIATE)
        1,                 # CreditRequest
        0,                 # Flags
        0,                 # NextCommand
        1,                 # MessageId
        0,                 # ProcessId
        0,                 # TreeId
        0,                 # SessionId
        b"\x00" * 16       # Signature
    )
    
    print(f"[DEBUG] SMB2 header: {smb2_header.hex()}")
    
    # Simple negotiate request - no contexts
    negotiate_body = (
        struct.pack("<H", 36) +                    # StructureSize
        struct.pack("<H", 1) +                     # DialectCount
        struct.pack("<H", 0) +                     # SecurityMode
        struct.pack("<H", 0) +                     # Reserved
        struct.pack("<I", 0) +                     # Capabilities
        client_guid +                              # ClientGuid
        struct.pack("<I", 0) +                     # NegotiateContextOffset (0 = no contexts)
        struct.pack("<H", 0) +                     # NegotiateContextCount (0)
        struct.pack("<H", 0) +                     # Reserved2
        struct.pack("<H", 0x0210)                  # SMB 2.1 dialect
    )
    
    smb2_packet = smb2_header + negotiate_body
    print(f"[DEBUG] Complete packet: {len(smb2_packet)} bytes")
    print(f"[DEBUG] Packet hex: {smb2_packet.hex()}")
    
    return smb2_packet

def test_smb21_baseline(host):
    """Test baseline SMB 2.1 negotiate"""
    print(f"=== Testing baseline SMB 2.1 to {host} ===")
    
    packet_data = build_smb21_negotiate()
    
    # Wrap with NBSS
    nbss_packet = b'\x00' + struct.pack(">I", len(packet_data))[1:] + packet_data
    print(f"[DEBUG] NBSS packet: {len(nbss_packet)} bytes")
    
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect((host, 445))
        
        print(f"[DEBUG] Connected, sending {len(nbss_packet)} bytes...")
        sock.send(nbss_packet)
        
        print(f"[DEBUG] Waiting for response...")
        response = sock.recv(4096)
        
        if response:
            print(f"[SUCCESS] Received {len(response)} bytes!")
            print(f"[DEBUG] Response: {response.hex()}")
            
            if len(response) >= 8:
                nbss_len = struct.unpack(">I", b'\x00' + response[1:4])[0]
                smb2_data = response[4:4+nbss_len]
                
                if len(smb2_data) >= 12:
                    status = struct.unpack("<I", smb2_data[8:12])[0]
                    print(f"[DEBUG] SMB2 status: 0x{status:08x}")
                    
                    if status == 0:
                        print(f"[SUCCESS] Negotiate succeeded!")
                        
                        # Parse response
                        if len(smb2_data) >= 70:
                            body = smb2_data[64:]
                            security_mode = struct.unpack("<H", body[2:4])[0]
                            dialect = struct.unpack("<H", body[4:6])[0]
                            
                            print(f"[SUCCESS] Security mode: 0x{security_mode:04x}")
                            print(f"[SUCCESS] Negotiated dialect: 0x{dialect:04x}")
                            
                            dialect_map = {0x0210: "2.1", 0x0300: "3.0", 0x0302: "3.0.2", 0x0311: "3.1.1"}
                            dialect_name = dialect_map.get(dialect, f"Unknown-0x{dialect:04x}")
                            print(f"[SUCCESS] Server supports: SMB {dialect_name}")
                            
                        return True
                    else:
                        print(f"[ERROR] Negotiate failed: 0x{status:08x}")
        else:
            print(f"[ERROR] No response received")
            
    except Exception as e:
        print(f"[ERROR] {type(e).__name__}: {e}")
    finally:
        if sock:
            sock.close()
    
    return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python test_smb21_baseline.py <host>")
        sys.exit(1)
    
    host = sys.argv[1]
    success = test_smb21_baseline(host)
    
    if success:
        print(f"\n✅ SMB 2.1 baseline test PASSED")
    else:
        print(f"\n❌ SMB 2.1 baseline test FAILED")