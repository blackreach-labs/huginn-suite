#!/usr/bin/env python3

import socket
import struct
import hashlib
import os
import sys

def build_minimal_smb311():
    """Build minimal SMB 3.1.1 negotiate with only preauth context"""
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
    
    # Only preauth context - minimal version
    preauth_data = struct.pack("<HH", 1, 0)  # HashAlgorithmCount=1, SaltLength=0
    preauth_data += struct.pack("<H", 1)     # SHA-512 algorithm
    
    # Context header: Type(2) + DataLength(2) + Reserved(4) + Data
    preauth_ctx = struct.pack("<HHI", 1, len(preauth_data), 0) + preauth_data
    
    print(f"[DEBUG] Preauth data: {preauth_data.hex()}")
    print(f"[DEBUG] Preauth context: {preauth_ctx.hex()}")
    print(f"[DEBUG] Preauth context length: {len(preauth_ctx)}")
    
    # Calculate offsets
    negotiate_fixed = 36
    dialects_size = 2
    base_offset = 64 + negotiate_fixed + dialects_size
    context_offset = ((base_offset + 7) // 8) * 8
    pad_needed = context_offset - base_offset
    
    print(f"[DEBUG] Context offset: {context_offset}, padding: {pad_needed}")
    
    # Build negotiate request
    negotiate_body = (
        struct.pack("<H", 36) +                    # StructureSize
        struct.pack("<H", 1) +                     # DialectCount
        struct.pack("<H", 1) +                     # SecurityMode (signing enabled)
        struct.pack("<H", 0) +                     # Reserved
        struct.pack("<I", 0) +                     # Capabilities
        client_guid +                              # ClientGuid
        struct.pack("<I", context_offset) +        # NegotiateContextOffset
        struct.pack("<H", 1) +                     # NegotiateContextCount (only 1)
        struct.pack("<H", 0) +                     # Reserved2
        struct.pack("<H", 0x0311) +                # SMB 3.1.1 dialect
        b"\x00" * pad_needed +                     # Padding
        preauth_ctx                                # Preauth context
    )
    
    smb2_packet = smb2_header + negotiate_body
    print(f"[DEBUG] Complete packet: {len(smb2_packet)} bytes")
    print(f"[DEBUG] Packet hex: {smb2_packet.hex()}")
    
    return smb2_packet

def test_minimal_smb311(host):
    """Test minimal SMB 3.1.1 negotiate"""
    print(f"=== Testing minimal SMB 3.1.1 to {host} ===")
    
    packet_data = build_minimal_smb311()
    
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
        print("Usage: python test_minimal_smb311.py <host>")
        sys.exit(1)
    
    host = sys.argv[1]
    success = test_minimal_smb311(host)
    
    if success:
        print(f"\n✅ Minimal SMB 3.1.1 test PASSED")
    else:
        print(f"\n❌ Minimal SMB 3.1.1 test FAILED")