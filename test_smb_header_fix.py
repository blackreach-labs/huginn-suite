#!/usr/bin/env python3

import socket
import struct
import os
import sys

def build_correct_smb2_negotiate():
    """Build SMB2 negotiate with correct header structure"""
    client_guid = os.urandom(16)
    
    # Correct SMB2 header structure per MS-SMB2
    smb2_header = struct.pack(
        "<4sHHIHHIIQIIQ16s",
        b"\xfeSMB",        # ProtocolId (4 bytes)
        64,                # StructureSize (2 bytes) - always 64 for SMB2 header
        1,                 # CreditCharge (2 bytes)
        0,                 # Status (4 bytes) - NT_STATUS
        0,                 # Command (2 bytes) - SMB2_NEGOTIATE = 0
        1,                 # CreditRequest (2 bytes)
        0,                 # Flags (4 bytes)
        0,                 # NextCommand (4 bytes)
        1,                 # MessageId (8 bytes)
        0,                 # ProcessId (4 bytes) - reserved
        0,                 # TreeId (4 bytes)
        0,                 # SessionId (8 bytes)
        b"\x00" * 16       # Signature (16 bytes)
    )
    
    print(f"[DEBUG] SMB2 header length: {len(smb2_header)} (should be 64)")
    print(f"[DEBUG] SMB2 header: {smb2_header.hex()}")
    
    # Verify header is exactly 64 bytes
    if len(smb2_header) != 64:
        print(f"[ERROR] Header is {len(smb2_header)} bytes, should be 64!")
        return None
    
    # SMB2 NEGOTIATE request body
    negotiate_body = struct.pack(
        "<HHHHI16sIHH",
        36,                # StructureSize (2 bytes) - always 36 for negotiate
        1,                 # DialectCount (2 bytes)
        0,                 # SecurityMode (2 bytes) - no signing required
        0,                 # Reserved (2 bytes)
        0,                 # Capabilities (4 bytes)
        client_guid,       # ClientGuid (16 bytes)
        0,                 # NegotiateContextOffset (4 bytes) - 0 means no contexts
        0,                 # NegotiateContextCount (2 bytes)
        0                  # Reserved2 (2 bytes)
    )
    
    # Add dialect
    negotiate_body += struct.pack("<H", 0x0210)  # SMB 2.1
    
    print(f"[DEBUG] Negotiate body length: {len(negotiate_body)}")
    print(f"[DEBUG] Negotiate body: {negotiate_body.hex()}")
    
    smb2_packet = smb2_header + negotiate_body
    print(f"[DEBUG] Complete SMB2 packet: {len(smb2_packet)} bytes")
    
    return smb2_packet

def test_corrected_smb2(host):
    """Test corrected SMB2 negotiate"""
    print(f"=== Testing corrected SMB2 header to {host} ===")
    
    packet_data = build_correct_smb2_negotiate()
    if not packet_data:
        return False
    
    # Wrap with NBSS
    nbss_packet = b'\x00' + struct.pack(">I", len(packet_data))[1:] + packet_data
    print(f"[DEBUG] NBSS packet: {len(nbss_packet)} bytes")
    print(f"[DEBUG] NBSS header: {nbss_packet[:4].hex()}")
    
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        
        print(f"[DEBUG] Connecting to {host}:445...")
        sock.connect((host, 445))
        print(f"[DEBUG] Connected successfully")
        
        print(f"[DEBUG] Sending {len(nbss_packet)} bytes...")
        bytes_sent = sock.send(nbss_packet)
        print(f"[DEBUG] Sent {bytes_sent} bytes")
        
        if bytes_sent != len(nbss_packet):
            print(f"[WARNING] Partial send: {bytes_sent}/{len(nbss_packet)}")
        
        print(f"[DEBUG] Waiting for response...")
        sock.settimeout(3.0)
        response = sock.recv(4096)
        
        if response:
            print(f"[SUCCESS] Received {len(response)} bytes!")
            print(f"[DEBUG] Response hex: {response.hex()}")
            
            if len(response) >= 8:
                # Parse NBSS header
                if response[0] == 0x00:
                    nbss_len = struct.unpack(">I", b'\x00' + response[1:4])[0]
                    print(f"[DEBUG] NBSS payload length: {nbss_len}")
                    
                    if len(response) >= 4 + nbss_len:
                        smb2_data = response[4:4+nbss_len]
                        print(f"[DEBUG] SMB2 data: {len(smb2_data)} bytes")
                        
                        if len(smb2_data) >= 64:
                            # Check SMB2 signature
                            signature = smb2_data[:4]
                            print(f"[DEBUG] SMB2 signature: {signature.hex()}")
                            
                            if signature == b'\xfeSMB':
                                print(f"[SUCCESS] Valid SMB2 response!")
                                
                                # Parse status
                                status = struct.unpack("<I", smb2_data[8:12])[0]
                                print(f"[DEBUG] Status: 0x{status:08x}")
                                
                                if status == 0:
                                    print(f"[SUCCESS] Negotiate succeeded!")
                                    
                                    # Parse negotiate response
                                    if len(smb2_data) >= 70:
                                        body = smb2_data[64:]
                                        security_mode = struct.unpack("<H", body[2:4])[0]
                                        dialect = struct.unpack("<H", body[4:6])[0]
                                        
                                        print(f"[SUCCESS] Security mode: 0x{security_mode:04x}")
                                        print(f"[SUCCESS] Negotiated dialect: 0x{dialect:04x}")
                                        
                                        dialect_map = {0x0210: "2.1", 0x0300: "3.0", 0x0302: "3.0.2", 0x0311: "3.1.1"}
                                        dialect_name = dialect_map.get(dialect, f"Unknown-0x{dialect:04x}")
                                        print(f"[SUCCESS] Server dialect: SMB {dialect_name}")
                                        
                                        return True
                                else:
                                    print(f"[ERROR] Negotiate failed with status: 0x{status:08x}")
                            else:
                                print(f"[ERROR] Invalid SMB2 signature: {signature.hex()}")
                        else:
                            print(f"[ERROR] SMB2 response too short: {len(smb2_data)} bytes")
                    else:
                        print(f"[ERROR] Incomplete NBSS packet")
                else:
                    print(f"[ERROR] Invalid NBSS header: {response[0]:02x}")
            else:
                print(f"[ERROR] Response too short: {len(response)} bytes")
        else:
            print(f"[ERROR] No response received")
            
    except socket.timeout:
        print(f"[ERROR] Timeout waiting for response")
    except Exception as e:
        print(f"[ERROR] {type(e).__name__}: {e}")
    finally:
        if sock:
            try:
                sock.close()
                print(f"[DEBUG] Socket closed")
            except:
                pass
    
    return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python test_smb_header_fix.py <host>")
        sys.exit(1)
    
    host = sys.argv[1]
    success = test_corrected_smb2(host)
    
    if success:
        print(f"\n✅ Corrected SMB2 test PASSED")
    else:
        print(f"\n❌ Corrected SMB2 test FAILED")