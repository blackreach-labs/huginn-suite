#!/usr/bin/env python3

import socket
import struct
import hashlib
import os
import sys
import time

def build_smb311_negotiate():
    """Build byte-perfect SMB 3.1.1 negotiate packet"""
    client_guid = os.urandom(16)
    
    print(f"[DEBUG] Client GUID: {client_guid.hex()}")

    # SMB2 header - exactly as per MS-SMB2
    smb2_header = struct.pack(
        "<4sHHIHHIIQIIQ16s",
        b"\xfeSMB",        # ProtocolId
        0x40,              # StructureSize (64)
        0x0001,            # CreditCharge
        0,                 # Status
        0x0000,            # Command (NEGOTIATE)
        0x0001,            # CreditRequest
        0,                 # Flags
        0,                 # NextCommand
        1,                 # MessageId
        0,                 # ProcessId
        0,                 # TreeId
        0,                 # SessionId
        b"\x00" * 16       # Signature (zero for negotiate)
    )
    
    print(f"[DEBUG] SMB2 header: {smb2_header.hex()}")
    print(f"[DEBUG] SMB2 header length: {len(smb2_header)} bytes")

    # Preauth Integrity Capabilities context - MS-SMB2 2.2.3.1.1
    preauth_data = struct.pack("<HH", 1, 0)  # HashAlgorithmCount=1, SaltLength=0
    preauth_data += struct.pack("<H", 0x0001)  # HashAlgorithms[0] = SHA-512
    # No salt (SaltLength=0)
    
    preauth_ctx = struct.pack("<HHI", 1, len(preauth_data), 0) + preauth_data
    # Pad to 8-byte boundary
    pad_len = (8 - (len(preauth_ctx) % 8)) % 8
    if pad_len > 0:
        preauth_ctx += b"\x00" * pad_len
    
    print(f"[DEBUG] Preauth context: {len(preauth_ctx)} bytes")
    print(f"[DEBUG] Preauth context hex: {preauth_ctx.hex()}")

    # Encryption Capabilities context - MS-SMB2 2.2.3.1.2
    enc_data = struct.pack("<H", 1)  # CipherCount=1
    enc_data += struct.pack("<H", 0x0001)  # Ciphers[0] = AES-128-CCM
    
    enc_ctx = struct.pack("<HHI", 2, len(enc_data), 0) + enc_data  # ContextType=2
    # Pad to 8-byte boundary
    pad_len = (8 - (len(enc_ctx) % 8)) % 8
    if pad_len > 0:
        enc_ctx += b"\x00" * pad_len
    
    print(f"[DEBUG] Encryption context: {len(enc_ctx)} bytes")
    print(f"[DEBUG] Encryption context hex: {enc_ctx.hex()}")

    # Negotiate body
    dialects = [0x0311]
    dialect_bytes = struct.pack("<H", 0x0311)
    
    print(f"[DEBUG] Dialect bytes: {dialect_bytes.hex()}")

    # Calculate context offset - must be 8-byte aligned from start of SMB2 packet
    fixed_part = 36  # negotiate request structure size
    dialects_size = 2  # one dialect (2 bytes)
    base_offset = 64 + fixed_part + dialects_size  # SMB2 header + negotiate + dialects
    context_offset = ((base_offset + 7) // 8) * 8  # round up to 8-byte boundary
    
    print(f"[DEBUG] Fixed part: {fixed_part}")
    print(f"[DEBUG] Dialects size: {dialects_size}")
    print(f"[DEBUG] Base offset: {base_offset}")
    print(f"[DEBUG] Context offset: {context_offset}")
    
    # Calculate padding needed
    pad_needed = context_offset - base_offset
    print(f"[DEBUG] Padding needed: {pad_needed}")

    negotiate_body = (
        struct.pack("<H", 36) +                   # StructureSize
        struct.pack("<H", 1) +                    # DialectCount
        struct.pack("<H", 0x0001) +               # SecurityMode (signing enabled)
        b"\x00\x00" +                             # Reserved
        struct.pack("<I", 0) +                    # Capabilities
        client_guid +                             # Client GUID
        struct.pack("<I", context_offset) +       # NegotiateContextOffset
        struct.pack("<H", 2) +                    # NegotiateContextCount
        b"\x00\x00" +                             # Reserved2
        dialect_bytes +                           # Dialects
        b"\x00" * pad_needed +                    # Padding to context offset
        preauth_ctx +                             # Preauth context
        enc_ctx                                   # Encryption context
    )
    
    print(f"[DEBUG] Negotiate body: {len(negotiate_body)} bytes")
    print(f"[DEBUG] Expected context start at offset: {context_offset - 64}")
    print(f"[DEBUG] Actual context start at offset: {36 + 2 + pad_needed}")
    print(f"[DEBUG] Negotiate body hex: {negotiate_body[:64].hex()}...")
    print(f"[DEBUG] Context area hex: {negotiate_body[36+2+pad_needed:36+2+pad_needed+32].hex()}...")

    smb2_packet = smb2_header + negotiate_body
    
    print(f"[DEBUG] Complete SMB2 packet: {len(smb2_packet)} bytes")
    
    # Compute preauth hash
    preauth_hash = hashlib.sha512(smb2_packet).digest()
    print(f"[DEBUG] Preauth hash: {preauth_hash.hex()}")
    
    return smb2_packet, preauth_hash, pad_needed

def nbss_wrap(smb2_bytes):
    """Wrap SMB2 packet with NetBIOS Session Service header"""
    length = len(smb2_bytes)
    return b'\x00' + struct.pack(">I", length)[1:] + smb2_bytes

def test_smb311_negotiate(host, port=445):
    """Test SMB 3.1.1 negotiate with detailed debugging"""
    print(f"=== Testing SMB 3.1.1 negotiate to {host}:{port} ===")
    
    # Build packet
    smb2_packet, preauth_hash, pad_needed = build_smb311_negotiate()
    
    # Wrap with NBSS
    packet = nbss_wrap(smb2_packet)
    print(f"[DEBUG] Final packet with NBSS: {len(packet)} bytes")
    print(f"[DEBUG] NBSS header: {packet[:4].hex()}")
    print(f"[DEBUG] Packet structure:")
    print(f"[DEBUG]   NBSS header (4): {packet[:4].hex()}")
    print(f"[DEBUG]   SMB2 header (64): {packet[4:68].hex()}")
    print(f"[DEBUG]   Negotiate fixed (36): {packet[68:104].hex()}")
    print(f"[DEBUG]   Dialects (2): {packet[104:106].hex()}")
    print(f"[DEBUG]   Padding ({pad_needed}): {packet[106:106+pad_needed].hex() if pad_needed > 0 else 'none'}")
    print(f"[DEBUG]   Contexts start: {packet[106+pad_needed:106+pad_needed+16].hex()}...")
    
    # Test connection
    sock = None
    try:
        print(f"[DEBUG] Creating socket...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        
        print(f"[DEBUG] Connecting to {host}:{port}...")
        start_time = time.time()
        sock.connect((host, port))
        connect_time = time.time() - start_time
        print(f"[DEBUG] Connected in {connect_time:.3f}s")
        
        print(f"[DEBUG] Local: {sock.getsockname()}")
        print(f"[DEBUG] Remote: {sock.getpeername()}")
        
        print(f"[DEBUG] Sending {len(packet)} bytes...")
        bytes_sent = sock.send(packet)
        print(f"[DEBUG] Sent {bytes_sent} bytes")
        print(f"[DEBUG] Packet successfully transmitted to network")
        
        # Small delay to ensure packet is processed
        time.sleep(0.1)
        
        if bytes_sent != len(packet):
            print(f"[ERROR] Partial send: {bytes_sent}/{len(packet)}")
            return False
        
        print(f"[DEBUG] Waiting for response...")
        
        # Try to receive NBSS header
        try:
            sock.settimeout(3.0)
            nbss_header = sock.recv(4)
            if not nbss_header:
                print(f"[ERROR] No NBSS header received (connection closed)")
                return False
                
            print(f"[DEBUG] NBSS header received: {nbss_header.hex()}")
            
            if len(nbss_header) < 4 or nbss_header[0] != 0x00:
                print(f"[ERROR] Invalid NBSS header")
                return False
            
            # Get payload length
            payload_len = struct.unpack(">I", b'\x00' + nbss_header[1:4])[0]
            print(f"[DEBUG] Payload length: {payload_len}")
            
            if payload_len > 0x10000:  # Sanity check
                print(f"[ERROR] Payload too large: {payload_len}")
                return False
            
            # Receive payload
            payload = b''
            while len(payload) < payload_len:
                chunk = sock.recv(payload_len - len(payload))
                if not chunk:
                    print(f"[ERROR] Connection closed during payload receive")
                    return False
                payload += chunk
            
            print(f"[DEBUG] Received {len(payload)} bytes payload")
            print(f"[DEBUG] Response SMB2 header: {payload[:64].hex()}")
            
            # Parse response
            if len(payload) >= 64:
                signature = payload[:4]
                status = struct.unpack("<I", payload[8:12])[0]
                command = struct.unpack("<H", payload[12:14])[0]
                
                print(f"[DEBUG] Response signature: {signature.hex()}")
                print(f"[DEBUG] Response status: 0x{status:08x}")
                print(f"[DEBUG] Response command: 0x{command:04x}")
                
                if signature == b'\xfeSMB':
                    print(f"[SUCCESS] Valid SMB2 response received!")
                    
                    if status == 0:
                        print(f"[SUCCESS] Negotiate succeeded!")
                        
                        # Parse negotiate response
                        if len(payload) >= 70:
                            body = payload[64:]
                            security_mode = struct.unpack("<H", body[2:4])[0]
                            dialect = struct.unpack("<H", body[4:6])[0]
                            
                            print(f"[SUCCESS] Security mode: 0x{security_mode:04x}")
                            print(f"[SUCCESS] Negotiated dialect: 0x{dialect:04x}")
                            
                            dialect_map = {0x0311: "3.1.1", 0x0302: "3.0.2", 0x0300: "3.0", 0x0210: "2.1"}
                            dialect_name = dialect_map.get(dialect, f"Unknown-0x{dialect:04x}")
                            print(f"[SUCCESS] Dialect: SMB {dialect_name}")
                            
                            return True
                    else:
                        print(f"[ERROR] Negotiate failed with status 0x{status:08x}")
                else:
                    print(f"[ERROR] Invalid SMB2 signature in response")
            else:
                print(f"[ERROR] Response too short")
                
        except socket.timeout:
            print(f"[ERROR] Timeout waiting for response")
        except Exception as e:
            print(f"[ERROR] Receive error: {type(e).__name__}: {e}")
            
    except Exception as e:
        print(f"[ERROR] Connection error: {type(e).__name__}: {e}")
        return False
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
        print("Usage: python test_smb311_debug.py <host>")
        sys.exit(1)
    
    host = sys.argv[1]
    success = test_smb311_negotiate(host)
    
    if success:
        print(f"\n✅ SMB 3.1.1 negotiate test PASSED")
    else:
        print(f"\n❌ SMB 3.1.1 negotiate test FAILED")
        sys.exit(1)