#!/usr/bin/env python3
"""
Debug SMB 3.1.1 packet construction with hex dumps
"""

import sys
import os
import struct
import hashlib
sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

def debug_smb311_packet():
    """Build and analyze SMB 3.1.1 packet with full debug"""
    
    client_guid = os.urandom(16)
    print(f"Client GUID: {client_guid.hex()}")
    
    # SMB2 header (64 bytes)
    smb2_header = struct.pack(
        "<4sHHIHHIIQIIQ16s",
        b"\xfeSMB",        # ProtocolId
        64,                # StructureSize
        1,                 # CreditCharge
        0,                 # Status
        0x0000,            # Command (NEGOTIATE)
        256,               # CreditRequest
        0,                 # Flags
        0,                 # NextCommand
        0,                 # MessageId
        0,                 # ProcessId
        0,                 # TreeId
        0,                 # SessionId
        b"\x00" * 16       # Signature
    )
    
    print(f"SMB2 Header ({len(smb2_header)} bytes):")
    print(f"  {smb2_header.hex()}")
    
    # Preauth Integrity Capabilities context
    salt = os.urandom(32)
    print(f"Salt: {salt.hex()}")
    
    preauth_data = struct.pack(
        "<HHHH", 
        1,              # HashAlgorithmCount
        32,             # SaltLength
        0x0001,         # SHA-512
        0               # Padding
    ) + salt
    
    preauth_ctx = struct.pack("<HHI", 1, len(preauth_data), 0) + preauth_data
    # 8-byte align
    pad_len = (8 - (len(preauth_ctx) % 8)) % 8
    preauth_ctx += b"\x00" * pad_len
    
    print(f"Preauth Context ({len(preauth_ctx)} bytes):")
    print(f"  {preauth_ctx.hex()}")
    
    # Encryption Capabilities context
    enc_data = struct.pack("<HHH", 1, 0, 0x0001)  # CipherCount=1, Reserved, AES-128-CCM
    enc_ctx = struct.pack("<HHI", 2, len(enc_data), 0) + enc_data
    # 8-byte align
    pad_len = (8 - (len(enc_ctx) % 8)) % 8
    enc_ctx += b"\x00" * pad_len
    
    print(f"Encryption Context ({len(enc_ctx)} bytes):")
    print(f"  {enc_ctx.hex()}")
    
    # Calculate context offset
    dialects = [0x0311]
    dialect_count = len(dialects)
    dialect_bytes = b"".join(struct.pack("<H", d) for d in dialects)
    
    base_body_size = 36 + (dialect_count * 2)  # Size until contexts
    pad_len = (8 - ((64 + base_body_size) % 8)) % 8
    context_offset = 64 + base_body_size + pad_len
    
    print(f"Context calculations:")
    print(f"  Base body size: {base_body_size}")
    print(f"  Padding length: {pad_len}")
    print(f"  Context offset: {context_offset}")
    
    # Negotiate body
    negotiate_body = (
        struct.pack("<H", 36) +                   # StructureSize
        struct.pack("<H", dialect_count) +        # DialectCount
        struct.pack("<H", 0x0001) +               # SecurityMode (signing enabled)
        b"\x00\x00" +                             # Reserved
        struct.pack("<I", 0) +                    # Capabilities
        client_guid +                             # Client GUID
        struct.pack("<I", context_offset) +       # NegotiateContextOffset
        struct.pack("<H", 2) +                    # NegotiateContextCount
        b"\x00\x00" +                             # Reserved2
        dialect_bytes +
        b"\x00" * pad_len +                       # Padding to context offset
        preauth_ctx +
        enc_ctx
    )
    
    print(f"Negotiate Body ({len(negotiate_body)} bytes):")
    print(f"  {negotiate_body.hex()}")
    
    # Complete SMB2 packet
    smb2_packet = smb2_header + negotiate_body
    
    print(f"Complete SMB2 Packet ({len(smb2_packet)} bytes):")
    print(f"  {smb2_packet.hex()}")
    
    # NBSS header
    nbss_length = len(smb2_packet)
    nbss_header = struct.pack(">I", nbss_length)
    
    print(f"NBSS Header ({len(nbss_header)} bytes):")
    print(f"  Length: {nbss_length} (0x{nbss_length:x})")
    print(f"  Header: {nbss_header.hex()}")
    
    # Complete packet
    complete_packet = nbss_header + smb2_packet
    
    print(f"Complete Packet ({len(complete_packet)} bytes):")
    print(f"  NBSS: {nbss_header.hex()}")
    print(f"  SMB2: {smb2_packet[:32].hex()}...")
    
    # Verify calculations
    print(f"\nVerification:")
    print(f"  NBSS says: {nbss_length} bytes")
    print(f"  SMB2 actual: {len(smb2_packet)} bytes")
    print(f"  Match: {nbss_length == len(smb2_packet)}")
    
    # Check context offset
    actual_context_start = 64 + base_body_size + pad_len
    print(f"  Context offset in packet: {context_offset}")
    print(f"  Actual context start: {actual_context_start}")
    print(f"  Match: {context_offset == actual_context_start}")

if __name__ == "__main__":
    debug_smb311_packet()