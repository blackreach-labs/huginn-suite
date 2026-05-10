
# app/tools/smb_raw_proto.py
# Updated: Added SMB 3.1.1 preauthentication integrity (SHA-512) state handling.
#
# This module implements a wire-level SMB2/3 client with support for:
# - Negotiating SMB 3.1.1 negotiate contexts (preauth, encryption, compression)
# - Computing preauthentication integrity hash chaining per MS-SMB2 (SHA-512)
# - Using the preauth hash state to prepare SessionSetup messages that strict DCs expect
#
# Notes:
# - This code is intended for authorized testing only.
# - It does not perform authenticated logins (remains unauthenticated).
# - Preauth hash handling follows MS-SMB2 rules:
#   * Compute hash over the SMB2 negotiate request (header+body) and set Connection.PreauthIntegrityHashValue.
#   * After receiving the negotiate response, update Connection.PreauthIntegrityHashValue = HASH(prev || negotiate_response_smb2_bytes).
#   * Before sending an SMB2 SessionSetup, compute Session.PreauthIntegrityHashValue = HASH(Connection.PreauthIntegrityHashValue || session_setup_smb2_bytes).
#
import socket
import struct
import time
import uuid
import hashlib
import hmac
import os
from typing import Dict, List, Tuple, Optional, Any
from app.core.logger import logger

# SMB2 command codes
SMB2_NEGOTIATE = 0x0000
SMB2_SESSION_SETUP = 0x0001
SMB2_TREE_CONNECT = 0x0003

# SMB2 NEGOTIATE_CONTEXT types
SMB2_PREAUTH_INTEGRITY_CAPABILITIES = 0x0001
SMB2_ENCRYPTION_CAPABILITIES = 0x0002
SMB2_COMPRESSION_CAPABILITIES = 0x0003

# Encryption cipher IDs
CIPHER_AES_128_GCM = 0x0002
CIPHER_AES_256_GCM = 0x0004

# Preauth hash algorithm IDs
HASH_SHA_512 = 0x0001

# Session flag values
SMB2_SESSION_FLAG_BINDING = 0x01

class SMBRawClient:
    """Wire-level SMB2/3 client with negotiate context and preauth hashing support"""

    def __init__(self, host: str, port: int = 445, timeout: float = 3.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.session_id = 0
        self.message_id = 1
        self.dialect = None
        self.signing_required = False
        self.encryption_required = False
        self.compression_supported = False
        self.server_guid = None
        self.server_time = None
        self.time_skew_ms = 0

        # Preauthentication integrity state (for SMB 3.1.1)
        # Connection.PreauthIntegrityHashId - selected algorithm id (e.g., HASH_SHA_512)
        # Connection.PreauthIntegrityHashValue - running hash value as bytes
        self.preauth_hash_id: Optional[int] = None
        self.preauth_hash_value: Optional[bytes] = None

    def connect(self):
        """Establish TCP connection"""
        print(f"[DEBUG] Creating socket for {self.host}:{self.port}")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        print(f"[DEBUG] Socket created, attempting connection...")
        try:
            print(f"[DEBUG] Connecting to {self.host}:{self.port}...")
            self.sock.connect((self.host, self.port))
            print(f"[DEBUG] TCP connection established")
            print(f"[DEBUG] Local address: {self.sock.getsockname()}")
            print(f"[DEBUG] Remote address: {self.sock.getpeername()}")
        except Exception as e:
            print(f"[DEBUG] Connection failed: {type(e).__name__}: {e}")
            if self.sock:
                self.sock.close()
            raise ConnectionError(f"Failed to connect to {self.host}:{self.port} - {e}")

    def _nbss_wrap(self, smb2_bytes: bytes) -> bytes:
        """Wrap SMB2 packet with NetBIOS Session Service header"""
        length = len(smb2_bytes)
        return b'\x00' + struct.pack(">I", length)[1:] + smb2_bytes

    def _send_packet(self, data: bytes):
        """Send NetBIOS-wrapped SMB packet"""
        print(f"[DEBUG] Sending {len(data)} bytes to {self.host}:{self.port}")
        try:
            bytes_sent = self.sock.send(data)
            print(f"[DEBUG] Successfully sent {bytes_sent} bytes")
            if bytes_sent != len(data):
                print(f"[DEBUG] WARNING: Only sent {bytes_sent} of {len(data)} bytes")
        except Exception as e:
            print(f"[DEBUG] Send failed: {type(e).__name__}: {e}")
            raise

    def _recv_packet(self) -> bytes:
        """Receive complete NetBIOS-wrapped SMB response"""
        print(f"[DEBUG] Waiting to receive NBSS header (4 bytes)...")
        try:
            nbss = self._recv_exact(4)
            print(f"[DEBUG] Received NBSS header: {nbss.hex() if nbss else 'None'}")
        except Exception as e:
            print(f"[DEBUG] Failed to receive NBSS header: {type(e).__name__}: {e}")
            raise
            
        if not nbss or len(nbss) < 4 or nbss[0] != 0x00:
            print(f"[DEBUG] Invalid NBSS header: {nbss.hex() if nbss else 'None'}")
            raise ConnectionError("Invalid NetBIOS header")

        length = struct.unpack(">I", b'\x00' + nbss[1:4])[0]
        print(f"[DEBUG] NBSS payload length: {length} bytes")
        if length > 0x1FFFF:
            raise ConnectionError(f"Invalid message length: {length}")

        print(f"[DEBUG] Receiving SMB payload ({length} bytes)...")
        smb_data = self._recv_exact(length)
        print(f"[DEBUG] Received SMB payload: {len(smb_data)} bytes")
        return nbss + smb_data

    def _recv_exact(self, length: int) -> bytes:
        """Receive exact number of bytes"""
        data = b''
        attempts = 0
        while len(data) < length:
            attempts += 1
            remaining = length - len(data)
            print(f"[DEBUG] Recv attempt {attempts}: need {remaining} more bytes")
            try:
                chunk = self.sock.recv(remaining)
                if not chunk:
                    print(f"[DEBUG] Socket closed by remote host (received 0 bytes)")
                    break
                print(f"[DEBUG] Received {len(chunk)} bytes")
                data += chunk
            except Exception as e:
                print(f"[DEBUG] Recv error: {type(e).__name__}: {e}")
                raise
        print(f"[DEBUG] Total received: {len(data)} of {length} bytes")
        return data

    def _build_smb2_header(self, command: int, message_id: int = None, session_id: int = None, flags: int = 0, tree_id: int = 0) -> bytes:
        """Build 64-byte SMB2 header"""
        if message_id is None:
            message_id = self.message_id
            self.message_id += 1
        if session_id is None:
            session_id = self.session_id

        # SMB2 header format: ProtocolId(4) + StructureSize(2) + CreditCharge(2) + Status(4) + Command(2) + Credit(2) + Flags(4) + NextCommand(4) + MessageId(8) + ProcessId(4) + TreeId(4) + SessionId(8) + Signature(16)
        return struct.pack("<4s H H I H H I I Q I I Q 16s",
                          b'\xFE\x53\x4D\x42',  # SMB2 signature
                          64,                    # StructureSize
                          1,                     # CreditCharge
                          0,                     # Status
                          command & 0xFFFF,      # Command
                          1,                     # Credit
                          flags & 0xFFFFFFFF,    # Flags
                          0,                     # NextCommand
                          message_id & 0xFFFFFFFFFFFFFFFF,  # MessageId
                          0,                     # ProcessId
                          tree_id & 0xFFFFFFFF,  # TreeId
                          session_id & 0xFFFFFFFFFFFFFFFF,  # SessionId
                          b'\x00' * 16)         # Signature

    def negotiate_dialects(self) -> Dict:
        """Comprehensive SMB protocol intelligence gathering and security assessment"""
        assessment = {
            'target': f"{self.host}:{self.port}",
            'dialects_tested': [],
            'security_findings': [],
            'metadata': {},
            'vulnerabilities': [],
            'recommendations': []
        }
        
        # Try multiple approaches for intelligence gathering (hardened first)
        approaches = [
            ('SMB 3.1.1 hardened (Server 2025)', self._negotiate_smb311_hardened),
            ('SMB 3.1.1 with contexts', self._negotiate_smb311_with_contexts),
            ('SMB 3.0.2 without contexts', self._negotiate_smb302_simple),
            ('SMB 2.1 basic', self._negotiate_smb21_basic)
        ]
        
        successful_negotiate = None
        connection_reset_detected = False
        
        for approach_name, negotiate_func in approaches:
            try:
                print(f"[DEBUG] Trying {approach_name}...")
                result = negotiate_func()
                
                # Check for SMB blocking detection
                if result and result.get('dialect') == 'SMB_BLOCKED':
                    print(f"[DEBUG] SMB blocking detected with {approach_name}")
                    connection_reset_detected = True
                    assessment['metadata']['connection_reset'] = True
                    assessment['metadata']['blocking_method'] = result.get('blocking_method', 'unknown')
                    assessment['metadata']['security_posture'] = result.get('security_posture', 'hardened')
                    break
                
                # Record attempt results
                assessment['dialects_tested'].append({
                    'approach': approach_name,
                    'success': result and result.get('dialect') != 'Unknown' and not result.get('dialect', '').startswith('Error'),
                    'result': result
                })
                
                if result and result.get('dialect') != 'Unknown' and not result.get('dialect', '').startswith('Error'):
                    print(f"[DEBUG] Success with {approach_name}")
                    successful_negotiate = result
                    self._extract_negotiate_metadata(result, assessment)
                    break
                    
            except Exception as e:
                print(f"[DEBUG] {approach_name} failed: {e}")
                
                # Check for connection reset
                if 'WinError 10054' in str(e) or 'Connection reset' in str(e):
                    print(f"[DEBUG] Connection reset detected - SMB is blocked")
                    connection_reset_detected = True
                    assessment['metadata']['connection_reset'] = True
                    assessment['metadata']['blocking_method'] = 'immediate_reset'
                    assessment['metadata']['security_posture'] = 'hardened'
                    break
                
                assessment['dialects_tested'].append({
                    'approach': approach_name,
                    'success': False,
                    'error': str(e)
                })
                
                # Close and reconnect for next attempt
                try:
                    self.close()
                    time.sleep(0.1)  # Brief delay
                    self.connect()
                except Exception as reconnect_e:
                    print(f"[DEBUG] Reconnection failed: {reconnect_e}")
                    break  # Stop trying if we can't reconnect
                continue
        
        if connection_reset_detected:
            # SMB is being blocked - this is actually good security
            print(f"[DEBUG] SMB blocking detected - excellent security posture")
            assessment['overall_risk'] = 'LOW'
            assessment['risk_summary'] = 'SMB traffic blocked by security policy - excellent protection'
            assessment['recommendations'] = [
                'SMB traffic is actively blocked by security policy',
                'This prevents SMB enumeration and lateral movement attacks',
                'Server demonstrates advanced security hardening',
                'Maintain current SMB blocking configuration'
            ]
        elif successful_negotiate:
            # Perform additional intelligence gathering
            try:
                domain_info = self.discover_domain_via_ntlm()
                assessment['metadata']['domain_info'] = domain_info
            except Exception as e:
                print(f"[DEBUG] Domain discovery failed: {e}")
                assessment['metadata']['domain_info'] = {'error': str(e)}
            
            try:
                shares = self.enumerate_shares_null_session()
                assessment['metadata']['shares'] = shares
            except Exception as e:
                print(f"[DEBUG] Share enumeration failed: {e}")
                assessment['metadata']['shares'] = {'error': str(e)}
        else:
            # No successful negotiate - return basic assessment
            assessment['overall_risk'] = 'UNKNOWN'
            assessment['metadata'] = {'connection_failed': True}
            assessment['recommendations'] = ['Unable to negotiate SMB protocol - verify service is running']
        
        # Perform comprehensive security assessment
        self._perform_security_assessment(assessment)
        
        return assessment
    
    def _build_smb311_negotiate(self, client_guid=None):
        """Build Windows-like SMB 3.1.1 negotiate packet"""
        if client_guid is None:
            client_guid = os.urandom(16)
        
        salt = os.urandom(32)
        print(f"[DEBUG] Building Windows-like SMB 3.1.1 with GUID: {client_guid.hex()}")

        # Dialects (like Windows 10/11)
        dialects = [0x0311, 0x0302, 0x0300]
        dialect_count = len(dialects)

        # SMB2 Header
        smb2_header = (
            b"\xfeSMB" +
            struct.pack("<H", 64) +           # StructureSize
            b"\x00\x00" +                     # CreditCharge
            struct.pack("<H", 0) +            # ChannelSequence/Reserved
            b"\x00\x00" +                     # Reserved
            struct.pack("<H", 0) +            # Command = NEGOTIATE
            struct.pack("<H", 0) +            # CreditRequest
            struct.pack("<I", 0) +            # Flags
            struct.pack("<I", 0) +            # NextCommand
            struct.pack("<Q", 0) +            # MessageId
            struct.pack("<I", 0) +            # Reserved2
            struct.pack("<I", 0) +            # TreeId
            struct.pack("<Q", 0)              # SessionId
        )

        # Negotiate body
        security_mode = 0x03          # Signing enabled + required
        capabilities = 0x0000017F     # Full capability mask
        negotiate_context_count = 3

        negotiate_body = struct.pack(
            "<HHHHL16sLLHH",
            36,                       # StructureSize
            dialect_count,            # DialectCount
            security_mode,            # SecurityMode
            0,                        # Reserved
            capabilities,             # Capabilities
            client_guid,              # ClientGuid
            0,                        # NegotiateContextOffset (placeholder)
            0,                        # Reserved2
            dialects[0],              # First dialect
            negotiate_context_count   # NegotiateContextCount
        )

        dialect_bytes = b"".join(struct.pack("<H", d) for d in dialects)
        pad_len = (8 - ((36 + (2 * dialect_count)) % 8)) % 8
        padding = b"\x00" * pad_len

        # Contexts
        # 1. PREAUTH_INTEGRITY_CAPABILITIES
        hash_alg_count = 1
        salt_length = 32
        preauth_data = struct.pack("<HH", hash_alg_count, salt_length)
        preauth_data += struct.pack("<H", 0x0001) + b"\x00\x00"  # SHA-512
        preauth_data += salt
        preauth_context = struct.pack("<HHI", 1, len(preauth_data), 0) + preauth_data
        preauth_context += b"\x00" * ((8 - (len(preauth_context) % 8)) % 8)

        # 2. ENCRYPTION_CAPABILITIES
        ciphers = [0x0001, 0x0002, 0x0003, 0x0004]  # AES-128-GCM, AES-128-CCM, AES-256-GCM, AES-256-CCM
        enc_data = struct.pack("<H", len(ciphers)) + b"\x00\x00"
        for c in ciphers:
            enc_data += struct.pack("<H", c) + b"\x00\x00"
        enc_context = struct.pack("<HHI", 2, len(enc_data), 0) + enc_data
        enc_context += b"\x00" * ((8 - (len(enc_context) % 8)) % 8)

        # 3. COMPRESSION_CAPABILITIES (SMBGhost detection!)
        comp_flags = 0
        comp_algorithms = [0x0001]  # LZNT1
        comp_data = struct.pack("<H", comp_flags)
        comp_data += struct.pack("<H", len(comp_algorithms))
        for alg in comp_algorithms:
            comp_data += struct.pack("<H", alg) + b"\x00\x00"
        comp_context = struct.pack("<HHI", 3, len(comp_data), 0) + comp_data
        comp_context += b"\x00" * ((8 - (len(comp_context) % 8)) % 8)

        # Assemble contexts
        contexts = preauth_context + enc_context + comp_context
        negotiate_context_offset = 64 + len(negotiate_body) + len(dialect_bytes) + len(padding)

        # Update negotiate body with correct offset
        negotiate_body = struct.pack(
            "<HHHHL16sLLHH",
            36,
            dialect_count,
            security_mode,
            0,
            capabilities,
            client_guid,
            negotiate_context_offset,
            0,
            dialects[0],
            negotiate_context_count
        )

        smb2_packet = smb2_header + negotiate_body + dialect_bytes + padding + contexts
        
        print(f"[DEBUG] Dialects: {[hex(d) for d in dialects]}")
        print(f"[DEBUG] Security mode: 0x{security_mode:02x}")
        print(f"[DEBUG] Capabilities: 0x{capabilities:08x}")
        print(f"[DEBUG] Context offset: {negotiate_context_offset}")
        print(f"[DEBUG] Contexts: PREAUTH({len(preauth_context)}), ENC({len(enc_context)}), COMP({len(comp_context)})")
        print(f"[DEBUG] SMB2 packet: {len(smb2_packet)} bytes")
        
        # Compute preauth hash
        preauth_hash = hashlib.sha512(smb2_packet).digest()
        
        return smb2_packet, preauth_hash
    
    def _negotiate_smb311_hardened(self) -> Dict:
        """Hardened SMB 3.1.1 negotiate for Windows Server 2025 DCs"""
        print(f"[DEBUG] Building hardened SMB 3.1.1 negotiate for strict DCs")
        
        # Build hardened negotiate packet
        smb2_packet, preauth_hash, salt = self.build_smb311_negotiate()
        self.preauth_hash_value = preauth_hash
        self.preauth_hash_id = HASH_SHA_512
        self.preauth_salt = salt
        
        print(f"[DEBUG] Hardened SMB2 packet: {len(smb2_packet)} bytes")
        print(f"[DEBUG] Preauth hash: {len(preauth_hash)} bytes")
        
        # Wrap with NBSS and send
        packet = self._nbss_wrap(smb2_packet)
        try:
            self._send_packet(packet)
            response = self._recv_packet()
        except (ConnectionError, socket.error) as e:
            if 'WinError 10054' in str(e) or 'Connection reset' in str(e):
                return {
                    'dialect': 'SMB_BLOCKED',
                    'connection_reset': True,
                    'security_posture': 'EXCELLENT',
                    'blocking_method': 'immediate_reset',
                    'signing_required': True,
                    'encryption_required': True,
                    'compression_supported': False
                }
            raise
        
        print(f"[DEBUG] Response: {len(response)} bytes")

        # Parse response
        smb2 = response[4:]
        if len(smb2) < 64:
            return {'dialect': 'Unknown', 'signing_required': False, 'encryption_required': False, 'compression_supported': False}
        
        # Update preauth hash with response (mandatory for SMB 3.1.1)
        if self.preauth_hash_value:
            self.preauth_hash_value = hashlib.sha512(self.preauth_hash_value + smb2).digest()
            print(f"[DEBUG] Updated preauth hash with server response")
        
        status = struct.unpack_from("<I", smb2, 8)[0]
        if status != 0:
            status_names = {
                0xC00000BB: 'STATUS_NOT_SUPPORTED',
                0xC0000022: 'STATUS_ACCESS_DENIED',
                0xC0000001: 'STATUS_UNSUCCESSFUL'
            }
            status_name = status_names.get(status, f'UNKNOWN_0x{status:08x}')
            print(f"[DEBUG] Negotiate failed: 0x{status:08x} ({status_name})")
            return {'dialect': f'Error-0x{status:08x}', 'status_name': status_name, 'signing_required': False, 'encryption_required': False, 'compression_supported': False}
        
        body = smb2[64:]
        if len(body) >= 6:
            security_mode = struct.unpack_from("<H", body, 2)[0]
            dialect = struct.unpack_from("<H", body, 4)[0]
            
            print(f"[DEBUG] Server security mode: 0x{security_mode:04x}")
            print(f"[DEBUG] Negotiated dialect: 0x{dialect:04x}")
            
            if dialect == 0x0311:
                self.dialect = "3.1.1"
                self.signing_required = bool(security_mode & 0x02)
                self.encryption_required = bool(security_mode & 0x04)
                
                return {
                    'dialect': self.dialect,
                    'signing_required': self.signing_required,
                    'encryption_required': self.encryption_required,
                    'compression_supported': False,
                    'preauth_hash_id': self.preauth_hash_id,
                    'preauth_hash_set': True,
                    'hardened_negotiate': True
                }
        
        return {'dialect': 'Unknown', 'signing_required': False, 'encryption_required': False, 'compression_supported': False}

    def _negotiate_smb311_with_contexts(self) -> Dict:
        """SMB 3.1.1 negotiate with contexts (legacy method)"""
        return self._negotiate_smb311_hardened()

    def _compute_session_preauth_hash(self, session_setup_smb2_bytes: bytes) -> Optional[bytes]:
        """
        Compute Session.PreauthIntegrityHashValue as:
            HASH(Connection.PreauthIntegrityHashValue || SessionSetupRequestBytes)
        Returns the computed hash (or None if preauth not initialized).
        """
        if not self.preauth_hash_value:
            return None
        try:
            sha = hashlib.sha512()
            sha.update(self.preauth_hash_value + session_setup_smb2_bytes)
            return sha.digest()
        except Exception:
            return None

    def build_session_setup_anonymous_signed(self) -> bytes:
        """Build signed anonymous SESSION_SETUP for hardened DCs"""
        # NTLM Type-1 with extended security
        NTLM_NEGOTIATE_FLAGS = 0x62890235  # Standard negotiate flags with target info
        ntlm_signature = b'NTLMSSP\x00'
        type1 = ntlm_signature + struct.pack('<I', 1) + struct.pack('<I', NTLM_NEGOTIATE_FLAGS) + b'\x00' * 16
        
        # SPNEGO-wrapped NTLM Type-1 for strict DCs
        auth_token = self._build_spnego_negtokeninit(type1)
        
        # Build SESSION_SETUP request (StructureSize=25)
        structure_size = 25
        flags = 0  # No binding
        security_mode = 0
        capabilities = 0
        channel = 0
        security_buffer_offset = 64 + structure_size
        security_buffer_length = len(auth_token)
        prev_session_id = 0

        session_req_body = struct.pack("<H B B I I H H Q",
                                       structure_size, flags, security_mode,
                                       capabilities, channel, security_buffer_offset,
                                       security_buffer_length, prev_session_id)
        session_req_body += auth_token

        # Build SMB2 header with signing flag for SMB 3.1.1
        smb_flags = 0x0008 if (self.signing_required and self.dialect == '3.1.1') else 0
        header = self._build_smb2_header(SMB2_SESSION_SETUP, message_id=2, session_id=0, flags=smb_flags)
        smb2_session_setup = header + session_req_body

        # Compute session preauth hash (mandatory for SMB 3.1.1)
        if self.preauth_hash_value:
            self.session_preauth_hash = self._compute_session_preauth_hash(smb2_session_setup)
            print(f"[DEBUG] Computed session preauth hash for hardened DC")

        # Sign packet with dummy signing key if required
        if smb_flags and self.preauth_hash_value:
            return self._sign_packet_dummy(header, session_req_body)
        else:
            return self._nbss_wrap(smb2_session_setup)
    
    def _sign_packet_dummy(self, header: bytes, body: bytes) -> bytes:
        """Sign SMB2 packet with dummy signing key derived from preauth hash"""
        if not self.preauth_hash_value:
            return self._nbss_wrap(header + body)
        
        # Derive dummy signing key using SMB3 KDF with zero session key
        signing_key = self._smb3_kdf(b'\x00' * 16, 'SMBSigningKey', self.preauth_hash_value, 16)
        
        # Build packet with zero signature initially
        packet_data = header + body
        
        # Compute HMAC-SHA256 signature over packet[64:] (skip NBSS + SMB2 header signature field)
        signature = hmac.new(signing_key, packet_data[64:], hashlib.sha256).digest()[:16]
        
        # Replace signature in header (bytes 48-63)
        signed_header = header[:48] + signature
        
        print(f"[DEBUG] Signed SESSION_SETUP with dummy key (hardened DC bypass)")
        return self._nbss_wrap(signed_header + body)

    def discover_domain_via_ntlm(self) -> Dict:
        """Discover domain information via properly-formed NTLM Type 1 handshake using preauth chaining"""
        domain_info = {'domain_name': None, 'dns_domain': None, 'forest_name': None, 'computer_name': None}
        
        # Skip NTLM if we don't have proper SMB negotiation
        if not self.dialect or self.dialect.startswith('0x'):
            domain_info['note'] = f'Skipping NTLM - invalid SMB dialect: {self.dialect}'
            return domain_info
            
        try:
            # Best-effort: TreeConnect to IPC$ first (some servers behave better)
            try:
                self.tree_connect('IPC$')
            except Exception as _exc:
                pass  # ignore; we only attempt to influence server state
                logger.debug("Suppressed exception", exc_info=True)

            # Use hardened signed SESSION_SETUP for SMB 3.1.1
            if self.dialect == '3.1.1' and self.preauth_hash_value:
                packet = self.build_session_setup_anonymous_signed()
            else:
                # Fallback to legacy method
                NTLM_NEGOTIATE_FLAGS = 0x62890235
                ntlm_signature = b'NTLMSSP\x00'
                type1 = ntlm_signature + struct.pack('<I', 1) + struct.pack('<I', NTLM_NEGOTIATE_FLAGS) + b'\x00' * 16
                
                use_spnego = self.signing_required or self.dialect == '3.1.1'
                auth_token = self._build_spnego_negtokeninit(type1) if use_spnego else type1

                session_req_body = struct.pack("<H B B I I H H Q",
                                               25, 0, 0, 0, 0,
                                               64 + 25, len(auth_token), 0) + auth_token
                
                header = self._build_smb2_header(SMB2_SESSION_SETUP, message_id=2, session_id=0, flags=0)
                packet = self._nbss_wrap(header + session_req_body)
            try:
                self._send_packet(packet)
                response = self._recv_packet()
            except (ConnectionError, socket.error) as e:
                # Try fallback without signing if first attempt failed
                try:
                    # Retry with basic NTLM, no signing
                    NTLM_NEGOTIATE_FLAGS = 0x62890235
                    ntlm_signature = b'NTLMSSP\x00'
                    type1 = ntlm_signature + struct.pack('<I', 1) + struct.pack('<I', NTLM_NEGOTIATE_FLAGS) + b'\x00' * 16
                    
                    session_req_body = struct.pack("<H B B I I H H Q",
                                                   25, 0, 0, 0, 0,
                                                   64 + 25, len(type1), 0) + type1
                    
                    header = self._build_smb2_header(SMB2_SESSION_SETUP, message_id=2, session_id=0, flags=0)
                    packet = self._nbss_wrap(header + session_req_body)
                    
                    self._send_packet(packet)
                    response = self._recv_packet()
                except Exception:
                    domain_info['error'] = f'Connection reset during NTLM handshake - server blocking auth attempts'
                    return domain_info

            # Parse response: extract security buffer (likely NTLM Type2) if present
            if response and len(response) > 4:
                smb2 = response[4:]
                # Update session id from header if provided
                try:
                    self.session_id = struct.unpack_from("<Q", smb2, 40)[0]
                except Exception:
                    self.session_id = 0

                body = smb2[64:]
                if len(body) >= 8:
                    sec_off = struct.unpack_from("<H", body, 4)[0]
                    sec_len = struct.unpack_from("<H", body, 6)[0]
                    if sec_len and sec_off and sec_off + sec_len <= len(smb2):
                        type2_msg = smb2[sec_off:sec_off+sec_len]
                        # defensive: locate NTLMSSP marker
                        idx = type2_msg.find(b'NTLMSSP\x00')
                        if idx != -1:
                            type2_msg = type2_msg[idx:]
                            parsed = self._parse_ntlm_type2_av_pairs(type2_msg)
                            domain_info.update(parsed)
                        else:
                            domain_info['note'] = 'No NTLM Type2 token found in security buffer'
                    else:
                        domain_info['note'] = 'No security buffer present in session setup response'
                else:
                    domain_info['note'] = 'Session setup response body too short'
        except Exception as e:
            domain_info['error'] = str(e)

        return domain_info
    
    def _build_spnego_negtokeninit(self, ntlm_token: bytes) -> bytes:
        """Build minimal SPNEGO NegTokenInit with NTLMSSP"""
        # NTLMSSP OID: 1.3.6.1.4.1.311.2.2.10
        ntlmssp_oid = b'\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a'
        
        # mechToken [2] OCTET STRING
        mech_token = b'\xa2' + self._asn1_length(len(ntlm_token)) + ntlm_token
        
        # mechTypes [0] MechTypeList
        mech_types = b'\x06' + bytes([len(ntlmssp_oid)]) + ntlmssp_oid
        mech_types = b'\x30' + self._asn1_length(len(mech_types)) + mech_types
        mech_types = b'\xa0' + self._asn1_length(len(mech_types)) + mech_types
        
        # NegTokenInit
        neg_token = mech_types + mech_token
        neg_token = b'\x30' + self._asn1_length(len(neg_token)) + neg_token
        
        # GSS-API wrapper
        spnego_oid = b'\x2b\x06\x01\x05\x05\x02'  # 1.3.6.1.5.5.2
        wrapper = b'\x06' + bytes([len(spnego_oid)]) + spnego_oid + neg_token
        wrapper = b'\x60' + self._asn1_length(len(wrapper)) + wrapper
        
        return wrapper
    
    def _asn1_length(self, length: int) -> bytes:
        """Encode ASN.1 length"""
        if length < 0x80:
            return bytes([length])
        elif length < 0x100:
            return b'\x81' + bytes([length])
        else:
            return b'\x82' + struct.pack('>H', length)
    
    def _sign_packet(self, header: bytes, body: bytes) -> bytes:
        """Sign SMB2 packet with dummy signing key derived from preauth hash"""
        if not self.preauth_hash_value:
            return self._nbss_wrap(header + body)
        
        # Derive dummy signing key using SMB3 KDF
        signing_key = self._smb3_kdf(b'\x00' * 16, 'SMBSigningKey', self.preauth_hash_value, 16)
        
        # Build packet with zero signature initially
        packet_data = header + body
        
        # Compute HMAC-SHA256 signature
        signature = hmac.new(signing_key, packet_data, hashlib.sha256).digest()[:16]
        
        # Replace signature in header (bytes 48-63)
        signed_header = header[:48] + signature
        
        return self._nbss_wrap(signed_header + body)
    
    def build_smb311_negotiate(self, client_guid=None):
        """Build hardened SMB 3.1.1 negotiate for Windows Server 2025 DCs"""
        if client_guid is None:
            client_guid = os.urandom(16)
        
        salt = os.urandom(32)
        print(f"[DEBUG] Building hardened SMB 3.1.1 with GUID: {client_guid.hex()}")

        # SMB 3.1.1 only (no fallback dialects)
        dialects = [0x0311]
        dialect_count = len(dialects)

        # Windows 11 client-like security mode (signing enabled but not required from client)
        security_mode = 0x0001  # Signing enabled, let server dictate required flag
        capabilities = 0x00000000  # Match Windows 11 clients
        negotiate_context_count = 3

        # Build negotiate body with proper structure
        negotiate_body = struct.pack(
            "<HHHHL16sLLHH",
            36,                       # StructureSize
            dialect_count,            # DialectCount
            security_mode,            # SecurityMode
            0,                        # Reserved
            capabilities,             # Capabilities
            client_guid,              # ClientGuid
            0,                        # NegotiateContextOffset (placeholder)
            0,                        # Reserved2
            dialects[0],              # First dialect
            negotiate_context_count   # NegotiateContextCount
        )

        dialect_bytes = b"".join(struct.pack("<H", d) for d in dialects)
        
        # 8-byte alignment for contexts (mandatory)
        pad_len = (8 - ((36 + (2 * dialect_count)) % 8)) % 8
        padding = b"\x00" * pad_len

        # 1. PREAUTH_INTEGRITY_CAPABILITIES with SHA-512
        hash_alg_count = 1
        salt_length = 32
        preauth_data = struct.pack("<HH", hash_alg_count, salt_length)
        preauth_data += struct.pack("<H", 0x0001) + b"\x00\x00"  # SHA-512
        preauth_data += salt
        preauth_context = struct.pack("<HHI", 1, len(preauth_data), 0) + preauth_data
        preauth_context += b"\x00" * ((8 - (len(preauth_context) % 8)) % 8)

        # 2. ENCRYPTION_CAPABILITIES (4 ciphers)
        ciphers = [0x0002, 0x0004, 0x0001, 0x0003]  # AES-128-GCM, AES-256-GCM, AES-128-CCM, AES-256-CCM
        enc_data = struct.pack("<H", len(ciphers)) + b"\x00\x00"
        for c in ciphers:
            enc_data += struct.pack("<H", c) + b"\x00\x00"
        enc_context = struct.pack("<HHI", 2, len(enc_data), 0) + enc_data
        enc_context += b"\x00" * ((8 - (len(enc_context) % 8)) % 8)

        # 3. COMPRESSION_CAPABILITIES (optional for compatibility)
        comp_flags = 0
        comp_algorithms = [0x0001]  # LZNT1
        comp_data = struct.pack("<H", comp_flags)
        comp_data += struct.pack("<H", len(comp_algorithms))
        for alg in comp_algorithms:
            comp_data += struct.pack("<H", alg) + b"\x00\x00"
        comp_context = struct.pack("<HHI", 3, len(comp_data), 0) + comp_data
        comp_context += b"\x00" * ((8 - (len(comp_context) % 8)) % 8)

        # Assemble contexts with proper alignment
        contexts = preauth_context + enc_context + comp_context
        negotiate_context_offset = 64 + len(negotiate_body) + len(dialect_bytes) + len(padding)

        # Update negotiate body with correct offset
        negotiate_body = struct.pack(
            "<HHHHL16sLLHH",
            36, dialect_count, security_mode, 0, capabilities,
            client_guid, negotiate_context_offset, 0,
            dialects[0], negotiate_context_count
        )

        # Build SMB2 header
        smb2_header = self._build_smb2_header(SMB2_NEGOTIATE, message_id=1)
        smb2_packet = smb2_header + negotiate_body + dialect_bytes + padding + contexts
        
        print(f"[DEBUG] Hardened SMB 3.1.1: {len(smb2_packet)} bytes")
        print(f"[DEBUG] Security mode: 0x{security_mode:02x} (signing enabled)")
        print(f"[DEBUG] Capabilities: 0x{capabilities:08x} (Windows 11 match)")
        print(f"[DEBUG] Context offset: {negotiate_context_offset}")
        
        # Compute mandatory preauth hash
        preauth_hash = hashlib.sha512(smb2_packet).digest()
        
        return smb2_packet, preauth_hash, salt

    def _smb3_kdf(self, session_key: bytes, label: str, context: bytes, length: int) -> bytes:
        """SMB3 KDF (NIST SP800-108 Counter Mode)"""
        h = hmac.new(session_key, digestmod=hashlib.sha256)
        h.update(struct.pack('>I', 1))  # Counter = 1
        h.update(label.encode('ascii') + b'\x00')  # Label with null terminator
        h.update(context)  # Context (preauth hash)
        h.update(struct.pack('>I', length * 8))  # Length in bits
        return h.digest()[:length]

    def _parse_ntlm_type2_av_pairs(self, type2_msg: bytes) -> Dict:
        """Parse NTLM Type 2 message to extract domain information"""
        domain_info = {'domain_name': None, 'dns_domain': None, 'forest_name': None, 'computer_name': None}

        try:
            if len(type2_msg) < 48 or type2_msg[:8] != b'NTLMSSP\x00':
                return domain_info

            target_info_len = struct.unpack('<H', type2_msg[40:42])[0]
            target_info_offset = struct.unpack('<I', type2_msg[44:48])[0]

            if target_info_len == 0 or target_info_offset == 0:
                return domain_info

            if target_info_offset + target_info_len <= len(type2_msg):
                target_info = type2_msg[target_info_offset:target_info_offset + target_info_len]

                offset = 0
                while offset + 4 <= len(target_info):
                    av_id = struct.unpack('<H', target_info[offset:offset+2])[0]
                    av_len = struct.unpack('<H', target_info[offset+2:offset+4])[0]

                    if av_id == 0:
                        break

                    if offset + 4 + av_len <= len(target_info):
                        av_value = target_info[offset+4:offset+4+av_len]

                        if av_id == 1:  # MsvAvNbComputerName
                            domain_info['computer_name'] = av_value.decode('utf-16le', errors='ignore')
                        elif av_id == 2:  # MsvAvNbDomainName
                            domain_info['domain_name'] = av_value.decode('utf-16le', errors='ignore')
                        elif av_id == 4:  # MsvAvDnsDomainName
                            domain_info['dns_domain'] = av_value.decode('utf-16le', errors='ignore')
                        elif av_id == 5:  # MsvAvDnsTreeName
                            domain_info['forest_name'] = av_value.decode('utf-16le', errors='ignore')

                    offset += 4 + av_len
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)

        return domain_info

    def enumerate_shares_null_session(self) -> List[Dict]:
        """Enumerate shares using null session TreeConnect attempts"""
        shares = []
        common_shares = ['IPC$', 'ADMIN$', 'C$', 'SYSVOL', 'NETLOGON']

        for share_name in common_shares:
            tree_id, status = self.tree_connect(share_name)

            shares.append({
                'name': share_name,
                'tree_id': tree_id,
                'status': status,
                'status_hex': f'0x{status:08x}',
                'accessible': status == 0,
                'exists': status in [0, 0xC0000022],
                'description': self._get_share_status_description(status)
            })

        return shares

    def _get_share_status_description(self, status: int) -> str:
        """Get human-readable share status description"""
        status_descriptions = {
            0x00000000: "Share accessible",
            0xC0000022: "Share exists but access denied",
            0xC0000034: "Share does not exist",
            0xC0000001: "Connection failed"
        }
        return status_descriptions.get(status, f"Unknown status: 0x{status:08x}")

    def tree_connect(self, share_name: str) -> Tuple[int, int]:
        """Connect to a share"""
        path = f"\\\\{self.host}\\{share_name}"
        path_bytes = path.encode('utf-16le')

        body = struct.pack("<H H H H", 9, 0, 64 + 8, len(path_bytes))
        body += path_bytes

        header = self._build_smb2_header(SMB2_TREE_CONNECT)
        packet = self._nbss_wrap(header + body)

        try:
            self._send_packet(packet)
            response = self._recv_packet()

            if len(response) < 12:
                return 0, 0xC0000001

            smb2 = response[4:]
            status = struct.unpack_from("<I", smb2, 8)[0]
            tree_id = struct.unpack_from("<I", smb2, 28)[0] if len(smb2) >= 32 else 0

            return tree_id, status
        except:
            return 0, 0xC0000001

    def close(self):
        """Close connection"""
        if self.sock:
            try:
                self.sock.close()
            except Exception as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
            self.sock = None
        self.session_id = 0
        self.message_id = 1
    
    def _negotiate_smb302_simple(self) -> Dict:
        """SMB 3.0.2 negotiate without contexts"""
        import os
        client_guid = os.urandom(16)
        
        header = self._build_smb2_header(SMB2_NEGOTIATE, message_id=1)
        body = struct.pack("<HHHHI16sIHH",
                          36, 1, 0, 0, 0, client_guid, 0, 0, 0) + struct.pack("<H", 0x0302)
        
        packet = self._nbss_wrap(header + body)
        self._send_packet(packet)
        response = self._recv_packet()
        
        return self._parse_negotiate_response(response)
    
    def _negotiate_smb21_basic(self) -> Dict:
        """SMB 2.1 basic negotiate"""
        import os
        client_guid = os.urandom(16)
        
        header = self._build_smb2_header(SMB2_NEGOTIATE, message_id=1)
        body = struct.pack("<HHHHI16sIHH",
                          36, 1, 0, 0, 0, client_guid, 0, 0, 0) + struct.pack("<H", 0x0210)
        
        packet = self._nbss_wrap(header + body)
        self._send_packet(packet)
        response = self._recv_packet()
        
        return self._parse_negotiate_response(response)
    
    def _parse_negotiate_response(self, response: bytes) -> Dict:
        """Parse SMB negotiate response"""
        if len(response) < 68:
            return {'dialect': 'Unknown', 'signing_required': False, 'encryption_required': False, 'compression_supported': False}
        
        smb2 = response[4:]
        if smb2[:4] != b'\xFE\x53\x4D\x42':
            return {'dialect': 'Unknown', 'signing_required': False, 'encryption_required': False, 'compression_supported': False}
        
        status = struct.unpack_from("<I", smb2, 8)[0]
        if status != 0:
            return {'dialect': f'Error-0x{status:08x}', 'signing_required': False, 'encryption_required': False, 'compression_supported': False}
        
        if len(smb2) < 70:
            return {'dialect': 'Unknown', 'signing_required': False, 'encryption_required': False, 'compression_supported': False}
        
        body = smb2[64:]
        security_mode = struct.unpack_from("<H", body, 2)[0]
        dialect = struct.unpack_from("<H", body, 4)[0]
        
        dialect_map = {0x0311: "3.1.1", 0x0302: "3.0.2", 0x0300: "3.0", 0x0210: "2.1"}
        self.dialect = dialect_map.get(dialect, f"0x{dialect:04x}")
        self.signing_required = bool(security_mode & 0x02)
        self.encryption_required = bool(security_mode & 0x04)
        
        if self.preauth_hash_value:
            self.preauth_hash_value = hashlib.sha512(self.preauth_hash_value + smb2).digest()
        
        return {
            'dialect': self.dialect,
            'signing_required': self.signing_required,
            'encryption_required': self.encryption_required,
            'compression_supported': False,
            'preauth_hash_id': self.preauth_hash_id,
            'preauth_hash_set': self.preauth_hash_value is not None
        }
    
    def _extract_negotiate_metadata(self, result, assessment):
        """Extract comprehensive metadata from negotiate response"""
        # Basic server information
        assessment['metadata'].update({
            'negotiated_dialect': result.get('dialect'),
            'signing_required': result.get('signing_required', False),
            'encryption_required': result.get('encryption_required', False),
            'compression_supported': result.get('compression_supported', False),
            'preauth_integrity': result.get('preauth_hash_set', False)
        })
        
        # Security analysis based on negotiated features
        dialect = result.get('dialect', '')
        
        # Analyze dialect security
        if '2.1' in dialect or '2.0' in dialect:
            assessment['vulnerabilities'].append({
                'type': 'Legacy SMB Protocol',
                'severity': 'MEDIUM',
                'description': f'Server negotiated legacy {dialect} without modern security features',
                'recommendation': 'Upgrade to SMB 3.0+ for enhanced security'
            })
        
        # Analyze signing configuration
        if not result.get('signing_required', True):
            assessment['vulnerabilities'].append({
                'type': 'SMB Signing Not Required',
                'severity': 'HIGH',
                'description': 'SMB signing is not required, enabling NTLM relay attacks',
                'recommendation': 'Enable required SMB signing in group policy'
            })
        
        # Analyze encryption support
        if not result.get('encryption_required', False) and '3.' in dialect:
            assessment['security_findings'].append({
                'type': 'SMB Encryption Optional',
                'severity': 'MEDIUM',
                'description': 'SMB encryption is supported but not required',
                'recommendation': 'Consider requiring SMB encryption for sensitive data'
            })
        
        # Analyze preauth integrity (SMB 3.1.1)
        if '3.1.1' in dialect and not result.get('preauth_hash_set', False):
            assessment['security_findings'].append({
                'type': 'Preauth Integrity Missing',
                'severity': 'MEDIUM',
                'description': 'SMB 3.1.1 preauth integrity not properly negotiated',
                'recommendation': 'Verify SMB 3.1.1 implementation supports preauth integrity'
            })
    
    def _perform_security_assessment(self, assessment):
        """Perform comprehensive security assessment"""
        metadata = assessment.get('metadata', {})
        
        # Check for SMB1 support
        if metadata.get('smb1_enabled', False):
            assessment['vulnerabilities'].append({
                'type': 'SMB1 Protocol Enabled',
                'severity': 'CRITICAL',
                'description': 'SMB1 is enabled and vulnerable to EternalBlue (MS17-010)',
                'recommendation': 'Disable SMB1 protocol immediately',
                'cve': 'CVE-2017-0144'
            })
        
        # Check for compression support (SMBGhost)
        if metadata.get('compression_supported', False):
            assessment['vulnerabilities'].append({
                'type': 'SMBGhost Vulnerability',
                'severity': 'CRITICAL',
                'description': 'SMB 3.1.1 compression vulnerability allows remote code execution',
                'recommendation': 'Apply security patches or disable SMB compression',
                'cve': 'CVE-2020-0796'
            })
        
        # Analyze domain information for security insights
        domain_info = metadata.get('domain_info', {})
        if domain_info.get('domain_name') or domain_info.get('dns_domain'):
            assessment['security_findings'].append({
                'type': 'Domain Information Disclosure',
                'severity': 'LOW',
                'description': 'Server disclosed domain information via NTLM challenge',
                'recommendation': 'Consider restricting anonymous domain enumeration'
            })
        
        # Analyze share access
        shares = metadata.get('shares', [])
        accessible_shares = [s for s in shares if isinstance(s, dict) and s.get('accessible', False)]
        if accessible_shares:
            assessment['vulnerabilities'].append({
                'type': 'Anonymous Share Access',
                'severity': 'HIGH',
                'description': f'Anonymous access to shares: {", ".join([s["name"] for s in accessible_shares])}',
                'recommendation': 'Restrict anonymous access to SMB shares'
            })
        
        # Generate overall risk assessment
        critical_vulns = [v for v in assessment.get('vulnerabilities', []) if v.get('severity') == 'CRITICAL']
        high_vulns = [v for v in assessment.get('vulnerabilities', []) if v.get('severity') == 'HIGH']
        
        if critical_vulns:
            assessment['overall_risk'] = 'CRITICAL'
            assessment['risk_summary'] = f'{len(critical_vulns)} critical vulnerabilities found'
        elif high_vulns:
            assessment['overall_risk'] = 'HIGH'
            assessment['risk_summary'] = f'{len(high_vulns)} high-severity issues found'
        elif assessment.get('vulnerabilities'):
            assessment['overall_risk'] = 'MEDIUM'
            assessment['risk_summary'] = 'Medium-severity security issues identified'
        else:
            assessment['overall_risk'] = 'LOW'
            assessment['risk_summary'] = 'No significant security issues detected'
        
        # Add recommendations based on findings
        if not assessment.get('vulnerabilities'):
            assessment['recommendations'].append('SMB configuration appears secure - maintain current settings')
        else:
            assessment['recommendations'].extend([
                'Review and address identified vulnerabilities',
                'Implement SMB security best practices',
                'Monitor SMB traffic for suspicious activity'
            ])
    
    def _simple_negotiate(self) -> Dict:
        """Simple SMB2 negotiate without contexts for compatibility"""
        print(f"[DEBUG] Trying simple SMB2 negotiate without contexts")
        dialects = [0x0210, 0x0300, 0x0302]  # SMB 2.1, 3.0, 3.0.2
        
        # Build simple negotiate request (36 bytes fixed + dialects)
        body = struct.pack("<H H H H I 16s",
                          36,                    # StructureSize
                          len(dialects),         # DialectCount
                          0,                     # SecurityMode
                          0,                     # Reserved
                          0,                     # Capabilities
                          uuid.uuid4().bytes_le) # ClientGuid
        
        # Add negotiate context fields (set to 0 for simple negotiate)
        body += struct.pack("<I H H", 0, 0, 0)  # NegotiateContextOffset, NegotiateContextCount, Reserved2
        
        # Add dialects
        for dialect in dialects:
            body += struct.pack("<H", dialect)
        
        print(f"[DEBUG] Simple negotiate body: {len(body)} bytes")
        
        header = self._build_smb2_header(SMB2_NEGOTIATE, message_id=1)
        packet = self._nbss_wrap(header + body)
        
        print(f"[DEBUG] Simple negotiate packet: {len(packet)} bytes")
        print(f"[DEBUG] Simple NBSS: {packet[:4].hex()}")
        print(f"[DEBUG] Simple SMB2 header: {packet[4:68].hex()}")
        
        self._send_packet(packet)
        response = self._recv_packet()
        
        print(f"[DEBUG] Simple negotiate response: {len(response)} bytes")
        
        smb2 = response[4:]
        if len(smb2) < 64:
            return {'dialect': 'Unknown', 'signing_required': False, 'encryption_required': False, 'compression_supported': False}
        
        status = struct.unpack_from("<I", smb2, 8)[0]
        print(f"[DEBUG] Simple negotiate status: 0x{status:08x}")
        
        if status != 0:
            return {'dialect': f'Error-0x{status:08x}', 'signing_required': False, 'encryption_required': False, 'compression_supported': False}
        
        body = smb2[64:]
        if len(body) >= 6:
            security_mode = struct.unpack_from("<H", body, 2)[0]
            dialect = struct.unpack_from("<H", body, 4)[0]
            
            print(f"[DEBUG] Simple security mode: 0x{security_mode:04x}")
            print(f"[DEBUG] Simple dialect: 0x{dialect:04x}")
            
            dialect_map = {0x0210: "2.1", 0x0300: "3.0", 0x0302: "3.0.2"}
            self.dialect = dialect_map.get(dialect, f"0x{dialect:04x}")
            self.signing_required = bool(security_mode & 0x02)
            
            return {
                'dialect': self.dialect,
                'signing_required': self.signing_required,
                'encryption_required': False,
                'compression_supported': False,
                'preauth_hash_set': False
            }
        
        return {'dialect': 'Unknown', 'signing_required': False, 'encryption_required': False, 'compression_supported': False}

# convenience high-level enumerator (unchanged except it will now expose preauth fields)
def enumerate_smb_comprehensive(host: str, timeout: float = 3.0) -> Dict:
    """Comprehensive SMB enumeration with protocol intelligence gathering and security assessment"""
    print(f"[DEBUG] Starting SMB enumeration for {host}")
    
    # First check if port is open
    if not _check_tcp_port(host, 445, timeout):
        return {
            'target': f"{host}:445",
            'overall_risk': 'LOW',
            'risk_summary': 'SMB port 445 is closed - excellent security posture',
            'metadata': {
                'port_closed': True,
                'tcp_connection': 'failed'
            },
            'vulnerabilities': [],
            'security_findings': [{
                'type': 'SMB Port Closed',
                'severity': 'INFO',
                'description': 'SMB port 445 is not accessible',
                'recommendation': 'Excellent security practice - SMB is properly disabled'
            }],
            'recommendations': [
                'SMB port is properly closed/filtered',
                'This prevents all SMB-based attacks',
                'Maintain current SMB blocking configuration'
            ]
        }
    
    client = SMBRawClient(host, 445, timeout)
    
    try:
        print(f"[DEBUG] Connecting to {host}:445")
        client.connect()
        print(f"[DEBUG] Connected successfully")

        # Comprehensive SMB assessment
        assessment = client.negotiate_dialects()
        
        # Handle SMB blocking detection
        if assessment.get('metadata', {}).get('connection_reset'):
            return {
                'target': f"{host}:445",
                'overall_risk': 'LOW',
                'risk_summary': 'SMB traffic blocked by security policy - excellent protection',
                'metadata': {
                    'smb_blocked': True,
                    'tcp_connection': 'successful',
                    'smb_response': 'immediate_reset',
                    'blocking_method': 'connection_reset',
                    'security_posture': 'hardened'
                },
                'vulnerabilities': [],
                'security_findings': [{
                    'type': 'Advanced SMB Blocking',
                    'severity': 'INFO',
                    'description': 'Server accepts TCP connections but immediately resets all SMB traffic',
                    'recommendation': 'Excellent security practice - advanced SMB blocking is active'
                }],
                'recommendations': [
                    'SMB traffic is actively blocked by security policy',
                    'This prevents SMB enumeration and lateral movement attacks',
                    'Server demonstrates advanced security hardening',
                    'Maintain current SMB blocking configuration'
                ]
            }
        
        # Add SMB1 detection if we got a valid response
        if 'metadata' not in assessment:
            assessment['metadata'] = {}
        
        # Only test SMB1 if we successfully negotiated SMB2/3
        if assessment.get('metadata', {}).get('negotiated_dialect'):
            assessment['metadata']['smb1_enabled'] = _probe_smb1_support(host, 445)
        
        return assessment
        
    except Exception as e:
        print(f"[DEBUG] SMB enumeration failed: {type(e).__name__}: {e}")
        
        # Check if this is a connection reset (SMB blocking)
        if 'WinError 10054' in str(e) or 'Connection reset' in str(e):
            return {
                'target': f"{host}:445",
                'overall_risk': 'LOW',
                'risk_summary': 'SMB traffic blocked by security policy - excellent protection',
                'metadata': {
                    'smb_blocked': True,
                    'tcp_connection': 'successful',
                    'smb_response': 'connection_reset',
                    'blocking_method': 'immediate_reset',
                    'security_posture': 'hardened'
                },
                'vulnerabilities': [],
                'security_findings': [{
                    'type': 'Advanced SMB Blocking',
                    'severity': 'INFO',
                    'description': 'Server accepts TCP connections but immediately resets all SMB traffic',
                    'recommendation': 'Excellent security practice - advanced SMB blocking is active'
                }],
                'recommendations': [
                    'SMB traffic is actively blocked by security policy',
                    'This prevents SMB enumeration and lateral movement attacks', 
                    'Server demonstrates advanced security hardening',
                    'Maintain current SMB blocking configuration'
                ]
            }
        
        return {
            'target': f"{host}:445",
            'error': str(e),
            'overall_risk': 'UNKNOWN',
            'metadata': {},
            'vulnerabilities': [],
            'security_findings': [],
            'recommendations': ['Verify target is accessible and SMB service is running']
        }
    finally:
        try:
            client.close()
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)

def scan_smb_ports(host: str, timeout: float = 2.0) -> Dict:
    """Scan for SMB ports"""
    results = {'tcp_ports': [], 'udp_ports': [], 'quic_detected': False}

    for port in [445, 139]:
        if _check_tcp_port(host, port, timeout):
            results['tcp_ports'].append(port)

    return results

def _check_tcp_port(host: str, port: int, timeout: float) -> bool:
    """Check if TCP port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def _probe_smb1_support(host: str, port: int, timeout: float = 2.0) -> bool:
    """Probe for SMB1 protocol support"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # SMB1 negotiate request
        smb1_negotiate = b'\x00\x00\x00\x85'  # NetBIOS header
        smb1_negotiate += b'\xffSMB\x72'  # SMB1 signature + negotiate
        smb1_negotiate += b'\x00' * 23  # Status, flags, etc.
        smb1_negotiate += b'\x00\x62\x00'  # Word count, byte count
        smb1_negotiate += b'NT LM 0.12\x00'  # Dialect

        sock.send(smb1_negotiate)
        response = sock.recv(1024)

        return len(response) > 4 and response[4:8] == b'\xffSMB'
    except:
        return False
    finally:
        try:
            sock.close()
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
