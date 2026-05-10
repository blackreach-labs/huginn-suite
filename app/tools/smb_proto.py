# app/tools/smb_proto.py
import socket
import struct
import time
import hashlib
from typing import Dict, List, Tuple, Optional
from app.core.logger import logger

class SMBClient:
    def __init__(self, host: str, port: int = 445, timeout: float = 3.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.session_id = 0
        self.tree_ids = {}
        self.server_guid = None
        self.dialect = None
        self.signing_required = False
        self.encryption_ciphers = []
        self.is_guest = False
        self.ntlm_target_info = {}
        self.server_time = None
        self.time_skew_ms = 0
        self.capabilities = {}

    def _connect(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect((self.host, self.port))
            self.sock = s
        except (ConnectionRefusedError, OSError, socket.timeout) as e:
            s.close()
            raise IOError(f"Connection failed: {e}")

    def _send(self, data: bytes):
        hdr = b"\x00" + struct.pack(">I", len(data))[1:]
        self.sock.sendall(hdr + data)

    def _recv(self) -> bytes:
        hdr = self._recvn(4)
        if not hdr or hdr[0] != 0x00:
            raise IOError("Invalid NBSS header")
        length = struct.unpack(">I", b"\x00" + hdr[1:])[0]
        return self._recvn(length)

    def _recvn(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise IOError("socket closed")
            buf += chunk
        return buf

    def negotiate(self):
        # SMB2 NEGOTIATE request
        dialects = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311]  # SMB 2.0.2 to 3.1.1
        
        negotiate_req = struct.pack('<H', 36)  # StructureSize
        negotiate_req += struct.pack('<H', len(dialects))  # DialectCount
        negotiate_req += struct.pack('<H', 0x0001)  # SecurityMode (signing enabled)
        negotiate_req += struct.pack('<H', 0)  # Reserved
        negotiate_req += struct.pack('<L', 0x7F)  # Capabilities
        negotiate_req += b'\x00' * 16  # ClientGuid
        negotiate_req += struct.pack('<Q', 0)  # ClientStartTime
        
        for dialect in dialects:
            negotiate_req += struct.pack('<H', dialect)
        
        # Pad to 8-byte boundary
        while len(negotiate_req) % 8 != 0:
            negotiate_req += b'\x00'

        smb2_hdr = self._build_smb2_header(0x0000, 0, 0)  # NEGOTIATE command
        packet = smb2_hdr + negotiate_req
        
        self._send(packet)
        response = self._recv()
        
        if len(response) < 64:
            raise IOError("Invalid negotiate response")
        
        # Parse SMB2 header
        protocol_id = response[0:4]
        if protocol_id != b'\xfeSMB':
            raise IOError("Invalid SMB2 response")
        
        # Parse negotiate response
        struct_size = struct.unpack('<H', response[64:66])[0]
        security_mode = struct.unpack('<H', response[66:68])[0]
        dialect_revision = struct.unpack('<H', response[68:70])[0]
        
        self.signing_required = bool(security_mode & 0x02)
        self.dialect = f"{dialect_revision >> 8}.{dialect_revision & 0xFF}"
        
        # Extract server GUID
        if len(response) >= 96:
            self.server_guid = response[80:96].hex()
        
        # Extract server time and calculate skew
        if len(response) >= 104:
            server_time = struct.unpack('<Q', response[96:104])[0]
            # Convert Windows FILETIME to Unix timestamp
            self.server_time = (server_time - 116444736000000000) / 10000000
            self.time_skew_ms = int(abs(time.time() - self.server_time) * 1000)

    def session_setup_anonymous(self):
        # Simple anonymous session setup
        session_setup_req = struct.pack('<H', 25)  # StructureSize
        session_setup_req += struct.pack('<B', 0)  # Flags
        session_setup_req += struct.pack('<B', 0x01)  # SecurityMode
        session_setup_req += struct.pack('<L', 0)  # Capabilities
        session_setup_req += struct.pack('<L', 0)  # Channel
        session_setup_req += struct.pack('<H', 88)  # SecurityBufferOffset
        session_setup_req += struct.pack('<H', 0)  # SecurityBufferLength
        session_setup_req += struct.pack('<Q', 0)  # PreviousSessionId
        
        # Pad to security buffer offset
        while len(session_setup_req) < 24:
            session_setup_req += b'\x00'

        smb2_hdr = self._build_smb2_header(0x0001, 0, 0)  # SESSION_SETUP command
        packet = smb2_hdr + session_setup_req
        
        try:
            self._send(packet)
            response = self._recv()
            
            if len(response) >= 68:
                session_flags = struct.unpack('<H', response[66:68])[0]
                self.is_guest = bool(session_flags & 0x0001)
                
                # Extract session ID from header
                if len(response) >= 44:
                    self.session_id = struct.unpack('<Q', response[36:44])[0]
                    
        except Exception as _exc:
            # Anonymous session setup failed, but that's expected
            pass
            logger.debug("Suppressed exception", exc_info=True)

    def tree_connect(self, sharename: str) -> Tuple[int, int]:
        path = f"\\\\{self.host}\\{sharename}"
        path_bytes = path.encode('utf-16le')
        
        tree_connect_req = struct.pack('<H', 9)  # StructureSize
        tree_connect_req += struct.pack('<H', 0)  # Flags
        tree_connect_req += struct.pack('<H', 72)  # PathOffset
        tree_connect_req += struct.pack('<H', len(path_bytes))  # PathLength
        
        # Pad to path offset
        while len(tree_connect_req) < 8:
            tree_connect_req += b'\x00'
        
        tree_connect_req += path_bytes

        smb2_hdr = self._build_smb2_header(0x0003, 0, self.session_id)  # TREE_CONNECT
        packet = smb2_hdr + tree_connect_req
        
        try:
            self._send(packet)
            response = self._recv()
            
            # Extract status from header
            status = struct.unpack('<L', response[8:12])[0]
            
            if status == 0:  # STATUS_SUCCESS
                # Extract tree ID from header
                tree_id = struct.unpack('<L', response[28:32])[0]
                self.tree_ids[sharename] = tree_id
                return tree_id, status
            else:
                return 0, status
                
        except Exception:
            return 0, 0xC0000001  # STATUS_UNSUCCESSFUL

    def open_pipe(self, tree_id: int, pipename: str) -> int:
        filename = f"\\{pipename}"
        filename_bytes = filename.encode('utf-16le')
        
        create_req = struct.pack('<H', 57)  # StructureSize
        create_req += struct.pack('<B', 0)  # SecurityFlags
        create_req += struct.pack('<B', 0)  # RequestedOplockLevel
        create_req += struct.pack('<L', 0)  # ImpersonationLevel
        create_req += struct.pack('<Q', 0)  # SmbCreateFlags
        create_req += struct.pack('<Q', 0)  # Reserved
        create_req += struct.pack('<L', 0x80100080)  # DesiredAccess
        create_req += struct.pack('<L', 0)  # FileAttributes
        create_req += struct.pack('<L', 0x00000007)  # ShareAccess
        create_req += struct.pack('<L', 0x00000001)  # CreateDisposition
        create_req += struct.pack('<L', 0)  # CreateOptions
        create_req += struct.pack('<H', 120)  # NameOffset
        create_req += struct.pack('<H', len(filename_bytes))  # NameLength
        create_req += struct.pack('<L', 0)  # CreateContextsOffset
        create_req += struct.pack('<L', 0)  # CreateContextsLength
        
        # Pad to name offset
        while len(create_req) < 56:
            create_req += b'\x00'
            
        create_req += filename_bytes

        smb2_hdr = self._build_smb2_header(0x0005, tree_id, self.session_id)  # CREATE
        packet = smb2_hdr + create_req
        
        try:
            self._send(packet)
            response = self._recv()
            
            # Extract status from header
            status = struct.unpack('<L', response[8:12])[0]
            return status
            
        except Exception:
            return 0xC0000001  # STATUS_UNSUCCESSFUL

    def _build_smb2_header(self, command: int, tree_id: int, session_id: int) -> bytes:
        header = b'\xfeSMB'  # ProtocolId
        header += struct.pack('<H', 64)  # StructureSize
        header += struct.pack('<H', 0)  # CreditCharge
        header += struct.pack('<L', 0)  # Status
        header += struct.pack('<H', command)  # Command
        header += struct.pack('<H', 1)  # CreditRequest
        header += struct.pack('<L', 0)  # Flags
        header += struct.pack('<L', 0)  # NextCommand
        header += struct.pack('<Q', 1)  # MessageId
        header += struct.pack('<L', 0)  # Reserved
        header += struct.pack('<L', tree_id)  # TreeId
        header += struct.pack('<Q', session_id)  # SessionId
        header += b'\x00' * 16  # Signature
        return header

    def close(self):
        try:
            if self.sock:
                self.sock.close()
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)

def enumerate_smb_anonymous(host: str, timeout: float = 2.0, 
                          share_candidates: List[str] = None, 
                          pipe_candidates: List[str] = None) -> Dict:
    
    COMMON_SHARES = ["IPC$", "ADMIN$", "C$", "D$", "SYSVOL", "NETLOGON", "print$", "Users", "Public"]
    COMMON_PIPES = ["srvsvc", "samr", "lsarpc", "netlogon", "browser", "spoolss"]
    
    c = SMBClient(host, timeout=timeout)
    results = {
        "host": host,
        "smb": {
            "negotiation": {},
            "session": {},
            "security": {},
            "shares": [],
            "pipes": []
        }
    }
    
    try:
        # Test basic connectivity first
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_sock.settimeout(timeout)
        test_result = test_sock.connect_ex((host, 445))
        test_sock.close()
        
        if test_result != 0:
            return None  # Port not accessible
        
        c._connect()
        c.negotiate()

        results["smb"]["negotiation"] = {
            "dialect": c.dialect,
            "server_guid": c.server_guid,
            "server_time": c.server_time,
            "time_skew_ms": c.time_skew_ms
        }
        
        results["smb"]["security"] = {
            "signing_required": c.signing_required,
            "encryption_ciphers": c.encryption_ciphers
        }

        c.session_setup_anonymous()
        results["smb"]["session"] = {
            "is_guest": c.is_guest,
            "ntlm_target_info": c.ntlm_target_info
        }

        # Always try IPC$ first
        ipc_tid, status = c.tree_connect("IPC$")
        results["smb"]["shares"].append({
            "name": "IPC$", 
            "status": status, 
            "exists": status in (0, 0xC0000022),
            "anonymous_access": status == 0
        })

        # Pipe probing if IPC$ accessible
        if status == 0:
            for p in (pipe_candidates or COMMON_PIPES):
                pipe_status = c.open_pipe(ipc_tid, p)
                results["smb"]["pipes"].append({"name": p, "status": pipe_status})

        # Share discovery
        for name in (share_candidates or COMMON_SHARES):
            if name == "IPC$":
                continue
            tid, st = c.tree_connect(name)
            exists = st in (0, 0xC0000022)  # SUCCESS or ACCESS_DENIED
            results["smb"]["shares"].append({
                "name": name,
                "exists": exists,
                "status": st,
                "anonymous_access": (st == 0)
            })

        return results

    except Exception as e:
        return None
    finally:
        c.close()