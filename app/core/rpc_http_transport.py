# app/core/rpc_http_transport.py
import socket
import struct
import uuid
import base64
from typing import Optional, Dict, Tuple
import urllib.parse
from app.core.logger import logger

class RPCHTTPTransport:
    """RPC over HTTP transport for Domain Controllers with SMB signing"""
    
    def __init__(self, target: str, port: int = 593):
        self.target = target
        self.port = port
        self.socket = None
        self.call_id = 1
        self.debug = False
    
    def _debug_log(self, message: str):
        # Debug logging disabled to prevent console output
        pass
    
    def connect(self, username: str = "", password: str = "", domain: str = "") -> bool:
        """Connect to RPC over HTTP endpoint"""
        try:
            self._debug_log(f"Connecting to RPC over HTTP at {self.target}:{self.port}")
            
            # TCP connection to RPC over HTTP port
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(15)
            self.socket.connect((self.target, self.port))
            self._debug_log("TCP connection established")
            
            # Send HTTP CONNECT request for RPC tunnel
            if not self._establish_http_tunnel():
                self._debug_log("HTTP tunnel establishment failed")
                return False
            
            self._debug_log("RPC over HTTP connection successful")
            return True
            
        except Exception as e:
            self._debug_log(f"RPC HTTP connection failed: {str(e)}")
            return False
    
    def _establish_http_tunnel(self) -> bool:
        """Establish HTTP tunnel for RPC communication"""
        try:
            # HTTP CONNECT request for RPC tunnel
            connect_request = f"CONNECT {self.target}:135 HTTP/1.1\r\n"
            connect_request += f"Host: {self.target}:135\r\n"
            connect_request += "User-Agent: MSRPC\r\n"
            connect_request += "Content-Length: 0\r\n"
            connect_request += "Pragma: no-cache\r\n"
            connect_request += "\r\n"
            
            self._debug_log(f"Sending HTTP CONNECT request")
            self.socket.send(connect_request.encode())
            
            # Receive HTTP response
            response = self.socket.recv(1024).decode()
            self._debug_log(f"HTTP response: {response[:100]}...")
            
            if "200 Connection established" in response or "HTTP/1.1 200" in response:
                self._debug_log("HTTP tunnel established successfully")
                return True
            else:
                self._debug_log(f"HTTP tunnel failed: {response}")
                return False
                
        except Exception as e:
            self._debug_log(f"HTTP tunnel error: {str(e)}")
            return False
    
    def bind_interface(self, interface_uuid: uuid.UUID, version: Tuple[int, int]) -> bool:
        """Bind to RPC interface over HTTP"""
        try:
            self._debug_log(f"Binding to interface {interface_uuid} over HTTP")
            
            # Create RPC bind request
            bind_request = self._create_bind_request(interface_uuid, version)
            
            # Send over HTTP tunnel
            if not self.socket:
                return False
            
            self.socket.send(bind_request)
            
            # Receive bind response
            response = self.socket.recv(1024)
            
            if len(response) >= 16:
                ptype = response[2] if len(response) > 2 else 0
                success = ptype == 0x0C  # RPC_BIND_ACK
                
                if success:
                    self._debug_log("RPC interface bind successful over HTTP")
                else:
                    self._debug_log(f"RPC interface bind failed, packet type: {hex(ptype)}")
                
                return success
            
            return False
            
        except Exception as e:
            self._debug_log(f"RPC HTTP bind error: {str(e)}")
            return False
    
    def call_rpc(self, opnum: int, request_data: bytes) -> Optional[bytes]:
        """Make RPC call over HTTP"""
        try:
            if not self.socket:
                return None
            
            # Create RPC request
            rpc_request = self._create_rpc_request(opnum, request_data)
            
            # Send request
            self.socket.send(rpc_request)
            
            # Receive response
            response = self.socket.recv(4096)
            
            if response and len(response) >= 16:
                return response[16:]  # Skip RPC header
            
            return None
            
        except Exception:
            return None
    
    def _create_bind_request(self, interface_uuid: uuid.UUID, version: Tuple[int, int]) -> bytes:
        """Create RPC bind request"""
        try:
            # RPC header
            rpc_vers = 5
            rpc_vers_minor = 0
            ptype = 0x0B  # RPC_BIND
            flags = 0x03  # PFC_FIRST_FRAG | PFC_LAST_FRAG
            drep = 0x10000000  # Little endian
            auth_len = 0
            call_id = self.call_id
            self.call_id += 1
            
            # Interface UUID and version
            uuid_bytes = interface_uuid.bytes_le
            if_version_major, if_version_minor = version
            
            # Transfer syntax (NDR)
            ndr_uuid = uuid.UUID('8a885d04-1ceb-11c9-9fe8-08002b104860').bytes_le
            ndr_version = (2, 0)
            
            # Build bind request
            bind_data = struct.pack('<HH', 5840, 1)  # max_xmit_frag, max_recv_frag, n_context_elem
            bind_data += struct.pack('<HBB', 0, 1, 0)  # context_id, n_transfer_syn, reserved
            bind_data += uuid_bytes + struct.pack('<HH', if_version_major, if_version_minor)
            bind_data += ndr_uuid + struct.pack('<HH', ndr_version[0], ndr_version[1])
            
            frag_len = 16 + len(bind_data)
            
            # RPC header
            header = struct.pack('<BBBBIHHI',
                rpc_vers, rpc_vers_minor, ptype, flags,
                drep, frag_len, auth_len, call_id)
            
            return header + bind_data
            
        except Exception:
            return b''
    
    def _create_rpc_request(self, opnum: int, request_data: bytes) -> bytes:
        """Create RPC request"""
        try:
            # RPC header
            rpc_vers = 5
            rpc_vers_minor = 0
            ptype = 0x00  # RPC_REQUEST
            flags = 0x03  # PFC_FIRST_FRAG | PFC_LAST_FRAG
            drep = 0x10000000  # Little endian
            auth_len = 0
            call_id = self.call_id
            self.call_id += 1
            
            # Request data
            alloc_hint = len(request_data)
            context_id = 0
            
            request_header = struct.pack('<IHH', alloc_hint, context_id, opnum)
            full_request = request_header + request_data
            
            frag_len = 16 + len(full_request)
            
            # RPC header
            header = struct.pack('<BBBBIHHI',
                rpc_vers, rpc_vers_minor, ptype, flags,
                drep, frag_len, auth_len, call_id)
            
            return header + full_request
            
        except Exception:
            return b''
    
    def disconnect(self):
        """Disconnect from RPC over HTTP"""
        try:
            if self.socket:
                self.socket.close()
                self.socket = None
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
