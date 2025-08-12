# app/core/smb_client.py
import socket
import struct
import hashlib
import hmac
import os
from typing import Optional, Tuple

class SMBClient:
    """SMB2/3 client for RPC transport"""
    
    def __init__(self, target: str, port: int = 445):
        self.target = target
        self.port = port
        self.socket = None
        self.session_id = 0
        self.tree_id = 0
        self.message_id = 1
        self.dialect = None
        self.debug = False
    
    def _debug_log(self, message: str):
        """Debug logging helper"""
        # Debug logging disabled to prevent console output
        pass
        
    def connect(self, username: str = "", password: str = "", domain: str = "") -> bool:
        """Connect and authenticate to SMB server with multiple fallback methods"""
        try:
            self._debug_log(f"Connecting to {self.target}:{self.port}")
            
            # TCP connection with retries
            for attempt in range(3):
                try:
                    self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.socket.settimeout(15)  # Increased timeout
                    self.socket.connect((self.target, self.port))
                    self._debug_log(f"TCP connection established (attempt {attempt + 1})")
                    break
                except Exception as e:
                    self._debug_log(f"TCP connection attempt {attempt + 1} failed: {str(e)}")
                    if self.socket:
                        self.socket.close()
                        self.socket = None
                    if attempt == 2:  # Last attempt
                        return False
                    import time
                    time.sleep(1)
            
            # Try NetBIOS session request with multiple fallbacks
            self._debug_log("Attempting NetBIOS session establishment")
            if not self._establish_netbios_session():
                self._debug_log("All NetBIOS session methods failed")
                return False
            self._debug_log("NetBIOS session established")
            
            # SMB negotiate with retries
            self._debug_log("Starting SMB negotiate")
            if not self._negotiate_with_retries():
                self._debug_log("SMB negotiate failed")
                return False
            self._debug_log(f"SMB negotiate successful, dialect: {hex(self.dialect) if self.dialect else 'None'}")
            
            # Session setup with NTLM
            if username and password:
                self._debug_log(f"Starting NTLM authentication for {domain}\\{username}")
                if not self._session_setup(username, password, domain):
                    self._debug_log("NTLM authentication failed")
                    return False
                self._debug_log(f"NTLM authentication successful, session_id: {hex(self.session_id)}")
            
            # Tree connect to IPC$
            self._debug_log("Connecting to IPC$ share")
            if not self._tree_connect():
                self._debug_log("IPC$ tree connect failed")
                return False
            self._debug_log(f"IPC$ tree connect successful, tree_id: {hex(self.tree_id)}")
            
            return True
            
        except Exception as e:
            self._debug_log(f"Connection failed with exception: {str(e)}")
            return False
    
    def _netbios_session_request(self) -> bool:
        """Send NetBIOS session request with proper packet structure"""
        try:
            # Build proper NetBIOS names
            called_name = self._build_netbios_name('*SMBSERVER', 0x20)  # Server service
            calling_name = self._build_netbios_name('HUGGIN', 0x00)     # Workstation service
            
            # Calculate total length
            data_length = len(called_name) + len(calling_name)
            
            # NetBIOS session request packet
            session_request = b'\x81'  # Session request type
            session_request += struct.pack('>I', data_length)[1:]  # Length (3 bytes, big-endian)
            session_request += called_name
            session_request += calling_name
            
            self._debug_log(f"Sending NetBIOS session request, length: {len(session_request)}")
            self._debug_log(f"Called name length: {len(called_name)}, Calling name length: {len(calling_name)}")
            
            self.socket.send(session_request)
            
            # Receive response with timeout
            self.socket.settimeout(5)
            response = self.socket.recv(4)
            
            if len(response) >= 1:
                response_type = response[0]
                self._debug_log(f"NetBIOS session response type: {hex(response_type)}")
                
                if response_type == 0x82:  # Positive session response
                    self._debug_log("NetBIOS session established successfully")
                    return True
                elif response_type == 0x83:  # Negative session response
                    if len(response) >= 2:
                        error_code = response[1]
                        error_msg = self._get_netbios_error(error_code)
                        self._debug_log(f"NetBIOS session rejected: {error_msg} (code: {hex(error_code)})")
                    return False
                else:
                    self._debug_log(f"Unexpected NetBIOS response type: {hex(response_type)}")
                    return False
            
            self._debug_log("No NetBIOS response received")
            return False
            
        except socket.timeout:
            self._debug_log("NetBIOS session request timeout")
            return False
        except Exception as e:
            self._debug_log(f"NetBIOS session request exception: {str(e)}")
            return False
    
    def _build_netbios_name(self, name: str, name_type: int) -> bytes:
        """Build properly formatted NetBIOS name with service type"""
        try:
            # Convert to bytes and pad to 15 characters (16th byte is service type)
            name_bytes = name.upper().encode('ascii')[:15]
            name_bytes = name_bytes.ljust(15, b' ')
            name_bytes += bytes([name_type])  # Add service type as 16th byte
            
            # Encode using NetBIOS first-level encoding
            encoded = b''
            for byte in name_bytes:
                encoded += bytes([0x41 + (byte >> 4)])    # High nibble
                encoded += bytes([0x41 + (byte & 0x0F)])  # Low nibble
            
            # Add length prefix and suffix
            result = bytes([32]) + encoded + b'\x00'  # Length (32) + encoded name + null terminator
            
            return result
            
        except Exception as e:
            self._debug_log(f"NetBIOS name encoding error: {str(e)}")
            # Fallback to basic encoding
            return b'\x20' + b'A' * 32 + b'\x00'
    
    def _get_netbios_error(self, error_code: int) -> str:
        """Get NetBIOS error message from error code"""
        error_codes = {
            0x80: "Not listening on called name",
            0x81: "Not listening for calling name",
            0x82: "Called name not present",
            0x83: "Called name present, but insufficient resources",
            0x8F: "Unspecified error"
        }
        return error_codes.get(error_code, f"Unknown error code: {hex(error_code)}")
    
    def disconnect(self):
        """Disconnect from SMB server with proper cleanup"""
        try:
            if self.socket:
                # Send SMB2 logoff if we have a session
                if self.session_id != 0:
                    try:
                        logoff_data = struct.pack('<HH', 4, 0)  # StructureSize, Reserved
                        self._send_smb2_request(0x02, logoff_data)  # SMB2_LOGOFF
                    except:
                        pass
                
                # Close socket
                try:
                    self.socket.shutdown(socket.SHUT_RDWR)
                except:
                    pass
                
                self.socket.close()
                self.socket = None
                
            # Reset state
            self.session_id = 0
            self.tree_id = 0
            self.message_id = 1
            self.dialect = None
            
        except Exception as e:
            self._debug_log(f"Disconnect error: {str(e)}")
    
    def is_connected(self) -> bool:
        """Check if SMB connection is still active"""
        try:
            if not self.socket:
                return False
            
            # Try to send a small packet to test connection
            self.socket.settimeout(1)
            original_timeout = self.socket.gettimeout()
            
            # Simple connection test - just check if socket is writable
            import select
            ready = select.select([], [self.socket], [], 0.1)
            
            self.socket.settimeout(original_timeout)
            return len(ready[1]) > 0 or self.session_id != 0
            
        except:
            return False
    
    def open_pipe(self, pipe_name: str) -> Optional[bytes]:
        """Open named pipe for RPC communication"""
        try:
            # SMB2 Create request for named pipe
            create_request = self._create_smb2_create(pipe_name)
            response = self._send_smb2_request(0x05, create_request)  # SMB2_CREATE
            
            if response and len(response) >= 132:
                # Extract file ID from create response (16 bytes at offset 132)
                file_id = response[132:148] if len(response) >= 148 else response[132:132+16]
                return file_id
            
            return None
            
        except Exception:
            return None
    
    def write_pipe(self, file_id: bytes, data: bytes) -> bool:
        """Write data to named pipe"""
        try:
            write_request = self._create_smb2_write(file_id, data)
            response = self._send_smb2_request(0x09, write_request)  # SMB2_WRITE
            return response is not None
            
        except Exception:
            return False
    
    def read_pipe(self, file_id: bytes, length: int = 4096) -> Optional[bytes]:
        """Read data from named pipe"""
        try:
            read_request = self._create_smb2_read(file_id, length)
            response = self._send_smb2_request(0x08, read_request)  # SMB2_READ
            
            if response and len(response) >= 88:
                # Extract data from read response
                data_offset = struct.unpack('<H', response[80:82])[0] if len(response) >= 82 else 0
                data_length = struct.unpack('<I', response[84:88])[0] if len(response) >= 88 else 0
                
                if data_offset > 0 and data_length > 0:
                    return response[data_offset:data_offset + data_length]
            
            return None
            
        except Exception:
            return None
    
    def close_pipe(self, file_id: bytes):
        """Close named pipe"""
        try:
            close_request = self._create_smb2_close(file_id)
            self._send_smb2_request(0x06, close_request)  # SMB2_CLOSE
        except:
            pass
    
    def _establish_netbios_session(self) -> bool:
        """Try multiple NetBIOS session establishment methods"""
        # Method 1: Standard NetBIOS session request
        self._debug_log("Method 1: Standard NetBIOS session request")
        if self._netbios_session_request():
            return True
        
        # Method 2: Try with different server names
        server_names = ['*SMBSERVER', self.target.upper(), 'WINDOWS']
        for server_name in server_names:
            self._debug_log(f"Method 2: Trying server name '{server_name}'")
            if self._netbios_session_request_with_name(server_name):
                return True
        
        # Method 3: Skip NetBIOS session (direct SMB)
        self._debug_log("Method 3: Attempting direct SMB without NetBIOS session")
        return True  # Allow direct SMB connection
    
    def _netbios_session_request_with_name(self, server_name: str) -> bool:
        """NetBIOS session request with custom server name"""
        try:
            called_name = self._build_netbios_name(server_name, 0x20)
            calling_name = self._build_netbios_name('HUGGIN', 0x00)
            
            data_length = len(called_name) + len(calling_name)
            session_request = b'\x81' + struct.pack('>I', data_length)[1:] + called_name + calling_name
            
            self._debug_log(f"Trying NetBIOS session with server name: {server_name}")
            self.socket.send(session_request)
            
            self.socket.settimeout(3)
            response = self.socket.recv(4)
            
            if len(response) >= 1 and response[0] == 0x82:
                self._debug_log(f"NetBIOS session successful with server name: {server_name}")
                return True
            
            return False
            
        except Exception as e:
            self._debug_log(f"NetBIOS session with name '{server_name}' failed: {str(e)}")
            return False
    
    def _negotiate_with_retries(self) -> bool:
        """SMB negotiate with multiple retry strategies"""
        try:
            # Strategy 1: Direct SMB2 negotiate
            self._debug_log("Strategy 1: Direct SMB2 negotiate")
            if self._negotiate_smb2():
                return True
            
            # Strategy 2: SMB1 then SMB2
            self._debug_log("Strategy 2: SMB1 then SMB2")
            if self._negotiate_smb1():
                self._debug_log("SMB1 negotiate successful, upgrading to SMB2")
                return self._negotiate_smb2()
            
            # Strategy 3: SMB2 with different dialects
            self._debug_log("Strategy 3: SMB2 with minimal dialects")
            return self._negotiate_smb2_minimal()
            
        except Exception as e:
            self._debug_log(f"All negotiate strategies failed: {str(e)}")
            return False
    
    def _negotiate_smb2_minimal(self) -> bool:
        """SMB2 negotiate with minimal dialect set"""
        try:
            # Minimal SMB2 negotiate with only SMB 2.02
            negotiate_data = struct.pack('<H', 36)  # StructureSize
            negotiate_data += struct.pack('<H', 1)   # DialectCount (only one)
            negotiate_data += struct.pack('<H', 0)   # SecurityMode
            negotiate_data += struct.pack('<H', 0)   # Reserved
            negotiate_data += struct.pack('<I', 0)   # Capabilities
            negotiate_data += os.urandom(16)         # ClientGuid
            negotiate_data += struct.pack('<Q', 0)   # ClientStartTime
            negotiate_data += struct.pack('<H', 0x0202)  # SMB 2.02 only
            
            self._debug_log("Sending minimal SMB2 negotiate (SMB 2.02 only)")
            response = self._send_smb2_request(0x00, negotiate_data)
            
            if response and len(response) >= 64:
                if len(response) >= 74:
                    self.dialect = struct.unpack('<H', response[72:74])[0]
                    self._debug_log(f"Minimal SMB2 negotiate successful, dialect: {hex(self.dialect)}")
                    return True
            
            return False
            
        except Exception as e:
            self._debug_log(f"Minimal SMB2 negotiate failed: {str(e)}")
            return False
    
    def _negotiate_smb1(self) -> bool:
        """SMB1 negotiate to establish connection"""
        try:
            # SMB1 negotiate request - simpler format
            smb1_data = b'\x00'  # Word count
            smb1_data += struct.pack('<H', 12)  # Byte count
            smb1_data += b'\x02'  # Dialect marker
            smb1_data += b'NT LM 0.12\x00'  # Dialect string
            
            # SMB1 header (32 bytes)
            header = b'\xffSMB'  # Protocol (4 bytes)
            header += b'\x72'    # Command - Negotiate (1 byte)
            header += struct.pack('<I', 0)  # Status (4 bytes)
            header += b'\x18'    # Flags (1 byte)
            header += struct.pack('<H', 0x0000)  # Flags2 (2 bytes)
            header += struct.pack('<H', 0)  # PID High (2 bytes)
            header += b'\x00' * 8  # Signature (8 bytes)
            header += struct.pack('<H', 0)  # Reserved (2 bytes)
            header += struct.pack('<H', 0)  # TID (2 bytes)
            header += struct.pack('<H', 0)  # PID (2 bytes)
            header += struct.pack('<H', 0)  # UID (2 bytes)
            header += struct.pack('<H', 1)  # MID (2 bytes)
            
            # Send without NetBIOS header since session is established
            full_packet = header + smb1_data
            self._debug_log(f"Sending SMB1 negotiate, length: {len(full_packet)}")
            self.socket.send(full_packet)
            
            # Receive response
            response = self.socket.recv(1024)
            self._debug_log(f"SMB1 negotiate response length: {len(response)}")
            
            if len(response) >= 32 and response[:4] == b'\xffSMB':
                self._debug_log("SMB1 negotiate successful")
                return True
            
            return False
            
        except Exception as e:
            self._debug_log(f"SMB1 negotiate exception: {str(e)}")
            return False
    
    def _negotiate_smb2(self) -> bool:
        """SMB2 negotiate protocol"""
        try:
            # SMB2 negotiate request with multiple dialects
            negotiate_data = struct.pack('<H', 36)  # StructureSize
            negotiate_data += struct.pack('<H', 3)   # DialectCount (try multiple)
            negotiate_data += struct.pack('<H', 0)   # SecurityMode
            negotiate_data += struct.pack('<H', 0)   # Reserved
            negotiate_data += struct.pack('<I', 0)   # Capabilities
            negotiate_data += os.urandom(16)         # ClientGuid (16 bytes)
            negotiate_data += struct.pack('<Q', 0)   # ClientStartTime
            # Multiple dialects for compatibility
            negotiate_data += struct.pack('<H', 0x0202)  # SMB 2.02
            negotiate_data += struct.pack('<H', 0x0210)  # SMB 2.10
            negotiate_data += struct.pack('<H', 0x0300)  # SMB 3.00
            
            self._debug_log(f"Sending SMB2 negotiate request, data length: {len(negotiate_data)}")
            response = self._send_smb2_request(0x00, negotiate_data)  # SMB2_NEGOTIATE
            
            if response and len(response) >= 64:
                # Extract dialect from response
                if len(response) >= 74:
                    self.dialect = struct.unpack('<H', response[72:74])[0]
                    self._debug_log(f"SMB2 negotiate response received, dialect: {hex(self.dialect)}")
                    return True
                else:
                    self._debug_log(f"SMB2 negotiate response too short: {len(response)} bytes")
            else:
                self._debug_log(f"Invalid SMB2 negotiate response: {len(response) if response else 0} bytes")
            
            return False
            
        except Exception as e:
            self._debug_log(f"SMB2 negotiate exception: {str(e)}")
            return False
    
    def _session_setup(self, username: str, password: str, domain: str) -> bool:
        """SMB2 session setup with NTLM authentication"""
        try:
            # NTLM Type 1 message
            type1_msg = self._create_ntlm_type1(domain)
            
            # Session setup request with Type 1
            session_setup_data = struct.pack('<HBB', 25, 0, 0)  # StructureSize, Flags, SecurityMode
            session_setup_data += struct.pack('<II', 0, 0)  # Capabilities, Channel
            session_setup_data += struct.pack('<HH', 88, len(type1_msg))  # SecurityBufferOffset, SecurityBufferLength
            session_setup_data += struct.pack('<Q', 0)  # PreviousSessionId
            session_setup_data += type1_msg
            
            response = self._send_smb2_request(0x01, session_setup_data)  # SMB2_SESSION_SETUP
            
            if not response or len(response) < 64:
                return False
            
            # Extract session ID and Type 2 challenge
            self.session_id = struct.unpack('<Q', response[44:52])[0]
            
            # Extract Type 2 message from response
            sec_buf_offset = struct.unpack('<H', response[72:74])[0]
            sec_buf_length = struct.unpack('<H', response[74:76])[0]
            
            if sec_buf_offset > 0 and sec_buf_length > 0:
                type2_msg = response[sec_buf_offset:sec_buf_offset + sec_buf_length]
                
                # Create NTLM Type 3 response
                type3_msg = self._create_ntlm_type3(username, password, domain, type2_msg)
                
                # Second session setup request with Type 3
                session_setup_data = struct.pack('<HBB', 25, 0, 0)
                session_setup_data += struct.pack('<II', 0, 0)
                session_setup_data += struct.pack('<HH', 88, len(type3_msg))
                session_setup_data += struct.pack('<Q', self.session_id)
                session_setup_data += type3_msg
                
                response = self._send_smb2_request(0x01, session_setup_data)
                return response is not None
            
            return False
            
        except Exception:
            return False
    
    def _tree_connect(self) -> bool:
        """Connect to IPC$ share"""
        try:
            path = f"\\\\{self.target}\\IPC$"
            path_utf16 = path.encode('utf-16le')
            
            tree_connect_data = struct.pack('<HH', 9, 0)  # StructureSize, Reserved
            tree_connect_data += struct.pack('<HH', 72, len(path_utf16))  # PathOffset, PathLength
            tree_connect_data += path_utf16
            
            response = self._send_smb2_request(0x03, tree_connect_data)  # SMB2_TREE_CONNECT
            
            if response and len(response) >= 64:
                self.tree_id = struct.unpack('<I', response[40:44])[0]
                return True
            
            return False
            
        except Exception:
            return False
    
    def _send_smb2_request(self, command: int, data: bytes) -> Optional[bytes]:
        """Send SMB2 request and receive response with enhanced error handling"""
        try:
            # SMB2 header (64 bytes)
            header = b'\xfeSMB'  # Protocol ID (4 bytes)
            header += struct.pack('<H', 64)  # StructureSize (2 bytes)
            header += struct.pack('<H', 0)  # CreditCharge (2 bytes)
            header += struct.pack('<I', 0)  # Status (4 bytes)
            header += struct.pack('<H', command)  # Command (2 bytes)
            header += struct.pack('<H', 1)  # CreditRequest (2 bytes)
            header += struct.pack('<I', 0)  # Flags (4 bytes)
            header += struct.pack('<I', 0)  # NextCommand (4 bytes)
            header += struct.pack('<Q', self.message_id)  # MessageId (8 bytes)
            header += struct.pack('<I', 0)  # ProcessId (4 bytes)
            header += struct.pack('<I', self.tree_id)  # TreeId (4 bytes)
            header += struct.pack('<Q', self.session_id)  # SessionId (8 bytes)
            header += b'\x00' * 16  # Signature (16 bytes)
            
            self.message_id += 1
            
            # NetBIOS session service header
            total_length = len(header) + len(data)
            netbios_header = struct.pack('>I', total_length & 0x00FFFFFF)
            
            self._debug_log(f"Sending SMB2 command {hex(command)}, message_id: {self.message_id-1}")
            
            # Send request with error handling
            full_request = netbios_header + header + data
            
            try:
                self.socket.send(full_request)
            except socket.error as e:
                self._debug_log(f"Socket send error: {str(e)}")
                return None
            
            # Receive response with timeout and error handling
            try:
                self.socket.settimeout(10)
                netbios_resp = self.socket.recv(4)
                
                if len(netbios_resp) != 4:
                    self._debug_log(f"Invalid NetBIOS response header: {len(netbios_resp)} bytes")
                    return None
                
                response_length = struct.unpack('>I', netbios_resp)[0] & 0x00FFFFFF
                self._debug_log(f"Expecting response length: {response_length}")
                
                if response_length > 1048576:  # 1MB sanity check
                    self._debug_log(f"Response length too large: {response_length}")
                    return None
                
                response = b''
                bytes_remaining = response_length
                
                while bytes_remaining > 0:
                    try:
                        chunk_size = min(bytes_remaining, 8192)  # Read in chunks
                        chunk = self.socket.recv(chunk_size)
                        
                        if not chunk:
                            self._debug_log(f"Connection closed while reading response (got {len(response)}/{response_length} bytes)")
                            break
                        
                        response += chunk
                        bytes_remaining -= len(chunk)
                        
                    except socket.timeout:
                        self._debug_log(f"Timeout while reading response (got {len(response)}/{response_length} bytes)")
                        break
                    except socket.error as e:
                        self._debug_log(f"Socket error while reading response: {str(e)}")
                        break
                
                self._debug_log(f"Received response: {len(response)}/{response_length} bytes")
                
                # Parse SMB2 response status
                if len(response) >= 12:
                    status = struct.unpack('<I', response[8:12])[0]
                    if status != 0:
                        status_msg = self._get_smb_status_message(status)
                        self._debug_log(f"SMB2 response status: {hex(status)} ({status_msg})")
                        
                        # Don't return None for some expected status codes
                        if status not in [0xC0000016, 0xC000006D]:  # STATUS_MORE_PROCESSING_REQUIRED, STATUS_LOGON_FAILURE
                            if command == 0x01 and status == 0xC000006D:  # Session setup logon failure
                                pass  # Allow session setup failures to be handled by caller
                            elif status == 0xC0000022:  # STATUS_ACCESS_DENIED
                                pass  # Allow access denied to be handled by caller
                            else:
                                return None
                
                return response if len(response) == response_length else None
                
            except socket.timeout:
                self._debug_log("Timeout waiting for SMB2 response")
                return None
            except socket.error as e:
                self._debug_log(f"Socket error receiving response: {str(e)}")
                return None
            
        except Exception as e:
            self._debug_log(f"SMB2 request exception: {str(e)}")
            return None
    
    def _get_smb_status_message(self, status: int) -> str:
        """Get human-readable SMB status message"""
        status_codes = {
            0x00000000: "STATUS_SUCCESS",
            0xC0000016: "STATUS_MORE_PROCESSING_REQUIRED",
            0xC000006D: "STATUS_LOGON_FAILURE",
            0xC0000022: "STATUS_ACCESS_DENIED",
            0xC000000D: "STATUS_INVALID_PARAMETER",
            0xC0000034: "STATUS_OBJECT_NAME_NOT_FOUND",
            0xC00000BB: "STATUS_NOT_SUPPORTED",
            0xC0000225: "STATUS_NOT_FOUND",
            0xC0000008: "STATUS_INVALID_HANDLE",
            0xC0000001: "STATUS_UNSUCCESSFUL"
        }
        return status_codes.get(status, f"Unknown status: {hex(status)}")
    
    def _create_smb2_create(self, pipe_name: str) -> bytes:
        """Create SMB2 create request for named pipe"""
        try:
            filename = f"\\{pipe_name}"
            filename_utf16 = filename.encode('utf-16le')
            
            create_data = struct.pack('<H', 57)  # StructureSize
            create_data += struct.pack('<B', 0)  # SecurityFlags
            create_data += struct.pack('<B', 0)  # RequestedOplockLevel
            create_data += struct.pack('<I', 0)  # ImpersonationLevel
            create_data += struct.pack('<Q', 0)  # SmbCreateFlags
            create_data += struct.pack('<Q', 0)  # Reserved
            create_data += struct.pack('<I', 0x80100080)  # DesiredAccess (GENERIC_READ | GENERIC_WRITE)
            create_data += struct.pack('<I', 0)  # FileAttributes
            create_data += struct.pack('<I', 7)  # ShareAccess (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            create_data += struct.pack('<I', 1)  # CreateDisposition (FILE_OPEN)
            create_data += struct.pack('<I', 0)  # CreateOptions
            create_data += struct.pack('<H', 120)  # NameOffset
            create_data += struct.pack('<H', len(filename_utf16))  # NameLength
            create_data += struct.pack('<I', 0)  # CreateContextsOffset
            create_data += struct.pack('<I', 0)  # CreateContextsLength
            create_data += filename_utf16
            
            return create_data
            
        except Exception:
            return b''
    
    def _create_smb2_write(self, file_id: bytes, data: bytes) -> bytes:
        """Create SMB2 write request"""
        try:
            write_data = struct.pack('<H', 49)  # StructureSize
            write_data += struct.pack('<H', 112)  # DataOffset
            write_data += struct.pack('<I', len(data))  # Length
            write_data += struct.pack('<Q', 0)  # Offset
            write_data += file_id  # FileId (16 bytes)
            write_data += struct.pack('<I', 0)  # Channel
            write_data += struct.pack('<I', 0)  # RemainingBytes
            write_data += struct.pack('<H', 0)  # WriteChannelInfoOffset
            write_data += struct.pack('<H', 0)  # WriteChannelInfoLength
            write_data += struct.pack('<I', 0)  # Flags
            write_data += data
            
            return write_data
            
        except Exception:
            return b''
    
    def _create_smb2_read(self, file_id: bytes, length: int) -> bytes:
        """Create SMB2 read request"""
        try:
            read_data = struct.pack('<H', 49)  # StructureSize
            read_data += struct.pack('<B', 0)  # Padding
            read_data += struct.pack('<B', 0)  # Flags
            read_data += struct.pack('<I', length)  # Length
            read_data += struct.pack('<Q', 0)  # Offset
            read_data += file_id  # FileId (16 bytes)
            read_data += struct.pack('<I', 1)  # MinimumCount
            read_data += struct.pack('<I', 0)  # Channel
            read_data += struct.pack('<I', 0)  # RemainingBytes
            read_data += struct.pack('<H', 0)  # ReadChannelInfoOffset
            read_data += struct.pack('<H', 0)  # ReadChannelInfoLength
            read_data += struct.pack('<B', 0)  # Buffer
            
            return read_data
            
        except Exception:
            return b''
    
    def _create_smb2_close(self, file_id: bytes) -> bytes:
        """Create SMB2 close request"""
        try:
            close_data = struct.pack('<H', 24)  # StructureSize
            close_data += struct.pack('<H', 0)  # Flags
            close_data += struct.pack('<I', 0)  # Reserved
            close_data += file_id  # FileId (16 bytes)
            
            return close_data
            
        except Exception:
            return b''
    
    def _create_ntlm_type1(self, domain: str) -> bytes:
        """Create NTLM Type 1 message"""
        try:
            # NTLM Type 1 message structure
            signature = b'NTLMSSP\x00'
            message_type = struct.pack('<I', 1)
            flags = struct.pack('<I', 0x62890235)  # Negotiate flags
            
            domain_len = len(domain)
            workstation = "HUGGIN"
            workstation_len = len(workstation)
            
            # Security buffer descriptors
            domain_sec_buf = struct.pack('<HHI', domain_len, domain_len, 40 + workstation_len)
            workstation_sec_buf = struct.pack('<HHI', workstation_len, workstation_len, 40)
            
            # Version info (optional)
            version = struct.pack('<BBHHBBBB', 6, 1, 7600, 15, 0, 0, 0, 0)
            
            type1_msg = signature + message_type + flags + domain_sec_buf + workstation_sec_buf + version
            type1_msg += workstation.encode('ascii') + domain.encode('ascii')
            
            return type1_msg
            
        except Exception:
            return b''
    
    def _create_ntlm_type3(self, username: str, password: str, domain: str, type2_msg: bytes) -> bytes:
        """Create NTLM Type 3 response message"""
        try:
            if len(type2_msg) < 48:
                return b''
            
            # Extract challenge from Type 2 message
            challenge = type2_msg[24:32]
            
            # Calculate NT hash
            nt_hash = hashlib.new('md4', password.encode('utf-16le')).digest()
            
            # Calculate NTLM response using HMAC-MD5
            lm_response = b'\x00' * 24  # Empty LM response
            nt_response = hmac.new(nt_hash, challenge, hashlib.md5).digest() + b'\x00' * 8
            
            # Build Type 3 message
            signature = b'NTLMSSP\x00'
            message_type = struct.pack('<I', 3)
            
            # Calculate offsets
            base_offset = 64
            domain_offset = base_offset
            username_offset = domain_offset + len(domain.encode('utf-16le'))
            workstation_offset = username_offset + len(username.encode('utf-16le'))
            lm_offset = workstation_offset + len("HUGGIN".encode('utf-16le'))
            nt_offset = lm_offset + len(lm_response)
            session_key_offset = nt_offset + len(nt_response)
            
            # Security buffer descriptors
            lm_sec_buf = struct.pack('<HHI', len(lm_response), len(lm_response), lm_offset)
            nt_sec_buf = struct.pack('<HHI', len(nt_response), len(nt_response), nt_offset)
            domain_sec_buf = struct.pack('<HHI', len(domain) * 2, len(domain) * 2, domain_offset)
            username_sec_buf = struct.pack('<HHI', len(username) * 2, len(username) * 2, username_offset)
            workstation_sec_buf = struct.pack('<HHI', 12, 12, workstation_offset)
            session_key_sec_buf = struct.pack('<HHI', 0, 0, session_key_offset)
            
            flags = struct.pack('<I', 0x62890235)
            
            type3_msg = signature + message_type + lm_sec_buf + nt_sec_buf + domain_sec_buf
            type3_msg += username_sec_buf + workstation_sec_buf + session_key_sec_buf + flags
            
            # Append data
            type3_msg += domain.encode('utf-16le')
            type3_msg += username.encode('utf-16le')
            type3_msg += "HUGGIN".encode('utf-16le')
            type3_msg += lm_response
            type3_msg += nt_response
            
            return type3_msg
            
        except Exception:
            return b''