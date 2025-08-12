# app/core/mssql_client.py
import socket
import ssl
import struct
import hashlib
import hmac
import base64
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from enum import IntEnum

class TDSPacketType(IntEnum):
    """TDS packet types"""
    SQL_BATCH = 1
    PRE_TDS7_LOGIN = 2
    RPC = 3
    TABULAR_RESULT = 4
    ATTENTION_SIGNAL = 6
    BULK_LOAD_DATA = 7
    FEDERATED_AUTH_TOKEN = 8
    TDS7_LOGIN = 16
    SSPI = 17
    PRE_LOGIN = 18

class TDSTokenType(IntEnum):
    """TDS token types"""
    COLMETADATA = 0x81
    ROW = 0xD1
    DONE = 0xFD
    DONEPROC = 0xFE
    DONEINPROC = 0xFF
    ERROR = 0xAA
    INFO = 0xAB
    LOGINACK = 0xAD
    RETURNSTATUS = 0x79
    RETURNVALUE = 0xAC

@dataclass
class MSSQLCredential:
    """MSSQL connection credential"""
    username: str
    password: str
    domain: str = ""
    auth_type: str = "SQL Server Auth"  # "SQL Server Auth" or "Windows Auth"

@dataclass
class MSSQLConnection:
    """MSSQL connection configuration"""
    host: str
    port: int = 1433
    database: str = "master"
    credential: MSSQLCredential = None
    use_tls: bool = True
    timeout: int = 30

class MSSQLClient:
    """Custom MSSQL client with raw TDS 7.4 protocol implementation"""
    
    def __init__(self, connection: MSSQLConnection):
        self.connection = connection
        self.socket = None
        self.packet_id = 0
        self.is_connected = False
        self.tls_enabled = False
        
    def connect(self) -> Tuple[bool, str]:
        """Establish connection to MSSQL server"""
        try:
            # Create socket connection
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.connection.timeout)
            self.socket.connect((self.connection.host, self.connection.port))
            
            # Send Pre-Login packet
            success, message = self._send_prelogin()
            if not success:
                return False, f"Pre-login failed: {message}"
            
            # Handle TLS if enabled
            if self.connection.use_tls and self.tls_enabled:
                success, message = self._enable_tls()
                if not success:
                    return False, f"TLS setup failed: {message}"
            
            # Send Login7 packet
            success, message = self._send_login7()
            if not success:
                return False, f"Login failed: {message}"
            
            self.is_connected = True
            return True, "Connected successfully"
            
        except Exception as e:
            self._cleanup()
            return False, f"Connection error: {str(e)}"
    
    def execute_query(self, query: str) -> Tuple[bool, List[Tuple], List[str], str]:
        """Execute SQL query and return results"""
        if not self.is_connected:
            return False, [], [], "Not connected"
        
        try:
            # Send SQL batch packet
            success, message = self._send_sql_batch(query)
            if not success:
                return False, [], [], f"Query execution failed: {message}"
            
            # Parse response
            results, columns, error_msg = self._parse_tabular_result()
            if error_msg:
                return False, [], [], error_msg
            
            return True, results, columns, f"{len(results)} rows returned"
            
        except Exception as e:
            return False, [], [], f"Query error: {str(e)}"
    
    def get_tables(self) -> List[str]:
        """Get list of tables"""
        success, results, _, _ = self.execute_query(
            "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE'"
        )
        return [row[0] for row in results] if success else []
    
    def get_schema(self, table_name: str) -> List[Dict]:
        """Get table schema"""
        query = f"""
            SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_DEFAULT
            FROM INFORMATION_SCHEMA.COLUMNS 
            WHERE TABLE_NAME = '{table_name}'
        """
        success, results, columns, _ = self.execute_query(query)
        if success:
            return [dict(zip(columns, row)) for row in results]
        return []
    
    def close(self):
        """Close connection"""
        self._cleanup()
    
    def _send_prelogin(self) -> Tuple[bool, str]:
        """Send TDS Pre-Login packet"""
        try:
            # Pre-Login packet structure
            prelogin_data = bytearray()
            
            # Version option
            prelogin_data.extend(b'\x00')  # VERSION token
            prelogin_data.extend(struct.pack('>H', 26))  # Offset
            prelogin_data.extend(struct.pack('>H', 6))   # Length
            
            # Encryption option
            prelogin_data.extend(b'\x01')  # ENCRYPTION token
            prelogin_data.extend(struct.pack('>H', 32))  # Offset
            prelogin_data.extend(struct.pack('>H', 1))   # Length
            
            # Instance option
            prelogin_data.extend(b'\x02')  # INSTANCE token
            prelogin_data.extend(struct.pack('>H', 33))  # Offset
            prelogin_data.extend(struct.pack('>H', 0))   # Length
            
            # Thread ID option
            prelogin_data.extend(b'\x03')  # THREADID token
            prelogin_data.extend(struct.pack('>H', 33))  # Offset
            prelogin_data.extend(struct.pack('>H', 4))   # Length
            
            # Mars option
            prelogin_data.extend(b'\x04')  # MARS token
            prelogin_data.extend(struct.pack('>H', 37))  # Offset
            prelogin_data.extend(struct.pack('>H', 1))   # Length
            
            # Terminator
            prelogin_data.extend(b'\xFF')
            
            # Option data
            prelogin_data.extend(b'\x0F\x00\x07\xD0\x00\x00')  # Version: 15.0.2000.0
            prelogin_data.extend(b'\x02' if self.connection.use_tls else b'\x00')  # Encryption: ENCRYPT_REQ or ENCRYPT_OFF
            # No instance data (length 0)
            prelogin_data.extend(struct.pack('<I', 0))  # Thread ID
            prelogin_data.extend(b'\x00')  # MARS: OFF
            
            # Send packet
            success, message = self._send_packet(TDSPacketType.PRE_LOGIN, prelogin_data)
            if not success:
                return False, message
            
            # Receive response
            packet_type, data = self._receive_packet()
            if packet_type != TDSPacketType.TABULAR_RESULT:
                return False, "Invalid pre-login response"
            
            # Parse pre-login response
            self._parse_prelogin_response(data)
            
            return True, "Pre-login successful"
            
        except Exception as e:
            return False, str(e)
    
    def _enable_tls(self) -> Tuple[bool, str]:
        """Enable TLS encryption"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            self.socket = context.wrap_socket(self.socket, server_hostname=self.connection.host)
            return True, "TLS enabled"
            
        except Exception as e:
            return False, str(e)
    
    def _send_login7(self) -> Tuple[bool, str]:
        """Send TDS7 Login packet"""
        try:
            if not self.connection.credential:
                return False, "No credentials provided"
            
            cred = self.connection.credential
            
            if cred.auth_type == "Windows Auth":
                return self._send_ntlm_login()
            else:
                return self._send_sql_auth_login()
                
        except Exception as e:
            return False, str(e)
    
    def _send_sql_auth_login(self) -> Tuple[bool, str]:
        """Send SQL Server authentication login"""
        try:
            cred = self.connection.credential
            
            # Login7 packet structure
            login_data = bytearray()
            
            # Fixed header (36 bytes)
            login_data.extend(struct.pack('<I', 0))  # Length (will be updated)
            login_data.extend(struct.pack('<I', 0x74000004))  # TDS version 7.4
            login_data.extend(struct.pack('<I', 4096))  # Packet size
            login_data.extend(struct.pack('<I', 0x0F000000))  # Client version
            login_data.extend(struct.pack('<I', 0))  # Client PID
            login_data.extend(struct.pack('<I', 0))  # Connection ID
            login_data.extend(b'\x20')  # Option flags 1
            login_data.extend(b'\x03')  # Option flags 2
            login_data.extend(b'\x00')  # Type flags
            login_data.extend(b'\x00')  # Option flags 3
            login_data.extend(struct.pack('<I', 0))  # Client time zone
            login_data.extend(struct.pack('<I', 0x0409))  # Client LCID
            
            # Variable data offsets and lengths
            offset = 36 + 50  # After fixed header + variable header
            
            # Hostname
            hostname = socket.gethostname()[:30]
            hostname_utf16 = hostname.encode('utf-16le')
            login_data.extend(struct.pack('<H', offset))
            login_data.extend(struct.pack('<H', len(hostname)))
            offset += len(hostname_utf16)
            
            # Username
            username_utf16 = cred.username.encode('utf-16le')
            login_data.extend(struct.pack('<H', offset))
            login_data.extend(struct.pack('<H', len(cred.username)))
            offset += len(username_utf16)
            
            # Password (scrambled)
            password_scrambled = self._scramble_password(cred.password)
            login_data.extend(struct.pack('<H', offset))
            login_data.extend(struct.pack('<H', len(cred.password)))
            offset += len(password_scrambled)
            
            # App name
            app_name = "Huggin MSSQL Client"
            app_name_utf16 = app_name.encode('utf-16le')
            login_data.extend(struct.pack('<H', offset))
            login_data.extend(struct.pack('<H', len(app_name)))
            offset += len(app_name_utf16)
            
            # Server name
            server_utf16 = self.connection.host.encode('utf-16le')
            login_data.extend(struct.pack('<H', offset))
            login_data.extend(struct.pack('<H', len(self.connection.host)))
            offset += len(server_utf16)
            
            # Extension/SSPI (not used)
            login_data.extend(struct.pack('<H', 0))
            login_data.extend(struct.pack('<H', 0))
            
            # Library name
            lib_name = "Huggin"
            lib_name_utf16 = lib_name.encode('utf-16le')
            login_data.extend(struct.pack('<H', offset))
            login_data.extend(struct.pack('<H', len(lib_name)))
            offset += len(lib_name_utf16)
            
            # Language (not used)
            login_data.extend(struct.pack('<H', 0))
            login_data.extend(struct.pack('<H', 0))
            
            # Database
            database_utf16 = self.connection.database.encode('utf-16le')
            login_data.extend(struct.pack('<H', offset))
            login_data.extend(struct.pack('<H', len(self.connection.database)))
            offset += len(database_utf16)
            
            # Client ID (6 bytes)
            login_data.extend(b'\x01\x02\x03\x04\x05\x06')
            
            # SSPI (not used)
            login_data.extend(struct.pack('<H', 0))
            login_data.extend(struct.pack('<H', 0))
            
            # Attach DB file (not used)
            login_data.extend(struct.pack('<H', 0))
            login_data.extend(struct.pack('<H', 0))
            
            # Change password (not used)
            login_data.extend(struct.pack('<H', 0))
            login_data.extend(struct.pack('<H', 0))
            
            # SSPI long
            login_data.extend(struct.pack('<I', 0))
            
            # Add variable data
            login_data.extend(hostname_utf16)
            login_data.extend(username_utf16)
            login_data.extend(password_scrambled)
            login_data.extend(app_name_utf16)
            login_data.extend(server_utf16)
            login_data.extend(lib_name_utf16)
            login_data.extend(database_utf16)
            
            # Update length
            struct.pack_into('<I', login_data, 0, len(login_data))
            
            # Send packet
            success, message = self._send_packet(TDSPacketType.TDS7_LOGIN, login_data)
            if not success:
                return False, message
            
            # Receive response
            packet_type, data = self._receive_packet()
            if packet_type != TDSPacketType.TABULAR_RESULT:
                return False, "Invalid login response"
            
            # Parse login response
            return self._parse_login_response(data)
            
        except Exception as e:
            return False, str(e)
    
    def _send_ntlm_login(self) -> Tuple[bool, str]:
        """Send Windows authentication login using NTLM"""
        try:
            # NTLM Type 1 message
            type1_msg = self._create_ntlm_type1()
            
            # Send SSPI packet with Type 1
            success, message = self._send_sspi_packet(type1_msg)
            if not success:
                return False, f"NTLM Type 1 failed: {message}"
            
            # Receive Type 2 challenge
            packet_type, data = self._receive_packet()
            if packet_type != TDSPacketType.SSPI:
                return False, "Expected SSPI response"
            
            type2_msg = self._parse_sspi_response(data)
            if not type2_msg:
                return False, "Invalid Type 2 message"
            
            # Create Type 3 response
            type3_msg = self._create_ntlm_type3(type2_msg)
            
            # Send Type 3
            success, message = self._send_sspi_packet(type3_msg)
            if not success:
                return False, f"NTLM Type 3 failed: {message}"
            
            # Receive final response
            packet_type, data = self._receive_packet()
            if packet_type != TDSPacketType.TABULAR_RESULT:
                return False, "Invalid NTLM login response"
            
            return self._parse_login_response(data)
            
        except Exception as e:
            return False, str(e)
    
    def _send_sql_batch(self, query: str) -> Tuple[bool, str]:
        """Send SQL batch packet"""
        try:
            query_utf16 = query.encode('utf-16le')
            
            # SQL Batch packet structure
            batch_data = bytearray()
            batch_data.extend(struct.pack('<I', len(query_utf16) + 8))  # Total length
            batch_data.extend(struct.pack('<I', 0x16))  # Header length
            batch_data.extend(query_utf16)
            
            success, message = self._send_packet(TDSPacketType.SQL_BATCH, batch_data)
            return success, message
            
        except Exception as e:
            return False, str(e)
    
    def _send_packet(self, packet_type: TDSPacketType, data: bytearray) -> Tuple[bool, str]:
        """Send TDS packet"""
        try:
            self.packet_id = (self.packet_id + 1) % 256
            
            # TDS header (8 bytes)
            header = bytearray()
            header.extend(struct.pack('B', packet_type))  # Type
            header.extend(struct.pack('B', 1))  # Status (EOM)
            header.extend(struct.pack('>H', len(data) + 8))  # Length
            header.extend(struct.pack('>H', 0))  # SPID
            header.extend(struct.pack('B', self.packet_id))  # Packet ID
            header.extend(struct.pack('B', 0))  # Window
            
            # Send header + data
            self.socket.sendall(header + data)
            return True, "Packet sent"
            
        except Exception as e:
            return False, str(e)
    
    def _receive_packet(self) -> Tuple[int, bytearray]:
        """Receive TDS packet"""
        try:
            # Read header (8 bytes)
            header = self.socket.recv(8)
            if len(header) != 8:
                raise Exception("Incomplete header received")
            
            packet_type = header[0]
            status = header[1]
            length = struct.unpack('>H', header[2:4])[0]
            
            # Read data
            data_length = length - 8
            data = bytearray()
            while len(data) < data_length:
                chunk = self.socket.recv(data_length - len(data))
                if not chunk:
                    raise Exception("Connection closed")
                data.extend(chunk)
            
            return packet_type, data
            
        except Exception as e:
            raise Exception(f"Packet receive error: {str(e)}")
    
    def _parse_tabular_result(self) -> Tuple[List[Tuple], List[str], str]:
        """Parse tabular result response"""
        try:
            results = []
            columns = []
            error_msg = ""
            
            while True:
                packet_type, data = self._receive_packet()
                if packet_type != TDSPacketType.TABULAR_RESULT:
                    break
                
                pos = 0
                while pos < len(data):
                    token = data[pos]
                    pos += 1
                    
                    if token == TDSTokenType.COLMETADATA:
                        columns, pos = self._parse_column_metadata(data, pos)
                    elif token == TDSTokenType.ROW:
                        row, pos = self._parse_row_data(data, pos, len(columns))
                        results.append(row)
                    elif token == TDSTokenType.DONE:
                        pos += 8  # Skip DONE token data
                        return results, columns, error_msg
                    elif token == TDSTokenType.ERROR:
                        error_msg, pos = self._parse_error_token(data, pos)
                    else:
                        # Skip unknown tokens
                        pos += 1
            
            return results, columns, error_msg
            
        except Exception as e:
            return [], [], str(e)
    
    def _parse_column_metadata(self, data: bytearray, pos: int) -> Tuple[List[str], int]:
        """Parse column metadata token"""
        try:
            column_count = struct.unpack('<H', data[pos:pos+2])[0]
            pos += 2
            
            columns = []
            for _ in range(column_count):
                # Skip column type info (simplified)
                pos += 4  # Type, length info
                
                # Column name
                name_len = data[pos]
                pos += 1
                name = data[pos:pos+name_len*2].decode('utf-16le')
                pos += name_len * 2
                
                columns.append(name)
            
            return columns, pos
            
        except Exception:
            return [], pos
    
    def _parse_row_data(self, data: bytearray, pos: int, column_count: int) -> Tuple[Tuple, int]:
        """Parse row data token"""
        try:
            row = []
            for _ in range(column_count):
                # Simplified: assume all data is string (would need proper type handling)
                if pos >= len(data):
                    break
                
                # Read length-prefixed string (simplified)
                if pos + 1 < len(data):
                    length = data[pos]
                    pos += 1
                    if length > 0 and pos + length <= len(data):
                        value = data[pos:pos+length].decode('utf-8', errors='ignore')
                        pos += length
                    else:
                        value = ""
                else:
                    value = ""
                
                row.append(value)
            
            return tuple(row), pos
            
        except Exception:
            return tuple(), pos
    
    def _parse_error_token(self, data: bytearray, pos: int) -> Tuple[str, int]:
        """Parse error token"""
        try:
            # Skip error details and extract message (simplified)
            pos += 8  # Skip error number, state, class, length
            msg_len = struct.unpack('<H', data[pos:pos+2])[0]
            pos += 2
            message = data[pos:pos+msg_len*2].decode('utf-16le')
            pos += msg_len * 2
            
            return message, pos
            
        except Exception:
            return "Unknown error", pos
    
    def _scramble_password(self, password: str) -> bytearray:
        """Scramble password for TDS login"""
        password_utf16 = password.encode('utf-16le')
        scrambled = bytearray()
        
        for byte in password_utf16:
            # XOR with 0xA5 and swap nibbles
            xored = byte ^ 0xA5
            scrambled.append(((xored & 0x0F) << 4) | ((xored & 0xF0) >> 4))
        
        return scrambled
    
    def _create_ntlm_type1(self) -> bytearray:
        """Create NTLM Type 1 message"""
        # Simplified NTLM Type 1 message
        msg = bytearray()
        msg.extend(b'NTLMSSP\x00')  # Signature
        msg.extend(struct.pack('<I', 1))  # Type 1
        msg.extend(struct.pack('<I', 0x06820000))  # Flags
        msg.extend(struct.pack('<H', 0))  # Domain length
        msg.extend(struct.pack('<H', 0))  # Domain max length
        msg.extend(struct.pack('<I', 0))  # Domain offset
        msg.extend(struct.pack('<H', 0))  # Workstation length
        msg.extend(struct.pack('<H', 0))  # Workstation max length
        msg.extend(struct.pack('<I', 0))  # Workstation offset
        
        return msg
    
    def _create_ntlm_type3(self, type2_msg: bytearray) -> bytearray:
        """Create NTLM Type 3 response"""
        # Simplified NTLM Type 3 - would need full NTLM implementation
        cred = self.connection.credential
        
        # Extract challenge from Type 2 (simplified)
        challenge = type2_msg[24:32] if len(type2_msg) >= 32 else b'\x00' * 8
        
        # Create responses (simplified - would need proper NTLM hash calculation)
        lm_response = b'\x00' * 24
        nt_response = self._create_nt_response(cred.password, challenge)
        
        # Build Type 3 message
        msg = bytearray()
        msg.extend(b'NTLMSSP\x00')  # Signature
        msg.extend(struct.pack('<I', 3))  # Type 3
        
        # Add fields (simplified structure)
        offset = 64
        
        # LM Response
        msg.extend(struct.pack('<H', len(lm_response)))
        msg.extend(struct.pack('<H', len(lm_response)))
        msg.extend(struct.pack('<I', offset))
        offset += len(lm_response)
        
        # NT Response
        msg.extend(struct.pack('<H', len(nt_response)))
        msg.extend(struct.pack('<H', len(nt_response)))
        msg.extend(struct.pack('<I', offset))
        offset += len(nt_response)
        
        # Domain
        domain_utf16 = cred.domain.encode('utf-16le')
        msg.extend(struct.pack('<H', len(domain_utf16)))
        msg.extend(struct.pack('<H', len(domain_utf16)))
        msg.extend(struct.pack('<I', offset))
        offset += len(domain_utf16)
        
        # Username
        username_utf16 = cred.username.encode('utf-16le')
        msg.extend(struct.pack('<H', len(username_utf16)))
        msg.extend(struct.pack('<H', len(username_utf16)))
        msg.extend(struct.pack('<I', offset))
        offset += len(username_utf16)
        
        # Workstation
        workstation = socket.gethostname()
        workstation_utf16 = workstation.encode('utf-16le')
        msg.extend(struct.pack('<H', len(workstation_utf16)))
        msg.extend(struct.pack('<H', len(workstation_utf16)))
        msg.extend(struct.pack('<I', offset))
        offset += len(workstation_utf16)
        
        # Session key (empty)
        msg.extend(struct.pack('<H', 0))
        msg.extend(struct.pack('<H', 0))
        msg.extend(struct.pack('<I', offset))
        
        # Flags
        msg.extend(struct.pack('<I', 0x06820000))
        
        # Add data
        msg.extend(lm_response)
        msg.extend(nt_response)
        msg.extend(domain_utf16)
        msg.extend(username_utf16)
        msg.extend(workstation_utf16)
        
        return msg
    
    def _create_nt_response(self, password: str, challenge: bytes) -> bytearray:
        """Create NT response (simplified)"""
        # This is a simplified version - full NTLM would require proper MD4/DES
        nt_hash = hashlib.md4(password.encode('utf-16le')).digest()
        response = hmac.new(nt_hash, challenge, hashlib.md5).digest()
        return bytearray(response + b'\x00' * 8)  # Pad to 24 bytes
    
    def _send_sspi_packet(self, sspi_data: bytearray) -> Tuple[bool, str]:
        """Send SSPI packet"""
        return self._send_packet(TDSPacketType.SSPI, sspi_data)
    
    def _parse_sspi_response(self, data: bytearray) -> Optional[bytearray]:
        """Parse SSPI response"""
        # Return the SSPI data (Type 2 message)
        return data if len(data) > 0 else None
    
    def _parse_prelogin_response(self, data: bytearray):
        """Parse pre-login response"""
        # Check if TLS is supported/required
        if len(data) > 5:
            encryption_option = data[5]
            if encryption_option in [0x01, 0x02]:  # ENCRYPT_ON or ENCRYPT_REQ
                self.tls_enabled = True
    
    def _parse_login_response(self, data: bytearray) -> Tuple[bool, str]:
        """Parse login response"""
        try:
            pos = 0
            while pos < len(data):
                token = data[pos]
                pos += 1
                
                if token == TDSTokenType.LOGINACK:
                    # Login successful
                    return True, "Login successful"
                elif token == TDSTokenType.ERROR:
                    error_msg, pos = self._parse_error_token(data, pos)
                    return False, f"Login failed: {error_msg}"
                else:
                    # Skip other tokens
                    pos += 1
            
            return False, "Unknown login response"
            
        except Exception as e:
            return False, str(e)
    
    def _cleanup(self):
        """Cleanup connection resources"""
        self.is_connected = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None