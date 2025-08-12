# app/core/samr_client.py
import struct
import uuid
from typing import Dict, List, Optional, Tuple

class SAMRClient:
    """Security Account Manager RPC client for user enumeration"""
    
    # SAMR Interface UUID: 12345778-1234-ABCD-EF00-0123456789AC
    SAMR_UUID = uuid.UUID('12345778-1234-ABCD-EF00-0123456789AC')
    SAMR_VERSION = (1, 0)
    
    # SAMR RPC Operation Numbers
    SAMR_CONNECT5 = 64
    SAMR_ENUMERATE_DOMAINS = 6
    SAMR_LOOKUP_DOMAIN = 5
    SAMR_OPEN_DOMAIN = 7
    SAMR_ENUMERATE_USERS = 13
    SAMR_OPEN_USER = 34
    SAMR_QUERY_USER_INFO = 36
    SAMR_ENUMERATE_GROUPS = 11
    SAMR_CLOSE_HANDLE = 1
    
    # User Info Levels
    USER_GENERAL_INFO = 1
    USER_PREFERENCES_INFO = 2
    USER_LOGON_INFO = 3
    USER_LOGON_HOURS_INFO = 4
    USER_ACCOUNT_INFO = 5
    USER_NAME_INFO = 6
    USER_ACCOUNT_NAME_INFO = 7
    USER_FULL_NAME_INFO = 8
    USER_PRIMARY_GROUP_INFO = 9
    USER_HOME_INFO = 10
    USER_SCRIPT_INFO = 11
    USER_PROFILE_INFO = 12
    USER_ADMIN_COMMENT_INFO = 13
    USER_WORKSTATIONS_INFO = 14
    USER_CONTROL_INFO = 16
    USER_EXPIRES_INFO = 17
    USER_INTERNAL1_INFO = 18
    USER_PARAMETERS_INFO = 20
    USER_ALL_INFO = 21
    
    def __init__(self, rpc_transport):
        self.transport = rpc_transport
        self.server_handle = None
        self.domain_handle = None
        
    def connect(self) -> bool:
        """Connect to SAMR service"""
        try:
            # Bind to SAMR interface
            if not self.transport.bind_interface(self.SAMR_UUID, self.SAMR_VERSION):
                return False
            
            # Connect to SAM server
            self.server_handle = self._samr_connect5()
            return self.server_handle is not None
            
        except Exception:
            return False
    
    def _samr_connect5(self) -> Optional[bytes]:
        """Connect to SAM server (SamrConnect5)"""
        try:
            # Build request
            server_name = b'\x00\x00'  # NULL server name (local)
            access_mask = 0x02000000  # MAXIMUM_ALLOWED
            in_version = 1
            in_revision_info = struct.pack('<II', 3, 0)  # Revision 3
            
            request_data = (
                server_name +
                struct.pack('<I', access_mask) +
                struct.pack('<I', in_version) +
                in_revision_info +
                b'\x00' * 4  # out_version (will be filled by server)
            )
            
            response = self.transport.call_rpc(self.SAMR_CONNECT5, request_data, self.SAMR_UUID)
            if not response or len(response) < 24:
                return None
            
            # Extract server handle (20 bytes)
            handle = response[:20]
            return handle
            
        except Exception:
            return None
    
    def enumerate_domains(self) -> List[Dict]:
        """Enumerate domains on the server"""
        try:
            if not self.server_handle:
                return []
            
            request_data = (
                self.server_handle +  # Server handle
                struct.pack('<I', 0) +  # Enumeration context
                struct.pack('<I', 1000)  # Preferred maximum length
            )
            
            response = self.transport.call_rpc(self.SAMR_ENUMERATE_DOMAINS, request_data, self.SAMR_UUID)
            if not response:
                return []
            
            return self._parse_enumeration_response(response)
            
        except Exception:
            return []
    
    def open_domain(self, domain_sid: bytes) -> bool:
        """Open domain for enumeration"""
        try:
            if not self.server_handle:
                return False
            
            access_mask = 0x02000000  # MAXIMUM_ALLOWED
            
            request_data = (
                self.server_handle +
                struct.pack('<I', access_mask) +
                domain_sid
            )
            
            response = self.transport.call_rpc(self.SAMR_OPEN_DOMAIN, request_data, self.SAMR_UUID)
            if not response or len(response) < 20:
                return False
            
            self.domain_handle = response[:20]
            return True
            
        except Exception:
            return False
    
    def enumerate_users(self) -> List[Dict]:
        """Enumerate users in the domain"""
        try:
            if not self.domain_handle:
                return []
            
            users = []
            enum_context = 0
            
            while True:
                request_data = (
                    self.domain_handle +
                    struct.pack('<I', enum_context) +
                    struct.pack('<I', 0) +  # User account control filter
                    struct.pack('<I', 1000)  # Preferred maximum length
                )
                
                response = self.transport.call_rpc(self.SAMR_ENUMERATE_USERS, request_data, self.SAMR_UUID)
                if not response:
                    break
                
                batch_users = self._parse_user_enumeration(response)
                users.extend(batch_users)
                
                # Check if more data available
                if len(response) < 8:
                    break
                
                enum_context = struct.unpack('<I', response[-8:-4])[0]
                if enum_context == 0:
                    break
            
            return users
            
        except Exception:
            return []
    
    def query_user_info(self, user_rid: int, info_level: int = USER_ALL_INFO) -> Optional[Dict]:
        """Query detailed user information"""
        try:
            if not self.domain_handle:
                return None
            
            # Open user handle
            user_handle = self._open_user(user_rid)
            if not user_handle:
                return None
            
            request_data = (
                user_handle +
                struct.pack('<H', info_level)
            )
            
            response = self.transport.call_rpc(self.SAMR_QUERY_USER_INFO, request_data, self.SAMR_UUID)
            if not response:
                self._close_handle(user_handle)
                return None
            
            user_info = self._parse_user_info(response, info_level)
            self._close_handle(user_handle)
            
            return user_info
            
        except Exception:
            return None
    
    def enumerate_groups(self) -> List[Dict]:
        """Enumerate groups in the domain"""
        try:
            if not self.domain_handle:
                return []
            
            request_data = (
                self.domain_handle +
                struct.pack('<I', 0) +  # Enumeration context
                struct.pack('<I', 1000)  # Preferred maximum length
            )
            
            response = self.transport.call_rpc(self.SAMR_ENUMERATE_GROUPS, request_data, self.SAMR_UUID)
            if not response:
                return []
            
            return self._parse_enumeration_response(response)
            
        except Exception:
            return []
    
    def _open_user(self, user_rid: int) -> Optional[bytes]:
        """Open user handle"""
        try:
            access_mask = 0x02000000  # MAXIMUM_ALLOWED
            
            request_data = (
                self.domain_handle +
                struct.pack('<I', access_mask) +
                struct.pack('<I', user_rid)
            )
            
            response = self.transport.call_rpc(self.SAMR_OPEN_USER, request_data, self.SAMR_UUID)
            if not response or len(response) < 20:
                return None
            
            return response[:20]
            
        except Exception:
            return None
    
    def _close_handle(self, handle: bytes):
        """Close RPC handle"""
        try:
            request_data = handle
            self.transport.call_rpc(self.SAMR_CLOSE_HANDLE, request_data, self.SAMR_UUID)
        except:
            pass
    
    def _parse_enumeration_response(self, response: bytes) -> List[Dict]:
        """Parse enumeration response"""
        try:
            items = []
            if len(response) < 8:
                return items
            
            # Skip enumeration context and count
            pos = 8
            count = struct.unpack('<I', response[4:8])[0]
            
            for i in range(min(count, 100)):  # Limit to prevent issues
                if pos + 8 > len(response):
                    break
                
                rid = struct.unpack('<I', response[pos:pos+4])[0]
                name_len = struct.unpack('<H', response[pos+4:pos+6])[0]
                pos += 8
                
                if pos + name_len > len(response):
                    break
                
                name = response[pos:pos+name_len].decode('utf-16le', errors='ignore').rstrip('\x00')
                pos += name_len
                
                items.append({
                    'rid': rid,
                    'name': name
                })
            
            return items
            
        except Exception:
            return []
    
    def _parse_user_enumeration(self, response: bytes) -> List[Dict]:
        """Parse user enumeration response"""
        try:
            users = []
            if len(response) < 8:
                return users
            
            pos = 8  # Skip header
            count = struct.unpack('<I', response[4:8])[0]
            
            for i in range(min(count, 100)):
                if pos + 12 > len(response):
                    break
                
                rid = struct.unpack('<I', response[pos:pos+4])[0]
                attributes = struct.unpack('<I', response[pos+4:pos+8])[0]
                name_len = struct.unpack('<H', response[pos+8:pos+10])[0]
                pos += 12
                
                if pos + name_len > len(response):
                    break
                
                name = response[pos:pos+name_len].decode('utf-16le', errors='ignore').rstrip('\x00')
                pos += name_len
                
                users.append({
                    'rid': rid,
                    'name': name,
                    'attributes': attributes,
                    'disabled': bool(attributes & 0x02),
                    'locked': bool(attributes & 0x10)
                })
            
            return users
            
        except Exception:
            return []
    
    def _parse_user_info(self, response: bytes, info_level: int) -> Dict:
        """Parse user information response"""
        try:
            user_info = {'info_level': info_level}
            
            if len(response) < 4:
                return user_info
            
            pos = 4  # Skip info level
            
            if info_level == self.USER_ALL_INFO:
                # Parse USER_ALL_INFORMATION structure
                if len(response) >= pos + 48:
                    # Basic fields
                    user_info.update({
                        'last_logon': struct.unpack('<Q', response[pos:pos+8])[0],
                        'last_logoff': struct.unpack('<Q', response[pos+8:pos+16])[0],
                        'password_last_set': struct.unpack('<Q', response[pos+16:pos+24])[0],
                        'account_expires': struct.unpack('<Q', response[pos+24:pos+32])[0],
                        'password_can_change': struct.unpack('<Q', response[pos+32:pos+40])[0],
                        'password_must_change': struct.unpack('<Q', response[pos+40:pos+48])[0]
                    })
                    pos += 48
                
                # Parse strings (username, full name, etc.)
                strings = ['username', 'full_name', 'home_directory', 'home_drive', 
                          'logon_script', 'profile_path', 'workstations', 'comment']
                
                for field in strings:
                    if pos + 4 <= len(response):
                        str_len = struct.unpack('<H', response[pos:pos+2])[0]
                        pos += 4  # Skip length and max length
                        
                        if pos + str_len <= len(response) and str_len > 0:
                            value = response[pos:pos+str_len].decode('utf-16le', errors='ignore').rstrip('\x00')
                            user_info[field] = value
                            pos += str_len
                        else:
                            user_info[field] = ''
            
            return user_info
            
        except Exception:
            return {'info_level': info_level}
    
    def cleanup(self):
        """Clean up handles"""
        try:
            if self.domain_handle:
                self._close_handle(self.domain_handle)
            if self.server_handle:
                self._close_handle(self.server_handle)
        except:
            pass