# app/core/lsarpc_client.py
import struct
import uuid
from typing import Dict, List, Optional
from app.core.logger import logger

class LSARPCClient:
    """Local Security Authority RPC client for policy enumeration"""
    
    # LSARPC Interface UUID: 12345778-1234-ABCD-EF00-0123456789AB
    LSARPC_UUID = uuid.UUID('12345778-1234-ABCD-EF00-0123456789AB')
    LSARPC_VERSION = (0, 0)
    
    # LSARPC RPC Operation Numbers
    LSA_OPEN_POLICY2 = 44
    LSA_QUERY_INFORMATION_POLICY = 7
    LSA_ENUMERATE_ACCOUNTS = 11
    LSA_ENUMERATE_TRUSTED_DOMAINS = 13
    LSA_LOOKUP_NAMES = 14
    LSA_LOOKUP_SIDS = 15
    LSA_ENUMERATE_PRIVILEGES = 2
    LSA_ENUMERATE_ACCOUNTS_WITH_USER_RIGHT = 35
    LSA_CLOSE = 0
    
    # Policy Information Classes
    POLICY_AUDIT_LOG_INFO = 1
    POLICY_AUDIT_EVENTS_INFO = 2
    POLICY_PRIMARY_DOMAIN_INFO = 3
    POLICY_PD_ACCOUNT_INFO = 4
    POLICY_ACCOUNT_DOMAIN_INFO = 5
    POLICY_SERVER_ROLE_INFO = 6
    POLICY_REPLICA_SOURCE_INFO = 7
    POLICY_DEFAULT_QUOTA_INFO = 8
    POLICY_MODIFICATION_INFO = 9
    POLICY_AUDIT_FULL_SET_INFO = 10
    POLICY_AUDIT_FULL_QUERY_INFO = 11
    POLICY_DNS_DOMAIN_INFO = 12
    
    def __init__(self, rpc_transport):
        self.transport = rpc_transport
        self.policy_handle = None
        
    def connect(self) -> bool:
        """Connect to LSA service"""
        try:
            # Bind to LSARPC interface
            if not self.transport.bind_interface(self.LSARPC_UUID, self.LSARPC_VERSION):
                return False
            
            # Open policy handle
            self.policy_handle = self._lsa_open_policy2()
            return self.policy_handle is not None
            
        except Exception:
            return False
    
    def _lsa_open_policy2(self) -> Optional[bytes]:
        """Open LSA policy handle (LsaOpenPolicy2)"""
        try:
            # Build request
            system_name = b'\x00\x00'  # NULL system name (local)
            object_attributes = b'\x00' * 12  # Empty OBJECT_ATTRIBUTES
            access_mask = 0x02000000  # MAXIMUM_ALLOWED
            
            request_data = (
                system_name +
                object_attributes +
                struct.pack('<I', access_mask)
            )
            
            response = self.transport.call_rpc(self.LSA_OPEN_POLICY2, request_data, self.LSARPC_UUID)
            if not response or len(response) < 20:
                return None
            
            # Extract policy handle (20 bytes)
            handle = response[:20]
            return handle
            
        except Exception:
            return None
    
    def query_policy_information(self, info_class: int) -> Optional[Dict]:
        """Query LSA policy information"""
        try:
            if not self.policy_handle:
                return None
            
            request_data = (
                self.policy_handle +
                struct.pack('<H', info_class)
            )
            
            response = self.transport.call_rpc(self.LSA_QUERY_INFORMATION_POLICY, request_data, self.LSARPC_UUID)
            if not response:
                return None
            
            return self._parse_policy_info(response, info_class)
            
        except Exception:
            return None
    
    def enumerate_accounts(self) -> List[Dict]:
        """Enumerate LSA accounts"""
        try:
            if not self.policy_handle:
                return []
            
            accounts = []
            enum_context = 0
            
            while True:
                request_data = (
                    self.policy_handle +
                    struct.pack('<I', enum_context) +
                    struct.pack('<I', 1000)  # Preferred maximum length
                )
                
                response = self.transport.call_rpc(self.LSA_ENUMERATE_ACCOUNTS, request_data, self.LSARPC_UUID)
                if not response:
                    break
                
                batch_accounts = self._parse_account_enumeration(response)
                accounts.extend(batch_accounts)
                
                # Check if more data available
                if len(response) < 8:
                    break
                
                enum_context = struct.unpack('<I', response[-8:-4])[0]
                if enum_context == 0:
                    break
            
            return accounts
            
        except Exception:
            return []
    
    def enumerate_trusted_domains(self) -> List[Dict]:
        """Enumerate trusted domains"""
        try:
            if not self.policy_handle:
                return []
            
            request_data = (
                self.policy_handle +
                struct.pack('<I', 0) +  # Enumeration context
                struct.pack('<I', 1000)  # Preferred maximum length
            )
            
            response = self.transport.call_rpc(self.LSA_ENUMERATE_TRUSTED_DOMAINS, request_data, self.LSARPC_UUID)
            if not response:
                return []
            
            return self._parse_trusted_domain_enumeration(response)
            
        except Exception:
            return []
    
    def enumerate_privileges(self) -> List[Dict]:
        """Enumerate system privileges"""
        try:
            if not self.policy_handle:
                return []
            
            request_data = (
                self.policy_handle +
                struct.pack('<I', 0) +  # Enumeration context
                struct.pack('<I', 1000)  # Preferred maximum length
            )
            
            response = self.transport.call_rpc(self.LSA_ENUMERATE_PRIVILEGES, request_data, self.LSARPC_UUID)
            if not response:
                return []
            
            return self._parse_privilege_enumeration(response)
            
        except Exception:
            return []
    
    def lookup_names(self, names: List[str]) -> List[Dict]:
        """Lookup SIDs for given names"""
        try:
            if not self.policy_handle or not names:
                return []
            
            # Build names array
            names_data = b''
            for name in names[:100]:  # Limit to prevent issues
                name_utf16 = name.encode('utf-16le')
                names_data += struct.pack('<H', len(name_utf16))
                names_data += struct.pack('<H', len(name_utf16) + 2)
                names_data += name_utf16
                names_data += b'\x00\x00'  # Null terminator
            
            request_data = (
                self.policy_handle +
                struct.pack('<I', len(names)) +
                names_data +
                struct.pack('<I', 1) +  # Lookup level
                struct.pack('<I', 0)    # Mapped count (output)
            )
            
            response = self.transport.call_rpc(self.LSA_LOOKUP_NAMES, request_data, self.LSARPC_UUID)
            if not response:
                return []
            
            return self._parse_lookup_response(response)
            
        except Exception:
            return []
    
    def lookup_sids(self, sids: List[bytes]) -> List[Dict]:
        """Lookup names for given SIDs"""
        try:
            if not self.policy_handle or not sids:
                return []
            
            # Build SIDs array
            sids_data = b''
            for sid in sids[:100]:  # Limit to prevent issues
                sids_data += struct.pack('<I', len(sid))
                sids_data += sid
            
            request_data = (
                self.policy_handle +
                struct.pack('<I', len(sids)) +
                sids_data +
                struct.pack('<I', 1) +  # Lookup level
                struct.pack('<I', 0)    # Mapped count (output)
            )
            
            response = self.transport.call_rpc(self.LSA_LOOKUP_SIDS, request_data, self.LSARPC_UUID)
            if not response:
                return []
            
            return self._parse_lookup_response(response)
            
        except Exception:
            return []
    
    def enumerate_accounts_with_user_right(self, user_right: str) -> List[Dict]:
        """Enumerate accounts with specific user right"""
        try:
            if not self.policy_handle:
                return []
            
            # Convert user right to UTF-16LE
            right_utf16 = user_right.encode('utf-16le')
            
            request_data = (
                self.policy_handle +
                struct.pack('<H', len(right_utf16)) +
                struct.pack('<H', len(right_utf16) + 2) +
                right_utf16 +
                b'\x00\x00'  # Null terminator
            )
            
            response = self.transport.call_rpc(self.LSA_ENUMERATE_ACCOUNTS_WITH_USER_RIGHT, request_data, self.LSARPC_UUID)
            if not response:
                return []
            
            return self._parse_account_enumeration(response)
            
        except Exception:
            return []
    
    def _parse_policy_info(self, response: bytes, info_class: int) -> Dict:
        """Parse policy information response"""
        try:
            info = {'info_class': info_class}
            
            if len(response) < 4:
                return info
            
            pos = 4  # Skip info class
            
            if info_class == self.POLICY_PRIMARY_DOMAIN_INFO:
                # Parse primary domain information
                if len(response) >= pos + 8:
                    name_len = struct.unpack('<H', response[pos:pos+2])[0]
                    pos += 8  # Skip name structure
                    
                    if pos + name_len <= len(response) and name_len > 0:
                        domain_name = response[pos:pos+name_len].decode('utf-16le', errors='ignore').rstrip('\x00')
                        info['domain_name'] = domain_name
                        pos += name_len
                    
                    # Parse domain SID if present
                    if pos + 4 <= len(response):
                        sid_len = struct.unpack('<I', response[pos:pos+4])[0]
                        pos += 4
                        
                        if pos + sid_len <= len(response) and sid_len > 0:
                            info['domain_sid'] = response[pos:pos+sid_len]
            
            elif info_class == self.POLICY_ACCOUNT_DOMAIN_INFO:
                # Parse account domain information
                if len(response) >= pos + 8:
                    name_len = struct.unpack('<H', response[pos:pos+2])[0]
                    pos += 8
                    
                    if pos + name_len <= len(response) and name_len > 0:
                        account_domain = response[pos:pos+name_len].decode('utf-16le', errors='ignore').rstrip('\x00')
                        info['account_domain'] = account_domain
            
            elif info_class == self.POLICY_DNS_DOMAIN_INFO:
                # Parse DNS domain information
                strings = ['dns_domain', 'dns_forest', 'domain_guid']
                for field in strings:
                    if pos + 8 <= len(response):
                        str_len = struct.unpack('<H', response[pos:pos+2])[0]
                        pos += 8
                        
                        if pos + str_len <= len(response) and str_len > 0:
                            if field == 'domain_guid':
                                info[field] = response[pos:pos+str_len].hex()
                            else:
                                info[field] = response[pos:pos+str_len].decode('utf-16le', errors='ignore').rstrip('\x00')
                            pos += str_len
            
            return info
            
        except Exception:
            return {'info_class': info_class}
    
    def _parse_account_enumeration(self, response: bytes) -> List[Dict]:
        """Parse account enumeration response"""
        try:
            accounts = []
            if len(response) < 8:
                return accounts
            
            pos = 8  # Skip header
            count = struct.unpack('<I', response[4:8])[0]
            
            for i in range(min(count, 100)):
                if pos + 4 > len(response):
                    break
                
                sid_len = struct.unpack('<I', response[pos:pos+4])[0]
                pos += 4
                
                if pos + sid_len > len(response):
                    break
                
                sid = response[pos:pos+sid_len]
                pos += sid_len
                
                accounts.append({
                    'sid': sid,
                    'sid_string': self._sid_to_string(sid)
                })
            
            return accounts
            
        except Exception:
            return []
    
    def _parse_trusted_domain_enumeration(self, response: bytes) -> List[Dict]:
        """Parse trusted domain enumeration response"""
        try:
            domains = []
            if len(response) < 8:
                return domains
            
            pos = 8
            count = struct.unpack('<I', response[4:8])[0]
            
            for i in range(min(count, 50)):
                if pos + 12 > len(response):
                    break
                
                name_len = struct.unpack('<H', response[pos:pos+2])[0]
                pos += 8  # Skip name structure
                
                if pos + name_len > len(response):
                    break
                
                name = response[pos:pos+name_len].decode('utf-16le', errors='ignore').rstrip('\x00')
                pos += name_len
                
                # Parse SID
                sid_len = struct.unpack('<I', response[pos:pos+4])[0]
                pos += 4
                
                if pos + sid_len > len(response):
                    break
                
                sid = response[pos:pos+sid_len]
                pos += sid_len
                
                domains.append({
                    'name': name,
                    'sid': sid,
                    'sid_string': self._sid_to_string(sid)
                })
            
            return domains
            
        except Exception:
            return []
    
    def _parse_privilege_enumeration(self, response: bytes) -> List[Dict]:
        """Parse privilege enumeration response"""
        try:
            privileges = []
            if len(response) < 8:
                return privileges
            
            pos = 8
            count = struct.unpack('<I', response[4:8])[0]
            
            for i in range(min(count, 100)):
                if pos + 16 > len(response):
                    break
                
                # Parse LUID (8 bytes)
                luid_low = struct.unpack('<I', response[pos:pos+4])[0]
                luid_high = struct.unpack('<I', response[pos+4:pos+8])[0]
                pos += 8
                
                # Parse name
                name_len = struct.unpack('<H', response[pos:pos+2])[0]
                pos += 8  # Skip name structure
                
                if pos + name_len > len(response):
                    break
                
                name = response[pos:pos+name_len].decode('utf-16le', errors='ignore').rstrip('\x00')
                pos += name_len
                
                privileges.append({
                    'name': name,
                    'luid_low': luid_low,
                    'luid_high': luid_high
                })
            
            return privileges
            
        except Exception:
            return []
    
    def _parse_lookup_response(self, response: bytes) -> List[Dict]:
        """Parse name/SID lookup response"""
        try:
            results = []
            if len(response) < 8:
                return results
            
            pos = 8
            count = struct.unpack('<I', response[4:8])[0]
            
            for i in range(min(count, 100)):
                if pos + 12 > len(response):
                    break
                
                sid_use = struct.unpack('<I', response[pos:pos+4])[0]
                pos += 4
                
                # Parse name
                name_len = struct.unpack('<H', response[pos:pos+2])[0]
                pos += 8
                
                if pos + name_len > len(response):
                    break
                
                name = response[pos:pos+name_len].decode('utf-16le', errors='ignore').rstrip('\x00')
                pos += name_len
                
                results.append({
                    'name': name,
                    'sid_use': sid_use,
                    'sid_use_name': self._get_sid_use_name(sid_use)
                })
            
            return results
            
        except Exception:
            return []
    
    def _sid_to_string(self, sid: bytes) -> str:
        """Convert binary SID to string format"""
        try:
            if len(sid) < 8:
                return "Invalid SID"
            
            revision = sid[0]
            sub_authority_count = sid[1]
            authority = struct.unpack('>Q', b'\x00\x00' + sid[2:8])[0]
            
            sid_string = f"S-{revision}-{authority}"
            
            pos = 8
            for i in range(sub_authority_count):
                if pos + 4 > len(sid):
                    break
                sub_auth = struct.unpack('<I', sid[pos:pos+4])[0]
                sid_string += f"-{sub_auth}"
                pos += 4
            
            return sid_string
            
        except Exception:
            return "Invalid SID"
    
    def _get_sid_use_name(self, sid_use: int) -> str:
        """Get human-readable SID use name"""
        sid_use_names = {
            1: "User",
            2: "Group", 
            3: "Domain",
            4: "Alias",
            5: "WellKnownGroup",
            6: "DeletedAccount",
            7: "Invalid",
            8: "Unknown",
            9: "Computer"
        }
        return sid_use_names.get(sid_use, f"Unknown({sid_use})")
    
    def cleanup(self):
        """Clean up policy handle"""
        try:
            if self.policy_handle:
                request_data = self.policy_handle
                self.transport.call_rpc(self.LSA_CLOSE, request_data, self.LSARPC_UUID)
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
