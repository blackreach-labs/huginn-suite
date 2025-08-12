"""
Windows Registry (winreg) RPC Client
Implements remote registry access via RPC
"""
import struct
from typing import Optional, Dict, List

class WinRegClient:
    def __init__(self, rpc_transport):
        self.rpc = rpc_transport
        self.registry_handles = {}
        
    def connect(self) -> bool:
        """Connect to Windows Registry service"""
        from .rpc_transport import RPC_INTERFACES
        
        interface = RPC_INTERFACES['winreg']
        return self.rpc.bind_interface(
            interface['uuid'],
            interface['version'],
            interface['pipe']
        )
    
    def open_key(self, hive: str, subkey: str = "") -> Optional[bytes]:
        """Open registry key"""
        # Map hive names to RPC functions
        hive_map = {
            'HKLM': 2,  # OpenLocalMachine
            'HKCU': 1,  # OpenCurrentUser
            'HKCR': 0,  # OpenClassesRoot
            'HKU': 3,   # OpenUsers
            'HKCC': 4   # OpenCurrentConfig
        }
        
        opnum = hive_map.get(hive.upper())
        if opnum is None:
            return None
        
        # Open predefined key
        request_data = struct.pack('<II', 
            0,          # Server name (NULL)
            0x02000000  # Access mask (KEY_READ)
        )
        
        response = self.rpc.call_function(opnum, request_data)
        if not response or len(response) < 24:
            return None
        
        # Extract handle
        handle = response[:20]
        return_code = struct.unpack('<I', response[20:24])[0]
        
        if return_code != 0:
            return None
        
        # If subkey specified, open it
        if subkey:
            return self._open_subkey(handle, subkey)
        
        return handle
    
    def _open_subkey(self, parent_handle: bytes, subkey: str) -> Optional[bytes]:
        """Open registry subkey"""
        # BaseRegOpenKey function (opnum 15)
        subkey_bytes = subkey.encode('utf-16le') + b'\x00\x00'
        
        request_data = parent_handle  # Parent key handle
        request_data += struct.pack('<I', len(subkey_bytes) // 2)  # Subkey name length
        request_data += subkey_bytes
        request_data += struct.pack('<II',
            0,          # Options
            0x20019     # Access mask (KEY_READ)
        )
        
        response = self.rpc.call_function(15, request_data)
        if not response or len(response) < 24:
            return None
        
        handle = response[:20]
        return_code = struct.unpack('<I', response[20:24])[0]
        
        return handle if return_code == 0 else None
    
    def query_value(self, key_handle: bytes, value_name: str) -> Optional[Dict]:
        """Query registry value"""
        # BaseRegQueryValue function (opnum 17)
        value_name_bytes = value_name.encode('utf-16le') + b'\x00\x00'
        
        request_data = key_handle  # Key handle
        request_data += struct.pack('<I', len(value_name_bytes) // 2)  # Value name length
        request_data += value_name_bytes
        request_data += struct.pack('<III',
            0,      # Type (output)
            0,      # Data (output)
            1024    # Data size
        )
        
        response = self.rpc.call_function(17, request_data)
        if not response or len(response) < 12:
            return None
        
        # Parse response
        value_type = struct.unpack('<I', response[0:4])[0]
        data_length = struct.unpack('<I', response[4:8])[0]
        return_code = struct.unpack('<I', response[8:12])[0]
        
        if return_code != 0:
            return None
        
        # Extract data
        data = response[12:12+data_length] if data_length > 0 else b''
        
        # Map registry types
        type_map = {
            1: 'REG_SZ',
            2: 'REG_EXPAND_SZ',
            3: 'REG_BINARY',
            4: 'REG_DWORD',
            7: 'REG_MULTI_SZ',
            11: 'REG_QWORD'
        }
        
        # Parse data based on type
        parsed_data = self._parse_registry_data(data, value_type)
        
        return {
            'name': value_name,
            'type': type_map.get(value_type, f'UNKNOWN_{value_type}'),
            'data': parsed_data,
            'raw_data': data
        }
    
    def enum_keys(self, key_handle: bytes) -> List[str]:
        """Enumerate registry subkeys"""
        keys = []
        index = 0
        
        while True:
            # BaseRegEnumKey function (opnum 9)
            request_data = key_handle  # Key handle
            request_data += struct.pack('<III',
                index,  # Index
                256,    # Name length
                0       # Last write time
            )
            
            response = self.rpc.call_function(9, request_data)
            if not response or len(response) < 8:
                break
            
            name_length = struct.unpack('<I', response[0:4])[0]
            return_code = struct.unpack('<I', response[4:8])[0]
            
            if return_code != 0:
                break
            
            # Extract key name
            if name_length > 0 and len(response) >= 8 + name_length * 2:
                key_name = response[8:8+name_length*2].decode('utf-16le', errors='ignore')
                keys.append(key_name.rstrip('\x00'))
            
            index += 1
        
        return keys
    
    def enum_values(self, key_handle: bytes) -> List[Dict]:
        """Enumerate registry values"""
        values = []
        index = 0
        
        while True:
            # BaseRegEnumValue function (opnum 10)
            request_data = key_handle  # Key handle
            request_data += struct.pack('<IIII',
                index,  # Index
                256,    # Name length
                1024,   # Data length
                0       # Type
            )
            
            response = self.rpc.call_function(10, request_data)
            if not response or len(response) < 16:
                break
            
            name_length = struct.unpack('<I', response[0:4])[0]
            data_length = struct.unpack('<I', response[4:8])[0]
            value_type = struct.unpack('<I', response[8:12])[0]
            return_code = struct.unpack('<I', response[12:16])[0]
            
            if return_code != 0:
                break
            
            # Extract value name and data
            offset = 16
            value_name = ""
            if name_length > 0:
                name_data = response[offset:offset+name_length*2]
                value_name = name_data.decode('utf-16le', errors='ignore').rstrip('\x00')
                offset += name_length * 2
            
            value_data = response[offset:offset+data_length] if data_length > 0 else b''
            
            # Map registry types
            type_map = {
                1: 'REG_SZ',
                2: 'REG_EXPAND_SZ',
                3: 'REG_BINARY',
                4: 'REG_DWORD',
                7: 'REG_MULTI_SZ',
                11: 'REG_QWORD'
            }
            
            parsed_data = self._parse_registry_data(value_data, value_type)
            
            values.append({
                'name': value_name,
                'type': type_map.get(value_type, f'UNKNOWN_{value_type}'),
                'data': parsed_data,
                'raw_data': value_data
            })
            
            index += 1
        
        return values
    
    def _parse_registry_data(self, data: bytes, reg_type: int):
        """Parse registry data based on type"""
        if not data:
            return None
        
        try:
            if reg_type == 1:  # REG_SZ
                return data.decode('utf-16le', errors='ignore').rstrip('\x00')
            elif reg_type == 2:  # REG_EXPAND_SZ
                return data.decode('utf-16le', errors='ignore').rstrip('\x00')
            elif reg_type == 4:  # REG_DWORD
                if len(data) >= 4:
                    return struct.unpack('<I', data[:4])[0]
            elif reg_type == 11:  # REG_QWORD
                if len(data) >= 8:
                    return struct.unpack('<Q', data[:8])[0]
            elif reg_type == 7:  # REG_MULTI_SZ
                strings = data.decode('utf-16le', errors='ignore').split('\x00')
                return [s for s in strings if s]
            else:  # REG_BINARY or unknown
                return data.hex()
        except:
            return data.hex()
        
        return None
    
    def close_key(self, key_handle: bytes):
        """Close registry key handle"""
        if key_handle:
            # BaseRegCloseKey function (opnum 5)
            response = self.rpc.call_function(5, key_handle)
    
    def get_os_info(self) -> Optional[Dict]:
        """Get OS information from registry"""
        key_handle = self.open_key('HKLM', r'SOFTWARE\Microsoft\Windows NT\CurrentVersion')
        if not key_handle:
            return None
        
        os_info = {}
        
        # Query common OS values
        values_to_query = [
            'ProductName',
            'CurrentVersion',
            'CurrentBuild',
            'ReleaseId',
            'DisplayVersion',
            'EditionID',
            'InstallationType'
        ]
        
        for value_name in values_to_query:
            value_data = self.query_value(key_handle, value_name)
            if value_data:
                os_info[value_name] = value_data['data']
        
        self.close_key(key_handle)
        return os_info if os_info else None