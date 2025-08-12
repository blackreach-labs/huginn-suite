"""
Service Control Manager (svcctl) RPC Client
Implements Windows Service enumeration via RPC
"""
import struct
from typing import List, Dict, Optional

class SvcCtlClient:
    def __init__(self, rpc_transport):
        self.rpc = rpc_transport
        self.scm_handle = None
        
    def connect(self) -> bool:
        """Connect to Service Control Manager"""
        from .rpc_transport import RPC_INTERFACES
        
        interface = RPC_INTERFACES['svcctl']
        return self.rpc.bind_interface(
            interface['uuid'],
            interface['version'],
            interface['pipe']
        )
    
    def open_scm(self, machine_name: str = None, access_mask: int = 0xF003F) -> bool:
        """Open Service Control Manager handle"""
        # ROpenSCManagerW function (opnum 15)
        machine_name_bytes = b''
        if machine_name:
            machine_name_bytes = machine_name.encode('utf-16le') + b'\x00\x00'
        
        # NDR encoding for ROpenSCManagerW
        request_data = struct.pack('<II', 
            len(machine_name_bytes) // 2 if machine_name_bytes else 0,  # Machine name length
            0  # Database name (NULL)
        )
        
        if machine_name_bytes:
            request_data += machine_name_bytes
        
        request_data += struct.pack('<I', access_mask)  # Desired access
        
        response = self.rpc.call_function(15, request_data)
        if response and len(response) >= 24:
            # Extract SCM handle (20 bytes)
            self.scm_handle = response[:20]
            # Check return code
            return_code = struct.unpack('<I', response[20:24])[0]
            return return_code == 0
        
        return False
    
    def enum_services(self, service_type: int = 0x30, service_state: int = 0x3) -> List[Dict]:
        """Enumerate services"""
        if not self.scm_handle:
            return []
        
        services = []
        resume_handle = 0
        
        while True:
            # REnumServicesStatusW function (opnum 14)
            request_data = self.scm_handle  # SCM handle
            request_data += struct.pack('<IIIII',
                service_type,    # Service type
                service_state,   # Service state
                8192,           # Buffer size
                resume_handle,   # Resume handle
                0               # Group name (NULL)
            )
            
            response = self.rpc.call_function(14, request_data)
            if not response or len(response) < 20:
                break
            
            # Parse response
            services_returned = struct.unpack('<I', response[0:4])[0]
            bytes_needed = struct.unpack('<I', response[4:8])[0]
            new_resume_handle = struct.unpack('<I', response[8:12])[0]
            return_code = struct.unpack('<I', response[16:20])[0]
            
            if return_code != 0 and return_code != 234:  # ERROR_MORE_DATA
                break
            
            # Parse service entries
            offset = 20
            for i in range(services_returned):
                if offset + 36 > len(response):
                    break
                
                service = self._parse_service_entry(response, offset)
                if service:
                    services.append(service)
                    offset += 36  # Size of ENUM_SERVICE_STATUSW structure
            
            if return_code != 234:  # No more data
                break
            
            resume_handle = new_resume_handle
        
        return services
    
    def query_service_status(self, service_name: str) -> Optional[Dict]:
        """Query specific service status"""
        if not self.scm_handle:
            return None
        
        # Open service handle first
        service_handle = self._open_service(service_name)
        if not service_handle:
            return None
        
        # RQueryServiceStatus function (opnum 6)
        request_data = service_handle
        
        response = self.rpc.call_function(6, request_data)
        if response and len(response) >= 32:
            return self._parse_service_status(response)
        
        return None
    
    def _open_service(self, service_name: str, access_mask: int = 0x20000) -> Optional[bytes]:
        """Open service handle"""
        # ROpenServiceW function (opnum 16)
        service_name_bytes = service_name.encode('utf-16le') + b'\x00\x00'
        
        request_data = self.scm_handle  # SCM handle
        request_data += struct.pack('<I', len(service_name_bytes) // 2)  # Service name length
        request_data += service_name_bytes
        request_data += struct.pack('<I', access_mask)  # Desired access
        
        response = self.rpc.call_function(16, request_data)
        if response and len(response) >= 24:
            return_code = struct.unpack('<I', response[20:24])[0]
            if return_code == 0:
                return response[:20]  # Service handle
        
        return None
    
    def _parse_service_entry(self, data: bytes, offset: int) -> Optional[Dict]:
        """Parse ENUM_SERVICE_STATUSW structure"""
        if offset + 36 > len(data):
            return None
        
        # Extract pointers and status
        service_name_ptr = struct.unpack('<I', data[offset:offset+4])[0]
        display_name_ptr = struct.unpack('<I', data[offset+4:offset+8])[0]
        
        # Service status structure (28 bytes)
        status_data = data[offset+8:offset+36]
        service_type = struct.unpack('<I', status_data[0:4])[0]
        current_state = struct.unpack('<I', status_data[4:8])[0]
        controls_accepted = struct.unpack('<I', status_data[8:12])[0]
        win32_exit_code = struct.unpack('<I', status_data[12:16])[0]
        
        # Map service states
        state_map = {
            1: 'STOPPED',
            2: 'START_PENDING',
            3: 'STOP_PENDING',
            4: 'RUNNING',
            5: 'CONTINUE_PENDING',
            6: 'PAUSE_PENDING',
            7: 'PAUSED'
        }
        
        # Map service types
        type_map = {
            0x1: 'KERNEL_DRIVER',
            0x2: 'FILE_SYSTEM_DRIVER',
            0x10: 'WIN32_OWN_PROCESS',
            0x20: 'WIN32_SHARE_PROCESS'
        }
        
        return {
            'service_name': f'Service_{offset}',  # Simplified - would need string parsing
            'display_name': f'Display_{offset}',
            'service_type': type_map.get(service_type, f'UNKNOWN_{service_type}'),
            'current_state': state_map.get(current_state, f'UNKNOWN_{current_state}'),
            'controls_accepted': controls_accepted,
            'win32_exit_code': win32_exit_code
        }
    
    def _parse_service_status(self, data: bytes) -> Dict:
        """Parse SERVICE_STATUS structure"""
        if len(data) < 28:
            return {}
        
        service_type = struct.unpack('<I', data[0:4])[0]
        current_state = struct.unpack('<I', data[4:8])[0]
        controls_accepted = struct.unpack('<I', data[8:12])[0]
        win32_exit_code = struct.unpack('<I', data[12:16])[0]
        service_specific_exit_code = struct.unpack('<I', data[16:20])[0]
        check_point = struct.unpack('<I', data[20:24])[0]
        wait_hint = struct.unpack('<I', data[24:28])[0]
        
        state_map = {
            1: 'STOPPED',
            2: 'START_PENDING',
            3: 'STOP_PENDING',
            4: 'RUNNING',
            5: 'CONTINUE_PENDING',
            6: 'PAUSE_PENDING',
            7: 'PAUSED'
        }
        
        return {
            'service_type': service_type,
            'current_state': state_map.get(current_state, f'UNKNOWN_{current_state}'),
            'controls_accepted': controls_accepted,
            'win32_exit_code': win32_exit_code,
            'service_specific_exit_code': service_specific_exit_code,
            'check_point': check_point,
            'wait_hint': wait_hint
        }
    
    def close_scm(self):
        """Close Service Control Manager handle"""
        if self.scm_handle:
            # RCloseServiceHandle function (opnum 0)
            response = self.rpc.call_function(0, self.scm_handle)
            self.scm_handle = None