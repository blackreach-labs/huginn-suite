# app/core/anonymous_rpc_enum.py
import subprocess
import socket
from typing import List, Dict
from app.core.logger import logger

def enumerate_services_via_rpc(target: str) -> List[Dict]:
    """Enumerate services via SMB named pipe svcctl - the original working method"""
    try:
        from .rpc_transport import RPCTransport
        
        transport = RPCTransport(target)
        transport.debug = True  # Enable debug to see what's happening
        
        # Try to connect and use SMB named pipe for svcctl
        if transport.connect('', '', ''):
            # Try to access svcctl via named pipe
            services = transport.enumerate_services_via_pipe()
            if services:
                return services
            
            transport.disconnect()
    
    except Exception as e:
        print(f"RPC enumeration error: {e}")
    
    return []

def parse_real_service_response(response: bytes) -> List[Dict]:
    """Parse real RPC service enumeration response"""
    services = []
    
    try:
        if len(response) > 32:
            # Basic parsing of service enumeration response
            # This would need proper NDR parsing in a full implementation
            offset = 0
            while offset + 64 < len(response):
                # Look for service name patterns
                try:
                    # Extract service name (simplified)
                    name_start = offset + 32
                    if name_start + 32 < len(response):
                        name_data = response[name_start:name_start+32]
                        # Look for null-terminated strings
                        if b'\x00' in name_data:
                            name = name_data[:name_data.find(b'\x00')].decode('utf-8', errors='ignore')
                            if name and len(name) > 2:
                                services.append({
                                    'name': name,
                                    'display_name': name,
                                    'state': 'RUNNING'
                                })
                except Exception as _exc:
                    pass
                    logger.debug("Suppressed exception", exc_info=True)
                
                offset += 64
                
                if len(services) > 50:  # Prevent infinite loop
                    break
    
    except Exception as _exc:
        pass
        logger.debug("Suppressed exception", exc_info=True)
    
    return services

# Removed old parse_service_response

def enumerate_services_comprehensive(target: str) -> List[Dict]:
    """Try multiple methods to enumerate services - NO MOCK DATA"""
    
    # Method 1: Try our RPC transport
    services = enumerate_services_via_rpc(target)
    if services:
        return services
    
    # Method 2: Try WMI
    try:
        cmd = ['wmic', f'/node:{target}', 'service', 'get', 'name,state,displayname', '/format:csv']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0 and len(result.stdout.split('\n')) > 2:
            services = []
            lines = result.stdout.split('\n')[1:]
            
            for line in lines:
                if line.strip() and ',' in line:
                    parts = line.split(',')
                    if len(parts) >= 4 and parts[2].strip():
                        services.append({
                            'name': parts[2].strip(),
                            'display_name': parts[1].strip(),
                            'state': parts[3].strip()
                        })
            
            return services
    except Exception as _exc:
        pass
        logger.debug("Suppressed exception", exc_info=True)
    
    # Method 3: Try PowerShell
    try:
        cmd = ['powershell', '-Command', f'Get-Service -ComputerName {target} | Select-Object Name,DisplayName,Status | ConvertTo-Csv -NoTypeInformation']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0 and 'Name' in result.stdout:
            services = []
            lines = result.stdout.split('\n')[1:]
            
            for line in lines:
                if line.strip() and ',' in line:
                    parts = [p.strip('"') for p in line.split(',')]
                    if len(parts) >= 3 and parts[0]:
                        services.append({
                            'name': parts[0],
                            'display_name': parts[1],
                            'state': parts[2]
                        })
            
            return services
    except Exception as _exc:
        pass
        logger.debug("Suppressed exception", exc_info=True)
    
    # NO MOCK DATA - return empty if nothing works
    return []