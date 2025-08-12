# Native RPC Scanner Architecture

## Overview

The native RPC scanner implements a complete DCE/RPC-over-SMB client in pure Python, eliminating dependencies on external tools like `netstat`, `reg query`, and `sc query`. It provides authenticated remote enumeration of Windows systems through direct RPC communication.

## Architecture Components

### 1. SMB Client (`smb_client.py`)
**Purpose**: Handles SMB2/3 protocol communication and NTLM authentication

**Key Features**:
- SMB2/3 protocol negotiation
- NTLM Type 1/2/3 authentication flow
- Support for password and NTLM hash authentication
- IPC$ share connection for RPC transport
- Proper session management and cleanup

**Binary Structures Implemented**:
- SMB2 Header (64 bytes)
- NTLM Type 1/3 messages
- SMB2 Session Setup requests/responses
- SMB2 Tree Connect for IPC$ access

### 2. RPC Transport (`rpc_transport.py`)
**Purpose**: Implements DCE/RPC protocol over named pipes

**Key Features**:
- DCE/RPC bind phase implementation
- Named pipe communication (`\pipe\svcctl`, `\pipe\winreg`)
- NDR (Network Data Representation) encoding
- RPC request/response handling
- Context management for multiple interfaces

**Binary Structures Implemented**:
- DCE/RPC Header (16 bytes)
- RPC Bind Request/Response
- RPC Request/Response packets
- Presentation Context structures

### 3. Service Control Manager Client (`svcctl_client.py`)
**Purpose**: Enumerates Windows services via RPC

**Key RPC Functions Implemented**:
- `ROpenSCManagerW` (opnum 15) - Open SCM handle
- `REnumServicesStatusW` (opnum 14) - Enumerate services
- `RQueryServiceStatus` (opnum 6) - Query service status
- `ROpenServiceW` (opnum 16) - Open service handle
- `RCloseServiceHandle` (opnum 0) - Close handles

**Data Structures**:
- `ENUM_SERVICE_STATUSW` - Service enumeration structure
- `SERVICE_STATUS` - Service status information

### 4. Windows Registry Client (`winreg_client.py`)
**Purpose**: Provides remote registry access via RPC

**Key RPC Functions Implemented**:
- `OpenLocalMachine` (opnum 2) - Open HKLM
- `OpenCurrentUser` (opnum 1) - Open HKCU
- `BaseRegOpenKey` (opnum 15) - Open registry key
- `BaseRegQueryValue` (opnum 17) - Query registry value
- `BaseRegEnumKey` (opnum 9) - Enumerate subkeys
- `BaseRegEnumValue` (opnum 10) - Enumerate values
- `BaseRegCloseKey` (opnum 5) - Close key handle

**Registry Types Supported**:
- REG_SZ (String)
- REG_DWORD (32-bit integer)
- REG_QWORD (64-bit integer)
- REG_BINARY (Binary data)
- REG_MULTI_SZ (Multi-string)

### 5. Main Orchestrator (`rpc_enum.py`)
**Purpose**: Coordinates all components for complete enumeration

**Capabilities**:
- Authenticated connection establishment
- Service enumeration with status information
- Registry access for OS information
- RPC endpoint discovery
- Error handling and cleanup

## Protocol Implementation Details

### SMB Authentication Flow
1. **TCP Connection**: Connect to port 445
2. **Protocol Negotiation**: SMB2/3 dialect selection
3. **Session Setup**: NTLM authentication (Type 1/2/3)
4. **Tree Connect**: Connect to IPC$ share
5. **Named Pipe Access**: Open RPC pipes

### NTLM Authentication
```
Type 1 (Negotiate) → Server
Type 2 (Challenge) ← Server  
Type 3 (Authenticate) → Server
```

**NTLM Hash Calculation**:
- Password → UTF-16LE → MD4 → NT Hash
- NT Hash + Challenge → DES encryption → Response

### DCE/RPC Communication
```
Client                    Server
  |                         |
  |--- RPC Bind Request --→ |
  |←-- RPC Bind Response ---|
  |                         |
  |--- RPC Call Request --→ |
  |←-- RPC Call Response ---|
```

**RPC Header Structure** (16 bytes):
```c
struct rpc_hdr {
    uint8_t  rpc_vers;      // RPC version (5)
    uint8_t  rpc_vers_minor; // Minor version (0)
    uint8_t  ptype;         // Packet type
    uint8_t  flags;         // Packet flags
    uint32_t drep;          // Data representation
    uint16_t frag_len;      // Fragment length
    uint16_t auth_len;      // Authentication length
    uint32_t call_id;       // Call identifier
};
```

## Security Considerations

### Authentication
- Supports both password and NTLM hash authentication
- Implements proper NTLM challenge-response
- Secure session establishment over SMB

### Network Security
- All communication encrypted via SMB
- Proper credential handling (no plaintext storage)
- Session cleanup and handle management

### Error Handling
- Graceful failure on authentication errors
- Timeout handling for network operations
- Proper resource cleanup on exceptions

## Usage Examples

### Basic Service Enumeration
```python
from app.core.rpc_enum import RPCEnumerator

enumerator = RPCEnumerator()
if enumerator.connect("192.168.1.100", "DOMAIN", "user", "password"):
    services = enumerator.enumerate_services()
    for service in services:
        print(f"{service['service_name']}: {service['current_state']}")
```

### Registry Access
```python
registry_data = enumerator.enumerate_registry()
os_info = registry_data.get('os_info', {})
print(f"OS: {os_info.get('ProductName', 'Unknown')}")
```

### Complete Enumeration
```python
from app.core.rpc_enum import enumerate_target

results = enumerate_target("192.168.1.100", "DOMAIN", "user", "password")
print(f"Services: {len(results['services'])}")
print(f"Registry keys: {len(results['registry'])}")
```

## Integration with Huggin Framework

The RPC scanner integrates seamlessly with the existing Huggin framework:

1. **Worker Integration**: Uses PyQt6 signals for progress updates
2. **Result Storage**: Compatible with existing result structures
3. **UI Integration**: Provides formatted output for the GUI
4. **Fallback Support**: Falls back to legacy methods if native fails

## Performance Optimizations

- **Connection Reuse**: Single SMB session for multiple RPC calls
- **Efficient Parsing**: Minimal memory allocation for large datasets
- **Timeout Management**: Configurable timeouts for network operations
- **Error Recovery**: Graceful handling of partial failures

## Limitations and Future Enhancements

### Current Limitations
- Limited to SMB2/3 (no SMB1 support)
- Basic endpoint mapper implementation
- Simplified NDR encoding (sufficient for current use cases)

### Planned Enhancements
- Full endpoint mapper client (port 135)
- Additional RPC interfaces (SAMR, LSARPC)
- WebSocket and HTTP RPC transport
- Advanced NDR encoding support
- Kerberos authentication support

## Testing and Validation

Use the provided test script:
```bash
python test_rpc.py 192.168.1.100 DOMAIN username password
```

The implementation has been tested against:
- Windows Server 2019/2022
- Windows 10/11 workstations
- Domain and workgroup environments
- Various authentication scenarios

## Dependencies

- **pycryptodome**: For DES encryption in NTLM authentication
- **Standard Library**: socket, struct, hashlib, hmac, uuid

No external security tools or libraries required.