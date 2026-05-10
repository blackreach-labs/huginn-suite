# app/core/rpc_service_impersonation.py
"""
RPC Service Impersonation
Create fake RPC services to capture authentication and perform attacks
"""
import socket
import threading
import struct
from typing import Dict, List, Optional
from .rpc_protocol import RPCPacket, RPCClient
import logging

class FakeRPCService:
    """Fake RPC service for impersonation attacks"""
    
    def __init__(self, interface_uuid: str, version: tuple, port: int = 135):
        self.interface_uuid = interface_uuid
        self.version = version
        self.port = port
        self.server_socket = None
        self.running = False
        self.captured_auth = []
        self.client_connections = []
    
    def start_service(self) -> bool:
        """Start fake RPC service"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(10)
            
            self.running = True
            print(f"[FAKE-RPC] Started fake RPC service on port {self.port}")
            print(f"[FAKE-RPC] Interface: {self.interface_uuid}")
            
            # Start accepting connections
            accept_thread = threading.Thread(target=self._accept_connections)
            accept_thread.daemon = True
            accept_thread.start()
            
            return True
            
        except Exception as e:
            print(f"[FAKE-RPC] Failed to start service: {e}")
            return False
    
    def stop_service(self):
        """Stop fake RPC service"""
        self.running = False
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception as _exc:
                pass
                logging.debug("Suppressed exception", exc_info=True)
        
        # Close client connections
        for conn in self.client_connections:
            try:
                conn.close()
            except Exception as _exc:
                pass
                logging.debug("Suppressed exception", exc_info=True)
        
        self.client_connections.clear()
        print(f"[FAKE-RPC] Fake RPC service stopped")
    
    def _accept_connections(self):
        """Accept incoming RPC connections"""
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                print(f"[FAKE-RPC] Incoming connection from {addr[0]}")
                
                self.client_connections.append(client_socket)
                
                # Handle client in separate thread
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, addr)
                )
                client_thread.daemon = True
                client_thread.start()
                
            except Exception as e:
                if self.running:
                    print(f"[FAKE-RPC] Accept error: {e}")
                break
    
    def _handle_client(self, client_socket, addr):
        """Handle individual RPC client"""
        try:
            while self.running:
                data = client_socket.recv(4096)
                if not data:
                    break
                
                # Parse RPC packet
                try:
                    packet = RPCPacket.unpack(data)
                    response = self._process_rpc_packet(packet, addr[0])
                    
                    if response:
                        client_socket.send(response)
                
                except Exception as e:
                    print(f"[FAKE-RPC] Packet processing error: {e}")
                    break
        
        except Exception as e:
            print(f"[FAKE-RPC] Client handling error: {e}")
        finally:
            try:
                client_socket.close()
                if client_socket in self.client_connections:
                    self.client_connections.remove(client_socket)
            except Exception as _exc:
                pass
                logging.debug("Suppressed exception", exc_info=True)
    
    def _process_rpc_packet(self, packet: RPCPacket, client_ip: str) -> Optional[bytes]:
        """Process incoming RPC packet"""
        if packet.packet_type == 11:  # Bind request
            return self._handle_bind_request(packet, client_ip)
        elif packet.packet_type == 0:  # Request
            return self._handle_rpc_request(packet, client_ip)
        elif packet.packet_type == 14:  # Auth3
            return self._handle_auth3(packet, client_ip)
        
        return None
    
    def _handle_bind_request(self, packet: RPCPacket, client_ip: str) -> bytes:
        """Handle RPC bind request"""
        print(f"[FAKE-RPC] Bind request from {client_ip}")
        
        # Extract authentication data if present
        if packet.auth_length > 0:
            auth_data = packet.data[-packet.auth_length:]
            self._capture_auth_data(auth_data, client_ip, 'bind')
        
        # Create bind response
        response = RPCPacket()
        response.packet_type = 12  # Bind response
        response.call_id = packet.call_id
        response.flags = 0x03  # First and last fragment
        
        # Build bind response data
        bind_resp_data = self._build_bind_response()
        response.data = bind_resp_data
        response.frag_length = 16 + len(bind_resp_data)
        
        return response.pack()
    
    def _handle_rpc_request(self, packet: RPCPacket, client_ip: str) -> bytes:
        """Handle RPC request"""
        print(f"[FAKE-RPC] RPC request from {client_ip}")
        
        # Extract operation number
        if len(packet.data) >= 4:
            opnum = struct.unpack('<H', packet.data[:2])[0]
            print(f"[FAKE-RPC] Operation: {opnum}")
        
        # Extract authentication data
        if packet.auth_length > 0:
            auth_data = packet.data[-packet.auth_length:]
            self._capture_auth_data(auth_data, client_ip, 'request')
        
        # Create response
        response = RPCPacket()
        response.packet_type = 2  # Response
        response.call_id = packet.call_id
        response.flags = 0x03
        
        # Build fake response data
        resp_data = self._build_fake_response(packet.data)
        response.data = resp_data
        response.frag_length = 16 + len(resp_data)
        
        return response.pack()
    
    def _handle_auth3(self, packet: RPCPacket, client_ip: str) -> Optional[bytes]:
        """Handle Auth3 packet"""
        print(f"[FAKE-RPC] Auth3 from {client_ip}")
        
        # Capture authentication data
        if packet.auth_length > 0:
            auth_data = packet.data[-packet.auth_length:]
            self._capture_auth_data(auth_data, client_ip, 'auth3')
        
        # Auth3 doesn't require response
        return None
    
    def _capture_auth_data(self, auth_data: bytes, client_ip: str, packet_type: str):
        """Capture authentication data"""
        auth_info = {
            'client_ip': client_ip,
            'packet_type': packet_type,
            'auth_data': auth_data.hex(),
            'timestamp': self._get_timestamp()
        }
        
        self.captured_auth.append(auth_info)
        print(f"[FAKE-RPC] Captured auth data from {client_ip} ({packet_type})")
    
    def _build_bind_response(self) -> bytes:
        """Build bind response data"""
        # Simplified bind response
        resp_data = b'\x05\x00'  # Max transmit/receive frag
        resp_data += b'\x00\x00'  # Assoc group
        resp_data += b'\x01'      # Num results
        resp_data += b'\x00\x00\x00'  # Reserved
        resp_data += b'\x00\x00'  # Result
        resp_data += b'\x00\x00'  # Reason
        
        # Add transfer syntax
        import uuid
        resp_data += uuid.UUID('8a885d04-1ceb-11c9-9fe8-08002b104860').bytes_le
        resp_data += b'\x02\x00\x00\x00'  # Version
        
        return resp_data
    
    def _build_fake_response(self, request_data: bytes) -> bytes:
        """Build fake response data"""
        # Return success response
        return b'\x00\x00\x00\x00'  # Success
    
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def get_captured_auth(self) -> List[Dict]:
        """Get captured authentication data"""
        return self.captured_auth

class RPCHoneypot:
    """RPC honeypot for detecting attacks"""
    
    def __init__(self):
        self.services = {}
        self.attack_log = []
        self.running = False
    
    def add_honeypot_service(self, name: str, interface_uuid: str, version: tuple, port: int):
        """Add honeypot RPC service"""
        service = FakeRPCService(interface_uuid, version, port)
        self.services[name] = service
        print(f"[HONEYPOT] Added service: {name} on port {port}")
    
    def start_honeypot(self) -> bool:
        """Start all honeypot services"""
        try:
            self.running = True
            
            for name, service in self.services.items():
                if service.start_service():
                    print(f"[HONEYPOT] Started {name}")
                else:
                    print(f"[HONEYPOT] Failed to start {name}")
            
            # Start monitoring thread
            monitor_thread = threading.Thread(target=self._monitor_attacks)
            monitor_thread.daemon = True
            monitor_thread.start()
            
            return True
            
        except Exception as e:
            print(f"[HONEYPOT] Failed to start: {e}")
            return False
    
    def stop_honeypot(self):
        """Stop all honeypot services"""
        self.running = False
        
        for name, service in self.services.items():
            service.stop_service()
            print(f"[HONEYPOT] Stopped {name}")
        
        self.services.clear()
    
    def _monitor_attacks(self):
        """Monitor for attacks"""
        while self.running:
            try:
                # Check for new authentication captures
                for name, service in self.services.items():
                    auth_data = service.get_captured_auth()
                    
                    for auth in auth_data:
                        if auth not in self.attack_log:
                            self.attack_log.append(auth)
                            self._log_attack(name, auth)
                
                # Sleep before next check
                import time
                time.sleep(5)
                
            except Exception as e:
                print(f"[HONEYPOT] Monitor error: {e}")
    
    def _log_attack(self, service_name: str, auth_data: Dict):
        """Log detected attack"""
        print(f"[HONEYPOT] ATTACK DETECTED on {service_name}")
        print(f"[HONEYPOT] Source: {auth_data['client_ip']}")
        print(f"[HONEYPOT] Type: {auth_data['packet_type']}")
        print(f"[HONEYPOT] Time: {auth_data['timestamp']}")
    
    def get_attack_summary(self) -> Dict:
        """Get attack summary"""
        summary = {
            'total_attacks': len(self.attack_log),
            'unique_ips': len(set(attack['client_ip'] for attack in self.attack_log)),
            'attack_types': {},
            'recent_attacks': self.attack_log[-10:]  # Last 10 attacks
        }
        
        # Count attack types
        for attack in self.attack_log:
            attack_type = attack['packet_type']
            summary['attack_types'][attack_type] = summary['attack_types'].get(attack_type, 0) + 1
        
        return summary

class RPCServiceDiscovery:
    """Advanced RPC service discovery"""
    
    def __init__(self, target: str):
        self.target = target
        self.discovered_services = []
    
    def discover_all_services(self) -> List[Dict]:
        """Discover all RPC services on target"""
        print(f"[DISCOVERY] Starting comprehensive RPC discovery on {self.target}")
        
        # Common RPC interfaces to check
        common_interfaces = [
            ("spoolss", "12345678-1234-abcd-ef00-0123456789ab", (1, 0)),
            ("samr", "12345778-1234-abcd-ef00-0123456789ac", (1, 0)),
            ("lsarpc", "12345778-1234-abcd-ef00-0123456789ac", (0, 0)),
            ("winreg", "338cd001-2244-31f1-aaaa-900038001003", (1, 0)),
            ("svcctl", "367abb81-9844-35f1-ad32-98f038001003", (2, 0)),
            ("netlogon", "12345678-1234-abcd-ef00-01234567cffb", (1, 0)),
            ("wkssvc", "6bffd098-a112-3610-9833-46c3f87e345a", (1, 0)),
            ("srvsvc", "4b324fc8-1670-01d3-1278-5a47bf6ee188", (3, 0)),
            ("eventlog", "82273fdc-e32a-18c3-3f78-827929dc23ea", (0, 0)),
            ("atsvc", "1ff70682-0a51-30e8-076d-740be8cee98b", (1, 0))
        ]
        
        for name, uuid, version in common_interfaces:
            result = self._test_interface(name, uuid, version)
            if result:
                self.discovered_services.append(result)
            import time
            time.sleep(0.2)  # Delay between interface tests
        
        # Try endpoint mapper enumeration
        epm_services = self._enumerate_endpoint_mapper()
        self.discovered_services.extend(epm_services)
        
        print(f"[DISCOVERY] Discovered {len(self.discovered_services)} RPC services")
        return self.discovered_services
    
    def _test_interface(self, name: str, uuid: str, version: tuple) -> Optional[Dict]:
        """Test if RPC interface is available"""
        try:
            # Skip actual RPC binding test - just return basic info
            # The real enumeration happens via the main RPC scanner
            print(f"[DISCOVERY] Checking {name} interface")
            
            service_info = {
                'name': name,
                'uuid': uuid,
                'version': version,
                'port': 135,
                'accessible': False  # Will be determined by main scanner
            }
            
            return service_info
            
        except Exception:
            return None
    
    def _enumerate_endpoint_mapper(self) -> List[Dict]:
        """Enumerate services via endpoint mapper"""
        services = []
        
        try:
            from .rpc_endpoint_mapper import RPCEndpointMapper
            
            epm = RPCEndpointMapper(self.target)
            endpoints = epm.enumerate_all_endpoints()
            
            for endpoint in endpoints:
                service_info = {
                    'name': endpoint.get('description', 'Unknown'),
                    'uuid': endpoint.get('uuid', 'Unknown'),
                    'version': (1, 0),
                    'port': endpoint.get('port', 135),
                    'protocol': endpoint.get('protocol', 'Unknown'),
                    'accessible': True
                }
                services.append(service_info)
            
        except Exception as e:
            print(f"[DISCOVERY] Endpoint mapper enumeration failed: {e}")
        
        return services
    
    def get_high_value_services(self) -> List[Dict]:
        """Get high-value services for attacks"""
        high_value = ['spoolss', 'samr', 'lsarpc', 'netlogon', 'winreg']
        
        return [
            service for service in self.discovered_services
            if service['name'] in high_value
        ]