# app/core/vpn_manager.py
import subprocess
import os
import time
import threading
import sys
import json
import ctypes
import shutil
from typing import Dict, Optional, List
from PyQt6.QtCore import QObject, pyqtSignal
from app.core.logger import logger

# Import the OpenVPN implementation
from app.core.openvpn_client import OpenVPNClient
from app.core.openvpn_ovpn_parser import OVPNConfigParser


def _is_admin() -> bool:
    """Check if the current process has administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


class VPNManager(QObject):
    """VPN connection management for secure scanning"""
    
    connection_status_changed = pyqtSignal(str, str)  # status, message
    
    def __init__(self):
        super().__init__()
        self.state_file = os.path.join("resources", "config", "vpn_state.json")
        self.current_connection = None
        self.openvpn_process = None
        self.openvpn_client = None
        self.connection_thread = None
        self.is_connected = False
        self._load_state()
        
    def connect_openvpn(self, config_file: str, username: str = "", password: str = "") -> Dict:
        """Connect using OpenVPN config file.
        
        OpenVPN requires administrator privileges to create TUN/TAP adapters and
        modify routing tables. This method handles that by:
        1. Checking if the OpenVPN Interactive Service is running (allows non-admin usage)
        2. If not, launching openvpn.exe with elevation via the interactive service pipe
        
        The key insight: openvpn.exe on Windows automatically communicates with the
        OpenVPNServiceInteractive via a named pipe for privileged operations. As long
        as that service is running, openvpn.exe does NOT need to run as admin itself.
        """
        try:
            if not os.path.exists(config_file):
                return {"success": False, "error": "Config file not found"}

            # Use specific OpenVPN executable path
            openvpn_exe = r"C:\Program Files\OpenVPN\bin\openvpn.exe"
            if not os.path.exists(openvpn_exe):
                return {"success": False, "error": "OpenVPN not found at expected location"}

            # Disconnect any existing connection first (releases TAP adapter)
            self.disconnect()

            # Ensure the interactive service is running - this is what allows
            # non-admin openvpn.exe to create adapters and routes
            if not self._ensure_interactive_service():
                logger.warning("OpenVPN Interactive Service not available")
                if not _is_admin():
                    return {
                        "success": False, 
                        "error": "OpenVPN Interactive Service not running and app is not admin. "
                                 "Start the service or run Huginn as Administrator."
                    }

            # Write log to a temp file. OpenVPN flushes file output immediately
            # (unlike stdout which gets block-buffered when piped to a non-TTY).
            import tempfile
            self._log_file = os.path.join(tempfile.gettempdir(), "huginn_openvpn.log")

            cmd = [
                openvpn_exe, 
                "--config", config_file, 
                "--verb", "3",
                "--log", self._log_file,  # --log truncates file first
            ]

            self.openvpn_process = subprocess.Popen(
                cmd, 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL, 
                stdin=subprocess.DEVNULL,
            )

            self.current_connection = {
                "type": "openvpn",
                "config": config_file,
                "username": username,
            }

            # Monitor stdout for connection status
            self.connection_thread = threading.Thread(
                target=self._monitor_openvpn,
                daemon=True
            )
            self.connection_thread.start()

            self.connection_status_changed.emit("connecting", "Establishing VPN connection...")
            logger.info(f"OpenVPN connection started with config: {config_file}")
            self._save_state()

            return {"success": True, "message": "VPN connection initiated"}

        except Exception as e:
            logger.error(f"OpenVPN connection failed: {e}")
            return {"success": False, "error": str(e)}

    def _ensure_interactive_service(self) -> bool:
        """Ensure the OpenVPN Interactive Service is running.
        
        This service (OpenVPNServiceInteractive) runs as SYSTEM and handles
        privileged operations for non-admin openvpn.exe instances via named pipe.
        """
        try:
            result = subprocess.run(
                ["sc", "query", "OpenVPNServiceInteractive"],
                capture_output=True, text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            if "RUNNING" in result.stdout:
                return True
            
            # Try to start it (may fail without admin, but worth trying)
            logger.info("Attempting to start OpenVPN Interactive Service...")
            subprocess.run(
                ["sc", "start", "OpenVPNServiceInteractive"],
                capture_output=True, text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            time.sleep(2)
            
            # Check again
            result = subprocess.run(
                ["sc", "query", "OpenVPNServiceInteractive"],
                capture_output=True, text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            return "RUNNING" in result.stdout
            
        except Exception as e:
            logger.error(f"Service check failed: {e}")
            return False

    def _monitor_openvpn(self):
        """Monitor OpenVPN by tailing its log file for connection state changes."""
        try:
            if not self.openvpn_process:
                return

            # Tail the log file for real-time updates
            log_file = self._log_file
            last_pos = 0
            
            while self.openvpn_process is not None and self.openvpn_process.poll() is None:
                try:
                    with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
                        f.seek(last_pos)
                        new_content = f.read()
                        last_pos = f.tell()
                    
                    if new_content:
                        for line in new_content.splitlines():
                            line = line.strip()
                            if not line:
                                continue
                            self._process_openvpn_line(line)
                    else:
                        time.sleep(0.5)
                        
                except FileNotFoundError:
                    time.sleep(0.5)
                except Exception as e:
                    logger.debug(f"Log read error: {e}")
                    time.sleep(0.5)

            # Process ended or was disconnected - read any remaining log content
            if self.openvpn_process is None:
                return  # Disconnected externally, don't emit anything
            
            time.sleep(0.5)
            try:
                with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
                    f.seek(last_pos)
                    remaining = f.read()
                if remaining:
                    for line in remaining.splitlines():
                        line = line.strip()
                        if line:
                            self._process_openvpn_line(line)
            except Exception:
                pass

        except Exception as e:
            logger.error(f"OpenVPN monitor error: {e}")
            self.connection_status_changed.emit("error", f"Monitor error: {str(e)}")
        finally:
            if self.is_connected:
                self.is_connected = False
                self.connection_status_changed.emit("disconnected", "VPN connection terminated")
                self._save_state()

    def _process_openvpn_line(self, line: str):
        """Process a single line of OpenVPN log output."""
        logger.debug(f"OpenVPN: {line}")
        
        # Successful connection
        if "Initialization Sequence Completed" in line:
            self.is_connected = True
            self.connection_status_changed.emit("connected", "VPN connection established")
            self._save_state()
        
        # Authentication failure
        elif "AUTH_FAILED" in line:
            self.connection_status_changed.emit("error", "Authentication failed")
        
        # TLS errors (but not normal TLS info messages)
        elif "TLS Error" in line or "TLS handshake failed" in line:
            self.connection_status_changed.emit("error", f"TLS Error: {line}")
        
        # Progress updates
        elif "Peer Connection Initiated" in line:
            self.connection_status_changed.emit("connecting", "Peer connection initiated...")
        elif "TLS: Initial packet" in line:
            self.connection_status_changed.emit("connecting", "TLS handshake in progress...")
        elif "SENT CONTROL" in line and "PUSH_REQUEST" in line:
            self.connection_status_changed.emit("connecting", "Requesting configuration...")
        elif "OPTIONS IMPORT" in line:
            self.connection_status_changed.emit("connecting", "Importing options...")
        elif ("open_tun" in line) or ("TAP-Windows" in line and "opened" in line):
            self.connection_status_changed.emit("connecting", "Opening TUN/TAP adapter...")
        elif "Route addition" in line and "succeeded" in line:
            self.connection_status_changed.emit("connecting", "Adding routes...")
        elif "TEST ROUTES" in line and "succeeded" in line:
            self.connection_status_changed.emit("connecting", "Routes verified...")
        
        # Fatal error conditions
        elif "All TAP-Windows adapters on this system are currently in use" in line:
            self.connection_status_changed.emit(
                "error",
                "No available TAP adapter - close other VPN connections first"
            )
        elif "PROCESS_EXIT" in line:
            pass  # Will be handled by process poll

    def connect_manual(self, server: str, port: int, protocol: str, username: str, password: str) -> Dict:
        """Connect using manual configuration"""
        try:
            # Create temporary config file
            config_content = f"""
client
dev tun
proto {protocol.lower()}
remote {server} {port}
resolv-retry infinite
nobind
persist-key
persist-tun
auth-user-pass
verb 3
"""
            
            temp_config = "temp_vpn_config.ovpn"
            with open(temp_config, 'w') as f:
                f.write(config_content)
            
            return self.connect_openvpn(temp_config, username, password)
            
        except Exception as e:
            logger.error(f"Manual VPN connection failed: {e}")
            return {"success": False, "error": str(e)}
    
    def disconnect(self) -> Dict:
        """Disconnect VPN"""
        try:
            if self.openvpn_process:
                if self.openvpn_process.poll() is None:
                    self.openvpn_process.terminate()
                    try:
                        self.openvpn_process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        self.openvpn_process.kill()
                        self.openvpn_process.wait(timeout=5)
                self.openvpn_process = None
            
            # Also try to kill any orphaned openvpn processes via taskkill
            # (handles cases where our process reference was lost)
            try:
                subprocess.run(
                    ["taskkill", "/F", "/IM", "openvpn.exe"],
                    capture_output=True, timeout=5,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
            except Exception:
                pass
            
            self.is_connected = False
            self.current_connection = None
            
            # Clean up temp files
            for temp_file in ["temp_auth.txt", "temp_vpn_config.ovpn"]:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            if hasattr(self, '_log_file') and os.path.exists(self._log_file):
                try:
                    os.remove(self._log_file)
                except Exception:
                    pass
            
            self.connection_status_changed.emit("disconnected", "VPN disconnected")
            logger.info("VPN connection terminated")
            self._save_state()
            
            return {"success": True, "message": "VPN disconnected"}
            
        except Exception as e:
            logger.error(f"VPN disconnect failed: {e}")
            return {"success": False, "error": str(e)}
    
    def get_status(self) -> Dict:
        """Get current VPN status"""
        process_running = self.openvpn_process and self.openvpn_process.poll() is None
            
        return {
            "connected": self.is_connected,
            "connection": self.current_connection,
            "process_running": process_running
        }
    
    def test_connectivity(self, target: str = "8.8.8.8") -> Dict:
        """Test connectivity through VPN"""
        try:
            result = subprocess.run(
                ["ping", "-n", "1", target],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            success = result.returncode == 0
            return {
                "success": success,
                "latency": self._extract_latency(result.stdout) if success else None,
                "output": result.stdout
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _extract_latency(self, ping_output: str) -> Optional[int]:
        """Extract latency from ping output"""
        import re
        match = re.search(r'time[<=](\d+)ms', ping_output)
        return int(match.group(1)) if match else None
    
    def _find_openvpn_executable(self) -> Optional[str]:
        """Find OpenVPN executable on system"""
        # Common OpenVPN installation paths on Windows (prioritize CLI version)
        common_paths = [
            r"C:\Program Files\OpenVPN\bin\openvpn.exe",
            r"C:\Program Files (x86)\OpenVPN\bin\openvpn.exe",
            r"C:\OpenVPN\bin\openvpn.exe",
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                return path
        
        exe_path = shutil.which("openvpn")
        if exe_path:
            return exe_path
        
        return None
    
    def _save_state(self):
        """Save VPN state to file"""
        try:
            state = {
                "is_connected": self.is_connected,
                "current_connection": self.current_connection,
                "process_pid": self.openvpn_process.pid if self.openvpn_process else None
            }
            os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
            with open(self.state_file, 'w') as f:
                json.dump(state, f)
        except Exception as e:
            logger.error(f"Failed to save VPN state: {e}")
    
    def _load_state(self):
        """Load VPN state from file"""
        try:
            if os.path.exists(self.state_file):
                with open(self.state_file, 'r') as f:
                    state = json.load(f)
                
                self.is_connected = state.get("is_connected", False)
                self.current_connection = state.get("current_connection")
                
                # Check if process is still running
                if self.is_connected and state.get("process_pid"):
                    try:
                        import psutil
                        if psutil.pid_exists(state["process_pid"]):
                            logger.info("Restored VPN connection state")
                        else:
                            self.is_connected = False
                            self.current_connection = None
                            self._save_state()
                    except ImportError:
                        self.is_connected = False
                        self.current_connection = None
                        self._save_state()
                        
        except Exception as e:
            logger.error(f"Failed to load VPN state: {e}")
            self.is_connected = False
            self.current_connection = None

# Global VPN manager instance
vpn_manager = VPNManager()
