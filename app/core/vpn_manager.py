# app/core/vpn_manager.py
import subprocess
import os
import time
import threading
import sys
import json
from typing import Dict, Optional, List
from PyQt6.QtCore import QObject, pyqtSignal
from app.core.logger import logger

# Import the OpenVPN implementation
from app.core.openvpn_client import OpenVPNClient
from app.core.openvpn_ovpn_parser import OVPNConfigParser

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
        """Connect using OpenVPN config file with official OpenVPN client"""
        try:
            if not os.path.exists(config_file):
                return {"success": False, "error": "Config file not found"}

            # Use specific OpenVPN executable path
            openvpn_exe = r"C:\Program Files\OpenVPN\bin\openvpn.exe"
            if not os.path.exists(openvpn_exe):
                return {"success": False, "error": "OpenVPN not found at expected location"}

            # Start OpenVPN process
            cmd = [openvpn_exe, "--config", config_file]
            self.openvpn_process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT, 
                text=True
            )

            self.current_connection = {
                "type": "openvpn",
                "config": config_file,
                "username": username
            }

            # Start monitoring thread
            self.connection_thread = threading.Thread(target=self._monitor_openvpn)
            self.connection_thread.daemon = True
            self.connection_thread.start()

            self.connection_status_changed.emit("connecting", "Establishing VPN connection...")
            logger.info(f"OpenVPN connection started with config: {config_file}")
            self._save_state()

            return {"success": True, "message": "VPN connection initiated"}

        except Exception as e:
            logger.error(f"OpenVPN connection failed: {e}")
            return {"success": False, "error": str(e)}

    
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
                self.openvpn_process.terminate()
                self.openvpn_process.wait(timeout=10)
                self.openvpn_process = None
            
            self.is_connected = False
            self.current_connection = None
            
            # Clean up temp files
            for temp_file in ["temp_auth.txt", "temp_vpn_config.ovpn"]:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            
            self.connection_status_changed.emit("disconnected", "VPN disconnected")
            logger.info("VPN connection terminated")
            self._save_state()
            
            return {"success": True, "message": "VPN disconnected"}
            
        except Exception as e:
            logger.error(f"VPN disconnect failed: {e}")
            return {"success": False, "error": str(e)}
    
    def _monitor_openvpn(self):
        """Monitor OpenVPN process output"""
        try:
            for line in self.openvpn_process.stdout:
                line = line.strip()
                if "Initialization Sequence Completed" in line:
                    self.is_connected = True
                    self.connection_status_changed.emit("connected", "VPN connection established")
                    self._save_state()
                elif "AUTH_FAILED" in line or "TLS Error" in line:
                    self.connection_status_changed.emit("error", "Authentication failed")
                    break
                    
            # Process ended
            self.openvpn_process.wait()
                
        except Exception as e:
            self.connection_status_changed.emit("error", f"Connection error: {str(e)}")
        finally:
            self.is_connected = False
            self.connection_status_changed.emit("disconnected", "VPN connection terminated")
            self._save_state()
    

    
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
        import shutil
        
        # Common OpenVPN installation paths on Windows (prioritize CLI version)
        common_paths = [
            r"C:\Program Files\OpenVPN\bin\openvpn.exe",
            r"C:\Program Files (x86)\OpenVPN\bin\openvpn.exe",
            r"C:\OpenVPN\bin\openvpn.exe",
            # GUI versions (less preferred)
            r"C:\Program Files\OpenVPN Connect\OpenVPNConnect.exe",
            r"C:\Program Files (x86)\OpenVPN Connect\OpenVPNConnect.exe"
        ]
        
        # Check common installation paths first
        for path in common_paths:
            if os.path.exists(path):
                return path
        
        # Check system PATH for both executables
        for exe_name in ['openvpn', 'OpenVPNConnect']:
            exe_path = shutil.which(exe_name)
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
                            # Process still exists, try to reconnect to it
                            logger.info("Restored VPN connection state")
                        else:
                            # Process died, reset state
                            self.is_connected = False
                            self.current_connection = None
                            self._save_state()
                    except ImportError:
                        # psutil not available, assume disconnected for safety
                        self.is_connected = False
                        self.current_connection = None
                        self._save_state()
                        
        except Exception as e:
            logger.error(f"Failed to load VPN state: {e}")
            self.is_connected = False
            self.current_connection = None

# Global VPN manager instance
vpn_manager = VPNManager()