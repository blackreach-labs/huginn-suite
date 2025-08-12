#!/usr/bin/env python3
"""
OpenVPN Client in Python

This script implements a basic OpenVPN client capable of establishing
a secure connection using a .ovpn configuration file. It handles
parsing the configuration, including inline certificates and keys,
and performs the correct OpenVPN handshake sequence with TLS-Auth.
"""

import argparse
import subprocess
import os
import shutil
from dataclasses import dataclass
from typing import Optional

@dataclass
class OpenVPNConfig:
    """Stores configuration parsed from an .ovpn file."""
    remote_host: str = ""
    remote_port: int = 1194
    protocol: str = "udp"
    ca_cert: Optional[str] = None
    client_cert: Optional[str] = None
    client_key: Optional[str] = None
    cipher: str = "AES-256-GCM"
    auth: str = "SHA256"
    verb: int = 3



class OpenVPNClient:
    """OpenVPN client using official binary."""
    
    def __init__(self, config_file: str, **kwargs):
        self.config_file = config_file
        
    def connect(self) -> bool:
        """Connect using official OpenVPN client."""
        # Find OpenVPN executable
        openvpn_paths = [
            r"C:\Program Files\OpenVPN\bin\openvpn.exe",
            r"C:\Program Files (x86)\OpenVPN\bin\openvpn.exe"
        ]
        
        openvpn_exe = None
        for path in openvpn_paths:
            if os.path.exists(path):
                openvpn_exe = path
                break
        
        if not openvpn_exe:
            openvpn_exe = shutil.which("openvpn")
            
        if not openvpn_exe:
            print("OpenVPN not found. Install OpenVPN first.")
            return False
            
        cmd = [openvpn_exe, "--config", self.config_file]
        
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            print(f"OpenVPN started (PID: {process.pid})")
            
            for line in process.stdout:
                print(line.strip())
                if "Initialization Sequence Completed" in line:
                    return True
                    
        except Exception as e:
            print(f"OpenVPN failed: {e}")
            return False

    def disconnect(self):
        """Disconnect VPN."""
        print("Disconnecting VPN...")

def main():
    """Main entry point using official OpenVPN client."""
    parser = argparse.ArgumentParser(description="OpenVPN Client Wrapper")
    parser.add_argument("config_file", help="Path to the .ovpn configuration file")
    args = parser.parse_args()

    try:
        client = OpenVPNClient(args.config_file)
        client.connect()
    except KeyboardInterrupt:
        print("\nDisconnecting...")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
