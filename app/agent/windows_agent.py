#!/usr/bin/env python3
"""
Windows Agent - Native service component
Handles privileged operations with attestation and audit logging
"""

import os
import json
import time
import hashlib
import subprocess
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
import uuid
import win32serviceutil
import win32service
import win32event
import servicemanager

class WindowsAgent:
    def __init__(self, config_path: str = "agent_config.json"):
        self.config_path = config_path
        self.config = self._load_config()
        self.audit_db = "agent_audit.db"
        self._init_audit_db()
        self.attestation_required = True
        
    def _load_config(self) -> Dict[str, Any]:
        """Load agent configuration"""
        default_config = {
            "allowed_operations": [
                "collect_eventlogs",
                "collect_processes",
                "collect_screenshots",
                "collect_network_info"
            ],
            "restricted_operations": [
                "modify_firewall",
                "modify_defender",
                "collect_pcap"
            ],
            "audit_retention_days": 90,
            "max_evidence_size_mb": 100
        }
        
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                config = json.load(f)
                default_config.update(config)
        
        return default_config
    
    def _init_audit_db(self):
        """Initialize audit database"""
        conn = sqlite3.connect(self.audit_db)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_logs (
                log_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                operation TEXT NOT NULL,
                user_context TEXT NOT NULL,
                attestation_hash TEXT,
                success BOOLEAN NOT NULL,
                details TEXT NOT NULL,
                evidence_path TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attestations (
                attestation_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                operation TEXT NOT NULL,
                signature_hash TEXT NOT NULL,
                valid_until TEXT NOT NULL,
                used BOOLEAN DEFAULT FALSE
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def verify_attestation(self, operation: str, attestation_data: str) -> bool:
        """Verify signed attestation for privileged operation"""
        if not self.attestation_required:
            return True
        
        try:
            # In production, verify digital signature
            # For now, simple hash verification
            expected_hash = hashlib.sha256(f"{operation}:huggin_agent".encode()).hexdigest()
            provided_hash = hashlib.sha256(attestation_data.encode()).hexdigest()
            
            if expected_hash == provided_hash:
                # Store attestation
                conn = sqlite3.connect(self.audit_db)
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO attestations 
                    (attestation_id, timestamp, operation, signature_hash, valid_until)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    str(uuid.uuid4()),
                    datetime.now().isoformat(),
                    operation,
                    provided_hash,
                    datetime.fromtimestamp(time.time() + 3600).isoformat()  # 1 hour validity
                ))
                conn.commit()
                conn.close()
                return True
                
        except Exception as e:
            self._audit_log(operation, "SYSTEM", None, False, f"Attestation error: {e}")
        
        return False
    
    def collect_eventlogs(self, log_names: List[str], hours_back: int = 24) -> str:
        """Collect Windows Event Logs"""
        operation = "collect_eventlogs"
        
        if operation not in self.config["allowed_operations"]:
            self._audit_log(operation, "SYSTEM", None, False, "Operation not allowed")
            return ""
        
        try:
            output_file = f"eventlogs_{int(time.time())}.json"
            events = []
            
            for log_name in log_names:
                try:
                    # Use PowerShell to collect events
                    ps_command = f'''
                    Get-WinEvent -LogName "{log_name}" -MaxEvents 1000 | 
                    Where-Object {{$_.TimeCreated -gt (Get-Date).AddHours(-{hours_back})}} |
                    Select-Object TimeCreated, Id, LevelDisplayName, Message |
                    ConvertTo-Json
                    '''
                    
                    result = subprocess.run(
                        ["powershell", "-Command", ps_command],
                        capture_output=True,
                        text=True,
                        timeout=60
                    )
                    
                    if result.returncode == 0 and result.stdout:
                        log_events = json.loads(result.stdout)
                        if isinstance(log_events, list):
                            events.extend(log_events)
                        else:
                            events.append(log_events)
                            
                except Exception as e:
                    self._audit_log(operation, "SYSTEM", None, False, f"Error collecting {log_name}: {e}")
            
            # Save to file
            evidence_path = Path("evidence") / output_file
            evidence_path.parent.mkdir(exist_ok=True)
            
            with open(evidence_path, 'w') as f:
                json.dump(events, f, indent=2, default=str)
            
            self._audit_log(operation, "SYSTEM", None, True, f"Collected {len(events)} events", str(evidence_path))
            return str(evidence_path)
            
        except Exception as e:
            self._audit_log(operation, "SYSTEM", None, False, f"Collection failed: {e}")
            return ""
    
    def collect_processes(self) -> str:
        """Collect running processes"""
        operation = "collect_processes"
        
        if operation not in self.config["allowed_operations"]:
            self._audit_log(operation, "SYSTEM", None, False, "Operation not allowed")
            return ""
        
        try:
            ps_command = '''
            Get-Process | Select-Object Name, Id, CPU, WorkingSet, Path, Company |
            ConvertTo-Json
            '''
            
            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                output_file = f"processes_{int(time.time())}.json"
                evidence_path = Path("evidence") / output_file
                evidence_path.parent.mkdir(exist_ok=True)
                
                with open(evidence_path, 'w') as f:
                    f.write(result.stdout)
                
                self._audit_log(operation, "SYSTEM", None, True, "Process list collected", str(evidence_path))
                return str(evidence_path)
            
        except Exception as e:
            self._audit_log(operation, "SYSTEM", None, False, f"Collection failed: {e}")
        
        return ""
    
    def collect_screenshots(self, count: int = 1) -> List[str]:
        """Collect screenshots"""
        operation = "collect_screenshots"
        
        if operation not in self.config["allowed_operations"]:
            self._audit_log(operation, "SYSTEM", None, False, "Operation not allowed")
            return []
        
        screenshots = []
        
        try:
            import PIL.ImageGrab as ImageGrab
            
            for i in range(count):
                screenshot = ImageGrab.grab()
                filename = f"screenshot_{int(time.time())}_{i}.png"
                evidence_path = Path("evidence") / filename
                evidence_path.parent.mkdir(exist_ok=True)
                
                screenshot.save(evidence_path)
                screenshots.append(str(evidence_path))
                
                if count > 1:
                    time.sleep(2)  # Delay between screenshots
            
            self._audit_log(operation, "SYSTEM", None, True, f"Collected {len(screenshots)} screenshots")
            
        except Exception as e:
            self._audit_log(operation, "SYSTEM", None, False, f"Screenshot failed: {e}")
        
        return screenshots
    
    def modify_firewall(self, rule_name: str, action: str, attestation: str) -> bool:
        """Modify Windows Firewall (requires attestation)"""
        operation = "modify_firewall"
        
        if not self.verify_attestation(operation, attestation):
            self._audit_log(operation, "SYSTEM", None, False, "Invalid attestation")
            return False
        
        try:
            if action == "add":
                ps_command = f'''
                New-NetFirewallRule -DisplayName "{rule_name}" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 4444
                '''
            elif action == "remove":
                ps_command = f'''
                Remove-NetFirewallRule -DisplayName "{rule_name}"
                '''
            else:
                raise ValueError(f"Invalid action: {action}")
            
            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            success = result.returncode == 0
            details = f"Firewall rule {action}: {rule_name}"
            if not success:
                details += f" - Error: {result.stderr}"
            
            self._audit_log(operation, "SYSTEM", attestation, success, details)
            return success
            
        except Exception as e:
            self._audit_log(operation, "SYSTEM", attestation, False, f"Firewall modification failed: {e}")
            return False
    
    def modify_defender(self, exclusion_path: str, action: str, attestation: str) -> bool:
        """Modify Windows Defender exclusions (requires attestation)"""
        operation = "modify_defender"
        
        if not self.verify_attestation(operation, attestation):
            self._audit_log(operation, "SYSTEM", None, False, "Invalid attestation")
            return False
        
        try:
            if action == "add":
                ps_command = f'''
                Add-MpPreference -ExclusionPath "{exclusion_path}"
                '''
            elif action == "remove":
                ps_command = f'''
                Remove-MpPreference -ExclusionPath "{exclusion_path}"
                '''
            else:
                raise ValueError(f"Invalid action: {action}")
            
            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            success = result.returncode == 0
            details = f"Defender exclusion {action}: {exclusion_path}"
            if not success:
                details += f" - Error: {result.stderr}"
            
            self._audit_log(operation, "SYSTEM", attestation, success, details)
            return success
            
        except Exception as e:
            self._audit_log(operation, "SYSTEM", attestation, False, f"Defender modification failed: {e}")
            return False
    
    def self_clean(self):
        """Revert all system modifications"""
        operation = "self_clean"
        
        try:
            # Get all successful firewall/defender modifications
            conn = sqlite3.connect(self.audit_db)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT operation, details FROM audit_logs 
                WHERE success = 1 AND operation IN ('modify_firewall', 'modify_defender')
                ORDER BY timestamp DESC
            ''')
            
            modifications = cursor.fetchall()
            conn.close()
            
            reverted = 0
            for op, details in modifications:
                try:
                    if op == "modify_firewall" and "add" in details:
                        # Extract rule name and remove it
                        rule_name = details.split(":")[1].strip()
                        ps_command = f'Remove-NetFirewallRule -DisplayName "{rule_name}"'
                        subprocess.run(["powershell", "-Command", ps_command], timeout=30)
                        reverted += 1
                    
                    elif op == "modify_defender" and "add" in details:
                        # Extract path and remove exclusion
                        exclusion_path = details.split(":")[1].strip()
                        ps_command = f'Remove-MpPreference -ExclusionPath "{exclusion_path}"'
                        subprocess.run(["powershell", "-Command", ps_command], timeout=30)
                        reverted += 1
                        
                except Exception as e:
                    print(f"Failed to revert {details}: {e}")
            
            self._audit_log(operation, "SYSTEM", None, True, f"Reverted {reverted} modifications")
            
        except Exception as e:
            self._audit_log(operation, "SYSTEM", None, False, f"Self-clean failed: {e}")
    
    def _audit_log(self, operation: str, user_context: str, attestation_hash: Optional[str], 
                   success: bool, details: str, evidence_path: Optional[str] = None):
        """Add audit log entry"""
        conn = sqlite3.connect(self.audit_db)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO audit_logs 
            (log_id, timestamp, operation, user_context, attestation_hash, success, details, evidence_path)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            str(uuid.uuid4()),
            datetime.now().isoformat(),
            operation,
            user_context,
            attestation_hash,
            success,
            details,
            evidence_path
        ))
        conn.commit()
        conn.close()
    
    def get_audit_logs(self, limit: int = 100) -> List[Dict]:
        """Get recent audit logs"""
        conn = sqlite3.connect(self.audit_db)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        )
        
        logs = []
        for row in cursor.fetchall():
            logs.append({
                'log_id': row[0],
                'timestamp': row[1],
                'operation': row[2],
                'user_context': row[3],
                'attestation_hash': row[4],
                'success': bool(row[5]),
                'details': row[6],
                'evidence_path': row[7]
            })
        
        conn.close()
        return logs

class HugginAgentService(win32serviceutil.ServiceFramework):
    """Windows Service wrapper for Huggin Agent"""
    
    _svc_name_ = "HugginAgent"
    _svc_display_name_ = "Huggin Security Agent"
    _svc_description_ = "Huggin Security Assessment Agent Service"
    
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.agent = WindowsAgent()
    
    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        # Clean up modifications before stopping
        self.agent.self_clean()
        win32event.SetEvent(self.hWaitStop)
    
    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        
        # Service main loop
        while True:
            rc = win32event.WaitForSingleObject(self.hWaitStop, 5000)
            if rc == win32event.WAIT_OBJECT_0:
                break
            
            # Perform periodic tasks
            # In production, this would handle RPC/REST API requests

if __name__ == '__main__':
    if len(sys.argv) == 1:
        # Run as standalone agent
        agent = WindowsAgent()
        
        # Example usage
        print("Collecting event logs...")
        logs_path = agent.collect_eventlogs(["System", "Application"])
        print(f"Event logs saved to: {logs_path}")
        
        print("Collecting processes...")
        proc_path = agent.collect_processes()
        print(f"Process list saved to: {proc_path}")
        
    else:
        # Run as Windows service
        win32serviceutil.HandleCommandLine(HugginAgentService)