#!/usr/bin/env python3
"""
C2 / Beacon Orchestrator (In-App, Optional Pro)
Lightweight, auditable beacon scheduler for lab/probe use
"""

import json
import time
import threading
import sqlite3
import random
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import uuid
import hashlib
from pathlib import Path

@dataclass
class BeaconConfig:
    beacon_id: str
    transport: str
    callback_interval: int
    jitter_percent: int
    max_callbacks: int
    allowed_ips: List[str]
    expiry_timestamp: int
    attestation_hash: str

@dataclass
class BeaconSession:
    session_id: str
    beacon_id: str
    remote_ip: str
    first_callback: str
    last_callback: str
    callback_count: int
    status: str
    metadata: Dict[str, Any]

@dataclass
class BeaconTask:
    task_id: str
    session_id: str
    command: str
    created_at: str
    executed_at: Optional[str]
    result: Optional[str]
    status: str

class C2Orchestrator:
    def __init__(self, db_path: str = "resources/c2_orchestrator.db", lab_mode: bool = True):
        self.db_path = db_path
        self.lab_mode = lab_mode
        self.beacons: Dict[str, BeaconConfig] = {}
        self.sessions: Dict[str, BeaconSession] = {}
        self.task_queue: Dict[str, List[BeaconTask]] = {}
        self.results: Dict[str, List[Dict]] = {}
        
        self._init_database()
        self._start_cleanup_thread()
        
        # Scoping restrictions for lab mode
        self.allowed_ip_ranges = [
            "192.168.0.0/16",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "127.0.0.0/8"
        ] if lab_mode else []
    
    def _init_database(self):
        """Initialize C2 orchestrator database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS beacon_configs (
                beacon_id TEXT PRIMARY KEY,
                transport TEXT NOT NULL,
                callback_interval INTEGER NOT NULL,
                jitter_percent INTEGER NOT NULL,
                max_callbacks INTEGER NOT NULL,
                allowed_ips TEXT NOT NULL,
                expiry_timestamp INTEGER NOT NULL,
                attestation_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                status TEXT DEFAULT 'active'
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS beacon_sessions (
                session_id TEXT PRIMARY KEY,
                beacon_id TEXT NOT NULL,
                remote_ip TEXT NOT NULL,
                first_callback TEXT NOT NULL,
                last_callback TEXT NOT NULL,
                callback_count INTEGER DEFAULT 0,
                status TEXT DEFAULT 'active',
                metadata TEXT NOT NULL,
                FOREIGN KEY (beacon_id) REFERENCES beacon_configs (beacon_id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS beacon_tasks (
                task_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                command TEXT NOT NULL,
                created_at TEXT NOT NULL,
                executed_at TEXT,
                result TEXT,
                status TEXT DEFAULT 'pending',
                FOREIGN KEY (session_id) REFERENCES beacon_sessions (session_id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS c2_audit_logs (
                log_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                beacon_id TEXT,
                session_id TEXT,
                remote_ip TEXT,
                details TEXT NOT NULL
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def create_beacon(self, transport: str, callback_interval: int = 30, 
                     jitter_percent: int = 20, max_callbacks: int = 1000,
                     allowed_ips: List[str] = None, ttl_hours: int = 24,
                     attestation: str = None) -> str:
        """Create a new beacon configuration"""
        
        # Verify attestation for production mode
        if not self.lab_mode and not self._verify_attestation(attestation):
            raise ValueError("Invalid attestation for production beacon")
        
        beacon_id = str(uuid.uuid4())
        
        # Default to lab-safe IPs if none specified
        if not allowed_ips:
            allowed_ips = ["127.0.0.1", "192.168.1.0/24"]
        
        # Validate IP ranges for lab mode
        if self.lab_mode:
            allowed_ips = self._validate_lab_ips(allowed_ips)
        
        expiry_timestamp = int(time.time()) + (ttl_hours * 3600)
        attestation_hash = hashlib.sha256(f"{beacon_id}:{attestation or 'lab_mode'}".encode()).hexdigest()
        
        beacon_config = BeaconConfig(
            beacon_id=beacon_id,
            transport=transport,
            callback_interval=callback_interval,
            jitter_percent=jitter_percent,
            max_callbacks=max_callbacks,
            allowed_ips=allowed_ips,
            expiry_timestamp=expiry_timestamp,
            attestation_hash=attestation_hash
        )
        
        self.beacons[beacon_id] = beacon_config
        self._store_beacon_config(beacon_config)
        self._audit_log("beacon_created", beacon_id, None, None, f"Transport: {transport}")
        
        return beacon_id
    
    def register_callback(self, beacon_id: str, remote_ip: str, 
                         metadata: Dict[str, Any] = None) -> Tuple[str, List[BeaconTask]]:
        """Register beacon callback and return session ID and pending tasks"""
        
        if beacon_id not in self.beacons:
            raise ValueError(f"Unknown beacon ID: {beacon_id}")
        
        beacon_config = self.beacons[beacon_id]
        
        # Check expiry
        if time.time() > beacon_config.expiry_timestamp:
            self._audit_log("callback_expired", beacon_id, None, remote_ip, "Beacon expired")
            raise ValueError("Beacon has expired")
        
        # Check IP restrictions
        if not self._is_ip_allowed(remote_ip, beacon_config.allowed_ips):
            self._audit_log("callback_blocked", beacon_id, None, remote_ip, "IP not allowed")
            raise ValueError(f"IP {remote_ip} not in allowed list")
        
        # Find or create session
        session_id = self._get_or_create_session(beacon_id, remote_ip, metadata or {})
        session = self.sessions[session_id]
        
        # Update session
        session.last_callback = datetime.now().isoformat()
        session.callback_count += 1
        
        # Check max callbacks
        if session.callback_count > beacon_config.max_callbacks:
            session.status = 'max_callbacks_reached'
            self._audit_log("max_callbacks_reached", beacon_id, session_id, remote_ip, 
                           f"Reached {beacon_config.max_callbacks} callbacks")
        
        self._update_session(session)
        
        # Get pending tasks
        pending_tasks = self._get_pending_tasks(session_id)
        
        self._audit_log("callback_received", beacon_id, session_id, remote_ip, 
                       f"Callback #{session.callback_count}")
        
        return session_id, pending_tasks
    
    def queue_task(self, session_id: str, command: str) -> str:
        """Queue a task for a beacon session"""
        
        if session_id not in self.sessions:
            raise ValueError(f"Unknown session ID: {session_id}")
        
        # Validate command for lab mode
        if self.lab_mode and not self._is_safe_command(command):
            raise ValueError(f"Command not allowed in lab mode: {command}")
        
        task_id = str(uuid.uuid4())
        task = BeaconTask(
            task_id=task_id,
            session_id=session_id,
            command=command,
            created_at=datetime.now().isoformat(),
            executed_at=None,
            result=None,
            status='pending'
        )
        
        if session_id not in self.task_queue:
            self.task_queue[session_id] = []
        
        self.task_queue[session_id].append(task)
        self._store_task(task)
        
        self._audit_log("task_queued", None, session_id, None, f"Command: {command}")
        
        return task_id
    
    def submit_task_result(self, task_id: str, result: str) -> bool:
        """Submit result for a completed task"""
        
        # Find task across all sessions
        task = None
        for session_tasks in self.task_queue.values():
            for t in session_tasks:
                if t.task_id == task_id:
                    task = t
                    break
            if task:
                break
        
        if not task:
            return False
        
        task.result = result
        task.executed_at = datetime.now().isoformat()
        task.status = 'completed'
        
        # Store result
        session_id = task.session_id
        if session_id not in self.results:
            self.results[session_id] = []
        
        self.results[session_id].append({
            'task_id': task_id,
            'command': task.command,
            'result': result,
            'executed_at': task.executed_at
        })
        
        self._update_task(task)
        self._audit_log("task_completed", None, session_id, None, f"Task: {task_id}")
        
        return True
    
    def get_session_results(self, session_id: str) -> List[Dict]:
        """Get all results for a session"""
        return self.results.get(session_id, [])
    
    def get_active_sessions(self) -> List[BeaconSession]:
        """Get all active beacon sessions"""
        active_sessions = []
        
        for session in self.sessions.values():
            if session.status == 'active':
                # Check if session is still alive (last callback within 2x interval)
                beacon_config = self.beacons.get(session.beacon_id)
                if beacon_config:
                    max_silence = beacon_config.callback_interval * 2
                    last_callback = datetime.fromisoformat(session.last_callback)
                    if (datetime.now() - last_callback).total_seconds() < max_silence:
                        active_sessions.append(session)
        
        return active_sessions
    
    def kill_beacon(self, beacon_id: str) -> bool:
        """Emergency kill a beacon"""
        if beacon_id not in self.beacons:
            return False
        
        # Mark beacon as killed
        beacon_config = self.beacons[beacon_id]
        beacon_config.expiry_timestamp = int(time.time())  # Expire immediately
        
        # Kill all sessions for this beacon
        for session in self.sessions.values():
            if session.beacon_id == beacon_id:
                session.status = 'killed'
                self._update_session(session)
        
        self._update_beacon_config(beacon_config)
        self._audit_log("beacon_killed", beacon_id, None, None, "Emergency kill")
        
        return True
    
    def generate_beacon_payload(self, beacon_id: str) -> str:
        """Generate beacon payload code"""
        if beacon_id not in self.beacons:
            raise ValueError(f"Unknown beacon ID: {beacon_id}")
        
        beacon_config = self.beacons[beacon_id]
        
        # Generate payload based on transport
        if beacon_config.transport == 'http':
            return self._generate_http_beacon_payload(beacon_config)
        elif beacon_config.transport == 'tcp':
            return self._generate_tcp_beacon_payload(beacon_config)
        elif beacon_config.transport == 'dns':
            return self._generate_dns_beacon_payload(beacon_config)
        else:
            raise ValueError(f"Unsupported transport: {beacon_config.transport}")
    
    def export_session_data(self, session_id: str, format: str = 'json') -> str:
        """Export session data for analysis"""
        if session_id not in self.sessions:
            raise ValueError(f"Unknown session ID: {session_id}")
        
        session = self.sessions[session_id]
        results = self.get_session_results(session_id)
        
        export_data = {
            'session': asdict(session),
            'results': results,
            'exported_at': datetime.now().isoformat()
        }
        
        if format == 'json':
            return json.dumps(export_data, indent=2)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _verify_attestation(self, attestation: str) -> bool:
        """Verify attestation for production mode"""
        if not attestation:
            return False
        
        # In production, this would verify digital signature
        # For now, simple validation
        return len(attestation) > 10
    
    def _validate_lab_ips(self, allowed_ips: List[str]) -> List[str]:
        """Validate IP ranges for lab mode"""
        validated_ips = []
        
        for ip in allowed_ips:
            # Only allow private IP ranges in lab mode
            if any(ip.startswith(prefix.split('/')[0][:3]) for prefix in self.allowed_ip_ranges):
                validated_ips.append(ip)
        
        return validated_ips if validated_ips else ["127.0.0.1"]
    
    def _is_ip_allowed(self, remote_ip: str, allowed_ips: List[str]) -> bool:
        """Check if IP is in allowed list"""
        # Simple IP matching - in production would use proper CIDR matching
        for allowed_ip in allowed_ips:
            if '/' in allowed_ip:
                # CIDR notation - simplified check
                network = allowed_ip.split('/')[0]
                if remote_ip.startswith(network[:network.rfind('.')]):
                    return True
            else:
                if remote_ip == allowed_ip:
                    return True
        
        return False
    
    def _is_safe_command(self, command: str) -> bool:
        """Check if command is safe for lab mode"""
        dangerous_commands = [
            'rm -rf', 'del /f', 'format', 'shutdown', 'reboot',
            'net user', 'useradd', 'passwd', 'reg delete'
        ]
        
        command_lower = command.lower()
        return not any(dangerous in command_lower for dangerous in dangerous_commands)
    
    def _get_or_create_session(self, beacon_id: str, remote_ip: str, 
                              metadata: Dict[str, Any]) -> str:
        """Get existing session or create new one"""
        # Look for existing session
        for session_id, session in self.sessions.items():
            if session.beacon_id == beacon_id and session.remote_ip == remote_ip:
                return session_id
        
        # Create new session
        session_id = str(uuid.uuid4())
        session = BeaconSession(
            session_id=session_id,
            beacon_id=beacon_id,
            remote_ip=remote_ip,
            first_callback=datetime.now().isoformat(),
            last_callback=datetime.now().isoformat(),
            callback_count=0,
            status='active',
            metadata=metadata
        )
        
        self.sessions[session_id] = session
        self._store_session(session)
        
        return session_id
    
    def _get_pending_tasks(self, session_id: str) -> List[BeaconTask]:
        """Get pending tasks for session"""
        if session_id not in self.task_queue:
            return []
        
        pending_tasks = [t for t in self.task_queue[session_id] if t.status == 'pending']
        
        # Mark tasks as sent
        for task in pending_tasks:
            task.status = 'sent'
            self._update_task(task)
        
        return pending_tasks
    
    def _generate_http_beacon_payload(self, config: BeaconConfig) -> str:
        """Generate HTTP beacon payload"""
        return f'''
import requests
import time
import random
import json

BEACON_ID = "{config.beacon_id}"
CALLBACK_URL = "http://127.0.0.1:8080/beacon/callback"
INTERVAL = {config.callback_interval}
JITTER = {config.jitter_percent}

def beacon_loop():
    while True:
        try:
            # Calculate jittered interval
            jitter_factor = random.uniform(1 - JITTER/100, 1 + JITTER/100)
            sleep_time = INTERVAL * jitter_factor
            
            # Make callback
            response = requests.post(CALLBACK_URL, json={{
                "beacon_id": BEACON_ID,
                "metadata": {{"hostname": "lab-host"}}
            }}, timeout=10)
            
            if response.status_code == 200:
                tasks = response.json().get("tasks", [])
                for task in tasks:
                    # Execute task (lab-safe only)
                    result = f"Executed: {{task['command']}}"
                    
                    # Submit result
                    requests.post(CALLBACK_URL + "/result", json={{
                        "task_id": task["task_id"],
                        "result": result
                    }})
            
            time.sleep(sleep_time)
            
        except Exception as e:
            time.sleep(60)  # Error backoff

if __name__ == "__main__":
    beacon_loop()
'''
    
    def _generate_tcp_beacon_payload(self, config: BeaconConfig) -> str:
        """Generate TCP beacon payload"""
        return f'''
import socket
import time
import random
import json

BEACON_ID = "{config.beacon_id}"
HOST = "127.0.0.1"
PORT = 4444
INTERVAL = {config.callback_interval}
JITTER = {config.jitter_percent}

def beacon_loop():
    while True:
        try:
            # Calculate jittered interval
            jitter_factor = random.uniform(1 - JITTER/100, 1 + JITTER/100)
            sleep_time = INTERVAL * jitter_factor
            
            # Connect and callback
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((HOST, PORT))
            
            # Send beacon ID
            sock.send(BEACON_ID.encode())
            
            # Receive tasks
            data = sock.recv(1024)
            if data:
                command = data.decode().strip()
                result = f"Executed: {{command}}"
                sock.send(result.encode())
            
            sock.close()
            time.sleep(sleep_time)
            
        except Exception as e:
            time.sleep(60)  # Error backoff

if __name__ == "__main__":
    beacon_loop()
'''
    
    def _generate_dns_beacon_payload(self, config: BeaconConfig) -> str:
        """Generate DNS beacon payload"""
        return f'''
import dns.resolver
import time
import random
import base64

BEACON_ID = "{config.beacon_id}"
DNS_DOMAIN = "beacon.local"
INTERVAL = {config.callback_interval}
JITTER = {config.jitter_percent}

def beacon_loop():
    while True:
        try:
            # Calculate jittered interval
            jitter_factor = random.uniform(1 - JITTER/100, 1 + JITTER/100)
            sleep_time = INTERVAL * jitter_factor
            
            # DNS callback
            query = f"{{BEACON_ID}}.{{DNS_DOMAIN}}"
            answers = dns.resolver.resolve(query, 'TXT')
            
            for answer in answers:
                command = base64.b64decode(str(answer).strip('"')).decode()
                if command:
                    result = f"Executed: {{command}}"
                    # Send result via DNS (implementation specific)
            
            time.sleep(sleep_time)
            
        except Exception as e:
            time.sleep(60)  # Error backoff

if __name__ == "__main__":
    beacon_loop()
'''
    
    def _store_beacon_config(self, config: BeaconConfig):
        """Store beacon configuration in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO beacon_configs
            (beacon_id, transport, callback_interval, jitter_percent, max_callbacks,
             allowed_ips, expiry_timestamp, attestation_hash, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            config.beacon_id, config.transport, config.callback_interval,
            config.jitter_percent, config.max_callbacks, json.dumps(config.allowed_ips),
            config.expiry_timestamp, config.attestation_hash, datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    def _store_session(self, session: BeaconSession):
        """Store beacon session in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO beacon_sessions
            (session_id, beacon_id, remote_ip, first_callback, last_callback,
             callback_count, status, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            session.session_id, session.beacon_id, session.remote_ip,
            session.first_callback, session.last_callback, session.callback_count,
            session.status, json.dumps(session.metadata)
        ))
        
        conn.commit()
        conn.close()
    
    def _store_task(self, task: BeaconTask):
        """Store beacon task in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO beacon_tasks
            (task_id, session_id, command, created_at, executed_at, result, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            task.task_id, task.session_id, task.command, task.created_at,
            task.executed_at, task.result, task.status
        ))
        
        conn.commit()
        conn.close()
    
    def _update_session(self, session: BeaconSession):
        """Update session in database"""
        self._store_session(session)  # Using REPLACE
    
    def _update_task(self, task: BeaconTask):
        """Update task in database"""
        self._store_task(task)  # Using REPLACE
    
    def _update_beacon_config(self, config: BeaconConfig):
        """Update beacon config in database"""
        self._store_beacon_config(config)  # Using REPLACE
    
    def _audit_log(self, action: str, beacon_id: Optional[str], session_id: Optional[str],
                   remote_ip: Optional[str], details: str):
        """Add audit log entry"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO c2_audit_logs
            (log_id, timestamp, action, beacon_id, session_id, remote_ip, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            str(uuid.uuid4()), datetime.now().isoformat(), action,
            beacon_id, session_id, remote_ip, details
        ))
        
        conn.commit()
        conn.close()
    
    def _start_cleanup_thread(self):
        """Start background cleanup thread"""
        def cleanup_worker():
            while True:
                try:
                    self._cleanup_expired_beacons()
                    time.sleep(300)  # Check every 5 minutes
                except Exception as e:
                    print(f"Cleanup error: {e}")
                    time.sleep(60)
        
        cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        cleanup_thread.start()
    
    def _cleanup_expired_beacons(self):
        """Clean up expired beacons and sessions"""
        current_time = time.time()
        
        # Mark expired beacons
        for beacon_id, config in list(self.beacons.items()):
            if current_time > config.expiry_timestamp:
                # Mark all sessions as expired
                for session in self.sessions.values():
                    if session.beacon_id == beacon_id:
                        session.status = 'expired'
                        self._update_session(session)
                
                self._audit_log("beacon_expired", beacon_id, None, None, "TTL expired")

# Example usage
if __name__ == "__main__":
    # Example C2 orchestrator usage
    c2 = C2Orchestrator(lab_mode=True)
    
    # Create beacon
    beacon_id = c2.create_beacon('http', callback_interval=30, ttl_hours=1)
    print(f"Created beacon: {beacon_id}")
    
    # Generate payload
    payload = c2.generate_beacon_payload(beacon_id)
    print(f"Beacon payload generated")
    
    # Simulate callback
    session_id, tasks = c2.register_callback(beacon_id, "127.0.0.1")
    print(f"Callback registered: {session_id}")
    
    # Queue task
    task_id = c2.queue_task(session_id, "whoami")
    print(f"Task queued: {task_id}")
    
    # Get active sessions
    active_sessions = c2.get_active_sessions()
    print(f"Active sessions: {len(active_sessions)}")