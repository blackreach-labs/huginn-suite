#!/usr/bin/env python3
"""
Listener Manager & Transport Plugin System
Manages listeners, sessions, transports, auto-expiry, and audit logs
"""

import json
import time
import threading
import sqlite3
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
import uuid

@dataclass
class ListenerConfig:
    transport: str
    host: str
    port: int
    options: Dict[str, Any]
    scope_restrictions: List[str]
    ttl_hours: int
    engagement_id: str

@dataclass
class Session:
    session_id: str
    listener_id: str
    remote_ip: str
    fingerprint: str
    first_seen: str
    last_seen: str
    metadata: Dict[str, Any]
    status: str  # active, expired, killed

class TransportPlugin(ABC):
    """Base class for transport plugins"""
    
    @abstractmethod
    def start_listener(self, config: ListenerConfig) -> str:
        """Start listener and return listener ID"""
        pass
    
    @abstractmethod
    def stop_listener(self, listener_id: str) -> bool:
        """Stop listener"""
        pass
    
    @abstractmethod
    def generate_payload(self, config: ListenerConfig) -> str:
        """Generate payload for this transport"""
        pass
    
    @abstractmethod
    def list_sessions(self, listener_id: str) -> List[Session]:
        """List active sessions for listener"""
        pass

class ListenerManager:
    def __init__(self, db_path: str = "resources/listeners.db"):
        self.db_path = db_path
        self.plugins: Dict[str, TransportPlugin] = {}
        self.active_listeners: Dict[str, Dict] = {}
        self.sessions: Dict[str, Session] = {}
        self._init_database()
        self._start_cleanup_thread()
    
    def _init_database(self):
        """Initialize SQLite database for listeners and sessions"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS listeners (
                listener_id TEXT PRIMARY KEY,
                transport TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                config TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                status TEXT NOT NULL,
                engagement_id TEXT NOT NULL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                listener_id TEXT NOT NULL,
                remote_ip TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                metadata TEXT NOT NULL,
                status TEXT NOT NULL,
                FOREIGN KEY (listener_id) REFERENCES listeners (listener_id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_logs (
                log_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                listener_id TEXT,
                session_id TEXT,
                details TEXT NOT NULL
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def register_plugin(self, transport: str, plugin: TransportPlugin):
        """Register a transport plugin"""
        self.plugins[transport] = plugin
        self._audit_log("plugin_registered", None, None, f"Transport: {transport}")
    
    def start_listener(self, config: ListenerConfig) -> str:
        """Start a new listener"""
        if config.transport not in self.plugins:
            raise ValueError(f"Transport {config.transport} not supported")
        
        plugin = self.plugins[config.transport]
        listener_id = plugin.start_listener(config)
        
        # Store in database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        expires_at = datetime.fromtimestamp(time.time() + (config.ttl_hours * 3600))
        
        cursor.execute('''
            INSERT INTO listeners 
            (listener_id, transport, host, port, config, created_at, expires_at, status, engagement_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            listener_id, config.transport, config.host, config.port,
            json.dumps(asdict(config)), datetime.now().isoformat(),
            expires_at.isoformat(), "active", config.engagement_id
        ))
        
        conn.commit()
        conn.close()
        
        self.active_listeners[listener_id] = {
            'config': config,
            'plugin': plugin,
            'started_at': time.time()
        }
        
        self._audit_log("listener_started", listener_id, None, 
                       f"Transport: {config.transport}, Host: {config.host}:{config.port}")
        
        return listener_id
    
    def stop_listener(self, listener_id: str) -> bool:
        """Stop a listener"""
        if listener_id not in self.active_listeners:
            return False
        
        plugin = self.active_listeners[listener_id]['plugin']
        success = plugin.stop_listener(listener_id)
        
        if success:
            # Update database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE listeners SET status = 'stopped' WHERE listener_id = ?",
                (listener_id,)
            )
            conn.commit()
            conn.close()
            
            del self.active_listeners[listener_id]
            self._audit_log("listener_stopped", listener_id, None, "Manual stop")
        
        return success
    
    def kill_listener(self, listener_id: str) -> bool:
        """Emergency kill listener"""
        success = self.stop_listener(listener_id)
        if success:
            self._audit_log("listener_killed", listener_id, None, "Emergency kill")
        return success
    
    def register_session(self, session: Session):
        """Register a new session"""
        self.sessions[session.session_id] = session
        
        # Store in database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO sessions 
            (session_id, listener_id, remote_ip, fingerprint, first_seen, last_seen, metadata, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            session.session_id, session.listener_id, session.remote_ip,
            session.fingerprint, session.first_seen, session.last_seen,
            json.dumps(session.metadata), session.status
        ))
        conn.commit()
        conn.close()
        
        self._audit_log("session_registered", session.listener_id, session.session_id,
                       f"Remote IP: {session.remote_ip}")
    
    def update_session(self, session_id: str, **updates):
        """Update session information"""
        if session_id in self.sessions:
            session = self.sessions[session_id]
            for key, value in updates.items():
                if hasattr(session, key):
                    setattr(session, key, value)
            
            # Update database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE sessions SET last_seen = ?, status = ? WHERE session_id = ?",
                (session.last_seen, session.status, session_id)
            )
            conn.commit()
            conn.close()
    
    def get_active_listeners(self) -> List[Dict]:
        """Get all active listeners"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM listeners WHERE status = 'active'")
        rows = cursor.fetchall()
        conn.close()
        
        listeners = []
        for row in rows:
            listeners.append({
                'listener_id': row[0],
                'transport': row[1],
                'host': row[2],
                'port': row[3],
                'config': json.loads(row[4]),
                'created_at': row[5],
                'expires_at': row[6],
                'status': row[7],
                'engagement_id': row[8]
            })
        
        return listeners
    
    def get_active_sessions(self) -> List[Session]:
        """Get all active sessions"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM sessions WHERE status = 'active'")
        rows = cursor.fetchall()
        conn.close()
        
        sessions = []
        for row in rows:
            sessions.append(Session(
                session_id=row[0],
                listener_id=row[1],
                remote_ip=row[2],
                fingerprint=row[3],
                first_seen=row[4],
                last_seen=row[5],
                metadata=json.loads(row[6]),
                status=row[7]
            ))
        
        return sessions
    
    def _cleanup_expired(self):
        """Clean up expired listeners and sessions"""
        current_time = time.time()
        
        # Check expired listeners
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT listener_id FROM listeners WHERE status = 'active' AND expires_at < ?",
            (datetime.fromtimestamp(current_time).isoformat(),)
        )
        expired_listeners = cursor.fetchall()
        
        for (listener_id,) in expired_listeners:
            if listener_id in self.active_listeners:
                self.stop_listener(listener_id)
                self._audit_log("listener_expired", listener_id, None, "TTL expired")
        
        # Mark expired sessions
        cursor.execute(
            "UPDATE sessions SET status = 'expired' WHERE status = 'active' AND last_seen < ?",
            (datetime.fromtimestamp(current_time - 3600).isoformat(),)  # 1 hour timeout
        )
        
        conn.commit()
        conn.close()
    
    def _start_cleanup_thread(self):
        """Start background cleanup thread"""
        def cleanup_worker():
            while True:
                try:
                    self._cleanup_expired()
                    time.sleep(300)  # Check every 5 minutes
                except Exception as e:
                    print(f"Cleanup error: {e}")
                    time.sleep(60)
        
        cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        cleanup_thread.start()
    
    def _audit_log(self, action: str, listener_id: Optional[str], 
                   session_id: Optional[str], details: str):
        """Add audit log entry"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO audit_logs (log_id, timestamp, action, listener_id, session_id, details)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            str(uuid.uuid4()), datetime.now().isoformat(),
            action, listener_id, session_id, details
        ))
        conn.commit()
        conn.close()
    
    def get_audit_logs(self, limit: int = 100) -> List[Dict]:
        """Get recent audit logs"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        )
        rows = cursor.fetchall()
        conn.close()
        
        logs = []
        for row in rows:
            logs.append({
                'log_id': row[0],
                'timestamp': row[1],
                'action': row[2],
                'listener_id': row[3],
                'session_id': row[4],
                'details': row[5]
            })
        
        return logs

# Global listener manager instance
listener_manager = ListenerManager()