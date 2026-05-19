#!/usr/bin/env python3
"""
Listener Manager & Transport Plugin System
Manages listeners, sessions, transports, auto-expiry, and audit logs.

Provides both the transport plugin architecture and the simplified API
used by the Shell Management UI widgets.
"""

import json
import time
import socket
import threading
import sqlite3
import psutil
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
import uuid

from PyQt6.QtCore import QObject, pyqtSignal


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


def get_network_interfaces() -> List[Dict[str, str]]:
    """Get available network interfaces with their IPv4 addresses.
    
    Only returns interfaces that are currently UP (active).
    Returns a list of dicts with keys: 'name', 'ip'
    """
    interfaces = []
    try:
        # Get interface stats to check which are UP
        stats = psutil.net_if_stats()
        
        for iface_name, addrs in psutil.net_if_addrs().items():
            # Only include interfaces that are currently up
            iface_stats = stats.get(iface_name)
            if iface_stats and not iface_stats.isup:
                continue
                
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    interfaces.append({
                        'name': iface_name,
                        'ip': addr.address
                    })
    except Exception:
        pass

    # Always include 0.0.0.0 (all interfaces) at the top
    interfaces.insert(0, {'name': 'All Interfaces', 'ip': '0.0.0.0'})
    return interfaces


class ListenerManager(QObject):
    """Manages network listeners for reverse shells and OOB data capture.
    
    Provides Qt signals for UI integration and a simplified create/start/stop API
    used by the Shell Management widgets.
    """

    # Qt signals for UI integration
    listener_started = pyqtSignal(str, int, str)       # listener_id, port, listener_type
    listener_stopped = pyqtSignal(str)                 # listener_id
    connection_received = pyqtSignal(str, str, str)    # listener_id, client_ip, data
    oob_data_received = pyqtSignal(str, str, str)      # listener_id, source_ip, data

    def __init__(self, db_path: str = None):
        super().__init__()

        if db_path is None:
            project_root = Path(__file__).parent.parent.parent
            resources_dir = project_root / "resources"
            resources_dir.mkdir(exist_ok=True)
            db_path = str(resources_dir / "listeners.db")

        self.db_path = db_path
        self.plugins: Dict[str, TransportPlugin] = {}
        self._listeners: Dict[str, Dict[str, Any]] = {}
        self._server_sockets: Dict[str, socket.socket] = {}
        self._listener_threads: Dict[str, threading.Thread] = {}
        self.sessions: Dict[str, Session] = {}
        self._init_database()
        self._start_cleanup_thread()

    # ------------------------------------------------------------------
    # Database
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Plugin registration (advanced transport plugin API)
    # ------------------------------------------------------------------

    def register_plugin(self, transport: str, plugin: TransportPlugin):
        """Register a transport plugin"""
        self.plugins[transport] = plugin
        self._audit_log("plugin_registered", None, None, f"Transport: {transport}")

    # ------------------------------------------------------------------
    # Simplified Listener API (used by Shell Management widgets)
    # ------------------------------------------------------------------

    def create_listener(self, port: int, listener_type: str, bind_ip: str = "0.0.0.0") -> str:
        """Create a new listener (does not start it yet).
        
        Args:
            port: Port number to listen on
            listener_type: Type of listener (netcat, http, http_oob, dns_oob, powershell)
            bind_ip: IP address to bind to (default 0.0.0.0)
            
        Returns:
            listener_id: Unique identifier for the listener
        """
        listener_id = f"lsnr_{listener_type}_{port}_{uuid.uuid4().hex[:6]}"

        self._listeners[listener_id] = {
            'id': listener_id,
            'port': port,
            'type': listener_type,
            'bind_ip': bind_ip,
            'status': 'created',
            'connections': [],
            'created_at': datetime.now().isoformat(),
        }

        self._audit_log("listener_created", listener_id, None,
                        f"Type: {listener_type}, Bind: {bind_ip}:{port}")
        return listener_id

    def start_listener(self, listener_id: str) -> bool:
        """Start a previously created listener.
        
        Returns True on success, False on failure.
        """
        listener = self._listeners.get(listener_id)
        if not listener:
            return False

        if listener['status'] == 'running':
            return True  # Already running

        port = listener['port']
        bind_ip = listener['bind_ip']
        listener_type = listener['type']

        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.settimeout(1.0)  # Allow periodic checks for shutdown
            server_sock.bind((bind_ip, port))
            server_sock.listen(5)

            self._server_sockets[listener_id] = server_sock
            listener['status'] = 'running'

            # Start accept thread
            thread = threading.Thread(
                target=self._accept_loop,
                args=(listener_id,),
                daemon=True
            )
            thread.start()
            self._listener_threads[listener_id] = thread

            # Persist to database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            expires_at = datetime.fromtimestamp(time.time() + 24 * 3600)  # 24h TTL
            cursor.execute('''
                INSERT OR REPLACE INTO listeners 
                (listener_id, transport, host, port, config, created_at, expires_at, status, engagement_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                listener_id, listener_type, bind_ip, port,
                json.dumps({'type': listener_type, 'bind_ip': bind_ip}),
                listener['created_at'], expires_at.isoformat(), "active", "default"
            ))
            conn.commit()
            conn.close()

            self._audit_log("listener_started", listener_id, None,
                            f"Type: {listener_type}, Bind: {bind_ip}:{port}")

            # Emit signal
            self.listener_started.emit(listener_id, port, listener_type)
            return True

        except OSError as e:
            listener['status'] = 'error'
            listener['error'] = str(e)
            self._audit_log("listener_start_failed", listener_id, None, str(e))
            return False

    def stop_listener(self, listener_id: str) -> bool:
        """Stop a running listener."""
        listener = self._listeners.get(listener_id)
        if not listener:
            return False

        listener['status'] = 'stopped'

        # Close server socket (will cause accept loop to exit)
        server_sock = self._server_sockets.pop(listener_id, None)
        if server_sock:
            try:
                server_sock.close()
            except Exception:
                pass

        # Close all client connections
        for conn_info in listener.get('connections', []):
            client_sock = conn_info.get('socket')
            if client_sock:
                try:
                    client_sock.close()
                except Exception:
                    pass
        listener['connections'] = []

        # Update database
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE listeners SET status = 'stopped' WHERE listener_id = ?",
                (listener_id,)
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

        self._audit_log("listener_stopped", listener_id, None, "Manual stop")
        self.listener_stopped.emit(listener_id)
        return True

    def send_command_to_connection(self, listener_id: str, command: str) -> bool:
        """Send a command to the first active connection on a listener."""
        listener = self._listeners.get(listener_id)
        if not listener or not listener['connections']:
            return False

        conn_info = listener['connections'][0]
        client_sock = conn_info.get('socket')
        if not client_sock:
            return False

        try:
            client_sock.sendall((command + "\n").encode('utf-8'))
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Query methods
    # ------------------------------------------------------------------

    def get_all_listeners(self) -> List[Dict]:
        """Get all listeners (active, stopped, etc.)"""
        return [
            {
                'id': l['id'],
                'port': l['port'],
                'type': l['type'],
                'bind_ip': l.get('bind_ip', '0.0.0.0'),
                'status': l['status'],
                'connections': l.get('connections', []),
                'created_at': l.get('created_at', ''),
            }
            for l in self._listeners.values()
        ]

    def get_active_listeners(self) -> List[Dict]:
        """Get only running listeners"""
        return [l for l in self.get_all_listeners() if l['status'] == 'running']

    def get_listener_info(self, listener_id: str) -> Optional[Dict]:
        """Get detailed info about a specific listener."""
        listener = self._listeners.get(listener_id)
        if not listener:
            return None
        return {
            'id': listener['id'],
            'port': listener['port'],
            'type': listener['type'],
            'bind_ip': listener.get('bind_ip', '0.0.0.0'),
            'status': listener['status'],
            'connections': [
                {'ip': c['ip'], 'connected_at': c.get('connected_at', '')}
                for c in listener.get('connections', [])
            ],
            'created_at': listener.get('created_at', ''),
        }

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def register_session(self, session: Session):
        """Register a new session"""
        self.sessions[session.session_id] = session

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

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE sessions SET last_seen = ?, status = ? WHERE session_id = ?",
                (session.last_seen, session.status, session_id)
            )
            conn.commit()
            conn.close()

    def get_active_sessions(self) -> List[Session]:
        """Get all active sessions"""
        return [s for s in self.sessions.values() if s.status == 'active']

    # ------------------------------------------------------------------
    # Internal: accept loop and connection handling
    # ------------------------------------------------------------------

    def _accept_loop(self, listener_id: str):
        """Background thread that accepts incoming connections."""
        listener = self._listeners.get(listener_id)
        server_sock = self._server_sockets.get(listener_id)

        if not listener or not server_sock:
            return

        while listener['status'] == 'running':
            try:
                client_sock, addr = server_sock.accept()
                client_ip = f"{addr[0]}:{addr[1]}"

                conn_info = {
                    'ip': client_ip,
                    'socket': client_sock,
                    'connected_at': datetime.now().isoformat(),
                }
                listener['connections'].append(conn_info)

                # Emit connection signal
                self.connection_received.emit(listener_id, client_ip, "Connected")

                # Start reader thread for this connection
                reader_thread = threading.Thread(
                    target=self._read_connection,
                    args=(listener_id, conn_info),
                    daemon=True
                )
                reader_thread.start()

            except socket.timeout:
                continue
            except OSError:
                # Socket closed, exit loop
                break

    def _read_connection(self, listener_id: str, conn_info: Dict):
        """Read data from a client connection and emit signals."""
        client_sock = conn_info['socket']
        client_ip = conn_info['ip']

        try:
            while True:
                client_sock.settimeout(1.0)
                try:
                    data = client_sock.recv(4096)
                    if not data:
                        break
                    decoded = data.decode('utf-8', errors='replace')
                    self.connection_received.emit(listener_id, client_ip, decoded)
                except socket.timeout:
                    # Check if listener is still running
                    listener = self._listeners.get(listener_id)
                    if not listener or listener['status'] != 'running':
                        break
                    continue
        except Exception:
            pass
        finally:
            # Remove from connections list
            listener = self._listeners.get(listener_id)
            if listener and conn_info in listener['connections']:
                listener['connections'].remove(conn_info)
            try:
                client_sock.close()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def _cleanup_expired(self):
        """Clean up expired listeners"""
        current_time = time.time()

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT listener_id FROM listeners WHERE status = 'active' AND expires_at < ?",
                (datetime.fromtimestamp(current_time).isoformat(),)
            )
            expired_listeners = cursor.fetchall()
            conn.close()

            for (lid,) in expired_listeners:
                if lid in self._listeners:
                    self.stop_listener(lid)
                    self._audit_log("listener_expired", lid, None, "TTL expired")
        except Exception:
            pass

    def _start_cleanup_thread(self):
        """Start background cleanup thread"""
        def cleanup_worker():
            while True:
                try:
                    self._cleanup_expired()
                    time.sleep(300)
                except Exception:
                    time.sleep(60)

        cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        cleanup_thread.start()

    # ------------------------------------------------------------------
    # Audit logging
    # ------------------------------------------------------------------

    def _audit_log(self, action: str, listener_id: Optional[str],
                   session_id: Optional[str], details: str):
        """Add audit log entry"""
        try:
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
        except Exception:
            pass

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
