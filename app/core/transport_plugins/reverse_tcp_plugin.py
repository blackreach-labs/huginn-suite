#!/usr/bin/env python3
"""
Reverse TCP Transport Plugin
"""

import socket
import threading
import time
import uuid
from typing import List
from ..listener_manager import TransportPlugin, ListenerConfig, Session
from datetime import datetime
from app.core.logger import logger

class ReverseTCPPlugin(TransportPlugin):
    def __init__(self):
        self.listeners = {}
        self.sessions = {}
    
    def start_listener(self, config: ListenerConfig) -> str:
        """Start TCP listener"""
        listener_id = str(uuid.uuid4())
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((config.host, config.port))
            sock.listen(5)
            
            self.listeners[listener_id] = {
                'socket': sock,
                'config': config,
                'thread': None,
                'running': True
            }
            
            # Start accept thread
            accept_thread = threading.Thread(
                target=self._accept_connections,
                args=(listener_id,),
                daemon=True
            )
            accept_thread.start()
            self.listeners[listener_id]['thread'] = accept_thread
            
            return listener_id
            
        except Exception as e:
            raise Exception(f"Failed to start TCP listener: {e}")
    
    def stop_listener(self, listener_id: str) -> bool:
        """Stop TCP listener"""
        if listener_id not in self.listeners:
            return False
        
        try:
            listener = self.listeners[listener_id]
            listener['running'] = False
            listener['socket'].close()
            
            # Close all sessions for this listener
            sessions_to_close = [
                sid for sid, session in self.sessions.items()
                if session['listener_id'] == listener_id
            ]
            
            for session_id in sessions_to_close:
                self._close_session(session_id)
            
            del self.listeners[listener_id]
            return True
            
        except Exception:
            return False
    
    def generate_payload(self, config: ListenerConfig) -> str:
        """Generate reverse TCP payload"""
        from ...tools.payload_builder import PayloadBuilder
        
        builder = PayloadBuilder()
        options = {
            'host': config.host,
            'port': config.port,
            'engagement_id': config.engagement_id
        }
        
        return builder.build_stager('reverse-tcp', options)
    
    def list_sessions(self, listener_id: str) -> List[Session]:
        """List active sessions for listener"""
        sessions = []
        for session_id, session_data in self.sessions.items():
            if session_data['listener_id'] == listener_id:
                sessions.append(Session(
                    session_id=session_id,
                    listener_id=listener_id,
                    remote_ip=session_data['remote_ip'],
                    fingerprint=session_data['fingerprint'],
                    first_seen=session_data['first_seen'],
                    last_seen=session_data['last_seen'],
                    metadata=session_data['metadata'],
                    status=session_data['status']
                ))
        return sessions
    
    def _accept_connections(self, listener_id: str):
        """Accept incoming connections"""
        listener = self.listeners[listener_id]
        sock = listener['socket']
        
        while listener['running']:
            try:
                client_sock, addr = sock.accept()
                
                # Create session
                session_id = str(uuid.uuid4())
                fingerprint = f"tcp_{int(time.time())}"
                
                session_data = {
                    'listener_id': listener_id,
                    'socket': client_sock,
                    'remote_ip': addr[0],
                    'fingerprint': fingerprint,
                    'first_seen': datetime.now().isoformat(),
                    'last_seen': datetime.now().isoformat(),
                    'metadata': {'transport': 'tcp', 'port': addr[1]},
                    'status': 'active'
                }
                
                self.sessions[session_id] = session_data
                
                # Start session handler thread
                session_thread = threading.Thread(
                    target=self._handle_session,
                    args=(session_id,),
                    daemon=True
                )
                session_thread.start()
                
            except Exception as e:
                if listener['running']:
                    print(f"Accept error: {e}")
                break
    
    def _handle_session(self, session_id: str):
        """Handle individual session"""
        session = self.sessions[session_id]
        client_sock = session['socket']
        
        try:
            while session['status'] == 'active':
                # Simple command shell
                client_sock.send(b"huggin> ")
                data = client_sock.recv(1024)
                
                if not data:
                    break
                
                command = data.decode().strip()
                if command == 'exit':
                    break
                
                # Update last seen
                session['last_seen'] = datetime.now().isoformat()
                
                # Echo command (in real implementation, execute it)
                response = f"Executed: {command}\n"
                client_sock.send(response.encode())
                
        except Exception as e:
            print(f"Session error: {e}")
        finally:
            self._close_session(session_id)
    
    def _close_session(self, session_id: str):
        """Close a session"""
        if session_id in self.sessions:
            session = self.sessions[session_id]
            session['status'] = 'closed'
            try:
                session['socket'].close()
            except Exception as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
            del self.sessions[session_id]