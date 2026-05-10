# app/core/auth_flow_recorder.py
import json
import time
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, parse_qs
from PyQt6.QtCore import QObject, pyqtSignal
from app.core.logger import logger

class AuthFlowRecorder(QObject):
    """Records authentication flows from proxy traffic"""
    
    flow_recorded = pyqtSignal(dict)  # Emitted when a flow is recorded
    session_started = pyqtSignal(str)  # session_id
    session_ended = pyqtSignal(str)    # session_id
    
    def __init__(self):
        super().__init__()
        self.recording = False
        self.current_session = None
        self.flows = {}  # session_id -> flow_data
        self.request_sequence = []
        self.auth_indicators = [
            'login', 'auth', 'oauth', 'token', 'callback', 'redirect_uri',
            'code', 'state', 'access_token', 'refresh_token', 'session',
            'csrf', 'nonce', 'saml', 'sso'
        ]
    
    def start_recording(self, session_name: str = None) -> str:
        """Start recording authentication flow"""
        session_id = session_name or f"auth_session_{int(time.time())}"
        self.current_session = session_id
        self.recording = True
        self.request_sequence = []
        
        self.flows[session_id] = {
            'session_id': session_id,
            'start_time': time.time(),
            'requests': [],
            'tokens': {},
            'cookies': {},
            'redirects': [],
            'endpoints': set(),
            'parameters': {}
        }
        
        self.session_started.emit(session_id)
        return session_id
    
    def stop_recording(self) -> Optional[dict]:
        """Stop recording and return flow data"""
        if not self.recording or not self.current_session:
            return None
        
        self.recording = False
        flow_data = self.flows.get(self.current_session)
        
        if flow_data:
            flow_data['end_time'] = time.time()
            flow_data['duration'] = flow_data['end_time'] - flow_data['start_time']
            flow_data['endpoints'] = list(flow_data['endpoints'])
            
            self.session_ended.emit(self.current_session)
            self.flow_recorded.emit(flow_data)
        
        session_id = self.current_session
        self.current_session = None
        return flow_data
    
    def process_request(self, http_request, http_response=None):
        """Process HTTP request/response pair"""
        if not self.recording or not self.current_session:
            return
        
        flow_data = self.flows[self.current_session]
        
        # Parse URL
        parsed_url = urlparse(http_request.url)
        
        # Check if this looks like an auth-related request
        is_auth_related = self._is_auth_related(http_request)
        
        request_data = {
            'timestamp': time.time(),
            'method': http_request.method,
            'url': http_request.url,
            'host': parsed_url.netloc,
            'path': parsed_url.path,
            'headers': http_request.headers,
            'data': http_request.data,
            'params': http_request.params,
            'cookies': http_request.cookies,
            'is_auth_related': is_auth_related,
            'sequence_number': len(flow_data['requests'])
        }
        
        # Add response data if available
        if http_response:
            request_data.update({
                'response_status': http_response.status_code,
                'response_headers': http_response.headers,
                'response_body': http_response.text[:10000],  # Limit size
                'response_time': getattr(http_response, 'elapsed_time', 0)
            })
            
            # Track redirects
            if 300 <= http_response.status_code < 400:
                location = http_response.headers.get('Location', '')
                if location:
                    flow_data['redirects'].append({
                        'from': http_request.url,
                        'to': location,
                        'status': http_response.status_code,
                        'timestamp': time.time()
                    })
        
        flow_data['requests'].append(request_data)
        flow_data['endpoints'].add(parsed_url.netloc)
        
        # Extract tokens and sensitive parameters
        self._extract_tokens(http_request, http_response, flow_data)
        self._extract_cookies(http_request, http_response, flow_data)
        self._extract_parameters(http_request, flow_data)
    
    def _is_auth_related(self, http_request) -> bool:
        """Check if request is authentication-related"""
        url_lower = http_request.url.lower()
        data_lower = (http_request.data or '').lower()
        
        # Check URL path and parameters
        for indicator in self.auth_indicators:
            if indicator in url_lower or indicator in data_lower:
                return True
        
        # Check headers
        auth_headers = ['authorization', 'x-csrf-token', 'x-requested-with']
        for header in auth_headers:
            if header in http_request.headers:
                return True
        
        return False
    
    def _extract_tokens(self, http_request, http_response, flow_data):
        """Extract tokens from request/response"""
        tokens = flow_data['tokens']
        
        # Extract from URL parameters
        parsed_url = urlparse(http_request.url)
        params = parse_qs(parsed_url.query)
        
        token_params = ['access_token', 'refresh_token', 'id_token', 'code', 'state']
        for param in token_params:
            if param in params:
                tokens[param] = {
                    'value': params[param][0],
                    'source': 'url_param',
                    'timestamp': time.time(),
                    'url': http_request.url
                }
        
        # Extract from request body
        if http_request.data:
            try:
                if http_request.headers.get('Content-Type', '').startswith('application/json'):
                    data = json.loads(http_request.data)
                    for param in token_params:
                        if param in data:
                            tokens[param] = {
                                'value': data[param],
                                'source': 'request_body',
                                'timestamp': time.time(),
                                'url': http_request.url
                            }
                elif 'application/x-www-form-urlencoded' in http_request.headers.get('Content-Type', ''):
                    data = parse_qs(http_request.data)
                    for param in token_params:
                        if param in data:
                            tokens[param] = {
                                'value': data[param][0],
                                'source': 'form_data',
                                'timestamp': time.time(),
                                'url': http_request.url
                            }
            except Exception as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        
        # Extract from response body
        if http_response and http_response.text:
            try:
                if 'application/json' in http_response.headers.get('content-type', ''):
                    data = json.loads(http_response.text)
                    for param in token_params:
                        if param in data:
                            tokens[param] = {
                                'value': data[param],
                                'source': 'response_body',
                                'timestamp': time.time(),
                                'url': http_request.url
                            }
            except Exception as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        
        # Extract JWT tokens from Authorization header
        auth_header = http_request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token_value = auth_header[7:]
            tokens['bearer_token'] = {
                'value': token_value,
                'source': 'auth_header',
                'timestamp': time.time(),
                'url': http_request.url
            }
    
    def _extract_cookies(self, http_request, http_response, flow_data):
        """Extract cookies from request/response"""
        cookies = flow_data['cookies']
        
        # Extract from request cookies
        for name, value in http_request.cookies.items():
            cookies[name] = {
                'value': value,
                'source': 'request',
                'timestamp': time.time(),
                'url': http_request.url
            }
        
        # Extract from response Set-Cookie headers
        if http_response:
            set_cookie = http_response.headers.get('Set-Cookie', '')
            if set_cookie:
                # Simple cookie parsing (could be enhanced)
                for cookie_str in set_cookie.split(','):
                    if '=' in cookie_str:
                        name, value = cookie_str.split('=', 1)
                        name = name.strip()
                        value = value.split(';')[0].strip()
                        cookies[name] = {
                            'value': value,
                            'source': 'response',
                            'timestamp': time.time(),
                            'url': http_request.url
                        }
    
    def _extract_parameters(self, http_request, flow_data):
        """Extract sensitive parameters"""
        parameters = flow_data['parameters']
        
        # Extract from URL
        parsed_url = urlparse(http_request.url)
        params = parse_qs(parsed_url.query)
        
        sensitive_params = [
            'redirect_uri', 'client_id', 'response_type', 'scope',
            'state', 'nonce', 'csrf_token', 'authenticity_token'
        ]
        
        for param in sensitive_params:
            if param in params:
                parameters[param] = {
                    'value': params[param][0],
                    'source': 'url_param',
                    'timestamp': time.time(),
                    'url': http_request.url
                }
    
    def get_flow_data(self, session_id: str) -> Optional[dict]:
        """Get recorded flow data"""
        return self.flows.get(session_id)
    
    def get_all_flows(self) -> Dict[str, dict]:
        """Get all recorded flows"""
        return self.flows.copy()
    
    def clear_flows(self):
        """Clear all recorded flows"""
        self.flows.clear()
    
    def export_flow(self, session_id: str, filepath: str):
        """Export flow to JSON file"""
        flow_data = self.flows.get(session_id)
        if flow_data:
            with open(filepath, 'w') as f:
                json.dump(flow_data, f, indent=2, default=str)
    
    def import_flow(self, filepath: str) -> Optional[str]:
        """Import flow from JSON file"""
        try:
            with open(filepath, 'r') as f:
                flow_data = json.load(f)
            
            session_id = flow_data.get('session_id', f"imported_{int(time.time())}")
            self.flows[session_id] = flow_data
            return session_id
        except Exception as e:
            print(f"Failed to import flow: {e}")
            return None