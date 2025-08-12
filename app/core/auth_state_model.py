# app/core/auth_state_model.py
import json
import time
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
from dataclasses import dataclass, asdict

@dataclass
class AuthNode:
    """Represents a node in the authentication flow graph"""
    id: str
    url: str
    method: str
    endpoint: str
    requires_auth: bool = False
    requires_token: bool = False
    requires_cookie: bool = False
    is_anonymous: bool = True
    node_type: str = "request"  # request, redirect, token_mint, callback
    parameters: Dict[str, str] = None
    headers: Dict[str, str] = None
    timestamp: float = 0
    
    def __post_init__(self):
        if self.parameters is None:
            self.parameters = {}
        if self.headers is None:
            self.headers = {}
        if self.timestamp == 0:
            self.timestamp = time.time()

@dataclass
class AuthEdge:
    """Represents a transition between nodes"""
    from_node: str
    to_node: str
    trigger: str  # redirect, response, form_submit, token_exchange
    condition: str = ""  # Optional condition for the transition
    parameters_passed: List[str] = None
    
    def __post_init__(self):
        if self.parameters_passed is None:
            self.parameters_passed = []

class AuthStateModel:
    """Builds and manages authentication flow state model"""
    
    def __init__(self):
        self.nodes: Dict[str, AuthNode] = {}
        self.edges: List[AuthEdge] = []
        self.flow_data = None
        self.token_lifecycle = {}  # Track token creation, usage, expiry
        self.sensitive_params = {
            'oauth': ['code', 'state', 'redirect_uri', 'client_id', 'response_type', 'scope'],
            'csrf': ['csrf_token', 'authenticity_token', '_token'],
            'session': ['session_id', 'JSESSIONID', 'PHPSESSID'],
            'auth': ['access_token', 'refresh_token', 'id_token', 'bearer_token']
        }
    
    def build_model(self, flow_data: dict):
        """Build state model from recorded flow data"""
        self.flow_data = flow_data
        self.nodes.clear()
        self.edges.clear()
        
        requests = flow_data.get('requests', [])
        if not requests:
            return
        
        # Create nodes for each request
        for i, request in enumerate(requests):
            node_id = f"node_{i}"
            parsed_url = urlparse(request['url'])
            
            node = AuthNode(
                id=node_id,
                url=request['url'],
                method=request['method'],
                endpoint=f"{parsed_url.netloc}{parsed_url.path}",
                timestamp=request['timestamp']
            )
            
            # Analyze node characteristics
            self._analyze_node_requirements(node, request)
            self._classify_node_type(node, request)
            
            self.nodes[node_id] = node
        
        # Create edges between sequential nodes
        for i in range(len(requests) - 1):
            current_node = f"node_{i}"
            next_node = f"node_{i + 1}"
            
            # Determine transition trigger
            trigger = self._determine_trigger(requests[i], requests[i + 1])
            
            # Find parameters passed between nodes
            params_passed = self._find_passed_parameters(requests[i], requests[i + 1])
            
            edge = AuthEdge(
                from_node=current_node,
                to_node=next_node,
                trigger=trigger,
                parameters_passed=params_passed
            )
            
            self.edges.append(edge)
        
        # Analyze token lifecycle
        self._analyze_token_lifecycle()
    
    def _analyze_node_requirements(self, node: AuthNode, request: dict):
        """Analyze what the node requires (auth, tokens, cookies)"""
        headers = request.get('headers', {})
        cookies = request.get('cookies', {})
        params = request.get('params', {})
        data = request.get('data', '')
        
        # Check for authorization requirements
        if 'Authorization' in headers:
            node.requires_auth = True
            node.is_anonymous = False
        
        # Check for token requirements
        token_indicators = ['access_token', 'token', 'bearer']
        for indicator in token_indicators:
            if any(indicator in str(v).lower() for v in headers.values()):
                node.requires_token = True
                node.is_anonymous = False
                break
            if any(indicator in str(v).lower() for v in params.values()):
                node.requires_token = True
                break
        
        # Check for cookie requirements
        session_cookies = ['session', 'JSESSIONID', 'PHPSESSID', 'auth']
        for cookie_name in cookies:
            if any(indicator in cookie_name.lower() for indicator in session_cookies):
                node.requires_cookie = True
                node.is_anonymous = False
                break
        
        # Store relevant parameters and headers
        node.parameters = params
        node.headers = {k: v for k, v in headers.items() 
                       if any(sensitive in k.lower() 
                             for param_group in self.sensitive_params.values() 
                             for sensitive in param_group)}
    
    def _classify_node_type(self, node: AuthNode, request: dict):
        """Classify the type of node based on URL and behavior"""
        url_lower = node.url.lower()
        path_lower = urlparse(node.url).path.lower()
        
        # Token minting endpoints
        if any(indicator in url_lower for indicator in ['token', 'oauth/token', 'auth/token']):
            node.node_type = "token_mint"
        
        # Callback endpoints
        elif any(indicator in url_lower for indicator in ['callback', 'redirect', 'return']):
            node.node_type = "callback"
        
        # Login endpoints
        elif any(indicator in path_lower for indicator in ['login', 'signin', 'auth']):
            node.node_type = "login"
        
        # Logout endpoints
        elif any(indicator in path_lower for indicator in ['logout', 'signout']):
            node.node_type = "logout"
        
        # Check for redirects in response
        elif request.get('response_status', 0) in [301, 302, 303, 307, 308]:
            node.node_type = "redirect"
        
        else:
            node.node_type = "request"
    
    def _determine_trigger(self, current_request: dict, next_request: dict) -> str:
        """Determine what triggered the transition to the next request"""
        current_status = current_request.get('response_status', 200)
        
        # Redirect triggers
        if current_status in [301, 302, 303, 307, 308]:
            return "redirect"
        
        # Form submission
        if (next_request.get('method') == 'POST' and 
            current_request.get('method') == 'GET'):
            return "form_submit"
        
        # Token exchange (POST to token endpoint)
        if ('token' in next_request.get('url', '').lower() and 
            next_request.get('method') == 'POST'):
            return "token_exchange"
        
        # AJAX/API call
        if 'application/json' in next_request.get('headers', {}).get('Content-Type', ''):
            return "api_call"
        
        return "response"
    
    def _find_passed_parameters(self, current_request: dict, next_request: dict) -> List[str]:
        """Find parameters passed from current to next request"""
        passed_params = []
        
        current_params = set()
        next_params = set()
        
        # Extract parameters from current request response
        try:
            if current_request.get('response_body'):
                response_body = current_request['response_body']
                # Simple extraction - could be enhanced with proper parsing
                for param_group in self.sensitive_params.values():
                    for param in param_group:
                        if param in response_body:
                            current_params.add(param)
        except:
            pass
        
        # Extract parameters from next request
        next_url_params = next_request.get('params', {})
        next_data = next_request.get('data', '')
        
        for param in next_url_params:
            next_params.add(param)
        
        # Check data for parameters
        for param_group in self.sensitive_params.values():
            for param in param_group:
                if param in next_data:
                    next_params.add(param)
        
        # Find intersection
        passed_params = list(current_params.intersection(next_params))
        
        return passed_params
    
    def _analyze_token_lifecycle(self):
        """Analyze token creation, usage, and expiry"""
        tokens = self.flow_data.get('tokens', {})
        
        for token_name, token_info in tokens.items():
            lifecycle = {
                'name': token_name,
                'created_at': token_info.get('timestamp'),
                'created_by': token_info.get('url'),
                'source': token_info.get('source'),
                'value': token_info.get('value', '')[:50] + '...',  # Truncate for security
                'used_in': [],
                'expires_at': None,
                'scope': None
            }
            
            # Find where token is used
            for node_id, node in self.nodes.items():
                if (token_name in str(node.parameters) or 
                    token_name in str(node.headers) or
                    token_info.get('value', '') in str(node.headers)):
                    lifecycle['used_in'].append({
                        'node_id': node_id,
                        'url': node.url,
                        'timestamp': node.timestamp
                    })
            
            # Try to extract expiry and scope for JWT tokens
            if token_name in ['access_token', 'id_token'] and token_info.get('value'):
                try:
                    import base64
                    # Simple JWT parsing (header.payload.signature)
                    parts = token_info['value'].split('.')
                    if len(parts) >= 2:
                        # Decode payload (add padding if needed)
                        payload = parts[1]
                        payload += '=' * (4 - len(payload) % 4)
                        decoded = base64.b64decode(payload)
                        jwt_data = json.loads(decoded)
                        
                        if 'exp' in jwt_data:
                            lifecycle['expires_at'] = jwt_data['exp']
                        if 'scope' in jwt_data:
                            lifecycle['scope'] = jwt_data['scope']
                except:
                    pass
            
            self.token_lifecycle[token_name] = lifecycle
    
    def get_graph_data(self) -> dict:
        """Get graph data for visualization"""
        nodes_data = []
        edges_data = []
        
        for node in self.nodes.values():
            node_data = asdict(node)
            node_data['label'] = f"{node.method} {urlparse(node.url).path}"
            node_data['color'] = self._get_node_color(node)
            nodes_data.append(node_data)
        
        for edge in self.edges:
            edge_data = asdict(edge)
            edge_data['label'] = edge.trigger
            edges_data.append(edge_data)
        
        return {
            'nodes': nodes_data,
            'edges': edges_data,
            'token_lifecycle': self.token_lifecycle
        }
    
    def _get_node_color(self, node: AuthNode) -> str:
        """Get color for node based on type and requirements"""
        if node.node_type == "token_mint":
            return "#FF6B6B"  # Red for token creation
        elif node.node_type == "callback":
            return "#4ECDC4"  # Teal for callbacks
        elif node.node_type == "login":
            return "#45B7D1"  # Blue for login
        elif node.node_type == "logout":
            return "#96CEB4"  # Green for logout
        elif node.requires_auth:
            return "#FECA57"  # Yellow for auth required
        elif node.is_anonymous:
            return "#DDA0DD"  # Light purple for anonymous
        else:
            return "#95A5A6"  # Gray for regular requests
    
    def find_security_issues(self) -> List[dict]:
        """Identify potential security issues in the flow"""
        issues = []
        
        # Check for missing state parameter in OAuth flows
        oauth_nodes = [n for n in self.nodes.values() if 'oauth' in n.url.lower()]
        for node in oauth_nodes:
            if 'state' not in node.parameters:
                issues.append({
                    'type': 'missing_state_parameter',
                    'severity': 'medium',
                    'node_id': node.id,
                    'description': 'OAuth flow missing state parameter (CSRF protection)',
                    'url': node.url
                })
        
        # Check for insecure redirect_uri
        for node in self.nodes.values():
            redirect_uri = node.parameters.get('redirect_uri', '')
            if redirect_uri and not redirect_uri.startswith('https://'):
                issues.append({
                    'type': 'insecure_redirect_uri',
                    'severity': 'high',
                    'node_id': node.id,
                    'description': 'Redirect URI not using HTTPS',
                    'url': node.url,
                    'redirect_uri': redirect_uri
                })
        
        # Check for tokens in URL parameters
        for node in self.nodes.values():
            for param, value in node.parameters.items():
                if 'token' in param.lower() and len(value) > 10:
                    issues.append({
                        'type': 'token_in_url',
                        'severity': 'high',
                        'node_id': node.id,
                        'description': 'Sensitive token found in URL parameters',
                        'url': node.url,
                        'parameter': param
                    })
        
        # Check for missing CSRF protection
        post_nodes = [n for n in self.nodes.values() if n.method == 'POST']
        for node in post_nodes:
            has_csrf = any('csrf' in param.lower() or 'token' in param.lower() 
                          for param in node.parameters.keys())
            if not has_csrf and node.node_type != "token_mint":
                issues.append({
                    'type': 'missing_csrf_protection',
                    'severity': 'medium',
                    'node_id': node.id,
                    'description': 'POST request without CSRF protection',
                    'url': node.url
                })
        
        return issues
    
    def export_model(self, filepath: str):
        """Export model to JSON file"""
        model_data = {
            'nodes': {k: asdict(v) for k, v in self.nodes.items()},
            'edges': [asdict(e) for e in self.edges],
            'token_lifecycle': self.token_lifecycle,
            'security_issues': self.find_security_issues(),
            'created_at': time.time()
        }
        
        with open(filepath, 'w') as f:
            json.dump(model_data, f, indent=2, default=str)
    
    def get_attack_surface(self) -> dict:
        """Analyze attack surface of the authentication flow"""
        return {
            'total_nodes': len(self.nodes),
            'auth_required_nodes': len([n for n in self.nodes.values() if n.requires_auth]),
            'anonymous_nodes': len([n for n in self.nodes.values() if n.is_anonymous]),
            'token_endpoints': len([n for n in self.nodes.values() if n.node_type == "token_mint"]),
            'callback_endpoints': len([n for n in self.nodes.values() if n.node_type == "callback"]),
            'sensitive_parameters': sum(len(n.parameters) for n in self.nodes.values()),
            'security_issues': len(self.find_security_issues()),
            'tokens_tracked': len(self.token_lifecycle)
        }