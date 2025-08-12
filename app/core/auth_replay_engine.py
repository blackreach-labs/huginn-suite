# app/core/auth_replay_engine.py
import asyncio
import json
import time
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse, parse_qs, urlencode
from PyQt6.QtCore import QObject, pyqtSignal, QThread
from .http_client import HttpRequest, HttpResponse, UnifiedHttpClient

class AuthReplayEngine(QObject):
    """Replays and mutates authentication flows"""
    
    replay_started = pyqtSignal(str)  # test_id
    replay_completed = pyqtSignal(str, dict)  # test_id, results
    request_sent = pyqtSignal(str, dict)  # test_id, request_info
    vulnerability_found = pyqtSignal(str, dict)  # test_id, vuln_info
    
    def __init__(self):
        super().__init__()
        self.http_client = UnifiedHttpClient()
        self.active_tests = {}
        
        # Mutation strategies
        self.mutations = {
            'remove_token': self._remove_token_mutation,
            'expired_token': self._expired_token_mutation,
            'swap_user_token': self._swap_user_token_mutation,
            'remove_state': self._remove_state_mutation,
            'modify_redirect_uri': self._modify_redirect_uri_mutation,
            'remove_csrf': self._remove_csrf_mutation,
            'privilege_escalation': self._privilege_escalation_mutation
        }
    
    def replay_flow(self, flow_data: dict, test_name: str = "basic_replay") -> str:
        """Replay authentication flow without mutations"""
        test_id = f"{test_name}_{int(time.time())}"
        
        # Start replay in thread
        replay_thread = ReplayThread(
            test_id, flow_data, self.http_client, mutations=None
        )
        replay_thread.request_sent.connect(self.request_sent)
        replay_thread.replay_completed.connect(self.replay_completed)
        replay_thread.start()
        
        self.active_tests[test_id] = replay_thread
        self.replay_started.emit(test_id)
        
        return test_id
    
    def test_mutations(self, flow_data: dict, mutations: List[str]) -> str:
        """Test authentication flow with specified mutations"""
        test_id = f"mutation_test_{int(time.time())}"
        
        # Start mutation test in thread
        replay_thread = ReplayThread(
            test_id, flow_data, self.http_client, mutations=mutations
        )
        replay_thread.request_sent.connect(self.request_sent)
        replay_thread.replay_completed.connect(self.replay_completed)
        replay_thread.vulnerability_found.connect(self.vulnerability_found)
        replay_thread.start()
        
        self.active_tests[test_id] = replay_thread
        self.replay_started.emit(test_id)
        
        return test_id
    
    def run_security_tests(self, flow_data: dict) -> str:
        """Run comprehensive security tests on authentication flow"""
        test_id = f"security_test_{int(time.time())}"
        
        # Define security test mutations
        security_mutations = [
            'remove_token',
            'remove_state', 
            'modify_redirect_uri',
            'remove_csrf',
            'privilege_escalation'
        ]
        
        return self.test_mutations(flow_data, security_mutations)
    
    def _remove_token_mutation(self, request: HttpRequest) -> HttpRequest:
        """Remove authentication tokens from request"""
        mutated = self._copy_request(request)
        
        # Remove Authorization header
        if 'Authorization' in mutated.headers:
            del mutated.headers['Authorization']
        
        # Remove token parameters
        token_params = ['access_token', 'token', 'bearer_token']
        for param in token_params:
            if param in mutated.params:
                del mutated.params[param]
        
        # Remove from request body
        if mutated.data:
            try:
                if 'application/json' in mutated.headers.get('Content-Type', ''):
                    data = json.loads(mutated.data)
                    for param in token_params:
                        if param in data:
                            del data[param]
                    mutated.data = json.dumps(data)
                elif 'application/x-www-form-urlencoded' in mutated.headers.get('Content-Type', ''):
                    data = parse_qs(mutated.data)
                    for param in token_params:
                        if param in data:
                            del data[param]
                    mutated.data = urlencode(data, doseq=True)
            except:
                pass
        
        return mutated
    
    def _expired_token_mutation(self, request: HttpRequest) -> HttpRequest:
        """Use an expired/invalid token"""
        mutated = self._copy_request(request)
        
        # Replace Authorization header with expired token
        if 'Authorization' in mutated.headers:
            mutated.headers['Authorization'] = 'Bearer expired_token_12345'
        
        # Replace token parameters
        token_params = ['access_token', 'token']
        for param in token_params:
            if param in mutated.params:
                mutated.params[param] = 'expired_token_12345'
        
        return mutated
    
    def _swap_user_token_mutation(self, request: HttpRequest) -> HttpRequest:
        """Swap tokens between different users (if available)"""
        mutated = self._copy_request(request)
        
        # This would need a token database in real implementation
        # For now, use a placeholder different token
        if 'Authorization' in mutated.headers:
            mutated.headers['Authorization'] = 'Bearer different_user_token_67890'
        
        return mutated
    
    def _remove_state_mutation(self, request: HttpRequest) -> HttpRequest:
        """Remove state parameter from OAuth requests"""
        mutated = self._copy_request(request)
        
        # Remove state parameter
        if 'state' in mutated.params:
            del mutated.params['state']
        
        # Remove from request body
        if mutated.data and 'state=' in mutated.data:
            try:
                if 'application/x-www-form-urlencoded' in mutated.headers.get('Content-Type', ''):
                    data = parse_qs(mutated.data)
                    if 'state' in data:
                        del data['state']
                    mutated.data = urlencode(data, doseq=True)
            except:
                pass
        
        return mutated
    
    def _modify_redirect_uri_mutation(self, request: HttpRequest) -> HttpRequest:
        """Modify redirect_uri to test for open redirects"""
        mutated = self._copy_request(request)
        
        malicious_uris = [
            'http://evil.com/callback',
            'https://attacker.com/steal',
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>'
        ]
        
        # Modify redirect_uri parameter
        if 'redirect_uri' in mutated.params:
            mutated.params['redirect_uri'] = malicious_uris[0]
        
        # Modify in request body
        if mutated.data and 'redirect_uri=' in mutated.data:
            try:
                if 'application/x-www-form-urlencoded' in mutated.headers.get('Content-Type', ''):
                    data = parse_qs(mutated.data)
                    if 'redirect_uri' in data:
                        data['redirect_uri'] = [malicious_uris[0]]
                    mutated.data = urlencode(data, doseq=True)
            except:
                pass
        
        return mutated
    
    def _remove_csrf_mutation(self, request: HttpRequest) -> HttpRequest:
        """Remove CSRF tokens"""
        mutated = self._copy_request(request)
        
        csrf_params = ['csrf_token', 'authenticity_token', '_token', 'csrfmiddlewaretoken']
        
        # Remove from parameters
        for param in csrf_params:
            if param in mutated.params:
                del mutated.params[param]
        
        # Remove from headers
        csrf_headers = ['X-CSRF-Token', 'X-CSRFToken', 'X-Requested-With']
        for header in csrf_headers:
            if header in mutated.headers:
                del mutated.headers[header]
        
        # Remove from request body
        if mutated.data:
            try:
                if 'application/json' in mutated.headers.get('Content-Type', ''):
                    data = json.loads(mutated.data)
                    for param in csrf_params:
                        if param in data:
                            del data[param]
                    mutated.data = json.dumps(data)
                elif 'application/x-www-form-urlencoded' in mutated.headers.get('Content-Type', ''):
                    data = parse_qs(mutated.data)
                    for param in csrf_params:
                        if param in data:
                            del data[param]
                    mutated.data = urlencode(data, doseq=True)
            except:
                pass
        
        return mutated
    
    def _privilege_escalation_mutation(self, request: HttpRequest) -> HttpRequest:
        """Test for privilege escalation by modifying user IDs"""
        mutated = self._copy_request(request)
        
        # Common user ID parameters
        user_params = ['user_id', 'uid', 'id', 'account_id', 'customer_id']
        
        # Try to escalate to admin (ID 1) or other users
        escalation_values = ['1', '0', 'admin', '999999']
        
        for param in user_params:
            if param in mutated.params:
                mutated.params[param] = escalation_values[0]
        
        # Modify in request body
        if mutated.data:
            try:
                if 'application/json' in mutated.headers.get('Content-Type', ''):
                    data = json.loads(mutated.data)
                    for param in user_params:
                        if param in data:
                            data[param] = escalation_values[0]
                    mutated.data = json.dumps(data)
            except:
                pass
        
        return mutated
    
    def _copy_request(self, request: HttpRequest) -> HttpRequest:
        """Create a copy of the request for mutation"""
        return HttpRequest(
            method=request.method,
            url=request.url,
            headers=request.headers.copy(),
            data=request.data,
            params=request.params.copy(),
            cookies=request.cookies.copy(),
            auth=request.auth,
            timeout=request.timeout,
            allow_redirects=request.allow_redirects,
            verify=request.verify
        )
    
    def stop_test(self, test_id: str):
        """Stop an active test"""
        if test_id in self.active_tests:
            thread = self.active_tests[test_id]
            thread.stop()
            del self.active_tests[test_id]

class ReplayThread(QThread):
    """Thread for replaying authentication flows"""
    
    request_sent = pyqtSignal(str, dict)  # test_id, request_info
    replay_completed = pyqtSignal(str, dict)  # test_id, results
    vulnerability_found = pyqtSignal(str, dict)  # test_id, vuln_info
    
    def __init__(self, test_id: str, flow_data: dict, http_client: UnifiedHttpClient, mutations: List[str] = None):
        super().__init__()
        self.test_id = test_id
        self.flow_data = flow_data
        self.http_client = http_client
        self.mutations = mutations or []
        self.should_stop = False
        self.results = {
            'test_id': test_id,
            'start_time': time.time(),
            'requests_sent': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'vulnerabilities': [],
            'responses': []
        }
    
    def stop(self):
        """Stop the replay"""
        self.should_stop = True
    
    def run(self):
        """Run the replay test"""
        try:
            requests = self.flow_data.get('requests', [])
            
            for i, request_data in enumerate(requests):
                if self.should_stop:
                    break
                
                # Create HTTP request
                http_request = self._create_http_request(request_data)
                
                # Apply mutations if specified
                if self.mutations:
                    for mutation in self.mutations:
                        if hasattr(self.parent(), 'mutations') and mutation in self.parent().mutations:
                            http_request = self.parent().mutations[mutation](http_request)
                
                # Send request
                self.request_sent.emit(self.test_id, {
                    'sequence': i,
                    'method': http_request.method,
                    'url': http_request.url,
                    'mutation': self.mutations[0] if self.mutations else None
                })
                
                response = self.http_client.send_request(http_request)
                self.results['requests_sent'] += 1
                
                if response:
                    self.results['successful_requests'] += 1
                    self.results['responses'].append({
                        'sequence': i,
                        'status_code': response.status_code,
                        'url': response.url,
                        'response_time': response.elapsed_time,
                        'content_length': len(response.text)
                    })
                    
                    # Check for vulnerabilities
                    self._check_for_vulnerabilities(http_request, response, i)
                else:
                    self.results['failed_requests'] += 1
                
                # Small delay between requests
                time.sleep(0.5)
            
            self.results['end_time'] = time.time()
            self.results['duration'] = self.results['end_time'] - self.results['start_time']
            
            self.replay_completed.emit(self.test_id, self.results)
            
        except Exception as e:
            self.results['error'] = str(e)
            self.replay_completed.emit(self.test_id, self.results)
    
    def _create_http_request(self, request_data: dict) -> HttpRequest:
        """Create HttpRequest from recorded request data"""
        return HttpRequest(
            method=request_data.get('method', 'GET'),
            url=request_data.get('url', ''),
            headers=request_data.get('headers', {}),
            data=request_data.get('data', ''),
            params=request_data.get('params', {}),
            cookies=request_data.get('cookies', {}),
            timeout=30,
            allow_redirects=True,
            verify=True
        )
    
    def _check_for_vulnerabilities(self, request: HttpRequest, response: HttpResponse, sequence: int):
        """Check response for potential vulnerabilities"""
        vulnerabilities = []
        
        # Check for authentication bypass
        if self.mutations and 'remove_token' in self.mutations:
            if response.status_code == 200:
                vulnerabilities.append({
                    'type': 'authentication_bypass',
                    'severity': 'high',
                    'description': 'Request succeeded without authentication token',
                    'sequence': sequence,
                    'url': request.url,
                    'status_code': response.status_code
                })
        
        # Check for CSRF bypass
        if self.mutations and 'remove_csrf' in self.mutations:
            if response.status_code == 200 and request.method == 'POST':
                vulnerabilities.append({
                    'type': 'csrf_bypass',
                    'severity': 'medium',
                    'description': 'POST request succeeded without CSRF token',
                    'sequence': sequence,
                    'url': request.url,
                    'status_code': response.status_code
                })
        
        # Check for open redirect
        if self.mutations and 'modify_redirect_uri' in self.mutations:
            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location', '')
                if 'evil.com' in location or 'attacker.com' in location:
                    vulnerabilities.append({
                        'type': 'open_redirect',
                        'severity': 'medium',
                        'description': 'Application redirects to malicious URL',
                        'sequence': sequence,
                        'url': request.url,
                        'redirect_location': location
                    })
        
        # Check for privilege escalation
        if self.mutations and 'privilege_escalation' in self.mutations:
            if response.status_code == 200:
                # Simple check - in real implementation, would analyze response content
                if 'admin' in response.text.lower() or 'administrator' in response.text.lower():
                    vulnerabilities.append({
                        'type': 'privilege_escalation',
                        'severity': 'critical',
                        'description': 'Possible privilege escalation detected',
                        'sequence': sequence,
                        'url': request.url,
                        'status_code': response.status_code
                    })
        
        # Emit vulnerabilities found
        for vuln in vulnerabilities:
            self.vulnerability_found.emit(self.test_id, vuln)
            self.results['vulnerabilities'].append(vuln)