# app/tools/enterprise_fingerprint.py
import requests
import json
import hashlib
import ssl
import socket
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import base64

class EnterpriseFingerprinter:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 10
        self.device_db = self._load_device_db()
        self.default_creds = self._load_default_creds()
        
    def _load_device_db(self):
        """Load device fingerprint database"""
        try:
            import json
            import os
            
            db_path = os.path.join(os.path.dirname(__file__), '..', '..', 'resources', 'device_fingerprints.json')
            if os.path.exists(db_path):
                with open(db_path, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        
        # Fallback to embedded database
        return {
            "routers": {
                "tplink": {
                    "model_keys": ["modelName", "productModel", "model"],
                    "title_patterns": ["TP-Link", "Archer", "TL-"],
                    "cert_domains": ["tplinkmodem.net", "tplinkwifi.net"],
                    "favicon_hashes": [-370593630],
                    "server_patterns": ["TP-LINK", "lighttpd"]
                }
            }
        }
    
    def _load_default_creds(self):
        """Load default credentials database"""
        try:
            import json
            import os
            
            creds_path = os.path.join(os.path.dirname(__file__), '..', '..', 'resources', 'default_credentials.json')
            if os.path.exists(creds_path):
                with open(creds_path, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        
        # Fallback to embedded credentials
        return {
            "generic": [
                {"username": "admin", "password": "admin"},
                {"username": "admin", "password": "password"},
                {"username": "admin", "password": ""}
            ]
        }
    
    def comprehensive_fingerprint(self, target):
        """Perform comprehensive enterprise fingerprinting"""
        results = {
            "target": target,
            "fingerprint": {},
            "security_audit": {},
            "surface_index": {},
            "device_match": {},
            "vulnerabilities": []
        }
        
        # 1. Advanced Fingerprinting
        results["fingerprint"] = self._advanced_fingerprint(target)
        
        # 2. Security Audit
        results["security_audit"] = self._security_audit(target)
        
        # 3. Surface Indexing
        results["surface_index"] = self._index_surface(target)
        
        # 4. Custom DB Matching
        results["device_match"] = self._match_device_db(results["fingerprint"])
        
        # 5. Vulnerability Checks
        results["vulnerabilities"] = self._check_vulnerabilities(target, results)
        
        return results
    
    def _advanced_fingerprint(self, target):
        """Advanced fingerprinting using multiple methods"""
        fingerprint = {}
        
        try:
            response = self.session.get(target)
            
            # Server header
            fingerprint["server"] = response.headers.get("Server", "")
            
            # HTML analysis
            soup = BeautifulSoup(response.text, 'html.parser')
            fingerprint["title"] = soup.title.string if soup.title else ""
            
            # Meta tags and JS variables
            fingerprint["meta_info"] = self._extract_meta_info(soup)
            fingerprint["js_variables"] = self._extract_js_variables(response.text)
            
            # Favicon hash
            fingerprint["favicon_hash"] = self._get_favicon_hash(target)
            
            # TLS certificate
            fingerprint["tls_cert"] = self._get_tls_cert_info(target)
            
            # Cookie analysis
            fingerprint["cookies"] = self._analyze_cookies(response.cookies)
            
        except Exception as e:
            fingerprint["error"] = str(e)
        
        return fingerprint
    
    def _extract_meta_info(self, soup):
        """Extract meta information and JS model variables"""
        meta_info = {}
        
        # Meta tags
        for meta in soup.find_all('meta'):
            name = meta.get('name') or meta.get('property')
            content = meta.get('content')
            if name and content:
                meta_info[name] = content
        
        # Look for model information in scripts
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string:
                # Look for common model patterns
                patterns = [
                    r'modelName["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                    r'productModel["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                    r'model["\']?\s*[:=]\s*["\']([^"\']+)["\']'
                ]
                for pattern in patterns:
                    matches = re.findall(pattern, script.string, re.IGNORECASE)
                    if matches:
                        meta_info['detected_model'] = matches[0]
                        break
        
        return meta_info
    
    def _extract_js_variables(self, content):
        """Extract JavaScript variables that might contain device info"""
        js_vars = {}
        
        patterns = {
            'modelName': r'modelName["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            'productModel': r'productModel["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            'firmwareVersion': r'firmwareVersion["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            'hardwareVersion': r'hardwareVersion["\']?\s*[:=]\s*["\']([^"\']+)["\']'
        }
        
        for var_name, pattern in patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                js_vars[var_name] = matches[0]
        
        return js_vars
    
    def _get_favicon_hash(self, target):
        """Get favicon hash for device identification"""
        try:
            favicon_url = urljoin(target, '/favicon.ico')
            response = self.session.get(favicon_url)
            if response.status_code == 200:
                # Use mmh3 hash if available, otherwise use simple hash
                try:
                    import mmh3
                    return mmh3.hash(response.content)
                except ImportError:
                    return hash(response.content)
        except:
            pass
        return None
    
    def _get_tls_cert_info(self, target):
        """Extract TLS certificate information"""
        cert_info = {}
        try:
            parsed = urlparse(target)
            if parsed.scheme == 'https':
                hostname = parsed.hostname
                port = parsed.port or 443
                
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((hostname, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        
                        cert_info['subject'] = dict(x[0] for x in cert.get('subject', []))
                        cert_info['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                        cert_info['san'] = []
                        
                        # Extract SAN domains
                        for ext in cert.get('subjectAltName', []):
                            if ext[0] == 'DNS':
                                cert_info['san'].append(ext[1])
        except:
            pass
        return cert_info
    
    def _analyze_cookies(self, cookies):
        """Analyze cookies for technology indicators"""
        cookie_info = {}
        for cookie in cookies:
            cookie_info[cookie.name] = {
                'value': cookie.value[:50] + '...' if len(cookie.value) > 50 else cookie.value,
                'secure': cookie.secure,
                'httponly': cookie.has_nonstandard_attr('HttpOnly')
            }
        return cookie_info
    
    def _security_audit(self, target):
        """Comprehensive security audit"""
        audit = {}
        
        try:
            response = self.session.get(target)
            
            # Security headers check
            audit["security_headers"] = self._check_security_headers(response.headers)
            
            # TLS configuration
            audit["tls_config"] = self._check_tls_config(target)
            
            # HTTP methods
            audit["http_methods"] = self._check_http_methods(target)
            
            # Default credentials test
            audit["default_creds"] = self._test_default_creds(target)
            
            # Known vulnerabilities
            audit["known_vulns"] = self._check_known_vulns(target, response)
            
        except Exception as e:
            audit["error"] = str(e)
        
        return audit
    
    def _check_security_headers(self, headers):
        """Check for security headers"""
        security_headers = {
            'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
            'X-Frame-Options': headers.get('X-Frame-Options'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
            'Content-Security-Policy': headers.get('Content-Security-Policy'),
            'X-XSS-Protection': headers.get('X-XSS-Protection'),
            'Referrer-Policy': headers.get('Referrer-Policy')
        }
        
        # Score security posture
        present = sum(1 for v in security_headers.values() if v)
        total = len(security_headers)
        security_headers['score'] = f"{present}/{total}"
        
        return security_headers
    
    def _check_tls_config(self, target):
        """Check TLS configuration"""
        tls_config = {}
        try:
            parsed = urlparse(target)
            if parsed.scheme == 'https':
                hostname = parsed.hostname
                port = parsed.port or 443
                
                # Check TLS versions
                for version in [ssl.PROTOCOL_TLSv1, ssl.PROTOCOL_TLSv1_1, ssl.PROTOCOL_TLSv1_2]:
                    try:
                        context = ssl.SSLContext(version)
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        
                        with socket.create_connection((hostname, port), timeout=5) as sock:
                            with context.wrap_socket(sock) as ssock:
                                tls_config[f'TLS_{version}'] = True
                    except:
                        tls_config[f'TLS_{version}'] = False
        except:
            pass
        return tls_config
    
    def _check_http_methods(self, target):
        """Check allowed HTTP methods"""
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE', 'PATCH']
        allowed_methods = []
        
        for method in methods:
            try:
                response = self.session.request(method, target, timeout=5)
                if response.status_code not in [405, 501]:
                    allowed_methods.append(method)
            except:
                pass
        
        return allowed_methods
    
    def _test_default_creds(self, target):
        """Test for blank/empty credentials vulnerability"""
        cred_results = []
        
        # Test only for blank credentials vulnerability
        blank_creds = [
            {'username': 'admin', 'password': ''},
            {'username': '', 'password': ''},
            {'username': 'root', 'password': ''}
        ]
        
        # Try HTTP Basic Auth with blank credentials
        for cred in blank_creds:
            try:
                response = self.session.get(
                    target, 
                    auth=(cred['username'], cred['password']),
                    timeout=5
                )
                if response.status_code == 200:
                    cred_results.append({
                        'vendor': 'generic',
                        'username': cred['username'] or '(blank)',
                        'password': '(blank)',
                        'success': True
                    })
                    break  # Stop after first successful blank credential
            except:
                pass
        
        return cred_results
    
    def _check_known_vulns(self, target, response):
        """Check for known vulnerabilities"""
        vulns = []
        
        # Check for common vulnerability indicators
        if 'TRACE' in self._check_http_methods(target):
            vulns.append({
                'type': 'HTTP TRACE Enabled',
                'severity': 'Medium',
                'description': 'HTTP TRACE method is enabled, potential for XST attacks'
            })
        
        # Check for directory traversal
        try:
            test_response = self.session.get(f"{target}/../../../etc/passwd", timeout=5)
            if 'root:' in test_response.text:
                vulns.append({
                    'type': 'Directory Traversal',
                    'severity': 'High',
                    'description': 'Possible directory traversal vulnerability'
                })
        except:
            pass
        
        return vulns
    
    def _index_surface(self, target):
        """Index accessible surface with catchall detection"""
        surface = {
            'routes': [],
            'login_portals': [],
            'apis': [],
            'admin_panels': []
        }
        
        # Detect catchall responses first
        catchall_responses = []
        try:
            for i in range(3):  # Test 3 random paths
                import random
                import string
                random_path = '/' + ''.join(random.choices(string.ascii_lowercase, k=15))
                test_url = urljoin(target, random_path)
                test_response = self.session.get(test_url, timeout=5, allow_redirects=False)
                if test_response.status_code in [200, 301, 302]:
                    catchall_responses.append({
                        'status': test_response.status_code,
                        'length': len(test_response.content),
                        'content_hash': hash(test_response.content[:1000])
                    })
            
            # Temporarily disable catchall detection for debugging
            # if len(catchall_responses) >= 2:  # If 2+ random paths return redirects, likely catchall
            #     return surface  # Return empty surface to avoid false positives
        except:
            pass
        
        # Common paths to check
        common_paths = [
            '/admin', '/login', '/user', '/cgi-bin/', '/setup', '/config',
            '/status', '/web', '/manager', '/api', '/v1', '/v2',
            '/dashboard', '/panel', '/control', '/system', '/invite',
            '/register', '/signup', '/auth', '/oauth', '/token',
            '/graphql', '/rest', '/endpoint', '/service'
        ]
        
        for path in common_paths:
            try:
                url = urljoin(target, path)
                response = self.session.get(url, timeout=5, allow_redirects=False)
                
                if response.status_code in [200, 301, 302, 401, 403]:
                    # Filter catchall responses
                    is_catchall = False
                    if catchall_responses:
                        response_length = len(response.content)
                        response_hash = hash(response.content[:1000])
                        
                        for catchall in catchall_responses:
                            if (response.status_code == catchall['status'] and 
                                abs(response_length - catchall['length']) < 200 and 
                                response_hash == catchall['content_hash']):
                                is_catchall = True
                                break
                    
                    if not is_catchall:
                        route_info = {
                            'path': path,
                            'status': response.status_code,
                            'length': len(response.content),
                            'type': self._classify_endpoint(path, response)
                        }
                        
                        surface['routes'].append(route_info)
                        
                        # Classify by type
                        if route_info['type'] == 'login':
                            surface['login_portals'].append(route_info)
                        elif route_info['type'] == 'api':
                            surface['apis'].append(route_info)
                        elif route_info['type'] == 'admin':
                            surface['admin_panels'].append(route_info)
            except:
                pass
        
        return surface
    
    def _classify_endpoint(self, path, response):
        """Classify endpoint type"""
        path_lower = path.lower()
        
        if any(keyword in path_lower for keyword in ['login', 'signin', 'auth']):
            return 'login'
        elif any(keyword in path_lower for keyword in ['admin', 'panel', 'dashboard', 'control']):
            return 'admin'
        elif any(keyword in path_lower for keyword in ['api', 'v1', 'v2', 'rest']):
            return 'api'
        elif response.status_code == 401:
            return 'protected'
        else:
            return 'general'
    
    def _match_device_db(self, fingerprint):
        """Match against device database"""
        matches = []
        
        # Flatten the database structure for easier matching
        for category, devices in self.device_db.items():
            for vendor, db_entry in devices.items():
                score = 0
                match_details = {}
                
                # Check server header
                if fingerprint.get('server'):
                    for pattern in db_entry.get('server_patterns', []):
                        if pattern.lower() in fingerprint['server'].lower():
                            score += 3
                            match_details['server_match'] = pattern
                
                # Check title
                if fingerprint.get('title'):
                    for pattern in db_entry.get('title_patterns', []):
                        if pattern.lower() in fingerprint['title'].lower():
                            score += 2
                            match_details['title_match'] = pattern
                
                # Check favicon hash
                if fingerprint.get('favicon_hash'):
                    for hash_val in db_entry.get('favicon_hashes', []):
                        if fingerprint['favicon_hash'] == hash_val:
                            score += 5
                            match_details['favicon_match'] = True
                            break
                
                # Check TLS certificate domains
                if fingerprint.get('tls_cert', {}).get('san'):
                    for domain in fingerprint['tls_cert']['san']:
                        for cert_domain in db_entry.get('cert_domains', []):
                            if cert_domain in domain:
                                score += 4
                                match_details['cert_match'] = cert_domain
                
                # Check JS variables for model info
                js_vars = fingerprint.get('js_variables', {})
                for model_key in db_entry.get('model_keys', []):
                    if model_key in js_vars:
                        score += 3
                        match_details['model_detected'] = js_vars[model_key]
                
                if score > 0:
                    matches.append({
                        'category': category,
                        'vendor': vendor,
                        'score': score,
                        'confidence': min(score * 10, 100),
                        'details': match_details,
                        'vulnerabilities': db_entry.get('vulnerabilities', [])
                    })
        
        # Sort by score
        matches.sort(key=lambda x: x['score'], reverse=True)
        return matches
    
    def _check_vulnerabilities(self, target, results):
        """Check for specific vulnerabilities based on fingerprint"""
        vulnerabilities = []
        
        # Check based on device matches
        for match in results.get('device_match', []):
            vendor = match['vendor']
            
            # Add vendor-specific vulnerability checks
            if vendor == 'tplink':
                vulnerabilities.extend(self._check_tplink_vulns(target))
            elif vendor == 'netgear':
                vulnerabilities.extend(self._check_netgear_vulns(target))
        
        # Generic vulnerability checks
        vulnerabilities.extend(self._check_generic_vulns(target, results))
        
        return vulnerabilities
    
    def _check_tplink_vulns(self, target):
        """Check TP-Link specific vulnerabilities"""
        vulns = []
        
        # Check for known TP-Link vulnerabilities
        test_paths = [
            '/cgi-bin/luci/admin/system/admin',
            '/cgi-bin/luci',
            '/userRpm/LoginRpm.htm'
        ]
        
        for path in test_paths:
            try:
                response = self.session.get(urljoin(target, path), timeout=5)
                if response.status_code == 200:
                    vulns.append({
                        'type': 'TP-Link Admin Interface',
                        'severity': 'Medium',
                        'path': path,
                        'description': 'TP-Link admin interface accessible'
                    })
            except:
                pass
        
        return vulns
    
    def _check_netgear_vulns(self, target):
        """Check Netgear specific vulnerabilities"""
        vulns = []
        
        # Check for Netgear vulnerabilities
        test_paths = [
            '/setup.cgi',
            '/currentsetting.htm',
            '/passwordrecovered.cgi'
        ]
        
        for path in test_paths:
            try:
                response = self.session.get(urljoin(target, path), timeout=5)
                if response.status_code == 200:
                    vulns.append({
                        'type': 'Netgear Interface',
                        'severity': 'Medium',
                        'path': path,
                        'description': 'Netgear interface accessible'
                    })
            except:
                pass
        
        return vulns
    
    def _check_generic_vulns(self, target, results):
        """Check for generic vulnerabilities"""
        vulns = []
        
        # Check for weak security headers
        security_headers = results.get('security_audit', {}).get('security_headers', {})
        missing_headers = [k for k, v in security_headers.items() if not v and k != 'score']
        
        if len(missing_headers) > 3:
            vulns.append({
                'type': 'Missing Security Headers',
                'severity': 'Medium',
                'description': f'Missing {len(missing_headers)} security headers'
            })
        
        # Check for default credentials
        default_creds = results.get('security_audit', {}).get('default_creds', [])
        if default_creds:
            vulns.append({
                'type': 'Default Credentials',
                'severity': 'High',
                'description': 'Default credentials are still active'
            })
        
        return vulns