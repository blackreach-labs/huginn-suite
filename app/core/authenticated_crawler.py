# app/core/authenticated_crawler.py
import requests
import re
import json
import time
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from typing import Dict, List, Optional, Tuple, Any
from PyQt6.QtCore import QObject, pyqtSignal
from .secure_credential_manager import secure_credential_manager
from .session_manager import session_manager
from .connection_pool import connection_pool
from app.core.logger import logger

class AuthenticatedCrawler(QObject):
    """Enhanced crawler with authentication support"""
    
    # Signals for real-time updates
    auth_success = pyqtSignal(str, dict)  # method, credentials
    auth_failed = pyqtSignal(str, str)    # method, error
    page_crawled = pyqtSignal(str, dict)  # url, page_data
    token_extracted = pyqtSignal(str, str, str)  # token_type, token_value, source
    
    def __init__(self):
        super().__init__()
        self.session = connection_pool.get_session("authenticated_crawler")
        self.authenticated = False
        self.auth_tokens = {}
        self.csrf_tokens = {}
        self.visited_urls = set()
        self.crawled_data = {}
        self._post_login_url = None  # Captured after successful form login redirect
        
    def authenticate(self, target_url: str, auth_method: str = "auto", 
                    username: str = "", password: str = "", 
                    custom_headers: Dict = None, cookies: Dict = None) -> bool:
        """Authenticate with the target application"""
        
        if auth_method == "auto":
            return self._auto_authenticate(target_url, username, password)
        elif auth_method == "session_replay":
            return self._session_replay(target_url, cookies or {})
        elif auth_method == "header_auth":
            return self._header_authentication(target_url, custom_headers or {})
        elif auth_method == "form_login":
            return self._form_login(target_url, username, password)
        elif auth_method == "basic_auth":
            return self._basic_auth(target_url, username, password)
        
        return False
    
    def _auto_authenticate(self, target_url: str, username: str = "", password: str = "") -> bool:
        """Automatically detect and attempt authentication"""
        
        # Try session replay first if we have cookies
        if self.session.cookies:
            if self._session_replay(target_url, dict(self.session.cookies)):
                return True
        
        # Try form-based login
        if username and password:
            if self._form_login(target_url, username, password):
                return True
        
        # Try stored credentials from secure manager
        for service in secure_credential_manager.list_services():
            cred = secure_credential_manager.get_credential(service)
            if cred and cred.username and cred.password:
                if self._form_login(target_url, cred.username, cred.password):
                    return True
        
        return False
    
    def _session_replay(self, target_url: str, cookies: Dict) -> bool:
        """Authenticate using session cookies"""
        try:
            # Set cookies in session
            for name, value in cookies.items():
                self.session.cookies.set(name, value)
            
            # Test authentication by accessing a protected page
            response = self.session.get(target_url, timeout=10)
            
            # Check if we're authenticated (not redirected to login)
            if self._is_authenticated_response(response):
                self.authenticated = True
                self.auth_tokens.update(cookies)
                self.auth_success.emit("session_replay", cookies)
                return True
                
        except Exception as e:
            self.auth_failed.emit("session_replay", str(e))
        
        return False
    
    def _header_authentication(self, target_url: str, headers: Dict) -> bool:
        """Authenticate using custom headers (API keys, Bearer tokens)"""
        try:
            # Update session headers
            self.session.headers.update(headers)
            
            # Test authentication
            response = self.session.get(target_url, timeout=10)
            
            if self._is_authenticated_response(response):
                self.authenticated = True
                self.auth_tokens.update(headers)
                self.auth_success.emit("header_auth", headers)
                return True
                
        except Exception as e:
            self.auth_failed.emit("header_auth", str(e))
        
        return False
    
    def _form_login(self, target_url: str, username: str, password: str) -> bool:
        """Authenticate using form-based login"""
        try:
            # Find login form
            login_form = self._find_login_form(target_url)
            if not login_form:
                # Fallback: try common JSON login patterns
                return self._try_json_login(target_url, username, password)
            
            # Extract CSRF token if present
            csrf_token = self._extract_csrf_token(login_form['page_content'])
            
            # Prepare login data
            login_data = {
                login_form['username_field']: username,
                login_form['password_field']: password
            }
            
            # Add CSRF token if found
            if csrf_token:
                login_data[csrf_token['name']] = csrf_token['value']
                self.csrf_tokens[csrf_token['name']] = csrf_token['value']
            
            # Include any other hidden fields from the form (some apps require them)
            for hidden_field in login_form.get('hidden_fields', {}):
                if hidden_field not in login_data:
                    login_data[hidden_field] = login_form['hidden_fields'][hidden_field]
            
            # Submit login form
            response = self.session.post(
                login_form['action_url'],
                data=login_data,
                timeout=10,
                allow_redirects=True
            )
            
            # Check if login was successful
            if self._is_authenticated_response(response):
                self.authenticated = True
                
                # Capture the post-login landing URL (where the app redirected after login)
                # This is typically the authenticated area entry point (e.g. /admin/dashboard)
                if response.url and response.url != login_form['action_url']:
                    self._post_login_url = response.url
                
                # Extract session tokens from cookies
                for cookie in self.session.cookies:
                    self.auth_tokens[cookie.name] = cookie.value
                
                # Store successful credentials in secure manager
                secure_credential_manager.store_credential(
                    service="web_login",
                    username=username,
                    password=password,
                    source="authenticated_crawler"
                )
                
                self.auth_success.emit("form_login", {
                    'username': username,
                    'password': password,
                    'tokens': self.auth_tokens
                })
                return True
            
            # If form POST didn't work, try JSON login as fallback
            return self._try_json_login(target_url, username, password)
                
        except Exception as e:
            self.auth_failed.emit("form_login", str(e))
        
        return False
    
    def _try_json_login(self, target_url: str, username: str, password: str) -> bool:
        """Try JSON-based login (common in modern web apps / SPAs)"""
        try:
            from urllib.parse import urlparse, urljoin
            parsed = urlparse(target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            path = parsed.path.rstrip('/')
            
            # Common JSON login payload patterns
            json_payloads = [
                {"email": username, "password": password},
                {"username": username, "password": password},
                {"user": username, "password": password},
                {"identifier": username, "password": password},
                {"login": username, "password": password},
            ]
            
            # Build list of login endpoints to try, ordered by likelihood
            login_endpoints = []
            
            # First: try the target URL itself as a JSON endpoint (user specified it)
            login_endpoints.append(target_url)
            
            # Second: try API-prefixed variants of the path
            if path:
                # e.g. /signin -> /api/v1/users/signin, /api/v1/auth/signin
                path_base = path.split('/')[-1]  # e.g. "signin" from "/signin"
                login_endpoints.append(urljoin(base_url, f"/api/v1/users/{path_base}"))
                login_endpoints.append(urljoin(base_url, f"/api/v1/auth/{path_base}"))
                login_endpoints.append(urljoin(base_url, f"/api/v1/{path_base}"))
                login_endpoints.append(urljoin(base_url, f"/api/users/{path_base}"))
                login_endpoints.append(urljoin(base_url, f"/api/auth/{path_base}"))
                login_endpoints.append(urljoin(base_url, f"/api/{path_base}"))
            
            # Third: common API login endpoints
            login_endpoints.extend([
                urljoin(base_url, "/api/v1/users/signin"),
                urljoin(base_url, "/api/v1/users/login"),
                urljoin(base_url, "/api/v1/auth/login"),
                urljoin(base_url, "/api/v1/auth/signin"),
                urljoin(base_url, "/api/v1/login"),
                urljoin(base_url, "/api/v1/signin"),
                urljoin(base_url, "/api/auth/login"),
                urljoin(base_url, "/api/auth/signin"),
                urljoin(base_url, "/api/login"),
                urljoin(base_url, "/api/signin"),
                urljoin(base_url, "/auth/login"),
                urljoin(base_url, "/auth/signin"),
            ])
            
            # Deduplicate while preserving order
            seen = set()
            unique_endpoints = []
            for ep in login_endpoints:
                if ep not in seen:
                    seen.add(ep)
                    unique_endpoints.append(ep)
            
            for endpoint in unique_endpoints:
                for payload in json_payloads:
                    try:
                        response = self.session.post(
                            endpoint,
                            json=payload,
                            timeout=10,
                            allow_redirects=True
                        )
                        
                        # Skip non-existent endpoints
                        if response.status_code in (404, 405):
                            break  # No point trying other payloads for this endpoint
                        
                        # Skip bad request / unauthorized - try next payload
                        if response.status_code in (400, 401, 403):
                            continue
                        
                        # Check for successful response
                        if response.status_code in (200, 201, 302):
                            # Check if we got session cookies
                            has_cookies = len(self.session.cookies) > 0
                            
                            # Check for token in JSON response body
                            got_token = False
                            try:
                                resp_json = response.json()
                                # Check for error responses
                                if isinstance(resp_json, dict):
                                    error_keys = ('error', 'message', 'msg')
                                    for ek in error_keys:
                                        if ek in resp_json:
                                            err_val = str(resp_json[ek]).lower()
                                            if any(w in err_val for w in ('invalid', 'incorrect', 'unauthorized', 'failed', 'wrong')):
                                                break
                                    else:
                                        # No error found, check for tokens
                                        for key in ('token', 'access_token', 'accessToken', 'jwt', 
                                                   'session_token', 'id_token', 'auth_token'):
                                            if key in resp_json:
                                                self.session.headers['Authorization'] = f"Bearer {resp_json[key]}"
                                                self.auth_tokens[key] = resp_json[key]
                                                got_token = True
                                                break
                                        
                                        # Some APIs nest the token
                                        if not got_token and 'data' in resp_json and isinstance(resp_json['data'], dict):
                                            for key in ('token', 'access_token', 'accessToken'):
                                                if key in resp_json['data']:
                                                    self.session.headers['Authorization'] = f"Bearer {resp_json['data'][key]}"
                                                    self.auth_tokens[key] = resp_json['data'][key]
                                                    got_token = True
                                                    break
                            except (ValueError, KeyError):
                                pass
                            
                            if has_cookies or got_token:
                                self.authenticated = True
                                for cookie in self.session.cookies:
                                    self.auth_tokens[cookie.name] = cookie.value
                                
                                self.auth_success.emit("form_login", {
                                    'username': username,
                                    'password': password,
                                    'tokens': self.auth_tokens,
                                    'endpoint': endpoint
                                })
                                return True
                            
                            # 200 response with no error message might still be success
                            if response.status_code == 200 and has_cookies:
                                self.authenticated = True
                                for cookie in self.session.cookies:
                                    self.auth_tokens[cookie.name] = cookie.value
                                self.auth_success.emit("form_login", {
                                    'username': username,
                                    'password': password,
                                    'tokens': self.auth_tokens,
                                    'endpoint': endpoint
                                })
                                return True
                                
                    except Exception:
                        continue
            
        except Exception as e:
            logger.debug(f"JSON login attempt failed: {e}")
        
        return False
    
    def _basic_auth(self, target_url: str, username: str, password: str) -> bool:
        """Authenticate using HTTP Basic Auth"""
        try:
            self.session.auth = (username, password)
            response = self.session.get(target_url, timeout=10)
            
            if response.status_code != 401:
                self.authenticated = True
                self.auth_tokens['basic_auth'] = f"{username}:{password}"
                self.auth_success.emit("basic_auth", {
                    'username': username,
                    'password': password
                })
                return True
                
        except Exception as e:
            self.auth_failed.emit("basic_auth", str(e))
        
        return False
    
    def _find_login_form(self, target_url: str) -> Optional[Dict]:
        """Find login form on the page"""
        try:
            response = self.session.get(target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Look for forms with password fields
            forms = soup.find_all('form')
            for form in forms:
                password_fields = form.find_all('input', {'type': 'password'})
                if password_fields:
                    # Found a form with password field
                    action = form.get('action', '')
                    action_url = urljoin(target_url, action) if action else target_url
                    
                    # Find username/email field using multiple strategies
                    username_field = None
                    
                    # Strategy 1: Check name attribute against common patterns
                    username_patterns = ['username', 'user', 'email', 'login', 'userid', 
                                        'identifier', 'account', 'mail', 'uname']
                    for pattern in username_patterns:
                        field = form.find('input', {'name': re.compile(pattern, re.I)})
                        if field and field.get('type', '').lower() != 'hidden':
                            username_field = field.get('name')
                            break
                    
                    # Strategy 2: Check id attribute against common patterns
                    if not username_field:
                        for pattern in username_patterns:
                            field = form.find('input', {'id': re.compile(pattern, re.I)})
                            if field and field.get('type', '').lower() != 'hidden':
                                username_field = field.get('name') or field.get('id')
                                break
                    
                    # Strategy 3: Check placeholder text
                    if not username_field:
                        placeholder_patterns = ['email', 'username', 'user', 'login', 'account']
                        for inp in form.find_all('input'):
                            inp_type = inp.get('type', '').lower()
                            if inp_type in ('text', 'email', 'tel', ''):
                                placeholder = (inp.get('placeholder') or '').lower()
                                if any(p in placeholder for p in placeholder_patterns):
                                    username_field = inp.get('name') or inp.get('id')
                                    break
                    
                    # Strategy 4: Find email type input
                    if not username_field:
                        email_inputs = form.find_all('input', {'type': 'email'})
                        if email_inputs:
                            username_field = email_inputs[0].get('name') or email_inputs[0].get('id')
                    
                    # Strategy 5: Find text/email input that appears before the password field
                    if not username_field:
                        all_inputs = form.find_all('input')
                        for inp in all_inputs:
                            inp_type = inp.get('type', 'text').lower()
                            if inp_type in ('text', 'email', 'tel'):
                                username_field = inp.get('name') or inp.get('id')
                                break
                    
                    # Collect hidden fields (for CSRF tokens, etc.)
                    hidden_fields = {}
                    for hidden in form.find_all('input', {'type': 'hidden'}):
                        name = hidden.get('name')
                        value = hidden.get('value', '')
                        if name:
                            hidden_fields[name] = value
                    
                    if username_field:
                        password_field_name = password_fields[0].get('name') or password_fields[0].get('id') or 'password'
                        return {
                            'action_url': action_url,
                            'username_field': username_field,
                            'password_field': password_field_name,
                            'hidden_fields': hidden_fields,
                            'page_content': response.text
                        }
            
            # Fallback: no form tag found, but page might use JavaScript forms
            # Look for any password input on the page (outside of form tags)
            password_inputs = soup.find_all('input', {'type': 'password'})
            if password_inputs:
                # Try to find a nearby email/text input
                all_inputs = soup.find_all('input')
                username_field = None
                for inp in all_inputs:
                    inp_type = inp.get('type', 'text').lower()
                    if inp_type in ('text', 'email', 'tel'):
                        username_field = inp.get('name') or inp.get('id')
                        break
                
                if username_field:
                    password_field_name = password_inputs[0].get('name') or password_inputs[0].get('id') or 'password'
                    return {
                        'action_url': target_url,
                        'username_field': username_field,
                        'password_field': password_field_name,
                        'hidden_fields': {},
                        'page_content': response.text
                    }
            
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        
        return None
    
    def _extract_csrf_token(self, html_content: str) -> Optional[Dict]:
        """Extract CSRF token from HTML"""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Common CSRF token patterns
            csrf_patterns = [
                {'name': re.compile(r'csrf', re.I), 'type': 'hidden'},
                {'name': re.compile(r'_token', re.I), 'type': 'hidden'},
                {'name': re.compile(r'authenticity_token', re.I), 'type': 'hidden'},
            ]
            
            for pattern in csrf_patterns:
                token_input = soup.find('input', pattern)
                if token_input and token_input.get('value'):
                    return {
                        'name': token_input.get('name'),
                        'value': token_input.get('value')
                    }
            
            # Check meta tags
            meta_csrf = soup.find('meta', {'name': re.compile(r'csrf', re.I)})
            if meta_csrf and meta_csrf.get('content'):
                return {
                    'name': meta_csrf.get('name'),
                    'value': meta_csrf.get('content')
                }
            
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        
        return None
    
    def _is_authenticated_response(self, response) -> bool:
        """Check if response indicates successful authentication"""
        # Check status code
        if response.status_code == 401:
            return False
        
        # Check for login redirects (being redirected BACK to login = failed)
        if response.status_code in [302, 303, 307, 308]:
            location = response.headers.get('Location', '').lower()
            if any(keyword in location for keyword in ['login', 'signin', 'auth']):
                return False
        
        # If we got session cookies set, that's a strong indicator of success
        if self.session.cookies:
            session_cookie_names = ['session', 'sess', 'sid', 'token', 'auth', 'jwt', 'connect.sid',
                                    'PHPSESSID', 'JSESSIONID', 'laravel_session', '_session']
            for cookie in self.session.cookies:
                cookie_lower = cookie.name.lower()
                if any(pattern in cookie_lower for pattern in session_cookie_names):
                    return True
        
        # Check response content for authentication indicators
        content_lower = response.text.lower()
        
        # Strong positive indicators (we're logged in)
        positive_indicators = ['logout', 'sign out', 'signout', 'log out', 'dashboard', 
                              'profile', 'my account', 'welcome back', 'logged in',
                              'signed in successfully', 'authentication successful']
        if any(indicator in content_lower for indicator in positive_indicators):
            return True
        
        # Strong negative indicators (we're still on a login page)
        # Only count as failed if the page is clearly a login form
        negative_indicators = ['invalid credentials', 'login failed', 'incorrect password',
                              'authentication failed', 'invalid username', 'invalid email',
                              'wrong password', 'access denied', 'unauthorized']
        if any(indicator in content_lower for indicator in negative_indicators):
            return False
        
        # If response is a redirect to a non-login page, likely successful
        if response.history:
            final_url = response.url.lower()
            login_url_patterns = ['login', 'signin', 'sign-in', 'auth/login']
            if not any(pattern in final_url for pattern in login_url_patterns):
                return True
        
        # If status is 200 and we have cookies, assume success
        if response.status_code == 200 and len(self.session.cookies) > 0:
            return True
        
        # Default: if we got a 200 with no clear login failure indicators, assume success
        if response.status_code == 200:
            return True
        
        return False
    
    def crawl_authenticated(self, target_url: str, max_depth: int = 3, 
                          max_pages: int = 100) -> Dict:
        """Crawl website with authentication"""
        
        if not self.authenticated:
            raise Exception("Not authenticated. Call authenticate() first.")
        
        self.visited_urls.clear()
        self.crawled_data.clear()
        
        base_domain = urlparse(target_url).netloc
        
        # Start crawling from the main target
        self._crawl_recursive_authenticated(target_url, base_domain, 0, max_depth, max_pages)
        
        # Also crawl from the post-login landing page if it differs from target
        # This ensures authenticated-only areas (e.g. /admin/dashboard) are discovered
        if self._post_login_url:
            parsed_post_login = urlparse(self._post_login_url)
            if (self._post_login_url not in self.visited_urls and
                parsed_post_login.netloc == base_domain):
                self._crawl_recursive_authenticated(
                    self._post_login_url, base_domain, 0, max_depth, max_pages)
            
            # Seed from the parent path of the post-login URL as well
            # e.g. if post-login lands on /admin/dashboard, also try /admin/
            parent_path = parsed_post_login.path.rsplit('/', 1)[0]
            if parent_path and parent_path != '/':
                parent_url = f"{parsed_post_login.scheme}://{parsed_post_login.netloc}{parent_path}"
                if parent_url not in self.visited_urls:
                    self._crawl_recursive_authenticated(
                        parent_url, base_domain, 0, max_depth, max_pages)
        
        return self.crawled_data
    
    def _crawl_recursive_authenticated(self, url: str, base_domain: str, 
                                     depth: int, max_depth: int, max_pages: int):
        """Recursively crawl with authentication"""
        
        if (depth > max_depth or 
            len(self.visited_urls) >= max_pages or 
            url in self.visited_urls):
            return
        
        try:
            parsed_url = urlparse(url)
            if parsed_url.netloc != base_domain:
                return
            
            self.visited_urls.add(url)
            
            # Make authenticated request
            response = self.session.get(url, timeout=10)
            
            # Extract authentication artifacts
            auth_artifacts = self._extract_auth_artifacts(response)
            
            # Store page data
            page_data = {
                'url': url,
                'status_code': response.status_code,
                'title': self._extract_title(response.text),
                'content_type': response.headers.get('Content-Type', ''),
                'content_length': len(response.content),
                'links': [],
                'forms': [],
                'auth_artifacts': auth_artifacts,
                'depth': depth,
                'authenticated': True
            }
            
            if response.status_code == 200 and 'text/html' in response.headers.get('Content-Type', ''):
                page_data['links'] = self._extract_links(response.text, url)
                page_data['forms'] = self._extract_forms_with_auth(response.text, url)
                
                # SPA detection: if this is the root page and we found very few HTML links
                # but there are JS bundles, try to discover SPA routes from the JS
                if depth == 0 and len(page_data['links']) <= 3:
                    spa_routes = self._discover_spa_routes(response.text, url, base_domain)
                    if spa_routes:
                        page_data['links'].extend(spa_routes)
                        page_data['spa_detected'] = True
                
                # Also discover API endpoints if authenticated
                if depth == 0 and self.authenticated:
                    api_endpoints = self._discover_api_endpoints(url, base_domain)
                    if api_endpoints:
                        page_data['api_endpoints'] = api_endpoints
                        # Add API endpoints as links to crawl
                        page_data['links'].extend(api_endpoints)
                
                # Continue crawling found links
                for link in page_data['links'][:30]:
                    if len(self.visited_urls) < max_pages:
                        self._crawl_recursive_authenticated(link, base_domain, depth + 1, max_depth, max_pages)
            
            # Handle JSON API responses
            elif response.status_code == 200 and 'application/json' in response.headers.get('Content-Type', ''):
                try:
                    json_data = response.json()
                    page_data['json_data'] = json_data
                    page_data['content_type'] = 'application/json'
                    # Extract URLs from JSON responses
                    json_links = self._extract_links_from_json(json_data, url)
                    page_data['links'] = json_links
                except (ValueError, KeyError):
                    pass
            
            self.crawled_data[url] = page_data
            self.page_crawled.emit(url, page_data)
            
        except Exception as e:
            self.crawled_data[url] = {
                'url': url,
                'error': str(e),
                'depth': depth,
                'authenticated': True
            }
    
    def _discover_spa_routes(self, html_content: str, base_url: str, base_domain: str) -> List[str]:
        """Discover routes from SPA JavaScript bundles"""
        routes = []
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            parsed_base = urlparse(base_url)
            base = f"{parsed_base.scheme}://{parsed_base.netloc}"
            
            # Find JS bundle URLs
            js_urls = []
            for script in soup.find_all('script', src=True):
                src = script['src']
                if src.endswith('.js') and ('index' in src or 'main' in src or 'app' in src or 'chunk' in src):
                    js_urls.append(urljoin(base_url, src))
            
            # Download and parse JS bundles for route patterns
            for js_url in js_urls[:3]:  # Limit to 3 bundles
                try:
                    js_response = self.session.get(js_url, timeout=15)
                    if js_response.status_code == 200:
                        js_content = js_response.text
                        
                        # Extract route paths from common SPA patterns
                        # React Router: path: "/dashboard", path: "/chatflows"
                        route_patterns = [
                            re.compile(r'path:\s*["\'](/[a-zA-Z0-9_\-/]+)["\']'),
                            re.compile(r'to:\s*["\'](/[a-zA-Z0-9_\-/]+)["\']'),
                            re.compile(r'navigate\(["\'](/[a-zA-Z0-9_\-/]+)["\']'),
                            re.compile(r'href:\s*["\'](/[a-zA-Z0-9_\-/]+)["\']'),
                            re.compile(r'route:\s*["\'](/[a-zA-Z0-9_\-/]+)["\']'),
                            re.compile(r'push\(["\'](/[a-zA-Z0-9_\-/]+)["\']'),
                            re.compile(r'replace\(["\'](/[a-zA-Z0-9_\-/]+)["\']'),
                        ]
                        
                        found_paths = set()
                        for pattern in route_patterns:
                            matches = pattern.findall(js_content)
                            for match in matches:
                                # Filter out common non-page paths
                                if not any(skip in match for skip in ['/static/', '/assets/', '/node_modules/', '/.', '/favicon']):
                                    found_paths.add(match)
                        
                        # Also look for API endpoint patterns
                        api_patterns = [
                            re.compile(r'["\'](/api/v\d+/[a-zA-Z0-9_\-/]+)["\']'),
                            re.compile(r'fetch\(["\'](/[a-zA-Z0-9_\-/]+)["\']'),
                            re.compile(r'axios\.\w+\(["\'](/[a-zA-Z0-9_\-/]+)["\']'),
                            re.compile(r'url:\s*["\'](/api/[a-zA-Z0-9_\-/]+)["\']'),
                        ]
                        
                        for pattern in api_patterns:
                            matches = pattern.findall(js_content)
                            for match in matches:
                                found_paths.add(match)
                        
                        for path in found_paths:
                            full_url = urljoin(base, path)
                            if full_url not in routes:
                                routes.append(full_url)
                                
                except Exception:
                    continue
            
        except Exception as e:
            logger.debug(f"SPA route discovery failed: {e}")
        
        return routes
    
    def _discover_api_endpoints(self, base_url: str, base_domain: str) -> List[str]:
        """Discover accessible API endpoints by probing common paths"""
        endpoints = []
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        # Common API base paths to probe
        api_probes = [
            "/api/v1/chatflows",
            "/api/v1/assistants",
            "/api/v1/tools",
            "/api/v1/credentials",
            "/api/v1/nodes",
            "/api/v1/variables",
            "/api/v1/apikey",
            "/api/v1/users",
            "/api/v1/flows",
            "/api/v1/executions",
            "/api/v1/webhooks",
            "/api/v1/settings",
            "/api/v1/stats",
            "/api/v1/health",
            "/api/v1/version",
            "/api/v1/config",
        ]
        
        for probe in api_probes:
            try:
                url = urljoin(base, probe)
                response = self.session.get(url, timeout=5)
                if response.status_code == 200:
                    endpoints.append(url)
            except Exception:
                continue
        
        return endpoints
    
    def _extract_links_from_json(self, json_data, base_url: str) -> List[str]:
        """Extract URLs from JSON response data"""
        links = []
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        def _scan_value(value):
            if isinstance(value, str):
                # Look for URL-like strings
                if value.startswith(('http://', 'https://')):
                    links.append(value)
                elif value.startswith('/') and len(value) > 1:
                    links.append(urljoin(base, value))
            elif isinstance(value, dict):
                for v in value.values():
                    _scan_value(v)
            elif isinstance(value, list):
                for item in value[:50]:  # Limit list scanning
                    _scan_value(item)
        
        _scan_value(json_data)
        return list(set(links))[:100]  # Cap at 100 links
    
    def _extract_auth_artifacts(self, response) -> Dict:
        """Extract authentication artifacts from response"""
        artifacts = {
            'cookies': {},
            'tokens': {},
            'headers': {},
            'storage_data': {}
        }
        
        # Extract cookies
        for cookie in self.session.cookies:
            artifacts['cookies'][cookie.name] = cookie.value
        
        # Extract tokens from response
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # JWT tokens in script tags
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string:
                    # Look for JWT patterns
                    jwt_pattern = r'["\']([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)["\']'
                    jwt_matches = re.findall(jwt_pattern, script.string)
                    for match in jwt_matches:
                        if len(match.split('.')) == 3:  # Valid JWT structure
                            artifacts['tokens']['jwt'] = match
                            self.token_extracted.emit("JWT", match, "script_tag")
            
            # API keys in JavaScript
            api_key_patterns = [
                r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'access[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'bearer["\']?\s*[:=]\s*["\']([^"\']+)["\']'
            ]
            
            for script in scripts:
                if script.string:
                    for pattern in api_key_patterns:
                        matches = re.findall(pattern, script.string, re.IGNORECASE)
                        for match in matches:
                            if len(match) > 10:  # Reasonable token length
                                token_type = pattern.split('[')[0]
                                artifacts['tokens'][token_type] = match
                                self.token_extracted.emit(token_type, match, "javascript")
            
            # localStorage/sessionStorage data
            storage_pattern = r'(localStorage|sessionStorage)\.setItem\(["\']([^"\']+)["\'],\s*["\']([^"\']+)["\']'
            for script in scripts:
                if script.string:
                    storage_matches = re.findall(storage_pattern, script.string)
                    for storage_type, key, value in storage_matches:
                        if storage_type not in artifacts['storage_data']:
                            artifacts['storage_data'][storage_type] = {}
                        artifacts['storage_data'][storage_type][key] = value
        
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        
        # Extract relevant headers
        auth_headers = ['authorization', 'x-auth-token', 'x-api-key', 'x-csrf-token']
        for header in auth_headers:
            if header in response.headers:
                artifacts['headers'][header] = response.headers[header]
        
        return artifacts
    
    def _extract_title(self, html_content: str) -> str:
        """Extract page title"""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            title_tag = soup.find('title')
            return title_tag.get_text().strip() if title_tag else 'No title'
        except:
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', html_content, re.IGNORECASE)
            return title_match.group(1).strip() if title_match else 'No title'
    
    def _extract_links(self, html_content: str, base_url: str) -> List[str]:
        """Extract links from HTML content"""
        links = []
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            for link_tag in soup.find_all('a', href=True):
                href = link_tag['href']
                if href.startswith(('http://', 'https://')):
                    links.append(href)
                elif href.startswith('/'):
                    links.append(urljoin(base_url, href))
                elif not href.startswith(('#', 'mailto:', 'tel:', 'javascript:')):
                    links.append(urljoin(base_url, href))
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        
        return list(set(links))
    
    def _extract_forms_with_auth(self, html_content: str, base_url: str) -> List[Dict]:
        """Extract forms with authentication context"""
        forms = []
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            for form_tag in soup.find_all('form'):
                action = form_tag.get('action', '')
                method = form_tag.get('method', 'GET').upper()
                
                if action:
                    if not action.startswith(('http://', 'https://')):
                        action = urljoin(base_url, action)
                else:
                    action = base_url
                
                # Extract input fields with authentication context
                inputs = []
                for input_tag in form_tag.find_all(['input', 'select', 'textarea']):
                    input_info = {
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', ''),
                        'required': input_tag.has_attr('required')
                    }
                    if input_info['name']:
                        inputs.append(input_info)
                
                # Check if form needs CSRF token
                csrf_token = self._extract_csrf_token(str(form_tag))
                
                form_data = {
                    'action': action,
                    'method': method,
                    'inputs': inputs,
                    'csrf_token': csrf_token,
                    'authenticated_form': True
                }
                
                forms.append(form_data)
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        
        return forms
    
    def export_auth_session(self) -> Dict:
        """Export authentication session for reuse"""
        return {
            'authenticated': self.authenticated,
            'auth_tokens': self.auth_tokens,
            'csrf_tokens': self.csrf_tokens,
            'cookies': dict(self.session.cookies),
            'headers': dict(self.session.headers)
        }
    
    def import_auth_session(self, session_data: Dict) -> bool:
        """Import authentication session"""
        try:
            self.authenticated = session_data.get('authenticated', False)
            self.auth_tokens = session_data.get('auth_tokens', {})
            self.csrf_tokens = session_data.get('csrf_tokens', {})
            
            # Set cookies
            for name, value in session_data.get('cookies', {}).items():
                self.session.cookies.set(name, value)
            
            # Set headers
            self.session.headers.update(session_data.get('headers', {}))
            
            return True
        except Exception:
            return False