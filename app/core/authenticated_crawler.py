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
                return False
            
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
                
        except Exception as e:
            self.auth_failed.emit("form_login", str(e))
        
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
                    
                    # Find username field (common patterns)
                    username_field = None
                    username_patterns = ['username', 'user', 'email', 'login', 'userid']
                    
                    for pattern in username_patterns:
                        field = form.find('input', {'name': re.compile(pattern, re.I)})
                        if field:
                            username_field = field.get('name')
                            break
                    
                    if not username_field:
                        # Try to find text input before password
                        text_inputs = form.find_all('input', {'type': 'text'})
                        if text_inputs:
                            username_field = text_inputs[0].get('name')
                    
                    if username_field:
                        return {
                            'action_url': action_url,
                            'username_field': username_field,
                            'password_field': password_fields[0].get('name'),
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
        
        # Check for login redirects
        if response.status_code in [302, 303, 307, 308]:
            location = response.headers.get('Location', '').lower()
            if any(keyword in location for keyword in ['login', 'signin', 'auth']):
                return False
        
        # Check response content for login indicators
        content_lower = response.text.lower()
        login_indicators = ['login', 'sign in', 'username', 'password']
        logout_indicators = ['logout', 'sign out', 'dashboard', 'profile']
        
        # If we see logout indicators, we're likely authenticated
        if any(indicator in content_lower for indicator in logout_indicators):
            return True
        
        # If we only see login indicators, we're likely not authenticated
        login_count = sum(1 for indicator in login_indicators if indicator in content_lower)
        if login_count > 2:  # Multiple login indicators suggest login page
            return False
        
        return True
    
    def crawl_authenticated(self, target_url: str, max_depth: int = 3, 
                          max_pages: int = 100) -> Dict:
        """Crawl website with authentication"""
        
        if not self.authenticated:
            raise Exception("Not authenticated. Call authenticate() first.")
        
        self.visited_urls.clear()
        self.crawled_data.clear()
        
        # Start crawling
        self._crawl_recursive_authenticated(target_url, urlparse(target_url).netloc, 0, max_depth, max_pages)
        
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
                
                # Continue crawling found links
                for link in page_data['links'][:10]:
                    if len(self.visited_urls) < max_pages:
                        self._crawl_recursive_authenticated(link, base_domain, depth + 1, max_depth, max_pages)
            
            self.crawled_data[url] = page_data
            self.page_crawled.emit(url, page_data)
            
        except Exception as e:
            self.crawled_data[url] = {
                'url': url,
                'error': str(e),
                'depth': depth,
                'authenticated': True
            }
    
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