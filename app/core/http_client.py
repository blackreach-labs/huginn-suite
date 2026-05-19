# app/core/http_client.py
import requests
import time
from PyQt6.QtCore import QObject, pyqtSignal
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, parse_qs, urlencode
import json
from app.core.logger import logger

class HttpRequest:
    """Unified HTTP request object"""
    def __init__(self, method="GET", url="", headers=None, data="", params=None, 
                 cookies=None, auth=None, timeout=30, allow_redirects=True, verify=True):
        self.method = method.upper()
        self.url = url
        self.headers = headers or {}
        self.data = data
        self.params = params or {}
        self.cookies = cookies or {}
        self.auth = auth
        self.timeout = timeout
        self.allow_redirects = allow_redirects
        self.verify = verify
        self.timestamp = time.time()
    
    @classmethod
    def from_mitmproxy_flow(cls, flow):
        """Create HttpRequest from mitmproxy flow"""
        request = flow.request
        
        # Extract auth from headers
        auth = None
        if 'authorization' in request.headers:
            auth_header = request.headers['authorization']
            if auth_header.startswith('Basic '):
                import base64
                try:
                    decoded = base64.b64decode(auth_header[6:]).decode('utf-8')
                    if ':' in decoded:
                        auth = tuple(decoded.split(':', 1))
                except Exception as _exc:
                    pass
                    logger.debug("Suppressed exception", exc_info=True)
        
        # Safely extract request data
        try:
            request_data = request.get_text() or ""
        except UnicodeDecodeError:
            request_data = "[Binary Content]"
        except Exception:
            request_data = ""
        
        return cls(
            method=request.method,
            url=request.pretty_url,
            headers=dict(request.headers),
            data=request_data,
            cookies=dict(request.cookies),
            auth=auth,
            verify=request.scheme == 'https'
        )
    
    def to_dict(self):
        """Convert to dictionary for serialization"""
        return {
            'method': self.method,
            'url': self.url,
            'headers': self.headers,
            'data': self.data,
            'params': self.params,
            'cookies': self.cookies,
            'auth': self.auth,
            'timeout': self.timeout,
            'allow_redirects': self.allow_redirects,
            'verify': self.verify,
            'timestamp': self.timestamp
        }

class HttpResponse:
    """Unified HTTP response object"""
    def __init__(self, status_code, headers, content, url, elapsed_time, request=None):
        self.status_code = status_code
        self.headers = headers
        self.content = content
        self.text = content if isinstance(content, str) else content.decode('utf-8', errors='ignore')
        self.url = url
        self.elapsed_time = elapsed_time
        self.request = request
        self.timestamp = time.time()
    
    @classmethod
    def from_requests_response(cls, response, request=None):
        """Create HttpResponse from requests.Response"""
        return cls(
            status_code=response.status_code,
            headers=dict(response.headers),
            content=response.content,
            url=response.url,
            elapsed_time=response.elapsed.total_seconds(),
            request=request
        )
    
    @classmethod
    def from_mitmproxy_flow(cls, flow):
        """Create HttpResponse from mitmproxy flow"""
        if not flow.response:
            return None
        
        response = flow.response
        return cls(
            status_code=response.status_code,
            headers=dict(response.headers),
            content=response.content,
            url=flow.request.pretty_url,
            elapsed_time=0,  # mitmproxy doesn't track this
            request=HttpRequest.from_mitmproxy_flow(flow)
        )
    
    def to_dict(self):
        """Convert to dictionary for serialization"""
        return {
            'status_code': self.status_code,
            'headers': self.headers,
            'content': self.text,
            'url': self.url,
            'elapsed_time': self.elapsed_time,
            'timestamp': self.timestamp
        }

class UnifiedHttpClient(QObject):
    """Unified HTTP client replacing subprocess curl"""
    request_sent = pyqtSignal(object, object)  # request, response
    request_failed = pyqtSignal(object, str)   # request, error
    
    def __init__(self):
        super().__init__()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Huginn Security Scanner/1.0'
        })
    
    def send_request(self, http_request: HttpRequest) -> Optional[HttpResponse]:
        """Send HTTP request using requests library"""
        try:
            # Resolve hostname using global DNS configuration
            from urllib.parse import urlparse, urlunparse
            from app.core.dns_resolver import dns_resolver
            
            parsed_url = urlparse(http_request.url)
            original_hostname = parsed_url.hostname
            resolved_url = http_request.url
            host_header = None
            
            if original_hostname and not self._is_ip(original_hostname):
                resolved_ip = dns_resolver.resolve_hostname(original_hostname)
                if resolved_ip and resolved_ip != original_hostname:
                    # Replace hostname with resolved IP in URL
                    if parsed_url.port:
                        new_netloc = f"{resolved_ip}:{parsed_url.port}"
                    else:
                        new_netloc = resolved_ip
                    resolved_url = urlunparse(parsed_url._replace(netloc=new_netloc))
                    host_header = original_hostname
            
            # Prepare request parameters
            kwargs = {
                'method': http_request.method,
                'url': resolved_url,
                'headers': dict(http_request.headers) if http_request.headers else {},
                'timeout': http_request.timeout,
                'allow_redirects': http_request.allow_redirects,
                'verify': http_request.verify
            }
            
            # Add Host header if we resolved the hostname to an IP
            if host_header and 'Host' not in kwargs['headers']:
                kwargs['headers']['Host'] = host_header
            
            # Add data/json based on content type
            if http_request.data:
                content_type = http_request.headers.get('Content-Type', '').lower()
                if 'application/json' in content_type:
                    try:
                        kwargs['json'] = json.loads(http_request.data)
                    except json.JSONDecodeError:
                        kwargs['data'] = http_request.data
                else:
                    kwargs['data'] = http_request.data
            
            # Add parameters
            if http_request.params:
                kwargs['params'] = http_request.params
            
            # Add cookies
            if http_request.cookies:
                kwargs['cookies'] = http_request.cookies
            
            # Add authentication
            if http_request.auth:
                kwargs['auth'] = http_request.auth
            
            # Send request
            start_time = time.time()
            response = self.session.request(**kwargs)
            
            # Create unified response
            http_response = HttpResponse.from_requests_response(response, http_request)
            
            # Emit signal
            self.request_sent.emit(http_request, http_response)
            
            return http_response
            
        except requests.exceptions.RequestException as e:
            error_msg = str(e)
            self.request_failed.emit(http_request, error_msg)
            return None
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            self.request_failed.emit(http_request, error_msg)
            return None
    
    def send_multiple(self, http_request: HttpRequest, count: int) -> List[HttpResponse]:
        """Send request multiple times (Intruder functionality)"""
        responses = []
        for i in range(count):
            response = self.send_request(http_request)
            if response:
                responses.append(response)
        return responses
    
    def inject_payload(self, http_request: HttpRequest, param_name: str, payload: str) -> HttpRequest:
        """Inject payload into request parameter"""
        new_request = HttpRequest(
            method=http_request.method,
            url=http_request.url,
            headers=http_request.headers.copy(),
            data=http_request.data,
            params=http_request.params.copy(),
            cookies=http_request.cookies.copy(),
            auth=http_request.auth,
            timeout=http_request.timeout,
            allow_redirects=http_request.allow_redirects,
            verify=http_request.verify
        )
        
        # Inject into URL parameters
        if param_name in new_request.params:
            new_request.params[param_name] = payload
        
        # Inject into POST data
        elif new_request.data:
            content_type = new_request.headers.get('Content-Type', '').lower()
            
            if 'application/json' in content_type:
                try:
                    data = json.loads(new_request.data)
                    if param_name in data:
                        data[param_name] = payload
                        new_request.data = json.dumps(data)
                except json.JSONDecodeError as _exc:
                    pass
                    logger.debug("Suppressed exception", exc_info=True)
            
            elif 'application/x-www-form-urlencoded' in content_type:
                try:
                    data = parse_qs(new_request.data)
                    if param_name in data:
                        data[param_name] = [payload]
                        new_request.data = urlencode(data, doseq=True)
                except Exception as _exc:
                    pass
                    logger.debug("Suppressed exception", exc_info=True)
        
        return new_request
    
    def close(self):
        """Close the session"""
        self.session.close()
    
    @staticmethod
    def _is_ip(hostname):
        """Check if a string is an IP address"""
        import ipaddress
        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            return False