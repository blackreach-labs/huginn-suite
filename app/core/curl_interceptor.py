# app/core/curl_interceptor.py
import subprocess
import json
import re
from PyQt6.QtCore import QObject, pyqtSignal, QThread
from typing import Dict, List, Optional
import time

class CurlRequest:
    def __init__(self, method="GET", url="", headers=None, data="", cookies=None, auth=None, timeout=30, follow_redirects=True, verify_ssl=True):
        self.method = method
        self.url = url
        self.headers = headers or {}
        self.data = data
        self.cookies = cookies or {}
        self.auth = auth
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl
        self.original_command = ""
    
    @classmethod
    def from_curl_command(cls, command: str):
        """Create CurlRequest from curl command"""
        instance = cls()
        instance.original_command = command
        instance.parse_curl_command(command)
        return instance
    
    def parse_curl_command(self, command: str):
        """Parse curl command into components"""
        url_match = re.search(r'curl\s+(?:-[^\s]+\s+)*["\']?([^"\'\s]+)["\']?', command)
        if url_match:
            self.url = url_match.group(1)
        
        method_match = re.search(r'-X\s+([A-Z]+)', command)
        if method_match:
            self.method = method_match.group(1)
        
        header_matches = re.findall(r'-H\s+["\']([^"\']+)["\']', command)
        for header in header_matches:
            if ':' in header:
                key, value = header.split(':', 1)
                self.headers[key.strip()] = value.strip()
        
        data_match = re.search(r'--data(?:-raw)?\s+["\']([^"\']*)["\']', command)
        if data_match:
            self.data = data_match.group(1)
        
        auth_match = re.search(r'-u\s+["\']?([^"\'\s]*:[^"\'\s]*)["\']?', command)
        if auth_match:
            username, password = auth_match.group(1).split(':', 1)
            self.auth = (username.strip(), password.strip())
    
    def to_curl_command(self) -> str:
        """Convert back to curl command"""
        import shlex
        cmd = f"curl -X {self.method}"
        
        for key, value in self.headers.items():
            cmd += f' -H "{key}: {value}"'
        
        if self.data:
            cmd += f' --data {shlex.quote(self.data)}'
        
        if self.auth:
            cmd += f' -u "{self.auth[0]}:{self.auth[1]}"'
        
        if self.timeout != 30:
            cmd += f' --max-time {self.timeout}'
        
        if not self.verify_ssl:
            cmd += ' -k'
        
        if self.follow_redirects:
            cmd += ' -L -v'
        
        if self.cookies:
            cookie_str = '; '.join([f'{k}={v}' for k, v in self.cookies.items()])
            cmd += f' --cookie "{cookie_str}"'
        
        cmd += f' "{self.url}"'
        return cmd

class CurlInterceptor(QObject):
    request_intercepted = pyqtSignal(object)
    response_received = pyqtSignal(str, str)
    history_updated = pyqtSignal(list)
    
    def __init__(self):
        super().__init__()
        self.paused_requests = []
        self.intercept_enabled = False
        self.request_history = []
    
    def enable_intercept(self, enabled: bool):
        self.intercept_enabled = enabled
    
    def execute_curl(self, curl_request: CurlRequest, pause_before_send: bool = False):
        """Execute curl command with optional pause"""
        if pause_before_send and self.intercept_enabled:
            self.paused_requests.append(curl_request)
            self.request_intercepted.emit(curl_request)
            return
        
        self._send_request(curl_request)
    
    def _send_request(self, curl_request: CurlRequest):
        """Actually send the request"""
        try:
            import shlex
            import time
            
            start_time = time.time()
            cmd_parts = shlex.split(curl_request.to_curl_command())
            result = subprocess.run(
                cmd_parts,
                capture_output=True,
                text=True,
                timeout=curl_request.timeout
            )
            end_time = time.time()
            
            # Combine stdout and stderr to show redirects and final response
            response = ""
            if result.stderr:
                response += "[VERBOSE]\n" + result.stderr + "\n\n"
            if result.stdout:
                response += "[RESPONSE]\n" + result.stdout
            else:
                response = result.stderr if result.stderr else "No response"
            
            # Store in history
            history_entry = {
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'method': curl_request.method,
                'url': curl_request.url,
                'status_code': self._extract_status_code(result.stderr),
                'response_time': round((end_time - start_time) * 1000, 2),
                'request': curl_request,
                'response': response
            }
            self.request_history.append(history_entry)
            self.history_updated.emit(self.request_history)
            
            self.response_received.emit(curl_request.to_curl_command(), response)
            
        except subprocess.TimeoutExpired:
            self.response_received.emit(curl_request.to_curl_command(), "Request timed out")
        except Exception as e:
            self.response_received.emit(curl_request.to_curl_command(), f"Error: {str(e)}")
    
    def send_paused_request(self, index: int):
        """Send a paused request"""
        if 0 <= index < len(self.paused_requests):
            request = self.paused_requests.pop(index)
            self._send_request(request)
    
    def drop_paused_request(self, index: int):
        """Drop a paused request"""
        if 0 <= index < len(self.paused_requests):
            self.paused_requests.pop(index)
    
    def send_repeated(self, curl_request: CurlRequest, times: int):
        """Send request multiple times (Intruder functionality)"""
        for i in range(times):
            self._send_request(curl_request)
    
    def get_history(self):
        """Get request history"""
        return self.request_history
    
    def clear_history(self):
        """Clear request history"""
        self.request_history.clear()
        self.history_updated.emit(self.request_history)
    
    def _extract_status_code(self, stderr_output):
        """Extract HTTP status code from curl verbose output"""
        if not stderr_output:
            return None
        
        # Look for HTTP status line
        import re
        status_match = re.search(r'HTTP/[\d\.]+ (\d{3})', stderr_output)
        return int(status_match.group(1)) if status_match else None