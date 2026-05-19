# app/core/unified_request_handler.py
from PyQt6.QtCore import QObject, pyqtSignal
from typing import Dict, List, Optional
import time
try:
    from .http_client import UnifiedHttpClient, HttpRequest, HttpResponse
    from .proxy_engine import ProxyEngine
    from .scanner_engine import PassiveScanner, ActiveScanner
except ImportError:
    from app.core.http_client import UnifiedHttpClient, HttpRequest, HttpResponse
    from app.core.proxy_engine import ProxyEngine
    from app.core.scanner_engine import PassiveScanner, ActiveScanner

class UnifiedRequestHandler(QObject):
    """Central handler for all HTTP requests - the core of the unified system"""
    
    # Signals
    request_sent = pyqtSignal(object, object)      # request, response
    request_intercepted = pyqtSignal(int, object)   # flow_id, request
    request_failed = pyqtSignal(object, str)        # request, error message
    history_updated = pyqtSignal(list)
    finding_detected = pyqtSignal(dict)
    scan_completed = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        
        # Core components
        self.http_client = UnifiedHttpClient()
        self.proxy_engine = ProxyEngine()
        self.passive_scanner = PassiveScanner()
        self.active_scanner = ActiveScanner()
        
        # State
        self.history = []
        self.paused_requests = {}
        self.intercept_enabled = False
        self.proxy_available = self.proxy_engine.proxy_available
        
        # Connect signals
        self._setup_connections()
    
    def _setup_connections(self):
        """Setup signal connections between components"""
        # HTTP Client
        self.http_client.request_sent.connect(self._on_request_sent)
        self.http_client.request_failed.connect(self._on_request_failed)
        
        # Proxy Engine
        self.proxy_engine.request_intercepted.connect(self._on_request_intercepted)
        self.proxy_engine.request_logged.connect(self._on_request_logged)
        self.proxy_engine.response_received.connect(self._on_response_received)
        self.proxy_engine.passive_scan_request.connect(self.passive_scanner.scan_response)
        
        # Scanners
        self.passive_scanner.finding_detected.connect(self.finding_detected.emit)
        self.active_scanner.finding_detected.connect(self.finding_detected.emit)
        self.active_scanner.scan_completed.connect(self.scan_completed.emit)
    
    # Repeater functionality
    def send_request(self, http_request: HttpRequest) -> Optional[HttpResponse]:
        """Send a single request (Repeater functionality)"""
        return self.http_client.send_request(http_request)
    
    def send_multiple(self, http_request: HttpRequest, count: int) -> List[HttpResponse]:
        """Send request multiple times (Intruder functionality)"""
        return self.http_client.send_multiple(http_request, count)
    
    # Proxy functionality
    def start_proxy(self, port=8080):
        """Start proxy server"""
        if self.proxy_available:
            return self.proxy_engine.start_proxy(port)
        else:
            print("Proxy functionality not available - install mitmproxy: pip install mitmproxy")
            return False
    
    def stop_proxy(self):
        """Stop proxy server"""
        self.proxy_engine.stop_proxy()
    
    def enable_intercept(self, enabled: bool):
        """Enable/disable request interception"""
        self.intercept_enabled = enabled
        self.proxy_engine.enable_intercept(enabled)
    
    def forward_request(self, flow_id: int):
        """Forward intercepted request"""
        return self.proxy_engine.forward_request(flow_id)
    
    def drop_request(self, flow_id: int):
        """Drop intercepted request"""
        return self.proxy_engine.drop_request(flow_id)
    
    def modify_and_forward_request(self, flow_id: int, modified_request: HttpRequest):
        """Modify and forward intercepted request"""
        return self.proxy_engine.modify_and_forward_request(flow_id, modified_request)
    
    # Scanner functionality
    def scan_request(self, http_request: HttpRequest, target_params=None):
        """Actively scan a request for vulnerabilities"""
        return self.active_scanner.scan_request(http_request, target_params)
    
    def scan_response_passive(self, http_response: HttpResponse):
        """Passively scan a response"""
        return self.passive_scanner.scan_response(http_response)
    
    # History management
    def get_history(self):
        """Get request/response history"""
        return self.history
    
    def clear_history(self):
        """Clear history"""
        self.history.clear()
        self.history_updated.emit(self.history)
    
    def send_to_repeater(self, history_index: int):
        """Send history item to repeater"""
        if 0 <= history_index < len(self.history):
            return self.history[history_index]['request']
        return None
    
    def send_to_scanner(self, history_index: int):
        """Send history item to scanner"""
        if 0 <= history_index < len(self.history):
            request = self.history[history_index]['request']
            self.scan_request(request)
    
    # Event handlers
    def _on_request_sent(self, request: HttpRequest, response: HttpResponse):
        """Handle request sent from HTTP client"""
        self._add_to_history(request, response)
        self.request_sent.emit(request, response)
        
        # Run passive scan
        self.passive_scanner.scan_response(response)
    
    def _on_request_failed(self, request: HttpRequest, error: str):
        """Handle failed request"""
        # Create error response
        error_response = HttpResponse(
            status_code=0,
            headers={},
            content=f"Error: {error}",
            url=request.url,
            elapsed_time=0,
            request=request
        )
        self._add_to_history(request, error_response)
        self.request_failed.emit(request, error)
    
    def _on_request_intercepted(self, flow_id: int, request: HttpRequest):
        """Handle intercepted request from proxy"""
        self.paused_requests[flow_id] = request
        self.request_intercepted.emit(flow_id, request)
    
    def _on_request_logged(self, request: HttpRequest):
        """Handle logged request from proxy (not intercepted)"""
        # Just log it, response will come later
        pass
    
    def _on_response_received(self, response: HttpResponse):
        """Handle response from proxy"""
        if response.request:
            self._add_to_history(response.request, response)
    
    def _add_to_history(self, request: HttpRequest, response: HttpResponse):
        """Add request/response to history"""
        entry = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'request': request,
            'response': response,
            'method': request.method,
            'url': request.url,
            'status_code': response.status_code,
            'response_time': response.elapsed_time * 1000,  # Convert to ms
            'size': len(response.content) if hasattr(response, 'content') else len(response.text)
        }
        
        self.history.append(entry)
        self.history_updated.emit(self.history)
    
    def get_findings(self):
        """Get all security findings"""
        passive_findings = self.passive_scanner.get_findings()
        active_findings = self.active_scanner.get_findings()
        return passive_findings + active_findings
    
    def clear_findings(self):
        """Clear all findings"""
        self.passive_scanner.clear_findings()
        self.active_scanner.clear_findings()