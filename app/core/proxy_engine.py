# app/core/proxy_engine.py
import asyncio
from PyQt6.QtCore import QObject, pyqtSignal, QThread
import json
import time
from urllib.parse import urlparse

try:
    from mitmproxy import http, options
    from mitmproxy.tools.dump import DumpMaster
    MITMPROXY_AVAILABLE = True
except ImportError:
    MITMPROXY_AVAILABLE = False
    http = None
    options = None
    DumpMaster = None

try:
    from .http_client import HttpRequest, HttpResponse
    from .proxy_database import ProxyDatabase
except ImportError:
    from app.core.http_client import HttpRequest, HttpResponse
    from app.core.proxy_database import ProxyDatabase

class ProxyAddon:
    def __init__(self, signals, db_path=None):
        if not MITMPROXY_AVAILABLE:
            raise ImportError("mitmproxy not available - proxy functionality disabled")
        self.signals = signals
        self.intercept_enabled = False
        self.paused_flows = {}
        self.flow_counter = 0
        self.db = ProxyDatabase(db_path)  # Will use resources/proxy.db by default
        self.request_start_times = {}
    
    def request(self, flow: http.HTTPFlow):
        """Handle intercepted requests"""
        # Store request start time for response time calculation
        self.request_start_times[id(flow)] = time.time()
        
        # Convert to unified format
        http_request = HttpRequest.from_mitmproxy_flow(flow)
        
        if self.intercept_enabled:
            flow_id = self.flow_counter
            self.flow_counter += 1
            flow.metadata['huggin_id'] = flow_id
            
            # Actually pause the flow
            flow.intercept()
            self.paused_flows[flow_id] = flow
            self.signals.request_intercepted.emit(flow_id, http_request)
        else:
            self.signals.request_logged.emit(http_request)
    
    def response(self, flow: http.HTTPFlow):
        """Handle responses and store in database"""
        # Calculate response time
        start_time = self.request_start_times.pop(id(flow), time.time())
        response_time = time.time() - start_time
        
        # Parse URL
        parsed_url = urlparse(flow.request.pretty_url)
        
        # Safely extract text content
        def safe_get_text(content_obj):
            try:
                return content_obj.get_text() or ''
            except UnicodeDecodeError:
                return '[Binary Content]'
            except Exception:
                return ''
        
        # Prepare data for database
        request_data = {
            'timestamp': time.time(),
            'method': flow.request.method,
            'url': flow.request.pretty_url,
            'host': parsed_url.netloc,
            'path': parsed_url.path,
            'status_code': flow.response.status_code if flow.response else None,
            'response_time': response_time,
            'request_size': len(flow.request.raw_content) if flow.request.raw_content else 0,
            'response_size': len(flow.response.raw_content) if flow.response and flow.response.raw_content else 0,
            'request_headers': dict(flow.request.headers),
            'response_headers': dict(flow.response.headers) if flow.response else {},
            'request_body': safe_get_text(flow.request),
            'response_body': safe_get_text(flow.response) if flow.response else '',
            'content_type': flow.response.headers.get('content-type', '') if flow.response else ''
        }
        
        # Store in database
        request_id = self.db.store_request(request_data)
        
        # Convert to unified format and emit signals
        http_response = HttpResponse.from_mitmproxy_flow(flow)
        if http_response:
            self.signals.response_received.emit(http_response)
            self.signals.passive_scan_request.emit(http_response)
            self.signals.history_updated.emit(request_id)
    
    def resume_flow(self, flow_id: int):
        """Resume a paused flow"""
        if flow_id in self.paused_flows:
            flow = self.paused_flows.pop(flow_id)
            flow.resume()
            return True
        return False
    
    def kill_flow(self, flow_id: int):
        """Kill a paused flow"""
        if flow_id in self.paused_flows:
            flow = self.paused_flows.pop(flow_id)
            flow.kill()
            return True
        return False
    
    def modify_and_resume_flow(self, flow_id: int, modified_request):
        """Modify and resume a paused flow"""
        if flow_id in self.paused_flows:
            flow = self.paused_flows.pop(flow_id)
            
            # Parse the modified URL
            from urllib.parse import urlparse
            parsed_url = urlparse(modified_request.url)
            
            # Modify the flow's request using mitmproxy's methods
            flow.request.method = modified_request.method
            flow.request.scheme = parsed_url.scheme
            flow.request.host = parsed_url.hostname
            flow.request.port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
            flow.request.path = parsed_url.path or '/'
            
            # Set query parameters
            if parsed_url.query:
                flow.request.query = parsed_url.query
            else:
                flow.request.query = b''
            
            # Clear and set headers
            flow.request.headers.clear()
            for key, value in modified_request.headers.items():
                flow.request.headers[key] = value
            
            # Set request content/body using set_content method
            if modified_request.data:
                flow.request.set_content(modified_request.data.encode('utf-8'))
            else:
                flow.request.set_content(b'')
            
            # Resume the flow
            flow.resume()
            return True
        return False
    
    def get_history(self, limit=1000, offset=0):
        """Get request/response history from database"""
        return self.db.get_requests(limit, offset)
    
    def get_request_details(self, request_id):
        """Get detailed request information"""
        return self.db.get_request_details(request_id)
    
    def clear_history(self):
        """Clear history from database"""
        self.db.clear_history()

class ProxyEngine(QObject):
    request_intercepted = pyqtSignal(int, object)  # flow_id, HttpRequest
    request_logged = pyqtSignal(object)            # HttpRequest
    response_received = pyqtSignal(object)         # HttpResponse
    passive_scan_request = pyqtSignal(object)      # HttpResponse for scanning
    proxy_started = pyqtSignal(int)
    proxy_stopped = pyqtSignal()
    history_updated = pyqtSignal(int)              # request_id
    
    def __init__(self):
        super().__init__()
        self.master = None
        self.addon = None
        self.port = 8080
        self.proxy_thread = None
        self.proxy_available = MITMPROXY_AVAILABLE
        
        if MITMPROXY_AVAILABLE:
            try:
                self.addon = ProxyAddon(self)
            except ImportError:
                self.proxy_available = False
    
    def start_proxy(self, port=8080):
        """Start the proxy server"""
        if not self.proxy_available:
            print("Proxy functionality not available - mitmproxy not installed")
            return False
            
        try:
            self.port = port
            opts = options.Options(listen_port=port)
            
            # Run in thread with proper event loop
            self.proxy_thread = ProxyThread(opts, self.addon, port)
            self.proxy_thread.proxy_started.connect(lambda p: self.proxy_started.emit(p))
            self.proxy_thread.start()
            return True
        except Exception as e:
            print(f"Failed to start proxy: {e}")
            return False
    
    def stop_proxy(self):
        """Stop the proxy server"""
        if self.proxy_thread and self.proxy_thread.isRunning():
            if self.proxy_thread.master:
                try:
                    self.proxy_thread.master.shutdown()
                except:
                    pass
            self.proxy_thread.quit()
            self.proxy_thread.wait()
            self.proxy_stopped.emit()
    
    def enable_intercept(self, enabled):
        """Enable/disable request interception"""
        if self.addon:
            self.addon.intercept_enabled = enabled
    
    def forward_request(self, flow_id: int):
        """Forward a paused request"""
        return self.addon.resume_flow(flow_id) if self.addon else False
    
    def drop_request(self, flow_id: int):
        """Drop a paused request"""
        return self.addon.kill_flow(flow_id) if self.addon else False
    
    def modify_and_forward_request(self, flow_id: int, modified_request):
        """Modify and forward a paused request"""
        return self.addon.modify_and_resume_flow(flow_id, modified_request) if self.addon else False
    
    def get_history(self, limit=1000, offset=0):
        """Get request/response history"""
        if self.addon:
            return self.addon.get_history(limit, offset)
        return []
    
    def get_request_details(self, request_id):
        """Get detailed request information"""
        if self.addon:
            return self.addon.get_request_details(request_id)
        return None
    
    def clear_history(self):
        """Clear history"""
        if self.addon:
            self.addon.clear_history()
        self.history_updated.emit(0)

class ProxyThread(QThread):
    proxy_started = pyqtSignal(int)
    
    def __init__(self, opts, addon, port):
        super().__init__()
        self.opts = opts
        self.addon = addon
        self.port = port
        self.master = None
    
    def run(self):
        async def run_proxy():
            self.master = DumpMaster(self.opts)
            self.master.addons.add(self.addon)
            self.proxy_started.emit(self.port)
            await self.master.run()
        
        try:
            asyncio.run(run_proxy())
        except Exception as e:
            print(f"Proxy thread error: {e}")