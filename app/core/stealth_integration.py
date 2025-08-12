# app/core/stealth_integration.py
import time
import requests
from typing import Dict, Optional
from app.core.stealth_engine import stealth_engine
from app.core.rate_limiter import rate_limiter

class StealthHTTPClient:
    """HTTP client with integrated stealth features"""
    
    def __init__(self):
        self.session = requests.Session()
    
    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Make HTTP request with stealth features applied"""
        start_time = time.time()
        
        try:
            # Apply rate limiting with dynamic rate
            if stealth_engine.dynamic_rate_enabled:
                rate_limiter.wait_if_needed('http_client', stealth_engine.current_rate)
            else:
                rate_limiter.wait_if_needed('http_client')
            
            # Apply timing delay with jitter
            delay = stealth_engine.get_timing_delay(stealth_engine.evasion_level)
            time.sleep(delay)
            
            # Apply randomized headers
            if stealth_engine.randomize_headers:
                headers = kwargs.get('headers', {})
                headers.update(stealth_engine.get_random_headers())
                kwargs['headers'] = headers
            
            # Apply proxy rotation
            proxy = stealth_engine.get_next_proxy()
            if proxy:
                kwargs['proxies'] = {'http': proxy, 'https': proxy}
            
            # Make the request
            response = self.session.request(method, url, **kwargs)
            
            # Update dynamic rate limiting
            response_time = time.time() - start_time
            is_error = response.status_code >= 400
            stealth_engine.update_dynamic_rate(response_time, is_error)
            
            return response
            
        except Exception as e:
            # Update dynamic rate limiting for errors
            response_time = time.time() - start_time
            stealth_engine.update_dynamic_rate(response_time, True)
            raise e
    
    def get(self, url: str, **kwargs) -> requests.Response:
        """GET request with stealth features"""
        return self.request('GET', url, **kwargs)
    
    def post(self, url: str, **kwargs) -> requests.Response:
        """POST request with stealth features"""
        return self.request('POST', url, **kwargs)

# Global stealth HTTP client
stealth_http_client = StealthHTTPClient()