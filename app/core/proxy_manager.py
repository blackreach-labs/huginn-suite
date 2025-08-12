# app/core/proxy_manager.py
import requests
from urllib.parse import urlparse
import threading

class ProxyManager:
    """Manage proxy settings for all tools"""
    
    def __init__(self):
        self.proxy_config = {
            'enabled': False,
            'http_proxy': '',
            'https_proxy': '',
            'socks_proxy': '',
            'auth_username': '',
            'auth_password': '',
            'bypass_list': []
        }
        self._lock = threading.Lock()
    
    def set_proxy(self, proxy_type: str, proxy_url: str, username: str = '', password: str = ''):
        """Set proxy configuration"""
        with self._lock:
            if proxy_type == 'http':
                self.proxy_config['http_proxy'] = proxy_url
                self.proxy_config['https_proxy'] = proxy_url
            elif proxy_type == 'socks':
                self.proxy_config['socks_proxy'] = proxy_url
            
            self.proxy_config['auth_username'] = username
            self.proxy_config['auth_password'] = password
            self.proxy_config['enabled'] = bool(proxy_url)
    
    def get_proxy_dict(self) -> dict:
        """Get proxy dictionary for requests"""
        if not self.proxy_config['enabled']:
            return {}
        
        proxies = {}
        
        if self.proxy_config['http_proxy']:
            proxy_url = self._format_proxy_url(self.proxy_config['http_proxy'])
            proxies['http'] = proxy_url
            proxies['https'] = proxy_url
        
        if self.proxy_config['socks_proxy']:
            proxy_url = self._format_proxy_url(self.proxy_config['socks_proxy'])
            proxies['http'] = proxy_url
            proxies['https'] = proxy_url
        
        return proxies
    
    def _format_proxy_url(self, proxy_url: str) -> str:
        """Format proxy URL with authentication"""
        if not proxy_url:
            return ''
        
        # Add auth if provided
        username = self.proxy_config.get('auth_username', '')
        password = self.proxy_config.get('auth_password', '')
        
        if username and password:
            parsed = urlparse(proxy_url)
            if not parsed.username:  # Only add auth if not already present
                proxy_url = f"{parsed.scheme}://{username}:{password}@{parsed.netloc}{parsed.path}"
        
        return proxy_url
    
    def test_proxy(self) -> tuple:
        """Test proxy connectivity"""
        if not self.proxy_config['enabled']:
            return False, "Proxy not enabled"
        
        try:
            proxies = self.get_proxy_dict()
            response = requests.get('http://httpbin.org/ip', proxies=proxies, timeout=10)
            if response.status_code == 200:
                return True, f"Proxy working - IP: {response.json().get('origin', 'Unknown')}"
            else:
                return False, f"Proxy test failed - Status: {response.status_code}"
        except Exception as e:
            return False, f"Proxy test error: {str(e)}"
    
    def is_enabled(self) -> bool:
        """Check if proxy is enabled"""
        return self.proxy_config['enabled']
    
    def disable(self):
        """Disable proxy"""
        with self._lock:
            self.proxy_config['enabled'] = False

# Global instance
proxy_manager = ProxyManager()