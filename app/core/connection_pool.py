# app/core/connection_pool.py
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.poolmanager import PoolManager
import threading
from typing import Dict, Optional

class ConnectionPool:
    """Singleton connection pool for HTTP requests"""
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not hasattr(self, 'initialized'):
            self.sessions: Dict[str, requests.Session] = {}
            self.initialized = True
    
    def get_session(self, pool_key: str = "default") -> requests.Session:
        """Get or create a session with connection pooling"""
        if pool_key not in self.sessions:
            session = requests.Session()
            
            # Configure retry strategy
            retry_strategy = Retry(
                total=3,
                backoff_factor=0.3,
                status_forcelist=[429, 500, 502, 503, 504],
            )
            
            # Configure adapter with connection pooling
            adapter = HTTPAdapter(
                pool_connections=10,
                pool_maxsize=20,
                max_retries=retry_strategy
            )
            
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            
            # Set default headers
            session.headers.update({
                'User-Agent': 'Huggin/2.0 (Security Scanner)',
                'Accept': '*/*',
                'Connection': 'keep-alive'
            })
            
            self.sessions[pool_key] = session
        
        return self.sessions[pool_key]
    
    def close_all(self):
        """Close all sessions"""
        for session in self.sessions.values():
            session.close()
        self.sessions.clear()

# Global instance
connection_pool = ConnectionPool()