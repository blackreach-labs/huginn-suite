# app/core/connection_pool.py
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import threading
from typing import Dict

from app.core.logger import logger

# Read SSL config once at module level so all sessions share the same setting.
def _get_ssl_verify() -> bool:
    try:
        from app.core.config import config as _cfg
        return _cfg.get('security.ssl_verify', True)
    except Exception:
        return True


# Maximum number of named sessions the pool will hold.
# Prevents unbounded memory growth when callers use unique pool keys.
_MAX_SESSIONS = 50


class ConnectionPool:
    """Singleton connection pool for HTTP requests.

    Limits
    ------
    - At most ``_MAX_SESSIONS`` named sessions are kept alive.  When the limit
      is reached the oldest session is closed and evicted (LRU-style).
    - Each session uses ``HTTPAdapter`` with ``pool_connections=10`` and
      ``pool_maxsize=20`` so urllib3 itself caps per-host connections.
    """

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
            # Use an ordered dict so we can evict the oldest entry
            self.sessions: Dict[str, requests.Session] = {}
            self._session_lock = threading.Lock()
            self.initialized = True

    def get_session(self, pool_key: str = "default") -> requests.Session:
        """Get or create a session with connection pooling."""
        with self._session_lock:
            if pool_key not in self.sessions:
                # Evict oldest session if at capacity
                if len(self.sessions) >= _MAX_SESSIONS:
                    oldest_key = next(iter(self.sessions))
                    try:
                        self.sessions[oldest_key].close()
                    except Exception as e:
                        logger.debug(f"Error closing evicted session '{oldest_key}': {e}")
                    del self.sessions[oldest_key]
                    logger.debug(
                        f"Connection pool at capacity ({_MAX_SESSIONS}); "
                        f"evicted session '{oldest_key}'"
                    )

                session = requests.Session()

                retry_strategy = Retry(
                    total=3,
                    backoff_factor=0.3,
                    status_forcelist=[429, 500, 502, 503, 504],
                )
                adapter = HTTPAdapter(
                    pool_connections=10,
                    pool_maxsize=20,
                    max_retries=retry_strategy,
                )
                session.mount("http://", adapter)
                session.mount("https://", adapter)
                session.headers.update({
                    'User-Agent': 'Huginn/2.0 (Security Scanner)',
                    'Accept': '*/*',
                    'Connection': 'keep-alive',
                })
                session.verify = _get_ssl_verify()
                self.sessions[pool_key] = session

            return self.sessions[pool_key]

    def close_session(self, pool_key: str):
        """Close and remove a specific session."""
        with self._session_lock:
            session = self.sessions.pop(pool_key, None)
            if session:
                try:
                    session.close()
                except Exception as e:
                    logger.debug(f"Error closing session '{pool_key}': {e}")

    def close_all(self):
        """Close all sessions and clear the pool."""
        with self._session_lock:
            for key, session in list(self.sessions.items()):
                try:
                    session.close()
                except Exception as e:
                    logger.debug(f"Error closing session '{key}': {e}")
            self.sessions.clear()
        logger.debug("Connection pool closed all sessions")

    @property
    def session_count(self) -> int:
        """Current number of open sessions."""
        with self._session_lock:
            return len(self.sessions)


# Global instance
connection_pool = ConnectionPool()