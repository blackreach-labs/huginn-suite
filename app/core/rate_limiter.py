# app/core/rate_limiter.py
import time
import threading
from typing import Dict
from app.core.logger import logger

class RateLimiter:
    """Global rate limiter for all scanning operations"""
    
    def __init__(self):
        self.limits = {
            'requests_per_second': 10,
            'concurrent_threads': 50,
            'delay_between_requests': 0.1,
            'burst_limit': 20,
            'enabled': False
        }
        self._last_request_times = {}
        self._request_counts = {}
        self._lock = threading.Lock()
    
    def set_rate_limit(self, requests_per_second: int, concurrent_threads: int = None, enabled: bool = True):
        """Set rate limiting parameters"""
        with self._lock:
            self.limits['requests_per_second'] = max(1, requests_per_second)
            self.limits['delay_between_requests'] = 1.0 / self.limits['requests_per_second']
            if concurrent_threads:
                self.limits['concurrent_threads'] = max(1, concurrent_threads)
            self.limits['enabled'] = enabled
    
    def wait_if_needed(self, tool_name: str = 'default', dynamic_rate: int = None):
        """Wait if rate limit would be exceeded"""
        if not self.limits['enabled']:
            return
        
        with self._lock:
            current_time = time.time()
            
            # Use dynamic rate if provided
            effective_rate = dynamic_rate or self.limits['requests_per_second']
            effective_delay = 1.0 / effective_rate
            
            # Initialize tracking for this tool
            if tool_name not in self._last_request_times:
                self._last_request_times[tool_name] = 0
                self._request_counts[tool_name] = []
            
            # Clean old request counts (older than 1 second)
            self._request_counts[tool_name] = [
                t for t in self._request_counts[tool_name] 
                if current_time - t < 1.0
            ]
            
            # Check if we need to wait
            if len(self._request_counts[tool_name]) >= effective_rate:
                sleep_time = 1.0 - (current_time - self._request_counts[tool_name][0])
                if sleep_time > 0:
                    time.sleep(sleep_time)
                    current_time = time.time()
            
            # Ensure minimum delay between requests
            time_since_last = current_time - self._last_request_times[tool_name]
            if time_since_last < effective_delay:
                sleep_time = effective_delay - time_since_last
                time.sleep(sleep_time)
                current_time = time.time()
            
            # Record this request
            self._last_request_times[tool_name] = current_time
            self._request_counts[tool_name].append(current_time)
    
    def get_current_limits(self) -> Dict:
        """Get current rate limiting configuration"""
        return self.limits.copy()
    
    def is_enabled(self) -> bool:
        """Check if rate limiting is enabled"""
        return self.limits['enabled']
    
    def disable(self):
        """Disable rate limiting"""
        with self._lock:
            self.limits['enabled'] = False
    
    def get_recommended_thread_count(self, dynamic_rate: int = None) -> int:
        """Get recommended thread count based on rate limits"""
        if not self.limits['enabled']:
            return 50  # Default
        
        effective_rate = dynamic_rate or self.limits['requests_per_second']
        # Conservative thread count to avoid overwhelming rate limits
        return min(self.limits['concurrent_threads'], effective_rate * 2)
    
    def update_from_stealth_engine(self):
        """Update rate limits from stealth engine if available"""
        try:
            from app.core.stealth_engine import stealth_engine
            if stealth_engine.dynamic_rate_enabled:
                self.set_rate_limit(stealth_engine.current_rate)
        except ImportError as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)

# Global instance
rate_limiter = RateLimiter()