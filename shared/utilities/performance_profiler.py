import time
import functools
from typing import Dict, List, Callable, Any
from dataclasses import dataclass
from datetime import datetime

@dataclass
class ProfileResult:
    function_name: str
    execution_time: float
    call_count: int
    avg_time: float
    max_time: float
    min_time: float

class PerformanceProfiler:
    """Advanced performance profiler for function execution"""
    
    def __init__(self):
        self.profiles: Dict[str, List[float]] = {}
        self.enabled = True
    
    def profile(self, func_name: str = None):
        """Decorator for profiling function execution"""
        def decorator(func: Callable) -> Callable:
            name = func_name or f"{func.__module__}.{func.__name__}"
            
            @functools.wraps(func)
            def wrapper(*args, **kwargs) -> Any:
                if not self.enabled:
                    return func(*args, **kwargs)
                
                start_time = time.perf_counter()
                try:
                    result = func(*args, **kwargs)
                    return result
                finally:
                    end_time = time.perf_counter()
                    execution_time = end_time - start_time
                    
                    if name not in self.profiles:
                        self.profiles[name] = []
                    self.profiles[name].append(execution_time)
            
            return wrapper
        return decorator
    
    def get_profile_results(self) -> List[ProfileResult]:
        """Get profiling results for all functions"""
        results = []
        
        for func_name, times in self.profiles.items():
            if times:
                results.append(ProfileResult(
                    function_name=func_name,
                    execution_time=sum(times),
                    call_count=len(times),
                    avg_time=sum(times) / len(times),
                    max_time=max(times),
                    min_time=min(times)
                ))
        
        return sorted(results, key=lambda r: r.execution_time, reverse=True)
    
    def reset_profiles(self):
        """Reset all profiling data"""
        self.profiles.clear()
    
    def enable_profiling(self):
        """Enable profiling"""
        self.enabled = True
    
    def disable_profiling(self):
        """Disable profiling"""
        self.enabled = False

# Global profiler instance
profiler = PerformanceProfiler()