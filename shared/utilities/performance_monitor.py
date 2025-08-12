import time
import psutil
import threading
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class PerformanceMetrics:
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    memory_mb: float
    active_threads: int
    operation: str = ""

class PerformanceMonitor:
    """Performance monitoring with metrics collection"""
    
    def __init__(self, collection_interval: float = 1.0):
        self.collection_interval = collection_interval
        self.metrics: List[PerformanceMetrics] = []
        self.callbacks: List[Callable[[PerformanceMetrics], None]] = []
        self._monitoring = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()
    
    def start_monitoring(self):
        """Start performance monitoring"""
        with self._lock:
            if self._monitoring:
                return
            
            self._monitoring = True
            self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self._monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop performance monitoring"""
        with self._lock:
            self._monitoring = False
            if self._monitor_thread:
                self._monitor_thread.join(timeout=2.0)
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self._monitoring:
            try:
                metrics = self._collect_metrics()
                
                with self._lock:
                    self.metrics.append(metrics)
                    # Keep only last 1000 metrics
                    if len(self.metrics) > 1000:
                        self.metrics = self.metrics[-1000:]
                
                # Notify callbacks
                for callback in self.callbacks:
                    try:
                        callback(metrics)
                    except Exception:
                        pass
                
                time.sleep(self.collection_interval)
            except Exception:
                pass
    
    def _collect_metrics(self) -> PerformanceMetrics:
        """Collect current performance metrics"""
        process = psutil.Process()
        
        return PerformanceMetrics(
            timestamp=datetime.now(),
            cpu_percent=process.cpu_percent(),
            memory_percent=process.memory_percent(),
            memory_mb=process.memory_info().rss / 1024 / 1024,
            active_threads=threading.active_count()
        )
    
    def add_callback(self, callback: Callable[[PerformanceMetrics], None]):
        """Add performance metrics callback"""
        self.callbacks.append(callback)
    
    def get_recent_metrics(self, count: int = 10) -> List[PerformanceMetrics]:
        """Get recent performance metrics"""
        with self._lock:
            return self.metrics[-count:] if self.metrics else []
    
    def get_average_metrics(self, minutes: int = 5) -> Optional[PerformanceMetrics]:
        """Get average metrics for specified time period"""
        with self._lock:
            if not self.metrics:
                return None
            
            cutoff_time = datetime.now().timestamp() - (minutes * 60)
            recent_metrics = [m for m in self.metrics 
                            if m.timestamp.timestamp() > cutoff_time]
            
            if not recent_metrics:
                return None
            
            return PerformanceMetrics(
                timestamp=datetime.now(),
                cpu_percent=sum(m.cpu_percent for m in recent_metrics) / len(recent_metrics),
                memory_percent=sum(m.memory_percent for m in recent_metrics) / len(recent_metrics),
                memory_mb=sum(m.memory_mb for m in recent_metrics) / len(recent_metrics),
                active_threads=int(sum(m.active_threads for m in recent_metrics) / len(recent_metrics)),
                operation="average"
            )

# Global performance monitor instance
performance_monitor = PerformanceMonitor()