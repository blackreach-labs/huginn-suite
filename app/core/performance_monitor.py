"""Performance monitoring and optimization utilities"""
import gc
import time
import psutil
import threading
from typing import Dict, List, Optional
from PyQt6.QtCore import QObject, pyqtSignal, QTimer
from app.core.logger import logger

class PerformanceMonitor(QObject):
    """Monitor and optimize application performance"""
    
    memory_warning = pyqtSignal(float)  # memory_percent
    performance_alert = pyqtSignal(str, dict)  # alert_type, metrics
    
    def __init__(self):
        super().__init__()
        self.process = psutil.Process()
        self.baseline_memory = self.process.memory_info().rss
        self.memory_samples = []
        self.max_samples = 100
        self.gc_threshold = 80.0  # Memory percentage
        self.monitoring = False
        
        # Performance metrics
        self.metrics = {
            'scan_times': [],
            'memory_peaks': [],
            'gc_collections': 0,
            'cache_hits': 0,
            'cache_misses': 0
        }
        
        # Setup monitoring timer
        self.monitor_timer = QTimer()
        self.monitor_timer.timeout.connect(self._collect_metrics)
        
    def start_monitoring(self, interval_ms=5000):
        """Start performance monitoring"""
        if not self.monitoring:
            self.monitoring = True
            self.monitor_timer.start(interval_ms)
            logger.info("Performance monitoring started")
    
    def stop_monitoring(self):
        """Stop performance monitoring"""
        if self.monitoring:
            self.monitoring = False
            self.monitor_timer.stop()
            logger.info("Performance monitoring stopped")
    
    def _collect_metrics(self):
        """Collect performance metrics"""
        try:
            # Memory metrics
            memory_info = self.process.memory_info()
            memory_percent = self.process.memory_percent()
            
            self.memory_samples.append({
                'timestamp': time.time(),
                'rss': memory_info.rss,
                'vms': memory_info.vms,
                'percent': memory_percent
            })
            
            # Keep only recent samples
            if len(self.memory_samples) > self.max_samples:
                self.memory_samples.pop(0)
            
            # Check for memory issues
            if memory_percent > self.gc_threshold:
                self.memory_warning.emit(memory_percent)
                self._trigger_gc()
            
            # Detect memory leaks
            if len(self.memory_samples) >= 10:
                self._check_memory_trend()
                
        except Exception as e:
            logger.error(f"Error collecting performance metrics: {e}")
    
    def _trigger_gc(self):
        """Trigger garbage collection"""
        try:
            collected = gc.collect()
            self.metrics['gc_collections'] += 1
            logger.info(f"Garbage collection triggered, collected {collected} objects")
        except Exception as e:
            logger.error(f"Error during garbage collection: {e}")
    
    def _check_memory_trend(self):
        """Check for memory leak patterns"""
        recent_samples = self.memory_samples[-10:]
        memory_values = [s['rss'] for s in recent_samples]
        
        # Simple trend detection
        if len(memory_values) >= 5:
            first_half = sum(memory_values[:5]) / 5
            second_half = sum(memory_values[5:]) / 5
            growth_rate = (second_half - first_half) / first_half
            
            if growth_rate > 0.2:  # 20% growth
                self.performance_alert.emit('memory_leak', {
                    'growth_rate': growth_rate,
                    'current_memory': memory_values[-1],
                    'baseline_memory': self.baseline_memory
                })
    
    def record_scan_time(self, scan_type: str, duration: float):
        """Record scan execution time"""
        self.metrics['scan_times'].append({
            'type': scan_type,
            'duration': duration,
            'timestamp': time.time()
        })
        
        # Keep only recent scan times
        if len(self.metrics['scan_times']) > 100:
            self.metrics['scan_times'].pop(0)
    
    def record_cache_hit(self):
        """Record cache hit"""
        self.metrics['cache_hits'] += 1
    
    def record_cache_miss(self):
        """Record cache miss"""
        self.metrics['cache_misses'] += 1
    
    def get_performance_summary(self) -> Dict:
        """Get performance summary"""
        try:
            memory_info = self.process.memory_info()
            cpu_percent = self.process.cpu_percent()
            
            # Calculate averages
            avg_scan_time = 0
            if self.metrics['scan_times']:
                avg_scan_time = sum(s['duration'] for s in self.metrics['scan_times']) / len(self.metrics['scan_times'])
            
            cache_hit_rate = 0
            total_cache_ops = self.metrics['cache_hits'] + self.metrics['cache_misses']
            if total_cache_ops > 0:
                cache_hit_rate = self.metrics['cache_hits'] / total_cache_ops
            
            return {
                'memory': {
                    'current_mb': memory_info.rss / 1024 / 1024,
                    'baseline_mb': self.baseline_memory / 1024 / 1024,
                    'percent': self.process.memory_percent()
                },
                'cpu_percent': cpu_percent,
                'performance': {
                    'avg_scan_time': avg_scan_time,
                    'cache_hit_rate': cache_hit_rate,
                    'gc_collections': self.metrics['gc_collections']
                },
                'samples_collected': len(self.memory_samples)
            }
        except Exception as e:
            logger.error(f"Error generating performance summary: {e}")
            return {}
    
    def optimize_memory(self):
        """Perform memory optimization"""
        try:
            # Clear old samples
            if len(self.memory_samples) > 50:
                self.memory_samples = self.memory_samples[-50:]
            
            # Clear old scan times
            if len(self.metrics['scan_times']) > 50:
                self.metrics['scan_times'] = self.metrics['scan_times'][-50:]
            
            # Force garbage collection
            self._trigger_gc()
            
            logger.info("Memory optimization completed")
            return True
        except Exception as e:
            logger.error(f"Error during memory optimization: {e}")
            return False

# Global performance monitor instance
performance_monitor = PerformanceMonitor()