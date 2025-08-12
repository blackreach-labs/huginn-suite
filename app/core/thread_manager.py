"""Enhanced thread management for concurrent operations"""
import threading
import time
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Callable, Any
from PyQt6.QtCore import QObject, pyqtSignal, QMutex, QMutexLocker
from app.core.logger import logger

class ThreadManager(QObject):
    """Centralized thread management with proper resource control"""
    
    thread_started = pyqtSignal(str)  # thread_id
    thread_finished = pyqtSignal(str, bool)  # thread_id, success
    thread_error = pyqtSignal(str, str)  # thread_id, error_message
    
    def __init__(self, max_workers=None):
        super().__init__()
        self.max_workers = max_workers or min(32, (os.cpu_count() or 1) + 4)
        self.executor = ThreadPoolExecutor(max_workers=self.max_workers)
        self.active_threads = {}
        self.thread_counter = 0
        self.mutex = QMutex()
        
        # Thread pools for different types of operations
        self.scan_executor = ThreadPoolExecutor(max_workers=min(8, self.max_workers))
        self.io_executor = ThreadPoolExecutor(max_workers=min(4, self.max_workers))
        
    def submit_scan_task(self, func: Callable, *args, **kwargs) -> str:
        """Submit a scanning task"""
        return self._submit_task(self.scan_executor, "scan", func, *args, **kwargs)
    
    def submit_io_task(self, func: Callable, *args, **kwargs) -> str:
        """Submit an I/O task"""
        return self._submit_task(self.io_executor, "io", func, *args, **kwargs)
    
    def submit_general_task(self, func: Callable, *args, **kwargs) -> str:
        """Submit a general task"""
        return self._submit_task(self.executor, "general", func, *args, **kwargs)
    
    def _submit_task(self, executor: ThreadPoolExecutor, task_type: str, 
                    func: Callable, *args, **kwargs) -> str:
        """Submit task to specific executor"""
        with QMutexLocker(self.mutex):
            self.thread_counter += 1
            thread_id = f"{task_type}_{self.thread_counter}"
        
        try:
            future = executor.submit(self._wrapped_task, thread_id, func, *args, **kwargs)
            self.active_threads[thread_id] = {
                'future': future,
                'type': task_type,
                'start_time': time.time(),
                'cancelled': False
            }
            
            self.thread_started.emit(thread_id)
            logger.debug(f"Started thread {thread_id} ({task_type})")
            return thread_id
            
        except Exception as e:
            logger.error(f"Failed to submit task {thread_id}: {e}")
            self.thread_error.emit(thread_id, str(e))
            return ""
    
    def _wrapped_task(self, thread_id: str, func: Callable, *args, **kwargs):
        """Wrapper for task execution with error handling"""
        try:
            result = func(*args, **kwargs)
            self._cleanup_thread(thread_id, True)
            return result
        except Exception as e:
            logger.error(f"Thread {thread_id} failed: {e}")
            self.thread_error.emit(thread_id, str(e))
            self._cleanup_thread(thread_id, False)
            raise
    
    def _cleanup_thread(self, thread_id: str, success: bool):
        """Clean up completed thread"""
        with QMutexLocker(self.mutex):
            if thread_id in self.active_threads:
                thread_info = self.active_threads.pop(thread_id)
                duration = time.time() - thread_info['start_time']
                logger.debug(f"Thread {thread_id} completed in {duration:.2f}s")
        
        self.thread_finished.emit(thread_id, success)
    
    def cancel_thread(self, thread_id: str) -> bool:
        """Cancel a specific thread"""
        with QMutexLocker(self.mutex):
            if thread_id in self.active_threads:
                thread_info = self.active_threads[thread_id]
                if not thread_info['cancelled']:
                    success = thread_info['future'].cancel()
                    if success:
                        thread_info['cancelled'] = True
                        logger.info(f"Cancelled thread {thread_id}")
                    return success
        return False
    
    def cancel_all_threads(self):
        """Cancel all active threads"""
        with QMutexLocker(self.mutex):
            thread_ids = list(self.active_threads.keys())
        
        cancelled_count = 0
        for thread_id in thread_ids:
            if self.cancel_thread(thread_id):
                cancelled_count += 1
        
        logger.info(f"Cancelled {cancelled_count} threads")
        return cancelled_count
    
    def get_active_threads(self) -> Dict[str, Dict]:
        """Get information about active threads"""
        with QMutexLocker(self.mutex):
            return {
                thread_id: {
                    'type': info['type'],
                    'duration': time.time() - info['start_time'],
                    'cancelled': info['cancelled']
                }
                for thread_id, info in self.active_threads.items()
            }
    
    def get_thread_stats(self) -> Dict[str, Any]:
        """Get thread pool statistics"""
        return {
            'max_workers': self.max_workers,
            'active_threads': len(self.active_threads),
            'scan_pool': {
                'active': len([t for t in self.active_threads.values() if t['type'] == 'scan']),
                'max_workers': self.scan_executor._max_workers
            },
            'io_pool': {
                'active': len([t for t in self.active_threads.values() if t['type'] == 'io']),
                'max_workers': self.io_executor._max_workers
            },
            'general_pool': {
                'active': len([t for t in self.active_threads.values() if t['type'] == 'general']),
                'max_workers': self.executor._max_workers
            }
        }
    
    def shutdown(self, wait=True):
        """Shutdown all thread pools"""
        logger.info("Shutting down thread manager...")
        
        # Cancel all active threads first
        self.cancel_all_threads()
        
        # Shutdown executors
        self.scan_executor.shutdown(wait=wait)
        self.io_executor.shutdown(wait=wait)
        self.executor.shutdown(wait=wait)
        
        logger.info("Thread manager shutdown complete")

# Global thread manager instance
thread_manager = ThreadManager()