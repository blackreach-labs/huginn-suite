# app/core/scan_controller.py
import threading
from typing import Callable, Optional
from PyQt6.QtCore import QObject, pyqtSignal

class ScanController(QObject):
    """Controls scan execution with pause/resume capability"""
    
    status_changed = pyqtSignal(str)  # "running", "paused", "stopped"
    
    def __init__(self):
        super().__init__()
        self.is_running = False
        self.is_paused = False
        self.should_stop = False
        self._lock = threading.Lock()
        
    def start(self):
        """Start or resume scan"""
        with self._lock:
            self.is_running = True
            self.is_paused = False
            self.should_stop = False
        self.status_changed.emit("running")
        
    def pause(self):
        """Pause scan"""
        with self._lock:
            self.is_paused = True
        self.status_changed.emit("paused")
        
    def resume(self):
        """Resume paused scan"""
        with self._lock:
            self.is_paused = False
        self.status_changed.emit("running")
        
    def stop(self):
        """Stop scan completely"""
        with self._lock:
            self.should_stop = True
            self.is_running = False
            self.is_paused = False
        self.status_changed.emit("stopped")
        
    def wait_if_paused(self):
        """Block execution if paused"""
        while self.is_paused and not self.should_stop:
            threading.Event().wait(0.1)
            
    def should_continue(self) -> bool:
        """Check if scan should continue"""
        return self.is_running and not self.should_stop
        
    def reset(self):
        """Reset controller state"""
        with self._lock:
            self.is_running = False
            self.is_paused = False
            self.should_stop = False
        self.status_changed.emit("stopped")