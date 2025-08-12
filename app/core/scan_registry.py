# app/core/scan_registry.py
import time
import threading
from typing import Dict, Optional, Callable
from PyQt6.QtCore import QObject, pyqtSignal

class ScanInfo:
    """Information about a running scan"""
    def __init__(self, scan_id: str, scan_type: str, target: str, total_items: int = 0):
        self.scan_id = scan_id
        self.scan_type = scan_type
        self.target = target
        self.total_items = total_items
        self.completed_items = 0
        self.start_time = time.time()
        self.status = "Running"
        self.details = f"{scan_type} scan on {target}"
        self.thread_id = None
        self.controller = None

class ScanRegistry(QObject):
    """Global registry for tracking all running scans"""
    
    scan_started = pyqtSignal(str, str, str)  # scan_id, scan_type, target
    scan_updated = pyqtSignal(str, int)       # scan_id, completed_items
    scan_finished = pyqtSignal(str, str)      # scan_id, status
    
    def __init__(self):
        super().__init__()
        self.scans: Dict[str, ScanInfo] = {}
        self.lock = threading.Lock()
        self._scan_counter = 0
    
    def register_scan(self, scan_type: str, target: str, total_items: int = 0, 
                     thread_id: str = None, controller=None) -> str:
        """Register a new scan and return scan ID"""
        with self.lock:
            self._scan_counter += 1
            scan_id = f"{scan_type.lower().replace(' ', '_')}_{self._scan_counter}_{int(time.time())}"
            
            scan_info = ScanInfo(scan_id, scan_type, target, total_items)
            scan_info.thread_id = thread_id
            scan_info.controller = controller
            
            self.scans[scan_id] = scan_info
            
        self.scan_started.emit(scan_id, scan_type, target)
        return scan_id
    
    def update_scan_progress(self, scan_id: str, completed_items: int):
        """Update scan progress"""
        with self.lock:
            if scan_id in self.scans:
                self.scans[scan_id].completed_items = completed_items
                self.scan_updated.emit(scan_id, completed_items)
    
    def update_scan_details(self, scan_id: str, details: str):
        """Update scan details"""
        with self.lock:
            if scan_id in self.scans:
                self.scans[scan_id].details = details
    
    def finish_scan(self, scan_id: str, status: str = "Completed"):
        """Mark scan as finished"""
        with self.lock:
            if scan_id in self.scans:
                self.scans[scan_id].status = status
                self.scan_finished.emit(scan_id, status)
    
    def pause_scan(self, scan_id: str) -> bool:
        """Pause a scan"""
        with self.lock:
            if scan_id in self.scans:
                scan_info = self.scans[scan_id]
                if scan_info.controller and hasattr(scan_info.controller, 'pause'):
                    scan_info.controller.pause()
                    scan_info.status = "Paused"
                    return True
        return False
    
    def resume_scan(self, scan_id: str) -> bool:
        """Resume a paused scan"""
        with self.lock:
            if scan_id in self.scans:
                scan_info = self.scans[scan_id]
                if scan_info.controller and hasattr(scan_info.controller, 'resume'):
                    scan_info.controller.resume()
                    scan_info.status = "Running"
                    return True
        return False
    
    def stop_scan(self, scan_id: str) -> bool:
        """Stop a scan"""
        with self.lock:
            if scan_id in self.scans:
                scan_info = self.scans[scan_id]
                
                # Try to stop via controller first
                if scan_info.controller and hasattr(scan_info.controller, 'stop'):
                    scan_info.controller.stop()
                
                # Try to cancel thread
                if scan_info.thread_id:
                    from app.core.thread_manager import thread_manager
                    thread_manager.cancel_thread(scan_info.thread_id)
                
                scan_info.status = "Stopped"
                self.scan_finished.emit(scan_id, "Stopped")
                return True
        return False
    
    def get_scan_info(self, scan_id: str) -> Optional[ScanInfo]:
        """Get scan information"""
        with self.lock:
            return self.scans.get(scan_id)
    
    def get_all_scans(self) -> Dict[str, ScanInfo]:
        """Get all scan information"""
        with self.lock:
            return self.scans.copy()
    
    def get_active_scans(self) -> Dict[str, ScanInfo]:
        """Get only active (running/paused) scans"""
        with self.lock:
            return {
                scan_id: scan_info 
                for scan_id, scan_info in self.scans.items()
                if scan_info.status in ["Running", "Paused"]
            }
    
    def cleanup_finished_scans(self, max_age_seconds: int = 300):
        """Remove finished scans older than max_age_seconds"""
        current_time = time.time()
        to_remove = []
        
        with self.lock:
            for scan_id, scan_info in self.scans.items():
                if (scan_info.status in ["Completed", "Stopped", "Failed"] and 
                    current_time - scan_info.start_time > max_age_seconds):
                    to_remove.append(scan_id)
            
            for scan_id in to_remove:
                del self.scans[scan_id]
        
        return len(to_remove)
    
    def stop_all_scans(self) -> int:
        """Stop all active scans"""
        stopped_count = 0
        
        with self.lock:
            scan_ids = list(self.scans.keys())
        
        for scan_id in scan_ids:
            if self.stop_scan(scan_id):
                stopped_count += 1
        
        return stopped_count

# Global scan registry instance
scan_registry = ScanRegistry()