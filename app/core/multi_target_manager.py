# app/core/multi_target_manager.py
import threading
from typing import List, Dict, Callable
from concurrent.futures import ThreadPoolExecutor
import time

class MultiTargetManager:
    """Manage scanning of multiple targets simultaneously"""
    
    def __init__(self):
        self.active_scans = {}
        self.scan_results = {}
        self.max_concurrent_targets = 5
        self._lock = threading.Lock()
    
    def scan_multiple_targets(self, targets: List[str], scan_function: Callable, 
                            scan_params: Dict, progress_callback: Callable = None,
                            result_callback: Callable = None) -> str:
        """Start scanning multiple targets"""
        scan_id = f"multi_scan_{int(time.time())}"
        
        with self._lock:
            self.active_scans[scan_id] = {
                'targets': targets,
                'completed': 0,
                'total': len(targets),
                'results': {},
                'status': 'running'
            }
        
        # Start scanning in background thread
        scan_thread = threading.Thread(
            target=self._execute_multi_scan,
            args=(scan_id, targets, scan_function, scan_params, progress_callback, result_callback),
            daemon=True
        )
        scan_thread.start()
        
        return scan_id
    
    def _execute_multi_scan(self, scan_id: str, targets: List[str], scan_function: Callable,
                          scan_params: Dict, progress_callback: Callable, result_callback: Callable):
        """Execute multi-target scan"""
        try:
            with ThreadPoolExecutor(max_workers=self.max_concurrent_targets) as executor:
                # Submit all target scans
                future_to_target = {}
                for target in targets:
                    params = scan_params.copy()
                    params['target'] = target
                    future = executor.submit(scan_function, **params)
                    future_to_target[future] = target
                
                # Collect results as they complete
                for future in future_to_target:
                    target = future_to_target[future]
                    try:
                        result = future.result(timeout=300)  # 5 minute timeout per target
                        
                        with self._lock:
                            self.active_scans[scan_id]['results'][target] = result
                            self.active_scans[scan_id]['completed'] += 1
                        
                        if progress_callback:
                            progress = (self.active_scans[scan_id]['completed'] / 
                                      self.active_scans[scan_id]['total']) * 100
                            progress_callback(f"Completed {target} ({progress:.1f}%)")
                        
                        if result_callback:
                            result_callback(target, result)
                            
                    except Exception as e:
                        with self._lock:
                            self.active_scans[scan_id]['results'][target] = {'error': str(e)}
                            self.active_scans[scan_id]['completed'] += 1
                        
                        if progress_callback:
                            progress_callback(f"Failed {target}: {str(e)}")
            
            # Mark scan as completed
            with self._lock:
                self.active_scans[scan_id]['status'] = 'completed'
            
            if progress_callback:
                progress_callback("Multi-target scan completed")
                
        except Exception as e:
            with self._lock:
                self.active_scans[scan_id]['status'] = 'failed'
                self.active_scans[scan_id]['error'] = str(e)
            
            if progress_callback:
                progress_callback(f"Multi-target scan failed: {str(e)}")
    
    def get_scan_status(self, scan_id: str) -> Dict:
        """Get status of multi-target scan"""
        with self._lock:
            return self.active_scans.get(scan_id, {})
    
    def get_scan_results(self, scan_id: str) -> Dict:
        """Get results of multi-target scan"""
        with self._lock:
            scan_info = self.active_scans.get(scan_id, {})
            return scan_info.get('results', {})
    
    def cancel_scan(self, scan_id: str) -> bool:
        """Cancel multi-target scan"""
        with self._lock:
            if scan_id in self.active_scans:
                self.active_scans[scan_id]['status'] = 'cancelled'
                return True
            return False
    
    def parse_target_list(self, target_input: str) -> List[str]:
        """Parse target input into list of targets"""
        targets = []
        
        # Split by common separators
        for line in target_input.replace(',', '\n').replace(';', '\n').split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):  # Skip empty lines and comments
                targets.append(line)
        
        return list(set(targets))  # Remove duplicates
    
    def load_targets_from_file(self, filepath: str) -> List[str]:
        """Load targets from file"""
        try:
            with open(filepath, 'r') as f:
                content = f.read()
            return self.parse_target_list(content)
        except Exception:
            return []

# Global instance
multi_target_manager = MultiTargetManager()