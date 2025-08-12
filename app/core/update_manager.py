from .auto_updater import SecureUpdater
from .temp_update_fix import TempSecureUpdater
import threading
import time

class UpdateManager:
    def __init__(self):
        self.updater = TempSecureUpdater()
        self.auto_check = False
        self.check_interval = 3600  # 1 hour
        self._stop_event = threading.Event()
        
    def start_auto_check(self, interval_seconds=3600):
        """Start automatic update checking"""
        self.auto_check = True
        self.check_interval = interval_seconds
        self._stop_event.clear()
        
        thread = threading.Thread(target=self._auto_check_loop, daemon=True)
        thread.start()
        
    def stop_auto_check(self):
        """Stop automatic update checking"""
        self.auto_check = False
        self._stop_event.set()
        
    def _auto_check_loop(self):
        """Background loop for automatic updates"""
        while self.auto_check and not self._stop_event.is_set():
            try:
                manifest = self.updater.check_for_updates()
                if manifest:
                    print(f"Update available: {manifest['version']}")
                    # Could trigger UI notification here
                    
            except Exception as e:
                print(f"Auto-update check failed: {e}")
                
            self._stop_event.wait(self.check_interval)
    
    def check_now(self):
        """Manual update check"""
        return self.updater.check_for_updates()
    
    def install_update(self, manifest):
        """Install available update"""
        return self.updater.download_and_install(manifest)

# Global instance
update_manager = UpdateManager()