# app/core/scheduler.py
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Callable
import json
import os

class ScanScheduler:
    """Schedule scans to run at specific times"""
    
    def __init__(self):
        self.scheduled_scans = {}
        self.scheduler_thread = None
        self.running = False
        self.schedules_file = "schedules.json"
        self.load_schedules()
    
    def schedule_scan(self, scan_id: str, target: str, scan_type: str, 
                     schedule_time: datetime, template: Dict = None, 
                     repeat_interval: int = 0) -> bool:
        """Schedule a scan to run at specific time"""
        try:
            schedule = {
                'scan_id': scan_id,
                'target': target,
                'scan_type': scan_type,
                'schedule_time': schedule_time.isoformat(),
                'template': template or {},
                'repeat_interval': repeat_interval,  # Hours, 0 = no repeat
                'created': datetime.now().isoformat(),
                'status': 'scheduled'
            }
            
            self.scheduled_scans[scan_id] = schedule
            self.save_schedules()
            
            if not self.running:
                self.start_scheduler()
            
            return True
        except Exception:
            return False
    
    def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a scheduled scan"""
        if scan_id in self.scheduled_scans:
            del self.scheduled_scans[scan_id]
            self.save_schedules()
            return True
        return False
    
    def get_scheduled_scans(self) -> List[Dict]:
        """Get list of scheduled scans"""
        scans = []
        for scan_id, schedule in self.scheduled_scans.items():
            schedule_copy = schedule.copy()
            schedule_copy['time_until'] = self._get_time_until(schedule['schedule_time'])
            scans.append(schedule_copy)
        return sorted(scans, key=lambda x: x['schedule_time'])
    
    def start_scheduler(self):
        """Start the scheduler thread"""
        if self.running:
            return
        
        self.running = True
        self.scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self.scheduler_thread.start()
    
    def stop_scheduler(self):
        """Stop the scheduler thread"""
        self.running = False
    
    def _scheduler_loop(self):
        """Main scheduler loop"""
        while self.running:
            current_time = datetime.now()
            scans_to_run = []
            
            for scan_id, schedule in self.scheduled_scans.items():
                schedule_time = datetime.fromisoformat(schedule['schedule_time'])
                
                if current_time >= schedule_time and schedule['status'] == 'scheduled':
                    scans_to_run.append((scan_id, schedule))
            
            # Execute due scans
            for scan_id, schedule in scans_to_run:
                self._execute_scan(scan_id, schedule)
            
            time.sleep(30)  # Check every 30 seconds
    
    def _execute_scan(self, scan_id: str, schedule: Dict):
        """Execute a scheduled scan"""
        try:
            # Mark as running
            schedule['status'] = 'running'
            schedule['last_run'] = datetime.now().isoformat()
            
            # Here would be the actual scan execution
            # For now, just mark as completed
            schedule['status'] = 'completed'
            
            # Handle repeat scheduling
            if schedule['repeat_interval'] > 0:
                next_run = datetime.now() + timedelta(hours=schedule['repeat_interval'])
                schedule['schedule_time'] = next_run.isoformat()
                schedule['status'] = 'scheduled'
            else:
                # Remove one-time scans after completion
                if scan_id in self.scheduled_scans:
                    del self.scheduled_scans[scan_id]
            
            self.save_schedules()
            
        except Exception:
            schedule['status'] = 'failed'
            self.save_schedules()
    
    def _get_time_until(self, schedule_time_str: str) -> str:
        """Get human-readable time until scheduled execution"""
        try:
            schedule_time = datetime.fromisoformat(schedule_time_str)
            current_time = datetime.now()
            
            if schedule_time <= current_time:
                return "Due now"
            
            delta = schedule_time - current_time
            
            if delta.days > 0:
                return f"{delta.days} days"
            elif delta.seconds > 3600:
                hours = delta.seconds // 3600
                return f"{hours} hours"
            elif delta.seconds > 60:
                minutes = delta.seconds // 60
                return f"{minutes} minutes"
            else:
                return "< 1 minute"
                
        except Exception:
            return "Unknown"
    
    def save_schedules(self):
        """Save schedules to file"""
        try:
            with open(self.schedules_file, 'w') as f:
                json.dump(self.scheduled_scans, f, indent=2)
        except Exception:
            pass
    
    def load_schedules(self):
        """Load schedules from file"""
        try:
            if os.path.exists(self.schedules_file):
                with open(self.schedules_file, 'r') as f:
                    self.scheduled_scans = json.load(f)
                
                # Clean up old completed scans
                current_time = datetime.now()
                to_remove = []
                
                for scan_id, schedule in self.scheduled_scans.items():
                    if schedule['status'] == 'completed' and schedule['repeat_interval'] == 0:
                        schedule_time = datetime.fromisoformat(schedule['schedule_time'])
                        if current_time - schedule_time > timedelta(days=1):
                            to_remove.append(scan_id)
                
                for scan_id in to_remove:
                    del self.scheduled_scans[scan_id]
                
                if to_remove:
                    self.save_schedules()
                    
        except Exception:
            self.scheduled_scans = {}

# Global instance
scan_scheduler = ScanScheduler()