# app/core/multi_target_coordinator.py
import time
import threading
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from app.core.multi_target_manager import multi_target_manager
from app.core.multi_target_orchestrator import MultiTargetOrchestrator

class MultiTargetCoordinator:
    """Enterprise-scale multi-target coordination"""
    
    def __init__(self):
        self.active_campaigns = {}
        self.orchestrator = MultiTargetOrchestrator(max_concurrent_targets=5)
        self.campaign_counter = 0
        self._lock = threading.Lock()
    
    def launch_campaign(self, targets: Optional[List[str]] = None, profile: str = 'normal') -> str:
        """Launch multi-target campaign"""
        with self._lock:
            self.campaign_counter += 1
            campaign_id = f"campaign_{self.campaign_counter}_{int(time.time())}"
        
        # Use default targets if none provided
        if not targets:
            targets = ['example.com', 'test.com', 'demo.com']
        
        # Create campaign using orchestrator
        campaign = self.orchestrator.add_scan_campaign(
            campaign_name=campaign_id,
            targets=targets,
            profile=profile
        )
        
        with self._lock:
            self.active_campaigns[campaign_id] = {
                'status': 'queued',
                'targets': targets,
                'profile': profile,
                'created_at': time.time(),
                'campaign_data': campaign
            }
        
        # Start campaign in background
        threading.Thread(
            target=self._execute_campaign_async,
            args=(campaign_id,),
            daemon=True
        ).start()
        
        print(f"🎯 Multi-target campaign launched: {campaign_id}")
        return campaign_id
    
    def _execute_campaign_async(self, campaign_id: str):
        """Execute campaign asynchronously"""
        try:
            import asyncio
            
            # Update status
            with self._lock:
                if campaign_id in self.active_campaigns:
                    self.active_campaigns[campaign_id]['status'] = 'running'
            
            # Execute campaign
            results = asyncio.run(self.orchestrator.execute_campaign(campaign_id))
            
            # Update with results
            with self._lock:
                if campaign_id in self.active_campaigns:
                    self.active_campaigns[campaign_id].update({
                        'status': 'completed',
                        'results': results,
                        'completed_at': time.time()
                    })
            
        except Exception as e:
            with self._lock:
                if campaign_id in self.active_campaigns:
                    self.active_campaigns[campaign_id].update({
                        'status': 'failed',
                        'error': str(e),
                        'completed_at': time.time()
                    })
    
    def get_campaign_status(self, campaign_id: str) -> Dict:
        """Get campaign status"""
        with self._lock:
            return self.active_campaigns.get(campaign_id, {'error': 'Campaign not found'})
    
    def list_campaigns(self) -> Dict:
        """List all campaigns"""
        with self._lock:
            return dict(self.active_campaigns)
    
    def get_campaign_summary(self, campaign_id: str) -> Dict:
        """Get campaign summary"""
        campaign = self.get_campaign_status(campaign_id)
        if 'error' in campaign:
            return campaign
        
        if campaign['status'] == 'completed':
            return self.orchestrator.generate_campaign_summary(campaign_id)
        
        return {
            'campaign_id': campaign_id,
            'status': campaign['status'],
            'targets': len(campaign.get('targets', [])),
            'profile': campaign.get('profile', 'unknown')
        }

# Global instance
multi_target_coordinator = MultiTargetCoordinator()