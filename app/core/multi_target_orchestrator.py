import asyncio
import time
from typing import Dict, List
from concurrent.futures import ThreadPoolExecutor

class MultiTargetOrchestrator:
    """Orchestrates scanning across multiple targets with resource management"""
    
    def __init__(self, max_concurrent_targets: int = 3):
        self.max_concurrent_targets = max_concurrent_targets
        self.scan_queue = []
        self.active_scans = {}
        self.completed_scans = {}
    
    def add_scan_campaign(self, campaign_name: str, targets: List[str], profile: str = 'normal'):
        """Add a scan campaign with multiple targets"""
        campaign = {
            'name': campaign_name,
            'targets': targets,
            'profile': profile,
            'created_at': time.time(),
            'status': 'queued'
        }
        
        self.scan_queue.append(campaign)
        return campaign
    
    async def execute_campaign(self, campaign_name: str) -> Dict:
        """Execute a scan campaign"""
        campaign = next((c for c in self.scan_queue if c['name'] == campaign_name), None)
        if not campaign:
            return {'error': 'Campaign not found'}
        
        campaign['status'] = 'running'
        campaign['started_at'] = time.time()
        
        # Create semaphore for concurrent target limiting
        semaphore = asyncio.Semaphore(self.max_concurrent_targets)
        
        # Execute scans for all targets
        tasks = []
        for target in campaign['targets']:
            task = self._scan_target_with_semaphore(semaphore, target, campaign['profile'])
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Compile campaign results
        campaign_results = {
            'campaign_name': campaign_name,
            'total_targets': len(campaign['targets']),
            'completed_at': time.time(),
            'duration': time.time() - campaign['started_at'],
            'target_results': {}
        }
        
        for i, result in enumerate(results):
            target = campaign['targets'][i]
            if isinstance(result, Exception):
                campaign_results['target_results'][target] = {'error': str(result)}
            else:
                campaign_results['target_results'][target] = result
        
        campaign['status'] = 'completed'
        self.completed_scans[campaign_name] = campaign_results
        
        return campaign_results
    
    async def _scan_target_with_semaphore(self, semaphore: asyncio.Semaphore, target: str, profile: str):
        """Scan individual target with semaphore control"""
        async with semaphore:
            from ..tools.huginn_vuln_scanner import HuginnVulnScanner
            
            scanner = HuginnVulnScanner(target, profile=profile)
            return await scanner.scan()
    
    def get_campaign_status(self, campaign_name: str) -> Dict:
        """Get status of a scan campaign"""
        # Check active scans
        if campaign_name in self.active_scans:
            return self.active_scans[campaign_name]
        
        # Check completed scans
        if campaign_name in self.completed_scans:
            return self.completed_scans[campaign_name]
        
        # Check queued scans
        queued = next((c for c in self.scan_queue if c['name'] == campaign_name), None)
        if queued:
            return queued
        
        return {'error': 'Campaign not found'}
    
    def generate_campaign_summary(self, campaign_name: str) -> Dict:
        """Generate summary across all targets in campaign"""
        campaign_results = self.completed_scans.get(campaign_name)
        if not campaign_results:
            return {'error': 'Campaign not completed or not found'}
        
        summary = {
            'campaign_name': campaign_name,
            'total_targets': campaign_results['total_targets'],
            'duration': campaign_results['duration'],
            'aggregate_stats': {
                'total_vulnerabilities': 0,
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0,
                'low_count': 0
            },
            'target_summaries': {}
        }
        
        for target, results in campaign_results['target_results'].items():
            if 'error' in results:
                summary['target_summaries'][target] = {'status': 'failed', 'error': results['error']}
                continue
            
            vulnerabilities = results.get('vulnerabilities', [])
            target_summary = {
                'status': 'completed',
                'vulnerability_count': len(vulnerabilities),
                'severity_breakdown': {
                    'Critical': sum(1 for v in vulnerabilities if v.get('severity') == 'Critical'),
                    'High': sum(1 for v in vulnerabilities if v.get('severity') == 'High'),
                    'Medium': sum(1 for v in vulnerabilities if v.get('severity') == 'Medium'),
                    'Low': sum(1 for v in vulnerabilities if v.get('severity') == 'Low')
                }
            }
            
            # Add to aggregate stats
            summary['aggregate_stats']['total_vulnerabilities'] += len(vulnerabilities)
            summary['aggregate_stats']['critical_count'] += target_summary['severity_breakdown']['Critical']
            summary['aggregate_stats']['high_count'] += target_summary['severity_breakdown']['High']
            summary['aggregate_stats']['medium_count'] += target_summary['severity_breakdown']['Medium']
            summary['aggregate_stats']['low_count'] += target_summary['severity_breakdown']['Low']
            
            summary['target_summaries'][target] = target_summary
        
        return summary
    
    def schedule_recurring_scan(self, campaign_name: str, targets: List[str], 
                              profile: str = 'normal', interval_hours: int = 24):
        """Schedule recurring scans (placeholder for scheduler integration)"""
        schedule_config = {
            'campaign_name': f"{campaign_name}_recurring",
            'targets': targets,
            'profile': profile,
            'interval_hours': interval_hours,
            'next_run': time.time() + (interval_hours * 3600),
            'type': 'recurring'
        }
        
        return schedule_config
    
    def get_resource_usage(self) -> Dict:
        """Get current resource usage statistics"""
        return {
            'active_scans': len(self.active_scans),
            'queued_campaigns': len([c for c in self.scan_queue if c['status'] == 'queued']),
            'completed_campaigns': len(self.completed_scans),
            'max_concurrent_targets': self.max_concurrent_targets
        }