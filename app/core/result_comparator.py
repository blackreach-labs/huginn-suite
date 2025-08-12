# app/core/result_comparator.py
import json
import os
from datetime import datetime
from typing import Dict, List, Tuple

class ResultComparator:
    """Compare scan results to identify changes"""
    
    def __init__(self):
        self.comparison_dir = "comparisons"
        os.makedirs(self.comparison_dir, exist_ok=True)
    
    def compare_results(self, current_results: Dict, target: str, scan_type: str) -> Dict:
        """Compare current results with previous scans"""
        comparison = {
            'target': target,
            'scan_type': scan_type,
            'timestamp': datetime.now().isoformat(),
            'changes_detected': False,
            'new_findings': [],
            'removed_findings': [],
            'unchanged_findings': [],
            'summary': {}
        }
        
        # Find previous scan
        previous_results = self._get_previous_scan(target, scan_type)
        if not previous_results:
            comparison['summary'] = {'status': 'first_scan', 'message': 'No previous scan found for comparison'}
            return comparison
        
        # Perform comparison
        if scan_type == 'dns_enum':
            comparison.update(self._compare_dns_results(current_results, previous_results))
        else:
            comparison.update(self._compare_generic_results(current_results, previous_results))
        
        # Save comparison
        self._save_comparison(comparison)
        return comparison
    
    def _get_previous_scan(self, target: str, scan_type: str) -> Dict:
        """Get most recent previous scan results"""
        cache_dir = "cache"
        if not os.path.exists(cache_dir):
            return {}
        
        # Look for cached results
        for filename in os.listdir(cache_dir):
            if filename.endswith('.json'):
                try:
                    with open(os.path.join(cache_dir, filename), 'r') as f:
                        cache_data = json.load(f)
                    if (cache_data.get('tool') == scan_type and 
                        cache_data.get('target') == target):
                        return cache_data.get('results', {})
                except:
                    continue
        return {}
    
    def _compare_dns_results(self, current: Dict, previous: Dict) -> Dict:
        """Compare DNS enumeration results"""
        current_domains = set(current.keys()) if isinstance(current, dict) else set()
        previous_domains = set(previous.keys()) if isinstance(previous, dict) else set()
        
        new_domains = current_domains - previous_domains
        removed_domains = previous_domains - current_domains
        unchanged_domains = current_domains & previous_domains
        
        changes = {
            'changes_detected': bool(new_domains or removed_domains),
            'new_findings': [{'type': 'new_subdomain', 'value': domain, 'details': current.get(domain, {})} 
                           for domain in new_domains],
            'removed_findings': [{'type': 'removed_subdomain', 'value': domain, 'details': previous.get(domain, {})} 
                               for domain in removed_domains],
            'unchanged_findings': [{'type': 'existing_subdomain', 'value': domain} 
                                 for domain in unchanged_domains],
            'summary': {
                'new_count': len(new_domains),
                'removed_count': len(removed_domains),
                'unchanged_count': len(unchanged_domains),
                'total_current': len(current_domains),
                'total_previous': len(previous_domains)
            }
        }
        
        return changes
    
    def _compare_generic_results(self, current: Dict, previous: Dict) -> Dict:
        """Compare generic scan results"""
        current_str = json.dumps(current, sort_keys=True)
        previous_str = json.dumps(previous, sort_keys=True)
        
        changes_detected = current_str != previous_str
        
        return {
            'changes_detected': changes_detected,
            'new_findings': [{'type': 'data_change', 'value': 'Results modified'}] if changes_detected else [],
            'removed_findings': [],
            'unchanged_findings': [{'type': 'data_unchanged', 'value': 'Results identical'}] if not changes_detected else [],
            'summary': {
                'status': 'changed' if changes_detected else 'unchanged',
                'message': 'Results have changed since last scan' if changes_detected else 'Results unchanged'
            }
        }
    
    def _save_comparison(self, comparison: Dict):
        """Save comparison results"""
        filename = f"{comparison['target']}_{comparison['scan_type']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(self.comparison_dir, filename)
        
        try:
            with open(filepath, 'w') as f:
                json.dump(comparison, f, indent=2)
        except:
            pass  # Fail silently
    
    def get_comparison_history(self, target: str, scan_type: str) -> List[Dict]:
        """Get comparison history for target"""
        history = []
        if not os.path.exists(self.comparison_dir):
            return history
        
        prefix = f"{target}_{scan_type}_"
        for filename in sorted(os.listdir(self.comparison_dir)):
            if filename.startswith(prefix) and filename.endswith('.json'):
                try:
                    with open(os.path.join(self.comparison_dir, filename), 'r') as f:
                        history.append(json.load(f))
                except:
                    continue
        
        return history[-10:]  # Return last 10 comparisons

# Global instance
result_comparator = ResultComparator()