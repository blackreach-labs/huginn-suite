# app/tools/scan_plugins/idor_plugin.py
from .base_plugin import BaseScanPlugin
import re

class IDORPlugin(BaseScanPlugin):
    def __init__(self):
        super().__init__("IDOR Scanner", "Insecure Direct Object Reference detection")
    
    def scan(self, url, response, session):
        """Scan for IDOR vulnerabilities"""
        results = {'vulnerabilities': [], 'parameters': []}
        
        # Look for numeric IDs in URL and forms
        url_ids = re.findall(r'[?&](\w*id\w*)[=](\d+)', url, re.IGNORECASE)
        
        for param, value in url_ids:
            results['parameters'].append(f"{param}={value}")
            
            # Test ID manipulation
            try:
                test_id = str(int(value) + 1)
                test_url = url.replace(f"{param}={value}", f"{param}={test_id}")
                test_response = session.get(test_url, timeout=5, verify=False)
                
                if test_response.status_code == 200 and len(test_response.text) > 100:
                    results['vulnerabilities'].append({
                        'type': 'Potential IDOR',
                        'parameter': param,
                        'original_id': value,
                        'test_id': test_id,
                        'evidence': f'Different ID accessible: {test_response.status_code}'
                    })
            except:
                pass
        
        return results if results['vulnerabilities'] or results['parameters'] else None