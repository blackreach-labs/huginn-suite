# app/tools/scan_plugins/ssrf_plugin.py
from .base_plugin import BaseScanPlugin
import re

class SSRFPlugin(BaseScanPlugin):
    def __init__(self):
        super().__init__("SSRF Scanner", "Server-Side Request Forgery detection")
    
    def scan(self, url, response, session):
        """Scan for SSRF vulnerabilities"""
        results = {'vulnerabilities': [], 'parameters': []}
        
        # Look for URL parameters in forms
        if response.text:
            # Find forms with URL-like parameters
            form_pattern = r'<form[^>]*>(.*?)</form>'
            forms = re.findall(form_pattern, response.text, re.DOTALL | re.IGNORECASE)
            
            for form in forms:
                # Look for URL/callback parameters
                url_params = re.findall(r'name=["\']([^"\']*(?:url|callback|redirect|link)[^"\']*)["\']', form, re.IGNORECASE)
                for param in url_params:
                    results['parameters'].append(param)
                    
                    # Test basic SSRF payload
                    try:
                        test_data = {param: 'http://127.0.0.1:80'}
                        test_response = session.post(url, data=test_data, timeout=5, verify=False)
                        if test_response.status_code != response.status_code:
                            results['vulnerabilities'].append({
                                'type': 'Potential SSRF',
                                'parameter': param,
                                'evidence': f'Status code changed: {response.status_code} -> {test_response.status_code}'
                            })
                    except:
                        pass
        
        return results if results['vulnerabilities'] or results['parameters'] else None