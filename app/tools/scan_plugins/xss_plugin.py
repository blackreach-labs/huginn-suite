# app/tools/scan_plugins/xss_plugin.py
from .base_plugin import BaseScanPlugin
import re

class XSSPlugin(BaseScanPlugin):
    def __init__(self):
        super().__init__("XSS Scanner", "Cross-Site Scripting detection")
    
    def scan(self, url, response, session):
        """Scan for XSS vulnerabilities"""
        results = {'vulnerabilities': [], 'parameters': []}
        
        if response.text:
            # Find input parameters
            input_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>'
            inputs = re.findall(input_pattern, response.text, re.IGNORECASE)
            
            for input_name in inputs:
                results['parameters'].append(input_name)
                
                # Test basic XSS payload
                try:
                    xss_payload = '<script>alert(1)</script>'
                    test_data = {input_name: xss_payload}
                    test_response = session.post(url, data=test_data, timeout=5, verify=False)
                    
                    if xss_payload in test_response.text:
                        results['vulnerabilities'].append({
                            'type': 'Reflected XSS',
                            'parameter': input_name,
                            'payload': xss_payload,
                            'evidence': 'Payload reflected in response'
                        })
                except:
                    pass
        
        return results if results['vulnerabilities'] or results['parameters'] else None