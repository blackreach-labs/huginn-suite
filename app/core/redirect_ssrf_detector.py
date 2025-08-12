import re

class RedirectSSRFDetector:
    """Detect open redirect and SSRF attack surfaces"""
    
    def __init__(self):
        self.redirect_params = [
            'redirect', 'url', 'next', 'return', 'goto', 'continue', 'dest', 
            'destination', 'redir', 'out', 'view', 'to', 'link', 'site'
        ]
    
    def analyze_parameters(self, parameters):
        """Identify potential redirect/SSRF parameters"""
        findings = []
        candidates = []
        
        for url, forms in parameters.items():
            for form in forms:
                for input_field in form['inputs']:
                    param_name = input_field['name'].lower()
                    
                    # Check if parameter name suggests URL/redirect functionality
                    if any(keyword in param_name for keyword in self.redirect_params):
                        candidates.append({
                            'url': form['action'],
                            'method': form['method'],
                            'parameter': input_field['name'],
                            'type': input_field['type']
                        })
        
        if candidates:
            findings.append({
                'type': 'Open Redirect/SSRF Surface',
                'severity': 'MEDIUM',
                'description': f'Found {len(candidates)} parameters that may accept URLs',
                'candidates': candidates[:10],  # Show first 10
                'recommendation': 'Validate URL parameters against whitelist and check for SSRF/open redirect'
            })
            
        return findings
    
    def analyze_links(self, content, base_url):
        """Find links with redirect parameters"""
        findings = []
        redirect_links = []
        
        # Find links with redirect parameters
        link_pattern = r'href=["\']([^"\']*(?:redirect|url|next|return|goto)=[^"\']*)["\']'
        matches = re.findall(link_pattern, content, re.IGNORECASE)
        
        for match in matches:
            redirect_links.append(match)
            
        if redirect_links:
            findings.append({
                'type': 'Redirect Links Discovered',
                'severity': 'INFO',
                'description': f'Found {len(redirect_links)} links with redirect parameters',
                'links': redirect_links[:5],  # Show first 5
                'recommendation': 'Test these links for open redirect vulnerabilities'
            })
            
        return findings