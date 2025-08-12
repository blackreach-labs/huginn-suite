import re
from urllib.parse import urlparse

class MixedContentDetector:
    """Detect mixed content vulnerabilities (HTTP resources on HTTPS pages)"""
    
    def __init__(self):
        self.resource_patterns = [
            re.compile(r'src=["\']([^"\']+)["\']', re.IGNORECASE),
            re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE),
            re.compile(r'action=["\']([^"\']+)["\']', re.IGNORECASE),
            re.compile(r'url\(["\']?([^"\'()]+)["\']?\)', re.IGNORECASE)  # CSS url()
        ]
    
    def analyze_mixed_content(self, page_url, content):
        """Detect HTTP resources loaded on HTTPS pages"""
        findings = []
        
        # Only check HTTPS pages
        if not page_url.startswith('https://'):
            return findings
        
        http_resources = set()
        
        # Extract all resource URLs
        for pattern in self.resource_patterns:
            matches = pattern.findall(content)
            for match in matches:
                if match.startswith('http://'):
                    http_resources.add(match)
        
        if http_resources:
            # Categorize resources
            scripts = [url for url in http_resources if url.endswith(('.js', '.jsx'))]
            stylesheets = [url for url in http_resources if url.endswith(('.css'))]
            images = [url for url in http_resources if url.endswith(('.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico'))]
            forms = [url for url in http_resources if not any(url.endswith(ext) for ext in ['.js', '.jsx', '.css', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico'])]
            
            severity = 'HIGH' if scripts or forms else 'MEDIUM'
            
            findings.append({
                'type': 'Mixed Content Vulnerability',
                'severity': severity,
                'url': page_url,
                'description': f'HTTPS page loads {len(http_resources)} HTTP resources',
                'resources': {
                    'scripts': scripts[:3],  # Show first 3 of each type
                    'stylesheets': stylesheets[:3],
                    'images': images[:3],
                    'forms': forms[:3]
                },
                'total_count': len(http_resources),
                'recommendation': 'Update all resource URLs to use HTTPS or protocol-relative URLs'
            })
        
        return findings