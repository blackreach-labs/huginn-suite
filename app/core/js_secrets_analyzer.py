import re
from urllib.parse import urljoin, urlparse

class JSSecretsAnalyzer:
    """Extract hidden endpoints and secrets from JavaScript"""
    
    def __init__(self):
        self.api_patterns = [
            re.compile(r'["\']([/]api[/][\w/.-]+)["\']', re.IGNORECASE),
            re.compile(r'fetch\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
            re.compile(r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
            re.compile(r'["\']([/][\w/.-]*\.json)["\']', re.IGNORECASE)
        ]
        
        self.secret_patterns = [
            re.compile(r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([^"\']{10,})["\']', re.IGNORECASE),
            re.compile(r'(?:token|auth[_-]?token)\s*[:=]\s*["\']([^"\']{20,})["\']', re.IGNORECASE),
            re.compile(r'(?:secret|client[_-]?secret)\s*[:=]\s*["\']([^"\']{10,})["\']', re.IGNORECASE),
            re.compile(r'(?:password|pass)\s*[:=]\s*["\']([^"\']{6,})["\']', re.IGNORECASE)
        ]
    
    async def analyze_javascript(self, session, base_url, content):
        """Extract endpoints and secrets from JavaScript"""
        findings = []
        js_urls = set()
        
        # Find script sources
        script_src_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
        for match in script_src_pattern.findall(content):
            js_urls.add(urljoin(base_url, match))
        
        # Find inline scripts
        inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', content, re.DOTALL | re.IGNORECASE)
        
        all_js_content = '\n'.join(inline_scripts)
        
        # Download external JS files (limit to avoid overwhelming)
        for js_url in list(js_urls)[:5]:
            try:
                async with session.get(js_url) as response:
                    if response.content_type and 'javascript' in response.content_type:
                        js_content = await response.text()
                        all_js_content += '\n' + js_content
            except Exception:
                continue
        
        if not all_js_content.strip():
            return findings
        
        # Extract API endpoints
        api_endpoints = set()
        for pattern in self.api_patterns:
            matches = pattern.findall(all_js_content)
            for match in matches:
                if match.startswith('/'):
                    api_endpoints.add(urljoin(base_url, match))
                elif match.startswith('http'):
                    api_endpoints.add(match)
        
        if api_endpoints:
            findings.append({
                'type': 'Hidden API Endpoints',
                'severity': 'INFO',
                'description': f'Found {len(api_endpoints)} API endpoints in JavaScript',
                'endpoints': list(api_endpoints)[:10],  # Show first 10
                'recommendation': 'Review these endpoints for authentication and authorization'
            })
        
        # Extract potential secrets
        secrets_found = []
        for pattern in self.secret_patterns:
            matches = pattern.findall(all_js_content)
            for match in matches:
                # Filter out obvious test/dummy values
                if not any(dummy in match.lower() for dummy in ['test', 'demo', 'example', 'placeholder', 'xxx']):
                    secrets_found.append({
                        'type': pattern.pattern.split('|')[0].replace('(?:', '').replace('[_-]?', '_'),
                        'value': match[:20] + '...' if len(match) > 20 else match
                    })
        
        if secrets_found:
            findings.append({
                'type': 'Potential Secrets in JavaScript',
                'severity': 'HIGH',
                'description': f'Found {len(secrets_found)} potential secrets in JavaScript',
                'secrets': secrets_found[:5],  # Show first 5
                'recommendation': 'Remove hardcoded secrets from client-side code'
            })
        
        return findings