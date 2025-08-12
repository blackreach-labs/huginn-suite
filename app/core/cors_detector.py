import re
from urllib.parse import urlparse

class CORSDetector:
    """Detect CORS misconfigurations that allow data exfiltration"""
    
    def __init__(self):
        self.dangerous_origins = ['*', 'null']
    
    async def check_cors(self, session, endpoints):
        """Check CORS configuration on sensitive endpoints"""
        findings = []
        
        for endpoint in endpoints[:5]:  # Limit to avoid overwhelming target
            try:
                headers = {'Origin': 'https://evil.com'}
                async with session.options(endpoint, headers=headers) as response:
                    cors_headers = {
                        'allow_origin': response.headers.get('Access-Control-Allow-Origin'),
                        'allow_credentials': response.headers.get('Access-Control-Allow-Credentials'),
                        'allow_methods': response.headers.get('Access-Control-Allow-Methods')
                    }
                    
                    # Check for dangerous configurations
                    allow_origin = cors_headers['allow_origin']
                    allow_creds = cors_headers['allow_credentials']
                    
                    if allow_origin == '*' and allow_creds == 'true':
                        findings.append({
                            'type': 'Critical CORS Misconfiguration',
                            'severity': 'CRITICAL',
                            'url': endpoint,
                            'description': f'CORS allows any origin (*) with credentials enabled',
                            'evidence': f'Access-Control-Allow-Origin: {allow_origin}, Access-Control-Allow-Credentials: {allow_creds}',
                            'recommendation': 'Use specific origins instead of wildcard when allowing credentials'
                        })
                    elif allow_origin == 'https://evil.com':  # Echoing arbitrary origin
                        findings.append({
                            'type': 'CORS Origin Reflection',
                            'severity': 'HIGH',
                            'url': endpoint,
                            'description': f'CORS reflects arbitrary Origin header',
                            'evidence': f'Sent Origin: https://evil.com, Received: {allow_origin}',
                            'recommendation': 'Validate Origin header against whitelist of allowed domains'
                        })
                    elif allow_origin == '*':
                        findings.append({
                            'type': 'Permissive CORS Policy',
                            'severity': 'MEDIUM',
                            'url': endpoint,
                            'description': f'CORS allows any origin (*)',
                            'evidence': f'Access-Control-Allow-Origin: {allow_origin}',
                            'recommendation': 'Restrict CORS to specific trusted origins'
                        })
                        
            except Exception:
                continue
                
        return findings