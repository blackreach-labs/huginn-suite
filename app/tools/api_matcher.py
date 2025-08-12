# app/tools/api_matcher.py
import requests
from urllib.parse import urljoin

class APIMatcher:
    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.session.verify = False
    
    def match_endpoints(self, base_url, endpoints):
        """Match JavaScript endpoints to accessible APIs"""
        matched_endpoints = []
        
        for endpoint in endpoints[:20]:  # Limit to first 20 endpoints
            try:
                # Clean and construct full URL
                if endpoint.startswith('/'):
                    full_url = urljoin(base_url, endpoint)
                else:
                    full_url = urljoin(base_url, '/' + endpoint)
                
                # Test endpoint accessibility
                response = self.session.get(full_url, timeout=5)
                
                endpoint_info = {
                    'endpoint': endpoint,
                    'full_url': full_url,
                    'status_code': response.status_code,
                    'accessible': response.status_code < 400,
                    'content_type': response.headers.get('Content-Type', ''),
                    'content_length': len(response.content)
                }
                
                # Analyze response for API characteristics
                if response.status_code < 400:
                    endpoint_info.update(self._analyze_api_response(response))
                
                matched_endpoints.append(endpoint_info)
                
            except Exception as e:
                matched_endpoints.append({
                    'endpoint': endpoint,
                    'full_url': full_url if 'full_url' in locals() else endpoint,
                    'error': str(e),
                    'accessible': False
                })
        
        return matched_endpoints
    
    def _analyze_api_response(self, response):
        """Analyze API response characteristics"""
        analysis = {}
        
        content_type = response.headers.get('Content-Type', '').lower()
        
        # Determine API type
        if 'application/json' in content_type:
            analysis['api_type'] = 'JSON API'
            try:
                import json
                data = json.loads(response.text)
                analysis['json_structure'] = self._analyze_json_structure(data)
            except:
                pass
        elif 'application/xml' in content_type or 'text/xml' in content_type:
            analysis['api_type'] = 'XML API'
        elif 'text/html' in content_type:
            analysis['api_type'] = 'HTML Endpoint'
        else:
            analysis['api_type'] = 'Unknown'
        
        # Check for common API patterns
        if any(header in response.headers for header in ['X-RateLimit-Limit', 'X-API-Version']):
            analysis['api_characteristics'] = 'REST API with rate limiting'
        
        # Authentication hints
        if response.status_code == 401:
            analysis['authentication'] = 'Required'
            auth_header = response.headers.get('WWW-Authenticate', '')
            if auth_header:
                analysis['auth_type'] = auth_header.split()[0] if auth_header else 'Unknown'
        
        return analysis
    
    def _analyze_json_structure(self, data):
        """Analyze JSON structure"""
        if isinstance(data, dict):
            return {
                'type': 'object',
                'keys': list(data.keys())[:10],  # First 10 keys
                'key_count': len(data)
            }
        elif isinstance(data, list):
            return {
                'type': 'array',
                'length': len(data),
                'item_type': type(data[0]).__name__ if data else 'empty'
            }
        else:
            return {
                'type': type(data).__name__,
                'value': str(data)[:100]  # First 100 chars
            }