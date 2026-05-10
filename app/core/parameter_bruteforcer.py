import asyncio
from urllib.parse import urljoin
from app.core.logger import logger

class ParameterBruteforcer:
    """Bruteforce hidden parameters using common parameter names"""
    
    def __init__(self):
        self.common_params = [
            # Common web parameters
            'id', 'user', 'username', 'email', 'password', 'token', 'key', 'api_key',
            'page', 'limit', 'offset', 'sort', 'order', 'filter', 'search', 'query',
            'action', 'method', 'function', 'cmd', 'command', 'exec', 'system',
            'file', 'path', 'dir', 'folder', 'upload', 'download', 'view', 'show',
            'admin', 'debug', 'test', 'dev', 'mode', 'format', 'type', 'lang',
            # API parameters
            'callback', 'jsonp', 'format', 'version', 'v', 'api', 'endpoint',
            # Hidden/debug parameters
            'debug', 'verbose', 'trace', 'log', 'dump', 'info', 'status'
        ]
    
    async def bruteforce_parameters(self, session, target_url, known_params=None):
        """Bruteforce hidden parameters on target URL"""
        findings = []
        discovered_params = []
        
        # Get baseline response
        try:
            async with session.get(target_url) as baseline_response:
                baseline_status = baseline_response.status
                baseline_content = await baseline_response.text()
                baseline_size = len(baseline_content)
        except Exception:
            return findings
        
        # Filter out known parameters
        known_param_names = set()
        if known_params:
            for url, forms in known_params.items():
                for form in forms:
                    for input_field in form['inputs']:
                        known_param_names.add(input_field['name'].lower())
        
        # Test each parameter
        for param in self.common_params:
            if param.lower() in known_param_names:
                continue  # Skip already known parameters
                
            # Test with different values
            test_values = ['1', 'true', 'test', '']
            
            for value in test_values:
                try:
                    params = {param: value}
                    async with session.get(target_url, params=params) as response:
                        content = await response.text()
                        
                        # Check for significant differences
                        if (response.status != baseline_status or 
                            abs(len(content) - baseline_size) > 50 or
                            self._has_error_indicators(content, baseline_content)):
                            
                            discovered_params.append({
                                'parameter': param,
                                'test_value': value,
                                'status_code': response.status,
                                'response_size': len(content),
                                'difference_type': self._classify_difference(
                                    baseline_status, response.status, 
                                    baseline_size, len(content)
                                )
                            })
                            break  # Stop testing values for this parameter
                    
                    await asyncio.sleep(0.1)  # Rate limiting
                    
                except Exception:
                    continue
        
        if discovered_params:
            # Categorize by potential impact
            high_impact = [p for p in discovered_params if 
                         any(keyword in p['parameter'] for keyword in 
                             ['admin', 'debug', 'cmd', 'exec', 'system', 'password', 'token'])]
            
            if high_impact:
                findings.append({
                    'type': 'High-Impact Hidden Parameters',
                    'severity': 'MEDIUM',
                    'description': f'Discovered {len(high_impact)} potentially dangerous hidden parameters',
                    'parameters': high_impact,
                    'recommendation': 'Review these parameters for security implications and access controls'
                })
            
            findings.append({
                'type': 'Hidden Parameter Discovery',
                'severity': 'INFO',
                'description': f'Discovered {len(discovered_params)} hidden parameters',
                'discovered_parameters': discovered_params[:10],  # Show first 10
                'recommendation': 'Test discovered parameters for injection vulnerabilities'
            })
        
        return findings
    
    def _has_error_indicators(self, content, baseline_content):
        """Check if response contains error indicators not in baseline"""
        error_indicators = ['error', 'exception', 'warning', 'invalid', 'missing', 'required']
        
        content_lower = content.lower()
        baseline_lower = baseline_content.lower()
        
        for indicator in error_indicators:
            if indicator in content_lower and indicator not in baseline_lower:
                return True
        return False
    
    def _classify_difference(self, baseline_status, response_status, baseline_size, response_size):
        """Classify the type of difference observed"""
        if baseline_status != response_status:
            return f'status_change_{baseline_status}_to_{response_status}'
        elif abs(response_size - baseline_size) > 100:
            return 'significant_size_change'
        else:
            return 'minor_change'