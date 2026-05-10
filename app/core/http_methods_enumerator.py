from app.core.logger import logger
class HTTPMethodsEnumerator:
    """Enumerate and test HTTP methods beyond basic OPTIONS"""
    
    def __init__(self):
        self.methods_to_test = [
            'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS',
            'TRACE', 'CONNECT', 'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK'
        ]
        self.dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH']
        self.webdav_methods = ['PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK']
    
    async def enumerate_methods(self, session, target_url):
        """Comprehensive HTTP methods enumeration"""
        findings = []
        allowed_methods = []
        
        for method in self.methods_to_test:
            try:
                async with session.request(method, target_url) as response:
                    # Method is allowed if we don't get 405 (Method Not Allowed)
                    if response.status != 405:
                        allowed_methods.append({
                            'method': method,
                            'status': response.status,
                            'response_size': len(await response.text()) if response.status < 400 else 0
                        })
                        
                        # Check for dangerous methods
                        if method in self.dangerous_methods:
                            severity = 'HIGH' if method in ['PUT', 'DELETE'] else 'MEDIUM'
                            findings.append({
                                'type': 'Dangerous HTTP Method',
                                'severity': severity,
                                'method': method,
                                'status_code': response.status,
                                'description': f'{method} method is allowed (Status: {response.status})',
                                'recommendation': f'Disable {method} method if not required for application functionality'
                            })
                        
                        # Check for WebDAV methods
                        if method in self.webdav_methods:
                            findings.append({
                                'type': 'WebDAV Method Enabled',
                                'severity': 'MEDIUM',
                                'method': method,
                                'status_code': response.status,
                                'description': f'WebDAV method {method} is enabled',
                                'recommendation': 'Disable WebDAV if not required, or restrict access'
                            })
            except Exception:
                continue
        
        # Check for method override headers
        override_findings = await self._test_method_override(session, target_url)
        findings.extend(override_findings)
        
        # Summary finding
        if allowed_methods:
            method_names = [m['method'] for m in allowed_methods]
            findings.append({
                'type': 'HTTP Methods Summary',
                'severity': 'INFO',
                'description': f'Allowed HTTP methods: {", ".join(method_names)}',
                'allowed_methods': allowed_methods,
                'recommendation': 'Review and restrict HTTP methods to only those required'
            })
        
        return findings
    
    async def _test_method_override(self, session, target_url):
        """Test for HTTP method override vulnerabilities"""
        findings = []
        override_headers = [
            'X-HTTP-Method-Override',
            'X-HTTP-Method',
            'X-Method-Override'
        ]
        
        for header in override_headers:
            try:
                headers = {header: 'PUT'}
                async with session.post(target_url, headers=headers) as response:
                    # If server processes the override, it might behave differently
                    if response.status not in [405, 501]:  # Not "Method Not Allowed" or "Not Implemented"
                        findings.append({
                            'type': 'HTTP Method Override',
                            'severity': 'MEDIUM',
                            'header': header,
                            'description': f'Server may process {header} header for method override',
                            'recommendation': 'Disable HTTP method override if not required'
                        })
            except Exception:
                continue
                
        return findings