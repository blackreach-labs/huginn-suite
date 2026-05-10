import json
import re
from typing import Dict, List, Optional
from app.core.logger import logger

class APISecurityTester:
    """Advanced API security testing module"""
    
    def __init__(self, session):
        self.session = session
        self.discovered_endpoints = []
    
    async def test_api_security(self, target: str) -> List[Dict]:
        """Comprehensive API security testing"""
        vulnerabilities = []
        
        # Discover API endpoints
        api_endpoints = await self._discover_api_endpoints(target)
        
        for endpoint in api_endpoints:
            # Test each endpoint
            vulns = await self._test_endpoint_security(endpoint)
            vulnerabilities.extend(vulns)
        
        # Test for GraphQL
        graphql_vulns = await self._test_graphql_security(target)
        vulnerabilities.extend(graphql_vulns)
        
        # Test JWT security
        jwt_vulns = await self._test_jwt_security(target)
        vulnerabilities.extend(jwt_vulns)
        
        return vulnerabilities
    
    async def _discover_api_endpoints(self, target: str) -> List[str]:
        """Discover API endpoints"""
        endpoints = []
        
        # Common API paths
        api_paths = [
            '/api', '/api/v1', '/api/v2', '/rest', '/graphql',
            '/swagger', '/api-docs', '/openapi.json'
        ]
        
        for path in api_paths:
            try:
                async with self.session.get(f"{target}{path}") as resp:
                    if resp.status == 200:
                        endpoints.append(f"{target}{path}")
                        
                        # Parse API documentation
                        content = await resp.text()
                        if 'swagger' in content.lower() or 'openapi' in content.lower():
                            additional_endpoints = self._parse_api_docs(content, target)
                            endpoints.extend(additional_endpoints)
            except Exception as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        
        return endpoints
    
    def _parse_api_docs(self, content: str, base_url: str) -> List[str]:
        """Parse API documentation for endpoints"""
        endpoints = []
        
        # Extract paths from Swagger/OpenAPI docs
        try:
            if content.strip().startswith('{'):
                api_doc = json.loads(content)
                if 'paths' in api_doc:
                    for path in api_doc['paths'].keys():
                        endpoints.append(f"{base_url}{path}")
        except:
            # Fallback to regex extraction
            path_patterns = re.findall(r'["\'](/api/[^"\']*)["\']', content)
            endpoints.extend([f"{base_url}{path}" for path in path_patterns])
        
        return endpoints[:10]  # Limit results
    
    async def _test_endpoint_security(self, endpoint: str) -> List[Dict]:
        """Test individual API endpoint security"""
        vulnerabilities = []
        
        # Test for IDOR
        if re.search(r'/\d+/?$', endpoint):
            idor_vuln = await self._test_api_idor(endpoint)
            if idor_vuln:
                vulnerabilities.append(idor_vuln)
        
        # Test for injection
        injection_vuln = await self._test_api_injection(endpoint)
        if injection_vuln:
            vulnerabilities.append(injection_vuln)
        
        # Test for rate limiting
        rate_limit_vuln = await self._test_rate_limiting(endpoint)
        if rate_limit_vuln:
            vulnerabilities.append(rate_limit_vuln)
        
        return vulnerabilities
    
    async def _test_api_idor(self, endpoint: str) -> Optional[Dict]:
        """Test for API IDOR vulnerabilities"""
        try:
            # Get baseline response
            async with self.session.get(endpoint) as resp:
                baseline_status = resp.status
                baseline_content = await resp.text()
            
            # Test with different IDs
            modified_endpoint = re.sub(r'/\d+/?$', '/999999', endpoint)
            async with self.session.get(modified_endpoint) as resp:
                if resp.status == 200 and len(await resp.text()) > 100:
                    return {
                        'type': 'API IDOR',
                        'severity': 'High',
                        'description': f'IDOR vulnerability in API endpoint: {endpoint}',
                        'cvss_score': 7.5,
                        'remediation': 'Implement proper authorization checks for API endpoints'
                    }
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        
        return None
    
    async def _test_api_injection(self, endpoint: str) -> Optional[Dict]:
        """Test for API injection vulnerabilities"""
        injection_payloads = [
            "'; DROP TABLE users--",
            '<script>alert(1)</script>',
            '{{7*7}}',
            '../../../etc/passwd'
        ]
        
        for payload in injection_payloads:
            try:
                # Test in query parameters
                async with self.session.get(f"{endpoint}?q={payload}") as resp:
                    content = await resp.text()
                    
                    # Check for injection indicators
                    if any(indicator in content.lower() for indicator in ['error', 'exception', '49', 'root:']):
                        return {
                            'type': 'API Injection',
                            'severity': 'High',
                            'description': f'Injection vulnerability in API: {endpoint}',
                            'payload': payload,
                            'cvss_score': 8.1,
                            'remediation': 'Implement input validation and parameterized queries'
                        }
            except:
                continue
        
        return None
    
    async def _test_rate_limiting(self, endpoint: str) -> Optional[Dict]:
        """Test for missing rate limiting"""
        try:
            # Send multiple rapid requests
            tasks = []
            for _ in range(10):
                tasks.append(self.session.get(endpoint))
            
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            success_count = sum(1 for r in responses if hasattr(r, 'status') and r.status == 200)
            
            if success_count >= 8:  # Most requests succeeded
                return {
                    'type': 'Missing Rate Limiting',
                    'severity': 'Medium',
                    'description': f'No rate limiting on API endpoint: {endpoint}',
                    'cvss_score': 5.3,
                    'remediation': 'Implement rate limiting to prevent abuse'
                }
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        
        return None
    
    async def _test_graphql_security(self, target: str) -> List[Dict]:
        """Test GraphQL security"""
        vulnerabilities = []
        
        graphql_endpoints = ['/graphql', '/api/graphql', '/v1/graphql']
        
        for endpoint in graphql_endpoints:
            try:
                # Test introspection
                introspection_query = {
                    "query": "query IntrospectionQuery { __schema { queryType { name } } }"
                }
                
                async with self.session.post(f"{target}{endpoint}", json=introspection_query) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        if 'queryType' in content:
                            vulnerabilities.append({
                                'type': 'GraphQL Introspection Enabled',
                                'severity': 'Medium',
                                'description': f'GraphQL introspection enabled at {endpoint}',
                                'cvss_score': 5.3,
                                'remediation': 'Disable GraphQL introspection in production'
                            })
            except Exception as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        
        return vulnerabilities
    
    async def _test_jwt_security(self, target: str) -> List[Dict]:
        """Test JWT token security"""
        vulnerabilities = []
        
        try:
            # Look for JWT tokens in responses
            async with self.session.get(target) as resp:
                content = await resp.text()
                
                # Find JWT tokens
                jwt_pattern = r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
                jwt_tokens = re.findall(jwt_pattern, content)
                
                for token in jwt_tokens:
                    # Basic JWT security checks
                    parts = token.split('.')
                    if len(parts) == 3:
                        # Check for 'none' algorithm
                        try:
                            import base64
                            header = json.loads(base64.b64decode(parts[0] + '=='))
                            if header.get('alg') == 'none':
                                vulnerabilities.append({
                                    'type': 'JWT None Algorithm',
                                    'severity': 'High',
                                    'description': 'JWT token uses insecure "none" algorithm',
                                    'cvss_score': 7.5,
                                    'remediation': 'Use secure JWT signing algorithms (RS256, HS256)'
                                })
                        except Exception as _exc:
                            pass
                            logger.debug("Suppressed exception", exc_info=True)
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        
        return vulnerabilities