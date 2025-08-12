"""Basic injection vulnerability tester"""
import asyncio
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup

class BasicInjectionTester:
    """Test for basic injection vulnerabilities"""
    
    def __init__(self, session):
        self.session = session
        self.vulnerabilities = []
    
    async def test_injections(self, base_url, content):
        """Test for basic injection vulnerabilities"""
        # Parse forms for injection testing
        soup = BeautifulSoup(content, 'html.parser')
        
        # Test forms
        for form in soup.find_all('form'):
            await self._test_form_injections(base_url, form)
        
        # Test URL parameters
        await self._test_url_parameters(base_url)
        
        return self.vulnerabilities
    
    async def _test_form_injections(self, base_url, form):
        """Test form fields for injection vulnerabilities"""
        action = form.get('action', base_url)
        method = form.get('method', 'GET').upper()
        
        # Build form action URL
        if not action.startswith('http'):
            action = urljoin(base_url, action)
        
        # Get form fields
        fields = {}
        for field in form.find_all(['input', 'textarea', 'select']):
            name = field.get('name')
            if name and field.get('type') != 'submit':
                fields[name] = 'test'
        
        if not fields:
            return
        
        # Test basic XSS
        await self._test_xss_in_form(action, method, fields)
        
        # Test basic SQL injection
        await self._test_sqli_in_form(action, method, fields)
    
    async def _test_xss_in_form(self, action, method, fields):
        """Test for XSS in form fields"""
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            "';alert('XSS');//"
        ]
        
        for payload in xss_payloads:
            test_fields = fields.copy()
            # Test each field individually
            for field_name in fields.keys():
                test_fields[field_name] = payload
                
                try:
                    if method == 'POST':
                        async with self.session.post(action, data=test_fields, timeout=10) as response:
                            content = await response.text()
                            if payload in content and response.status == 200:
                                self.vulnerabilities.append({
                                    'type': 'Cross-Site Scripting (XSS)',
                                    'severity': 'HIGH',
                                    'description': f'XSS vulnerability found in form field "{field_name}" at {action}',
                                    'url': action,
                                    'parameter': field_name,
                                    'payload': payload
                                })
                    else:
                        # GET request
                        async with self.session.get(action, params=test_fields, timeout=10) as response:
                            content = await response.text()
                            if payload in content and response.status == 200:
                                self.vulnerabilities.append({
                                    'type': 'Cross-Site Scripting (XSS)',
                                    'severity': 'HIGH',
                                    'description': f'XSS vulnerability found in parameter "{field_name}" at {action}',
                                    'url': action,
                                    'parameter': field_name,
                                    'payload': payload
                                })
                
                except Exception:
                    pass
                
                # Reset field value
                test_fields[field_name] = fields[field_name]
    
    async def _test_sqli_in_form(self, action, method, fields):
        """Test for SQL injection in form fields"""
        sqli_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin'--",
            "' UNION SELECT NULL--"
        ]
        
        sql_error_indicators = [
            'mysql_fetch_array',
            'ORA-01756',
            'Microsoft OLE DB Provider',
            'SQLServer JDBC Driver',
            'PostgreSQL query failed',
            'Warning: mysql_',
            'MySQLSyntaxErrorException',
            'valid MySQL result',
            'check the manual that corresponds to your MySQL',
            'Unknown column',
            'ORA-00933',
            'SQL syntax.*MySQL',
            'Warning.*mysql_.*',
            'valid MySQL result',
            'MySqlClient\\.'
        ]
        
        for payload in sqli_payloads:
            test_fields = fields.copy()
            # Test each field individually
            for field_name in fields.keys():
                test_fields[field_name] = payload
                
                try:
                    if method == 'POST':
                        async with self.session.post(action, data=test_fields, timeout=10) as response:
                            content = await response.text()
                            # Check for SQL error messages
                            if any(error.lower() in content.lower() for error in sql_error_indicators):
                                self.vulnerabilities.append({
                                    'type': 'SQL Injection',
                                    'severity': 'CRITICAL',
                                    'description': f'SQL injection vulnerability found in form field "{field_name}" at {action}',
                                    'url': action,
                                    'parameter': field_name,
                                    'payload': payload
                                })
                    else:
                        # GET request
                        async with self.session.get(action, params=test_fields, timeout=10) as response:
                            content = await response.text()
                            # Check for SQL error messages
                            if any(error.lower() in content.lower() for error in sql_error_indicators):
                                self.vulnerabilities.append({
                                    'type': 'SQL Injection',
                                    'severity': 'CRITICAL',
                                    'description': f'SQL injection vulnerability found in parameter "{field_name}" at {action}',
                                    'url': action,
                                    'parameter': field_name,
                                    'payload': payload
                                })
                
                except Exception:
                    pass
                
                # Reset field value
                test_fields[field_name] = fields[field_name]
    
    async def _test_url_parameters(self, base_url):
        """Test URL parameters for injection vulnerabilities"""
        parsed = urlparse(base_url)
        if not parsed.query:
            return
        
        params = parse_qs(parsed.query)
        base_url_no_params = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # Test XSS in URL parameters
        xss_payload = '<script>alert("XSS")</script>'
        for param_name in params.keys():
            test_params = {k: v[0] if v else '' for k, v in params.items()}
            test_params[param_name] = xss_payload
            
            try:
                async with self.session.get(base_url_no_params, params=test_params, timeout=10) as response:
                    content = await response.text()
                    if xss_payload in content and response.status == 200:
                        self.vulnerabilities.append({
                            'type': 'Cross-Site Scripting (XSS)',
                            'severity': 'HIGH',
                            'description': f'XSS vulnerability found in URL parameter "{param_name}"',
                            'url': base_url_no_params,
                            'parameter': param_name,
                            'payload': xss_payload
                        })
            except Exception:
                pass