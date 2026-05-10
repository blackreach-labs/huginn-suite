"""Command injection vulnerability tester"""
import asyncio
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from app.core.logger import logger

class CommandInjectionTester:
    """Test for command injection vulnerabilities"""
    
    def __init__(self, session):
        self.session = session
        self.vulnerabilities = []
    
    async def test_command_injection(self, base_url, content):
        """Test for command injection vulnerabilities"""
        # Parse forms for command-related parameters
        soup = BeautifulSoup(content, 'html.parser')
        
        # Test forms
        for form in soup.find_all('form'):
            await self._test_form_command_injection(base_url, form)
        
        # Test URL parameters
        await self._test_url_command_injection(base_url)
        
        return self.vulnerabilities
    
    async def _test_form_command_injection(self, base_url, form):
        """Test form fields for command injection"""
        action = form.get('action', base_url)
        method = form.get('method', 'GET').upper()
        
        # Build form action URL
        if not action.startswith('http'):
            action = urljoin(base_url, action)
        
        # Get form fields, focus on command-related ones
        fields = {}
        cmd_related_fields = []
        
        for field in form.find_all(['input', 'textarea', 'select']):
            name = field.get('name', '').lower()
            if name and field.get('type') != 'submit':
                fields[name] = 'test'
                # Check if field name suggests command operations
                if any(keyword in name for keyword in ['cmd', 'command', 'exec', 'system', 'shell', 'run', 'ping', 'host']):
                    cmd_related_fields.append(name)
        
        if not fields:
            return
        
        # If no obvious command fields, test all fields (limited)
        if not cmd_related_fields:
            cmd_related_fields = list(fields.keys())[:2]  # Limit to first 2 fields
        
        # Test command injection payloads
        await self._test_cmd_payloads(action, method, fields, cmd_related_fields)
    
    async def _test_cmd_payloads(self, action, method, fields, target_fields):
        """Test command injection payloads"""
        # Safe command injection payloads that don't cause harm
        cmd_payloads = [
            '; echo "CMDINJECTION_TEST"',
            '| echo "CMDINJECTION_TEST"',
            '&& echo "CMDINJECTION_TEST"',
            '`echo "CMDINJECTION_TEST"`',
            '$(echo "CMDINJECTION_TEST")',
            '; whoami',
            '| whoami',
            '&& whoami',
            '`whoami`',
            '$(whoami)'
        ]
        
        # Indicators of successful command injection
        cmd_indicators = [
            'CMDINJECTION_TEST',
            'uid=',
            'gid=',
            'groups=',
            'root',
            'www-data',
            'apache',
            'nginx',
            'nobody'
        ]
        
        for payload in cmd_payloads:
            for field_name in target_fields:
                test_fields = fields.copy()
                test_fields[field_name] = payload
                
                try:
                    if method == 'POST':
                        async with self.session.post(action, data=test_fields, timeout=10) as response:
                            content = await response.text()
                            # Check for command injection indicators
                            if any(indicator in content for indicator in cmd_indicators):
                                self.vulnerabilities.append({
                                    'type': 'Command Injection',
                                    'severity': 'CRITICAL',
                                    'description': f'Command injection vulnerability found in form field "{field_name}" at {action}',
                                    'url': action,
                                    'parameter': field_name,
                                    'payload': payload
                                })
                                break  # Found vulnerability, no need to test more payloads for this field
                    else:
                        # GET request
                        async with self.session.get(action, params=test_fields, timeout=10) as response:
                            content = await response.text()
                            # Check for command injection indicators
                            if any(indicator in content for indicator in cmd_indicators):
                                self.vulnerabilities.append({
                                    'type': 'Command Injection',
                                    'severity': 'CRITICAL',
                                    'description': f'Command injection vulnerability found in parameter "{field_name}" at {action}',
                                    'url': action,
                                    'parameter': field_name,
                                    'payload': payload
                                })
                                break  # Found vulnerability, no need to test more payloads for this field
                
                except Exception as _exc:
                    pass
                    logger.debug("Suppressed exception", exc_info=True)
    
    async def _test_url_command_injection(self, base_url):
        """Test URL parameters for command injection"""
        parsed = urlparse(base_url)
        if not parsed.query:
            return
        
        params = parse_qs(parsed.query)
        base_url_no_params = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # Focus on command-related parameters
        cmd_params = []
        for param_name in params.keys():
            if any(keyword in param_name.lower() for keyword in ['cmd', 'command', 'exec', 'system', 'shell', 'run', 'ping', 'host']):
                cmd_params.append(param_name)
        
        # If no obvious command params, test all params (limited)
        if not cmd_params:
            cmd_params = list(params.keys())[:1]  # Limit to first param only
        
        cmd_payload = '; echo "CMDINJECTION_TEST"'
        cmd_indicators = ['CMDINJECTION_TEST']
        
        for param_name in cmd_params:
            test_params = {k: v[0] if v else '' for k, v in params.items()}
            test_params[param_name] = cmd_payload
            
            try:
                async with self.session.get(base_url_no_params, params=test_params, timeout=10) as response:
                    content = await response.text()
                    if any(indicator in content for indicator in cmd_indicators):
                        self.vulnerabilities.append({
                            'type': 'Command Injection',
                            'severity': 'CRITICAL',
                            'description': f'Command injection vulnerability found in URL parameter "{param_name}"',
                            'url': base_url_no_params,
                            'parameter': param_name,
                            'payload': cmd_payload
                        })
            except Exception as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
