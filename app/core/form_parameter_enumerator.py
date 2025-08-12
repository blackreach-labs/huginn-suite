"""
Form Parameter Enumerator - Enhanced form and parameter discovery
"""
import re
from urllib.parse import urljoin, urlparse, parse_qsl
from typing import Dict, List, Any

class FormParameterEnumerator:
    def __init__(self):
        # Parameter patterns to look for in JavaScript
        self.js_patterns = [
            r'[\"\']([a-zA-Z_][a-zA-Z0-9_]*)[\"\']\s*:\s*[\"\']\$\{[^}]*\}[\"\'"]',  # Template variables
            r'data\[[\"\'"]([^\"\']+)[\"\']\]',  # data['param']
            r'params\.([a-zA-Z_][a-zA-Z0-9_]*)',  # params.paramName
            r'getParameter\([\"\'"]([^\"\']+)[\"\']\)',  # getParameter('param')
            r'request\[[\"\'"]([^\"\']+)[\"\']\]'  # request['param']
        ]
        
        # API endpoint patterns
        self.api_patterns = [
            r'[\"\']([/]api[^\"\'>\s]*)[\"\'"]',
            r'[\"\']([^\"\'>\s]+\.json)[\"\'"]',
            r'fetch\([\"\'"]([^\"\'">]+)[\"\'"]',
            r'axios\.[a-z]+\([\"\'"]([^\"\'">]+)[\"\'"]'
        ]

    def enumerate_page(self, url: str, content: str) -> Dict[str, Any]:
        """Enumerate parameters from a single page"""
        results = {
            'forms': [],
            'parameters': set(),
            'parameter_map': {},  # param_name -> [urls]
            'api_endpoints': [],
            'js_parameters': []
        }
        
        # Parse HTML forms
        self._parse_html_forms(url, content, results)
        
        # Extract URL parameters
        self._extract_url_parameters(url, results)
        
        # Extract JavaScript parameters
        self._extract_js_parameters(content, results)
        
        # Extract API endpoints
        self._extract_api_endpoints(url, content, results)
        
        # Build parameter mapping
        self._build_parameter_map(results)
        
        # Convert set to list for JSON serialization
        results['parameters'] = list(results['parameters'])
        
        return results
    
    def _parse_html_forms(self, url: str, content: str, results: Dict[str, Any]):
        """Parse HTML forms from content"""
        # Find all form tags
        form_pattern = r'<form[^>]*>(.*?)</form>'
        forms = re.findall(form_pattern, content, re.DOTALL | re.IGNORECASE)
        
        for form_html in forms:
            form_data = self._parse_single_form(url, form_html, content)
            if form_data:
                results['forms'].append(form_data)
                
                # Add parameters to global set
                for input_field in form_data['inputs']:
                    results['parameters'].add(input_field['name'])
    
    def _parse_single_form(self, base_url: str, form_html: str, full_content: str) -> Dict[str, Any]:
        """Parse a single form"""
        # Extract form attributes from the opening tag
        form_tag_match = re.search(r'<form([^>]*)>', full_content, re.IGNORECASE)
        if not form_tag_match:
            return None
        
        form_attrs = form_tag_match.group(1)
        
        # Extract action and method
        action_match = re.search(r'action=["\']([^"\']*)["\']', form_attrs, re.IGNORECASE)
        method_match = re.search(r'method=["\']([^"\']*)["\']', form_attrs, re.IGNORECASE)
        
        action = action_match.group(1) if action_match else ''
        method = method_match.group(1).lower() if method_match else 'get'
        
        # Make action URL absolute
        if action:
            action_url = urljoin(base_url, action)
        else:
            action_url = base_url
        
        # Extract input fields
        inputs = self._extract_form_inputs(form_html)
        
        return {
            'action': action_url,
            'method': method,
            'inputs': inputs,
            'input_count': len(inputs)
        }
    
    def _extract_form_inputs(self, form_html: str) -> List[Dict[str, Any]]:
        """Extract input fields from form HTML"""
        inputs = []
        
        # Input tags
        input_pattern = r'<input[^>]*>'
        input_matches = re.findall(input_pattern, form_html, re.IGNORECASE)
        
        for input_tag in input_matches:
            name_match = re.search(r'name=["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
            type_match = re.search(r'type=["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
            
            if name_match:
                inputs.append({
                    'name': name_match.group(1),
                    'type': type_match.group(1) if type_match else 'text',
                    'tag': 'input'
                })
        
        # Textarea tags
        textarea_pattern = r'<textarea[^>]*name=["\']([^"\']*)["\'][^>]*>'
        textarea_matches = re.findall(textarea_pattern, form_html, re.IGNORECASE)
        
        for name in textarea_matches:
            inputs.append({
                'name': name,
                'type': 'textarea',
                'tag': 'textarea'
            })
        
        # Select tags
        select_pattern = r'<select[^>]*name=["\']([^"\']*)["\'][^>]*>'
        select_matches = re.findall(select_pattern, form_html, re.IGNORECASE)
        
        for name in select_matches:
            inputs.append({
                'name': name,
                'type': 'select',
                'tag': 'select'
            })
        
        return inputs
    
    def _extract_url_parameters(self, url: str, results: Dict[str, Any]):
        """Extract parameters from URL query string"""
        parsed_url = urlparse(url)
        if parsed_url.query:
            params = parse_qsl(parsed_url.query)
            for name, value in params:
                results['parameters'].add(name)
    
    def _extract_js_parameters(self, content: str, results: Dict[str, Any]):
        """Extract parameter names from JavaScript code"""
        for pattern in self.js_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    param_name = match[0]
                else:
                    param_name = match
                
                if param_name and len(param_name) > 1:
                    results['js_parameters'].append(param_name)
                    results['parameters'].add(param_name)
    
    def _extract_api_endpoints(self, base_url: str, content: str, results: Dict[str, Any]):
        """Extract API endpoints from JavaScript"""
        endpoints = set()
        
        for pattern in self.api_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if match.startswith('/'):
                    full_url = urljoin(base_url, match)
                    endpoints.add(full_url)
        
        results['api_endpoints'] = list(endpoints)
    
    def _build_parameter_map(self, results: Dict[str, Any]):
        """Build mapping of parameter names to URLs where they appear"""
        param_map = {}
        
        # Map form parameters
        for form in results['forms']:
            for input_field in form['inputs']:
                param_name = input_field['name']
                if param_name not in param_map:
                    param_map[param_name] = []
                param_map[param_name].append(form['action'])
        
        results['parameter_map'] = param_map