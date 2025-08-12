"""
Form Analyzer - Analyzes forms for security issues
"""
import re
from typing import Dict, List, Any

class FormAnalyzer:
    def __init__(self):
        # Sensitive parameter names that indicate security risks
        self.sensitive_params = {
            'high_risk': ['cmd', 'exec', 'system', 'eval', 'file', 'path', 'url', 'redirect'],
            'medium_risk': ['id', 'user', 'admin', 'password', 'token', 'key'],
            'csrf_indicators': ['csrf', 'token', '_token', 'authenticity_token', 'csrfmiddlewaretoken']
        }
        
        # File upload indicators
        self.upload_indicators = ['file', 'upload', 'attachment', 'document', 'image']

    def analyze_page(self, url: str, content: str) -> Dict[str, Any]:
        """Analyze all forms on a page"""
        results = {
            'forms_found': 0,
            'security_issues': [],
            'form_details': [],
            'csrf_protected_forms': 0,
            'file_upload_forms': 0,
            'login_forms': 0
        }
        
        # Find all forms
        form_pattern = r'<form[^>]*>(.*?)</form>'
        forms = re.finditer(form_pattern, content, re.DOTALL | re.IGNORECASE)
        
        for form_match in forms:
            form_data = self._analyze_single_form(url, form_match, content)
            results['form_details'].append(form_data)
            results['forms_found'] += 1
            
            # Aggregate statistics
            if form_data['has_csrf_protection']:
                results['csrf_protected_forms'] += 1
            if form_data['is_file_upload']:
                results['file_upload_forms'] += 1
            if form_data['is_login_form']:
                results['login_forms'] += 1
            
            # Add security issues
            results['security_issues'].extend(form_data['security_issues'])
        
        return results
    
    def _analyze_single_form(self, base_url: str, form_match: re.Match, full_content: str) -> Dict[str, Any]:
        """Analyze a single form for security issues"""
        form_html = form_match.group(0)
        form_content = form_match.group(1)
        
        # Extract form attributes
        form_attrs = self._extract_form_attributes(form_html)
        
        # Extract inputs
        inputs = self._extract_all_inputs(form_content)
        
        # Analyze form characteristics
        analysis = {
            'action': form_attrs.get('action', ''),
            'method': form_attrs.get('method', 'get').lower(),
            'inputs': inputs,
            'input_count': len(inputs),
            'has_csrf_protection': self._has_csrf_protection(inputs),
            'is_file_upload': self._is_file_upload_form(inputs),
            'is_login_form': self._is_login_form(inputs),
            'security_issues': []
        }
        
        # Check for security issues
        self._check_csrf_protection(analysis)
        self._check_sensitive_parameters(analysis)
        self._check_file_upload_security(analysis)
        self._check_login_form_security(analysis)
        self._check_hidden_fields(analysis)
        
        return analysis
    
    def _extract_form_attributes(self, form_html: str) -> Dict[str, str]:
        """Extract attributes from form tag"""
        attrs = {}
        
        # Extract action
        action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        if action_match:
            attrs['action'] = action_match.group(1)
        
        # Extract method
        method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        if method_match:
            attrs['method'] = method_match.group(1)
        
        # Extract enctype
        enctype_match = re.search(r'enctype=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        if enctype_match:
            attrs['enctype'] = enctype_match.group(1)
        
        return attrs
    
    def _extract_all_inputs(self, form_content: str) -> List[Dict[str, str]]:
        """Extract all input elements from form"""
        inputs = []
        
        # Input tags
        input_pattern = r'<input[^>]*>'
        for input_match in re.finditer(input_pattern, form_content, re.IGNORECASE):
            input_tag = input_match.group(0)
            input_data = self._parse_input_tag(input_tag)
            if input_data:
                inputs.append(input_data)
        
        # Textarea tags
        textarea_pattern = r'<textarea[^>]*name=["\']([^"\']*)["\'][^>]*>'
        for textarea_match in re.finditer(textarea_pattern, form_content, re.IGNORECASE):
            inputs.append({
                'name': textarea_match.group(1),
                'type': 'textarea',
                'tag': 'textarea'
            })
        
        # Select tags
        select_pattern = r'<select[^>]*name=["\']([^"\']*)["\'][^>]*>'
        for select_match in re.finditer(select_pattern, form_content, re.IGNORECASE):
            inputs.append({
                'name': select_match.group(1),
                'type': 'select',
                'tag': 'select'
            })
        
        return inputs
    
    def _parse_input_tag(self, input_tag: str) -> Dict[str, str]:
        """Parse individual input tag"""
        name_match = re.search(r'name=["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
        type_match = re.search(r'type=["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
        value_match = re.search(r'value=["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
        
        if not name_match:
            return None
        
        return {
            'name': name_match.group(1),
            'type': type_match.group(1) if type_match else 'text',
            'value': value_match.group(1) if value_match else '',
            'tag': 'input'
        }
    
    def _has_csrf_protection(self, inputs: List[Dict[str, str]]) -> bool:
        """Check if form has CSRF protection"""
        for input_field in inputs:
            name = input_field['name'].lower()
            if any(csrf_indicator in name for csrf_indicator in self.sensitive_params['csrf_indicators']):
                return True
        return False
    
    def _is_file_upload_form(self, inputs: List[Dict[str, str]]) -> bool:
        """Check if form is for file upload"""
        for input_field in inputs:
            if input_field['type'].lower() == 'file':
                return True
            name = input_field['name'].lower()
            if any(upload_indicator in name for upload_indicator in self.upload_indicators):
                return True
        return False
    
    def _is_login_form(self, inputs: List[Dict[str, str]]) -> bool:
        """Check if form is a login form"""
        has_password = any(inp['type'].lower() == 'password' for inp in inputs)
        has_username = any(name in inp['name'].lower() for inp in inputs 
                          for name in ['user', 'login', 'email', 'username'])
        return has_password and has_username
    
    def _check_csrf_protection(self, analysis: Dict[str, Any]):
        """Check for CSRF protection issues"""
        if analysis['method'] == 'post' and not analysis['has_csrf_protection']:
            severity = 'HIGH' if analysis['is_login_form'] else 'MEDIUM'
            analysis['security_issues'].append({
                'type': 'Missing CSRF Protection',
                'severity': severity,
                'description': f'Form at {analysis["action"]} lacks CSRF token',
                'form_action': analysis['action']
            })
    
    def _check_sensitive_parameters(self, analysis: Dict[str, Any]):
        """Check for sensitive parameter names"""
        for input_field in analysis['inputs']:
            name = input_field['name'].lower()
            
            # Check high-risk parameters
            for high_risk in self.sensitive_params['high_risk']:
                if high_risk in name:
                    analysis['security_issues'].append({
                        'type': 'Sensitive Parameter Name',
                        'severity': 'HIGH',
                        'description': f'Form contains potentially dangerous parameter: {input_field["name"]}',
                        'parameter_name': input_field['name'],
                        'risk_type': high_risk
                    })
                    break
            
            # Check medium-risk parameters
            for medium_risk in self.sensitive_params['medium_risk']:
                if medium_risk in name:
                    analysis['security_issues'].append({
                        'type': 'Sensitive Parameter Name',
                        'severity': 'MEDIUM',
                        'description': f'Form contains sensitive parameter: {input_field["name"]}',
                        'parameter_name': input_field['name'],
                        'risk_type': medium_risk
                    })
                    break
    
    def _check_file_upload_security(self, analysis: Dict[str, Any]):
        """Check file upload security"""
        if analysis['is_file_upload']:
            analysis['security_issues'].append({
                'type': 'File Upload Form',
                'severity': 'HIGH',
                'description': 'File upload form detected - potential for malicious file upload',
                'form_action': analysis['action']
            })
    
    def _check_login_form_security(self, analysis: Dict[str, Any]):
        """Check login form security"""
        if analysis['is_login_form']:
            analysis['security_issues'].append({
                'type': 'Login Form Detected',
                'severity': 'MEDIUM',
                'description': 'Login form detected - potential target for brute force attacks',
                'form_action': analysis['action']
            })
    
    def _check_hidden_fields(self, analysis: Dict[str, Any]):
        """Check for multiple hidden fields"""
        hidden_count = sum(1 for inp in analysis['inputs'] if inp['type'].lower() == 'hidden')
        
        if hidden_count > 3:
            analysis['security_issues'].append({
                'type': 'Multiple Hidden Fields',
                'severity': 'LOW',
                'description': f'Form contains {hidden_count} hidden fields - potential information disclosure',
                'hidden_field_count': hidden_count
            })