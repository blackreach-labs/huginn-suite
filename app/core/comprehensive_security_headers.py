"""
Comprehensive Security Headers Analyzer
"""
import re
from typing import Dict, List, Any

class ComprehensiveSecurityHeaders:
    def __init__(self):
        # Required security headers with their purposes
        self.required_headers = {
            'X-Frame-Options': {
                'purpose': 'clickjacking protection',
                'severity': 'MEDIUM',
                'valid_values': ['DENY', 'SAMEORIGIN']
            },
            'X-Content-Type-Options': {
                'purpose': 'MIME sniffing protection',
                'severity': 'MEDIUM',
                'valid_values': ['nosniff']
            },
            'X-XSS-Protection': {
                'purpose': 'XSS filter',
                'severity': 'MEDIUM',
                'valid_values': ['1; mode=block', '1']
            },
            'Strict-Transport-Security': {
                'purpose': 'HTTPS enforcement',
                'severity': 'MEDIUM',
                'min_max_age': 31536000  # 1 year
            },
            'Content-Security-Policy': {
                'purpose': 'XSS and injection protection',
                'severity': 'HIGH',
                'unsafe_directives': ['unsafe-inline', 'unsafe-eval', '*']
            },
            'Referrer-Policy': {
                'purpose': 'information leakage prevention',
                'severity': 'LOW',
                'valid_values': ['no-referrer', 'strict-origin', 'strict-origin-when-cross-origin']
            },
            'Permissions-Policy': {
                'purpose': 'feature restrictions',
                'severity': 'LOW'
            }
        }
        
        # Information disclosure headers
        self.disclosure_headers = [
            'Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version'
        ]

    def analyze_headers(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Analyze HTTP headers for security issues"""
        issues = []
        
        # Check for missing required headers
        for header_name, config in self.required_headers.items():
            if header_name not in headers:
                issues.append({
                    'type': f'Missing {header_name} Header',
                    'severity': config['severity'],
                    'description': f'Missing {header_name} header allows {config["purpose"]} attacks',
                    'remediation': f'Add {header_name} header with appropriate value'
                })
            else:
                # Validate header values
                header_value = headers[header_name]
                header_issues = self._validate_header(header_name, header_value, config)
                issues.extend(header_issues)
        
        # Check for information disclosure
        for header_name in self.disclosure_headers:
            if header_name in headers:
                issues.append({
                    'type': f'{header_name.replace("-", " ")} Disclosure',
                    'severity': 'LOW',
                    'description': f'{header_name} header discloses {self._get_disclosure_type(header_name)}: {headers[header_name]}',
                    'disclosed_info': headers[header_name]
                })
        
        return issues
    
    def _validate_header(self, header_name: str, value: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Validate specific header values"""
        issues = []
        
        if header_name == 'Content-Security-Policy':
            issues.extend(self._validate_csp(value))
        elif header_name == 'Strict-Transport-Security':
            issues.extend(self._validate_hsts(value, config))
        elif 'valid_values' in config:
            if not any(valid in value for valid in config['valid_values']):
                issues.append({
                    'type': f'Weak {header_name} Configuration',
                    'severity': config['severity'],
                    'description': f'{header_name} header has weak configuration: {value}',
                    'current_value': value,
                    'recommended_values': config['valid_values']
                })
        
        return issues
    
    def _validate_csp(self, csp_value: str) -> List[Dict[str, Any]]:
        """Validate Content Security Policy"""
        issues = []
        
        # Check for unsafe directives
        unsafe_patterns = [
            (r"'unsafe-inline'", 'unsafe-inline', 'HIGH'),
            (r"'unsafe-eval'", 'unsafe-eval', 'HIGH'),
            (r'\*(?!\.[a-zA-Z])', '*', 'MEDIUM')  # * but not *.domain.com
        ]
        
        for pattern, directive, severity in unsafe_patterns:
            if re.search(pattern, csp_value):
                issues.append({
                    'type': 'Unsafe CSP Directive',
                    'severity': severity,
                    'description': f'CSP contains unsafe directive: {directive}',
                    'directive': directive,
                    'csp_value': csp_value
                })
        
        # Check for missing important directives
        important_directives = ['default-src', 'script-src', 'object-src']
        for directive in important_directives:
            if directive not in csp_value:
                issues.append({
                    'type': 'Missing CSP Directive',
                    'severity': 'MEDIUM',
                    'description': f'CSP missing important directive: {directive}',
                    'missing_directive': directive
                })
        
        return issues
    
    def _validate_hsts(self, hsts_value: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Validate HSTS header"""
        issues = []
        
        # Extract max-age value
        max_age_match = re.search(r'max-age=(\d+)', hsts_value)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            min_age = config.get('min_max_age', 31536000)
            
            if max_age < min_age:
                issues.append({
                    'type': 'Weak HSTS Configuration',
                    'severity': 'MEDIUM',
                    'description': f'HSTS max-age too low: {max_age} seconds (recommended: {min_age})',
                    'current_max_age': max_age,
                    'recommended_max_age': min_age
                })
        
        # Check for includeSubDomains
        if 'includeSubDomains' not in hsts_value:
            issues.append({
                'type': 'HSTS Missing includeSubDomains',
                'severity': 'LOW',
                'description': 'HSTS header should include includeSubDomains directive',
                'current_value': hsts_value
            })
        
        return issues
    
    def _get_disclosure_type(self, header_name: str) -> str:
        """Get the type of information disclosed by header"""
        disclosure_types = {
            'Server': 'server version information',
            'X-Powered-By': 'technology',
            'X-AspNet-Version': 'ASP.NET version',
            'X-AspNetMvc-Version': 'ASP.NET MVC version'
        }
        return disclosure_types.get(header_name, 'system information')