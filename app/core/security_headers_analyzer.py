"""Enhanced security headers analysis module"""

class SecurityHeadersAnalyzer:
    """Comprehensive security headers validation"""
    
    REQUIRED_HEADERS = {
        'X-Frame-Options': {'values': ['DENY', 'SAMEORIGIN'], 'severity': 'MEDIUM'},
        'X-Content-Type-Options': {'values': ['nosniff'], 'severity': 'MEDIUM'},
        'X-XSS-Protection': {'values': ['1; mode=block'], 'severity': 'MEDIUM'},
        'Strict-Transport-Security': {'min_age': 31536000, 'severity': 'HIGH'},
        'Content-Security-Policy': {'required': True, 'severity': 'HIGH'},
        'Referrer-Policy': {'values': ['strict-origin-when-cross-origin', 'no-referrer'], 'severity': 'LOW'},
        'Permissions-Policy': {'required': False, 'severity': 'LOW'}
    }
    
    def analyze_headers(self, headers):
        """Analyze response headers for security issues"""
        issues = []
        print(f"[DEBUG] Analyzing headers: {list(headers.keys())}")
        
        # Check each critical header individually (case-insensitive)
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        if 'x-frame-options' not in headers_lower:
            issues.append({
                'type': 'Missing X-Frame-Options Header',
                'severity': 'MEDIUM',
                'description': 'Missing X-Frame-Options header - site vulnerable to clickjacking attacks'
            })
            print("[DEBUG] Added X-Frame-Options vulnerability")
        
        if 'x-content-type-options' not in headers_lower:
            issues.append({
                'type': 'Missing X-Content-Type-Options Header',
                'severity': 'MEDIUM',
                'description': 'Missing X-Content-Type-Options header - site vulnerable to MIME type sniffing'
            })
            print("[DEBUG] Added X-Content-Type-Options vulnerability")
        
        if 'x-xss-protection' not in headers_lower:
            issues.append({
                'type': 'Missing X-XSS-Protection Header',
                'severity': 'MEDIUM',
                'description': 'Missing X-XSS-Protection header - reduced XSS protection in older browsers'
            })
            print("[DEBUG] Added X-XSS-Protection vulnerability")
        
        if 'content-security-policy' not in headers_lower:
            issues.append({
                'type': 'Missing Content Security Policy',
                'severity': 'HIGH',
                'description': 'Missing Content-Security-Policy header - site vulnerable to XSS and data injection attacks'
            })
            print("[DEBUG] Added CSP vulnerability")
        
        if 'strict-transport-security' not in headers_lower:
            issues.append({
                'type': 'Missing HSTS Header',
                'severity': 'MEDIUM',
                'description': 'Missing Strict-Transport-Security header - site vulnerable to protocol downgrade attacks'
            })
            print("[DEBUG] Added HSTS vulnerability")
        
        # Check for information disclosure headers
        if 'Server' in headers:
            server_header = headers['Server']
            if any(version_indicator in server_header for version_indicator in ['/', '(', 'v', 'V']):
                issues.append({
                    'type': 'Server Information Disclosure',
                    'severity': 'LOW',
                    'description': f'Server header reveals version information: {server_header}'
                })
                print(f"[DEBUG] Added Server disclosure vulnerability: {server_header}")
        
        if 'X-Powered-By' in headers:
            issues.append({
                'type': 'Technology Information Disclosure',
                'severity': 'LOW',
                'description': f'X-Powered-By header reveals technology stack: {headers["X-Powered-By"]}'
            })
            print(f"[DEBUG] Added X-Powered-By disclosure vulnerability")
        
        print(f"[DEBUG] Security headers analysis returning {len(issues)} issues")
        if len(issues) == 0:
            print("[DEBUG] WARNING: No security issues found - this is unusual for most websites")
        
        # Always check for common security improvements
        if 'Referrer-Policy' not in headers:
            issues.append({
                'type': 'Missing Referrer Policy',
                'severity': 'LOW',
                'description': 'Missing Referrer-Policy header - may leak sensitive information in referrer'
            })
        
        if 'Permissions-Policy' not in headers:
            issues.append({
                'type': 'Missing Permissions Policy',
                'severity': 'LOW', 
                'description': 'Missing Permissions-Policy header - browser features not restricted'
            })
        
        # Check for weak CSP if present
        if 'Content-Security-Policy' in headers:
            csp_value = headers['Content-Security-Policy']
            if 'unsafe-inline' in csp_value or 'unsafe-eval' in csp_value:
                issues.append({
                    'type': 'Weak Content Security Policy',
                    'severity': 'MEDIUM',
                    'description': 'CSP contains unsafe directives that reduce security effectiveness'
                })
        
        return issues
    
    def _validate_hsts(self, hsts_value):
        """Validate HSTS header configuration"""
        issues = []
        if 'max-age=' not in hsts_value.lower():
            issues.append({
                'type': 'Weak HSTS Configuration',
                'severity': 'MEDIUM',
                'description': 'HSTS header missing max-age directive'
            })
        return issues
    
    def _validate_csp(self, csp_value):
        """Validate CSP header for unsafe directives"""
        issues = []
        unsafe_keywords = ['unsafe-inline', 'unsafe-eval', '*']
        
        for keyword in unsafe_keywords:
            if keyword in csp_value:
                issues.append({
                    'type': 'Weak CSP Configuration',
                    'severity': 'MEDIUM',
                    'description': f'CSP contains unsafe directive: {keyword}'
                })
        return issues