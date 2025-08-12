# app/tools/http_utils.py
"""HTTP utility functions for the HTTP scanner"""

def get_default_headers():
    """Get default HTTP headers for requests"""
    return {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

def is_valid_response(response, wildcard_response=None, wildcard_length=None):
    """Check if response is valid (not a wildcard false positive)"""
    if response.status_code in [200, 301, 302, 403]:
        # If we detected wildcard responses, filter them out
        if wildcard_response and wildcard_length:
            if (response.status_code == wildcard_response and 
                abs(len(response.content) - wildcard_length) < 100):
                return False  # Likely a wildcard response
        return True
    return False

def extract_title_from_html(html_content):
    """Extract title from HTML content using regex fallback"""
    import re
    title_match = re.search(r'<title[^>]*>([^<]+)</title>', html_content, re.IGNORECASE)
    if title_match:
        return title_match.group(1).strip()
    return "No title"

def extract_forms_from_html(html_content):
    """Extract forms from HTML content using regex"""
    import re
    forms = []
    form_pattern = r'<form[^>]*action=[\"\\']([^\"\\']*)[\"\\'][^>]*>(.*?)</form>'
    form_matches = re.findall(form_pattern, html_content, re.DOTALL | re.IGNORECASE)
    
    for action, form_content in form_matches:
        # Extract input fields
        input_pattern = r'<input[^>]*name=[\"\\']([^\"\\']*)[\"\\'][^>]*>'
        inputs = re.findall(input_pattern, form_content, re.IGNORECASE)
        
        forms.append({
            'action': action,
            'inputs': inputs
        })
    
    return forms

def extract_links_from_html(html_content):
    """Extract links from HTML content using regex"""
    import re
    link_pattern = r'<a[^>]+href=[\"\\']([^\"\\']+)[\"\\'][^>]*>'
    links = re.findall(link_pattern, html_content, re.IGNORECASE)
    return list(set(links))  # Remove duplicates

def detect_technology_stack(html_content, headers):
    """Detect technology stack from HTML content and headers"""
    tech_indicators = {
        'WordPress': ['wp-content', 'wp-includes', '/wp-admin/'],
        'Drupal': ['sites/default', 'drupal.js', 'Drupal.'],
        'Joomla': ['/administrator/', 'joomla', 'option=com_'],
        'Laravel': ['laravel_session', '_token', 'Laravel'],
        'Django': ['csrfmiddlewaretoken', 'django', '__admin'],
        'React': ['react', 'ReactDOM', '_react'],
        'Angular': ['ng-', 'angular', 'AngularJS'],
        'Vue.js': ['vue', 'Vue.js', 'v-'],
        'PHP': ['<?php', '.php', 'PHPSESSID'],
        'ASP.NET': ['__VIEWSTATE', 'ASP.NET', '.aspx'],
        'Node.js': ['express', 'node', 'npm']
    }
    
    detected_tech = []
    headers_str = str(headers).lower()
    content_lower = html_content.lower()
    
    for tech, indicators in tech_indicators.items():
        if any(indicator.lower() in content_lower or indicator.lower() in headers_str for indicator in indicators):
            detected_tech.append(tech)
    
    return detected_tech

def check_security_headers(headers):
    """Check for security headers and return analysis"""
    security_headers = {
        'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
        'Content-Security-Policy': headers.get('Content-Security-Policy'),
        'X-Frame-Options': headers.get('X-Frame-Options'),
        'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
        'Referrer-Policy': headers.get('Referrer-Policy'),
        'X-XSS-Protection': headers.get('X-XSS-Protection')
    }
    
    present = sum(1 for v in security_headers.values() if v)
    total = len(security_headers)
    
    return {
        'headers': security_headers,
        'score': f"{present}/{total}",
        'missing': [k for k, v in security_headers.items() if not v]
    }