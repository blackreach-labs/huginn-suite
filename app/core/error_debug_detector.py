import re

class ErrorDebugDetector:
    """Detect error messages and debug information leakage"""
    
    def __init__(self):
        self.error_patterns = [
            # Stack traces
            (re.compile(r'Traceback \(most recent call last\):', re.IGNORECASE), 'Python Stack Trace'),
            (re.compile(r'Exception in thread', re.IGNORECASE), 'Java Exception'),
            (re.compile(r'Fatal error:', re.IGNORECASE), 'PHP Fatal Error'),
            (re.compile(r'Warning: mysql_', re.IGNORECASE), 'MySQL Warning'),
            
            # SQL errors
            (re.compile(r'SQL syntax.*?error', re.IGNORECASE), 'SQL Syntax Error'),
            (re.compile(r'ORA-\d{5}', re.IGNORECASE), 'Oracle Error'),
            (re.compile(r'Microsoft.*ODBC.*SQL Server', re.IGNORECASE), 'SQL Server Error'),
            (re.compile(r'PostgreSQL.*ERROR', re.IGNORECASE), 'PostgreSQL Error'),
            
            # Framework errors
            (re.compile(r'<h1>Server Error.*</h1>', re.IGNORECASE), 'Server Error Page'),
            (re.compile(r'Django.*Error', re.IGNORECASE), 'Django Error'),
            (re.compile(r'Rails.*Error', re.IGNORECASE), 'Rails Error'),
            (re.compile(r'Spring.*Exception', re.IGNORECASE), 'Spring Exception'),
            
            # Debug information
            (re.compile(r'<pre[^>]*>.*?</pre>', re.DOTALL | re.IGNORECASE), 'Debug Output'),
            (re.compile(r'DEBUG.*?=.*?true', re.IGNORECASE), 'Debug Mode Enabled')
        ]
    
    def analyze_response(self, url, content, status_code):
        """Analyze response for error messages and debug info"""
        findings = []
        
        # Only analyze error responses and suspicious content
        if status_code >= 400 or any(keyword in content.lower() for keyword in ['error', 'exception', 'debug', 'traceback']):
            
            for pattern, error_type in self.error_patterns:
                matches = pattern.findall(content)
                if matches:
                    # Extract context around the error
                    match_text = matches[0] if isinstance(matches[0], str) else str(matches[0])
                    context = self._extract_context(content, match_text)
                    
                    findings.append({
                        'type': 'Error Information Disclosure',
                        'severity': 'MEDIUM',
                        'url': url,
                        'error_type': error_type,
                        'description': f'{error_type} detected in response',
                        'evidence': context[:200] + '...' if len(context) > 200 else context,
                        'recommendation': 'Configure custom error pages to prevent information disclosure'
                    })
        
        return findings
    
    def _extract_context(self, content, match_text):
        """Extract context around error message"""
        try:
            start_pos = content.find(match_text)
            if start_pos == -1:
                return match_text
            
            # Get 100 characters before and after
            context_start = max(0, start_pos - 100)
            context_end = min(len(content), start_pos + len(match_text) + 100)
            
            return content[context_start:context_end].strip()
        except Exception:
            return match_text