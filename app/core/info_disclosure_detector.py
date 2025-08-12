"""Information disclosure vulnerability detector"""
import re

class InfoDisclosureDetector:
    """Detect information disclosure vulnerabilities"""
    
    def __init__(self):
        self.vulnerabilities = []
    
    def analyze_response(self, url, content, headers):
        """Analyze response for information disclosure"""
        # Check response content
        self._check_content_disclosure(url, content)
        
        # Check headers
        self._check_header_disclosure(url, headers)
        
        return self.vulnerabilities
    
    def _check_content_disclosure(self, url, content):
        """Check response content for sensitive information"""
        # Database connection strings
        db_patterns = [
            r'mysql://[^\\s]+',
            r'postgresql://[^\\s]+',
            r'mongodb://[^\\s]+',
            r'Server=.*?;Database=.*?;',
            r'Data Source=.*?;Initial Catalog=.*?;',
            r'connectionString.*?=.*?["\']([^"\']+)["\']'
        ]
        
        for pattern in db_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                self.vulnerabilities.append({
                    'type': 'Database Connection String Disclosure',
                    'severity': 'HIGH',
                    'description': f'Database connection string exposed at {url}',
                    'url': url,
                    'evidence': matches[0][:100] + '...' if len(matches[0]) > 100 else matches[0]
                })
        
        # API keys and tokens
        api_patterns = [
            r'api[_-]?key["\']?\\s*[:=]\\s*["\']([a-zA-Z0-9_-]{20,})["\']',
            r'access[_-]?token["\']?\\s*[:=]\\s*["\']([a-zA-Z0-9_-]{20,})["\']',
            r'secret[_-]?key["\']?\\s*[:=]\\s*["\']([a-zA-Z0-9_-]{20,})["\']',
            r'aws[_-]?access[_-]?key["\']?\\s*[:=]\\s*["\']([A-Z0-9]{20})["\']',
            r'AKIA[0-9A-Z]{16}',  # AWS Access Key
            r'sk-[a-zA-Z0-9]{48}',  # OpenAI API Key pattern
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                self.vulnerabilities.append({
                    'type': 'API Key/Token Disclosure',
                    'severity': 'CRITICAL',
                    'description': f'API key or token exposed at {url}',
                    'url': url,
                    'evidence': f'Found {len(matches)} potential API key(s)'
                })
        
        # Email addresses
        email_pattern = r'\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b'
        emails = re.findall(email_pattern, content)
        if len(emails) > 5:  # Only report if many emails found
            self.vulnerabilities.append({
                'type': 'Email Address Disclosure',
                'severity': 'LOW',
                'description': f'Multiple email addresses exposed at {url}',
                'url': url,
                'evidence': f'Found {len(emails)} email addresses'
            })
        
        # Stack traces and error messages
        error_patterns = [
            r'Exception in thread',
            r'Traceback \\(most recent call last\\):',
            r'Fatal error:.*?in.*?on line',
            r'Warning:.*?in.*?on line',
            r'Notice:.*?in.*?on line',
            r'Parse error:.*?in.*?on line',
            r'Microsoft OLE DB Provider for ODBC Drivers error',
            r'java\\.lang\\.[A-Za-z]*Exception',
            r'at java\\.',
            r'Caused by: java\\.'
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                self.vulnerabilities.append({
                    'type': 'Error Message Disclosure',
                    'severity': 'MEDIUM',
                    'description': f'Detailed error message exposed at {url}',
                    'url': url,
                    'evidence': 'Stack trace or detailed error information found'
                })
                break  # Only report once per page
        
        # File paths and directory structures
        path_patterns = [
            r'[A-Za-z]:\\\\[^\\s<>"]+',  # Windows paths
            r'/(?:home|var|etc|usr|opt)/[^\\s<>"]+',  # Unix paths
            r'/[a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+\\.(?:php|asp|jsp|py|rb|pl)',  # Web file paths
        ]
        
        path_count = 0
        for pattern in path_patterns:
            matches = re.findall(pattern, content)
            path_count += len(matches)
        
        if path_count > 3:  # Only report if multiple paths found
            self.vulnerabilities.append({
                'type': 'File Path Disclosure',
                'severity': 'LOW',
                'description': f'File system paths exposed at {url}',
                'url': url,
                'evidence': f'Found {path_count} file system paths'
            })
        
        # Version information
        version_patterns = [
            r'Apache/([0-9.]+)',
            r'nginx/([0-9.]+)',
            r'PHP/([0-9.]+)',
            r'MySQL ([0-9.]+)',
            r'PostgreSQL ([0-9.]+)',
            r'Microsoft-IIS/([0-9.]+)',
            r'jQuery v([0-9.]+)',
            r'WordPress ([0-9.]+)'
        ]
        
        for pattern in version_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                self.vulnerabilities.append({
                    'type': 'Version Information Disclosure',
                    'severity': 'LOW',
                    'description': f'Software version information exposed at {url}',
                    'url': url,
                    'evidence': f'Version information found in content'
                })
                break  # Only report once per page
    
    def _check_header_disclosure(self, url, headers):
        """Check response headers for information disclosure"""
        # Server version disclosure
        server_header = headers.get('Server', '')
        if server_header and any(char in server_header for char in ['/', '(', 'v']):
            self.vulnerabilities.append({
                'type': 'Server Version Disclosure',
                'severity': 'LOW',
                'description': f'Server version information disclosed in headers at {url}',
                'url': url,
                'evidence': f'Server: {server_header}'
            })
        
        # Technology stack disclosure
        powered_by = headers.get('X-Powered-By', '')
        if powered_by:
            self.vulnerabilities.append({
                'type': 'Technology Stack Disclosure',
                'severity': 'LOW',
                'description': f'Technology stack information disclosed in headers at {url}',
                'url': url,
                'evidence': f'X-Powered-By: {powered_by}'
            })
        
        # Debug headers
        debug_headers = ['X-Debug', 'X-Debug-Token', 'X-Debug-Info', 'X-Symfony-Debug']
        for header in debug_headers:
            if header in headers:
                self.vulnerabilities.append({
                    'type': 'Debug Information Disclosure',
                    'severity': 'MEDIUM',
                    'description': f'Debug information disclosed in headers at {url}',
                    'url': url,
                    'evidence': f'{header}: {headers[header]}'
                })
        
        # Internal IP disclosure
        internal_ip_headers = ['X-Real-IP', 'X-Forwarded-For', 'X-Originating-IP']
        for header in internal_ip_headers:
            if header in headers:
                ip_value = headers[header]
                # Check if it's a private IP
                if any(ip_value.startswith(private) for private in ['10.', '172.', '192.168.', '127.']):
                    self.vulnerabilities.append({
                        'type': 'Internal IP Address Disclosure',
                        'severity': 'LOW',
                        'description': f'Internal IP address disclosed in headers at {url}',
                        'url': url,
                        'evidence': f'{header}: {ip_value}'
                    })