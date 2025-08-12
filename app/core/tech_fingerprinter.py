"""Advanced technology fingerprinting module"""
import re
from bs4 import BeautifulSoup

class TechFingerprinter:
    """Identify web technologies and versions"""
    
    TECH_SIGNATURES = {
        'WordPress': {
            'patterns': [r'wp-content/', r'wp-includes/', r'/wp-json/'],
            'meta': ['generator'],
            'headers': ['X-Pingback']
        },
        'Joomla': {
            'patterns': [r'/media/system/', r'/administrator/'],
            'meta': ['generator'],
            'cookies': ['joomla_user_state']
        },
        'React': {
            'patterns': [r'react\.js', r'react\.min\.js', r'__REACT_DEVTOOLS'],
            'scripts': ['react']
        },
        'Angular': {
            'patterns': [r'angular\.js', r'ng-app', r'ng-controller'],
            'scripts': ['angular']
        },
        'jQuery': {
            'patterns': [r'jquery-[\d\.]+\.js', r'jquery\.min\.js'],
            'scripts': ['jquery']
        }
    }
    
    def fingerprint_response(self, response_text, headers, url):
        """Extract technology information from response"""
        technologies = {}
        soup = BeautifulSoup(response_text, 'html.parser')
        
        # Check HTML patterns
        for tech, config in self.TECH_SIGNATURES.items():
            if self._check_patterns(response_text, config.get('patterns', [])):
                technologies[tech] = self._extract_version(response_text, tech)
        
        # Check meta tags
        for meta in soup.find_all('meta'):
            if meta.get('name') == 'generator':
                content = meta.get('content', '')
                tech_info = self._parse_generator(content)
                if tech_info:
                    technologies.update(tech_info)
        
        # Check script sources
        for script in soup.find_all('script', src=True):
            src = script['src']
            tech_info = self._analyze_script_src(src)
            if tech_info:
                technologies.update(tech_info)
        
        # Check server headers
        server = headers.get('Server', '')
        if server:
            technologies['Server'] = server
        
        powered_by = headers.get('X-Powered-By', '')
        if powered_by:
            technologies['Framework'] = powered_by
        
        return technologies
    
    def _check_patterns(self, text, patterns):
        """Check if any patterns match in text"""
        return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)
    
    def _extract_version(self, text, tech):
        """Extract version number for detected technology"""
        version_patterns = {
            'WordPress': r'wp-includes/js/wp-emoji-release\.min\.js\?ver=([\d\.]+)',
            'jQuery': r'jquery-([\d\.]+)\.min\.js'
        }
        
        pattern = version_patterns.get(tech)
        if pattern:
            match = re.search(pattern, text)
            return match.group(1) if match else 'Unknown'
        return 'Unknown'
    
    def _parse_generator(self, content):
        """Parse generator meta tag content"""
        generators = {}
        if 'WordPress' in content:
            match = re.search(r'WordPress ([\d\.]+)', content)
            generators['WordPress'] = match.group(1) if match else 'Unknown'
        elif 'Joomla' in content:
            match = re.search(r'Joomla! ([\d\.]+)', content)
            generators['Joomla'] = match.group(1) if match else 'Unknown'
        return generators
    
    def _analyze_script_src(self, src):
        """Analyze script source URLs for technology detection"""
        tech_info = {}
        
        # jQuery version detection
        jquery_match = re.search(r'jquery-([\d\.]+)\.min\.js', src)
        if jquery_match:
            tech_info['jQuery'] = jquery_match.group(1)
        
        # React detection
        if 'react' in src.lower():
            react_match = re.search(r'react@([\d\.]+)', src)
            tech_info['React'] = react_match.group(1) if react_match else 'Unknown'
        
        return tech_info