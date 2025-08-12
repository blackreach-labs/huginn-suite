# app/core/source_map_analyzer.py
import json
import re
import requests
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin

class SourceMapAnalyzer:
    """Analyzer for JavaScript source maps"""
    
    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.session.verify = False
        self.session.timeout = 10
    
    def find_source_maps(self, content: str, base_url: str) -> List[str]:
        """Find source map URLs in content"""
        source_maps = []
        
        # Find sourceMappingURL comments
        map_matches = re.findall(r'//# sourceMappingURL=([^\s]+)', content)
        for map_url in map_matches:
            if not map_url.startswith('http'):
                map_url = urljoin(base_url, map_url)
            source_maps.append(map_url)
        
        return source_maps
    
    def analyze_source_map(self, map_url: str) -> Dict[str, any]:
        """Analyze a source map file"""
        try:
            response = self.session.get(map_url, timeout=5)
            if response.status_code != 200:
                return {'error': f'Failed to fetch: {response.status_code}'}
            
            try:
                source_map = json.loads(response.text)
            except json.JSONDecodeError:
                return {'error': 'Invalid JSON in source map'}
            
            analysis = {
                'url': map_url,
                'sources': source_map.get('sources', []),
                'source_count': len(source_map.get('sources', [])),
                'findings': []
            }
            
            # Analyze source file paths for interesting patterns
            sources = source_map.get('sources', [])
            for source in sources:
                if any(pattern in source.lower() for pattern in ['test', 'dev', 'debug', 'admin']):
                    analysis['findings'].append(f'Development file: {source}')
                
                if any(pattern in source.lower() for pattern in ['config', 'secret', 'key']):
                    analysis['findings'].append(f'Configuration file: {source}')
            
            # Check for source content
            if 'sourcesContent' in source_map:
                analysis['has_source_content'] = True
                analysis['findings'].append('Source code embedded in map')
                
                # Analyze embedded source content
                for i, source_content in enumerate(source_map['sourcesContent']):
                    if source_content and len(source_content) > 100:
                        # Look for secrets in source content
                        secrets = self._find_secrets_in_source(source_content)
                        if secrets:
                            source_name = sources[i] if i < len(sources) else f'source_{i}'
                            analysis['findings'].append(f'Secrets in {source_name}: {len(secrets)} found')
            
            return analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    def _find_secrets_in_source(self, source_content: str) -> List[str]:
        """Find potential secrets in source content"""
        secrets = []
        
        # Common secret patterns
        secret_patterns = [
            r'(?i)(api[_-]?key|secret|token)[\'"]?\s*[:=]\s*[\'"]([A-Za-z0-9_\-]{16,})[\'"]',
            r'["\']?(AKIA|AIza|sk_live|ghp_)[A-Za-z0-9]{10,}["\']?',
            r'(?i)(password|pwd)[\'"]?\s*[:=]\s*[\'"]([^\'"\n]{3,})[\'"]'
        ]
        
        for pattern in secret_patterns:
            matches = re.findall(pattern, source_content)
            for match in matches:
                if isinstance(match, tuple):
                    secrets.append(match[1] if len(match) > 1 else match[0])
                else:
                    secrets.append(str(match))
        
        return secrets[:5]  # Limit to 5 secrets per file