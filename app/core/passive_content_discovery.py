"""
Passive Content Discovery - Discovers content through passive enumeration
"""
import re
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Any
from aiohttp import ClientSession

class PassiveContentDiscovery:
    def __init__(self):
        # High-value paths to test
        self.sensitive_paths = [
            '.git/config', '.git/HEAD', '.env', '.env.local',
            'config.php', 'wp-config.php', 'database.yml',
            'admin/', 'admin.php', 'administrator/',
            'backup/', 'backups/', 'backup.zip', 'backup.sql',
            'phpinfo.php', 'info.php', 'test.php',
            'robots.txt', 'sitemap.xml', 'crossdomain.xml',
            'web.config', '.htaccess', '.htpasswd',
            'server-status', 'server-info'
        ]
        
        # API documentation paths
        self.api_docs = [
            'api/', 'api/docs/', 'api/v1/', 'api/v2/',
            'swagger/', 'swagger.json', 'swagger.yaml',
            'openapi.json', 'docs/', 'documentation/'
        ]

    async def discover_content(self, session: ClientSession, base_url: str, content: str) -> Dict[str, Any]:
        """Discover content through passive enumeration"""
        results = {
            'discovered_paths': [],
            'sensitive_findings': [],
            'robots_paths': [],
            'sitemap_urls': [],
            'api_endpoints': []
        }
        
        # Parse robots.txt
        await self._parse_robots(session, base_url, results)
        
        # Extract sitemap URLs
        self._extract_sitemaps(content, base_url, results)
        
        # Test sensitive paths
        await self._test_sensitive_paths(session, base_url, results)
        
        # Extract JavaScript endpoints
        self._extract_js_endpoints(content, base_url, results)
        
        return results
    
    async def _parse_robots(self, session: ClientSession, base_url: str, results: Dict[str, Any]):
        """Parse robots.txt for interesting paths"""
        robots_url = urljoin(base_url, '/robots.txt')
        
        try:
            async with session.get(robots_url) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Extract disallowed paths
                    disallow_pattern = r'Disallow:\s*([^\s]+)'
                    matches = re.findall(disallow_pattern, content, re.IGNORECASE)
                    
                    for path in matches:
                        if path != '/' and len(path) > 1:
                            full_url = urljoin(base_url, path)
                            results['robots_paths'].append(full_url)
                            
                            # Flag sensitive paths in robots.txt
                            if any(sensitive in path.lower() for sensitive in ['admin', 'backup', 'config', 'private']):
                                results['sensitive_findings'].append({
                                    'type': 'Sensitive Path in Robots.txt',
                                    'severity': 'MEDIUM',
                                    'description': f'Sensitive path disclosed in robots.txt: {path}',
                                    'url': full_url,
                                    'path': path
                                })
        except Exception:
            pass
    
    def _extract_sitemaps(self, content: str, base_url: str, results: Dict[str, Any]):
        """Extract sitemap URLs from content"""
        patterns = [
            r'<link[^>]*rel=["\']sitemap["\'][^>]*href=["\']([^"\']+)["\']',
            r'sitemap[^"\']*\.xml',
            r'/sitemap\.xml'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                sitemap_url = urljoin(base_url, match)
                if sitemap_url not in results['sitemap_urls']:
                    results['sitemap_urls'].append(sitemap_url)
    
    async def _test_sensitive_paths(self, session: ClientSession, base_url: str, results: Dict[str, Any]):
        """Test for sensitive file exposure"""
        for path in self.sensitive_paths:
            try:
                test_url = urljoin(base_url, path)
                async with session.head(test_url) as response:
                    if response.status == 200:
                        severity = 'HIGH' if any(x in path for x in ['.env', '.git', 'config']) else 'MEDIUM'
                        results['sensitive_findings'].append({
                            'type': 'Sensitive File Exposed',
                            'severity': severity,
                            'description': f'Sensitive file accessible: {path}',
                            'url': test_url,
                            'status_code': response.status
                        })
                        results['discovered_paths'].append(test_url)
                    elif response.status == 403:
                        results['sensitive_findings'].append({
                            'type': 'Forbidden Directory/File',
                            'severity': 'LOW',
                            'description': f'Protected sensitive resource discovered: {path}',
                            'url': test_url,
                            'status_code': response.status
                        })
            except Exception:
                continue
    
    def _extract_js_endpoints(self, content: str, base_url: str, results: Dict[str, Any]):
        """Extract API endpoints from JavaScript"""
        patterns = [
            r'[\"\']([/][api][^\"\'>\s]*)[\"\'"]',
            r'fetch\([\"\'"]([^\"\'">]+)[\"\'"]',
            r'axios\.[a-z]+\([\"\'"]([^\"\'">]+)[\"\'"]',
            r'\.ajax\([^}]*url[^}]*[\"\'"]([^\"\'">]+)[\"\'"]'
        ]
        
        endpoints = set()
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if match.startswith('/'):
                    full_url = urljoin(base_url, match)
                    endpoints.add(full_url)
        
        results['api_endpoints'] = list(endpoints)
        
        # Flag API endpoints discovery
        if endpoints:
            results['sensitive_findings'].append({
                'type': 'API Endpoints Discovered',
                'severity': 'LOW',
                'description': f'Found {len(endpoints)} potential API endpoints in JavaScript',
                'endpoints': list(endpoints)[:5]  # Show first 5
            })