"""Content and directory discovery module"""
import asyncio
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import aiohttp
from app.core.logger import logger

class ContentDiscovery:
    """Discover sensitive files and directories"""
    
    SENSITIVE_PATHS = [
        '/admin', '/administrator', '/wp-admin', '/login', '/signin',
        '/backup', '/backups', '/old', '/temp', '/tmp',
        '/.git', '/.env', '/.htaccess', '/config.php', '/web.config',
        '/README', '/readme.txt', '/CHANGELOG', '/LICENSE',
        '/api', '/api/v1', '/graphql', '/swagger', '/api-docs',
        '/phpmyadmin', '/adminer', '/database',
        '/test', '/dev', '/staging', '/debug',
        '/console', '/manager', '/status', '/info',
        '/server-info', '/server-status', '/phpinfo.php',
        '/wp-config.php', '/config', '/configuration',
        '/uploads', '/files', '/documents', '/download',
        '/cgi-bin', '/scripts', '/bin'
    ]
    
    SENSITIVE_FILES = [
        'robots.txt', 'sitemap.xml', '.DS_Store', 'thumbs.db',
        'config.json', 'package.json', 'composer.json',
        'error_log', 'access.log', 'debug.log',
        '.env', '.env.local', '.env.production',
        'wp-config.php', 'config.php', 'database.yml',
        'phpinfo.php', 'info.php', 'test.php',
        'backup.sql', 'dump.sql', 'database.sql',
        '.htaccess', '.htpasswd', 'web.config',
        'crossdomain.xml', 'clientaccesspolicy.xml'
    ]
    
    def __init__(self, session):
        self.session = session
        self.discovered_urls = set()
        self.sensitive_findings = []
    
    async def discover_content(self, base_url):
        """Main content discovery orchestrator"""
        print(f"[DEBUG] Starting content discovery for {base_url}")
        
        # Parse robots.txt first
        await self._check_robots_txt(base_url)
        print(f"[DEBUG] After robots.txt check: {len(self.discovered_urls)} URLs, {len(self.sensitive_findings)} findings")
        
        # Check common sensitive paths
        await self._check_sensitive_paths(base_url)
        print(f"[DEBUG] After sensitive paths check: {len(self.discovered_urls)} URLs, {len(self.sensitive_findings)} findings")
        
        # Crawl main page for links
        await self._crawl_page(base_url)
        print(f"[DEBUG] After page crawl: {len(self.discovered_urls)} URLs, {len(self.sensitive_findings)} findings")
        
        return {
            'discovered_urls': list(self.discovered_urls),
            'sensitive_findings': self.sensitive_findings
        }
    
    async def _check_robots_txt(self, base_url):
        """Parse robots.txt for interesting paths"""
        robots_url = urljoin(base_url, '/robots.txt')
        try:
            async with self.session.get(robots_url) as response:
                if response.status == 200:
                    content = await response.text()
                    # Extract disallowed paths
                    for line in content.split('\n'):
                        if line.strip().startswith('Disallow:'):
                            path = line.split(':', 1)[1].strip()
                            if path and path != '/':
                                full_url = urljoin(base_url, path)
                                self.discovered_urls.add(full_url)
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
    
    async def _check_sensitive_paths(self, base_url):
        """Check for sensitive directories and files"""
        print(f"[DEBUG] Checking {len(self.SENSITIVE_PATHS)} paths and {len(self.SENSITIVE_FILES)} files")
        tasks = []
        
        # Check directories
        for path in self.SENSITIVE_PATHS:
            url = urljoin(base_url, path)
            tasks.append(self._check_url(url, 'directory'))
        
        # Check files
        for filename in self.SENSITIVE_FILES:
            url = urljoin(base_url, '/' + filename)
            tasks.append(self._check_url(url, 'file'))
        
        print(f"[DEBUG] Created {len(tasks)} tasks for content discovery")
        # Execute checks concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        print(f"[DEBUG] Completed {len(results)} content discovery tasks")
    
    async def _check_url(self, url, url_type):
        """Check if URL is accessible"""
        try:
            async with self.session.get(url, allow_redirects=False, timeout=5) as response:
                if response.status == 200:
                    content = await response.text()
                    print(f"[DEBUG] Found 200 response for {url} ({len(content)} chars)")
                    
                    # More aggressive detection - report any accessible sensitive path
                    if url_type == 'directory':
                        # Check for directory listing OR any content that isn't a clear error page
                        if self._is_directory_listing(content) or (len(content) > 500 and not self._is_default_error_page(content)):
                            self.discovered_urls.add(url)
                            self.sensitive_findings.append({
                                'type': 'Accessible Directory',
                                'url': url,
                                'severity': 'MEDIUM',
                                'description': f'Sensitive directory accessible at {url}'
                            })
                            print(f"[DEBUG] Added directory finding: {url}")
                    
                    elif url_type == 'file' and len(content) > 50:  # Lower threshold for files
                        # Report any accessible file that isn't clearly an error page
                        if not self._is_default_error_page(content):
                            self.discovered_urls.add(url)
                            severity = 'HIGH' if any(sensitive in url.lower() for sensitive in ['.env', 'config', 'backup', '.git']) else 'MEDIUM'
                            self.sensitive_findings.append({
                                'type': 'Sensitive File Exposed',
                                'url': url,
                                'severity': severity,
                                'description': f'Sensitive file accessible at {url}'
                            })
                            print(f"[DEBUG] Added file finding: {url}")
                
                # Also check for interesting response codes
                elif response.status == 403:
                    self.sensitive_findings.append({
                        'type': 'Forbidden Directory/File',
                        'url': url,
                        'severity': 'LOW',
                        'description': f'Forbidden access to {url} - may contain sensitive content'
                    })
                    print(f"[DEBUG] Added 403 finding: {url}")
                
                elif response.status == 401:
                    self.sensitive_findings.append({
                        'type': 'Authentication Required',
                        'url': url,
                        'severity': 'MEDIUM',
                        'description': f'Authentication required for {url} - protected resource discovered'
                    })
                    print(f"[DEBUG] Added 401 finding: {url}")
        
        except Exception as e:
            # Silently continue for now
            pass
            logger.debug("Suppressed exception", exc_info=True)
    
    async def _crawl_page(self, url):
        """Crawl page for additional links"""
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    content = await response.text()
                    soup = BeautifulSoup(content, 'html.parser')
                    
                    # Extract links
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        full_url = urljoin(url, href)
                        
                        # Only add same-domain URLs
                        if urlparse(full_url).netloc == urlparse(url).netloc:
                            self.discovered_urls.add(full_url)
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
    
    def _is_directory_listing(self, content):
        """Detect if content shows directory listing"""
        indicators = [
            'Index of /',
            'Directory Listing',
            '<title>Index of',
            'Parent Directory',
            '[DIR]'
        ]
        return any(indicator in content for indicator in indicators)
    
    def _is_default_error_page(self, content):
        """Check if content is a default error page"""
        # More specific error page detection
        error_indicators = [
            'HTTP Error 404',
            'Not Found',
            'The requested URL was not found',
            'IIS Windows Server',
            'Apache2 Ubuntu Default Page',
            'Welcome to nginx!',
            'It works!',
            'Test Page for the Apache HTTP Server',
            'Error 404',
            'Page not found',
            'File not found'
        ]
        
        # Check if content is very short (likely error)
        if len(content.strip()) < 100:
            return True
        
        # Check for multiple error indicators
        error_count = sum(1 for indicator in error_indicators if indicator.lower() in content.lower())
        return error_count >= 1