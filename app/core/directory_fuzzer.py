import asyncio
from urllib.parse import urljoin

class DirectoryFuzzer:
    """Advanced directory and file fuzzing with crawling"""
    
    def __init__(self):
        self.common_dirs = [
            'admin', 'api', 'backup', 'config', 'dev', 'test', 'tmp', 'uploads',
            'files', 'images', 'js', 'css', 'assets', 'static', 'public', 'private'
        ]
        self.common_files = [
            'robots.txt', 'sitemap.xml', '.htaccess', 'web.config', 'crossdomain.xml',
            'backup.zip', 'config.php', 'database.sql', '.env', '.git/config'
        ]
        self.interesting_extensions = ['.bak', '.old', '.tmp', '.backup', '.orig', '.save']
    
    async def fuzz_directories(self, session, target_url, discovered_paths=None):
        """Fuzz for hidden directories and files"""
        findings = []
        found_paths = []
        
        # Test common directories
        for directory in self.common_dirs[:10]:  # Limit to avoid overwhelming
            test_url = urljoin(target_url, f'{directory}/')
            result = await self._test_path(session, test_url, 'directory')
            if result:
                found_paths.append(result)
                
        # Test common files
        for filename in self.common_files[:10]:
            test_url = urljoin(target_url, filename)
            result = await self._test_path(session, test_url, 'file')
            if result:
                found_paths.append(result)
        
        # Test backup versions of discovered files
        if discovered_paths:
            backup_findings = await self._test_backup_files(session, target_url, discovered_paths[:5])
            found_paths.extend(backup_findings)
        
        if found_paths:
            # Categorize findings by sensitivity
            sensitive_paths = [p for p in found_paths if self._is_sensitive_path(p['path'])]
            
            if sensitive_paths:
                findings.append({
                    'type': 'Sensitive Directory/File Discovery',
                    'severity': 'MEDIUM',
                    'description': f'Found {len(sensitive_paths)} sensitive paths',
                    'sensitive_paths': sensitive_paths,
                    'recommendation': 'Restrict access to sensitive directories and files'
                })
            
            findings.append({
                'type': 'Directory Fuzzing Results',
                'severity': 'INFO',
                'description': f'Discovered {len(found_paths)} accessible paths',
                'discovered_paths': found_paths[:15],  # Show first 15
                'recommendation': 'Review discovered paths for sensitive information'
            })
        
        return findings
    
    async def _test_path(self, session, test_url, path_type):
        """Test individual path for accessibility"""
        try:
            async with session.get(test_url) as response:
                if response.status == 200:
                    content_length = len(await response.text())
                    return {
                        'path': test_url,
                        'type': path_type,
                        'status': response.status,
                        'size': content_length,
                        'content_type': response.headers.get('Content-Type', 'unknown')
                    }
                elif response.status in [301, 302]:  # Redirects might be interesting
                    location = response.headers.get('Location', '')
                    return {
                        'path': test_url,
                        'type': f'{path_type}_redirect',
                        'status': response.status,
                        'redirect_to': location
                    }
        except:
            pass
        
        await asyncio.sleep(0.1)  # Rate limiting
        return None
    
    async def _test_backup_files(self, session, base_url, discovered_paths):
        """Test for backup versions of discovered files"""
        backup_findings = []
        
        for path in discovered_paths:
            if isinstance(path, str) and '.' in path:
                # Test backup extensions
                for ext in self.interesting_extensions[:3]:  # Limit extensions
                    backup_url = urljoin(base_url, f'{path}{ext}')
                    result = await self._test_path(session, backup_url, 'backup_file')
                    if result:
                        backup_findings.append(result)
                        break  # Stop on first backup found
        
        return backup_findings
    
    def _is_sensitive_path(self, path):
        """Determine if a path contains sensitive information"""
        sensitive_indicators = [
            'admin', 'config', 'backup', '.env', '.git', 'database',
            'private', 'secret', 'key', 'password', '.htaccess'
        ]
        
        path_lower = path.lower()
        return any(indicator in path_lower for indicator in sensitive_indicators)