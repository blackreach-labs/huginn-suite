# app/core/azure_storage_crawler.py
import urllib.request
import urllib.error
import urllib.parse
import json
import xml.etree.ElementTree as ET
import time
import itertools
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from app.core.logger import logger

class AzureStorageCrawler:
    """Azure Storage Account crawler with SAS token bruteforcer and blob scraper"""
    
    def __init__(self):
        self.timeout = 10
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        
    def enumerate_storage_accounts(self, target: str) -> List[str]:
        """Enumerate potential storage account names"""
        patterns = [
            target,
            f"{target}storage",
            f"{target}data",
            f"{target}backup",
            f"{target}files",
            f"{target}logs",
            f"{target}assets",
            f"{target}media",
            f"{target}static",
            f"{target}web",
            f"{target}app",
            f"{target}dev",
            f"{target}prod",
            f"{target}test",
            f"storage{target}",
            f"data{target}",
            f"{target}01",
            f"{target}001"
        ]
        
        valid_accounts = []
        for account in patterns:
            if self.test_storage_account_exists(account):
                valid_accounts.append(account)
        
        return valid_accounts
    
    def test_storage_account_exists(self, account_name: str) -> bool:
        """Test if storage account exists"""
        try:
            url = f"https://{account_name}.blob.core.windows.net"
            req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
            urllib.request.urlopen(req, timeout=self.timeout)
            return True
        except urllib.error.HTTPError as e:
            # 400 = account exists but access denied
            # 404 = account doesn't exist
            return e.code == 400
        except:
            return False
    
    def enumerate_containers(self, account_name: str, sas_token: str = None) -> List[Dict[str, Any]]:
        """Enumerate containers in storage account"""
        containers = []
        
        # Try without authentication first
        try:
            url = f"https://{account_name}.blob.core.windows.net/?comp=list"
            if sas_token:
                url += f"&{sas_token}"
            
            req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
            response = urllib.request.urlopen(req, timeout=self.timeout)
            
            # Parse XML response
            root = ET.fromstring(response.read().decode())
            for container in root.findall('.//Container'):
                name_elem = container.find('Name')
                if name_elem is not None:
                    containers.append({
                        'name': name_elem.text,
                        'url': f"https://{account_name}.blob.core.windows.net/{name_elem.text}",
                        'public': sas_token is None
                    })
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        
        # Try common container names
        common_containers = [
            '$web', '$root', 'public', 'assets', 'images', 'files', 'data',
            'backup', 'logs', 'temp', 'cache', 'uploads', 'downloads',
            'documents', 'media', 'static', 'content', 'resources'
        ]
        
        for container in common_containers:
            if self.test_container_access(account_name, container, sas_token):
                containers.append({
                    'name': container,
                    'url': f"https://{account_name}.blob.core.windows.net/{container}",
                    'public': sas_token is None
                })
        
        return containers
    
    def test_container_access(self, account_name: str, container: str, sas_token: str = None) -> bool:
        """Test if container is accessible"""
        try:
            url = f"https://{account_name}.blob.core.windows.net/{container}?restype=container&comp=list"
            if sas_token:
                url += f"&{sas_token}"
            
            req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
            response = urllib.request.urlopen(req, timeout=self.timeout)
            return response.status == 200
        except:
            return False
    
    def enumerate_blobs(self, account_name: str, container: str, sas_token: str = None) -> List[Dict[str, Any]]:
        """Enumerate blobs in container"""
        blobs = []
        
        try:
            url = f"https://{account_name}.blob.core.windows.net/{container}?restype=container&comp=list"
            if sas_token:
                url += f"&{sas_token}"
            
            req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
            response = urllib.request.urlopen(req, timeout=self.timeout)
            
            # Parse XML response
            root = ET.fromstring(response.read().decode())
            for blob in root.findall('.//Blob'):
                name_elem = blob.find('Name')
                size_elem = blob.find('Properties/Content-Length')
                modified_elem = blob.find('Properties/Last-Modified')
                
                if name_elem is not None:
                    blobs.append({
                        'name': name_elem.text,
                        'url': f"https://{account_name}.blob.core.windows.net/{container}/{name_elem.text}",
                        'size': int(size_elem.text) if size_elem is not None else 0,
                        'modified': modified_elem.text if modified_elem is not None else None,
                        'interesting': self.is_interesting_file(name_elem.text)
                    })
        except Exception as e:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        
        return blobs
    
    def is_interesting_file(self, filename: str) -> bool:
        """Check if file is potentially interesting"""
        interesting_extensions = [
            '.config', '.xml', '.json', '.yml', '.yaml', '.env',
            '.key', '.pem', '.p12', '.pfx', '.crt', '.cer',
            '.sql', '.db', '.sqlite', '.mdb',
            '.log', '.txt', '.csv',
            '.zip', '.rar', '.7z', '.tar', '.gz',
            '.bak', '.backup', '.old', '.tmp'
        ]
        
        interesting_names = [
            'web.config', 'app.config', 'appsettings', 'connection',
            'database', 'backup', 'dump', 'export', 'password',
            'secret', 'key', 'token', 'credential', 'auth'
        ]
        
        filename_lower = filename.lower()
        
        # Check extensions
        for ext in interesting_extensions:
            if filename_lower.endswith(ext):
                return True
        
        # Check names
        for name in interesting_names:
            if name in filename_lower:
                return True
        
        return False
    
    def bruteforce_sas_tokens(self, account_name: str, container: str = None) -> List[Dict[str, Any]]:
        """Bruteforce common SAS token patterns"""
        found_tokens = []
        
        # Common SAS token patterns
        permissions = ['r', 'w', 'rw', 'rwl', 'rwla']
        
        # Generate date ranges (current time +/- 1 year)
        now = datetime.utcnow()
        start_times = [
            now - timedelta(days=365),
            now - timedelta(days=30),
            now - timedelta(days=1),
            now
        ]
        
        end_times = [
            now + timedelta(days=1),
            now + timedelta(days=30),
            now + timedelta(days=365)
        ]
        
        # Common resource types
        resources = ['b', 'c', 'o']  # blob, container, object
        
        # Try common weak patterns
        weak_patterns = [
            "sv=2020-08-04&ss=b&srt=sco&sp=rwdlacup&se=2025-12-31T23:59:59Z&st=2024-01-01T00:00:00Z&spr=https&sig=",
            "sv=2019-12-12&ss=bfqt&srt=sco&sp=rwdlacup&se=2024-12-31T23:59:59Z&st=2023-01-01T00:00:00Z&spr=https,http&sig=",
            "sp=r&st=2024-01-01T00:00:00Z&se=2025-01-01T00:00:00Z&spr=https&sv=2020-08-04&sr=c&sig="
        ]
        
        for pattern in weak_patterns:
            # Try with common signatures
            common_sigs = [
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D",
                "dGVzdA%3D%3D",  # base64 "test"
                "YWRtaW4%3D",   # base64 "admin"
                "cGFzc3dvcmQ%3D" # base64 "password"
            ]
            
            for sig in common_sigs:
                test_token = pattern + sig
                if self.test_sas_token(account_name, container, test_token):
                    found_tokens.append({
                        'token': test_token,
                        'type': 'weak_pattern',
                        'permissions': 'unknown'
                    })
        
        return found_tokens
    
    def test_sas_token(self, account_name: str, container: str, sas_token: str) -> bool:
        """Test if SAS token is valid"""
        try:
            if container:
                url = f"https://{account_name}.blob.core.windows.net/{container}?restype=container&comp=list&{sas_token}"
            else:
                url = f"https://{account_name}.blob.core.windows.net/?comp=list&{sas_token}"
            
            req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
            response = urllib.request.urlopen(req, timeout=self.timeout)
            return response.status == 200
        except:
            return False
    
    def download_blob(self, blob_url: str, sas_token: str = None, max_size: int = 1024*1024) -> Dict[str, Any]:
        """Download blob content (limited size for safety)"""
        try:
            url = blob_url
            if sas_token:
                separator = '&' if '?' in url else '?'
                url += f"{separator}{sas_token}"
            
            req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
            response = urllib.request.urlopen(req, timeout=self.timeout)
            
            # Read limited content
            content = response.read(max_size)
            
            return {
                'success': True,
                'content': content.decode('utf-8', errors='ignore')[:1000] + '...' if len(content) > 1000 else content.decode('utf-8', errors='ignore'),
                'size': len(content),
                'truncated': len(content) >= max_size
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def comprehensive_storage_scan(self, target: str) -> Dict[str, Any]:
        """Perform comprehensive storage account scan"""
        results = {
            'target': target,
            'storage_accounts': [],
            'containers': {},
            'blobs': {},
            'sas_tokens': {},
            'interesting_files': [],
            'summary': {}
        }
        
        # Enumerate storage accounts
        accounts = self.enumerate_storage_accounts(target)
        results['storage_accounts'] = accounts
        
        for account in accounts:
            # Enumerate containers
            containers = self.enumerate_containers(account)
            results['containers'][account] = containers
            
            # Bruteforce SAS tokens
            sas_tokens = self.bruteforce_sas_tokens(account)
            results['sas_tokens'][account] = sas_tokens
            
            # Enumerate blobs in each container
            for container in containers:
                container_name = container['name']
                
                # Try with found SAS tokens
                sas_token = sas_tokens[0]['token'] if sas_tokens else None
                
                blobs = self.enumerate_blobs(account, container_name, sas_token)
                results['blobs'][f"{account}/{container_name}"] = blobs
                
                # Collect interesting files
                for blob in blobs:
                    if blob['interesting']:
                        # Try to download interesting files
                        download_result = self.download_blob(blob['url'], sas_token)
                        blob['download_result'] = download_result
                        results['interesting_files'].append(blob)
        
        # Generate summary
        results['summary'] = self._generate_summary(results)
        
        return results
    
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary of storage scan results"""
        summary = {
            'accounts_found': len(results['storage_accounts']),
            'total_containers': 0,
            'total_blobs': 0,
            'public_containers': 0,
            'sas_tokens_found': 0,
            'interesting_files': len(results['interesting_files']),
            'security_findings': []
        }
        
        # Count containers and blobs
        for account, containers in results['containers'].items():
            summary['total_containers'] += len(containers)
            summary['public_containers'] += len([c for c in containers if c.get('public')])
        
        for key, blobs in results['blobs'].items():
            summary['total_blobs'] += len(blobs)
        
        # Count SAS tokens
        for account, tokens in results['sas_tokens'].items():
            summary['sas_tokens_found'] += len(tokens)
        
        # Security findings
        if summary['accounts_found'] > 0:
            summary['security_findings'].append(f"Found {summary['accounts_found']} accessible storage accounts")
        
        if summary['public_containers'] > 0:
            summary['security_findings'].append(f"Found {summary['public_containers']} publicly accessible containers")
        
        if summary['sas_tokens_found'] > 0:
            summary['security_findings'].append(f"Found {summary['sas_tokens_found']} valid SAS tokens")
        
        if summary['interesting_files'] > 0:
            summary['security_findings'].append(f"Found {summary['interesting_files']} potentially sensitive files")
        
        return summary

# Global storage crawler instance
storage_crawler = AzureStorageCrawler()