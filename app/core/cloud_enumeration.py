# app/core/cloud_enumeration.py
import requests
import threading
import time
from typing import Dict, List, Optional, Callable
from PyQt6.QtCore import QObject, pyqtSignal
from app.core.base_worker import BaseWorker
from app.core.html_utils import h
from app.core.logger import logger

try:
    from app.core.aws_pentest_engine import AWSPentestEngine
except ImportError:
    AWSPentestEngine = None

class CloudEnumerationEngine(QObject):
    """Cloud asset enumeration engine"""
    
    enumeration_event = pyqtSignal(str, str)  # event_type, message
    
    def __init__(self, proxy: Optional[str] = None, delay: float = 0.5, max_workers: int = 10):
        super().__init__()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Apply proxy settings
        if proxy:
            self.session.proxies.update({
                'http': proxy,
                'https': proxy
            })
        
        self.delay = delay
        self.max_workers = max_workers
    
    def validate_target(self, target: str) -> bool:
        """Validate target input"""
        import re
        
        # Domain pattern
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
        # IP pattern
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        
        return bool(re.match(domain_pattern, target) or re.match(ip_pattern, target))
        
    def enumerate_s3_buckets(self, target: str, wordlist: List[str]) -> Dict:
        """Enumerate S3 buckets for target with threading and enhanced validation"""
        if not self.validate_target(target):
            return {'buckets': [], 'accessible': [], 'errors': ['Invalid target format']}
            
        results = {'buckets': [], 'accessible': [], 'errors': []}
        
        # Common S3 bucket patterns
        patterns = [
            f"{target}",
            f"{target}-backup",
            f"{target}-backups", 
            f"{target}-data",
            f"{target}-logs",
            f"{target}-assets",
            f"{target}-files",
            f"{target}-uploads",
            f"{target}-static",
            f"{target}-dev",
            f"{target}-prod",
            f"{target}-staging"
        ]
        
        # Add wordlist patterns
        for word in wordlist:
            patterns.extend([
                f"{target}-{word}",
                f"{word}-{target}",
                f"{target}{word}",
                f"{word}{target}"
            ])
        
        from concurrent.futures import ThreadPoolExecutor
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(self._check_s3_bucket, name) for name in patterns]
            for future in futures:
                result = future.result()
                if result.get('exists'):
                    results['buckets'].append(result['bucket'])
                if result.get('accessible'):
                    results['accessible'].append(result)
                if result.get('error'):
                    results['errors'].append(result['error'])
                    
                # Rate limiting
                time.sleep(self.delay)
                
        return results
    
    def _check_s3_bucket(self, bucket_name: str) -> Dict:
        """Check individual S3 bucket with enhanced validation"""
        result = {'bucket': bucket_name, 'exists': False, 'accessible': False, 'error': None}
        
        try:
            url = f"https://{bucket_name}.s3.amazonaws.com"
            response = self.session.head(url, timeout=5)
            
            if response.status_code == 200:
                result['exists'] = True
                
                # Test public access
                list_response = self.session.get(url, timeout=5)
                if list_response.status_code == 200:
                    result['accessible'] = True
                    result['url'] = url
                    result['content'] = list_response.text[:500]
                else:
                    # Test known objects
                    test_objects = ['robots.txt', 'index.html', 'favicon.ico']
                    for obj in test_objects:
                        obj_url = f"{url}/{obj}"
                        obj_response = self.session.head(obj_url, timeout=3)
                        if obj_response.status_code == 200:
                            result['accessible'] = True
                            result['url'] = obj_url
                            break
                            
        except Exception as e:
            result['error'] = f"Error checking {bucket_name}: {str(e)}"
            
        return result
    
    def enumerate_azure_blobs(self, target: str, wordlist: List[str]) -> Dict:
        """Enumerate Azure Blob Storage containers"""
        results = {'containers': [], 'accessible': [], 'errors': []}
        
        # Common Azure storage patterns
        patterns = [
            f"{target}",
            f"{target}storage",
            f"{target}data",
            f"{target}files",
            f"{target}backup"
        ]
        
        # Add wordlist patterns
        for word in wordlist:
            patterns.extend([
                f"{target}{word}",
                f"{word}{target}",
                f"{target}-{word}",
                f"{word}-{target}"
            ])
        
        for storage_name in patterns:
            try:
                # Test Azure blob storage
                url = f"https://{storage_name}.blob.core.windows.net"
                response = self.session.head(url, timeout=5)
                
                if response.status_code in [200, 400]:  # 400 can indicate existence
                    results['containers'].append(storage_name)
                    
                    # Test container enumeration
                    list_url = f"{url}/?comp=list"
                    list_response = self.session.get(list_url, timeout=5)
                    if list_response.status_code == 200:
                        results['accessible'].append({
                            'container': storage_name,
                            'url': url,
                            'content': list_response.text[:500]
                        })
                        
            except Exception as e:
                results['errors'].append(f"Error checking {storage_name}: {str(e)}")
                
        return results
    
    def enumerate_azure_tenant(self, target: str) -> Dict:
        """Enumerate Azure AD tenant information with GUID harvesting"""
        results = {'tenant_info': {}, 'domains': [], 'tenant_guid': None, 'errors': []}
        
        try:
            # Test tenant via OpenID configuration
            url = f"https://login.microsoftonline.com/{target}/v2.0/.well-known/openid-configuration"
            response = self.session.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                results['tenant_info'] = {
                    'issuer': data.get('issuer'),
                    'authorization_endpoint': data.get('authorization_endpoint'),
                    'token_endpoint': data.get('token_endpoint'),
                    'valid': True
                }
                
                # Extract tenant GUID from issuer
                import re
                issuer = data.get('issuer', '')
                guid_match = re.search(r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', issuer)
                if guid_match:
                    results['tenant_guid'] = guid_match.group(1)
            else:
                results['tenant_info']['valid'] = False
                
        except Exception as e:
            results['errors'].append(f"Tenant enumeration error: {str(e)}")
        
        # Enhanced tenant GUID harvesting
        try:
            discovery_url = f"https://login.microsoftonline.com/common/discovery/instance?authorization_endpoint=https://login.microsoftonline.com/{target}/oauth2/authorize"
            discovery_response = self.session.get(discovery_url, timeout=5)
            if discovery_response.status_code == 200:
                discovery_data = discovery_response.json()
                tenant_discovery_endpoint = discovery_data.get('tenant_discovery_endpoint')
                if tenant_discovery_endpoint and not results['tenant_guid']:
                    # Extract GUID from discovery endpoint
                    import re
                    guid_match = re.search(r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', tenant_discovery_endpoint)
                    if guid_match:
                        results['tenant_guid'] = guid_match.group(1)
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        
        # Test common domain patterns
        domain_patterns = [
            f"{target}.onmicrosoft.com",
            f"{target}.com",
            f"{target}.net",
            f"{target}.org"
        ]
        
        for domain in domain_patterns:
            try:
                url = f"https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration"
                response = self.session.get(url, timeout=5)
                if response.status_code == 200:
                    results['domains'].append(domain)
            except Exception as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
                
        return results
    
    def enumerate_azure_app_services(self, target: str) -> Dict:
        """Enumerate Azure App Services with SCM exploitation"""
        results = {'apps': [], 'scm_endpoints': [], 'scm_exploits': [], 'errors': []}
        
        patterns = [
            f"{target}",
            f"{target}-api",
            f"{target}-app",
            f"{target}-web",
            f"{target}-dev",
            f"{target}-staging",
            f"{target}-prod"
        ]
        
        for app_name in patterns:
            try:
                # Test main app endpoint
                url = f"https://{app_name}.azurewebsites.net"
                response = self.session.head(url, timeout=5)
                
                if response.status_code in [200, 403, 404]:  # App exists
                    results['apps'].append({
                        'name': app_name,
                        'url': url,
                        'status': response.status_code
                    })
                    
                    # Test SCM endpoint with exploitation
                    scm_result = self._exploit_scm_endpoint(app_name)
                    if scm_result:
                        results['scm_endpoints'].append(scm_result)
                        if scm_result.get('exploitable'):
                            results['scm_exploits'].append(scm_result)
                    
                    # Test SSRF in App Services
                    ssrf_result = self._test_app_service_ssrf(url)
                    if ssrf_result:
                        results['scm_exploits'].append(ssrf_result)
                        
            except Exception as e:
                results['errors'].append(f"Error checking {app_name}: {str(e)}")
                
        return results
    
    def _exploit_scm_endpoint(self, app_name: str) -> Optional[Dict]:
        """Exploit Azure SCM endpoints"""
        scm_url = f"https://{app_name}.scm.azurewebsites.net"
        
        try:
            # Basic SCM check
            response = self.session.head(scm_url, timeout=5)
            if response.status_code not in [200, 401, 403]:
                return None
                
            result = {
                'name': app_name,
                'scm_url': scm_url,
                'status': response.status_code,
                'exploitable': False,
                'findings': []
            }
            
            # Test /api/settings endpoint
            settings_url = f"{scm_url}/api/settings"
            settings_response = self.session.get(settings_url, timeout=5)
            if settings_response.status_code == 200:
                result['exploitable'] = True
                result['findings'].append('Unauthenticated /api/settings access')
                
            # Test default credentials
            auth_tests = [('admin', 'admin'), ('admin', ''), ('', '')]
            for username, password in auth_tests:
                auth_response = self.session.get(scm_url, auth=(username, password), timeout=5)
                if auth_response.status_code == 200:
                    result['exploitable'] = True
                    result['findings'].append(f'Default credentials: {username}:{password}')
                    break
                    
            return result
            
        except Exception:
            return None
    
    def _test_app_service_ssrf(self, app_url: str) -> Optional[Dict]:
        """Test for SSRF in Azure App Services"""
        ssrf_payloads = [
            'http://localhost',
            'http://127.0.0.1',
            'http://169.254.169.254/metadata/instance'
        ]
        
        for payload in ssrf_payloads:
            try:
                # Test via redirect parameter
                test_url = f"{app_url}?redirect={payload}"
                response = self.session.get(test_url, timeout=3, allow_redirects=False)
                
                if response.status_code in [302, 301] and payload in response.headers.get('Location', ''):
                    return {
                        'type': 'SSRF',
                        'url': app_url,
                        'payload': payload,
                        'finding': 'Open redirect to internal URLs'
                    }
            except Exception:
                continue
                
        return None
    
    def query_metadata_apis(self, target_ip: str) -> Dict:
        """Query cloud metadata APIs with validation"""
        results = {'aws': {}, 'azure': {}, 'gcp': {}, 'errors': []}
        
        # Validate environment before querying metadata
        if not self._validate_cloud_environment(target_ip):
            results['errors'].append('Not in cloud environment - skipping metadata queries')
            return results
        
        # AWS metadata API
        try:
            aws_url = "http://169.254.169.254/latest/meta-data/"
            response = self.session.get(aws_url, timeout=3)
            if response.status_code == 200:
                results['aws']['available'] = True
                results['aws']['data'] = response.text
                
                # Get instance identity
                identity_url = f"{aws_url}instance-identity/document"
                identity_response = self.session.get(identity_url, timeout=3)
                if identity_response.status_code == 200:
                    results['aws']['identity'] = identity_response.json()
                    
        except Exception as e:
            results['errors'].append(f"AWS metadata error: {str(e)}")
    
    def _validate_cloud_environment(self, target_ip: str) -> bool:
        """Validate if we're in a cloud environment before querying metadata"""
        try:
            import subprocess
            
            # ICMP check to metadata IP
            result = subprocess.run(['ping', '-c', '1', '-W', '1000', '169.254.169.254'], 
                                  capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                # Additional validation via HTTP response fingerprinting
                try:
                    response = self.session.get('http://169.254.169.254/', timeout=2)
                    # Check for cloud-specific response patterns
                    cloud_indicators = ['latest', 'metadata', 'computeMetadata']
                    return any(indicator in response.text.lower() for indicator in cloud_indicators)
                except:
                    return False
                    
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
            
        return False
        
        # Azure metadata API
        try:
            azure_url = "http://169.254.169.254/metadata/instance"
            headers = {'Metadata': 'true'}
            response = self.session.get(azure_url, headers=headers, timeout=3)
            if response.status_code == 200:
                results['azure']['available'] = True
                results['azure']['data'] = response.json()
                
        except Exception as e:
            results['errors'].append(f"Azure metadata error: {str(e)}")
        
        # GCP metadata API
        try:
            gcp_url = "http://metadata.google.internal/computeMetadata/v1/"
            headers = {'Metadata-Flavor': 'Google'}
            response = self.session.get(gcp_url, headers=headers, timeout=3)
            if response.status_code == 200:
                results['gcp']['available'] = True
                results['gcp']['data'] = response.text
                
        except Exception as e:
            results['errors'].append(f"GCP metadata error: {str(e)}")
            
        return results

class CloudEnumerationWorker(BaseWorker):
    """Worker for cloud enumeration tasks"""
    
    def __init__(self, target: str, scan_type: str, wordlist: List[str] = None, 
                 proxy: Optional[str] = None, delay: float = 0.5, max_workers: int = 10):
        super().__init__(f"cloud_{scan_type}", f"Cloud {scan_type} enumeration")
        self.target = target
        self.scan_type = scan_type
        self.wordlist = wordlist or []
        self.engine = CloudEnumerationEngine(proxy=proxy, delay=delay, max_workers=max_workers)
        
        # Logging setup
        import logging
        self.logger = logging.getLogger(f'cloud_enum_{scan_type}')
        handler = logging.FileHandler('logs/cloud_enumeration.log')
        handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
        
    def run(self):
        try:
            self.logger.info(f"Starting {self.scan_type} enumeration for target: {self.target}")
            self.signals.progress_start.emit("Starting cloud enumeration...")
            
            if self.scan_type == "s3_buckets":
                results = self.engine.enumerate_s3_buckets(self.target, self.wordlist)
                self.format_s3_results(results)
                
            elif self.scan_type == "azure_blobs":
                results = self.engine.enumerate_azure_blobs(self.target, self.wordlist)
                self.format_azure_results(results)
                
            elif self.scan_type == "azure_tenant":
                results = self.engine.enumerate_azure_tenant(self.target)
                self.format_azure_tenant_results(results)
                
            elif self.scan_type == "azure_apps":
                results = self.engine.enumerate_azure_app_services(self.target)
                self.format_azure_app_results(results)
                
            elif self.scan_type == "metadata_apis":
                results = self.engine.query_metadata_apis(self.target)
                self.format_metadata_results(results)
                
            elif self.scan_type == "full_scan":
                # Run all enumeration types
                self.signals.output.emit("<p style='color: #00BFFF;'>Starting comprehensive cloud enumeration...</p>")
                
                # S3 enumeration
                s3_results = self.engine.enumerate_s3_buckets(self.target, self.wordlist)
                self.format_s3_results(s3_results)
                
                # Azure enumeration
                azure_results = self.engine.enumerate_azure_blobs(self.target, self.wordlist)
                self.format_azure_results(azure_results)
                
                # Azure tenant enumeration
                tenant_results = self.engine.enumerate_azure_tenant(self.target)
                self.format_azure_tenant_results(tenant_results)
                
                # Azure app services
                app_results = self.engine.enumerate_azure_app_services(self.target)
                self.format_azure_app_results(app_results)
                
                # Metadata APIs
                metadata_results = self.engine.query_metadata_apis(self.target)
                self.format_metadata_results(metadata_results)
                
                results = {
                    's3': s3_results,
                    'azure_blobs': azure_results,
                    'azure_tenant': tenant_results,
                    'azure_apps': app_results,
                    'metadata': metadata_results
                }
            
            self.signals.results_ready.emit(results)
            self.signals.finished.emit()
            
        except Exception as e:
            self.signals.error.emit(str(e))
            
    def format_s3_results(self, results: Dict):
        """Format S3 enumeration results"""
        self.signals.output.emit("<p style='color: #87CEEB;'>[S3 ENUMERATION]</p>")
        
        if results['buckets']:
            self.signals.output.emit(f"<p style='color: #00FF41;'>Found {len(results['buckets'])} S3 buckets:</p>")
            for bucket in results['buckets']:
                self.signals.output.emit(f"<p style='color: #DCDCDC;'>  • {h(bucket)}.s3.amazonaws.com</p>")
        
        if results['accessible']:
            self.signals.output.emit(f"<p style='color: #FF6B6B;'>Publicly accessible buckets ({len(results['accessible'])}):</p>")
            for bucket_info in results['accessible']:
                self.signals.output.emit(f"<p style='color: #FF6B6B;'>  ⚠️ {h(bucket_info['bucket'])} - {h(bucket_info['url'])}</p>")
        
        if results['errors']:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>Errors: {len(results['errors'])}</p>")
            
    def format_azure_results(self, results: Dict):
        """Format Azure enumeration results"""
        self.signals.output.emit("<p style='color: #87CEEB;'>[AZURE BLOB ENUMERATION]</p>")
        
        if results['containers']:
            self.signals.output.emit(f"<p style='color: #00FF41;'>Found {len(results['containers'])} Azure storage accounts:</p>")
            for container in results['containers']:
                self.signals.output.emit(f"<p style='color: #DCDCDC;'>  • {h(container)}.blob.core.windows.net</p>")
        
        if results['accessible']:
            self.signals.output.emit(f"<p style='color: #FF6B6B;'>Accessible containers ({len(results['accessible'])}):</p>")
            for container_info in results['accessible']:
                self.signals.output.emit(f"<p style='color: #FF6B6B;'>  ⚠️ {h(container_info['container'])} - {h(container_info['url'])}</p>")
                
    def format_metadata_results(self, results: Dict):
        """Format metadata API results"""
        self.signals.output.emit("<p style='color: #87CEEB;'>[CLOUD METADATA APIS]</p>")
        
        if results['aws'].get('available'):
            self.signals.output.emit("<p style='color: #00FF41;'>AWS Metadata API accessible</p>")
            if 'identity' in results['aws']:
                identity = results['aws']['identity']
                self.signals.output.emit(f"<p style='color: #DCDCDC;'>  Instance ID: {h(identity.get('instanceId', 'N/A'))}</p>")
                self.signals.output.emit(f"<p style='color: #DCDCDC;'>  Region: {h(identity.get('region', 'N/A'))}</p>")
                self.signals.output.emit(f"<p style='color: #DCDCDC;'>  Account ID: {h(identity.get('accountId', 'N/A'))}</p>")
        
        if results['azure'].get('available'):
            self.signals.output.emit("<p style='color: #00FF41;'>Azure Metadata API accessible</p>")
            if 'data' in results['azure']:
                data = results['azure']['data']
                compute = data.get('compute', {})
                self.signals.output.emit(f"<p style='color: #DCDCDC;'>  VM Name: {h(compute.get('name', 'N/A'))}</p>")
                self.signals.output.emit(f"<p style='color: #DCDCDC;'>  Location: {h(compute.get('location', 'N/A'))}</p>")
        
        if results['gcp'].get('available'):
            self.signals.output.emit("<p style='color: #00FF41;'>GCP Metadata API accessible</p>")
            
    def format_azure_tenant_results(self, results: Dict):
        """Format Azure tenant enumeration results"""
        self.signals.output.emit("<p style='color: #87CEEB;'>[AZURE TENANT ENUMERATION]</p>")
        
        if results['tenant_info'].get('valid'):
            self.signals.output.emit("<p style='color: #00FF41;'>✓ Valid Azure tenant found</p>")
            tenant_info = results['tenant_info']
            if 'issuer' in tenant_info:
                self.signals.output.emit(f"<p style='color: #DCDCDC;'>  Issuer: {h(tenant_info['issuer'])}</p>")
            if 'authorization_endpoint' in tenant_info:
                self.signals.output.emit(f"<p style='color: #DCDCDC;'>  Auth endpoint: {h(tenant_info['authorization_endpoint'])}</p>")
        else:
            self.signals.output.emit("<p style='color: #FF6B6B;'>✗ Invalid or inaccessible tenant</p>")
            
        if results['domains']:
            self.signals.output.emit(f"<p style='color: #00FF41;'>Found {len(results['domains'])} associated domains:</p>")
            for domain in results['domains']:
                self.signals.output.emit(f"<p style='color: #DCDCDC;'>  • {h(domain)}</p>")
                
        if results['errors']:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>Errors: {len(results['errors'])}</p>")
            
    def format_azure_app_results(self, results: Dict):
        """Format Azure App Services results"""
        self.signals.output.emit("<p style='color: #87CEEB;'>[AZURE APP SERVICES]</p>")
        
        if results['apps']:
            self.signals.output.emit(f"<p style='color: #00FF41;'>Found {len(results['apps'])} App Services:</p>")
            for app in results['apps']:
                status_color = "#00FF41" if app['status'] == 200 else "#FFAA00"
                self.signals.output.emit(f"<p style='color: {h(status_color)};'>  • {h(app['name'])} ({h(app['status'])}) - {h(app['url'])}</p>")
                
        if results['scm_endpoints']:
            self.signals.output.emit(f"<p style='color: #FF6B6B;'>SCM endpoints found ({len(results['scm_endpoints'])}):</p>")
            for scm in results['scm_endpoints']:
                self.signals.output.emit(f"<p style='color: #FF6B6B;'>  ⚠️ {h(scm['name'])} - {h(scm['scm_url'])}</p>")
                
        if results['errors']:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>Errors: {len(results['errors'])}</p>")

class CloudEnumerationPlugin:
    """Base class for cloud enumeration plugins"""
    
    def __init__(self, session: requests.Session):
        self.session = session
    
    def run(self, target: str, **kwargs) -> Dict:
        """Run plugin enumeration"""
        raise NotImplementedError

class CDNOriginExposurePlugin(CloudEnumerationPlugin):
    """Plugin to detect CDN origin exposure"""
    
    def run(self, target: str, **kwargs) -> Dict:
        results = {'origins': [], 'bypasses': [], 'errors': []}
        
        try:
            # Test Host header injection
            original_url = f"https://{target}"
            response = self.session.get(original_url, timeout=5)
            
            # Common origin patterns
            origin_patterns = [
                f"{target}.s3.amazonaws.com",
                f"{target}.blob.core.windows.net",
                f"origin-{target}.com",
                f"{target}-origin.com"
            ]
            
            for origin in origin_patterns:
                try:
                    # Test direct origin access
                    origin_response = self.session.get(f"https://{origin}", timeout=5)
                    if origin_response.status_code == 200:
                        results['origins'].append(origin)
                        
                        # Test Host header bypass
                        bypass_response = self.session.get(
                            original_url, 
                            headers={'Host': origin},
                            timeout=5
                        )
                        if bypass_response.text != response.text:
                            results['bypasses'].append({
                                'method': 'Host header injection',
                                'origin': origin,
                                'url': original_url
                            })
                except Exception:
                    continue
                    
        except Exception as e:
            results['errors'].append(str(e))
            
        return results

class CSPBypassPlugin(CloudEnumerationPlugin):
    """Plugin to check CSP bypass opportunities"""
    
    def run(self, target: str, **kwargs) -> Dict:
        results = {'csp_header': None, 'bypasses': [], 'errors': []}
        
        try:
            response = self.session.get(f"https://{target}", timeout=5)
            csp_header = response.headers.get('Content-Security-Policy')
            
            if csp_header:
                results['csp_header'] = csp_header
                
                # Check for common CSP bypasses
                bypass_indicators = [
                    ('unsafe-inline', 'Allows inline scripts'),
                    ('unsafe-eval', 'Allows eval()'),
                    ('data:', 'Allows data: URIs'),
                    ('*', 'Wildcard source allowed')
                ]
                
                for indicator, description in bypass_indicators:
                    if indicator in csp_header:
                        results['bypasses'].append({
                            'type': indicator,
                            'description': description
                        })
                        
        except Exception as e:
            results['errors'].append(str(e))
            
        return results

# Plugin registry
CLOUD_PLUGINS = {
    'cdn_origin_exposure': CDNOriginExposurePlugin,
    'csp_bypass': CSPBypassPlugin
}

# Global cloud enumeration engine
cloud_engine = CloudEnumerationEngine()

# Azure-specific enumeration functions for integration
def enumerate_azure_tenant_info(target: str) -> Dict:
    """Quick Azure tenant enumeration"""
    return cloud_engine.enumerate_azure_tenant(target)

def enumerate_azure_resources(target: str, wordlist: List[str] = None) -> Dict:
    """Comprehensive Azure resource enumeration"""
    if wordlist is None:
        wordlist = ['dev', 'prod', 'staging', 'test', 'api', 'web', 'app']
        
    results = {
        'tenant': cloud_engine.enumerate_azure_tenant(target),
        'blobs': cloud_engine.enumerate_azure_blobs(target, wordlist),
        'apps': cloud_engine.enumerate_azure_app_services(target)
    }
    return results

def run_cloud_plugins(target: str, session: requests.Session) -> Dict:
    """Run all available cloud enumeration plugins"""
    plugin_results = {}
    
    for plugin_name, plugin_class in CLOUD_PLUGINS.items():
        try:
            plugin = plugin_class(session)
            plugin_results[plugin_name] = plugin.run(target)
        except Exception as e:
            plugin_results[plugin_name] = {'error': str(e)}
            
    return plugin_results