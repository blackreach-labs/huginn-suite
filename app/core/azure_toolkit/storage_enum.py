"""
Azure Storage Account Enumeration Module
Enumerates Azure storage accounts and containers using Azure Storage SDK.
"""

from typing import Dict, List, Optional, Any
from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
import logging
from .auth import AzureAuthenticator
from app.core.logger import logger

logger = logging.getLogger(__name__)

class AzureStorageEnum:
    """Azure Storage Account enumeration and analysis"""
    
    def __init__(self, authenticator: AzureAuthenticator = None):
        self.auth = authenticator or AzureAuthenticator()
        
    def enumerate_storage_accounts(self, subscription_id: str, credential=None) -> Dict[str, Any]:
        """Enumerate storage accounts using ARM API"""
        from .arm_recon import AzureResourceRecon
        arm_recon = AzureResourceRecon(self.auth)
        return arm_recon.list_storage_accounts(subscription_id, credential)
    
    def list_containers_and_blobs(self, storage_account_name: str, credential=None) -> Dict[str, Any]:
        """List containers and blobs in a storage account"""
        try:
            if not credential:
                credential = self.auth.get_default_credential()
            
            # Construct storage account URL
            account_url = f"https://{storage_account_name}.blob.core.windows.net"
            
            # Create blob service client
            blob_service_client = BlobServiceClient(
                account_url=account_url,
                credential=credential
            )
            
            containers_data = []
            
            # List containers
            containers = blob_service_client.list_containers(include_metadata=True)
            
            for container in containers:
                container_info = {
                    'name': container.name,
                    'last_modified': container.last_modified.isoformat() if container.last_modified else None,
                    'metadata': container.metadata or {},
                    'public_access': container.public_access.value if container.public_access else 'none',
                    'blobs': []
                }
                
                # List blobs in container (limit to first 100 for performance)
                try:
                    container_client = blob_service_client.get_container_client(container.name)
                    blob_list = container_client.list_blobs(include=['metadata', 'tags'])
                    
                    blob_count = 0
                    for blob in blob_list:
                        if blob_count >= 100:  # Limit for performance
                            break
                        
                        container_info['blobs'].append({
                            'name': blob.name,
                            'size': blob.size,
                            'last_modified': blob.last_modified.isoformat() if blob.last_modified else None,
                            'content_type': blob.content_settings.content_type if blob.content_settings else None,
                            'metadata': blob.metadata or {},
                            'tags': blob.tags or {},
                            'is_sensitive': self._is_sensitive_blob(blob.name)
                        })
                        blob_count += 1
                    
                    container_info['blob_count'] = blob_count
                    container_info['truncated'] = blob_count >= 100
                    
                except Exception as e:
                    logger.warning(f"Failed to list blobs in container {container.name}: {e}")
                    container_info['blob_error'] = str(e)
                
                containers_data.append(container_info)
            
            return {
                'storage_account': storage_account_name,
                'containers': containers_data,
                'container_count': len(containers_data)
            }
            
        except ClientAuthenticationError as e:
            logger.error(f"Authentication failed for storage account {storage_account_name}: {e}")
            return {'error': f'Authentication failed: {str(e)}'}
        except HttpResponseError as e:
            logger.error(f"HTTP error accessing storage account {storage_account_name}: {e}")
            return {'error': f'HTTP error: {str(e)}'}
        except Exception as e:
            logger.error(f"Failed to enumerate storage account {storage_account_name}: {e}")
            return {'error': str(e)}
    
    def _is_sensitive_blob(self, blob_name: str) -> bool:
        """Check if blob name indicates sensitive content"""
        sensitive_patterns = [
            'config', 'secret', 'key', 'password', 'credential',
            'backup', 'dump', 'export', 'private', 'confidential',
            '.env', '.config', '.xml', '.json', '.yml', '.yaml',
            '.key', '.pem', '.p12', '.pfx', '.crt', '.cer',
            '.sql', '.db', '.sqlite', '.bak', '.backup'
        ]
        
        blob_name_lower = blob_name.lower()
        return any(pattern in blob_name_lower for pattern in sensitive_patterns)
    
    def analyze_container_permissions(self, storage_account_name: str, container_name: str, credential=None) -> Dict[str, Any]:
        """Analyze container access permissions"""
        try:
            if not credential:
                credential = self.auth.get_default_credential()
            
            account_url = f"https://{storage_account_name}.blob.core.windows.net"
            blob_service_client = BlobServiceClient(account_url=account_url, credential=credential)
            
            container_client = blob_service_client.get_container_client(container_name)
            
            # Get container properties
            properties = container_client.get_container_properties()
            
            # Check public access level
            public_access = properties.public_access
            
            analysis = {
                'storage_account': storage_account_name,
                'container': container_name,
                'public_access_level': public_access.value if public_access else 'none',
                'is_public': public_access is not None and public_access.value != 'none',
                'last_modified': properties.last_modified.isoformat() if properties.last_modified else None,
                'metadata': properties.metadata or {},
                'security_findings': []
            }
            
            # Security analysis
            if analysis['is_public']:
                if public_access.value == 'container':
                    analysis['security_findings'].append("Container allows public read access to container and blob data")
                elif public_access.value == 'blob':
                    analysis['security_findings'].append("Container allows public read access to blob data only")
            
            return analysis
            
        except Exception as e:
            logger.error(f"Failed to analyze container permissions: {e}")
            return {'error': str(e)}
    
    def check_storage_account_security(self, storage_account_name: str, credential=None) -> Dict[str, Any]:
        """Check storage account security configuration"""
        try:
            # This would require ARM API access to get storage account properties
            from .arm_recon import AzureResourceRecon
            arm_recon = AzureResourceRecon(self.auth)
            
            # We need subscription ID and resource group to get detailed properties
            # For now, return basic blob service analysis
            
            if not credential:
                credential = self.auth.get_default_credential()
            
            account_url = f"https://{storage_account_name}.blob.core.windows.net"
            blob_service_client = BlobServiceClient(account_url=account_url, credential=credential)
            
            security_analysis = {
                'storage_account': storage_account_name,
                'accessible': True,
                'containers_analyzed': [],
                'security_findings': [],
                'recommendations': []
            }
            
            # Analyze containers
            try:
                containers = blob_service_client.list_containers()
                for container in containers:
                    container_analysis = self.analyze_container_permissions(
                        storage_account_name, container.name, credential
                    )
                    
                    if 'error' not in container_analysis:
                        security_analysis['containers_analyzed'].append(container_analysis)
                        
                        # Aggregate security findings
                        security_analysis['security_findings'].extend(
                            container_analysis.get('security_findings', [])
                        )
            
            except Exception as e:
                security_analysis['container_analysis_error'] = str(e)
            
            # Generate recommendations
            if any('public' in finding.lower() for finding in security_analysis['security_findings']):
                security_analysis['recommendations'].append(
                    "Review and restrict public access to storage containers"
                )
            
            return security_analysis
            
        except Exception as e:
            logger.error(f"Failed to check storage account security: {e}")
            return {'error': str(e)}
    
    def download_blob_sample(self, storage_account_name: str, container_name: str, 
                           blob_name: str, max_size: int = 1024, credential=None) -> Dict[str, Any]:
        """Download a sample of blob content for analysis"""
        try:
            if not credential:
                credential = self.auth.get_default_credential()
            
            account_url = f"https://{storage_account_name}.blob.core.windows.net"
            blob_service_client = BlobServiceClient(account_url=account_url, credential=credential)
            
            blob_client = blob_service_client.get_blob_client(
                container=container_name, 
                blob=blob_name
            )
            
            # Download first part of blob
            blob_data = blob_client.download_blob(max_concurrency=1)
            content = blob_data.readall()
            
            # Limit content size
            if len(content) > max_size:
                content = content[:max_size]
                truncated = True
            else:
                truncated = False
            
            # Try to decode as text
            try:
                text_content = content.decode('utf-8', errors='ignore')
            except Exception:
                text_content = f"<Binary content, {len(content)} bytes>"
            
            return {
                'storage_account': storage_account_name,
                'container': container_name,
                'blob': blob_name,
                'content': text_content,
                'size': len(content),
                'truncated': truncated,
                'is_sensitive': self._is_sensitive_blob(blob_name)
            }
            
        except Exception as e:
            logger.error(f"Failed to download blob sample: {e}")
            return {'error': str(e)}
    
    def comprehensive_storage_enum(self, subscription_id: str, credential=None) -> Dict[str, Any]:
        """Perform comprehensive storage enumeration for a subscription"""
        try:
            results = {
                'subscription_id': subscription_id,
                'storage_accounts': [],
                'security_findings': [],
                'sensitive_blobs': [],
                'public_containers': []
            }
            
            # Get storage accounts
            storage_accounts_result = self.enumerate_storage_accounts(subscription_id, credential)
            
            if 'error' in storage_accounts_result:
                return storage_accounts_result
            
            storage_accounts = storage_accounts_result.get('storage_accounts', [])
            
            # Analyze each storage account
            for account in storage_accounts[:5]:  # Limit to first 5 accounts
                account_name = account['name']
                
                # List containers and blobs
                containers_result = self.list_containers_and_blobs(account_name, credential)
                
                if 'error' not in containers_result:
                    account['containers'] = containers_result.get('containers', [])
                    
                    # Analyze for security issues
                    for container in account['containers']:
                        if container.get('public_access', 'none') != 'none':
                            results['public_containers'].append({
                                'storage_account': account_name,
                                'container': container['name'],
                                'public_access': container['public_access']
                            })
                        
                        # Check for sensitive blobs
                        for blob in container.get('blobs', []):
                            if blob.get('is_sensitive'):
                                results['sensitive_blobs'].append({
                                    'storage_account': account_name,
                                    'container': container['name'],
                                    'blob': blob['name'],
                                    'size': blob.get('size', 0)
                                })
                
                # Security analysis
                security_result = self.check_storage_account_security(account_name, credential)
                if 'error' not in security_result:
                    results['security_findings'].extend(
                        security_result.get('security_findings', [])
                    )
                
                results['storage_accounts'].append(account)
            
            # Generate summary
            results['summary'] = self._generate_storage_summary(results)
            
            return results
            
        except Exception as e:
            logger.error(f"Comprehensive storage enumeration failed: {e}")
            return {'error': str(e)}
    
    def _generate_storage_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary of storage enumeration results"""
        summary = {
            'storage_account_count': len(results.get('storage_accounts', [])),
            'total_containers': 0,
            'total_blobs': 0,
            'public_container_count': len(results.get('public_containers', [])),
            'sensitive_blob_count': len(results.get('sensitive_blobs', [])),
            'security_finding_count': len(results.get('security_findings', [])),
            'risk_level': 'Low'
        }
        
        # Count containers and blobs
        for account in results.get('storage_accounts', []):
            containers = account.get('containers', [])
            summary['total_containers'] += len(containers)
            
            for container in containers:
                summary['total_blobs'] += len(container.get('blobs', []))
        
        # Determine risk level
        if summary['public_container_count'] > 0 or summary['sensitive_blob_count'] > 5:
            summary['risk_level'] = 'High'
        elif summary['sensitive_blob_count'] > 0 or summary['security_finding_count'] > 0:
            summary['risk_level'] = 'Medium'
        
        return summary