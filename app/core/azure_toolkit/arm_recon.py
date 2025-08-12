"""
Azure Resource Manager Enumeration Module
Enumerates Azure resources using Azure Management APIs.
"""

from typing import Dict, List, Optional, Any
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
import logging
from .auth import AzureAuthenticator

logger = logging.getLogger(__name__)

class AzureResourceRecon:
    """Azure Resource Manager reconnaissance and enumeration"""
    
    def __init__(self, authenticator: AzureAuthenticator = None):
        self.auth = authenticator or AzureAuthenticator()
        
    def list_subscriptions(self, credential=None) -> Dict[str, Any]:
        """List accessible subscriptions"""
        try:
            if not credential:
                credential = self.auth.get_default_credential()
            
            from azure.mgmt.resource import SubscriptionClient
            subscription_client = SubscriptionClient(credential)
            
            subscriptions = []
            for sub in subscription_client.subscriptions.list():
                subscriptions.append({
                    'subscription_id': sub.subscription_id,
                    'display_name': sub.display_name,
                    'state': sub.state.value if sub.state else 'Unknown',
                    'tenant_id': sub.tenant_id
                })
            
            return {
                'subscriptions': subscriptions,
                'count': len(subscriptions)
            }
            
        except ClientAuthenticationError as e:
            logger.error(f"Authentication failed: {e}")
            return {'error': f'Authentication failed: {str(e)}'}
        except Exception as e:
            logger.error(f"Failed to list subscriptions: {e}")
            return {'error': str(e)}
    
    def list_resource_groups(self, subscription_id: str, credential=None) -> Dict[str, Any]:
        """List resource groups in a subscription"""
        try:
            if not credential:
                credential = self.auth.get_default_credential()
            
            resource_client = ResourceManagementClient(credential, subscription_id)
            
            resource_groups = []
            for rg in resource_client.resource_groups.list():
                resource_groups.append({
                    'name': rg.name,
                    'location': rg.location,
                    'provisioning_state': rg.provisioning_state,
                    'tags': rg.tags or {}
                })
            
            return {
                'resource_groups': resource_groups,
                'count': len(resource_groups),
                'subscription_id': subscription_id
            }
            
        except HttpResponseError as e:
            logger.error(f"HTTP error listing resource groups: {e}")
            return {'error': f'HTTP error: {str(e)}'}
        except Exception as e:
            logger.error(f"Failed to list resource groups: {e}")
            return {'error': str(e)}
    
    def list_resources(self, subscription_id: str, credential=None, resource_group: str = None) -> Dict[str, Any]:
        """List resources in a subscription or resource group"""
        try:
            if not credential:
                credential = self.auth.get_default_credential()
            
            resource_client = ResourceManagementClient(credential, subscription_id)
            
            resources = []
            if resource_group:
                resource_list = resource_client.resources.list_by_resource_group(resource_group)
            else:
                resource_list = resource_client.resources.list()
            
            for resource in resource_list:
                resources.append({
                    'name': resource.name,
                    'type': resource.type,
                    'location': resource.location,
                    'resource_group': resource.id.split('/')[4] if resource.id else 'Unknown',
                    'provisioning_state': getattr(resource, 'provisioning_state', 'Unknown'),
                    'tags': resource.tags or {},
                    'id': resource.id
                })
            
            return {
                'resources': resources,
                'count': len(resources),
                'subscription_id': subscription_id,
                'resource_group': resource_group
            }
            
        except HttpResponseError as e:
            logger.error(f"HTTP error listing resources: {e}")
            return {'error': f'HTTP error: {str(e)}'}
        except Exception as e:
            logger.error(f"Failed to list resources: {e}")
            return {'error': str(e)}
    
    def list_storage_accounts(self, subscription_id: str, credential=None) -> Dict[str, Any]:
        """List storage accounts in a subscription"""
        try:
            if not credential:
                credential = self.auth.get_default_credential()
            
            storage_client = StorageManagementClient(credential, subscription_id)
            
            storage_accounts = []
            for account in storage_client.storage_accounts.list():
                # Get account properties
                account_props = storage_client.storage_accounts.get_properties(
                    account.id.split('/')[4],  # resource group name
                    account.name
                )
                
                storage_accounts.append({
                    'name': account.name,
                    'location': account.location,
                    'resource_group': account.id.split('/')[4],
                    'sku_name': account.sku.name if account.sku else 'Unknown',
                    'kind': account.kind.value if account.kind else 'Unknown',
                    'provisioning_state': account.provisioning_state.value if account.provisioning_state else 'Unknown',
                    'primary_endpoints': {
                        'blob': account_props.primary_endpoints.blob if account_props.primary_endpoints else None,
                        'file': account_props.primary_endpoints.file if account_props.primary_endpoints else None,
                        'queue': account_props.primary_endpoints.queue if account_props.primary_endpoints else None,
                        'table': account_props.primary_endpoints.table if account_props.primary_endpoints else None
                    },
                    'https_traffic_only': getattr(account_props, 'enable_https_traffic_only', False),
                    'allow_blob_public_access': getattr(account_props, 'allow_blob_public_access', None),
                    'tags': account.tags or {}
                })
            
            return {
                'storage_accounts': storage_accounts,
                'count': len(storage_accounts),
                'subscription_id': subscription_id
            }
            
        except HttpResponseError as e:
            logger.error(f"HTTP error listing storage accounts: {e}")
            return {'error': f'HTTP error: {str(e)}'}
        except Exception as e:
            logger.error(f"Failed to list storage accounts: {e}")
            return {'error': str(e)}
    
    def list_key_vaults(self, subscription_id: str, credential=None) -> Dict[str, Any]:
        """List Key Vaults in a subscription"""
        try:
            if not credential:
                credential = self.auth.get_default_credential()
            
            kv_client = KeyVaultManagementClient(credential, subscription_id)
            
            key_vaults = []
            for vault in kv_client.vaults.list():
                key_vaults.append({
                    'name': vault.name,
                    'location': vault.location,
                    'resource_group': vault.id.split('/')[4],
                    'vault_uri': vault.properties.vault_uri if vault.properties else None,
                    'tenant_id': vault.properties.tenant_id if vault.properties else None,
                    'sku': vault.properties.sku.name.value if vault.properties and vault.properties.sku else 'Unknown',
                    'enabled_for_deployment': vault.properties.enabled_for_deployment if vault.properties else False,
                    'enabled_for_template_deployment': vault.properties.enabled_for_template_deployment if vault.properties else False,
                    'enabled_for_disk_encryption': vault.properties.enabled_for_disk_encryption if vault.properties else False,
                    'tags': vault.tags or {}
                })
            
            return {
                'key_vaults': key_vaults,
                'count': len(key_vaults),
                'subscription_id': subscription_id
            }
            
        except HttpResponseError as e:
            logger.error(f"HTTP error listing Key Vaults: {e}")
            return {'error': f'HTTP error: {str(e)}'}
        except Exception as e:
            logger.error(f"Failed to list Key Vaults: {e}")
            return {'error': str(e)}
    
    def get_resource_details(self, subscription_id: str, resource_group: str, 
                           resource_name: str, resource_type: str, credential=None) -> Dict[str, Any]:
        """Get detailed information about a specific resource"""
        try:
            if not credential:
                credential = self.auth.get_default_credential()
            
            resource_client = ResourceManagementClient(credential, subscription_id)
            
            # Construct resource ID
            resource_id = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/{resource_type}/{resource_name}"
            
            resource = resource_client.resources.get_by_id(resource_id, api_version="2021-04-01")
            
            return {
                'name': resource.name,
                'type': resource.type,
                'location': resource.location,
                'resource_group': resource_group,
                'properties': resource.properties,
                'tags': resource.tags or {},
                'id': resource.id
            }
            
        except HttpResponseError as e:
            logger.error(f"HTTP error getting resource details: {e}")
            return {'error': f'HTTP error: {str(e)}'}
        except Exception as e:
            logger.error(f"Failed to get resource details: {e}")
            return {'error': str(e)}
    
    def check_resource_permissions(self, subscription_id: str, credential=None) -> Dict[str, Any]:
        """Check permissions on subscription and resources"""
        try:
            if not credential:
                credential = self.auth.get_default_credential()
            
            from azure.mgmt.authorization import AuthorizationManagementClient
            auth_client = AuthorizationManagementClient(credential, subscription_id)
            
            # Get role assignments
            role_assignments = []
            for assignment in auth_client.role_assignments.list():
                role_assignments.append({
                    'principal_id': assignment.principal_id,
                    'role_definition_id': assignment.role_definition_id,
                    'scope': assignment.scope
                })
            
            return {
                'role_assignments': role_assignments,
                'count': len(role_assignments),
                'subscription_id': subscription_id
            }
            
        except HttpResponseError as e:
            logger.error(f"HTTP error checking permissions: {e}")
            return {'error': f'HTTP error: {str(e)}'}
        except Exception as e:
            logger.error(f"Failed to check permissions: {e}")
            return {'error': str(e)}
    
    def comprehensive_arm_enum(self, credential=None) -> Dict[str, Any]:
        """Perform comprehensive Azure Resource Manager enumeration"""
        try:
            results = {
                'subscriptions': self.list_subscriptions(credential),
                'resource_summary': {},
                'security_findings': []
            }
            
            # If we have subscriptions, enumerate resources in each
            subscriptions = results['subscriptions'].get('subscriptions', [])
            
            for sub in subscriptions[:3]:  # Limit to first 3 subscriptions
                sub_id = sub['subscription_id']
                
                # Get resource groups
                rg_result = self.list_resource_groups(sub_id, credential)
                
                # Get storage accounts
                storage_result = self.list_storage_accounts(sub_id, credential)
                
                # Get Key Vaults
                kv_result = self.list_key_vaults(sub_id, credential)
                
                # Get all resources
                resources_result = self.list_resources(sub_id, credential)
                
                results['resource_summary'][sub_id] = {
                    'subscription_name': sub['display_name'],
                    'resource_groups': rg_result,
                    'storage_accounts': storage_result,
                    'key_vaults': kv_result,
                    'all_resources': resources_result
                }
                
                # Analyze for security findings
                self._analyze_security_findings(results['security_findings'], sub_id, {
                    'storage_accounts': storage_result,
                    'key_vaults': kv_result,
                    'resources': resources_result
                })
            
            # Generate summary
            results['summary'] = self._generate_summary(results)
            
            return results
            
        except Exception as e:
            logger.error(f"Comprehensive ARM enumeration failed: {e}")
            return {'error': str(e)}
    
    def _analyze_security_findings(self, findings: List[str], subscription_id: str, data: Dict[str, Any]):
        """Analyze resources for security findings"""
        # Check storage accounts
        storage_accounts = data.get('storage_accounts', {}).get('storage_accounts', [])
        for account in storage_accounts:
            if not account.get('https_traffic_only', True):
                findings.append(f"Storage account {account['name']} allows HTTP traffic")
            
            if account.get('allow_blob_public_access') is True:
                findings.append(f"Storage account {account['name']} allows public blob access")
        
        # Check Key Vaults
        key_vaults = data.get('key_vaults', {}).get('key_vaults', [])
        for vault in key_vaults:
            if vault.get('enabled_for_deployment'):
                findings.append(f"Key Vault {vault['name']} enabled for VM deployment")
    
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary of ARM enumeration results"""
        summary = {
            'subscription_count': 0,
            'total_resource_groups': 0,
            'total_storage_accounts': 0,
            'total_key_vaults': 0,
            'total_resources': 0,
            'security_findings_count': len(results.get('security_findings', [])),
            'top_resource_types': {}
        }
        
        subscriptions = results.get('subscriptions', {}).get('subscriptions', [])
        summary['subscription_count'] = len(subscriptions)
        
        # Aggregate counts across subscriptions
        resource_type_counts = {}
        
        for sub_data in results.get('resource_summary', {}).values():
            summary['total_resource_groups'] += sub_data.get('resource_groups', {}).get('count', 0)
            summary['total_storage_accounts'] += sub_data.get('storage_accounts', {}).get('count', 0)
            summary['total_key_vaults'] += sub_data.get('key_vaults', {}).get('count', 0)
            
            resources = sub_data.get('all_resources', {}).get('resources', [])
            summary['total_resources'] += len(resources)
            
            # Count resource types
            for resource in resources:
                resource_type = resource.get('type', 'Unknown')
                resource_type_counts[resource_type] = resource_type_counts.get(resource_type, 0) + 1
        
        # Get top 5 resource types
        sorted_types = sorted(resource_type_counts.items(), key=lambda x: x[1], reverse=True)
        summary['top_resource_types'] = dict(sorted_types[:5])
        
        return summary