"""
Azure AD Enumeration Module
Enumerates Azure Active Directory entities using Microsoft Graph API.
"""

from typing import Dict, List, Optional, Any
import requests
import logging
from .auth import AzureAuthenticator

logger = logging.getLogger(__name__)

class AzureADRecon:
    """Azure Active Directory reconnaissance and enumeration"""
    
    def __init__(self, authenticator: AzureAuthenticator = None):
        self.auth = authenticator or AzureAuthenticator()
        self.graph_base_url = "https://graph.microsoft.com/v1.0"
        
    def _make_graph_request(self, endpoint: str, token: str, params: Dict = None) -> Dict[str, Any]:
        """Make authenticated request to Microsoft Graph API"""
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        url = f"{self.graph_base_url}{endpoint}"
        
        try:
            response = requests.get(url, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Graph API request failed: {e}")
            return {'error': str(e)}
    
    def list_users(self, token: str, limit: int = 100) -> Dict[str, Any]:
        """List users in the tenant"""
        params = {'$top': limit, '$select': 'id,displayName,userPrincipalName,mail,jobTitle,department'}
        
        result = self._make_graph_request('/users', token, params)
        
        if 'error' in result:
            return result
        
        users = []
        for user in result.get('value', []):
            users.append({
                'id': user.get('id'),
                'displayName': user.get('displayName'),
                'userPrincipalName': user.get('userPrincipalName'),
                'mail': user.get('mail'),
                'jobTitle': user.get('jobTitle'),
                'department': user.get('department')
            })
        
        return {
            'users': users,
            'count': len(users),
            'nextLink': result.get('@odata.nextLink')
        }
    
    def list_groups(self, token: str, limit: int = 100) -> Dict[str, Any]:
        """List groups in the tenant"""
        params = {'$top': limit, '$select': 'id,displayName,description,groupTypes,securityEnabled'}
        
        result = self._make_graph_request('/groups', token, params)
        
        if 'error' in result:
            return result
        
        groups = []
        for group in result.get('value', []):
            groups.append({
                'id': group.get('id'),
                'displayName': group.get('displayName'),
                'description': group.get('description'),
                'groupTypes': group.get('groupTypes', []),
                'securityEnabled': group.get('securityEnabled'),
                'isSecurityGroup': group.get('securityEnabled') and not group.get('groupTypes')
            })
        
        return {
            'groups': groups,
            'count': len(groups),
            'nextLink': result.get('@odata.nextLink')
        }
    
    def list_service_principals(self, token: str, limit: int = 100) -> Dict[str, Any]:
        """List service principals in the tenant"""
        params = {'$top': limit, '$select': 'id,appId,displayName,servicePrincipalType,accountEnabled'}
        
        result = self._make_graph_request('/servicePrincipals', token, params)
        
        if 'error' in result:
            return result
        
        service_principals = []
        for sp in result.get('value', []):
            service_principals.append({
                'id': sp.get('id'),
                'appId': sp.get('appId'),
                'displayName': sp.get('displayName'),
                'servicePrincipalType': sp.get('servicePrincipalType'),
                'accountEnabled': sp.get('accountEnabled')
            })
        
        return {
            'servicePrincipals': service_principals,
            'count': len(service_principals),
            'nextLink': result.get('@odata.nextLink')
        }
    
    def list_roles_and_assignments(self, token: str) -> Dict[str, Any]:
        """List directory roles and their assignments"""
        # Get directory roles
        roles_result = self._make_graph_request('/directoryRoles', token)
        
        if 'error' in roles_result:
            return roles_result
        
        roles_with_members = []
        
        for role in roles_result.get('value', []):
            role_id = role.get('id')
            role_info = {
                'id': role_id,
                'displayName': role.get('displayName'),
                'description': role.get('description'),
                'members': []
            }
            
            # Get role members
            members_result = self._make_graph_request(f'/directoryRoles/{role_id}/members', token)
            
            if 'error' not in members_result:
                for member in members_result.get('value', []):
                    role_info['members'].append({
                        'id': member.get('id'),
                        'displayName': member.get('displayName'),
                        'userPrincipalName': member.get('userPrincipalName'),
                        'objectType': member.get('@odata.type', '').split('.')[-1]
                    })
            
            roles_with_members.append(role_info)
        
        return {
            'directoryRoles': roles_with_members,
            'count': len(roles_with_members)
        }
    
    def get_current_user(self, token: str) -> Dict[str, Any]:
        """Get current authenticated user information"""
        result = self._make_graph_request('/me', token)
        
        if 'error' in result:
            return result
        
        return {
            'id': result.get('id'),
            'displayName': result.get('displayName'),
            'userPrincipalName': result.get('userPrincipalName'),
            'mail': result.get('mail'),
            'jobTitle': result.get('jobTitle'),
            'department': result.get('department'),
            'officeLocation': result.get('officeLocation')
        }
    
    def get_user_groups(self, token: str, user_id: str = 'me') -> Dict[str, Any]:
        """Get groups for a specific user"""
        endpoint = f'/users/{user_id}/memberOf' if user_id != 'me' else '/me/memberOf'
        result = self._make_graph_request(endpoint, token)
        
        if 'error' in result:
            return result
        
        groups = []
        for group in result.get('value', []):
            groups.append({
                'id': group.get('id'),
                'displayName': group.get('displayName'),
                'description': group.get('description'),
                'objectType': group.get('@odata.type', '').split('.')[-1]
            })
        
        return {
            'groups': groups,
            'count': len(groups)
        }
    
    def list_applications(self, token: str, limit: int = 100) -> Dict[str, Any]:
        """List application registrations"""
        params = {'$top': limit, '$select': 'id,appId,displayName,createdDateTime,signInAudience'}
        
        result = self._make_graph_request('/applications', token, params)
        
        if 'error' in result:
            return result
        
        applications = []
        for app in result.get('value', []):
            applications.append({
                'id': app.get('id'),
                'appId': app.get('appId'),
                'displayName': app.get('displayName'),
                'createdDateTime': app.get('createdDateTime'),
                'signInAudience': app.get('signInAudience')
            })
        
        return {
            'applications': applications,
            'count': len(applications),
            'nextLink': result.get('@odata.nextLink')
        }
    
    def get_tenant_info(self, token: str) -> Dict[str, Any]:
        """Get tenant organization information"""
        result = self._make_graph_request('/organization', token)
        
        if 'error' in result:
            return result
        
        orgs = result.get('value', [])
        if not orgs:
            return {'error': 'No organization information found'}
        
        org = orgs[0]
        return {
            'id': org.get('id'),
            'displayName': org.get('displayName'),
            'verifiedDomains': org.get('verifiedDomains', []),
            'technicalNotificationMails': org.get('technicalNotificationMails', []),
            'country': org.get('countryLetterCode'),
            'createdDateTime': org.get('createdDateTime')
        }
    
    def search_users(self, token: str, search_term: str) -> Dict[str, Any]:
        """Search for users by display name or UPN"""
        params = {
            '$search': f'"displayName:{search_term}" OR "userPrincipalName:{search_term}"',
            '$select': 'id,displayName,userPrincipalName,mail'
        }
        
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
            'ConsistencyLevel': 'eventual'
        }
        
        try:
            response = requests.get(
                f"{self.graph_base_url}/users",
                headers=headers,
                params=params,
                timeout=30
            )
            response.raise_for_status()
            result = response.json()
            
            users = []
            for user in result.get('value', []):
                users.append({
                    'id': user.get('id'),
                    'displayName': user.get('displayName'),
                    'userPrincipalName': user.get('userPrincipalName'),
                    'mail': user.get('mail')
                })
            
            return {
                'users': users,
                'count': len(users)
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"User search failed: {e}")
            return {'error': str(e)}
    
    def comprehensive_ad_enum(self, credential=None) -> Dict[str, Any]:
        """Perform comprehensive Azure AD enumeration"""
        try:
            token = self.auth.get_graph_token(credential)
            
            results = {
                'tenant_info': self.get_tenant_info(token),
                'current_user': self.get_current_user(token),
                'user_groups': self.get_user_groups(token),
                'users': self.list_users(token, limit=50),
                'groups': self.list_groups(token, limit=50),
                'service_principals': self.list_service_principals(token, limit=50),
                'applications': self.list_applications(token, limit=50),
                'directory_roles': self.list_roles_and_assignments(token)
            }
            
            # Generate summary
            results['summary'] = self._generate_summary(results)
            
            return results
            
        except Exception as e:
            logger.error(f"Comprehensive AD enumeration failed: {e}")
            return {'error': str(e)}
    
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary of AD enumeration results"""
        summary = {
            'tenant_name': 'Unknown',
            'current_user_name': 'Unknown',
            'user_count': 0,
            'group_count': 0,
            'service_principal_count': 0,
            'application_count': 0,
            'directory_role_count': 0,
            'privileged_roles': [],
            'findings': []
        }
        
        # Extract tenant name
        tenant_info = results.get('tenant_info', {})
        if 'displayName' in tenant_info:
            summary['tenant_name'] = tenant_info['displayName']
        
        # Extract current user
        current_user = results.get('current_user', {})
        if 'displayName' in current_user:
            summary['current_user_name'] = current_user['displayName']
        
        # Count entities
        summary['user_count'] = results.get('users', {}).get('count', 0)
        summary['group_count'] = results.get('groups', {}).get('count', 0)
        summary['service_principal_count'] = results.get('service_principals', {}).get('count', 0)
        summary['application_count'] = results.get('applications', {}).get('count', 0)
        summary['directory_role_count'] = results.get('directory_roles', {}).get('count', 0)
        
        # Identify privileged roles
        privileged_role_names = [
            'Global Administrator', 'Privileged Role Administrator',
            'Security Administrator', 'User Administrator',
            'Application Administrator', 'Cloud Application Administrator'
        ]
        
        directory_roles = results.get('directory_roles', {}).get('directoryRoles', [])
        for role in directory_roles:
            if role.get('displayName') in privileged_role_names and role.get('members'):
                summary['privileged_roles'].append({
                    'role': role['displayName'],
                    'member_count': len(role['members'])
                })
        
        # Generate findings
        if summary['user_count'] > 0:
            summary['findings'].append(f"Enumerated {summary['user_count']} users")
        
        if summary['privileged_roles']:
            summary['findings'].append(f"Found {len(summary['privileged_roles'])} privileged roles with members")
        
        if summary['service_principal_count'] > 50:
            summary['findings'].append("High number of service principals detected")
        
        return summary