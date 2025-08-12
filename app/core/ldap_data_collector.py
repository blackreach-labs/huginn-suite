# app/core/ldap_data_collector.py
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional
from .centralized_scan_data import centralized_scan_data

class LDAPDataCollector:
    """LDAP-specific data collector that feeds into centralized system"""
    
    def __init__(self, tenant_id: str = "default"):
        self.tenant_id = tenant_id
        self.scan_type = "ldap"
        self.current_scan_id = None
    
    def start_ldap_scan(self, target: str, scanner: str, scan_subtype: str = "enumeration") -> str:
        """Start a new LDAP scan session"""
        self.current_scan_id = f"ldap_{uuid.uuid4().hex[:8]}_{int(datetime.now().timestamp())}"
        
        centralized_scan_data.start_scan(
            scan_id=self.current_scan_id,
            tenant_id=self.tenant_id,
            scan_type=f"{self.scan_type}_{scan_subtype}",
            target=target,
            scanner=scanner
        )
        
        return self.current_scan_id
    
    def collect_server_info(self, target: str, server_info: Dict) -> bool:
        """Collect LDAP server information"""
        if not self.current_scan_id:
            return False
        
        result_data = {
            'type': 'ldap_server_info',
            'target': target,
            'accessible': server_info.get('accessible', False),
            'port': server_info.get('port', 389),
            'ssl': server_info.get('ssl', False),
            'server_name': server_info.get('server_info', {}).get('server_name', 'Unknown'),
            'ldap_version': server_info.get('server_info', {}).get('supported_ldap_version', '3'),
            'naming_contexts': server_info.get('naming_contexts', []),
            'error': server_info.get('error'),
            'timestamp': datetime.now().isoformat()
        }
        
        centralized_scan_data.add_scan_result(
            scan_id=self.current_scan_id,
            tenant_id=self.tenant_id,
            scan_type="ldap_server_info",
            target=target,
            scanner="ldap_server_scanner",
            result_data=result_data
        )
        
        return True
    
    def collect_users(self, target: str, users: List[Dict]) -> bool:
        """Collect LDAP user data"""
        if not self.current_scan_id:
            return False
        
        for user in users:
            result_data = {
                'type': 'ldap_user',
                'target': target,
                'cn': user.get('cn', 'Unknown'),
                'sam_account_name': user.get('sAMAccountName', ''),
                'user_principal_name': user.get('userPrincipalName', ''),
                'member_of': user.get('memberOf', []),
                'last_logon': user.get('lastLogon', ''),
                'pwd_last_set': user.get('pwdLastSet', ''),
                'service_principal_name': user.get('servicePrincipalName', []),
                'timestamp': datetime.now().isoformat()
            }
            
            centralized_scan_data.add_scan_result(
                scan_id=self.current_scan_id,
                tenant_id=self.tenant_id,
                scan_type="ldap_users",
                target=target,
                scanner="ldap_user_enumerator",
                result_data=result_data
            )
        
        return True
    
    def collect_groups(self, target: str, groups: List[Dict]) -> bool:
        """Collect LDAP group data"""
        if not self.current_scan_id:
            return False
        
        for group in groups:
            result_data = {
                'type': 'ldap_group',
                'target': target,
                'cn': group.get('cn', 'Unknown'),
                'description': group.get('description', ''),
                'members': group.get('members', []),
                'member_count': group.get('memberCount', 0),
                'timestamp': datetime.now().isoformat()
            }
            
            centralized_scan_data.add_scan_result(
                scan_id=self.current_scan_id,
                tenant_id=self.tenant_id,
                scan_type="ldap_groups",
                target=target,
                scanner="ldap_group_enumerator",
                result_data=result_data
            )
        
        return True
    
    def collect_computers(self, target: str, computers: List[Dict]) -> bool:
        """Collect LDAP computer data"""
        if not self.current_scan_id:
            return False
        
        for computer in computers:
            result_data = {
                'type': 'ldap_computer',
                'target': target,
                'cn': computer.get('cn', 'Unknown'),
                'dns_host_name': computer.get('dNSHostName', ''),
                'operating_system': computer.get('operatingSystem', ''),
                'operating_system_version': computer.get('operatingSystemVersion', ''),
                'last_logon_timestamp': computer.get('lastLogonTimestamp', ''),
                'service_principal_name': computer.get('servicePrincipalName', []),
                'timestamp': datetime.now().isoformat()
            }
            
            centralized_scan_data.add_scan_result(
                scan_id=self.current_scan_id,
                tenant_id=self.tenant_id,
                scan_type="ldap_computers",
                target=target,
                scanner="ldap_computer_enumerator",
                result_data=result_data
            )
        
        return True
    
    def collect_service_accounts(self, target: str, service_accounts: List[Dict]) -> bool:
        """Collect LDAP service account data"""
        if not self.current_scan_id:
            return False
        
        for account in service_accounts:
            result_data = {
                'type': 'ldap_service_account',
                'target': target,
                'cn': account.get('cn', 'Unknown'),
                'sam_account_name': account.get('sAMAccountName', ''),
                'user_principal_name': account.get('userPrincipalName', ''),
                'service_principal_name': account.get('servicePrincipalName', []),
                'member_of': account.get('memberOf', []),
                'timestamp': datetime.now().isoformat()
            }
            
            centralized_scan_data.add_scan_result(
                scan_id=self.current_scan_id,
                tenant_id=self.tenant_id,
                scan_type="ldap_service_accounts",
                target=target,
                scanner="ldap_service_account_detector",
                result_data=result_data
            )
        
        return True
    
    def collect_privileged_users(self, target: str, privileged_users: List[Dict]) -> bool:
        """Collect LDAP privileged user data"""
        if not self.current_scan_id:
            return False
        
        for user in privileged_users:
            result_data = {
                'type': 'ldap_privileged_user',
                'target': target,
                'cn': user.get('cn', 'Unknown'),
                'sam_account_name': user.get('sAMAccountName', ''),
                'user_principal_name': user.get('userPrincipalName', ''),
                'member_of': user.get('memberOf', []),
                'privilege_level': 'high',
                'timestamp': datetime.now().isoformat()
            }
            
            centralized_scan_data.add_scan_result(
                scan_id=self.current_scan_id,
                tenant_id=self.tenant_id,
                scan_type="ldap_privileged_users",
                target=target,
                scanner="ldap_privilege_analyzer",
                result_data=result_data
            )
        
        return True
    
    def complete_ldap_scan(self, total_results: int = 0, error_message: str = None) -> bool:
        """Complete the current LDAP scan"""
        if not self.current_scan_id:
            return False
        
        success = centralized_scan_data.complete_scan(
            scan_id=self.current_scan_id,
            total_results=total_results,
            error_message=error_message
        )
        
        self.current_scan_id = None
        return success
    
    def get_ldap_data_for_ui(self, scan_type: str, target: str = None) -> Dict:
        """Get LDAP data formatted for UI consumption"""
        raw_data = centralized_scan_data.get_scan_data(
            tenant_id=self.tenant_id,
            scan_type=scan_type,
            target=target
        )
        
        ui_data = {
            'table_data': [],
            'graph_data': {},
            'summary': centralized_scan_data.get_scan_summary(
                tenant_id=self.tenant_id,
                scan_type=scan_type
            )
        }
        
        if scan_type == "ldap_users":
            ui_data['table_data'] = [{
                'Username': item['data'].get('sam_account_name', 'Unknown'),
                'Display Name': item['data'].get('cn', 'Unknown'),
                'UPN': item['data'].get('user_principal_name', ''),
                'Last Logon': item['data'].get('last_logon', 'Never'),
                'First Seen': item['first_seen'],
                'Count': item['count']
            } for item in raw_data]
            
        elif scan_type == "ldap_groups":
            ui_data['table_data'] = [{
                'Group Name': item['data'].get('cn', 'Unknown'),
                'Description': item['data'].get('description', ''),
                'Member Count': item['data'].get('member_count', 0),
                'First Seen': item['first_seen'],
                'Count': item['count']
            } for item in raw_data]
            
        elif scan_type == "ldap_computers":
            ui_data['table_data'] = [{
                'Computer Name': item['data'].get('cn', 'Unknown'),
                'DNS Name': item['data'].get('dns_host_name', ''),
                'Operating System': item['data'].get('operating_system', 'Unknown'),
                'Last Logon': item['data'].get('last_logon_timestamp', 'Never'),
                'First Seen': item['first_seen'],
                'Count': item['count']
            } for item in raw_data]
        
        ui_data['graph_data'] = self._generate_ldap_graph_data(scan_type, raw_data)
        return ui_data
    
    def _generate_ldap_graph_data(self, scan_type: str, raw_data: List[Dict]) -> Dict:
        """Generate graph data for LDAP results"""
        if scan_type == "ldap_users":
            return {
                'LDAP Users': {
                    'count': len(raw_data),
                    'details': f"Total unique users",
                    'children': {
                        'Active Users': {
                            'count': len([item for item in raw_data if item['data'].get('last_logon') != 'Never']),
                            'details': "Users with recent logon"
                        },
                        'Service Accounts': {
                            'count': len([item for item in raw_data if 'svc_' in item['data'].get('sam_account_name', '').lower()]),
                            'details': "Identified service accounts"
                        }
                    }
                }
            }
        elif scan_type == "ldap_groups":
            return {
                'LDAP Groups': {
                    'count': len(raw_data),
                    'details': f"Total unique groups",
                    'children': {
                        'Administrative Groups': {
                            'count': len([item for item in raw_data if 'admin' in item['data'].get('cn', '').lower()]),
                            'details': "Administrative groups"
                        }
                    }
                }
            }
        
        return {}

def create_ldap_collector(tenant_id: str = "default") -> LDAPDataCollector:
    """Create LDAP data collector for specific tenant"""
    return LDAPDataCollector(tenant_id=tenant_id)