"""
Azure DNS Enumeration Module
Performs passive DNS enumeration to discover Azure-related domains.
"""

from typing import Dict, List, Optional, Any
import dns.resolver
import dns.exception
import logging
import re

logger = logging.getLogger(__name__)

class AzureDNSRecon:
    """Azure DNS reconnaissance and domain enumeration"""
    
    def __init__(self):
        self.azure_domains = [
            'onmicrosoft.com',
            'azurewebsites.net',
            'cloudapp.net',
            'cloudapp.azure.com',
            'azurecontainer.io',
            'database.windows.net',
            'documents.azure.com',
            'vault.azure.net',
            'servicebus.windows.net',
            'blob.core.windows.net',
            'file.core.windows.net',
            'queue.core.windows.net',
            'table.core.windows.net'
        ]
        
        self.common_subdomains = [
            'www', 'api', 'app', 'web', 'admin', 'portal', 'dashboard',
            'dev', 'test', 'staging', 'prod', 'production',
            'mail', 'email', 'smtp', 'ftp', 'sftp',
            'vpn', 'remote', 'access', 'login', 'auth',
            'cdn', 'static', 'assets', 'media', 'images'
        ]
    
    def enumerate_domains(self, domain: str) -> Dict[str, Any]:
        """Enumerate Azure-related domains for a given organization"""
        results = {
            'target_domain': domain,
            'azure_domains': [],
            'subdomains': [],
            'dns_records': {},
            'potential_services': []
        }
        
        # Extract organization name from domain
        org_name = domain.split('.')[0]
        
        # Check Azure-specific domains
        for azure_domain in self.azure_domains:
            azure_subdomain = f"{org_name}.{azure_domain}"
            if self._check_domain_exists(azure_subdomain):
                results['azure_domains'].append({
                    'domain': azure_subdomain,
                    'service_type': self._identify_service_type(azure_domain),
                    'records': self._get_dns_records(azure_subdomain)
                })
        
        # Enumerate common subdomains
        for subdomain in self.common_subdomains:
            full_domain = f"{subdomain}.{domain}"
            if self._check_domain_exists(full_domain):
                results['subdomains'].append({
                    'domain': full_domain,
                    'records': self._get_dns_records(full_domain)
                })
        
        # Get DNS records for main domain
        results['dns_records'] = self._get_dns_records(domain)
        
        # Identify potential Azure services
        results['potential_services'] = self._identify_azure_services(results)
        
        return results
    
    def _check_domain_exists(self, domain: str) -> bool:
        """Check if a domain exists by performing DNS lookup"""
        try:
            dns.resolver.resolve(domain, 'A')
            return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return False
        except Exception as e:
            logger.debug(f"DNS lookup failed for {domain}: {e}")
            return False
    
    def _get_dns_records(self, domain: str) -> Dict[str, List[str]]:
        """Get various DNS records for a domain"""
        records = {}
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [str(rdata) for rdata in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                continue
            except Exception as e:
                logger.debug(f"Failed to get {record_type} records for {domain}: {e}")
                continue
        
        return records
    
    def _identify_service_type(self, azure_domain: str) -> str:
        """Identify Azure service type based on domain"""
        service_mapping = {
            'onmicrosoft.com': 'Azure AD Tenant',
            'azurewebsites.net': 'App Service',
            'cloudapp.net': 'Cloud Service (Classic)',
            'cloudapp.azure.com': 'Virtual Machine',
            'azurecontainer.io': 'Container Instance',
            'database.windows.net': 'SQL Database',
            'documents.azure.com': 'Cosmos DB',
            'vault.azure.net': 'Key Vault',
            'servicebus.windows.net': 'Service Bus',
            'blob.core.windows.net': 'Blob Storage',
            'file.core.windows.net': 'File Storage',
            'queue.core.windows.net': 'Queue Storage',
            'table.core.windows.net': 'Table Storage'
        }
        
        return service_mapping.get(azure_domain, 'Unknown Azure Service')
    
    def _identify_azure_services(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify potential Azure services from DNS enumeration results"""
        services = []
        
        # Analyze Azure domains
        for azure_domain in results['azure_domains']:
            domain_name = azure_domain['domain']
            service_type = azure_domain['service_type']
            
            service_info = {
                'domain': domain_name,
                'service_type': service_type,
                'confidence': 'High',
                'evidence': f"Direct Azure domain match: {domain_name}"
            }
            
            # Add additional context based on service type
            if 'App Service' in service_type:
                service_info['potential_endpoints'] = [
                    f"https://{domain_name}",
                    f"https://{domain_name}.scm.azurewebsites.net"
                ]
            elif 'Storage' in service_type:
                service_info['potential_endpoints'] = [
                    f"https://{domain_name}"
                ]
            elif 'Key Vault' in service_type:
                service_info['potential_endpoints'] = [
                    f"https://{domain_name}"
                ]
            
            services.append(service_info)
        
        # Analyze CNAME records for Azure services
        all_domains = results['azure_domains'] + results['subdomains']
        for domain_info in all_domains:
            cname_records = domain_info.get('records', {}).get('CNAME', [])
            for cname in cname_records:
                if any(azure_domain in cname for azure_domain in self.azure_domains):
                    services.append({
                        'domain': domain_info['domain'],
                        'service_type': 'Azure Service (CNAME)',
                        'confidence': 'Medium',
                        'evidence': f"CNAME points to Azure: {cname}",
                        'target': cname
                    })
        
        return services
    
    def check_azure_tenant(self, domain: str) -> Dict[str, Any]:
        """Check if domain has an associated Azure AD tenant"""
        results = {
            'domain': domain,
            'has_azure_tenant': False,
            'tenant_info': {},
            'federation_info': {}
        }
        
        # Check for Azure AD tenant
        tenant_domain = f"{domain.split('.')[0]}.onmicrosoft.com"
        
        if self._check_domain_exists(tenant_domain):
            results['has_azure_tenant'] = True
            results['tenant_info']['tenant_domain'] = tenant_domain
            
            # Try to get additional tenant information via OpenID configuration
            try:
                import requests
                openid_url = f"https://login.microsoftonline.com/{tenant_domain}/v2.0/.well-known/openid-configuration"
                response = requests.get(openid_url, timeout=10)
                
                if response.status_code == 200:
                    openid_config = response.json()
                    results['tenant_info']['issuer'] = openid_config.get('issuer')
                    results['tenant_info']['authorization_endpoint'] = openid_config.get('authorization_endpoint')
                    results['tenant_info']['token_endpoint'] = openid_config.get('token_endpoint')
            
            except Exception as e:
                logger.debug(f"Failed to get OpenID configuration: {e}")
        
        # Check federation information
        try:
            import requests
            fed_url = f"https://login.microsoftonline.com/getuserrealm.srf?login=test@{domain}"
            response = requests.get(fed_url, timeout=10)
            
            if response.status_code == 200:
                fed_info = response.json()
                results['federation_info'] = {
                    'account_type': fed_info.get('account_type'),
                    'domain_name': fed_info.get('domain_name'),
                    'federation_protocol': fed_info.get('federation_protocol'),
                    'authentication_url': fed_info.get('authentication_url')
                }
        
        except Exception as e:
            logger.debug(f"Failed to get federation information: {e}")
        
        return results
    
    def enumerate_azure_subdomains(self, org_name: str) -> Dict[str, Any]:
        """Enumerate Azure subdomains for an organization"""
        results = {
            'organization': org_name,
            'discovered_services': [],
            'total_found': 0
        }
        
        # Common Azure service patterns
        service_patterns = [
            # App Services
            (f"{org_name}.azurewebsites.net", "App Service"),
            (f"{org_name}-api.azurewebsites.net", "API App Service"),
            (f"{org_name}-web.azurewebsites.net", "Web App Service"),
            (f"{org_name}-app.azurewebsites.net", "App Service"),
            
            # Storage Accounts
            (f"{org_name}.blob.core.windows.net", "Blob Storage"),
            (f"{org_name}storage.blob.core.windows.net", "Blob Storage"),
            (f"{org_name}data.blob.core.windows.net", "Blob Storage"),
            
            # Key Vaults
            (f"{org_name}.vault.azure.net", "Key Vault"),
            (f"{org_name}-kv.vault.azure.net", "Key Vault"),
            (f"{org_name}-vault.vault.azure.net", "Key Vault"),
            
            # Databases
            (f"{org_name}.database.windows.net", "SQL Database"),
            (f"{org_name}-db.database.windows.net", "SQL Database"),
            
            # Container Instances
            (f"{org_name}.azurecontainer.io", "Container Instance"),
            
            # Virtual Machines
            (f"{org_name}.cloudapp.azure.com", "Virtual Machine"),
            
            # Service Bus
            (f"{org_name}.servicebus.windows.net", "Service Bus")
        ]
        
        for domain, service_type in service_patterns:
            if self._check_domain_exists(domain):
                service_info = {
                    'domain': domain,
                    'service_type': service_type,
                    'records': self._get_dns_records(domain),
                    'potential_urls': self._generate_service_urls(domain, service_type)
                }
                
                results['discovered_services'].append(service_info)
        
        results['total_found'] = len(results['discovered_services'])
        
        return results
    
    def _generate_service_urls(self, domain: str, service_type: str) -> List[str]:
        """Generate potential URLs for discovered services"""
        urls = [f"https://{domain}"]
        
        if service_type == "App Service":
            # Add SCM endpoint
            scm_domain = domain.replace('.azurewebsites.net', '.scm.azurewebsites.net')
            urls.append(f"https://{scm_domain}")
        
        return urls
    
    def comprehensive_dns_enum(self, domain: str) -> Dict[str, Any]:
        """Perform comprehensive DNS enumeration for Azure services"""
        org_name = domain.split('.')[0]
        
        results = {
            'target_domain': domain,
            'organization': org_name,
            'domain_enumeration': self.enumerate_domains(domain),
            'azure_tenant_check': self.check_azure_tenant(domain),
            'azure_subdomains': self.enumerate_azure_subdomains(org_name),
            'summary': {}
        }
        
        # Generate summary
        results['summary'] = self._generate_dns_summary(results)
        
        return results
    
    def _generate_dns_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary of DNS enumeration results"""
        summary = {
            'total_azure_domains': len(results['domain_enumeration'].get('azure_domains', [])),
            'total_subdomains': len(results['domain_enumeration'].get('subdomains', [])),
            'has_azure_tenant': results['azure_tenant_check'].get('has_azure_tenant', False),
            'discovered_services': len(results['azure_subdomains'].get('discovered_services', [])),
            'service_types': [],
            'high_value_targets': []
        }
        
        # Collect service types
        all_services = (
            results['domain_enumeration'].get('potential_services', []) +
            results['azure_subdomains'].get('discovered_services', [])
        )
        
        service_types = set()
        for service in all_services:
            service_types.add(service.get('service_type', 'Unknown'))
        
        summary['service_types'] = list(service_types)
        
        # Identify high-value targets
        high_value_services = ['Key Vault', 'SQL Database', 'Blob Storage', 'App Service']
        for service in all_services:
            if any(hv_service in service.get('service_type', '') for hv_service in high_value_services):
                summary['high_value_targets'].append({
                    'domain': service.get('domain'),
                    'service_type': service.get('service_type'),
                    'urls': service.get('potential_urls', service.get('potential_endpoints', []))
                })
        
        return summary