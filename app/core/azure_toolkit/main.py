"""
Azure Toolkit Main Orchestration Module
Coordinates execution of various Azure enumeration modules.
"""

import argparse
import json
import logging
from typing import Dict, List, Optional, Any
from tabulate import tabulate
from .auth import AzureAuthenticator
from .ad_recon import AzureADRecon
from .arm_recon import AzureResourceRecon
from .storage_enum import AzureStorageEnum
from .dns_recon import AzureDNSRecon

logger = logging.getLogger(__name__)

class AzureToolkit:
    """Main Azure Tenant Enumeration Toolkit orchestrator"""
    
    def __init__(self):
        self.auth = AzureAuthenticator()
        self.ad_recon = AzureADRecon(self.auth)
        self.arm_recon = AzureResourceRecon(self.auth)
        self.storage_enum = AzureStorageEnum(self.auth)
        self.dns_recon = AzureDNSRecon()
        
    def run_dns_enumeration(self, domain: str) -> Dict[str, Any]:
        """Run DNS enumeration for Azure services"""
        logger.info(f"Starting DNS enumeration for domain: {domain}")
        return self.dns_recon.comprehensive_dns_enum(domain)
    
    def run_ad_enumeration(self, credential=None) -> Dict[str, Any]:
        """Run Azure AD enumeration"""
        logger.info("Starting Azure AD enumeration")
        return self.ad_recon.comprehensive_ad_enum(credential)
    
    def run_arm_enumeration(self, credential=None) -> Dict[str, Any]:
        """Run Azure Resource Manager enumeration"""
        logger.info("Starting Azure Resource Manager enumeration")
        return self.arm_recon.comprehensive_arm_enum(credential)
    
    def run_storage_enumeration(self, subscription_id: str, credential=None) -> Dict[str, Any]:
        """Run Azure Storage enumeration"""
        logger.info(f"Starting Azure Storage enumeration for subscription: {subscription_id}")
        return self.storage_enum.comprehensive_storage_enum(subscription_id, credential)
    
    def run_comprehensive_scan(self, domain: str = None, subscription_id: str = None, 
                             credential=None) -> Dict[str, Any]:
        """Run comprehensive Azure enumeration"""
        logger.info("Starting comprehensive Azure enumeration")
        
        results = {
            'scan_type': 'comprehensive',
            'timestamp': self._get_timestamp(),
            'dns_enumeration': {},
            'ad_enumeration': {},
            'arm_enumeration': {},
            'storage_enumeration': {},
            'summary': {}
        }
        
        # DNS enumeration (passive, no auth required)
        if domain:
            try:
                results['dns_enumeration'] = self.run_dns_enumeration(domain)
            except Exception as e:
                logger.error(f"DNS enumeration failed: {e}")
                results['dns_enumeration'] = {'error': str(e)}
        
        # Authenticated enumerations
        if credential:
            # Azure AD enumeration
            try:
                results['ad_enumeration'] = self.run_ad_enumeration(credential)
            except Exception as e:
                logger.error(f"AD enumeration failed: {e}")
                results['ad_enumeration'] = {'error': str(e)}
            
            # ARM enumeration
            try:
                results['arm_enumeration'] = self.run_arm_enumeration(credential)
            except Exception as e:
                logger.error(f"ARM enumeration failed: {e}")
                results['arm_enumeration'] = {'error': str(e)}
            
            # Storage enumeration (requires subscription ID)
            if subscription_id:
                try:
                    results['storage_enumeration'] = self.run_storage_enumeration(subscription_id, credential)
                except Exception as e:
                    logger.error(f"Storage enumeration failed: {e}")
                    results['storage_enumeration'] = {'error': str(e)}
        
        # Generate comprehensive summary
        results['summary'] = self._generate_comprehensive_summary(results)
        
        return results
    
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def _generate_comprehensive_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive summary of all enumeration results"""
        summary = {
            'scan_timestamp': results.get('timestamp'),
            'modules_executed': [],
            'total_findings': 0,
            'high_risk_findings': [],
            'medium_risk_findings': [],
            'low_risk_findings': [],
            'recommendations': [],
            'discovered_services': [],
            'statistics': {}
        }
        
        # DNS enumeration summary
        dns_results = results.get('dns_enumeration', {})
        if 'error' not in dns_results and dns_results:
            summary['modules_executed'].append('DNS Enumeration')
            dns_summary = dns_results.get('summary', {})
            
            if dns_summary.get('has_azure_tenant'):
                summary['low_risk_findings'].append("Azure AD tenant identified")
            
            discovered_services = dns_summary.get('discovered_services', 0)
            if discovered_services > 0:
                summary['low_risk_findings'].append(f"Discovered {discovered_services} Azure services via DNS")
                
            # Add high-value targets
            for target in dns_summary.get('high_value_targets', []):
                summary['discovered_services'].append({
                    'service': target['service_type'],
                    'domain': target['domain'],
                    'source': 'DNS'
                })
        
        # AD enumeration summary
        ad_results = results.get('ad_enumeration', {})
        if 'error' not in ad_results and ad_results:
            summary['modules_executed'].append('Azure AD Enumeration')
            ad_summary = ad_results.get('summary', {})
            
            user_count = ad_summary.get('user_count', 0)
            if user_count > 0:
                summary['medium_risk_findings'].append(f"Enumerated {user_count} Azure AD users")
            
            privileged_roles = ad_summary.get('privileged_roles', [])
            if privileged_roles:
                summary['high_risk_findings'].append(f"Found {len(privileged_roles)} privileged roles with members")
            
            summary['statistics']['ad_users'] = user_count
            summary['statistics']['ad_groups'] = ad_summary.get('group_count', 0)
            summary['statistics']['service_principals'] = ad_summary.get('service_principal_count', 0)
        
        # ARM enumeration summary
        arm_results = results.get('arm_enumeration', {})
        if 'error' not in arm_results and arm_results:
            summary['modules_executed'].append('Azure Resource Manager Enumeration')
            arm_summary = arm_results.get('summary', {})
            
            subscription_count = arm_summary.get('subscription_count', 0)
            if subscription_count > 0:
                summary['medium_risk_findings'].append(f"Access to {subscription_count} Azure subscriptions")
            
            storage_accounts = arm_summary.get('total_storage_accounts', 0)
            key_vaults = arm_summary.get('total_key_vaults', 0)
            
            if storage_accounts > 0:
                summary['discovered_services'].append({
                    'service': 'Storage Accounts',
                    'count': storage_accounts,
                    'source': 'ARM'
                })
            
            if key_vaults > 0:
                summary['discovered_services'].append({
                    'service': 'Key Vaults',
                    'count': key_vaults,
                    'source': 'ARM'
                })
            
            summary['statistics']['subscriptions'] = subscription_count
            summary['statistics']['resource_groups'] = arm_summary.get('total_resource_groups', 0)
            summary['statistics']['total_resources'] = arm_summary.get('total_resources', 0)
        
        # Storage enumeration summary
        storage_results = results.get('storage_enumeration', {})
        if 'error' not in storage_results and storage_results:
            summary['modules_executed'].append('Azure Storage Enumeration')
            storage_summary = storage_results.get('summary', {})
            
            public_containers = storage_summary.get('public_container_count', 0)
            if public_containers > 0:
                summary['high_risk_findings'].append(f"Found {public_containers} publicly accessible storage containers")
            
            sensitive_blobs = storage_summary.get('sensitive_blob_count', 0)
            if sensitive_blobs > 0:
                summary['medium_risk_findings'].append(f"Found {sensitive_blobs} potentially sensitive files")
            
            summary['statistics']['storage_accounts'] = storage_summary.get('storage_account_count', 0)
            summary['statistics']['containers'] = storage_summary.get('total_containers', 0)
            summary['statistics']['blobs'] = storage_summary.get('total_blobs', 0)
        
        # Generate recommendations
        if summary['high_risk_findings']:
            summary['recommendations'].append("Immediately review and secure publicly accessible resources")
        
        if any('privileged' in finding.lower() for finding in summary['high_risk_findings']):
            summary['recommendations'].append("Review privileged role assignments and implement least privilege")
        
        if summary['discovered_services']:
            summary['recommendations'].append("Conduct security assessment of all discovered Azure services")
        
        # Calculate total findings
        summary['total_findings'] = (
            len(summary['high_risk_findings']) +
            len(summary['medium_risk_findings']) +
            len(summary['low_risk_findings'])
        )
        
        return summary
    
    def format_results(self, results: Dict[str, Any], output_format: str = 'json') -> str:
        """Format results for output"""
        if output_format.lower() == 'json':
            return json.dumps(results, indent=2, default=str)
        
        elif output_format.lower() == 'table':
            return self._format_table_output(results)
        
        elif output_format.lower() == 'summary':
            return self._format_summary_output(results)
        
        else:
            return json.dumps(results, indent=2, default=str)
    
    def _format_table_output(self, results: Dict[str, Any]) -> str:
        """Format results as tables"""
        output = []
        
        # Summary table
        if 'summary' in results:
            summary = results['summary']
            summary_data = [
                ['Modules Executed', ', '.join(summary.get('modules_executed', []))],
                ['Total Findings', summary.get('total_findings', 0)],
                ['High Risk', len(summary.get('high_risk_findings', []))],
                ['Medium Risk', len(summary.get('medium_risk_findings', []))],
                ['Low Risk', len(summary.get('low_risk_findings', []))]
            ]
            
            output.append("SCAN SUMMARY")
            output.append("=" * 50)
            output.append(tabulate(summary_data, headers=['Metric', 'Value'], tablefmt='grid'))
            output.append("")
        
        # Discovered services table
        if 'summary' in results and 'discovered_services' in results['summary']:
            services = results['summary']['discovered_services']
            if services:
                output.append("DISCOVERED SERVICES")
                output.append("=" * 50)
                
                service_data = []
                for service in services:
                    service_data.append([
                        service.get('service', 'Unknown'),
                        service.get('domain', service.get('count', 'N/A')),
                        service.get('source', 'Unknown')
                    ])
                
                output.append(tabulate(service_data, headers=['Service', 'Domain/Count', 'Source'], tablefmt='grid'))
                output.append("")
        
        return "\n".join(output)
    
    def _format_summary_output(self, results: Dict[str, Any]) -> str:
        """Format results as executive summary"""
        if 'summary' not in results:
            return "No summary available"
        
        summary = results['summary']
        output = []
        
        output.append("AZURE ENUMERATION EXECUTIVE SUMMARY")
        output.append("=" * 60)
        output.append(f"Scan Date: {summary.get('scan_timestamp', 'Unknown')}")
        output.append(f"Modules: {', '.join(summary.get('modules_executed', []))}")
        output.append("")
        
        # Findings
        high_risk = summary.get('high_risk_findings', [])
        if high_risk:
            output.append("HIGH RISK FINDINGS:")
            for finding in high_risk:
                output.append(f"  • {finding}")
            output.append("")
        
        medium_risk = summary.get('medium_risk_findings', [])
        if medium_risk:
            output.append("MEDIUM RISK FINDINGS:")
            for finding in medium_risk:
                output.append(f"  • {finding}")
            output.append("")
        
        # Recommendations
        recommendations = summary.get('recommendations', [])
        if recommendations:
            output.append("RECOMMENDATIONS:")
            for rec in recommendations:
                output.append(f"  • {rec}")
            output.append("")
        
        # Statistics
        stats = summary.get('statistics', {})
        if stats:
            output.append("STATISTICS:")
            for key, value in stats.items():
                output.append(f"  {key.replace('_', ' ').title()}: {value}")
        
        return "\n".join(output)

def main():
    """Main function for command-line usage"""
    parser = argparse.ArgumentParser(description='Azure Tenant Enumeration Toolkit')
    parser.add_argument('--domain', help='Target domain for DNS enumeration')
    parser.add_argument('--subscription-id', help='Azure subscription ID for resource enumeration')
    parser.add_argument('--module', choices=['dns', 'ad', 'arm', 'storage', 'all'], 
                       default='all', help='Module to run')
    parser.add_argument('--format', choices=['json', 'table', 'summary'], 
                       default='json', help='Output format')
    parser.add_argument('--output', help='Output file path')
    parser.add_argument('--auth-method', choices=['default', 'interactive', 'client-secret'],
                       default='default', help='Authentication method')
    parser.add_argument('--tenant-id', help='Azure tenant ID (for client secret auth)')
    parser.add_argument('--client-id', help='Azure client ID (for client secret auth)')
    parser.add_argument('--client-secret', help='Azure client secret (for client secret auth)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Initialize toolkit
    toolkit = AzureToolkit()
    
    # Setup authentication
    credential = None
    if args.auth_method == 'interactive':
        credential = toolkit.auth.get_interactive_credential()
    elif args.auth_method == 'client-secret':
        if not all([args.tenant_id, args.client_id, args.client_secret]):
            print("Error: Client secret authentication requires --tenant-id, --client-id, and --client-secret")
            return 1
        credential = toolkit.auth.get_client_secret_credential(
            args.tenant_id, args.client_id, args.client_secret
        )
    else:
        credential = toolkit.auth.get_default_credential()
    
    # Run enumeration
    try:
        if args.module == 'dns':
            if not args.domain:
                print("Error: DNS enumeration requires --domain")
                return 1
            results = toolkit.run_dns_enumeration(args.domain)
        
        elif args.module == 'ad':
            results = toolkit.run_ad_enumeration(credential)
        
        elif args.module == 'arm':
            results = toolkit.run_arm_enumeration(credential)
        
        elif args.module == 'storage':
            if not args.subscription_id:
                print("Error: Storage enumeration requires --subscription-id")
                return 1
            results = toolkit.run_storage_enumeration(args.subscription_id, credential)
        
        else:  # all
            results = toolkit.run_comprehensive_scan(args.domain, args.subscription_id, credential)
        
        # Format and output results
        formatted_output = toolkit.format_results(results, args.format)
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(formatted_output)
            print(f"Results saved to {args.output}")
        else:
            print(formatted_output)
        
        return 0
        
    except Exception as e:
        logger.error(f"Enumeration failed: {e}")
        print(f"Error: {e}")
        return 1

if __name__ == '__main__':
    exit(main())