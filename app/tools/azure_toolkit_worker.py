"""
Azure Toolkit Worker for Enumeration Page Integration
"""

from PyQt6.QtCore import QObject, pyqtSignal
from app.core.base_worker import WorkerSignals
import logging

logger = logging.getLogger(__name__)

class AzureToolkitWorker(QObject):
    """Worker for Azure toolkit operations in enumeration page"""
    
    def __init__(self, module, domain=None, subscription_id=None, auth_method="Default Credential", 
                 tenant_id=None, client_id=None, client_secret=None):
        super().__init__()
        self.signals = WorkerSignals()
        self.module = module
        self.domain = domain
        self.subscription_id = subscription_id
        self.auth_method = auth_method
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        
    def run(self):
        try:
            from app.core.azure_toolkit import AzureToolkit
            
            self.signals.output.emit(f"<p style='color: #00BFFF;'>Starting Azure {self.module}...</p>")
            
            toolkit = AzureToolkit()
            
            # Setup authentication
            credential = None
            if self.auth_method == "Interactive Browser":
                credential = toolkit.auth.get_interactive_credential()
            elif self.auth_method == "Client Secret":
                if not all([self.tenant_id, self.client_id, self.client_secret]):
                    self.signals.output.emit("<p style='color: #FF6B6B;'>Client Secret authentication requires Tenant ID, Client ID, and Client Secret</p>")
                    return
                credential = toolkit.auth.get_client_secret_credential(
                    self.tenant_id, self.client_id, self.client_secret
                )
            else:
                credential = toolkit.auth.get_default_credential()
            
            # Run appropriate module
            if self.module == "DNS Enumeration":
                if not self.domain:
                    self.signals.output.emit("<p style='color: #FF6B6B;'>Domain required for DNS enumeration</p>")
                    return
                results = toolkit.run_dns_enumeration(self.domain)
                self.format_dns_results(results)
                
            elif self.module == "Azure AD":
                results = toolkit.run_ad_enumeration(credential)
                self.format_ad_results(results)
                
            elif self.module == "ARM Resources":
                results = toolkit.run_arm_enumeration(credential)
                self.format_arm_results(results)
                
            elif self.module == "Storage":
                if not self.subscription_id:
                    self.signals.output.emit("<p style='color: #FF6B6B;'>Subscription ID required for storage enumeration</p>")
                    return
                results = toolkit.run_storage_enumeration(self.subscription_id, credential)
                self.format_storage_results(results)
                
            elif self.module == "Comprehensive":
                results = toolkit.run_comprehensive_scan(self.domain, self.subscription_id, credential)
                self.format_comprehensive_results(results)
            
            self.signals.finished.emit()
            
        except Exception as e:
            logger.error(f"Azure toolkit operation failed: {e}")
            self.signals.output.emit(f"<p style='color: #FF6B6B;'>Error: {str(e)}</p>")
            self.signals.error.emit(str(e))
    
    def format_dns_results(self, results):
        """Format DNS enumeration results"""
        if 'error' in results:
            self.signals.output.emit(f"<p style='color: #FF6B6B;'>DNS Error: {results['error']}</p>")
            return
        
        summary = results.get('summary', {})
        
        if summary.get('has_azure_tenant'):
            self.signals.output.emit("<p style='color: #00FF41;'>✓ Azure AD tenant confirmed</p>")
        
        discovered_services = summary.get('discovered_services', 0)
        if discovered_services > 0:
            self.signals.output.emit(f"<p style='color: #00FF41;'>Found {discovered_services} Azure services</p>")
            
            high_value_targets = summary.get('high_value_targets', [])
            for target in high_value_targets:
                service_type = target.get('service_type', 'Unknown')
                domain = target.get('domain', 'Unknown')
                self.signals.output.emit(f"<p style='color: #FFAA00;'>  • {service_type}: {domain}</p>")
    
    def format_ad_results(self, results):
        """Format Azure AD results"""
        if 'error' in results:
            self.signals.output.emit(f"<p style='color: #FF6B6B;'>AD Error: {results['error']}</p>")
            return
        
        summary = results.get('summary', {})
        
        tenant_name = summary.get('tenant_name', 'Unknown')
        user_count = summary.get('user_count', 0)
        
        self.signals.output.emit(f"<p style='color: #00FF41;'>Tenant: {tenant_name}</p>")
        if user_count > 0:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>Users enumerated: {user_count}</p>")
        
        privileged_roles = summary.get('privileged_roles', [])
        if privileged_roles:
            self.signals.output.emit(f"<p style='color: #FF6B6B;'>⚠️ Privileged roles: {len(privileged_roles)}</p>")
    
    def format_arm_results(self, results):
        """Format ARM results"""
        if 'error' in results:
            self.signals.output.emit(f"<p style='color: #FF6B6B;'>ARM Error: {results['error']}</p>")
            return
        
        summary = results.get('summary', {})
        
        subscription_count = summary.get('subscription_count', 0)
        if subscription_count > 0:
            self.signals.output.emit(f"<p style='color: #00FF41;'>Subscriptions: {subscription_count}</p>")
        
        storage_accounts = summary.get('total_storage_accounts', 0)
        key_vaults = summary.get('total_key_vaults', 0)
        
        if storage_accounts > 0:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>Storage Accounts: {storage_accounts}</p>")
        if key_vaults > 0:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>Key Vaults: {key_vaults}</p>")
    
    def format_storage_results(self, results):
        """Format storage results"""
        if 'error' in results:
            self.signals.output.emit(f"<p style='color: #FF6B6B;'>Storage Error: {results['error']}</p>")
            return
        
        summary = results.get('summary', {})
        
        account_count = summary.get('storage_account_count', 0)
        public_containers = summary.get('public_container_count', 0)
        sensitive_blobs = summary.get('sensitive_blob_count', 0)
        
        if account_count > 0:
            self.signals.output.emit(f"<p style='color: #00FF41;'>Storage Accounts: {account_count}</p>")
        
        if public_containers > 0:
            self.signals.output.emit(f"<p style='color: #FF6B6B;'>🚨 Public Containers: {public_containers}</p>")
        
        if sensitive_blobs > 0:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>⚠️ Sensitive Files: {sensitive_blobs}</p>")
    
    def format_comprehensive_results(self, results):
        """Format comprehensive results"""
        summary = results.get('summary', {})
        
        high_risk = summary.get('high_risk_findings', [])
        medium_risk = summary.get('medium_risk_findings', [])
        
        if high_risk:
            self.signals.output.emit(f"<p style='color: #FF6B6B;'>🔴 HIGH RISK ({len(high_risk)}):</p>")
            for finding in high_risk:
                self.signals.output.emit(f"<p style='color: #FF6B6B;'>  • {finding}</p>")
        
        if medium_risk:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>🟡 MEDIUM RISK ({len(medium_risk)}):</p>")
            for finding in medium_risk:
                self.signals.output.emit(f"<p style='color: #FFAA00;'>  • {finding}</p>")
        
        recommendations = summary.get('recommendations', [])
        if recommendations:
            self.signals.output.emit("<p style='color: #87CEEB;'>💡 RECOMMENDATIONS:</p>")
            for rec in recommendations:
                self.signals.output.emit(f"<p style='color: #87CEEB;'>  • {rec}</p>")