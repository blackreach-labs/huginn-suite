import asyncio
from urllib.parse import urlparse
from app.core.logger import logger

class VirtualHostScanner:
    """Test for virtual host attacks and subdomain enumeration"""
    
    def __init__(self):
        self.common_vhosts = [
            'admin', 'api', 'dev', 'test', 'staging', 'beta', 'demo', 'www',
            'mail', 'ftp', 'blog', 'shop', 'store', 'portal', 'app', 'mobile'
        ]
    
    async def test_vhost_attacks(self, session, target_url):
        """Test for virtual host bypass and subdomain discovery"""
        findings = []
        parsed = urlparse(target_url)
        base_domain = parsed.hostname
        
        if not base_domain:
            return findings
        
        # Test Host header injection
        host_injection_findings = await self._test_host_injection(session, target_url, base_domain)
        findings.extend(host_injection_findings)
        
        # Test virtual host discovery
        vhost_findings = await self._discover_virtual_hosts(session, target_url, base_domain)
        findings.extend(vhost_findings)
        
        return findings
    
    async def _test_host_injection(self, session, target_url, base_domain):
        """Test for Host header injection vulnerabilities"""
        findings = []
        malicious_hosts = [
            'evil.com',
            f'evil.{base_domain}',
            'localhost',
            '127.0.0.1'
        ]
        
        # Get baseline response
        try:
            async with session.get(target_url) as baseline_response:
                baseline_content = await baseline_response.text()
                baseline_status = baseline_response.status
        except Exception:
            return findings
        
        for malicious_host in malicious_hosts:
            try:
                headers = {'Host': malicious_host}
                async with session.get(target_url, headers=headers) as response:
                    content = await response.text()
                    
                    # Check if malicious host appears in response
                    if malicious_host in content and malicious_host not in baseline_content:
                        findings.append({
                            'type': 'Host Header Injection',
                            'severity': 'MEDIUM',
                            'description': f'Host header injection detected with {malicious_host}',
                            'malicious_host': malicious_host,
                            'evidence': f'Injected host appears in response content',
                            'recommendation': 'Validate Host header against whitelist of allowed domains'
                        })
                    
                    # Check for different response (potential virtual host)
                    elif response.status != baseline_status or len(content) != len(baseline_content):
                        findings.append({
                            'type': 'Virtual Host Response Difference',
                            'severity': 'INFO',
                            'description': f'Different response with Host: {malicious_host}',
                            'host_header': malicious_host,
                            'status_difference': f'{baseline_status} -> {response.status}',
                            'recommendation': 'Review virtual host configuration for information disclosure'
                        })
                        
                await asyncio.sleep(0.2)  # Rate limiting
                
            except Exception:
                continue
        
        return findings
    
    async def _discover_virtual_hosts(self, session, target_url, base_domain):
        """Discover virtual hosts through Host header manipulation"""
        findings = []
        discovered_vhosts = []
        
        # Get baseline response
        try:
            async with session.get(target_url) as baseline_response:
                baseline_status = baseline_response.status
                baseline_size = len(await baseline_response.text())
        except Exception:
            return findings
        
        for vhost in self.common_vhosts[:8]:  # Limit to avoid overwhelming
            test_host = f'{vhost}.{base_domain}'
            
            try:
                headers = {'Host': test_host}
                async with session.get(target_url, headers=headers) as response:
                    content = await response.text()
                    
                    # Check for significantly different response
                    if (response.status != baseline_status or 
                        abs(len(content) - baseline_size) > 100):
                        
                        discovered_vhosts.append({
                            'vhost': test_host,
                            'status': response.status,
                            'size': len(content),
                            'difference': 'status' if response.status != baseline_status else 'size'
                        })
                        
                await asyncio.sleep(0.1)  # Rate limiting
                
            except Exception:
                continue
        
        if discovered_vhosts:
            findings.append({
                'type': 'Virtual Host Discovery',
                'severity': 'INFO',
                'description': f'Discovered {len(discovered_vhosts)} potential virtual hosts',
                'discovered_vhosts': discovered_vhosts,
                'recommendation': 'Review discovered virtual hosts for additional attack surface'
            })
        
        return findings