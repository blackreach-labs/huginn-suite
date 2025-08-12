import asyncio
import aiohttp
import json
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
import re

class OSINTCollector:
    """Open Source Intelligence gathering for targets"""
    
    def __init__(self):
        self.collected_data = {}
        self.sources = {
            'certificate_transparency': self._collect_ct_data,
            'dns_records': self._collect_dns_data,
            'subdomain_enum': self._collect_subdomains,
            'technology_stack': self._collect_tech_stack,
            'social_media': self._collect_social_media
        }
    
    async def collect_intelligence(self, target: str) -> Dict[str, Any]:
        """Collect comprehensive OSINT data for target"""
        domain = self._extract_domain(target)
        intelligence = {
            'target': target,
            'domain': domain,
            'collection_timestamp': asyncio.get_event_loop().time(),
            'data': {}
        }
        
        # Collect from all sources
        for source_name, collector_func in self.sources.items():
            try:
                data = await collector_func(domain)
                intelligence['data'][source_name] = data
            except Exception as e:
                intelligence['data'][source_name] = {'error': str(e)}
        
        return intelligence
    
    async def _collect_ct_data(self, domain: str) -> Dict[str, Any]:
        """Collect Certificate Transparency data"""
        ct_data = {
            'certificates': [],
            'subdomains': set(),
            'issuers': set()
        }
        
        # Simulate CT log search (in production, use real CT APIs)
        common_subdomains = [
            f'www.{domain}', f'mail.{domain}', f'ftp.{domain}',
            f'admin.{domain}', f'api.{domain}', f'dev.{domain}',
            f'staging.{domain}', f'test.{domain}'
        ]
        
        for subdomain in common_subdomains:
            ct_data['subdomains'].add(subdomain)
        
        ct_data['subdomains'] = list(ct_data['subdomains'])
        ct_data['issuers'] = ['Let\'s Encrypt', 'DigiCert', 'Cloudflare']
        
        return ct_data
    
    async def _collect_dns_data(self, domain: str) -> Dict[str, Any]:
        """Collect DNS record information"""
        dns_data = {
            'a_records': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': [],
            'cname_records': []
        }
        
        # Simulate DNS lookups (in production, use real DNS queries)
        dns_data['a_records'] = ['192.168.1.100', '10.0.0.1']
        dns_data['mx_records'] = [f'mail.{domain}', f'mail2.{domain}']
        dns_data['ns_records'] = [f'ns1.{domain}', f'ns2.{domain}']
        dns_data['txt_records'] = ['v=spf1 include:_spf.google.com ~all']
        
        return dns_data
    
    async def _collect_subdomains(self, domain: str) -> Dict[str, Any]:
        """Enumerate subdomains using various techniques"""
        subdomains = {
            'discovered': [],
            'sources': ['certificate_transparency', 'dns_bruteforce', 'search_engines'],
            'total_count': 0
        }
        
        # Common subdomain wordlist
        common_subs = [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'staging',
            'test', 'blog', 'shop', 'portal', 'secure', 'vpn',
            'remote', 'support', 'help', 'docs', 'cdn', 'static'
        ]
        
        for sub in common_subs:
            subdomains['discovered'].append(f'{sub}.{domain}')
        
        subdomains['total_count'] = len(subdomains['discovered'])
        return subdomains
    
    async def _collect_tech_stack(self, domain: str) -> Dict[str, Any]:
        """Identify technology stack"""
        tech_stack = {
            'web_servers': [],
            'frameworks': [],
            'cms': [],
            'analytics': [],
            'cdn': [],
            'confidence_scores': {}
        }
        
        # Simulate technology detection
        tech_stack['web_servers'] = ['Apache/2.4.63', 'nginx/1.18.0']
        tech_stack['frameworks'] = ['PHP/7.4', 'jQuery/3.6.0']
        tech_stack['cms'] = ['WordPress/5.8']
        tech_stack['analytics'] = ['Google Analytics']
        tech_stack['cdn'] = ['Cloudflare']
        
        tech_stack['confidence_scores'] = {
            'Apache': 0.95,
            'PHP': 0.90,
            'WordPress': 0.85
        }
        
        return tech_stack
    
    async def _collect_social_media(self, domain: str) -> Dict[str, Any]:
        """Collect social media presence"""
        social_data = {
            'platforms': {},
            'mentions': [],
            'employees': []
        }
        
        # Common social media platforms
        platforms = ['twitter', 'linkedin', 'facebook', 'instagram', 'github']
        company_name = domain.split('.')[0]
        
        for platform in platforms:
            social_data['platforms'][platform] = {
                'url': f'https://{platform}.com/{company_name}',
                'verified': False,
                'followers': 0
            }
        
        return social_data
    
    def _extract_domain(self, target: str) -> str:
        """Extract domain from URL or IP"""
        if target.startswith('http'):
            parsed = urlparse(target)
            return parsed.netloc
        else:
            # Remove protocol if present
            domain = target.replace('https://', '').replace('http://', '')
            # Remove path if present
            domain = domain.split('/')[0]
            # Remove port if present
            domain = domain.split(':')[0]
            return domain
    
    def generate_osint_report(self, intelligence: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive OSINT report"""
        data = intelligence.get('data', {})
        
        # Count total findings
        total_subdomains = len(data.get('subdomain_enum', {}).get('discovered', []))
        total_certificates = len(data.get('certificate_transparency', {}).get('certificates', []))
        total_technologies = sum(len(v) for v in data.get('technology_stack', {}).values() if isinstance(v, list))
        
        report = {
            'target': intelligence.get('target'),
            'domain': intelligence.get('domain'),
            'summary': {
                'subdomains_found': total_subdomains,
                'certificates_found': total_certificates,
                'technologies_identified': total_technologies,
                'data_sources': len(self.sources)
            },
            'attack_surface': {
                'subdomains': data.get('subdomain_enum', {}).get('discovered', [])[:10],
                'technologies': data.get('technology_stack', {}),
                'dns_records': data.get('dns_records', {})
            },
            'intelligence_value': self._calculate_intelligence_value(data)
        }
        
        return report
    
    def _calculate_intelligence_value(self, data: Dict) -> str:
        """Calculate intelligence gathering value"""
        score = 0
        
        # Score based on data collected
        if data.get('subdomain_enum', {}).get('total_count', 0) > 10:
            score += 3
        if len(data.get('technology_stack', {}).get('web_servers', [])) > 0:
            score += 2
        if len(data.get('certificate_transparency', {}).get('subdomains', [])) > 5:
            score += 2
        if len(data.get('social_media', {}).get('platforms', {})) > 3:
            score += 1
        
        if score >= 6:
            return 'HIGH'
        elif score >= 4:
            return 'MEDIUM'
        else:
            return 'LOW'