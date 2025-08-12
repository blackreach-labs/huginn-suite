# app/core/cert_transparency.py
import requests
import json
import base64
from typing import Set, List, Dict, Callable
import re
from urllib.parse import quote

class CertificateTransparencyClient:
    """Certificate Transparency log client for subdomain discovery"""
    
    def __init__(self):
        self.ct_logs = [
            "https://crt.sh",
            "https://censys.io/api/v1/search/certificates",
            "https://api.certspotter.com/v1/issuances"
        ]
        self.timeout = 10
        self.max_results = 1000
    
    def search_certificates(self, domain: str, progress_callback: Callable = None) -> Dict:
        """Search Certificate Transparency logs for domain certificates"""
        
        results = {
            'subdomains': set(),
            'certificates': [],
            'sources': {},
            'stats': {}
        }
        
        try:
            # Search crt.sh (primary source)
            if progress_callback:
                progress_callback("Searching crt.sh...")
            
            crt_results = self._search_crtsh(domain)
            results['subdomains'].update(crt_results['subdomains'])
            results['certificates'].extend(crt_results['certificates'])
            results['sources']['crt.sh'] = len(crt_results['certificates'])
            
            # Search Certspotter (backup source)
            if progress_callback:
                progress_callback("Searching Certspotter...")
            
            certspotter_results = self._search_certspotter(domain)
            results['subdomains'].update(certspotter_results['subdomains'])
            results['certificates'].extend(certspotter_results['certificates'])
            results['sources']['certspotter'] = len(certspotter_results['certificates'])
            
            # Compile final results
            results['subdomains'] = sorted(list(results['subdomains']))
            results['stats'] = {
                'total_subdomains': len(results['subdomains']),
                'total_certificates': len(results['certificates']),
                'sources_used': len([s for s in results['sources'].values() if s > 0])
            }
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _search_crtsh(self, domain: str) -> Dict:
        """Search crt.sh Certificate Transparency log"""
        
        results = {'subdomains': set(), 'certificates': []}
        
        try:
            # Apply rate limiting
            try:
                from app.core.rate_limiter import rate_limiter
                rate_limiter.wait_if_needed('cert_transparency')
            except ImportError:
                pass
            
            # Get proxy settings
            proxies = {}
            try:
                from app.core.proxy_manager import proxy_manager
                proxies = proxy_manager.get_proxy_dict()
            except ImportError:
                pass
            
            # Search for certificates
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=self.timeout, proxies=proxies)
            
            if response.status_code == 200:
                certificates = response.json()
                
                for cert in certificates[:self.max_results]:
                    # Extract certificate info
                    cert_info = {
                        'id': cert.get('id'),
                        'issuer': cert.get('issuer_name', ''),
                        'common_name': cert.get('common_name', ''),
                        'name_value': cert.get('name_value', ''),
                        'not_before': cert.get('not_before', ''),
                        'not_after': cert.get('not_after', ''),
                        'source': 'crt.sh'
                    }
                    
                    results['certificates'].append(cert_info)
                    
                    # Extract subdomains from certificate
                    subdomains = self._extract_subdomains(cert_info['name_value'], domain)
                    results['subdomains'].update(subdomains)
                    
                    # Also check common name
                    if cert_info['common_name']:
                        cn_subdomains = self._extract_subdomains(cert_info['common_name'], domain)
                        results['subdomains'].update(cn_subdomains)
        
        except Exception:
            pass  # Fail silently for individual source failures
        
        return results
    
    def _search_certspotter(self, domain: str) -> Dict:
        """Search Certspotter Certificate Transparency API"""
        
        results = {'subdomains': set(), 'certificates': []}
        
        try:
            # Apply rate limiting
            try:
                from app.core.rate_limiter import rate_limiter
                rate_limiter.wait_if_needed('cert_transparency')
            except ImportError:
                pass
            
            # Get proxy settings
            proxies = {}
            try:
                from app.core.proxy_manager import proxy_manager
                proxies = proxy_manager.get_proxy_dict()
            except ImportError:
                pass
            
            # Search for certificates (free tier, no API key needed)
            url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
            response = requests.get(url, timeout=self.timeout, proxies=proxies)
            
            if response.status_code == 200:
                certificates = response.json()
                
                for cert in certificates[:100]:  # Limit for free tier
                    # Extract certificate info
                    cert_info = {
                        'id': cert.get('id'),
                        'issuer': cert.get('issuer', {}).get('name', ''),
                        'not_before': cert.get('not_before', ''),
                        'not_after': cert.get('not_after', ''),
                        'dns_names': cert.get('dns_names', []),
                        'source': 'certspotter'
                    }
                    
                    results['certificates'].append(cert_info)
                    
                    # Extract subdomains from DNS names
                    for dns_name in cert_info['dns_names']:
                        subdomains = self._extract_subdomains(dns_name, domain)
                        results['subdomains'].update(subdomains)
        
        except Exception:
            pass  # Fail silently for individual source failures
        
        return results
    
    def _extract_subdomains(self, cert_names: str, target_domain: str) -> Set[str]:
        """Extract valid subdomains from certificate names"""
        
        subdomains = set()
        
        if not cert_names:
            return subdomains
        
        # Handle multiple names (newline separated)
        names = cert_names.replace('\\n', '\n').split('\n')
        
        for name in names:
            name = name.strip().lower()
            
            # Skip wildcards and invalid entries
            if not name or name.startswith('*') or ' ' in name:
                continue
            
            # Check if it's a subdomain of target domain
            if name.endswith('.' + target_domain) or name == target_domain:
                # Validate domain format
                if self._is_valid_domain(name):
                    subdomains.add(name)
        
        return subdomains
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain format"""
        
        # Basic domain validation
        if not domain or len(domain) > 253:
            return False
        
        # Check for valid characters
        if not re.match(r'^[a-zA-Z0-9.-]+$', domain):
            return False
        
        # Check domain parts
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        for part in parts:
            if not part or len(part) > 63:
                return False
            if part.startswith('-') or part.endswith('-'):
                return False
        
        return True
    
    def get_certificate_details(self, cert_id: str, source: str = 'crt.sh') -> Dict:
        """Get detailed certificate information"""
        
        try:
            if source == 'crt.sh':
                url = f"https://crt.sh/?id={cert_id}&output=json"
                response = requests.get(url, timeout=self.timeout)
                
                if response.status_code == 200:
                    return response.json()
        
        except Exception:
            pass
        
        return {}

# Global instance
cert_transparency = CertificateTransparencyClient()