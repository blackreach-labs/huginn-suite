"""
Version CVE Mapper - Maps software versions to known CVEs
"""
import re
from typing import Dict, List, Any

class VersionCVEMapper:
    def __init__(self):
        # Embedded CVE data for common software
        self.cve_data = {
            'nginx': {
                '1.18.0': ['CVE-2019-20372'],
                '1.17.0': ['CVE-2019-20372'],
                '1.16.0': ['CVE-2019-9511', 'CVE-2019-9513'],
                '1.15.0': ['CVE-2019-9511', 'CVE-2019-9513'],
                '1.14.0': ['CVE-2018-16843', 'CVE-2018-16844']
            },
            'apache': {
                '2.4.41': ['CVE-2019-10081', 'CVE-2019-10082'],
                '2.4.39': ['CVE-2019-0196', 'CVE-2019-0197'],
                '2.4.38': ['CVE-2018-17199', 'CVE-2018-17189'],
                '2.4.37': ['CVE-2018-11763']
            },
            'php': {
                '7.3.0': ['CVE-2019-11036', 'CVE-2019-11034'],
                '7.2.0': ['CVE-2018-19935', 'CVE-2018-20783'],
                '7.1.0': ['CVE-2017-9224', 'CVE-2017-9226'],
                '5.6.40': ['CVE-2019-11036', 'CVE-2018-19935']
            },
            'mysql': {
                '8.0.15': ['CVE-2019-2534', 'CVE-2019-2529'],
                '5.7.25': ['CVE-2019-2534', 'CVE-2019-2529'],
                '5.6.43': ['CVE-2019-2534', 'CVE-2019-2529']
            }
        }
        
        # Latest safe versions
        self.latest_versions = {
            'nginx': '1.24.0',
            'apache': '2.4.57',
            'php': '8.2.0',
            'mysql': '8.0.33',
            'postgresql': '15.3',
            'redis': '7.0.11',
            'mongodb': '6.0.6'
        }

    def analyze_versions(self, headers: Dict[str, str], content: str) -> Dict[str, Any]:
        """Analyze headers and content for version information and CVEs"""
        results = {
            'detected_software': {},
            'cve_findings': [],
            'outdated_software': []
        }
        
        # Extract versions from headers
        server_header = headers.get('Server', '')
        powered_by = headers.get('X-Powered-By', '')
        
        # Parse server header
        if server_header:
            self._parse_server_header(server_header, results)
        
        # Parse X-Powered-By header
        if powered_by:
            self._parse_powered_by(powered_by, results)
        
        # Parse content for version info
        self._parse_content_versions(content, results)
        
        return results
    
    def _parse_server_header(self, server_header: str, results: Dict[str, Any]):
        """Parse Server header for version information"""
        patterns = [
            (r'nginx/(\d+\.\d+\.\d+)', 'nginx'),
            (r'Apache/(\d+\.\d+\.\d+)', 'apache'),
            (r'Microsoft-IIS/(\d+\.\d+)', 'iis')
        ]
        
        for pattern, software in patterns:
            match = re.search(pattern, server_header, re.IGNORECASE)
            if match:
                version = match.group(1)
                results['detected_software'][software] = version
                self._check_cves(software, version, results)
                self._check_outdated(software, version, results)
    
    def _parse_powered_by(self, powered_by: str, results: Dict[str, Any]):
        """Parse X-Powered-By header for version information"""
        patterns = [
            (r'PHP/(\d+\.\d+\.\d+)', 'php'),
            (r'ASP\.NET', 'aspnet')
        ]
        
        for pattern, software in patterns:
            match = re.search(pattern, powered_by, re.IGNORECASE)
            if match:
                if software == 'aspnet':
                    results['detected_software'][software] = 'detected'
                else:
                    version = match.group(1)
                    results['detected_software'][software] = version
                    self._check_cves(software, version, results)
                    self._check_outdated(software, version, results)
    
    def _parse_content_versions(self, content: str, results: Dict[str, Any]):
        """Parse content for version information"""
        patterns = [
            (r'WordPress (\d+\.\d+\.\d+)', 'wordpress'),
            (r'Joomla! (\d+\.\d+\.\d+)', 'joomla'),
            (r'Drupal (\d+\.\d+)', 'drupal'),
            (r'jQuery v(\d+\.\d+\.\d+)', 'jquery')
        ]
        
        for pattern, software in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                version = match.group(1)
                results['detected_software'][software] = version
                # Note: Would need CVE data for these in production
    
    def _check_cves(self, software: str, version: str, results: Dict[str, Any]):
        """Check if software version has known CVEs"""
        if software in self.cve_data and version in self.cve_data[software]:
            for cve in self.cve_data[software][version]:
                results['cve_findings'].append({
                    'type': 'Known CVE',
                    'severity': 'HIGH',
                    'description': f'{software} {version} has known vulnerability {cve}',
                    'cve': cve,
                    'software': software,
                    'version': version
                })
    
    def _check_outdated(self, software: str, version: str, results: Dict[str, Any]):
        """Check if software version is outdated"""
        if software in self.latest_versions:
            latest = self.latest_versions[software]
            if self._is_version_older(version, latest):
                results['outdated_software'].append({
                    'type': 'Outdated Software',
                    'severity': 'MEDIUM',
                    'description': f'{software} {version} is outdated (latest safe: {latest})',
                    'software': software,
                    'current_version': version,
                    'latest_version': latest
                })
    
    def _is_version_older(self, current: str, latest: str) -> bool:
        """Simple version comparison"""
        try:
            current_parts = [int(x) for x in current.split('.')]
            latest_parts = [int(x) for x in latest.split('.')]
            
            # Pad shorter version with zeros
            max_len = max(len(current_parts), len(latest_parts))
            current_parts.extend([0] * (max_len - len(current_parts)))
            latest_parts.extend([0] * (max_len - len(latest_parts)))
            
            return current_parts < latest_parts
        except ValueError:
            return False