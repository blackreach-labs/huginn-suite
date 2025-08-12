# app/core/ssh_banner_parser.py
import re
import json
from typing import List, Dict, Optional

class SSHBannerParser:
    """SSH banner analysis and vulnerability detection"""
    
    def __init__(self):
        self.vulnerability_db = self._load_vulnerability_database()
        self.software_patterns = self._load_software_patterns()
    
    def analyze_banner(self, banner: str) -> List[Dict]:
        """Analyze SSH banner for vulnerabilities and information"""
        if not banner:
            return []
        
        results = []
        
        # Parse banner components
        banner_info = self._parse_banner(banner)
        if not banner_info:
            return []
        
        # Check for known vulnerabilities
        vulnerabilities = self._check_vulnerabilities(banner_info)
        results.extend(vulnerabilities)
        
        # Analyze software version
        software_info = self._analyze_software(banner_info)
        if software_info:
            results.append(software_info)
        
        # Check for configuration issues
        config_issues = self._check_configuration_issues(banner_info)
        results.extend(config_issues)
        
        return results
    
    def _parse_banner(self, banner: str) -> Optional[Dict]:
        """Parse SSH banner into components"""
        try:
            # SSH banner format: SSH-<protocol_version>-<software_version> [comments]
            banner = banner.strip()
            
            if not banner.startswith('SSH-'):
                return None
            
            # Remove SSH- prefix
            banner_parts = banner[4:].split('-', 2)
            
            if len(banner_parts) < 2:
                return None
            
            protocol_version = banner_parts[0]
            software_version = banner_parts[1]
            comments = banner_parts[2] if len(banner_parts) > 2 else ""
            
            # Extract software name and version
            software_match = re.match(r'([^_\s]+)(?:[_\s]([^_\s]+))?', software_version)
            
            if software_match:
                software_name = software_match.group(1)
                version = software_match.group(2) if software_match.group(2) else ""
            else:
                software_name = software_version
                version = ""
            
            return {
                'full_banner': banner,
                'protocol_version': protocol_version,
                'software_name': software_name.lower(),
                'software_version': software_version,
                'version': version,
                'comments': comments
            }
            
        except Exception:
            return None
    
    def _check_vulnerabilities(self, banner_info: Dict) -> List[Dict]:
        """Check for known vulnerabilities based on banner"""
        vulnerabilities = []
        
        software_name = banner_info['software_name']
        version = banner_info['version']
        
        # Check against vulnerability database
        for vuln in self.vulnerability_db:
            if self._matches_vulnerability(banner_info, vuln):
                vulnerabilities.append({
                    'type': 'vulnerability',
                    'cve': vuln['cve'],
                    'description': vuln['description'],
                    'severity': vuln['severity'],
                    'affected_versions': vuln['affected_versions'],
                    'references': vuln.get('references', [])
                })
        
        return vulnerabilities
    
    def _matches_vulnerability(self, banner_info: Dict, vuln: Dict) -> bool:
        """Check if banner matches vulnerability criteria"""
        software_name = banner_info['software_name']
        version = banner_info['version']
        
        # Check software name match
        if vuln['software'].lower() not in software_name:
            return False
        
        # Check version range if specified
        if 'version_range' in vuln and version:
            return self._version_in_range(version, vuln['version_range'])
        
        # Check affected versions list
        if 'affected_versions' in vuln and version:
            return any(self._version_matches_pattern(version, pattern) 
                      for pattern in vuln['affected_versions'])
        
        return True
    
    def _version_in_range(self, version: str, version_range: Dict) -> bool:
        """Check if version is in specified range"""
        try:
            # Simple version comparison (would need more sophisticated logic for production)
            min_version = version_range.get('min')
            max_version = version_range.get('max')
            
            if min_version and self._compare_versions(version, min_version) < 0:
                return False
            
            if max_version and self._compare_versions(version, max_version) > 0:
                return False
            
            return True
        except Exception:
            return False
    
    def _version_matches_pattern(self, version: str, pattern: str) -> bool:
        """Check if version matches pattern"""
        try:
            # Handle wildcards and ranges
            if '*' in pattern:
                pattern_regex = pattern.replace('*', '.*')
                return bool(re.match(pattern_regex, version))
            
            return version == pattern
        except Exception:
            return False
    
    def _compare_versions(self, v1: str, v2: str) -> int:
        """Compare two version strings"""
        try:
            # Simple version comparison
            v1_parts = [int(x) for x in v1.split('.') if x.isdigit()]
            v2_parts = [int(x) for x in v2.split('.') if x.isdigit()]
            
            # Pad shorter version with zeros
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            for i in range(max_len):
                if v1_parts[i] < v2_parts[i]:
                    return -1
                elif v1_parts[i] > v2_parts[i]:
                    return 1
            
            return 0
        except Exception:
            return 0
    
    def _analyze_software(self, banner_info: Dict) -> Optional[Dict]:
        """Analyze software information from banner"""
        software_name = banner_info['software_name']
        version = banner_info['version']
        
        # Check against known software patterns
        for pattern in self.software_patterns:
            if pattern['name'].lower() in software_name:
                return {
                    'type': 'software_info',
                    'software': pattern['display_name'],
                    'version': version,
                    'vendor': pattern['vendor'],
                    'description': pattern['description'],
                    'common_ports': pattern.get('common_ports', [22]),
                    'os_hints': pattern.get('os_hints', [])
                }
        
        return {
            'type': 'software_info',
            'software': software_name,
            'version': version,
            'vendor': 'Unknown',
            'description': 'SSH server software'
        }
    
    def _check_configuration_issues(self, banner_info: Dict) -> List[Dict]:
        """Check for configuration issues"""
        issues = []
        
        # Check protocol version
        if banner_info['protocol_version'] == '1.99':
            issues.append({
                'type': 'configuration_issue',
                'issue': 'SSH Protocol 1.99 Support',
                'description': 'Server supports deprecated SSH protocol 1.99',
                'severity': 'medium',
                'recommendation': 'Disable SSH protocol 1.x support'
            })
        elif banner_info['protocol_version'].startswith('1.'):
            issues.append({
                'type': 'configuration_issue',
                'issue': 'SSH Protocol 1.x Support',
                'description': 'Server supports deprecated SSH protocol 1.x',
                'severity': 'high',
                'recommendation': 'Upgrade to SSH protocol 2.0 only'
            })
        
        # Check for verbose banners (information disclosure)
        if len(banner_info['comments']) > 50:
            issues.append({
                'type': 'configuration_issue',
                'issue': 'Verbose SSH Banner',
                'description': 'SSH banner contains excessive information',
                'severity': 'low',
                'recommendation': 'Configure minimal SSH banner'
            })
        
        return issues
    
    def _load_vulnerability_database(self) -> List[Dict]:
        """Load SSH vulnerability database"""
        return [
            {
                'cve': 'CVE-2018-15473',
                'software': 'openssh',
                'description': 'Username enumeration via packet timing',
                'severity': 'medium',
                'affected_versions': ['7.7*', '7.6*', '7.5*', '7.4*'],
                'version_range': {'min': '2.3', 'max': '7.7'},
                'references': [
                    'https://nvd.nist.gov/vuln/detail/CVE-2018-15473'
                ]
            },
            {
                'cve': 'CVE-2016-0777',
                'software': 'openssh',
                'description': 'Information leak in roaming code',
                'severity': 'medium',
                'affected_versions': ['5.4*', '5.5*', '5.6*', '5.7*', '5.8*', '5.9*', '6.*', '7.0*'],
                'references': [
                    'https://nvd.nist.gov/vuln/detail/CVE-2016-0777'
                ]
            },
            {
                'cve': 'CVE-2016-0778',
                'software': 'openssh',
                'description': 'Buffer overflow in roaming code',
                'severity': 'high',
                'affected_versions': ['5.4*', '5.5*', '5.6*', '5.7*', '5.8*', '5.9*', '6.*', '7.0*'],
                'references': [
                    'https://nvd.nist.gov/vuln/detail/CVE-2016-0778'
                ]
            },
            {
                'cve': 'CVE-2015-5600',
                'software': 'openssh',
                'description': 'MaxAuthTries bypass via keyboard-interactive',
                'severity': 'medium',
                'affected_versions': ['6.8*', '6.9*'],
                'references': [
                    'https://nvd.nist.gov/vuln/detail/CVE-2015-5600'
                ]
            },
            {
                'cve': 'CVE-2014-2532',
                'software': 'openssh',
                'description': 'AcceptEnv environment restriction bypass',
                'severity': 'medium',
                'affected_versions': ['6.6*'],
                'references': [
                    'https://nvd.nist.gov/vuln/detail/CVE-2014-2532'
                ]
            },
            {
                'cve': 'CVE-2010-4478',
                'software': 'openssh',
                'description': 'Certificate validation bypass',
                'severity': 'medium',
                'affected_versions': ['5.6*', '5.7*'],
                'references': [
                    'https://nvd.nist.gov/vuln/detail/CVE-2010-4478'
                ]
            },
            {
                'cve': 'CVE-2008-5161',
                'software': 'openssh',
                'description': 'Local privilege escalation',
                'severity': 'high',
                'affected_versions': ['5.1*'],
                'references': [
                    'https://nvd.nist.gov/vuln/detail/CVE-2008-5161'
                ]
            },
            {
                'cve': 'CVE-2006-5051',
                'software': 'openssh',
                'description': 'Signal handler race condition',
                'severity': 'high',
                'affected_versions': ['4.3*', '4.4*', '4.5*'],
                'references': [
                    'https://nvd.nist.gov/vuln/detail/CVE-2006-5051'
                ]
            }
        ]
    
    def _load_software_patterns(self) -> List[Dict]:
        """Load SSH software identification patterns"""
        return [
            {
                'name': 'openssh',
                'display_name': 'OpenSSH',
                'vendor': 'OpenBSD Project',
                'description': 'OpenSSH secure shell server',
                'common_ports': [22],
                'os_hints': ['linux', 'unix', 'bsd']
            },
            {
                'name': 'libssh',
                'display_name': 'libssh',
                'vendor': 'libssh.org',
                'description': 'libssh SSH library',
                'common_ports': [22],
                'os_hints': ['linux', 'unix']
            },
            {
                'name': 'dropbear',
                'display_name': 'Dropbear SSH',
                'vendor': 'Matt Johnston',
                'description': 'Dropbear SSH server',
                'common_ports': [22],
                'os_hints': ['embedded', 'linux']
            },
            {
                'name': 'bitvise',
                'display_name': 'Bitvise SSH Server',
                'vendor': 'Bitvise Limited',
                'description': 'Bitvise SSH Server for Windows',
                'common_ports': [22],
                'os_hints': ['windows']
            },
            {
                'name': 'freesshd',
                'display_name': 'FreeSSHd',
                'vendor': 'FreeSSHd Team',
                'description': 'FreeSSHd SSH server for Windows',
                'common_ports': [22],
                'os_hints': ['windows']
            },
            {
                'name': 'cisco',
                'display_name': 'Cisco SSH',
                'vendor': 'Cisco Systems',
                'description': 'Cisco device SSH server',
                'common_ports': [22],
                'os_hints': ['cisco', 'ios']
            },
            {
                'name': 'sun_ssh',
                'display_name': 'Sun SSH',
                'vendor': 'Oracle/Sun',
                'description': 'Sun Microsystems SSH server',
                'common_ports': [22],
                'os_hints': ['solaris', 'sunos']
            }
        ]
    
    def extract_os_information(self, banner_info: Dict) -> Optional[Dict]:
        """Extract OS information from SSH banner"""
        if not banner_info:
            return None
        
        software_name = banner_info['software_name']
        comments = banner_info.get('comments', '').lower()
        
        # Check for OS hints in comments
        os_patterns = {
            'ubuntu': {'os': 'Ubuntu Linux', 'confidence': 'high'},
            'debian': {'os': 'Debian Linux', 'confidence': 'high'},
            'centos': {'os': 'CentOS Linux', 'confidence': 'high'},
            'redhat': {'os': 'Red Hat Linux', 'confidence': 'high'},
            'fedora': {'os': 'Fedora Linux', 'confidence': 'high'},
            'suse': {'os': 'SUSE Linux', 'confidence': 'high'},
            'freebsd': {'os': 'FreeBSD', 'confidence': 'high'},
            'openbsd': {'os': 'OpenBSD', 'confidence': 'high'},
            'netbsd': {'os': 'NetBSD', 'confidence': 'high'},
            'solaris': {'os': 'Solaris', 'confidence': 'high'},
            'aix': {'os': 'IBM AIX', 'confidence': 'high'},
            'hpux': {'os': 'HP-UX', 'confidence': 'high'}
        }
        
        for pattern, info in os_patterns.items():
            if pattern in comments:
                return {
                    'os': info['os'],
                    'confidence': info['confidence'],
                    'evidence': f'SSH banner comments: {comments[:50]}',
                    'method': 'ssh_banner'
                }
        
        # Check software-based OS hints
        if 'openssh' in software_name:
            return {
                'os': 'Linux/Unix',
                'confidence': 'medium',
                'evidence': 'OpenSSH typically runs on Unix-like systems',
                'method': 'ssh_software'
            }
        elif 'bitvise' in software_name or 'freesshd' in software_name:
            return {
                'os': 'Windows',
                'confidence': 'high',
                'evidence': f'SSH software: {software_name}',
                'method': 'ssh_software'
            }
        
        return None