# app/core/ssh_audit_engine.py
import re
from typing import Dict, List, Optional, Tuple
from .ssh_protocol import SSHProtocol
from .ssh_banner_parser import SSHBannerParser

class SSHAuditEngine:
    """SSH security audit and compliance checking engine"""
    
    def __init__(self):
        self.ssh_protocol = SSHProtocol()
        self.banner_parser = SSHBannerParser()
        
        # Security baselines
        self.security_baselines = {
            'cis': self._load_cis_baseline(),
            'nist': self._load_nist_baseline(),
            'pci_dss': self._load_pci_dss_baseline(),
            'custom': self._load_custom_baseline()
        }
    
    def audit_ssh_server(self, target: str, port: int = 22, baseline: str = 'cis') -> Dict:
        """Perform comprehensive SSH server audit"""
        try:
            audit_results = {
                'target': target,
                'port': port,
                'baseline': baseline,
                'timestamp': time.time(),
                'overall_score': 0,
                'findings': [],
                'recommendations': [],
                'compliance_status': 'unknown'
            }
            
            # Get baseline rules
            rules = self.security_baselines.get(baseline, self.security_baselines['cis'])
            
            # Perform audit checks
            findings = []
            
            # 1. Banner and version analysis
            banner_findings = self._audit_banner(target, port, rules)
            findings.extend(banner_findings)
            
            # 2. Algorithm and cipher analysis
            crypto_findings = self._audit_cryptography(target, port, rules)
            findings.extend(crypto_findings)
            
            # 3. Authentication configuration
            auth_findings = self._audit_authentication(target, port, rules)
            findings.extend(auth_findings)
            
            # 4. Protocol configuration
            protocol_findings = self._audit_protocol_config(target, port, rules)
            findings.extend(protocol_findings)
            
            # 5. Security features
            security_findings = self._audit_security_features(target, port, rules)
            findings.extend(security_findings)
            
            # Calculate overall score
            audit_results['findings'] = findings
            audit_results['overall_score'] = self._calculate_audit_score(findings)
            audit_results['compliance_status'] = self._determine_compliance_status(findings, baseline)
            audit_results['recommendations'] = self._generate_recommendations(findings)
            
            return audit_results
            
        except Exception as e:
            return {
                'target': target,
                'port': port,
                'error': str(e),
                'overall_score': 0,
                'findings': [],
                'compliance_status': 'error'
            }
    
    def _audit_banner(self, target: str, port: int, rules: Dict) -> List[Dict]:
        """Audit SSH banner configuration"""
        findings = []
        
        try:
            # Get banner
            banner_info = self._get_banner_info(target, port)
            if not banner_info:
                findings.append({
                    'category': 'banner',
                    'severity': 'high',
                    'finding': 'SSH banner not accessible',
                    'description': 'Unable to retrieve SSH banner',
                    'rule_id': 'BANNER_001'
                })
                return findings
            
            banner = banner_info.get('banner', '')
            
            # Check banner disclosure rules
            if rules.get('banner_disclosure', {}).get('enabled', True):
                if len(banner) > rules.get('banner_disclosure', {}).get('max_length', 100):
                    findings.append({
                        'category': 'banner',
                        'severity': 'medium',
                        'finding': 'Verbose SSH banner',
                        'description': f'Banner length ({len(banner)}) exceeds recommended maximum',
                        'rule_id': 'BANNER_002',
                        'current_value': banner[:100] + '...' if len(banner) > 100 else banner
                    })
                
                # Check for information disclosure
                disclosure_patterns = [
                    r'ubuntu[\d\.-]+',
                    r'debian[\d\.-]+',
                    r'centos[\d\.-]+',
                    r'redhat[\d\.-]+',
                    r'openssh[\d\.-]+p[\d]+',
                    r'build\s+\d+',
                    r'patch\s+\d+'
                ]
                
                for pattern in disclosure_patterns:
                    if re.search(pattern, banner.lower()):
                        findings.append({
                            'category': 'banner',
                            'severity': 'low',
                            'finding': 'Information disclosure in banner',
                            'description': f'Banner contains potentially sensitive information: {pattern}',
                            'rule_id': 'BANNER_003',
                            'current_value': banner
                        })
                        break
            
            # Check protocol version
            if 'SSH-1.' in banner:
                findings.append({
                    'category': 'banner',
                    'severity': 'critical',
                    'finding': 'SSH Protocol 1.x support',
                    'description': 'Server supports deprecated SSH protocol 1.x',
                    'rule_id': 'BANNER_004',
                    'recommendation': 'Disable SSH protocol 1.x support'
                })
            
            # Analyze for vulnerabilities
            vuln_results = self.banner_parser.analyze_banner(banner)
            for vuln in vuln_results:
                if vuln.get('type') == 'vulnerability':
                    severity_map = {'critical': 'critical', 'high': 'high', 'medium': 'medium', 'low': 'low'}
                    findings.append({
                        'category': 'vulnerability',
                        'severity': severity_map.get(vuln.get('severity', 'medium'), 'medium'),
                        'finding': f"Known vulnerability: {vuln.get('cve', 'Unknown')}",
                        'description': vuln.get('description', ''),
                        'rule_id': f"VULN_{vuln.get('cve', 'UNKNOWN').replace('-', '_')}",
                        'cve': vuln.get('cve'),
                        'references': vuln.get('references', [])
                    })
            
        except Exception as e:
            findings.append({
                'category': 'banner',
                'severity': 'medium',
                'finding': 'Banner audit failed',
                'description': f'Error during banner analysis: {str(e)}',
                'rule_id': 'BANNER_ERROR'
            })
        
        return findings
    
    def _audit_cryptography(self, target: str, port: int, rules: Dict) -> List[Dict]:
        """Audit cryptographic algorithms and ciphers"""
        findings = []
        
        try:
            # Get supported algorithms
            algorithms = self.ssh_protocol.get_supported_algorithms(target, port)
            if not algorithms:
                findings.append({
                    'category': 'cryptography',
                    'severity': 'high',
                    'finding': 'Unable to enumerate algorithms',
                    'description': 'Could not retrieve supported cryptographic algorithms',
                    'rule_id': 'CRYPTO_001'
                })
                return findings
            
            # Check for weak algorithms
            weak_algorithms = self.ssh_protocol.detect_weak_algorithms(algorithms)
            for weak_alg in weak_algorithms:
                severity_map = {'high': 'high', 'medium': 'medium', 'low': 'low'}
                findings.append({
                    'category': 'cryptography',
                    'severity': severity_map.get(weak_alg.get('severity', 'medium'), 'medium'),
                    'finding': f"Weak algorithm: {weak_alg['algorithm']}",
                    'description': weak_alg['weakness'],
                    'rule_id': f"CRYPTO_{weak_alg['category'].upper()}",
                    'current_value': weak_alg['algorithm'],
                    'recommendation': f"Disable {weak_alg['algorithm']} in SSH configuration"
                })
            
            # Check cipher requirements
            crypto_rules = rules.get('cryptography', {})
            
            # Required strong ciphers
            required_ciphers = crypto_rules.get('required_ciphers', [])
            available_ciphers = algorithms.get('encryption_algorithms', [])
            
            for required_cipher in required_ciphers:
                if not any(required_cipher in cipher for cipher in available_ciphers):
                    findings.append({
                        'category': 'cryptography',
                        'severity': 'medium',
                        'finding': f"Missing required cipher: {required_cipher}",
                        'description': f"Server does not support required cipher {required_cipher}",
                        'rule_id': 'CRYPTO_REQUIRED',
                        'recommendation': f"Enable {required_cipher} in SSH configuration"
                    })
            
            # Prohibited weak ciphers
            prohibited_ciphers = crypto_rules.get('prohibited_ciphers', [])
            for prohibited_cipher in prohibited_ciphers:
                if any(prohibited_cipher in cipher for cipher in available_ciphers):
                    findings.append({
                        'category': 'cryptography',
                        'severity': 'high',
                        'finding': f"Prohibited cipher enabled: {prohibited_cipher}",
                        'description': f"Server supports prohibited weak cipher {prohibited_cipher}",
                        'rule_id': 'CRYPTO_PROHIBITED',
                        'current_value': prohibited_cipher,
                        'recommendation': f"Disable {prohibited_cipher} in SSH configuration"
                    })
            
            # Check MAC algorithms
            available_macs = algorithms.get('mac_algorithms', [])
            prohibited_macs = crypto_rules.get('prohibited_macs', ['hmac-md5', 'hmac-sha1-96'])
            
            for prohibited_mac in prohibited_macs:
                if any(prohibited_mac in mac for mac in available_macs):
                    findings.append({
                        'category': 'cryptography',
                        'severity': 'medium',
                        'finding': f"Weak MAC algorithm: {prohibited_mac}",
                        'description': f"Server supports weak MAC algorithm {prohibited_mac}",
                        'rule_id': 'CRYPTO_MAC',
                        'current_value': prohibited_mac,
                        'recommendation': f"Disable {prohibited_mac} MAC algorithm"
                    })
            
            # Check key exchange algorithms
            available_kex = algorithms.get('kex_algorithms', [])
            prohibited_kex = crypto_rules.get('prohibited_kex', ['diffie-hellman-group1-sha1'])
            
            for prohibited in prohibited_kex:
                if any(prohibited in kex for kex in available_kex):
                    findings.append({
                        'category': 'cryptography',
                        'severity': 'high',
                        'finding': f"Weak key exchange: {prohibited}",
                        'description': f"Server supports weak key exchange algorithm {prohibited}",
                        'rule_id': 'CRYPTO_KEX',
                        'current_value': prohibited,
                        'recommendation': f"Disable {prohibited} key exchange algorithm"
                    })
            
        except Exception as e:
            findings.append({
                'category': 'cryptography',
                'severity': 'medium',
                'finding': 'Cryptography audit failed',
                'description': f'Error during cryptographic analysis: {str(e)}',
                'rule_id': 'CRYPTO_ERROR'
            })
        
        return findings
    
    def _audit_authentication(self, target: str, port: int, rules: Dict) -> List[Dict]:
        """Audit authentication configuration"""
        findings = []
        
        try:
            auth_rules = rules.get('authentication', {})
            
            # Test for common authentication issues
            
            # 1. Test for root login
            if auth_rules.get('check_root_login', True):
                root_test = self._test_root_login_allowed(target, port)
                if root_test:
                    findings.append({
                        'category': 'authentication',
                        'severity': 'high',
                        'finding': 'Root login allowed',
                        'description': 'SSH server allows direct root login',
                        'rule_id': 'AUTH_ROOT',
                        'recommendation': 'Set PermitRootLogin to no in SSH configuration'
                    })
            
            # 2. Test for password authentication
            if auth_rules.get('check_password_auth', True):
                password_test = self._test_password_auth_enabled(target, port)
                if password_test and auth_rules.get('require_key_auth', False):
                    findings.append({
                        'category': 'authentication',
                        'severity': 'medium',
                        'finding': 'Password authentication enabled',
                        'description': 'SSH server allows password authentication',
                        'rule_id': 'AUTH_PASSWORD',
                        'recommendation': 'Disable password authentication and use key-based authentication'
                    })
            
            # 3. Test for empty passwords
            if auth_rules.get('check_empty_passwords', True):
                empty_password_test = self._test_empty_passwords_allowed(target, port)
                if empty_password_test:
                    findings.append({
                        'category': 'authentication',
                        'severity': 'critical',
                        'finding': 'Empty passwords allowed',
                        'description': 'SSH server allows empty passwords',
                        'rule_id': 'AUTH_EMPTY',
                        'recommendation': 'Set PermitEmptyPasswords to no'
                    })
            
            # 4. Test for user enumeration vulnerability
            if auth_rules.get('check_user_enum', True):
                user_enum_test = self._test_user_enumeration(target, port)
                if user_enum_test:
                    findings.append({
                        'category': 'authentication',
                        'severity': 'medium',
                        'finding': 'User enumeration possible',
                        'description': 'SSH server is vulnerable to username enumeration',
                        'rule_id': 'AUTH_ENUM',
                        'recommendation': 'Update SSH server to patch user enumeration vulnerabilities'
                    })
            
        except Exception as e:
            findings.append({
                'category': 'authentication',
                'severity': 'medium',
                'finding': 'Authentication audit failed',
                'description': f'Error during authentication analysis: {str(e)}',
                'rule_id': 'AUTH_ERROR'
            })
        
        return findings
    
    def _audit_protocol_config(self, target: str, port: int, rules: Dict) -> List[Dict]:
        """Audit SSH protocol configuration"""
        findings = []
        
        try:
            protocol_rules = rules.get('protocol', {})
            
            # Check for non-standard port
            if protocol_rules.get('check_default_port', True) and port == 22:
                findings.append({
                    'category': 'protocol',
                    'severity': 'low',
                    'finding': 'Default SSH port in use',
                    'description': 'SSH server is running on default port 22',
                    'rule_id': 'PROTO_PORT',
                    'recommendation': 'Consider changing SSH port to reduce automated attacks'
                })
            
            # Test connection limits and timeouts
            timeout_test = self._test_connection_timeout(target, port)
            if timeout_test and timeout_test > protocol_rules.get('max_timeout', 300):
                findings.append({
                    'category': 'protocol',
                    'severity': 'low',
                    'finding': 'Long connection timeout',
                    'description': f'SSH connection timeout is {timeout_test} seconds',
                    'rule_id': 'PROTO_TIMEOUT',
                    'current_value': str(timeout_test),
                    'recommendation': 'Reduce ClientAliveInterval and ClientAliveCountMax'
                })
            
        except Exception as e:
            findings.append({
                'category': 'protocol',
                'severity': 'medium',
                'finding': 'Protocol audit failed',
                'description': f'Error during protocol analysis: {str(e)}',
                'rule_id': 'PROTO_ERROR'
            })
        
        return findings
    
    def _audit_security_features(self, target: str, port: int, rules: Dict) -> List[Dict]:
        """Audit SSH security features"""
        findings = []
        
        try:
            security_rules = rules.get('security_features', {})
            
            # Test for rate limiting
            if security_rules.get('check_rate_limiting', True):
                rate_limit_test = self._test_rate_limiting(target, port)
                if not rate_limit_test:
                    findings.append({
                        'category': 'security',
                        'severity': 'medium',
                        'finding': 'No rate limiting detected',
                        'description': 'SSH server does not appear to implement connection rate limiting',
                        'rule_id': 'SEC_RATE_LIMIT',
                        'recommendation': 'Implement connection rate limiting or fail2ban'
                    })
            
            # Test for banner grabbing protection
            if security_rules.get('check_banner_protection', True):
                banner_protection_test = self._test_banner_protection(target, port)
                if not banner_protection_test:
                    findings.append({
                        'category': 'security',
                        'severity': 'low',
                        'finding': 'No banner protection',
                        'description': 'SSH server banner is easily accessible',
                        'rule_id': 'SEC_BANNER_PROTECT',
                        'recommendation': 'Consider implementing banner protection or port knocking'
                    })
            
        except Exception as e:
            findings.append({
                'category': 'security',
                'severity': 'medium',
                'finding': 'Security features audit failed',
                'description': f'Error during security features analysis: {str(e)}',
                'rule_id': 'SEC_ERROR'
            })
        
        return findings
    
    def _get_banner_info(self, target: str, port: int) -> Optional[Dict]:
        """Get SSH banner information"""
        try:
            import socket
            with socket.create_connection((target, port), timeout=5) as sock:
                banner = sock.recv(1024).decode(errors='ignore').strip()
                return {'banner': banner}
        except Exception:
            return None
    
    def _test_root_login_allowed(self, target: str, port: int) -> bool:
        """Test if root login is allowed"""
        try:
            # Attempt root login with invalid password
            result = self.ssh_protocol.authenticate_password(target, port, 'root', 'invalid_password_12345')
            # If we get a specific authentication failure (not connection refused), root login is likely allowed
            return 'Authentication failed' in result.get('error', '') or result.get('success', False)
        except Exception:
            return False
    
    def _test_password_auth_enabled(self, target: str, port: int) -> bool:
        """Test if password authentication is enabled"""
        try:
            # Attempt login with invalid credentials
            result = self.ssh_protocol.authenticate_password(target, port, 'testuser', 'invalid_password')
            # If we get authentication failure rather than method not allowed, password auth is enabled
            return 'Authentication failed' in result.get('error', '') or result.get('success', False)
        except Exception:
            return False
    
    def _test_empty_passwords_allowed(self, target: str, port: int) -> bool:
        """Test if empty passwords are allowed"""
        try:
            # Test common usernames with empty passwords
            test_users = ['root', 'admin', 'user', 'test']
            for username in test_users:
                result = self.ssh_protocol.authenticate_password(target, port, username, '')
                if result.get('success', False):
                    return True
            return False
        except Exception:
            return False
    
    def _test_user_enumeration(self, target: str, port: int) -> bool:
        """Test for user enumeration vulnerability"""
        try:
            # Test timing-based user enumeration
            valid_user_time = self._measure_auth_time(target, port, 'root', 'invalid_password')
            invalid_user_time = self._measure_auth_time(target, port, 'invalid_user_12345', 'invalid_password')
            
            # If there's a significant timing difference, enumeration may be possible
            return abs(valid_user_time - invalid_user_time) > 0.5
        except Exception:
            return False
    
    def _measure_auth_time(self, target: str, port: int, username: str, password: str) -> float:
        """Measure authentication attempt time"""
        import time
        try:
            start_time = time.time()
            self.ssh_protocol.authenticate_password(target, port, username, password)
            end_time = time.time()
            return end_time - start_time
        except Exception:
            return 0.0
    
    def _test_connection_timeout(self, target: str, port: int) -> Optional[int]:
        """Test SSH connection timeout"""
        try:
            import socket
            import time
            
            start_time = time.time()
            sock = socket.create_connection((target, port), timeout=30)
            
            # Read banner but don't respond
            sock.recv(1024)
            
            # Wait for server to close connection
            try:
                while True:
                    data = sock.recv(1024)
                    if not data:
                        break
            except Exception:
                pass
            
            end_time = time.time()
            sock.close()
            
            return int(end_time - start_time)
        except Exception:
            return None
    
    def _test_rate_limiting(self, target: str, port: int) -> bool:
        """Test for connection rate limiting"""
        try:
            import socket
            import time
            
            # Attempt multiple rapid connections
            connections = []
            start_time = time.time()
            
            for i in range(10):
                try:
                    sock = socket.create_connection((target, port), timeout=2)
                    connections.append(sock)
                except Exception:
                    # If connections start failing, rate limiting may be in place
                    for conn in connections:
                        try:
                            conn.close()
                        except:
                            pass
                    return True
                
                time.sleep(0.1)
            
            # Clean up connections
            for conn in connections:
                try:
                    conn.close()
                except:
                    pass
            
            # If all connections succeeded, no rate limiting detected
            return False
            
        except Exception:
            return False
    
    def _test_banner_protection(self, target: str, port: int) -> bool:
        """Test for banner protection mechanisms"""
        try:
            # Simple test - if we can easily get the banner, no protection
            banner_info = self._get_banner_info(target, port)
            return banner_info is None
        except Exception:
            return True  # If we can't connect, assume there's some protection
    
    def _calculate_audit_score(self, findings: List[Dict]) -> int:
        """Calculate overall audit score (0-100)"""
        if not findings:
            return 100
        
        # Weight findings by severity
        severity_weights = {
            'critical': 25,
            'high': 15,
            'medium': 10,
            'low': 5
        }
        
        total_deductions = 0
        for finding in findings:
            severity = finding.get('severity', 'medium')
            total_deductions += severity_weights.get(severity, 10)
        
        # Cap at 0
        score = max(0, 100 - total_deductions)
        return score
    
    def _determine_compliance_status(self, findings: List[Dict], baseline: str) -> str:
        """Determine compliance status based on findings"""
        critical_findings = [f for f in findings if f.get('severity') == 'critical']
        high_findings = [f for f in findings if f.get('severity') == 'high']
        
        if critical_findings:
            return 'non_compliant'
        elif len(high_findings) > 3:
            return 'non_compliant'
        elif high_findings:
            return 'partially_compliant'
        else:
            return 'compliant'
    
    def _generate_recommendations(self, findings: List[Dict]) -> List[str]:
        """Generate prioritized recommendations"""
        recommendations = []
        
        # Group by severity and extract recommendations
        critical_recs = [f.get('recommendation') for f in findings if f.get('severity') == 'critical' and f.get('recommendation')]
        high_recs = [f.get('recommendation') for f in findings if f.get('severity') == 'high' and f.get('recommendation')]
        medium_recs = [f.get('recommendation') for f in findings if f.get('severity') == 'medium' and f.get('recommendation')]
        low_recs = [f.get('recommendation') for f in findings if f.get('severity') == 'low' and f.get('recommendation')]
        
        # Add in priority order
        recommendations.extend([r for r in critical_recs if r])
        recommendations.extend([r for r in high_recs if r])
        recommendations.extend([r for r in medium_recs if r])
        recommendations.extend([r for r in low_recs if r])
        
        # Remove duplicates while preserving order
        seen = set()
        unique_recommendations = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
        
        return unique_recommendations[:10]  # Top 10 recommendations
    
    def _load_cis_baseline(self) -> Dict:
        """Load CIS (Center for Internet Security) baseline"""
        return {
            'banner_disclosure': {
                'enabled': True,
                'max_length': 80
            },
            'cryptography': {
                'required_ciphers': ['aes256-ctr', 'aes192-ctr', 'aes128-ctr'],
                'prohibited_ciphers': ['arcfour', 'des', '3des-cbc'],
                'prohibited_macs': ['hmac-md5', 'hmac-sha1-96'],
                'prohibited_kex': ['diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1']
            },
            'authentication': {
                'check_root_login': True,
                'check_password_auth': True,
                'check_empty_passwords': True,
                'check_user_enum': True,
                'require_key_auth': True
            },
            'protocol': {
                'check_default_port': True,
                'max_timeout': 300
            },
            'security_features': {
                'check_rate_limiting': True,
                'check_banner_protection': False
            }
        }
    
    def _load_nist_baseline(self) -> Dict:
        """Load NIST baseline"""
        return {
            'banner_disclosure': {
                'enabled': True,
                'max_length': 100
            },
            'cryptography': {
                'required_ciphers': ['aes256-gcm@openssh.com', 'aes128-gcm@openssh.com'],
                'prohibited_ciphers': ['arcfour', 'des', '3des-cbc', 'blowfish-cbc'],
                'prohibited_macs': ['hmac-md5', 'hmac-sha1-96', 'hmac-ripemd160'],
                'prohibited_kex': ['diffie-hellman-group1-sha1']
            },
            'authentication': {
                'check_root_login': True,
                'check_password_auth': False,  # NIST allows password auth with strong policies
                'check_empty_passwords': True,
                'check_user_enum': True,
                'require_key_auth': False
            },
            'protocol': {
                'check_default_port': False,
                'max_timeout': 600
            },
            'security_features': {
                'check_rate_limiting': True,
                'check_banner_protection': False
            }
        }
    
    def _load_pci_dss_baseline(self) -> Dict:
        """Load PCI DSS baseline"""
        return {
            'banner_disclosure': {
                'enabled': True,
                'max_length': 50
            },
            'cryptography': {
                'required_ciphers': ['aes256-ctr', 'aes256-gcm@openssh.com'],
                'prohibited_ciphers': ['arcfour', 'des', '3des-cbc', 'rc4'],
                'prohibited_macs': ['hmac-md5', 'hmac-sha1'],
                'prohibited_kex': ['diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1']
            },
            'authentication': {
                'check_root_login': True,
                'check_password_auth': True,
                'check_empty_passwords': True,
                'check_user_enum': True,
                'require_key_auth': True
            },
            'protocol': {
                'check_default_port': True,
                'max_timeout': 300
            },
            'security_features': {
                'check_rate_limiting': True,
                'check_banner_protection': True
            }
        }
    
    def _load_custom_baseline(self) -> Dict:
        """Load custom baseline"""
        return self._load_cis_baseline()  # Default to CIS