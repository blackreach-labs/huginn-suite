# app/core/license_manager.py
import hashlib
import json
import base64
from datetime import datetime, timedelta
from typing import Dict, Optional, List
from PyQt6.QtCore import QObject, pyqtSignal
from cryptography.fernet import Fernet
from app.core.logger import logger

class LicenseManager(QObject):
    """Professional license management for paid features"""
    
    license_event = pyqtSignal(str, str, dict)  # event_type, message, data
    
    def __init__(self):
        super().__init__()
        self.license_key = None
        self.license_data = {}
        self.features_enabled = {
            'stealth_mode': False,
            'hacking_mode': False,
            'proxychains': False,
            'exploit_database': False,
            'post_exploitation': False,
            'advanced_reporting': False,
            'web_scanner': False,
            'ad_enumeration': False,
            'enhanced_reporting': False,
            'wireless_security': False,
            'social_engineering': False,
            'anti_forensics': False,
            'api_integrations': False,
            'local_dns_server': False,
            'vpn_connection': False
        }
        self.license_file = "huggin.lic"
        self.load_license()
        
    def validate_license(self, license_key: str) -> Dict:
        """Validate license key and return license information"""
        try:
            # Decode license key (base64 encoded JSON)
            decoded = base64.b64decode(license_key.encode()).decode()
            license_data = json.loads(decoded)
            
            # Validate required fields
            required_fields = ['user_id', 'license_type', 'expiry_date', 'features', 'signature']
            if not all(field in license_data for field in required_fields):
                return {"valid": False, "error": "Invalid license format"}
                
            # Validate signature
            if not self._verify_signature(license_data):
                return {"valid": False, "error": "Invalid license signature"}
                
            # Check expiry
            expiry_date = datetime.fromisoformat(license_data['expiry_date'])
            if datetime.now() > expiry_date:
                return {"valid": False, "error": "License expired"}
                
            # License is valid
            self.license_key = license_key
            self.license_data = license_data
            self._update_enabled_features()
            self.save_license()
            
            self.license_event.emit('license_validated', 'License validated successfully', license_data)
            
            return {
                "valid": True,
                "license_type": license_data['license_type'],
                "expiry_date": license_data['expiry_date'],
                "features": license_data['features'],
                "user_id": license_data['user_id']
            }
            
        except Exception as e:
            logger.error(f"License validation error: {e}")
            return {"valid": False, "error": f"License validation failed: {str(e)}"}
            
    def _verify_signature(self, license_data: Dict) -> bool:
        """Verify license signature"""
        # Create signature from license data (excluding signature field)
        signature_data = {k: v for k, v in license_data.items() if k != 'signature'}
        signature_string = json.dumps(signature_data, sort_keys=True)
        
        # Use a secret key for signature verification (in production, this would be more secure)
        secret_key = "huggin_license_secret_2024"
        expected_signature = hashlib.sha256((signature_string + secret_key).encode()).hexdigest()
        
        return license_data.get('signature') == expected_signature
        
    def _update_enabled_features(self):
        """Update enabled features based on license"""
        if not self.license_data:
            return
            
        licensed_features = self.license_data.get('features', [])
        license_type = self.license_data.get('license_type', '')
        
        # Reset all features
        for feature in self.features_enabled:
            self.features_enabled[feature] = False
            
        # Enable licensed features
        for feature in licensed_features:
            if feature in self.features_enabled:
                self.features_enabled[feature] = True
                
        # Auto-enable features based on license type
        if 'Professional' in license_type or 'Enterprise' in license_type:
            self.features_enabled['web_scanner'] = True
            self.features_enabled['local_dns_server'] = True
            self.features_enabled['vpn_connection'] = True
        if 'Enterprise' in license_type:
            self.features_enabled['ad_enumeration'] = True
            self.features_enabled['enhanced_reporting'] = True
            self.features_enabled['wireless_security'] = True
            self.features_enabled['social_engineering'] = True
            self.features_enabled['anti_forensics'] = True
            self.features_enabled['advanced_reporting'] = True
                
        self.license_event.emit('features_updated', 'Licensed features updated', 
                              {'enabled_features': self.get_enabled_features()})
                              
    def is_feature_enabled(self, feature: str) -> bool:
        """Check if a specific feature is enabled"""
        return self.features_enabled.get(feature, False)
        
    def validate_feature_access(self, feature: str, server_side: bool = False) -> bool:
        """Validate access to a specific feature"""
        return self.is_feature_enabled(feature)
        
    def get_enabled_features(self) -> List[str]:
        """Get list of enabled features"""
        return [feature for feature, enabled in self.features_enabled.items() if enabled]
        
    def get_license_info(self) -> Dict:
        """Get current license information"""
        if not self.license_data:
            return {
                "licensed": False,
                "license_type": "Free",
                "features": [],
                "expiry_date": None
            }
            
        return {
            "licensed": True,
            "license_type": self.license_data.get('license_type', 'Unknown'),
            "features": self.license_data.get('features', []),
            "expiry_date": self.license_data.get('expiry_date'),
            "user_id": self.license_data.get('user_id'),
            "days_remaining": self._get_days_remaining()
        }
        
    def _get_days_remaining(self) -> int:
        """Get days remaining on license"""
        if not self.license_data:
            return 0
            
        try:
            expiry_date = datetime.fromisoformat(self.license_data['expiry_date'])
            remaining = expiry_date - datetime.now()
            return max(0, remaining.days)
        except Exception:
            return 0
            
    def save_license(self):
        """Save license to file"""
        if not self.license_key:
            return
            
        try:
            license_info = {
                'license_key': self.license_key,
                'validated_at': datetime.now().isoformat(),
                'license_data': self.license_data
            }
            
            # Encrypt license file
            key = Fernet.generate_key()
            cipher = Fernet(key)
            encrypted_data = cipher.encrypt(json.dumps(license_info).encode())
            
            with open(self.license_file, 'wb') as f:
                f.write(key + b'::' + encrypted_data)
                
            logger.info("License saved successfully")
            
        except Exception as e:
            logger.error(f"Failed to save license: {e}")
            
    def load_license(self):
        """Load license from file"""
        try:
            with open(self.license_file, 'rb') as f:
                content = f.read()
                
            # Split key and encrypted data
            key, encrypted_data = content.split(b'::', 1)
            
            # Decrypt license data
            cipher = Fernet(key)
            decrypted_data = cipher.decrypt(encrypted_data)
            license_info = json.loads(decrypted_data.decode())
            
            # Validate loaded license
            validation_result = self.validate_license(license_info['license_key'])
            if validation_result['valid']:
                logger.info("License loaded and validated successfully")
            else:
                logger.warning(f"Loaded license is invalid: {validation_result['error']}")
                
        except FileNotFoundError:
            logger.info("No license file found")
        except Exception as e:
            logger.error(f"Failed to load license: {e}")
            
    def generate_trial_license(self, days: int = 30) -> str:
        """Generate trial license (for testing purposes)"""
        expiry_date = datetime.now() + timedelta(days=days)
        
        license_data = {
            'user_id': 'trial_user',
            'license_type': 'Trial',
            'expiry_date': expiry_date.isoformat(),
            'features': ['stealth_mode', 'proxychains', 'web_scanner'],  # Limited trial features
        }
        
        # Generate signature
        signature_string = json.dumps(license_data, sort_keys=True)
        secret_key = "huggin_license_secret_2024"
        signature = hashlib.sha256((signature_string + secret_key).encode()).hexdigest()
        license_data['signature'] = signature
        
        # Encode license
        license_key = base64.b64encode(json.dumps(license_data).encode()).decode()
        
        return license_key
        
    def get_feature_descriptions(self) -> Dict:
        """Get descriptions of premium features"""
        return {
            'stealth_mode': {
                'name': 'Stealth Mode',
                'description': 'Advanced evasion techniques, packet fragmentation, timing controls',
                'tier': 'Professional'
            },
            'hacking_mode': {
                'name': 'Hacking Mode', 
                'description': 'Exploit frameworks integration, payload generation, attack chains',
                'tier': 'Professional'
            },
            'proxychains': {
                'name': 'ProxyChains',
                'description': 'Multi-proxy chaining, Tor integration, traffic obfuscation',
                'tier': 'Professional'
            },
            'exploit_database': {
                'name': 'Exploit Database',
                'description': 'CVE database, automated exploit matching, vulnerability analysis',
                'tier': 'Enterprise'
            },
            'post_exploitation': {
                'name': 'Post-Exploitation',
                'description': 'Persistence, lateral movement, data exfiltration, session management',
                'tier': 'Enterprise'
            },
            'advanced_reporting': {
                'name': 'Advanced Reporting',
                'description': 'Executive summaries, compliance reports, custom templates',
                'tier': 'Enterprise'
            },
            'web_scanner': {
                'name': 'Web Application Scanner',
                'description': 'OWASP Top 10 vulnerability detection, SQL injection, XSS testing',
                'tier': 'Professional'
            },
            'ad_enumeration': {
                'name': 'Active Directory Enumeration',
                'description': 'Kerberoasting, ASREPRoasting, BloodHound analysis, domain attacks',
                'tier': 'Enterprise'
            },
            'enhanced_reporting': {
                'name': 'Enhanced Reporting Engine',
                'description': 'Executive dashboards, compliance reports, risk assessment',
                'tier': 'Enterprise'
            },
            'wireless_security': {
                'name': 'Wireless Security Testing',
                'description': 'WiFi and Bluetooth security assessment, evil twin attacks',
                'tier': 'Enterprise'
            },
            'social_engineering': {
                'name': 'Social Engineering Toolkit',
                'description': 'Phishing campaigns, credential harvesting, user awareness testing',
                'tier': 'Enterprise'
            },
            'anti_forensics': {
                'name': 'Anti-Forensics & Evasion',
                'description': 'Log clearing, secure deletion, network obfuscation, memory evasion',
                'tier': 'Enterprise'
            },
            'api_integrations': {
                'name': 'API Integrations',
                'description': 'Shodan, VirusTotal, threat intelligence feeds, custom APIs',
                'tier': 'Enterprise'
            },
            'local_dns_server': {
                'name': 'Local DNS Server',
                'description': 'Custom DNS server for domain record management and testing',
                'tier': 'Professional'
            },
            'vpn_connection': {
                'name': 'VPN Connection Manager',
                'description': 'Secure VPN connection management for anonymous scanning',
                'tier': 'Professional'
            }
        }
        
    def get_purchase_url(self) -> str:
        """Get purchase URL for license"""
        return "https://huggin.com/purchase"
        
    def check_license_expiry(self) -> Dict:
        """Check license expiry and send warnings"""
        if not self.license_data:
            return {"status": "no_license"}
            
        days_remaining = self._get_days_remaining()
        
        if days_remaining <= 0:
            self.license_event.emit('license_expired', 'License has expired', 
                                  {'days_remaining': days_remaining})
            return {"status": "expired", "days_remaining": days_remaining}
        elif days_remaining <= 7:
            self.license_event.emit('license_expiring', f'License expires in {days_remaining} days', 
                                  {'days_remaining': days_remaining})
            return {"status": "expiring_soon", "days_remaining": days_remaining}
        else:
            return {"status": "valid", "days_remaining": days_remaining}

# Global license manager instance
license_manager = LicenseManager()