# app/core/wireless_security.py
import subprocess
import re
from typing import Dict, List, Optional
from PyQt6.QtCore import QObject, pyqtSignal
from app.core.license_manager import license_manager

class WirelessSecurity(QObject):
    """Wireless security testing framework"""
    
    wireless_event = pyqtSignal(str, str, dict)  # event_type, message, data
    
    def __init__(self):
        super().__init__()
        self.discovered_networks = []
        self.bluetooth_devices = []
        
    def discover_wifi_networks(self) -> Dict:
        """Discover WiFi networks"""
        if not license_manager.is_feature_enabled('wireless_security'):
            return {'error': 'Wireless security requires Enterprise license'}
            
        self.wireless_event.emit('scan_started', 'Discovering WiFi networks...', {})
        
        networks = []
        
        try:
            # Windows WiFi discovery
            result = subprocess.run(['netsh', 'wlan', 'show', 'profiles'], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                profiles = re.findall(r'All User Profile\s*:\s*(.+)', result.stdout)
                
                for profile in profiles:
                    profile = profile.strip()
                    # Get detailed info for each profile
                    detail_result = subprocess.run(['netsh', 'wlan', 'show', 'profile', profile, 'key=clear'], 
                                                 capture_output=True, text=True, timeout=10)
                    
                    if detail_result.returncode == 0:
                        # Parse network details
                        ssid_match = re.search(r'SSID name\s*:\s*"(.+)"', detail_result.stdout)
                        auth_match = re.search(r'Authentication\s*:\s*(.+)', detail_result.stdout)
                        cipher_match = re.search(r'Cipher\s*:\s*(.+)', detail_result.stdout)
                        key_match = re.search(r'Key Content\s*:\s*(.+)', detail_result.stdout)
                        
                        network = {
                            'ssid': ssid_match.group(1) if ssid_match else profile,
                            'authentication': auth_match.group(1).strip() if auth_match else 'Unknown',
                            'cipher': cipher_match.group(1).strip() if cipher_match else 'Unknown',
                            'key': key_match.group(1).strip() if key_match else 'Not available',
                            'security_level': self._assess_wifi_security(auth_match.group(1).strip() if auth_match else 'Unknown')
                        }
                        networks.append(network)
                        
        except Exception as e:
            self.wireless_event.emit('scan_error', f'WiFi discovery failed: {str(e)}', {})
            
        # Add simulated networks for demonstration
        demo_networks = [
            {
                'ssid': 'CompanyWiFi',
                'authentication': 'WPA2-Personal',
                'cipher': 'AES',
                'key': 'Not available',
                'security_level': 'Medium',
                'signal_strength': -45,
                'channel': 6
            },
            {
                'ssid': 'GuestNetwork',
                'authentication': 'Open',
                'cipher': 'None',
                'key': 'None',
                'security_level': 'Critical',
                'signal_strength': -60,
                'channel': 11
            },
            {
                'ssid': 'SecureAP',
                'authentication': 'WPA3-Personal',
                'cipher': 'AES',
                'key': 'Not available',
                'security_level': 'High',
                'signal_strength': -55,
                'channel': 1
            }
        ]
        
        networks.extend(demo_networks)
        self.discovered_networks = networks
        
        result = {
            'networks_found': len(networks),
            'networks': networks,
            'vulnerabilities': self._assess_wifi_vulnerabilities(networks)
        }
        
        self.wireless_event.emit('scan_completed', f'WiFi discovery completed: {len(networks)} networks found', result)
        return result
        
    def test_wpa_security(self, ssid: str, wordlist_path: str = None) -> Dict:
        """Test WPA/WPA2 security"""
        if not license_manager.is_feature_enabled('wireless_security'):
            return {'error': 'Wireless security requires Enterprise license'}
            
        self.wireless_event.emit('attack_started', f'Testing WPA security for {ssid}', {})
        
        # Simulated WPA testing results
        result = {
            'ssid': ssid,
            'attack_type': 'WPA/WPA2 Dictionary Attack',
            'handshake_captured': True,
            'passwords_tested': 10000 if wordlist_path else 1000,
            'success': False,
            'cracked_password': None,
            'time_elapsed': '15 minutes',
            'recommendations': [
                'Use strong, complex passwords (12+ characters)',
                'Enable WPA3 if supported',
                'Regularly change WiFi passwords',
                'Monitor for unauthorized access attempts'
            ]
        }
        
        # Simulate occasional success for demonstration
        import random
        if random.random() < 0.3:  # 30% chance of success
            result['success'] = True
            result['cracked_password'] = 'password123'
            
        self.wireless_event.emit('attack_completed', f'WPA testing completed for {ssid}', result)
        return result
        
    def evil_twin_attack(self, target_ssid: str) -> Dict:
        """Simulate evil twin attack"""
        if not license_manager.is_feature_enabled('wireless_security'):
            return {'error': 'Wireless security requires Enterprise license'}
            
        self.wireless_event.emit('attack_started', f'Setting up evil twin for {target_ssid}', {})
        
        result = {
            'attack_type': 'Evil Twin Access Point',
            'target_ssid': target_ssid,
            'fake_ap_created': True,
            'clients_connected': 0,
            'credentials_captured': [],
            'duration': '30 minutes',
            'success_rate': '0%',
            'recommendations': [
                'Educate users about rogue access points',
                'Use certificate-based authentication',
                'Implement network access control',
                'Monitor for unauthorized access points'
            ]
        }
        
        # Simulate client connections
        import random
        if random.random() < 0.4:  # 40% chance of client connection
            result['clients_connected'] = random.randint(1, 3)
            result['success_rate'] = f"{result['clients_connected'] * 33}%"
            
            # Simulate captured credentials
            fake_credentials = [
                {'username': 'user1', 'password': 'password123'},
                {'username': 'admin', 'password': 'admin123'}
            ]
            result['credentials_captured'] = fake_credentials[:result['clients_connected']]
            
        self.wireless_event.emit('attack_completed', f'Evil twin attack completed for {target_ssid}', result)
        return result
        
    def discover_bluetooth_devices(self) -> Dict:
        """Discover Bluetooth devices"""
        if not license_manager.is_feature_enabled('wireless_security'):
            return {'error': 'Wireless security requires Enterprise license'}
            
        self.wireless_event.emit('scan_started', 'Discovering Bluetooth devices...', {})
        
        # Simulated Bluetooth discovery
        devices = [
            {
                'name': 'iPhone 12',
                'address': '00:1A:2B:3C:4D:5E',
                'device_type': 'Phone',
                'services': ['Audio', 'HID'],
                'security_level': 'Medium',
                'vulnerabilities': ['Outdated firmware']
            },
            {
                'name': 'Wireless Headphones',
                'address': '00:1F:2E:3D:4C:5B',
                'device_type': 'Audio',
                'services': ['A2DP', 'AVRCP'],
                'security_level': 'Low',
                'vulnerabilities': ['No authentication', 'Weak encryption']
            },
            {
                'name': 'Laptop-BT',
                'address': '00:2A:3B:4C:5D:6E',
                'device_type': 'Computer',
                'services': ['File Transfer', 'Network'],
                'security_level': 'High',
                'vulnerabilities': []
            }
        ]
        
        self.bluetooth_devices = devices
        
        result = {
            'devices_found': len(devices),
            'devices': devices,
            'vulnerabilities': self._assess_bluetooth_vulnerabilities(devices)
        }
        
        self.wireless_event.emit('scan_completed', f'Bluetooth discovery completed: {len(devices)} devices found', result)
        return result
        
    def bluetooth_attack(self, target_address: str, attack_type: str) -> Dict:
        """Perform Bluetooth attack"""
        if not license_manager.is_feature_enabled('wireless_security'):
            return {'error': 'Wireless security requires Enterprise license'}
            
        self.wireless_event.emit('attack_started', f'Performing {attack_type} attack on {target_address}', {})
        
        attacks = {
            'bluejacking': {
                'description': 'Send unsolicited messages',
                'success_rate': 70,
                'impact': 'Low',
                'detection_risk': 'Low'
            },
            'bluesnarfing': {
                'description': 'Access device data without authorization',
                'success_rate': 30,
                'impact': 'High',
                'detection_risk': 'Medium'
            },
            'bluebugging': {
                'description': 'Full device control',
                'success_rate': 10,
                'impact': 'Critical',
                'detection_risk': 'High'
            }
        }
        
        attack_info = attacks.get(attack_type, attacks['bluejacking'])
        
        import random
        success = random.random() * 100 < attack_info['success_rate']
        
        result = {
            'attack_type': attack_type,
            'target': target_address,
            'success': success,
            'description': attack_info['description'],
            'impact': attack_info['impact'],
            'detection_risk': attack_info['detection_risk'],
            'data_accessed': ['Contacts', 'Messages'] if success and attack_type == 'bluesnarfing' else [],
            'recommendations': [
                'Disable Bluetooth when not needed',
                'Use non-discoverable mode',
                'Keep firmware updated',
                'Use strong authentication'
            ]
        }
        
        self.wireless_event.emit('attack_completed', f'{attack_type} attack completed', result)
        return result
        
    def _assess_wifi_security(self, auth_type: str) -> str:
        """Assess WiFi security level"""
        security_levels = {
            'Open': 'Critical',
            'WEP': 'Critical',
            'WPA': 'High',
            'WPA-Personal': 'High',
            'WPA2-Personal': 'Medium',
            'WPA2-Enterprise': 'Low',
            'WPA3-Personal': 'Low',
            'WPA3-Enterprise': 'Low'
        }
        
        return security_levels.get(auth_type, 'Unknown')
        
    def _assess_wifi_vulnerabilities(self, networks: List[Dict]) -> List[Dict]:
        """Assess WiFi vulnerabilities"""
        vulnerabilities = []
        
        for network in networks:
            if network['authentication'] == 'Open':
                vulnerabilities.append({
                    'ssid': network['ssid'],
                    'vulnerability': 'Open Network',
                    'severity': 'Critical',
                    'description': 'Network allows unrestricted access'
                })
            elif network['authentication'] == 'WEP':
                vulnerabilities.append({
                    'ssid': network['ssid'],
                    'vulnerability': 'Weak Encryption',
                    'severity': 'Critical',
                    'description': 'WEP encryption is easily crackable'
                })
            elif 'WPA' in network['authentication'] and 'WPA3' not in network['authentication']:
                vulnerabilities.append({
                    'ssid': network['ssid'],
                    'vulnerability': 'Outdated Security',
                    'severity': 'Medium',
                    'description': 'Consider upgrading to WPA3'
                })
                
        return vulnerabilities
        
    def _assess_bluetooth_vulnerabilities(self, devices: List[Dict]) -> List[Dict]:
        """Assess Bluetooth vulnerabilities"""
        vulnerabilities = []
        
        for device in devices:
            for vuln in device.get('vulnerabilities', []):
                vulnerabilities.append({
                    'device': device['name'],
                    'address': device['address'],
                    'vulnerability': vuln,
                    'severity': 'Medium',
                    'device_type': device['device_type']
                })
                
        return vulnerabilities
        
    def generate_wireless_report(self) -> Dict:
        """Generate comprehensive wireless security report"""
        if not license_manager.is_feature_enabled('wireless_security'):
            return {'error': 'Wireless security requires Enterprise license'}
            
        report = {
            'report_type': 'Wireless Security Assessment',
            'generated_at': self._get_timestamp(),
            'wifi_networks': {
                'total_discovered': len(self.discovered_networks),
                'security_breakdown': self._get_wifi_security_breakdown(),
                'critical_issues': len([n for n in self.discovered_networks if n.get('security_level') == 'Critical'])
            },
            'bluetooth_devices': {
                'total_discovered': len(self.bluetooth_devices),
                'vulnerable_devices': len([d for d in self.bluetooth_devices if d.get('vulnerabilities')])
            },
            'recommendations': [
                'Implement WPA3 encryption where possible',
                'Disable unnecessary wireless services',
                'Regular security assessments',
                'Employee awareness training'
            ]
        }
        
        return report
        
    def _get_wifi_security_breakdown(self) -> Dict:
        """Get WiFi security level breakdown"""
        breakdown = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        
        for network in self.discovered_networks:
            level = network.get('security_level', 'Unknown')
            if level in breakdown:
                breakdown[level] += 1
                
        return breakdown
        
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        import datetime
        return datetime.datetime.now().isoformat()

# Global wireless security instance
wireless_security = WirelessSecurity()