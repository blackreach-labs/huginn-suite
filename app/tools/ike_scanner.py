"""
IKE Enumeration Scanner
Provides IKE/IPSec enumeration capabilities using ike-scan
"""

import socket
import logging
import subprocess
from typing import Dict, List, Optional, Any
import re

logger = logging.getLogger(__name__)

class IKEScanner:
    """IKE/IPSec enumeration scanner"""
    
    def __init__(self):
        self.timeout = 30
        self.default_port = 500
        
    def scan_ike_basic(self, target: str, port: int = 500) -> Dict[str, Any]:
        """Basic IKE service detection"""
        results = {
            'target': target,
            'port': port,
            'service': 'ike',
            'accessible': False,
            'ike_scan_available': False,
            'error': None
        }
        
        try:
            # Check if ike-scan is available
            if not self._check_ike_scan_available():
                results['error'] = "ike-scan tool not available"
                return results
            
            results['ike_scan_available'] = True
            
            # Test basic UDP connectivity to IKE port
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            
            # Send a basic UDP packet to test connectivity
            try:
                sock.sendto(b'\x00', (target, port))
                sock.close()
                results['accessible'] = True
            except Exception:
                # UDP doesn't guarantee response, so we'll rely on ike-scan
                results['accessible'] = True
                sock.close()
                
        except Exception as e:
            results['error'] = str(e)
            logger.error(f"IKE basic scan error for {target}:{port} - {e}")
            
        return results
    
    def scan_ike_detailed(self, target: str, port: int = 500, 
                         aggressive_mode: bool = True) -> Dict[str, Any]:
        """Detailed IKE enumeration using ike-scan"""
        results = {
            'target': target,
            'port': port,
            'ike_scan_available': False,
            'transforms': [],
            'vendor_ids': [],
            'handshake_type': None,
            'raw_output': None,
            'error': None
        }
        
        try:
            # Check if ike-scan is available
            if not self._check_ike_scan_available():
                results['error'] = "ike-scan tool not available"
                return results
            
            results['ike_scan_available'] = True
            
            # Build ike-scan command
            cmd = ['ike-scan', target]
            
            if aggressive_mode:
                cmd.append('-M')  # Multiline output
            
            if port != 500:
                cmd.extend(['--dport', str(port)])
            
            # Execute ike-scan
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            
            if result.returncode == 0:
                results['raw_output'] = result.stdout
                # Parse ike-scan output
                parsed_data = self._parse_ike_scan_output(result.stdout)
                results.update(parsed_data)
            else:
                results['error'] = result.stderr or "ike-scan execution failed"
                
        except subprocess.TimeoutExpired:
            results['error'] = "ike-scan timeout"
        except Exception as e:
            results['error'] = str(e)
            logger.error(f"IKE detailed scan error for {target}:{port} - {e}")
            
        return results
    
    def scan_ike_transforms(self, target: str, port: int = 500) -> Dict[str, Any]:
        """Enumerate IKE transforms and proposals"""
        results = {
            'target': target,
            'port': port,
            'transforms': [],
            'proposals': [],
            'error': None
        }
        
        try:
            if not self._check_ike_scan_available():
                results['error'] = "ike-scan tool not available"
                return results
            
            # Scan with transform enumeration
            cmd = ['ike-scan', '--trans=1,2,3,4', target]
            if port != 500:
                cmd.extend(['--dport', str(port)])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            
            if result.returncode == 0:
                transforms = self._extract_transforms(result.stdout)
                results['transforms'] = transforms
            else:
                results['error'] = result.stderr or "Transform enumeration failed"
                
        except Exception as e:
            results['error'] = str(e)
            logger.error(f"IKE transform scan error: {e}")
            
        return results
    
    def _check_ike_scan_available(self) -> bool:
        """Check if ike-scan tool is available"""
        try:
            result = subprocess.run(['ike-scan', '--help'], 
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0 or 'usage' in result.stdout.lower()
        except:
            return False
    
    def _parse_ike_scan_output(self, output: str) -> Dict[str, Any]:
        """Parse ike-scan output for useful information"""
        parsed = {
            'transforms': [],
            'vendor_ids': [],
            'handshake_type': None
        }
        
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Look for transform information
            if 'SA=' in line:
                transforms = self._extract_sa_transforms(line)
                parsed['transforms'].extend(transforms)
            
            # Look for Vendor ID
            if 'VID=' in line:
                vendor_id = self._extract_vendor_id(line)
                if vendor_id:
                    parsed['vendor_ids'].append(vendor_id)
            
            # Detect handshake type
            if 'Main Mode' in line:
                parsed['handshake_type'] = 'Main Mode'
            elif 'Aggressive Mode' in line:
                parsed['handshake_type'] = 'Aggressive Mode'
        
        return parsed
    
    def _extract_sa_transforms(self, line: str) -> List[str]:
        """Extract SA transform information from ike-scan output"""
        transforms = []
        
        # Look for SA= patterns
        sa_match = re.search(r'SA=\((.*?)\)', line)
        if sa_match:
            sa_data = sa_match.group(1)
            # Parse transform data
            if 'Enc=' in sa_data:
                enc_match = re.search(r'Enc=([^,\)]+)', sa_data)
                if enc_match:
                    transforms.append(f"Encryption: {enc_match.group(1)}")
            
            if 'Hash=' in sa_data:
                hash_match = re.search(r'Hash=([^,\)]+)', sa_data)
                if hash_match:
                    transforms.append(f"Hash: {hash_match.group(1)}")
            
            if 'Auth=' in sa_data:
                auth_match = re.search(r'Auth=([^,\)]+)', sa_data)
                if auth_match:
                    transforms.append(f"Authentication: {auth_match.group(1)}")
            
            if 'Group=' in sa_data:
                group_match = re.search(r'Group=([^,\)]+)', sa_data)
                if group_match:
                    transforms.append(f"DH Group: {group_match.group(1)}")
        
        return transforms
    
    def _extract_vendor_id(self, line: str) -> Optional[str]:
        """Extract Vendor ID information"""
        vid_match = re.search(r'VID=([a-fA-F0-9]+)', line)
        if vid_match:
            vid_hex = vid_match.group(1)
            # Try to decode common vendor IDs
            vendor = self._decode_vendor_id(vid_hex)
            return f"{vid_hex} ({vendor})" if vendor else vid_hex
        return None
    
    def _decode_vendor_id(self, vid_hex: str) -> Optional[str]:
        """Decode common vendor IDs"""
        common_vids = {
            '4a131c81070358455c5728f20e95452f': 'RFC 3947 NAT-T',
            '90cb80913ebb696e086381b5ec427b1f': 'RFC 3947 NAT-T v02',
            '4048b7d56ebce88525e7de7f00d6c2d3': 'IKE Fragmentation',
            'afcad71368a1f1c96b8696fc77570100': 'Dead Peer Detection',
        }
        
        return common_vids.get(vid_hex.lower())
    
    def _extract_transforms(self, output: str) -> List[str]:
        """Extract transform information from output"""
        transforms = []
        
        # Common IKE transforms
        if 'DES' in output:
            transforms.append('DES Encryption')
        if '3DES' in output:
            transforms.append('3DES Encryption')
        if 'AES' in output:
            transforms.append('AES Encryption')
        if 'MD5' in output:
            transforms.append('MD5 Hash')
        if 'SHA' in output:
            transforms.append('SHA Hash')
        if 'PSK' in output:
            transforms.append('Pre-Shared Key Auth')
        if 'RSA' in output:
            transforms.append('RSA Signatures')
        
        return transforms

# Global scanner instance
ike_scanner = IKEScanner()