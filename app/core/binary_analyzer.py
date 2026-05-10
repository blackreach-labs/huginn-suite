import re
import struct
from typing import Dict, List, Optional, Tuple
from app.core.logger import logger

class BinaryAnalyzer:
    """Binary analysis and protocol-level testing capabilities"""
    
    def __init__(self):
        self.known_signatures = {
            'elf': b'\x7fELF',
            'pe': b'MZ',
            'pdf': b'%PDF',
            'zip': b'PK\x03\x04',
            'png': b'\x89PNG',
            'jpeg': b'\xff\xd8\xff',
            'gif': b'GIF8'
        }
    
    def analyze_binary_response(self, response_data: bytes) -> Dict:
        """Analyze binary response for security issues"""
        analysis = {
            'file_type': self._detect_file_type(response_data),
            'embedded_strings': self._extract_strings(response_data),
            'potential_vulnerabilities': [],
            'metadata': {}
        }
        
        # Check for embedded credentials
        credentials = self._find_embedded_credentials(response_data)
        if credentials:
            analysis['potential_vulnerabilities'].extend(credentials)
        
        # Check for debug information
        debug_info = self._find_debug_information(response_data)
        if debug_info:
            analysis['potential_vulnerabilities'].extend(debug_info)
        
        # Analyze file structure
        if analysis['file_type'] in ['pe', 'elf']:
            analysis['metadata'] = self._analyze_executable(response_data, analysis['file_type'])
        
        return analysis
    
    def _detect_file_type(self, data: bytes) -> str:
        """Detect file type from binary signature"""
        for file_type, signature in self.known_signatures.items():
            if data.startswith(signature):
                return file_type
        return 'unknown'
    
    def _extract_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """Extract printable strings from binary data"""
        strings = []
        current_string = b''
        
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += bytes([byte])
            else:
                if len(current_string) >= min_length:
                    try:
                        strings.append(current_string.decode('ascii'))
                    except Exception as _exc:
                        pass
                        logger.debug("Suppressed exception", exc_info=True)
                current_string = b''
        
        # Don't forget the last string
        if len(current_string) >= min_length:
            try:
                strings.append(current_string.decode('ascii'))
            except Exception as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        
        return strings[:100]  # Limit results
    
    def _find_embedded_credentials(self, data: bytes) -> List[Dict]:
        """Find potential embedded credentials in binary data"""
        vulnerabilities = []
        strings = self._extract_strings(data)
        
        credential_patterns = [
            (r'password\s*[:=]\s*["\']?([^"\'\s]+)', 'Embedded Password'),
            (r'api[_-]?key\s*[:=]\s*["\']?([^"\'\s]+)', 'Embedded API Key'),
            (r'secret\s*[:=]\s*["\']?([^"\'\s]+)', 'Embedded Secret'),
            (r'token\s*[:=]\s*["\']?([^"\'\s]+)', 'Embedded Token'),
            (r'mysql://([^:]+):([^@]+)@', 'Database Connection String'),
            (r'postgresql://([^:]+):([^@]+)@', 'Database Connection String')
        ]
        
        for string in strings:
            for pattern, vuln_type in credential_patterns:
                matches = re.findall(pattern, string, re.IGNORECASE)
                if matches:
                    vulnerabilities.append({
                        'type': vuln_type,
                        'severity': 'Critical',
                        'description': f'Found embedded credential in binary: {string[:50]}...',
                        'cvss_score': 9.8,
                        'remediation': 'Remove hardcoded credentials from binary files'
                    })
        
        return vulnerabilities
    
    def _find_debug_information(self, data: bytes) -> List[Dict]:
        """Find debug information leakage"""
        vulnerabilities = []
        strings = self._extract_strings(data)
        
        debug_indicators = [
            'debug', 'test', 'development', 'staging',
            '/home/', '/Users/', 'C:\\Users\\', 'C:\\temp\\',
            '.pdb', '.map', '__FILE__', '__LINE__'
        ]
        
        for string in strings:
            for indicator in debug_indicators:
                if indicator.lower() in string.lower():
                    vulnerabilities.append({
                        'type': 'Debug Information Disclosure',
                        'severity': 'Medium',
                        'description': f'Debug information found: {string[:50]}...',
                        'cvss_score': 5.3,
                        'remediation': 'Remove debug information from production binaries'
                    })
                    break  # Only report once per string
        
        return vulnerabilities
    
    def _analyze_executable(self, data: bytes, file_type: str) -> Dict:
        """Analyze executable file structure"""
        metadata = {}
        
        if file_type == 'pe':
            metadata = self._analyze_pe_file(data)
        elif file_type == 'elf':
            metadata = self._analyze_elf_file(data)
        
        return metadata
    
    def _analyze_pe_file(self, data: bytes) -> Dict:
        """Basic PE file analysis"""
        try:
            # PE header starts at offset specified in DOS header
            dos_header = struct.unpack('<H', data[0:2])[0]
            if dos_header != 0x5A4D:  # 'MZ'
                return {}
            
            pe_offset = struct.unpack('<L', data[60:64])[0]
            pe_signature = struct.unpack('<L', data[pe_offset:pe_offset+4])[0]
            
            if pe_signature != 0x00004550:  # 'PE\0\0'
                return {}
            
            # Basic PE info
            machine = struct.unpack('<H', data[pe_offset+4:pe_offset+6])[0]
            timestamp = struct.unpack('<L', data[pe_offset+8:pe_offset+12])[0]
            
            return {
                'format': 'PE',
                'machine_type': hex(machine),
                'timestamp': timestamp,
                'analysis': 'Basic PE structure detected'
            }
        except:
            return {'error': 'Failed to parse PE file'}
    
    def _analyze_elf_file(self, data: bytes) -> Dict:
        """Basic ELF file analysis"""
        try:
            if not data.startswith(b'\x7fELF'):
                return {}
            
            # ELF header analysis
            ei_class = data[4]  # 32-bit or 64-bit
            ei_data = data[5]   # Endianness
            e_type = struct.unpack('<H' if ei_data == 1 else '>H', data[16:18])[0]
            
            return {
                'format': 'ELF',
                'class': '64-bit' if ei_class == 2 else '32-bit',
                'endianness': 'little' if ei_data == 1 else 'big',
                'type': e_type,
                'analysis': 'Basic ELF structure detected'
            }
        except:
            return {'error': 'Failed to parse ELF file'}
    
    def test_protocol_fuzzing(self, target_url: str, protocol: str = 'http') -> List[Dict]:
        """Perform protocol-level fuzzing tests"""
        vulnerabilities = []
        
        if protocol == 'http':
            vulnerabilities.extend(self._test_http_protocol_fuzzing(target_url))
        
        return vulnerabilities
    
    def _test_http_protocol_fuzzing(self, target_url: str) -> List[Dict]:
        """Test HTTP protocol-level vulnerabilities"""
        # This would integrate with the main scanner's session
        # For now, return conceptual test cases
        
        protocol_tests = [
            {
                'test': 'HTTP Request Smuggling',
                'description': 'Test for HTTP request smuggling vulnerabilities',
                'payloads': [
                    'Content-Length: 0\r\nContent-Length: 44\r\n\r\nGET /admin HTTP/1.1\r\nHost: vulnerable.com\r\n\r\n',
                    'Transfer-Encoding: chunked\r\nContent-Length: 44\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: vulnerable.com\r\n\r\n'
                ]
            },
            {
                'test': 'HTTP Response Splitting',
                'description': 'Test for HTTP response splitting vulnerabilities',
                'payloads': [
                    'test\r\nSet-Cookie: admin=true',
                    'test\r\n\r\n<script>alert(1)</script>'
                ]
            }
        ]
        
        return []  # Would return actual test results in full implementation