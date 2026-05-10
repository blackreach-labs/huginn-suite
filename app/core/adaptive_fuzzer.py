import asyncio
import random
from urllib.parse import quote
from app.core.logger import logger

class AdaptiveFuzzer:
    """Adaptive fuzzing engine that learns from responses"""
    
    def __init__(self):
        self.base_payloads = [
            # XSS payloads
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            "';alert(1);//",
            
            # SQL injection payloads
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "admin'--",
            
            # Command injection
            '; id',
            '| whoami',
            '`id`',
            
            # Path traversal
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            
            # SSTI payloads
            '{{7*7}}',
            '${7*7}',
            '#{7*7}'
        ]
        
        self.mutation_strategies = [
            'case_variation',
            'encoding_variation',
            'length_variation',
            'character_substitution',
            'payload_combination'
        ]
    
    async def adaptive_fuzz(self, session, parameters, baseline_responses=None):
        """Perform adaptive fuzzing based on application responses"""
        findings = []
        successful_payloads = []
        
        for url, forms in parameters.items():
            for form in forms:
                for input_field in form['inputs']:
                    if input_field['type'] in ['text', 'search', 'email', 'url']:
                        # Get baseline response
                        baseline = await self._get_baseline_response(session, form, input_field)
                        if not baseline:
                            continue
                        
                        # Adaptive fuzzing rounds
                        round_findings = await self._fuzz_parameter_adaptive(
                            session, form, input_field, baseline, successful_payloads
                        )
                        findings.extend(round_findings)
                        
                        # Learn from successful payloads
                        for finding in round_findings:
                            if 'payload' in finding:
                                successful_payloads.append(finding['payload'])
        
        return findings
    
    async def _get_baseline_response(self, session, form, input_field):
        """Get baseline response for comparison"""
        try:
            data = {input_field['name']: 'test'}
            
            if form['method'].lower() == 'post':
                async with session.post(form['action'], data=data) as response:
                    return {
                        'status': response.status,
                        'content': await response.text(),
                        'headers': dict(response.headers)
                    }
            else:
                params = {input_field['name']: 'test'}
                async with session.get(form['action'], params=params) as response:
                    return {
                        'status': response.status,
                        'content': await response.text(),
                        'headers': dict(response.headers)
                    }
        except:
            return None
    
    async def _fuzz_parameter_adaptive(self, session, form, input_field, baseline, successful_payloads):
        """Adaptive fuzzing for individual parameter"""
        findings = []
        tested_payloads = set()
        
        # Start with base payloads
        current_payloads = self.base_payloads.copy()
        
        # Add successful payloads from previous tests
        if successful_payloads:
            current_payloads.extend(successful_payloads[-5:])  # Last 5 successful
        
        for round_num in range(3):  # 3 adaptive rounds
            round_findings = []
            
            for payload in current_payloads[:10]:  # Limit per round
                if payload in tested_payloads:
                    continue
                tested_payloads.add(payload)
                
                try:
                    data = {input_field['name']: payload}
                    
                    if form['method'].lower() == 'post':
                        async with session.post(form['action'], data=data) as response:
                            content = await response.text()
                            result = self._analyze_fuzzing_response(
                                content, response.status, payload, form, input_field, baseline
                            )
                            if result:
                                round_findings.append(result)
                                findings.append(result)
                    else:
                        params = {input_field['name']: payload}
                        async with session.get(form['action'], params=params) as response:
                            content = await response.text()
                            result = self._analyze_fuzzing_response(
                                content, response.status, payload, form, input_field, baseline
                            )
                            if result:
                                round_findings.append(result)
                                findings.append(result)
                    
                    await asyncio.sleep(0.1)
                    
                except Exception:
                    continue
            
            # Adapt payloads based on round results
            if round_findings:
                current_payloads = self._generate_adaptive_payloads(round_findings, current_payloads)
            else:
                # No findings, try different mutation strategies
                current_payloads = self._mutate_payloads(current_payloads)
        
        return findings
    
    def _analyze_fuzzing_response(self, content, status, payload, form, input_field, baseline):
        """Analyze fuzzing response for vulnerabilities"""
        # Check for significant differences from baseline
        baseline_content = baseline['content']
        baseline_status = baseline['status']
        
        # XSS detection
        if payload in content and any(tag in payload for tag in ['<script', '<img', '<svg']):
            return {
                'type': 'Adaptive Fuzzing - XSS',
                'severity': 'HIGH',
                'url': form['action'],
                'parameter': input_field['name'],
                'payload': payload,
                'description': f'Adaptive fuzzing detected XSS vulnerability',
                'recommendation': 'Implement proper input sanitization'
            }
        
        # SQL injection detection
        sql_errors = ['sql syntax', 'mysql_fetch', 'ora-01756', 'sqlite_exception']
        if any(error in content.lower() for error in sql_errors):
            return {
                'type': 'Adaptive Fuzzing - SQL Injection',
                'severity': 'CRITICAL',
                'url': form['action'],
                'parameter': input_field['name'],
                'payload': payload,
                'description': f'Adaptive fuzzing detected SQL injection vulnerability',
                'recommendation': 'Use parameterized queries and input validation'
            }
        
        # Command injection detection
        if any(indicator in content for indicator in ['uid=', 'gid=', '/bin/bash']):
            return {
                'type': 'Adaptive Fuzzing - Command Injection',
                'severity': 'CRITICAL',
                'url': form['action'],
                'parameter': input_field['name'],
                'payload': payload,
                'description': f'Adaptive fuzzing detected command injection vulnerability',
                'recommendation': 'Avoid system command execution with user input'
            }
        
        # SSTI detection
        if '49' in content and ('7*7' in payload or '{{7*7}}' in payload):
            return {
                'type': 'Adaptive Fuzzing - SSTI',
                'severity': 'HIGH',
                'url': form['action'],
                'parameter': input_field['name'],
                'payload': payload,
                'description': f'Adaptive fuzzing detected SSTI vulnerability',
                'recommendation': 'Sanitize template input and use sandboxing'
            }
        
        # Error-based detection
        if (status != baseline_status or 
            abs(len(content) - len(baseline_content)) > 100):
            
            error_indicators = ['error', 'exception', 'warning', 'fatal']
            if any(indicator in content.lower() for indicator in error_indicators):
                return {
                    'type': 'Adaptive Fuzzing - Error Response',
                    'severity': 'MEDIUM',
                    'url': form['action'],
                    'parameter': input_field['name'],
                    'payload': payload,
                    'description': f'Adaptive fuzzing triggered error response',
                    'recommendation': 'Review error handling and input validation'
                }
        
        return None
    
    def _generate_adaptive_payloads(self, successful_findings, current_payloads):
        """Generate new payloads based on successful findings"""
        new_payloads = []
        
        for finding in successful_findings:
            payload = finding.get('payload', '')
            if payload:
                # Generate variations of successful payload
                variations = self._create_payload_variations(payload)
                new_payloads.extend(variations[:3])  # Limit variations
        
        # Combine with existing payloads
        return new_payloads + current_payloads[:5]
    
    def _create_payload_variations(self, payload):
        """Create variations of a successful payload"""
        variations = []
        
        # Case variations
        variations.append(payload.upper())
        variations.append(payload.lower())
        
        # Encoding variations
        try:
            variations.append(quote(payload))
            variations.append(payload.replace(' ', '+'))
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        
        # Character substitutions
        substitutions = {
            '<': '%3C',
            '>': '%3E',
            '"': '%22',
            "'": '%27'
        }
        
        for char, encoded in substitutions.items():
            if char in payload:
                variations.append(payload.replace(char, encoded))
        
        return variations[:5]  # Limit variations
    
    def _mutate_payloads(self, payloads):
        """Mutate payloads when no findings occur"""
        mutated = []
        
        for payload in payloads[:5]:
            # Random character insertion
            if len(payload) > 5:
                pos = random.randint(1, len(payload) - 1)
                mutated.append(payload[:pos] + 'X' + payload[pos:])
            
            # Random character substitution
            if payload:
                chars = list(payload)
                if chars:
                    pos = random.randint(0, len(chars) - 1)
                    chars[pos] = chr(ord(chars[pos]) + 1)
                    mutated.append(''.join(chars))
        
        return mutated + payloads