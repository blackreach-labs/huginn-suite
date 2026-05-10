import asyncio
from typing import Dict, List, Optional
from app.core.logger import logger

class AdaptiveScanner:
    """Adaptive scanning engine that learns from responses"""
    
    def __init__(self, session):
        self.session = session
        self.learned_patterns = {}
        self.success_indicators = []
        self.failure_indicators = []
    
    async def adaptive_fuzz(self, url: str, param: str, base_payloads: List[str]) -> List[Dict]:
        """Adaptive fuzzing that learns from responses"""
        vulnerabilities = []
        successful_patterns = []
        
        # Test base payloads first
        for payload in base_payloads[:3]:
            result = await self._test_payload(url, param, payload)
            if result:
                vulnerabilities.append(result)
                successful_patterns.append(self._extract_pattern(payload))
        
        # Generate adaptive payloads based on successful patterns
        if successful_patterns:
            adaptive_payloads = self._generate_adaptive_payloads(successful_patterns)
            for payload in adaptive_payloads:
                result = await self._test_payload(url, param, payload)
                if result:
                    vulnerabilities.append(result)
        
        return vulnerabilities
    
    async def _test_payload(self, url: str, param: str, payload: str) -> Optional[Dict]:
        """Test individual payload and learn from response"""
        try:
            test_url = f"{url}?{param}={payload}"
            async with self.session.get(test_url) as resp:
                content = await resp.text()
                
                # Learn from response
                self._learn_from_response(payload, content, resp.status)
                
                # Check for vulnerability indicators
                if self._is_vulnerable_response(content, resp.status):
                    return {
                        'type': 'Adaptive Detection',
                        'severity': 'High',
                        'description': f'Vulnerability detected via adaptive fuzzing in {param}',
                        'payload': payload,
                        'cvss_score': 7.5,
                        'remediation': 'Implement proper input validation'
                    }
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        
        return None
    
    def _learn_from_response(self, payload: str, content: str, status: int):
        """Learn patterns from response"""
        if status == 500 or 'error' in content.lower():
            self.failure_indicators.append(payload[:10])  # Store pattern prefix
        elif len(content) > 1000 and status == 200:
            self.success_indicators.append(payload[:10])
    
    def _extract_pattern(self, payload: str) -> str:
        """Extract pattern from successful payload"""
        if '<script>' in payload:
            return 'script_injection'
        elif "'" in payload:
            return 'quote_injection'
        elif '../' in payload:
            return 'path_traversal'
        return 'generic'
    
    def _generate_adaptive_payloads(self, patterns: List[str]) -> List[str]:
        """Generate new payloads based on learned patterns"""
        adaptive_payloads = []
        
        if 'script_injection' in patterns:
            adaptive_payloads.extend([
                '<img src=x onerror=alert(document.domain)>',
                '<svg/onload=alert(String.fromCharCode(88,83,83))>'
            ])
        
        if 'quote_injection' in patterns:
            adaptive_payloads.extend([
                "' AND SLEEP(5)--",
                "' UNION SELECT user(),version()--"
            ])
        
        return adaptive_payloads
    
    def _is_vulnerable_response(self, content: str, status: int) -> bool:
        """Determine if response indicates vulnerability"""
        vuln_indicators = [
            'syntax error', 'mysql', 'oracle', 'postgresql',
            'alert(', 'onerror=', 'root:', 'admin:'
        ]
        
        return any(indicator in content.lower() for indicator in vuln_indicators)