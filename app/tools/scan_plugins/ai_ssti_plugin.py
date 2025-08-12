# app/tools/scan_plugins/ai_ssti_plugin.py
import asyncio
import time
from typing import Dict, List, Optional
from urllib.parse import urljoin
from app.core.ai_payload_engine import AIPayloadEngine, ResponseType

class AISSTIPlugin:
    def __init__(self, session, progress_callback=None):
        self.session = session
        self.progress_callback = progress_callback
        self.ai_engine = AIPayloadEngine()
        self.max_adaptation_rounds = 5
        self.ssl_verify = False
        
    async def scan(self, target_url: str, endpoints: List[str] = None) -> Dict:
        """AI-driven SSTI scanning with adaptive payload generation"""
        results = {
            'vulnerabilities': [],
            'ai_intelligence': {},
            'adaptation_history': []
        }
        
        # Get test endpoints
        test_endpoints = endpoints or self._discover_endpoints(target_url)
        
        for endpoint in test_endpoints:
            if self.progress_callback:
                self.progress_callback(f"AI SSTI testing: {endpoint}")
                
            endpoint_results = await self._test_endpoint_adaptive(target_url, endpoint)
            if endpoint_results['vulnerable']:
                results['vulnerabilities'].append(endpoint_results)
                
            results['adaptation_history'].extend(endpoint_results['adaptation_history'])
        
        # Get accumulated intelligence
        results['ai_intelligence'] = self.ai_engine.get_target_intelligence(target_url)
        
        return results
    
    async def _test_endpoint_adaptive(self, target_url: str, endpoint: str) -> Dict:
        """Test single endpoint with AI adaptation"""
        result = {
            'endpoint': endpoint,
            'vulnerable': False,
            'vulnerability_type': None,
            'successful_payload': None,
            'adaptation_history': [],
            'response_classifications': []
        }
        
        # Test different payload types
        payload_types = ['python_class_access', 'jinja2_config', 'flask_globals']
        
        for payload_type in payload_types:
            # Generate initial payloads
            initial_payloads = self.ai_engine.generate_adaptive_payloads(target_url, payload_type)
            
            for initial_payload in initial_payloads:
                adaptation_result = await self._adaptive_payload_loop(
                    target_url, endpoint, initial_payload, payload_type
                )
                
                result['adaptation_history'].extend(adaptation_result['history'])
                result['response_classifications'].extend(adaptation_result['classifications'])
                
                if adaptation_result['success']:
                    result['vulnerable'] = True
                    result['vulnerability_type'] = payload_type
                    result['successful_payload'] = adaptation_result['final_payload']
                    return result
        
        return result
    
    async def _adaptive_payload_loop(self, target_url: str, endpoint: str, 
                                   initial_payload: str, payload_type: str) -> Dict:
        """Adaptive payload testing loop with AI-driven modifications"""
        loop_result = {
            'success': False,
            'final_payload': None,
            'history': [],
            'classifications': []
        }
        
        current_payload = initial_payload
        round_count = 0
        
        while round_count < self.max_adaptation_rounds:
            round_count += 1
            
            # Test current payload
            response_data = await self._test_payload(endpoint, current_payload)
            
            # AI classification and adaptation
            result_type, next_payload = self.ai_engine.process_response_and_adapt(
                target_url, current_payload, response_data, payload_type
            )
            
            # Record this round
            round_info = {
                'round': round_count,
                'payload': current_payload,
                'response_type': result_type.value,
                'status_code': response_data.get('status_code', 0),
                'content_length': len(response_data.get('content', '')),
                'next_payload': next_payload
            }
            
            loop_result['history'].append(round_info)
            loop_result['classifications'].append(result_type.value)
            
            # Check for success
            if result_type == ResponseType.EVALUATED:
                loop_result['success'] = True
                loop_result['final_payload'] = current_payload
                break
            elif result_type == ResponseType.EXECUTED:
                loop_result['success'] = True
                loop_result['final_payload'] = current_payload
                break
            
            # No more adaptations possible
            if not next_payload or next_payload == current_payload:
                break
                
            current_payload = next_payload
            
            # Brief delay between rounds
            await asyncio.sleep(0.5)
        
        return loop_result
    
    async def _test_payload(self, endpoint: str, payload: str) -> Dict:
        """Test single payload against endpoint"""
        response_data = {
            'status_code': 0,
            'content': '',
            'headers': {},
            'connection_error': False
        }
        
        try:
            # Test GET parameter injection
            get_response = await self._test_get_injection(endpoint, payload)
            if get_response:
                response_data.update(get_response)
                return response_data
            
            # Test POST parameter injection
            post_response = await self._test_post_injection(endpoint, payload)
            if post_response:
                response_data.update(post_response)
                return response_data
                
        except Exception as e:
            response_data['connection_error'] = True
            response_data['error'] = str(e)
        
        return response_data
    
    async def _test_get_injection(self, endpoint: str, payload: str) -> Optional[Dict]:
        """Test GET parameter injection"""
        test_params = ['q', 'search', 'name', 'value', 'data', 'input']
        
        for param in test_params:
            try:
                response = self.session.get(
                    endpoint,
                    params={param: payload},
                    timeout=10,
                    verify=self.ssl_verify
                )
                
                return {
                    'status_code': response.status_code,
                    'content': response.text,
                    'headers': dict(response.headers),
                    'method': 'GET',
                    'parameter': param
                }
            except:
                continue
        
        return None
    
    async def _test_post_injection(self, endpoint: str, payload: str) -> Optional[Dict]:
        """Test POST parameter injection"""
        test_params = ['q', 'search', 'name', 'value', 'data', 'input']
        
        for param in test_params:
            try:
                response = self.session.post(
                    endpoint,
                    data={param: payload},
                    timeout=10,
                    verify=self.ssl_verify
                )
                
                return {
                    'status_code': response.status_code,
                    'content': response.text,
                    'headers': dict(response.headers),
                    'method': 'POST',
                    'parameter': param
                }
            except:
                continue
        
        return None
    
    def _discover_endpoints(self, target_url: str) -> List[str]:
        """Discover potential SSTI test endpoints"""
        common_endpoints = [
            '/',
            '/search',
            '/contact',
            '/feedback',
            '/login',
            '/register',
            '/profile',
            '/settings'
        ]
        
        return [urljoin(target_url, endpoint) for endpoint in common_endpoints]
    
    def get_scan_summary(self, results: Dict) -> str:
        """Generate human-readable scan summary"""
        vuln_count = len(results['vulnerabilities'])
        intelligence = results['ai_intelligence']
        
        summary = f"AI SSTI Scan Results:\n"
        summary += f"- Vulnerabilities found: {vuln_count}\n"
        summary += f"- Blocked tokens identified: {len(intelligence.get('blocked_tokens', []))}\n"
        summary += f"- Working bypasses: {len(intelligence.get('working_bypasses', {}))}\n"
        summary += f"- Recommended approach: {intelligence.get('recommended_approach', 'unknown')}\n"
        
        if vuln_count > 0:
            summary += "\nVulnerable endpoints:\n"
            for vuln in results['vulnerabilities']:
                summary += f"  - {vuln['endpoint']} ({vuln['vulnerability_type']})\n"
        
        return summary