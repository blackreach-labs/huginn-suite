#!/usr/bin/env python3
"""
Demo of AI-driven SSTI scanning with adaptive payload generation
"""
import asyncio
from app.core.ai_payload_engine import AIPayloadEngine, ResponseType
import logging

def demo_ai_adaptation():
    """Demonstrate AI payload adaptation logic"""
    print("AI-Driven SSTI Payload Adaptation Demo")
    print("="*50)
    
    # Initialize AI engine
    ai_engine = AIPayloadEngine()
    target_url = "http://10.10.11.62:5000"
    
    # Simulate response scenarios
    scenarios = [
        {
            'name': 'WAF Block Detection',
            'payload': '{{7*7}}',
            'response': {'status_code': 403, 'content': 'Request blocked by security policy'},
            'expected_classification': ResponseType.FILTERED
        },
        {
            'name': 'Math Evaluation Success',
            'payload': '{{7*7}}',
            'response': {'status_code': 200, 'content': 'Result: 49'},
            'expected_classification': ResponseType.EVALUATED
        },
        {
            'name': 'Syntax Error',
            'payload': '{{invalid_syntax}}',
            'response': {'status_code': 500, 'content': 'TemplateSyntaxError: invalid syntax'},
            'expected_classification': ResponseType.SYNTAX_ERROR
        },
        {
            'name': 'Payload Reflection',
            'payload': '{{test}}',
            'response': {'status_code': 200, 'content': 'You entered: {{test}}'},
            'expected_classification': ResponseType.NEUTRAL
        }
    ]
    
    print("\nResponse Classification Tests:")
    for scenario in scenarios:
        result_type, next_payload = ai_engine.process_response_and_adapt(
            target_url, 
            scenario['payload'], 
            scenario['response']
        )
        
        status = "PASS" if result_type == scenario['expected_classification'] else "FAIL"
        print(f"{status} {scenario['name']}: {result_type.value}")
        if next_payload:
            print(f"   Next payload: {next_payload[:60]}...")
    
    # Demonstrate payload obfuscation
    print(f"\nPayload Obfuscation Examples:")
    strategy = ai_engine.strategy
    dangerous_token = "__class__"
    
    for method_name, method_func in strategy.obfuscation_methods.items():
        try:
            obfuscated = method_func(dangerous_token)
            print(f"   {method_name}: {dangerous_token} → {obfuscated}")
        except Exception:
            print(f"   {method_name}: Failed")
    
    # Show target intelligence
    print(f"\nTarget Intelligence for {target_url}:")
    intelligence = ai_engine.get_target_intelligence(target_url)
    print(f"   Blocked tokens: {intelligence['blocked_tokens']}")
    print(f"   Working bypasses: {intelligence['working_bypasses']}")
    print(f"   Recommended approach: {intelligence['recommended_approach']}")
    
    # Generate adaptive payloads
    print(f"\nGenerated Adaptive Payloads:")
    payload_types = ['python_class_access', 'jinja2_config', 'flask_globals']
    
    for payload_type in payload_types:
        payloads = ai_engine.generate_adaptive_payloads(target_url, payload_type)
        print(f"   {payload_type}:")
        for payload in payloads[:3]:  # Show first 3
            print(f"     • {payload}")

if __name__ == "__main__":
    demo_ai_adaptation()