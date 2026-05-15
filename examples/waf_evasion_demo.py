#!/usr/bin/env python3
"""
WAF Evasion Engine Demonstration
Phase 3: Advanced Features - WAF Evasion Engine

This script demonstrates the enhanced WAF evasion capabilities of the Huginn Advanced Security Scanner.
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from app.core.evasion_engine import EvasionEngine

def demonstrate_waf_evasion():
    """Demonstrate advanced WAF evasion techniques"""
    
    print("🛡️ Huginn Advanced WAF Evasion Engine - Phase 3 Demo")
    print("=" * 60)
    
    # Initialize the evasion engine
    evasion_engine = EvasionEngine()
    
    # Test payloads
    test_payloads = [
        "<script>alert('XSS')</script>",
        "' OR 1=1--",
        "UNION SELECT * FROM users",
        "../../../etc/passwd",
        "javascript:alert(1)"
    ]
    
    print("\n1. Basic WAF Evasion Techniques")
    print("-" * 40)
    
    for payload in test_payloads[:2]:  # Limit for demo
        print(f"\nOriginal payload: {payload}")
        
        # Generate multiple bypass variants
        variants = evasion_engine.create_waf_bypass_variants(payload)
        
        for i, variant in enumerate(variants[:3], 1):  # Show first 3 variants
            print(f"  Variant {i}: {variant}")
    
    print("\n2. WAF-Specific Bypass Techniques")
    print("-" * 40)
    
    # Test WAF-specific bypasses
    waf_types = ['cloudflare', 'aws_waf', 'akamai']
    test_payload = "<script>alert(1)</script>"
    
    for waf_type in waf_types:
        print(f"\n{waf_type.upper()} WAF Bypass:")
        evaded = evasion_engine.evade_payload(test_payload, 'auto', waf_type)
        print(f"  Original: {test_payload}")
        print(f"  Evaded:   {evaded}")
        
        # Generate bypass headers
        headers = evasion_engine.generate_waf_bypass_headers(waf_type)
        print(f"  Headers:  {list(headers.keys())[:3]}...")  # Show first 3 headers
    
    print("\n3. Advanced Payload Generation")
    print("-" * 40)
    
    # Generate advanced bypass payload
    advanced_payload = evasion_engine.generate_advanced_bypass_payload(
        "<script>alert('test')</script>", 
        target_type='xss', 
        waf_type='cloudflare'
    )
    
    print(f"Original: {advanced_payload['original']}")
    print(f"WAF Type: {advanced_payload['waf_type']}")
    print(f"Variants generated: {len(advanced_payload['variants'])}")
    
    for i, variant in enumerate(advanced_payload['variants'][:3], 1):
        print(f"  Variant {i}: {variant['payload'][:50]}...")
        print(f"    Encoding: {variant['encoding']}")
        print(f"    Confidence: {variant['confidence']:.2f}")
    
    print("\n4. WAF Detection Simulation")
    print("-" * 40)
    
    # Simulate WAF detection
    mock_headers = {
        'cf-ray': '12345-DFW',
        'server': 'cloudflare',
        'cf-cache-status': 'DYNAMIC'
    }
    
    detected_waf = evasion_engine.detect_waf_type(mock_headers)
    print(f"Detected WAF: {detected_waf}")
    
    # Test bypass effectiveness simulation
    mock_responses = [
        {'status_code': 403, 'body': 'blocked by security policy'},
        {'status_code': 200, 'body': 'success', 'technique': 'unicode_encode'},
        {'status_code': 200, 'body': 'success', 'technique': 'case_variation'},
        {'status_code': 403, 'body': 'forbidden'}
    ]
    
    effectiveness = evasion_engine.test_waf_bypass_effectiveness(True, mock_responses)
    print(f"Bypass effectiveness: {effectiveness['success_rate']}")
    print(f"Successful techniques: {effectiveness['best_techniques']}")
    
    print("\n5. Transformation Chains")
    print("-" * 40)
    
    # Demonstrate transformation chains
    base_payload = "SELECT * FROM users WHERE id=1"
    print(f"Base payload: {base_payload}")
    
    # Apply transformation chain
    transformed = base_payload
    chain = ['case_variation', 'comment_insertion', 'keyword_fragmentation']
    
    for technique in chain:
        transformed = evasion_engine.evade_payload(transformed, technique)
        print(f"After {technique}: {transformed}")
    
    print("\n🎯 WAF Evasion Engine Features:")
    print("✅ 12+ bypass techniques implemented")
    print("✅ WAF detection from headers/responses")
    print("✅ Payload transformation chains")
    print("✅ Target-specific optimizations")
    print("✅ Effectiveness testing")
    print("✅ Advanced header manipulation")
    
    print("\n🚀 Phase 3 Advanced Features: COMPLETED")

if __name__ == "__main__":
    demonstrate_waf_evasion()