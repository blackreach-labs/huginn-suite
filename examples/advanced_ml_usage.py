#!/usr/bin/env python3
"""
Advanced ML and Zero-Day Discovery Usage Examples
Demonstrates Phase 7 machine learning and fuzzing capabilities
"""

import asyncio
from app.tools.huginn_vuln_scanner import HuginnVulnScanner
from app.core.ml_vulnerability_predictor import MLVulnerabilityPredictor
from app.core.zero_day_fuzzer import ZeroDayFuzzer

async def ml_behavioral_analysis_demo():
    """Demonstrate ML-based behavioral analysis"""
    print("=== ML BEHAVIORAL ANALYSIS ===")
    
    scanner = HuginnVulnScanner('https://demo.testfire.net', profile='aggressive')
    results = await scanner.scan()
    
    # Show ML predictions
    ml_vulns = [v for v in results['vulnerabilities'] if 'ML-Predicted' in v.get('type', '')]
    print(f"ML Predictions: {len(ml_vulns)}")
    
    for vuln in ml_vulns:
        print(f"- {vuln['type']}: {vuln['description']}")
        print(f"  Confidence: {vuln.get('confidence', 'N/A')}")
        print(f"  Indicators: {vuln.get('indicators', [])}")

async def zero_day_fuzzing_demo():
    """Demonstrate zero-day discovery fuzzing"""
    print("\n=== ZERO-DAY DISCOVERY FUZZING ===")
    
    fuzzer = ZeroDayFuzzer()
    
    # Generate various fuzzing payloads
    boundary_payloads = fuzzer.generate_boundary_payloads()
    format_payloads = fuzzer.generate_format_string_payloads()
    buffer_payloads = fuzzer.generate_buffer_overflow_payloads()
    
    print(f"Generated {len(boundary_payloads)} boundary test cases")
    print(f"Generated {len(format_payloads)} format string payloads")
    print(f"Generated {len(buffer_payloads)} buffer overflow payloads")
    
    # Evolutionary fuzzing example
    seed_payloads = ['test', '<script>', "' OR 1=1"]
    evolved_payloads = fuzzer.generate_evolutionary_payloads(seed_payloads, generations=3)
    
    print(f"Evolved {len(seed_payloads)} seed payloads into {len(evolved_payloads)} variants")
    print("Sample evolved payloads:")
    for payload in evolved_payloads[:5]:
        print(f"  - {repr(payload)}")

async def advanced_scanner_demo():
    """Demonstrate advanced scanner with all Phase 7 features"""
    print("\n=== ADVANCED SCANNER WITH ML & FUZZING ===")
    
    # Use insane profile for maximum coverage
    scanner = HuginnVulnScanner('https://demo.testfire.net', profile='insane')
    results = await scanner.scan()
    
    print(f"Total vulnerabilities found: {len(results['vulnerabilities'])}")
    
    # Categorize findings by advanced techniques
    categories = {
        'Traditional': 0,
        'ML-Predicted': 0,
        'Zero-Day': 0,
        'Binary Analysis': 0,
        'AI-Enhanced': 0
    }
    
    for vuln in results['vulnerabilities']:
        vuln_type = vuln.get('type', '')
        if 'ML-Predicted' in vuln_type:
            categories['ML-Predicted'] += 1
        elif 'Zero-Day' in vuln_type:
            categories['Zero-Day'] += 1
        elif 'Binary' in vuln_type:
            categories['Binary Analysis'] += 1
        elif any(keyword in vuln_type for keyword in ['AI', 'Adaptive', 'Pattern']):
            categories['AI-Enhanced'] += 1
        else:
            categories['Traditional'] += 1
    
    print("\nFindings by detection method:")
    for category, count in categories.items():
        print(f"  {category}: {count}")
    
    # Show advanced insights
    if 'ai_insights' in results:
        print(f"\nAI Insights: {len(results['ai_insights'])}")
        for insight in results['ai_insights'][:3]:
            print(f"  - {insight}")
    
    # Show attack chains
    if 'vulnerability_correlations' in results:
        chains = results['vulnerability_correlations'].get('attack_chains', [])
        print(f"\nAttack Chains Identified: {len(chains)}")
        for chain in chains:
            print(f"  - {chain['chain']}: {chain['description']}")

def demonstrate_ml_training():
    """Demonstrate ML model training and prediction"""
    print("\n=== ML MODEL TRAINING DEMO ===")
    
    predictor = MLVulnerabilityPredictor()
    
    # Simulate normal baseline responses
    normal_responses = [
        {'response_time': 0.5, 'content': 'Welcome to our site', 'status_code': 200},
        {'response_time': 0.6, 'content': 'About us page', 'status_code': 200},
        {'response_time': 0.4, 'content': 'Contact information', 'status_code': 200},
    ]
    
    predictor.train_baseline(normal_responses)
    print("Trained baseline model with normal responses")
    
    # Test anomalous responses
    test_cases = [
        {'response_time': 5.0, 'content': 'SQL error occurred', 'status_code': 500},
        {'response_time': 0.1, 'content': 'root:x:0:0:root:/root:/bin/bash', 'status_code': 200},
        {'response_time': 0.5, 'content': 'Normal page content', 'status_code': 200},
    ]
    
    print("\nTesting anomaly detection:")
    for i, test_case in enumerate(test_cases):
        likelihood, indicators = predictor.predict_vulnerability_likelihood(test_case)
        print(f"Test {i+1}: Vulnerability likelihood = {likelihood:.2f}")
        if indicators:
            print(f"  Indicators: {indicators}")

if __name__ == '__main__':
    # Run advanced ML and fuzzing demos
    asyncio.run(ml_behavioral_analysis_demo())
    asyncio.run(zero_day_fuzzing_demo())
    asyncio.run(advanced_scanner_demo())
    demonstrate_ml_training()