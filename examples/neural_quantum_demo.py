#!/usr/bin/env python3
"""
Neural Network and Quantum Fuzzing Demo
Demonstrates Phase 8 advanced AI capabilities
"""

import asyncio
from app.tools.huginn_vuln_scanner import HuginnVulnScanner
from app.core.neural_vulnerability_engine import NeuralVulnerabilityEngine
from app.core.quantum_fuzzer import QuantumFuzzer
from app.core.autonomous_agent import AutonomousSecurityAgent, AgentState

async def neural_engine_demo():
    """Demonstrate neural vulnerability engine"""
    print("=== NEURAL VULNERABILITY ENGINE ===")
    
    neural_engine = NeuralVulnerabilityEngine()
    
    # Train on vulnerability examples
    training_examples = [
        {
            'response': {'content': 'SQL syntax error near', 'status_code': 500, 'response_time': 2.1},
            'payload': "' OR 1=1--",
            'context': {'tech_stack': ['MySQL', 'PHP']},
            'vulnerable': True
        },
        {
            'response': {'content': '<script>alert(1)</script>', 'status_code': 200, 'response_time': 0.5},
            'payload': '<script>alert(1)</script>',
            'context': {'tech_stack': ['Apache', 'HTML']},
            'vulnerable': True
        },
        {
            'response': {'content': 'Welcome to our site', 'status_code': 200, 'response_time': 0.3},
            'payload': 'normal_input',
            'context': {'tech_stack': ['Apache']},
            'vulnerable': False
        }
    ]
    
    # Train neural network
    for example in training_examples:
        neural_engine.train_on_vulnerability(example, example['vulnerable'])
    
    print("Neural network trained on vulnerability examples")
    
    # Test predictions
    test_cases = [
        {
            'response': {'content': 'Database error occurred', 'status_code': 500, 'response_time': 3.0},
            'payload': "' UNION SELECT version()--",
            'context': {'tech_stack': ['MySQL']}
        },
        {
            'response': {'content': 'Page not found', 'status_code': 404, 'response_time': 0.2},
            'payload': 'test',
            'context': {'tech_stack': ['Apache']}
        }
    ]
    
    print("\nNeural network predictions:")
    for i, test_case in enumerate(test_cases):
        probability, confidence = neural_engine.predict_vulnerability(test_case)
        print(f"Test {i+1}: Vulnerability probability = {probability:.3f} ({confidence} confidence)")
    
    # Generate targeted payloads
    target_profile = {'tech_stack': ['WordPress', 'MySQL'], 'known_vulnerabilities': ['SQLi']}
    targeted_payloads = neural_engine.generate_targeted_payloads(target_profile)
    
    print(f"\nGenerated {len(targeted_payloads)} targeted payloads:")
    for payload in targeted_payloads[:3]:
        print(f"  - {payload}")

async def quantum_fuzzing_demo():
    """Demonstrate quantum-inspired fuzzing"""
    print("\n=== QUANTUM FUZZING ENGINE ===")
    
    quantum_fuzzer = QuantumFuzzer()
    
    # Create quantum superposition
    base_payloads = ['<script>alert(1)</script>', "' OR 1=1--", '../etc/passwd']
    quantum_payloads = quantum_fuzzer.create_payload_superposition(base_payloads)
    
    print(f"Created quantum superposition with {len(quantum_payloads)} quantum states")
    
    # Demonstrate superposition collapse
    context = {'tech_stack': ['PHP'], 'waf_detected': True}
    
    print("\nQuantum superposition collapse examples:")
    for i, quantum_payload in enumerate(quantum_payloads):
        collapsed = quantum_fuzzer.collapse_superposition(quantum_payload, context)
        print(f"Quantum payload {i+1}: {quantum_payload['base_payload']} -> {collapsed}")
    
    # Create entangled payloads
    payload_pairs = [
        ("' OR 1=1--", "' AND 1=2--"),
        ('<script>alert(1)</script>', '<img src=x onerror=alert(1)>')
    ]
    
    entangled_sets = quantum_fuzzer.create_entangled_payloads(payload_pairs)
    print(f"\nCreated {len(entangled_sets)} entangled payload sets")
    
    # Quantum interference patterns
    target_params = ['username', 'password', 'email']
    interference_patterns = quantum_fuzzer.quantum_interference_fuzzing(target_params)
    
    print(f"Generated {len(interference_patterns)} quantum interference patterns")
    for pattern in interference_patterns[:2]:
        print(f"  {pattern['type']} interference: {pattern['params']}")
    
    # Quantum tunneling bypass
    blocked_payloads = ['<script>alert(1)</script>', "' OR 1=1--"]
    tunneled_payloads = quantum_fuzzer.quantum_tunneling_bypass(blocked_payloads)
    
    print(f"\nQuantum tunneling generated {len(tunneled_payloads)} bypass variants:")
    for payload in tunneled_payloads[:3]:
        print(f"  - {payload}")

async def autonomous_agent_demo():
    """Demonstrate autonomous security agent"""
    print("\n=== AUTONOMOUS SECURITY AGENT ===")
    
    # This would normally use a real session, but we'll simulate
    class MockSession:
        async def get(self, url):
            class MockResponse:
                status = 200
                async def text(self): return "mock response"
                async def read(self): return b"mock binary"
            return MockResponse()
    
    agent = AutonomousSecurityAgent(MockSession())
    
    print(f"Agent initialized in state: {agent.current_state.value}")
    print(f"Decision tree has {len(agent.decision_tree)} states")
    
    # Execute autonomous mission
    objectives = ['discover_services', 'find_vulnerabilities', 'test_exploits']
    
    print(f"\nExecuting autonomous mission with objectives: {objectives}")
    mission_result = await agent.execute_autonomous_mission('https://demo.target.com', objectives)
    
    print(f"Mission completed in {mission_result['duration']:.2f} seconds")
    print(f"Success rate: {mission_result['success_rate']:.2f}")
    print(f"States executed: {len(mission_result['states_executed'])}")
    print(f"Actions taken: {len(mission_result['actions_taken'])}")
    
    # Show mission progression
    print("\nMission progression:")
    for state_exec in mission_result['states_executed']:
        print(f"  {state_exec['state']}: {len(state_exec['result']['actions_completed'])} actions")

async def integrated_neural_quantum_scan():
    """Demonstrate integrated neural and quantum scanning"""
    print("\n=== INTEGRATED NEURAL-QUANTUM SCAN ===")
    
    # Use maximum profile for all advanced features
    scanner = HuginnVulnScanner('https://demo.testfire.net', profile='insane')
    results = await scanner.scan()
    
    print(f"Advanced scan completed with {len(results['vulnerabilities'])} total findings")
    
    # Categorize by detection method
    detection_methods = {
        'Traditional': 0,
        'Neural Network': 0,
        'Quantum Fuzzing': 0,
        'Autonomous Agent': 0,
        'ML Prediction': 0
    }
    
    for vuln in results['vulnerabilities']:
        vuln_type = vuln.get('type', '')
        source = vuln.get('source', '')
        
        if 'Neural Network' in vuln_type:
            detection_methods['Neural Network'] += 1
        elif 'Quantum' in vuln_type:
            detection_methods['Quantum Fuzzing'] += 1
        elif source == 'autonomous_agent':
            detection_methods['Autonomous Agent'] += 1
        elif 'ML-Predicted' in vuln_type:
            detection_methods['ML Prediction'] += 1
        else:
            detection_methods['Traditional'] += 1
    
    print("\nFindings by advanced detection method:")
    for method, count in detection_methods.items():
        if count > 0:
            print(f"  {method}: {count}")
    
    # Show autonomous mission results
    if 'autonomous_mission' in results:
        mission = results['autonomous_mission']
        print(f"\nAutonomous mission statistics:")
        print(f"  Duration: {mission['duration']:.2f}s")
        print(f"  Success rate: {mission['success_rate']:.2f}")
        print(f"  States executed: {mission['states_executed']}")
        print(f"  Actions taken: {mission['actions_taken']}")

if __name__ == '__main__':
    # Run neural and quantum demos
    asyncio.run(neural_engine_demo())
    asyncio.run(quantum_fuzzing_demo())
    asyncio.run(autonomous_agent_demo())
    asyncio.run(integrated_neural_quantum_scan())