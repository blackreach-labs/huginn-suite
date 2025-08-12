#!/usr/bin/env python3
import asyncio
import requests
from app.tools.scan_plugins.ai_ssti_plugin import AISSTIPlugin

async def test_ai_ssti():
    target_url = "http://10.10.11.62:5000"
    
    # Create session
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    
    def progress_callback(msg):
        print(f"[AI SSTI] {msg}")
    
    # Initialize AI SSTI plugin
    ai_plugin = AISSTIPlugin(session, progress_callback)
    
    # Test endpoints (Flask app likely has these)
    test_endpoints = [
        f"{target_url}/",
        f"{target_url}/search",
        f"{target_url}/execute",
        f"{target_url}/eval",
        f"{target_url}/code"
    ]
    
    print(f"[AI SSTI] Starting adaptive SSTI scan on {target_url}")
    print(f"[AI SSTI] Testing {len(test_endpoints)} endpoints")
    
    # Run AI scan
    results = await ai_plugin.scan(target_url, test_endpoints)
    
    # Display results
    print("\n" + "="*60)
    print("AI SSTI SCAN RESULTS")
    print("="*60)
    
    vuln_count = len(results['vulnerabilities'])
    print(f"Vulnerabilities found: {vuln_count}")
    
    if vuln_count > 0:
        for i, vuln in enumerate(results['vulnerabilities'], 1):
            print(f"\n[VULNERABILITY {i}]")
            print(f"Endpoint: {vuln['endpoint']}")
            print(f"Type: {vuln['vulnerability_type']}")
            print(f"Successful Payload: {vuln['successful_payload']}")
            
            # Show adaptation history
            if vuln['adaptation_history']:
                print(f"Adaptation rounds: {len(vuln['adaptation_history'])}")
                for round_info in vuln['adaptation_history']:
                    print(f"  Round {round_info['round']}: {round_info['response_type']} -> {round_info.get('next_payload', 'N/A')[:50]}...")
    
    # Show AI intelligence
    intelligence = results['ai_intelligence']
    print(f"\n[AI INTELLIGENCE]")
    print(f"Blocked tokens: {intelligence.get('blocked_tokens', [])}")
    print(f"Working bypasses: {len(intelligence.get('working_bypasses', {}))}")
    print(f"Recommended approach: {intelligence.get('recommended_approach', 'unknown')}")
    
    # Show summary
    print(f"\n[SUMMARY]")
    print(ai_plugin.get_scan_summary(results))

if __name__ == "__main__":
    asyncio.run(test_ai_ssti())