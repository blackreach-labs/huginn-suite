#!/usr/bin/env python3
"""
Advanced Huggin Scanner Usage Examples
Demonstrates Phase 1-3 enhancements
"""

import asyncio
from app.tools.huggin_vuln_scanner import HugginVulnScanner

async def basic_scan():
    """Basic scan with normal profile"""
    scanner = HugginVulnScanner('https://example.com', profile='normal')
    results = await scanner.scan()
    
    print(f"Found {len(results['vulnerabilities'])} vulnerabilities")
    for vuln in results['vulnerabilities']:
        print(f"[{vuln['severity']}] {vuln['type']}")

async def aggressive_scan_with_auth():
    """Aggressive scan with authentication"""
    scanner = HugginVulnScanner('https://app.example.com', profile='aggressive')
    
    # Configure authentication
    scanner.config_manager.set_auth('login', username='testuser', password='testpass')
    
    # Set webhook for real-time alerts
    scanner.webhook_notifier.set_webhook_url('https://hooks.slack.com/services/YOUR/WEBHOOK/URL')
    
    results = await scanner.scan()
    
    # Export with evidence
    html_report = scanner.export_results('html')
    with open('scan_report.html', 'w') as f:
        f.write(html_report)

async def custom_profile_scan():
    """Scan with custom configuration"""
    scanner = HugginVulnScanner('https://target.com', profile='insane')
    
    # Update profile for maximum coverage
    scanner.config_manager.update_profile('insane', {
        'max_concurrent': 300,
        'payload_limit': 10,
        'modules': ['all', 'ssti_detection', 'business_logic', 'dependency_scan']
    })
    
    results = await scanner.scan()
    
    # Show advanced findings
    for vuln in results['vulnerabilities']:
        if vuln['type'] in ['Server-Side Template Injection', 'Insecure Direct Object Reference']:
            print(f"🚨 Advanced vulnerability: {vuln['type']} - CVSS: {vuln['cvss_score']}")

if __name__ == '__main__':
    # Run different scan types
    asyncio.run(basic_scan())
    # asyncio.run(aggressive_scan_with_auth())
    # asyncio.run(custom_profile_scan())