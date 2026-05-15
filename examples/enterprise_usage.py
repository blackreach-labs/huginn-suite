#!/usr/bin/env python3
"""
Enterprise Huginn Scanner Usage Examples
Demonstrates Phase 6 enterprise integration features
"""

import asyncio
from app.tools.huginn_vuln_scanner import HuginnVulnScanner
from app.core.multi_target_orchestrator import MultiTargetOrchestrator

async def enterprise_scan_campaign():
    """Multi-target enterprise scan campaign"""
    orchestrator = MultiTargetOrchestrator(max_concurrent_targets=3)
    
    # Define target list
    targets = [
        'https://app1.company.com',
        'https://api.company.com', 
        'https://admin.company.com',
        'https://staging.company.com'
    ]
    
    # Create scan campaign
    campaign = orchestrator.add_scan_campaign(
        campaign_name='Q4_Security_Assessment',
        targets=targets,
        profile='aggressive'
    )
    
    print(f"Created campaign: {campaign['name']}")
    
    # Execute campaign
    results = await orchestrator.execute_campaign('Q4_Security_Assessment')
    
    # Generate campaign summary
    summary = orchestrator.generate_campaign_summary('Q4_Security_Assessment')
    
    print(f"Campaign completed:")
    print(f"- Total targets: {summary['total_targets']}")
    print(f"- Total vulnerabilities: {summary['aggregate_stats']['total_vulnerabilities']}")
    print(f"- Critical issues: {summary['aggregate_stats']['critical_count']}")
    print(f"- Duration: {summary['duration']:.2f} seconds")

async def compliance_reporting_demo():
    """Demonstrate compliance reporting features"""
    scanner = HuginnVulnScanner('https://demo.testfire.net', profile='normal')
    results = await scanner.scan()
    
    # Generate compliance reports
    print("=== EXECUTIVE SUMMARY ===")
    print(scanner.export_results('executive'))
    
    print("\n=== OWASP TOP 10 REPORT ===")
    owasp_report = scanner.export_results('owasp')
    print(f"OWASP Compliance Score: {results['owasp_report']['compliance_score']}/100")
    
    print("\n=== PCI DSS REPORT ===")
    pci_report = scanner.export_results('pci')
    print(f"PCI DSS Status: {results['pci_dss_report']['compliance_status']}")
    
    print("\n=== SECURITY GATE STATUS ===")
    gate_status = results['security_gate']
    print(f"Security Gate: {'PASSED' if gate_status['passed'] else 'FAILED'}")
    if not gate_status['passed']:
        for failure in gate_status['failures']:
            print(f"- {failure}")

def generate_cicd_configs():
    """Generate CI/CD pipeline configurations"""
    scanner = HuginnVulnScanner('https://api.company.com')
    
    # Generate Jenkins pipeline
    jenkins_config = scanner.generate_cicd_config('jenkins')
    with open('Jenkinsfile', 'w') as f:
        f.write(jenkins_config)
    print("Generated Jenkinsfile")
    
    # Generate GitHub Actions workflow
    github_config = scanner.generate_cicd_config('github')
    with open('.github/workflows/security-scan.yml', 'w') as f:
        f.write(github_config)
    print("Generated GitHub Actions workflow")

async def devsecops_integration_demo():
    """Demonstrate DevSecOps integration"""
    scanner = HuginnVulnScanner('https://staging.company.com', profile='normal')
    results = await scanner.scan()
    
    # Check security gate
    gate_status = results['security_gate']
    
    if gate_status['passed']:
        print("✅ Security gate PASSED - Deployment can proceed")
        exit_code = 0
    else:
        print("❌ Security gate FAILED - Blocking deployment")
        print("Failures:")
        for failure in gate_status['failures']:
            print(f"  - {failure}")
        exit_code = 1
    
    # Generate reports for stakeholders
    with open('security_report.html', 'w') as f:
        f.write(scanner.export_results('html'))
    
    with open('executive_summary.md', 'w') as f:
        f.write(scanner.export_results('executive'))
    
    return exit_code

if __name__ == '__main__':
    # Run enterprise demos
    print("=== ENTERPRISE SCAN CAMPAIGN ===")
    asyncio.run(enterprise_scan_campaign())
    
    print("\n=== COMPLIANCE REPORTING ===")
    asyncio.run(compliance_reporting_demo())
    
    print("\n=== CI/CD CONFIGURATION GENERATION ===")
    generate_cicd_configs()
    
    print("\n=== DEVSECOPS INTEGRATION ===")
    exit_code = asyncio.run(devsecops_integration_demo())
    print(f"Exit code: {exit_code}")