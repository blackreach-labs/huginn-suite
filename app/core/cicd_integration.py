import json
import os
from typing import Dict, List, Optional

class CICDIntegration:
    """CI/CD pipeline integration for DevSecOps workflows"""
    
    def __init__(self):
        self.security_gates = {
            'critical_threshold': 0,  # Fail if any critical vulns
            'high_threshold': 3,      # Fail if >3 high vulns
            'medium_threshold': 10    # Fail if >10 medium vulns
        }
    
    def generate_jenkins_pipeline(self, target_url: str, profile: str = 'normal') -> str:
        """Generate Jenkins pipeline script"""
        return f"""
pipeline {{
    agent any
    
    stages {{
        stage('Security Scan') {{
            steps {{
                script {{
                    sh '''
                    python -m app.tools.huginn_vuln_scanner \\
                        --target {target_url} \\
                        --profile {profile} \\
                        --output scan_results.json
                    '''
                    
                    def results = readJSON file: 'scan_results.json'
                    def criticalCount = results.vulnerabilities.count {{ it.severity == 'Critical' }}
                    def highCount = results.vulnerabilities.count {{ it.severity == 'High' }}
                    
                    if (criticalCount > 0) {{
                        error("Security gate failed: ${{criticalCount}} critical vulnerabilities found")
                    }}
                    
                    if (highCount > 3) {{
                        error("Security gate failed: ${{highCount}} high vulnerabilities found")
                    }}
                    
                    publishHTML([
                        allowMissing: false,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: '.',
                        reportFiles: 'scan_report.html',
                        reportName: 'Security Scan Report'
                    ])
                }}
            }}
        }}
    }}
}}
"""
    
    def generate_github_action(self, target_url: str, profile: str = 'normal') -> str:
        """Generate GitHub Actions workflow"""
        return f"""
name: Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
    
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
    
    - name: Run Huginn Security Scan
      run: |
        python -m app.tools.huginn_vuln_scanner \\
          --target {target_url} \\
          --profile {profile} \\
          --output scan_results.json
    
    - name: Security Gate Check
      run: |
        python -c "
import json
with open('scan_results.json') as f:
    results = json.load(f)
    
critical = sum(1 for v in results['vulnerabilities'] if v['severity'] == 'Critical')
high = sum(1 for v in results['vulnerabilities'] if v['severity'] == 'High')

if critical > 0:
    print(f'FAIL: {{critical}} critical vulnerabilities found')
    exit(1)
if high > 3:
    print(f'FAIL: {{high}} high vulnerabilities found') 
    exit(1)
print('PASS: Security gate passed')
"
    
    - name: Upload Security Report
      uses: actions/upload-artifact@v3
      with:
        name: security-report
        path: scan_report.html
"""
    
    def evaluate_security_gate(self, scan_results: Dict) -> Dict:
        """Evaluate if scan results pass security gates"""
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        severity_counts = {
            'Critical': sum(1 for v in vulnerabilities if v.get('severity') == 'Critical'),
            'High': sum(1 for v in vulnerabilities if v.get('severity') == 'High'),
            'Medium': sum(1 for v in vulnerabilities if v.get('severity') == 'Medium'),
            'Low': sum(1 for v in vulnerabilities if v.get('severity') == 'Low')
        }
        
        gate_results = {
            'passed': True,
            'severity_counts': severity_counts,
            'failures': []
        }
        
        if severity_counts['Critical'] > self.security_gates['critical_threshold']:
            gate_results['passed'] = False
            gate_results['failures'].append(f"Critical vulnerabilities: {severity_counts['Critical']} > {self.security_gates['critical_threshold']}")
        
        if severity_counts['High'] > self.security_gates['high_threshold']:
            gate_results['passed'] = False
            gate_results['failures'].append(f"High vulnerabilities: {severity_counts['High']} > {self.security_gates['high_threshold']}")
        
        if severity_counts['Medium'] > self.security_gates['medium_threshold']:
            gate_results['passed'] = False
            gate_results['failures'].append(f"Medium vulnerabilities: {severity_counts['Medium']} > {self.security_gates['medium_threshold']}")
        
        return gate_results
    
    def generate_security_policy(self) -> str:
        """Generate security policy template"""
        return """
# Security Policy

## Vulnerability Thresholds
- **Critical**: 0 allowed (immediate fix required)
- **High**: Maximum 3 allowed
- **Medium**: Maximum 10 allowed
- **Low**: No limit

## Scan Frequency
- **Production**: Weekly automated scans
- **Staging**: On every deployment
- **Development**: On pull requests

## Response Times
- **Critical**: 24 hours
- **High**: 7 days
- **Medium**: 30 days
- **Low**: Next release cycle

## Contacts
- Security Team: security@company.com
- DevOps Team: devops@company.com
"""