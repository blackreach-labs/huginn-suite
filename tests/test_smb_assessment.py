#!/usr/bin/env python3
"""
Test script for comprehensive SMB security assessment
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

from app.tools.smb_raw_proto import enumerate_smb_comprehensive
import json

def test_smb_assessment(target):
    """Test comprehensive SMB security assessment"""
    print(f"🔍 Testing SMB security assessment for {target}")
    print("=" * 60)
    
    try:
        # Perform comprehensive assessment
        assessment = enumerate_smb_comprehensive(target, timeout=5.0)
        
        # Display results in structured format
        print(f"🎯 Target: {assessment.get('target', target)}")
        
        # Overall risk assessment
        risk_level = assessment.get('overall_risk', 'UNKNOWN')
        risk_icons = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}
        risk_icon = risk_icons.get(risk_level, '❓')
        print(f"{risk_icon} Overall Risk: {risk_level}")
        
        if assessment.get('risk_summary'):
            print(f"📊 Risk Summary: {assessment['risk_summary']}")
        
        print()
        
        # Protocol intelligence
        metadata = assessment.get('metadata', {})
        if metadata:
            print("📋 SMB Protocol Intelligence:")
            if metadata.get('negotiated_dialect'):
                print(f"  • Negotiated Dialect: SMB {metadata['negotiated_dialect']}")
            
            signing_status = "✅ Required" if metadata.get('signing_required') else "⚠️ Optional"
            print(f"  • SMB Signing: {signing_status}")
            
            if metadata.get('encryption_required'):
                print(f"  • SMB Encryption: ✅ Required")
            elif '3.' in str(metadata.get('negotiated_dialect', '')):
                print(f"  • SMB Encryption: ⚠️ Optional")
            
            if metadata.get('preauth_integrity'):
                print(f"  • Preauth Integrity: ✅ Enabled")
            
            if metadata.get('smb1_enabled'):
                print(f"  • SMB1 Support: 🔴 ENABLED (Critical Risk)")
            
            print()
        
        # Domain intelligence
        domain_info = metadata.get('domain_info', {})
        if domain_info and not domain_info.get('error'):
            print("🏛️ Domain Intelligence:")
            if domain_info.get('domain_name'):
                print(f"  • NetBIOS Domain: {domain_info['domain_name']}")
            if domain_info.get('dns_domain'):
                print(f"  • DNS Domain: {domain_info['dns_domain']}")
            if domain_info.get('computer_name'):
                print(f"  • Computer Name: {domain_info['computer_name']}")
            if domain_info.get('forest_name'):
                print(f"  • Forest Name: {domain_info['forest_name']}")
            print()
        
        # Share enumeration
        shares = metadata.get('shares', [])
        if shares and not isinstance(shares, dict):
            print("📁 Share Enumeration:")
            for share in shares:
                if isinstance(share, dict):
                    share_name = share.get('name', 'Unknown')
                    if share.get('accessible'):
                        print(f"  • ✅ {share_name} - Accessible")
                    elif share.get('exists'):
                        print(f"  • 🔒 {share_name} - Access Denied")
                    else:
                        print(f"  • ❓ {share_name} - Not Found")
            print()
        
        # Security vulnerabilities
        vulnerabilities = assessment.get('vulnerabilities', [])
        if vulnerabilities:
            print("🚨 Security Vulnerabilities:")
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'UNKNOWN')
                severity_icons = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}
                severity_icon = severity_icons.get(severity, '❓')
                
                print(f"  {severity_icon} {vuln.get('type', 'Unknown Vulnerability')} [{severity}]")
                if vuln.get('description'):
                    print(f"    Description: {vuln['description']}")
                if vuln.get('cve'):
                    print(f"    CVE: {vuln['cve']}")
                if vuln.get('recommendation'):
                    print(f"    Recommendation: {vuln['recommendation']}")
            print()
        
        # Security findings
        findings = assessment.get('security_findings', [])
        if findings:
            print("🔍 Security Findings:")
            for finding in findings:
                severity = finding.get('severity', 'INFO')
                severity_icons = {'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵', 'INFO': 'ℹ️'}
                severity_icon = severity_icons.get(severity, 'ℹ️')
                
                print(f"  {severity_icon} {finding.get('type', 'Security Finding')}")
                if finding.get('description'):
                    print(f"    {finding['description']}")
            print()
        
        # Recommendations
        recommendations = assessment.get('recommendations', [])
        if recommendations:
            print("💡 Security Recommendations:")
            for rec in recommendations:
                print(f"  • {rec}")
            print()
        
        # Dialect testing results
        dialects_tested = assessment.get('dialects_tested', [])
        if dialects_tested:
            print("🔬 Protocol Testing Results:")
            for test in dialects_tested:
                status_icon = "✅" if test.get('success') else "❌"
                print(f"  {status_icon} {test.get('approach', 'Unknown approach')}")
            print()
        
        # Raw JSON output for debugging
        print("📄 Raw Assessment Data:")
        print(json.dumps(assessment, indent=2, default=str))
        
    except Exception as e:
        print(f"❌ Assessment failed: {e}")
        import traceback
        print(f"Debug: {traceback.format_exc()}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python test_smb_assessment.py <target_ip>")
        sys.exit(1)
    
    target = sys.argv[1]
    test_smb_assessment(target)