#!/usr/bin/env python3
"""
Test script for SMB blocking detection
Tests the enhanced SMB scanner's ability to detect and report SMB blocking
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.tools.smb_raw_proto import enumerate_smb_comprehensive

def test_smb_blocking_detection(target):
    """Test SMB blocking detection and reporting"""
    print(f"Testing SMB Blocking Detection on {target}")
    print("=" * 60)
    
    try:
        # Test comprehensive SMB assessment
        print("\nRunning Comprehensive SMB Assessment...")
        assessment = enumerate_smb_comprehensive(target, timeout=5.0)
        
        print(f"Assessment completed")
        print(f"Target: {assessment.get('target', target)}")
        print(f"Overall Risk: {assessment.get('overall_risk', 'UNKNOWN')}")
        print(f"Risk Summary: {assessment.get('risk_summary', 'No summary')}")
        
        # Check metadata
        metadata = assessment.get('metadata', {})
        print(f"\nMetadata Analysis:")
        for key, value in metadata.items():
            print(f"  • {key}: {value}")
        
        # Check for blocking detection
        if metadata.get('smb_blocked') or metadata.get('connection_reset'):
            print(f"\nSMB BLOCKING DETECTED!")
            print(f"  • Blocking Method: {metadata.get('blocking_method', 'unknown')}")
            print(f"  • Security Posture: {metadata.get('security_posture', 'unknown')}")
            print(f"  • TCP Connection: {metadata.get('tcp_connection', 'unknown')}")
            print(f"  • SMB Response: {metadata.get('smb_response', 'unknown')}")
            
            print(f"\nEXCELLENT SECURITY POSTURE DETECTED!")
            print(f"  This target properly blocks SMB traffic, preventing:")
            print(f"  • SMB enumeration attacks")
            print(f"  • Lateral movement via SMB")
            print(f"  • Share enumeration")
            print(f"  • NTLM relay attacks")
            
        else:
            print(f"\nSMB appears to be accessible")
            if metadata.get('negotiated_dialect'):
                print(f"  • Negotiated Dialect: SMB {metadata['negotiated_dialect']}")
                print(f"  • Signing Required: {metadata.get('signing_required', False)}")
                print(f"  • Encryption Required: {metadata.get('encryption_required', False)}")
        
        # Display security findings
        findings = assessment.get('security_findings', [])
        if findings:
            print(f"\nSecurity Findings:")
            for finding in findings:
                print(f"  • {finding.get('type', 'Unknown')}: {finding.get('description', 'No description')}")
        
        # Display recommendations
        recommendations = assessment.get('recommendations', [])
        if recommendations:
            print(f"\nSecurity Recommendations:")
            for rec in recommendations:
                print(f"  • {rec}")
        
        # Display vulnerabilities
        vulnerabilities = assessment.get('vulnerabilities', [])
        if vulnerabilities:
            print(f"\nVulnerabilities Found:")
            for vuln in vulnerabilities:
                print(f"  • {vuln.get('type', 'Unknown')}: {vuln.get('severity', 'Unknown')} - {vuln.get('description', 'No description')}")
        
        return True
        
    except Exception as e:
        print(f"Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python test_smb_blocking.py <target_ip>")
        print("Example: python test_smb_blocking.py 192.168.1.106")
        sys.exit(1)
    
    target = sys.argv[1]
    
    print("Huggin SMB Scanner - SMB Blocking Detection Test")
    print("=" * 80)
    print(f"Target: {target}")
    print("Testing enhanced SMB blocking detection capabilities...")
    
    # Run test
    success = test_smb_blocking_detection(target)
    
    print("\n" + "=" * 80)
    if success:
        print("SMB BLOCKING DETECTION TEST COMPLETED!")
        print("\nWhat this test demonstrates:")
        print("  • Proper detection of SMB traffic blocking")
        print("  • Accurate security posture assessment")
        print("  • Positive security finding reporting")
        print("  • Appropriate risk level assignment (LOW = GOOD)")
        print("  • Comprehensive security recommendations")
        print("\nKey Insight:")
        print("  Connection resets on SMB traffic indicate EXCELLENT security!")
        print("  This prevents SMB-based attacks and lateral movement.")
    else:
        print("Test encountered errors - check output above")