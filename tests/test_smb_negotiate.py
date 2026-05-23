#!/usr/bin/env python3
"""
Test script for SMB2/3 Negotiate Protocol Exchange with NTLM Domain Discovery
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

from app.tools.smb_raw_proto import SMBRawClient, enumerate_smb_comprehensive

def test_smb_negotiate(target):
    """Test SMB2/3 negotiate protocol with domain discovery"""
    print(f"Testing SMB2/3 Negotiate Protocol Exchange on {target}")
    print("=" * 60)
    
    try:
        # Stage 1: SMB2/3 Negotiate Protocol Exchange
        print("Stage 1: SMB2/3 Negotiate Protocol Exchange")
        print("-" * 40)
        
        client = SMBRawClient(target, 445, timeout=5.0)
        client.connect()
        print(f"✅ TCP connection established to {target}:445")
        
        # Negotiate SMB3.1.1 with compression for SMBGhost detection
        negotiate_result = client.negotiate_dialects()
        print(f"✅ SMB Negotiate successful:")
        print(f"   • Dialect: {negotiate_result['dialect']}")
        print(f"   • Signing Required: {negotiate_result['signing_required']}")
        print(f"   • Encryption Required: {negotiate_result['encryption_required']}")
        print(f"   • Compression Supported: {negotiate_result.get('compression_supported', False)}")
        print(f"   • Server GUID: {negotiate_result['server_guid']}")
        print(f"   • Time Skew: {negotiate_result['time_skew_ms']}ms")
        
        # Stage 2: NTLM Handshake for Domain Discovery
        print("\nStage 2: NTLM Handshake for Domain Discovery")
        print("-" * 40)
        
        domain_info = client.discover_domain_via_ntlm()
        if domain_info.get('domain_name') or domain_info.get('dns_domain'):
            print("✅ Domain information discovered via NTLM Type 2 challenge:")
            if domain_info.get('domain_name'):
                print(f"   • NetBIOS Domain: {domain_info['domain_name']}")
            if domain_info.get('dns_domain'):
                print(f"   • DNS Domain: {domain_info['dns_domain']}")
            if domain_info.get('forest_name'):
                print(f"   • Forest Name: {domain_info['forest_name']}")
            if domain_info.get('computer_name'):
                print(f"   • Computer Name: {domain_info['computer_name']}")
            if domain_info.get('dns_computer_name'):
                print(f"   • DNS Computer Name: {domain_info['dns_computer_name']}")
        else:
            print("⚠️  No domain information available from NTLM challenge")
        
        # Stage 3: Null Session Share Enumeration
        print("\nStage 3: Null Session Share Enumeration")
        print("-" * 40)
        
        shares = client.enumerate_shares_null_session()
        if shares:
            print("✅ Share enumeration results:")
            for share in shares:
                status_icon = "✅" if share['accessible'] else "🔒" if share['exists'] else "❌"
                print(f"   {status_icon} {share['name']}: {share['description']}")
        else:
            print("⚠️  No shares enumerated")
        
        client.close()
        print("\n✅ SMB connection closed successfully")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return False
    
    return True

def test_comprehensive_enumeration(target):
    """Test comprehensive SMB enumeration"""
    print(f"\nTesting Comprehensive SMB Enumeration on {target}")
    print("=" * 60)
    
    try:
        results = enumerate_smb_comprehensive(target, timeout=5.0)
        
        print("📊 Enumeration Results:")
        print("-" * 20)
        
        if 'capabilities' in results:
            caps = results['capabilities']
            print(f"SMB Protocol: {caps.get('dialect', 'Unknown')}")
            print(f"Signing Required: {caps.get('signing_required', False)}")
            print(f"Encryption Required: {caps.get('encryption_required', False)}")
            print(f"Compression Supported: {caps.get('compression_supported', False)}")
        
        if 'domain_info' in results and results['domain_info']:
            domain = results['domain_info']
            print(f"\n🏛️ Domain Information:")
            if domain.get('domain_name'):
                print(f"   NetBIOS Domain: {domain['domain_name']}")
            if domain.get('dns_domain'):
                print(f"   DNS Domain: {domain['dns_domain']}")
            if domain.get('forest_name'):
                print(f"   Forest: {domain['forest_name']}")
            if domain.get('computer_name'):
                print(f"   Computer: {domain['computer_name']}")
        
        if 'shares' in results and results['shares']:
            print(f"\n📂 Shares ({len(results['shares'])}):")
            for share in results['shares']:
                status = "Accessible" if share['accessible'] else "Exists" if share['exists'] else "Not Found"
                print(f"   • {share['name']}: {status}")
        
        if 'vulnerabilities' in results and results['vulnerabilities']:
            print(f"\n⚠️  Vulnerabilities ({len(results['vulnerabilities'])}):")
            for vuln in results['vulnerabilities']:
                severity_icon = {"critical": "🚨", "high": "🔴", "medium": "🟠", "low": "🟡"}.get(vuln['severity'], "ℹ️")
                print(f"   {severity_icon} {vuln['name']}: {vuln['description']}")
        
        if 'error' in results:
            print(f"\n❌ Error: {results['error']}")
            if 'recommendations' in results:
                print("💡 Recommendations:")
                for rec in results['recommendations']:
                    print(f"   • {rec}")
        
    except Exception as e:
        print(f"❌ Comprehensive enumeration error: {str(e)}")
        return False
    
    return True

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python test_smb_negotiate.py <target_ip>")
        print("Example: python test_smb_negotiate.py 192.168.1.100")
        sys.exit(1)
    
    target = sys.argv[1]
    
    print("SMB2/3 Negotiate Protocol Exchange Test")
    print("=" * 60)
    print(f"Target: {target}")
    print(f"Port: 445 (SMB)")
    print()
    
    # Test basic negotiate protocol
    success1 = test_smb_negotiate(target)
    
    # Test comprehensive enumeration
    success2 = test_comprehensive_enumeration(target)
    
    print("\n" + "=" * 60)
    if success1 and success2:
        print("✅ All tests completed successfully!")
    else:
        print("❌ Some tests failed - check output above")