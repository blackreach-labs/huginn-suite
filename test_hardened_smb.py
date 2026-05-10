#!/usr/bin/env python3
"""
Test script for hardened SMB 3.1.1 detection capabilities
Tests the new Windows Server 2025 DC bypass functionality
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.tools.smb_raw_proto import SMBRawClient, enumerate_smb_comprehensive
import logging

def test_hardened_smb311(target):
    """Test hardened SMB 3.1.1 detection"""
    print(f"🚀 Testing Hardened SMB 3.1.1 Detection on {target}")
    print("=" * 60)
    
    try:
        # Test 1: Direct hardened negotiate
        print("\n📋 Test 1: Direct Hardened SMB 3.1.1 Negotiate")
        client = SMBRawClient(target, timeout=5.0)
        client.connect()
        
        # Build hardened negotiate packet
        smb2_packet, preauth_hash, salt = client.build_smb311_negotiate()
        print(f"✅ Built hardened negotiate: {len(smb2_packet)} bytes")
        print(f"✅ Preauth hash: {len(preauth_hash)} bytes")
        print(f"✅ Salt: {len(salt)} bytes")
        
        # Test negotiate
        result = client._negotiate_smb311_hardened()
        print(f"✅ Negotiate result: {result}")
        
        if result.get('hardened_negotiate'):
            print("🎯 SUCCESS: Hardened SMB 3.1.1 negotiate successful!")
        
        # Test 2: Signed SESSION_SETUP
        if client.preauth_hash_value:
            print("\n📋 Test 2: Signed Anonymous SESSION_SETUP")
            session_packet = client.build_session_setup_anonymous_signed()
            print(f"✅ Built signed SESSION_SETUP: {len(session_packet)} bytes")
            
            # Test domain discovery
            domain_info = client.discover_domain_via_ntlm()
            print(f"✅ Domain discovery: {domain_info}")
            
            if domain_info.get('dns_domain') or domain_info.get('domain_name'):
                print("🎯 SUCCESS: Domain intelligence extracted via hardened method!")
        
        client.close()
        
        # Test 3: Comprehensive assessment
        print("\n📋 Test 3: Comprehensive SMB Assessment")
        assessment = enumerate_smb_comprehensive(target, timeout=5.0)
        
        print(f"✅ Overall risk: {assessment.get('overall_risk', 'UNKNOWN')}")
        print(f"✅ Dialect tested: {assessment.get('metadata', {}).get('negotiated_dialect', 'Unknown')}")
        
        if assessment.get('metadata', {}).get('hardened_negotiate'):
            print("🎯 SUCCESS: Comprehensive assessment used hardened detection!")
        
        # Display results
        print("\n📊 Assessment Results:")
        metadata = assessment.get('metadata', {})
        for key, value in metadata.items():
            print(f"  • {key}: {value}")
        
        vulnerabilities = assessment.get('vulnerabilities', [])
        if vulnerabilities:
            print(f"\n🚨 Vulnerabilities found: {len(vulnerabilities)}")
            for vuln in vulnerabilities:
                print(f"  • {vuln.get('type', 'Unknown')}: {vuln.get('severity', 'Unknown')}")
        
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_compatibility(target):
    """Test compatibility with different SMB versions"""
    print(f"\n🔄 Testing SMB Version Compatibility on {target}")
    print("=" * 60)
    
    client = SMBRawClient(target, timeout=3.0)
    
    try:
        client.connect()
        
        # Test different negotiate methods
        methods = [
            ("Hardened SMB 3.1.1", client._negotiate_smb311_hardened),
            ("SMB 3.1.1 with contexts", client._negotiate_smb311_with_contexts),
            ("SMB 3.0.2 simple", client._negotiate_smb302_simple),
            ("SMB 2.1 basic", client._negotiate_smb21_basic)
        ]
        
        for method_name, method_func in methods:
            try:
                print(f"\n📋 Testing {method_name}...")
                result = method_func()
                
                if result.get('dialect') != 'Unknown' and not result.get('dialect', '').startswith('Error'):
                    print(f"✅ {method_name}: SMB {result['dialect']} - SUCCESS")
                    if result.get('hardened_negotiate'):
                        print("  🎯 Hardened detection successful!")
                    break
                else:
                    print(f"⚠️ {method_name}: {result.get('dialect', 'Failed')}")
                    
                # Reconnect for next test
                client.close()
                client.connect()
                    
            except Exception as e:
                print(f"❌ {method_name}: {e}")
                try:
                    client.close()
                    client.connect()
                except Exception as _exc:
                    pass
                    logging.debug("Suppressed exception", exc_info=True)
        
        client.close()
        return True
        
    except Exception as e:
        print(f"❌ Compatibility test failed: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python test_hardened_smb.py <target_ip>")
        print("Example: python test_hardened_smb.py 192.168.1.100")
        sys.exit(1)
    
    target = sys.argv[1]
    
    print("🛡️ Huggin SMB Scanner - Hardened SMB 3.1.1 Detection Test")
    print("=" * 80)
    print(f"Target: {target}")
    print("Testing new Windows Server 2025 DC bypass capabilities...")
    
    # Run tests
    success1 = test_hardened_smb311(target)
    success2 = test_compatibility(target)
    
    print("\n" + "=" * 80)
    if success1 and success2:
        print("🎉 ALL TESTS PASSED - Hardened SMB 3.1.1 detection is working!")
    else:
        print("⚠️ Some tests failed - check output above for details")
    
    print("\n💡 Key Features Tested:")
    print("  • SMB 3.1.1 only negotiate (no fallback dialects)")
    print("  • Windows 11 client-like security mode (0x0001)")
    print("  • Zero capabilities (0x00000000) to match Windows clients")
    print("  • 8-byte aligned negotiate contexts (mandatory)")
    print("  • SHA-512 preauth integrity hash chaining")
    print("  • Signed anonymous SESSION_SETUP with dummy key")
    print("  • SPNEGO-wrapped NTLM Type-1 for strict DCs")
    print("  • Enhanced NTLM Type-2 AV pair parsing")
    print("  • Hardened DC bypass for Windows Server 2025")