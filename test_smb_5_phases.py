#!/usr/bin/env python3
"""
5-Phase SMB Protocol Intelligence Test Script
Tests each phase with full debug output and pauses between steps
"""

import sys
import os
import time
sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

from app.tools.smb_raw_proto import SMBRawClient

def pause_for_user(phase_name):
    """Pause and wait for user input"""
    print(f"\n{'='*60}")
    print(f"PHASE COMPLETE: {phase_name}")
    print(f"{'='*60}")
    input("Press ENTER to continue to next phase...")
    print()

def test_phase_1_dialect_negotiation(client, target):
    """Phase 1: Dialect Negotiation - Extract server metadata"""
    print("🔍 PHASE 1: DIALECT NEGOTIATION")
    print("-" * 40)
    
    dialects = [
        (0x0311, "SMB 3.1.1"),
        (0x0302, "SMB 3.0.2"), 
        (0x0300, "SMB 3.0"),
        (0x0210, "SMB 2.1")
    ]
    
    for dialect_id, dialect_name in dialects:
        print(f"\n[TESTING] {dialect_name} (0x{dialect_id:04x})")
        try:
            client.connect()
            
            if dialect_id == 0x0311:
                result = client._negotiate_smb311_with_contexts()
            else:
                result = client._negotiate_smb302_simple() if dialect_id == 0x0302 else client._negotiate_smb21_basic()
            
            print(f"[RESULT] {dialect_name}: {result}")
            
            if result.get('dialect') != 'Unknown':
                print(f"[SUCCESS] Negotiated {dialect_name}")
                print(f"[METADATA] Signing Required: {result.get('signing_required')}")
                print(f"[METADATA] Encryption Required: {result.get('encryption_required')}")
                print(f"[METADATA] Preauth Hash Set: {result.get('preauth_hash_set')}")
                return result
                
        except Exception as e:
            print(f"[ERROR] {dialect_name}: {e}")
        finally:
            client.close()
            time.sleep(0.5)
    
    print("[CONCLUSION] No SMB dialects accepted - server blocks SMB protocol")
    return None

def test_phase_2_session_setup(client, target):
    """Phase 2: Session Setup - NTLM domain discovery"""
    print("🔍 PHASE 2: SESSION SETUP (NTLM DOMAIN DISCOVERY)")
    print("-" * 40)
    
    try:
        client.connect()
        negotiate_result = client._negotiate_smb311_with_contexts()
        
        if negotiate_result.get('dialect') == 'Unknown':
            print("[SKIP] Session setup skipped - no successful negotiate")
            return None
            
        print("[ATTEMPT] Anonymous session setup with SPNEGO/NTLM...")
        domain_info = client.discover_domain_via_ntlm()
        
        print(f"[RESULT] Domain Info: {domain_info}")
        
        if domain_info.get('domain_name'):
            print(f"[INTELLIGENCE] NetBIOS Domain: {domain_info['domain_name']}")
        if domain_info.get('dns_domain'):
            print(f"[INTELLIGENCE] DNS Domain: {domain_info['dns_domain']}")
        if domain_info.get('computer_name'):
            print(f"[INTELLIGENCE] Computer Name: {domain_info['computer_name']}")
        if domain_info.get('forest_name'):
            print(f"[INTELLIGENCE] Forest Name: {domain_info['forest_name']}")
            
        return domain_info
        
    except Exception as e:
        print(f"[ERROR] Session setup failed: {e}")
        return None
    finally:
        client.close()

def test_phase_3_tree_connect_shares(client, target):
    """Phase 3: Tree Connect - Share enumeration"""
    print("🔍 PHASE 3: TREE CONNECT (SHARE ENUMERATION)")
    print("-" * 40)
    
    shares = ['IPC$', 'ADMIN$', 'C$', 'SYSVOL', 'NETLOGON']
    results = []
    
    try:
        client.connect()
        negotiate_result = client._negotiate_smb311_with_contexts()
        
        if negotiate_result.get('dialect') == 'Unknown':
            print("[SKIP] Tree connect skipped - no successful negotiate")
            return None
            
        for share in shares:
            print(f"\n[TESTING] Share: {share}")
            try:
                tree_id, status = client.tree_connect(share)
                
                print(f"[RESULT] {share}: TreeID={tree_id}, Status=0x{status:08x}")
                
                if status == 0:
                    print(f"[SUCCESS] {share}: Anonymous access granted")
                    results.append({'share': share, 'status': 'accessible'})
                elif status == 0xC0000022:
                    print(f"[EXISTS] {share}: Share exists but access denied")
                    results.append({'share': share, 'status': 'exists_denied'})
                elif status == 0xC0000034:
                    print(f"[NOT_FOUND] {share}: Share does not exist")
                    results.append({'share': share, 'status': 'not_found'})
                else:
                    print(f"[UNKNOWN] {share}: Unknown status 0x{status:08x}")
                    results.append({'share': share, 'status': f'unknown_0x{status:08x}'})
                    
            except Exception as e:
                print(f"[ERROR] {share}: {e}")
                results.append({'share': share, 'status': 'error', 'error': str(e)})
        
        return results
        
    except Exception as e:
        print(f"[ERROR] Tree connect phase failed: {e}")
        return None
    finally:
        client.close()

def test_phase_4_pipe_probing(client, target):
    """Phase 4: Named Pipe Probing - RPC surface discovery"""
    print("🔍 PHASE 4: NAMED PIPE PROBING (RPC SURFACE)")
    print("-" * 40)
    
    pipes = [
        '\\pipe\\srvsvc',
        '\\pipe\\samr', 
        '\\pipe\\lsarpc',
        '\\pipe\\netlogon',
        '\\pipe\\spoolss'
    ]
    
    try:
        client.connect()
        negotiate_result = client._negotiate_smb311_with_contexts()
        
        if negotiate_result.get('dialect') == 'Unknown':
            print("[SKIP] Pipe probing skipped - no successful negotiate")
            return None
            
        # First connect to IPC$
        print("[PREREQUISITE] Connecting to IPC$ share...")
        tree_id, status = client.tree_connect('IPC$')
        
        if status != 0:
            print(f"[SKIP] IPC$ not accessible (status=0x{status:08x}) - cannot probe pipes")
            return None
            
        print(f"[SUCCESS] IPC$ connected (TreeID={tree_id})")
        
        # Note: Actual pipe probing would require SMB2 CREATE requests
        # This is a placeholder showing the methodology
        print("[NOTE] Pipe probing requires SMB2 CREATE implementation")
        for pipe in pipes:
            print(f"[WOULD_TEST] {pipe} - CREATE request needed")
            
        return {'ipc_accessible': True, 'pipes_to_test': pipes}
        
    except Exception as e:
        print(f"[ERROR] Pipe probing failed: {e}")
        return None
    finally:
        client.close()

def test_phase_5_vulnerability_assessment(client, target, previous_results):
    """Phase 5: Vulnerability Assessment - Security analysis"""
    print("🔍 PHASE 5: VULNERABILITY ASSESSMENT")
    print("-" * 40)
    
    vulnerabilities = []
    
    # SMB1 Detection
    print("\n[TEST] SMB1 Protocol Detection...")
    try:
        from app.tools.smb_raw_proto import _probe_smb1_support
        smb1_enabled = _probe_smb1_support(target, 445)
        
        if smb1_enabled:
            print("[CRITICAL] SMB1 is enabled - EternalBlue risk (CVE-2017-0144)")
            vulnerabilities.append({
                'name': 'SMB1 Enabled',
                'severity': 'CRITICAL',
                'cve': 'CVE-2017-0144',
                'description': 'SMB1 protocol vulnerable to EternalBlue'
            })
        else:
            print("[SECURE] SMB1 is disabled")
            
    except Exception as e:
        print(f"[ERROR] SMB1 detection failed: {e}")
    
    # Signing Policy Assessment
    print("\n[TEST] SMB Signing Policy...")
    negotiate_result = previous_results.get('negotiate')
    if negotiate_result and not negotiate_result.get('signing_required'):
        print("[MEDIUM] SMB signing not required - NTLM relay risk")
        vulnerabilities.append({
            'name': 'SMB Signing Not Required',
            'severity': 'MEDIUM', 
            'description': 'Enables NTLM relay attacks'
        })
    else:
        print("[SECURE] SMB signing properly configured")
    
    # Anonymous Access Assessment
    print("\n[TEST] Anonymous Access...")
    shares_result = previous_results.get('shares', [])
    accessible_shares = [s for s in shares_result if s.get('status') == 'accessible']
    
    if accessible_shares:
        print(f"[HIGH] Anonymous share access detected: {[s['share'] for s in accessible_shares]}")
        vulnerabilities.append({
            'name': 'Anonymous Share Access',
            'severity': 'HIGH',
            'description': f'Anonymous access to: {", ".join([s["share"] for s in accessible_shares])}'
        })
    else:
        print("[SECURE] No anonymous share access")
    
    # Overall Assessment
    print(f"\n[SUMMARY] Found {len(vulnerabilities)} vulnerabilities")
    for vuln in vulnerabilities:
        print(f"[{vuln['severity']}] {vuln['name']}: {vuln['description']}")
    
    return vulnerabilities

def main():
    if len(sys.argv) != 2:
        print("Usage: python test_smb_5_phases.py <target_ip>")
        sys.exit(1)
    
    target = sys.argv[1]
    print(f"🎯 SMB 5-Phase Protocol Intelligence Test")
    print(f"Target: {target}")
    print(f"{'='*60}")
    
    client = SMBRawClient(target, 445, timeout=5.0)
    results = {}
    
    # Phase 1: Dialect Negotiation
    results['negotiate'] = test_phase_1_dialect_negotiation(client, target)
    pause_for_user("DIALECT NEGOTIATION")
    
    # Phase 2: Session Setup
    results['session'] = test_phase_2_session_setup(client, target)
    pause_for_user("SESSION SETUP")
    
    # Phase 3: Tree Connect
    results['shares'] = test_phase_3_tree_connect_shares(client, target)
    pause_for_user("TREE CONNECT")
    
    # Phase 4: Pipe Probing
    results['pipes'] = test_phase_4_pipe_probing(client, target)
    pause_for_user("PIPE PROBING")
    
    # Phase 5: Vulnerability Assessment
    results['vulnerabilities'] = test_phase_5_vulnerability_assessment(client, target, results)
    pause_for_user("VULNERABILITY ASSESSMENT")
    
    # Final Summary
    print("🏁 FINAL INTELLIGENCE SUMMARY")
    print("=" * 60)
    
    if results['negotiate']:
        print(f"✅ SMB Protocol: {results['negotiate'].get('dialect', 'Unknown')}")
    else:
        print("❌ SMB Protocol: Blocked/Filtered")
    
    if results['session']:
        domain = results['session'].get('domain_name', 'Unknown')
        print(f"🏛️ Domain: {domain}")
    else:
        print("❌ Domain Discovery: Failed")
    
    if results['shares']:
        accessible = [s for s in results['shares'] if s.get('status') == 'accessible']
        print(f"📁 Accessible Shares: {len(accessible)}")
    else:
        print("❌ Share Enumeration: Failed")
    
    if results['vulnerabilities']:
        critical = [v for v in results['vulnerabilities'] if v.get('severity') == 'CRITICAL']
        high = [v for v in results['vulnerabilities'] if v.get('severity') == 'HIGH']
        print(f"🚨 Vulnerabilities: {len(critical)} Critical, {len(high)} High")
    else:
        print("✅ No vulnerabilities detected")

if __name__ == "__main__":
    main()