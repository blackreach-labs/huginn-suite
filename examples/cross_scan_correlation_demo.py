# examples/cross_scan_correlation_demo.py
"""
Cross-Scan Correlation System Demo

This demo shows how the cross-scan correlation engine analyzes data from multiple
scan types to identify attack paths, security gaps, and provide intelligent insights.
"""

import sys
import os
import json
from datetime import datetime

# Add the app directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.core.cross_scan_correlator import create_cross_scan_correlator
from app.core.centralized_scan_data import centralized_scan_data
from app.core.rpc_data_collector import create_rpc_collector

def populate_demo_data():
    """Populate demo data for correlation analysis"""
    print("🔄 Populating demo scan data...")
    
    # Create collectors
    rpc_collector = create_rpc_collector("demo_company")
    
    # Simulate RPC scan data for lateral movement scenario
    target1 = "192.168.1.100"
    target2 = "192.168.1.101"
    
    # Start RPC scans
    scan_id1 = rpc_collector.start_rpc_scan(target1, "rpc_scanner")
    scan_id2 = rpc_collector.start_rpc_scan(target2, "rpc_scanner")
    
    # Add RPC endpoints (SAMR/LSA interfaces exposed)
    rpc_endpoints1 = [
        {
            'protocol': 'ncacn_np',
            'uuid': '12345778-1234-abcd-ef00-0123456789ab',  # SAMR
            'port': '\\pipe\\samr',
            'version_major': 1,
            'version_minor': 0,
            'annotation': 'Security Account Manager'
        },
        {
            'protocol': 'ncacn_np',
            'uuid': '12345778-1234-abcd-ef00-0123456789ac',  # LSA
            'port': '\\pipe\\lsarpc',
            'version_major': 1,
            'version_minor': 0,
            'annotation': 'Local Security Authority'
        }
    ]
    
    rpc_collector.collect_rpc_endpoints(target1, rpc_endpoints1)
    rpc_collector.collect_rpc_endpoints(target2, rpc_endpoints1)
    
    # Add Windows services (administrative services running)
    services1 = [
        {
            'name': 'Server',
            'display_name': 'Server Service',
            'state': 'Running',
            'start_type': 'Automatic',
            'service_type': 'Win32ShareProcess',
            'binary_path': 'C:\\Windows\\System32\\svchost.exe -k netsvcs'
        },
        {
            'name': 'Workstation',
            'display_name': 'Workstation Service',
            'state': 'Running',
            'start_type': 'Automatic',
            'service_type': 'Win32ShareProcess',
            'binary_path': 'C:\\Windows\\System32\\svchost.exe -k NetworkService'
        }
    ]
    
    rpc_collector.collect_rpc_services(target1, services1)
    rpc_collector.collect_rpc_services(target2, services1)
    
    # Add vulnerabilities (high-severity RPC vulnerabilities)
    vulnerabilities1 = [
        {
            'name': 'MS17-010 EternalBlue SMB Vulnerability',
            'severity': 'Critical',
            'cve': 'CVE-2017-0144',
            'interface': 'SMB',
            'description': 'Remote code execution vulnerability in SMBv1 server',
            'impact': 'Complete system compromise',
            'remediation': 'Apply MS17-010 patch, disable SMBv1',
            'exploitable': True
        },
        {
            'name': 'RPC Endpoint Mapper Information Disclosure',
            'severity': 'High',
            'cve': '',
            'interface': 'RPC Endpoint Mapper',
            'description': 'Anonymous access to RPC endpoint information',
            'impact': 'Service enumeration and attack surface mapping',
            'remediation': 'Restrict anonymous RPC access',
            'exploitable': True
        }
    ]
    
    rpc_collector.collect_rpc_vulnerabilities(target1, vulnerabilities1)
    rpc_collector.collect_rpc_vulnerabilities(target2, vulnerabilities1)
    
    # Add SAMR data (anonymous enumeration possible)
    samr_data1 = {
        'domains': ['WORKGROUP', 'BUILTIN'],
        'sample_users': ['Administrator', 'Guest', 'DefaultAccount'],
        'groups': ['Administrators', 'Users', 'Power Users'],
        'password_policy': {
            'min_length': 0,
            'complexity': False,
            'lockout_threshold': 0
        }
    }
    
    rpc_collector.collect_samr_data(target1, samr_data1)
    rpc_collector.collect_samr_data(target2, samr_data1)
    
    # Add LSA data (domain information accessible)
    lsa_data1 = {
        'domain_name': 'WORKGROUP',
        'trusted_domains': [],
        'policy_info': {
            'audit_log_retention': 7,
            'audit_log_size': 512000
        }
    }
    
    rpc_collector.collect_lsa_data(target1, lsa_data1)
    rpc_collector.collect_lsa_data(target2, lsa_data1)
    
    # Add network endpoints (RPC and SMB ports open)
    network_endpoints1 = [
        {
            'port': 135,
            'protocol': 'tcp',
            'service': 'RPC Endpoint Mapper',
            'state': 'open',
            'banner': 'Microsoft Windows RPC',
            'version': '5.0'
        },
        {
            'port': 445,
            'protocol': 'tcp',
            'service': 'SMB',
            'state': 'open',
            'banner': 'Microsoft Windows SMB',
            'version': '2.1'
        },
        {
            'port': 139,
            'protocol': 'tcp',
            'service': 'NetBIOS-SSN',
            'state': 'open',
            'banner': 'Microsoft Windows NetBIOS',
            'version': '1.0'
        }
    ]
    
    rpc_collector.collect_network_endpoints(target1, network_endpoints1)
    rpc_collector.collect_network_endpoints(target2, network_endpoints1)
    
    # Complete scans
    rpc_collector.complete_rpc_scan(total_results=15)
    
    # Add some DNS and HTTP data for information disclosure correlation
    # Simulate DNS data
    dns_data = [
        {
            'scan_id': 'dns_001',
            'tenant_id': 'demo_company',
            'scan_type': 'dns_subdomains',
            'target': 'example.com',
            'scanner': 'dns_enumerator',
            'timestamp': datetime.now().isoformat(),
            'data': {
                'type': 'subdomain',
                'subdomain': 'admin.example.com',
                'ip': '192.168.1.100',
                'record_type': 'A'
            },
            'dedupe_hash': 'dns_hash_001',
            'first_seen': datetime.now().isoformat(),
            'last_seen': datetime.now().isoformat(),
            'count': 1
        },
        {
            'scan_id': 'dns_002',
            'tenant_id': 'demo_company',
            'scan_type': 'dns_subdomains',
            'target': 'example.com',
            'scanner': 'dns_enumerator',
            'timestamp': datetime.now().isoformat(),
            'data': {
                'type': 'subdomain',
                'subdomain': 'internal.example.com',
                'ip': '192.168.1.101',
                'record_type': 'A'
            },
            'dedupe_hash': 'dns_hash_002',
            'first_seen': datetime.now().isoformat(),
            'last_seen': datetime.now().isoformat(),
            'count': 1
        }
    ]
    
    # Add DNS data directly to centralized database
    for dns_item in dns_data:
        centralized_scan_data.add_scan_result(
            scan_id=dns_item['scan_id'],
            tenant_id=dns_item['tenant_id'],
            scan_type=dns_item['scan_type'],
            target=dns_item['target'],
            scanner=dns_item['scanner'],
            result_data=dns_item['data']
        )
    
    # Add HTTP directory data for information disclosure
    http_data = [
        {
            'scan_id': 'http_001',
            'tenant_id': 'demo_company',
            'scan_type': 'http_directories',
            'target': '192.168.1.100',
            'scanner': 'http_enumerator',
            'timestamp': datetime.now().isoformat(),
            'data': {
                'type': 'directory',
                'path': '/admin',
                'status_code': 200,
                'size': 1024,
                'accessible': True
            },
            'dedupe_hash': 'http_hash_001',
            'first_seen': datetime.now().isoformat(),
            'last_seen': datetime.now().isoformat(),
            'count': 1
        },
        {
            'scan_id': 'http_002',
            'tenant_id': 'demo_company',
            'scan_type': 'http_directories',
            'target': '192.168.1.100',
            'scanner': 'http_enumerator',
            'timestamp': datetime.now().isoformat(),
            'data': {
                'type': 'directory',
                'path': '/config',
                'status_code': 200,
                'size': 2048,
                'accessible': True
            },
            'dedupe_hash': 'http_hash_002',
            'first_seen': datetime.now().isoformat(),
            'last_seen': datetime.now().isoformat(),
            'count': 1
        }
    ]
    
    # Add HTTP data
    for http_item in http_data:
        centralized_scan_data.add_scan_result(
            scan_id=http_item['scan_id'],
            tenant_id=http_item['tenant_id'],
            scan_type=http_item['scan_type'],
            target=http_item['target'],
            scanner=http_item['scanner'],
            result_data=http_item['data']
        )
    
    print("✅ Demo data populated successfully!")

def demonstrate_correlation_analysis():
    """Demonstrate correlation analysis capabilities"""
    print("\n🔍 Running Cross-Scan Correlation Analysis...")
    
    # Create correlator
    correlator = create_cross_scan_correlator("demo_company")
    
    # Get correlations
    correlations = correlator.correlate_all_findings(time_window_hours=24)
    
    print(f"\n📊 Found {len(correlations)} correlations:")
    print("=" * 60)
    
    for i, correlation in enumerate(correlations, 1):
        print(f"\n{i}. {correlation.title}")
        print(f"   Type: {correlation.correlation_type.replace('_', ' ').title()}")
        print(f"   Severity: {correlation.severity}")
        print(f"   Risk Score: {correlation.risk_score}/10")
        print(f"   Affected Targets: {', '.join(correlation.affected_targets)}")
        print(f"   Scan Types: {', '.join(correlation.scan_types_involved)}")
        print(f"   Description: {correlation.description}")
        
        print(f"   Evidence:")
        for evidence in correlation.evidence:
            print(f"     - {evidence['type'].replace('_', ' ').title()}: {evidence.get('count', 'N/A')} items")
        
        print(f"   Attack Path:")
        for j, step in enumerate(correlation.attack_path, 1):
            print(f"     {j}. {step}")
        
        print(f"   Remediation: {correlation.remediation}")
    
    return correlations

def demonstrate_attack_chains(correlations):
    """Demonstrate attack chain generation"""
    print("\n⛓️ Generating Attack Chains...")
    
    correlator = create_cross_scan_correlator("demo_company")
    attack_chains = correlator.generate_attack_chains(correlations)
    
    print(f"\n🎯 Generated {len(attack_chains)} attack chains:")
    print("=" * 60)
    
    for i, chain in enumerate(attack_chains, 1):
        print(f"\n{i}. Attack Chain: {chain.chain_id}")
        print(f"   Risk Level: {chain.risk_level}")
        print(f"   Likelihood: {chain.likelihood:.2f}")
        print(f"   Entry Points: {', '.join(chain.entry_points)}")
        print(f"   Final Objectives: {', '.join(chain.final_objectives)}")
        
        print(f"   Attack Steps:")
        for step in chain.attack_steps:
            print(f"     Step {step['step_number']}: {step['title']}")
            print(f"       Type: {step['correlation_type'].replace('_', ' ').title()}")
            print(f"       Risk Score: {step['risk_score']}/10")
    
    return attack_chains

def demonstrate_export_capabilities(correlations):
    """Demonstrate export capabilities"""
    print("\n📤 Demonstrating Export Capabilities...")
    
    correlator = create_cross_scan_correlator("demo_company")
    
    # Export to JSON
    json_export = correlator.export_correlations(correlations, format='json')
    
    # Save to file
    export_filename = f"correlation_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(export_filename, 'w') as f:
        f.write(json_export)
    
    print(f"✅ Correlations exported to: {export_filename}")
    print(f"📊 Export contains {len(correlations)} correlations with full details")
    
    # Show sample of exported data
    export_data = json.loads(json_export)
    if export_data:
        sample = export_data[0]
        print(f"\n📋 Sample exported correlation:")
        print(f"   ID: {sample['correlation_id']}")
        print(f"   Type: {sample['correlation_type']}")
        print(f"   Severity: {sample['severity']}")
        print(f"   Risk Score: {sample['risk_score']}")

def demonstrate_real_time_capabilities():
    """Demonstrate real-time correlation capabilities"""
    print("\n⏱️ Real-time Correlation Capabilities:")
    print("=" * 50)
    
    print("✅ Automatic correlation updates every 30 seconds")
    print("✅ New scan data automatically triggers re-analysis")
    print("✅ UI components update in real-time with new correlations")
    print("✅ Attack chains recalculated when new correlations found")
    print("✅ Risk scores dynamically adjusted based on new evidence")
    
    print("\n🔄 Integration Points:")
    print("   - Centralized scan database monitors for new data")
    print("   - Correlation engine triggered on data changes")
    print("   - UI widgets receive automatic updates via Qt signals")
    print("   - Dashboard refreshes correlation statistics")
    print("   - Export capabilities available for all correlation data")

def main():
    """Main demo function"""
    print("🚀 Cross-Scan Correlation System Demo")
    print("=" * 50)
    
    try:
        # Step 1: Populate demo data
        populate_demo_data()
        
        # Step 2: Demonstrate correlation analysis
        correlations = demonstrate_correlation_analysis()
        
        # Step 3: Demonstrate attack chains
        if correlations:
            attack_chains = demonstrate_attack_chains(correlations)
        
        # Step 4: Demonstrate export capabilities
        if correlations:
            demonstrate_export_capabilities(correlations)
        
        # Step 5: Show real-time capabilities
        demonstrate_real_time_capabilities()
        
        print("\n🎉 Cross-Scan Correlation Demo Complete!")
        print("\n💡 Key Benefits Demonstrated:")
        print("   ✅ Intelligent correlation across multiple scan types")
        print("   ✅ Attack path identification and risk assessment")
        print("   ✅ Automated security gap analysis")
        print("   ✅ Actionable remediation recommendations")
        print("   ✅ Real-time correlation updates")
        print("   ✅ Comprehensive export and reporting")
        
        print(f"\n📊 Summary:")
        print(f"   - Analyzed data from 5+ scan types")
        print(f"   - Found {len(correlations) if correlations else 0} security correlations")
        print(f"   - Generated attack chains with risk assessment")
        print(f"   - Provided specific remediation guidance")
        
    except Exception as e:
        print(f"❌ Demo error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()