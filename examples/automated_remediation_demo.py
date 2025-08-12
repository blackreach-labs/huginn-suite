# examples/automated_remediation_demo.py
"""
Automated Remediation Engine Demo

This demo shows how the automated remediation engine generates specific
configuration fixes and executable scripts for identified security vulnerabilities.
"""

import sys
import os
from datetime import datetime

# Add the app directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.core.automated_remediation import create_remediation_engine
from app.core.cross_scan_correlator import create_cross_scan_correlator, CorrelationFinding

def create_demo_correlations():
    """Create demo correlation findings for remediation"""
    correlations = [
        CorrelationFinding(
            correlation_id="cred_harvest_001",
            correlation_type="credential_harvesting",
            severity="Critical",
            title="Credential Harvesting Opportunity - 192.168.1.100",
            description="Target allows anonymous RPC access and has accessible administrative shares",
            affected_targets=["192.168.1.100"],
            scan_types_involved=["rpc_samr", "rpc_lsa", "smb_shares"],
            evidence=[
                {
                    'type': 'anonymous_access',
                    'count': 2,
                    'methods': [
                        {'type': 'SAMR', 'data': {'domains': ['WORKGROUP'], 'users': ['Administrator']}},
                        {'type': 'LSA', 'data': {'domain_name': 'WORKGROUP'}}
                    ]
                },
                {
                    'type': 'accessible_shares',
                    'count': 2,
                    'shares': [
                        {'data': {'name': 'ADMIN$', 'accessible': True}},
                        {'data': {'name': 'C$', 'accessible': True}}
                    ]
                }
            ],
            attack_path=[
                "1. Connect anonymously to RPC services",
                "2. Enumerate domain users via SAMR interface",
                "3. Access administrative shares for credential files",
                "4. Extract hashes from SAM/SECURITY hives"
            ],
            risk_score=9.2,
            remediation="Disable anonymous access, restrict share permissions, enable SMB signing",
            timestamp=datetime.now().isoformat()
        ),
        CorrelationFinding(
            correlation_id="lateral_move_001",
            correlation_type="lateral_movement",
            severity="High",
            title="Lateral Movement Opportunity - 192.168.1.101",
            description="Target exposes administrative services with unquoted service paths",
            affected_targets=["192.168.1.101"],
            scan_types_involved=["rpc_services", "rpc_endpoints", "port_open_ports"],
            evidence=[
                {
                    'type': 'admin_services',
                    'count': 2,
                    'services': [
                        {
                            'data': {
                                'name': 'VulnService',
                                'binary_path': 'C:\\Program Files\\Vulnerable App\\service.exe',
                                'state': 'Running'
                            }
                        },
                        {
                            'data': {
                                'name': 'TestService',
                                'binary_path': 'C:\\Test Path\\app.exe',
                                'state': 'Running'
                            }
                        }
                    ]
                }
            ],
            attack_path=[
                "1. Identify unquoted service paths",
                "2. Place malicious executable in path",
                "3. Restart service to execute payload",
                "4. Gain SYSTEM privileges"
            ],
            risk_score=8.5,
            remediation="Quote service paths, restrict file system permissions",
            timestamp=datetime.now().isoformat()
        ),
        CorrelationFinding(
            correlation_id="service_exploit_001",
            correlation_type="service_exploitation",
            severity="High",
            title="Service Exploitation Chain - 192.168.1.102",
            description="Target has exploitable vulnerabilities in privileged services",
            affected_targets=["192.168.1.102"],
            scan_types_involved=["rpc_vulnerabilities", "rpc_services"],
            evidence=[
                {
                    'type': 'privileged_services',
                    'count': 2,
                    'services': [
                        {'data': {'name': 'telnet', 'state': 'Running'}},
                        {'data': {'name': 'ftp', 'state': 'Running'}}
                    ]
                }
            ],
            attack_path=[
                "1. Identify vulnerable service versions",
                "2. Craft exploit for specific vulnerability",
                "3. Execute exploit against privileged service",
                "4. Gain elevated privileges on target system"
            ],
            risk_score=8.8,
            remediation="Disable unnecessary services, apply security patches",
            timestamp=datetime.now().isoformat()
        )
    ]
    
    return correlations

def demonstrate_remediation_generation():
    """Demonstrate remediation plan generation"""
    print("🛠️ Generating Automated Remediation Plan...")
    print("=" * 60)
    
    # Create remediation engine
    remediation_engine = create_remediation_engine("demo_company")
    
    # Get demo correlations
    correlations = create_demo_correlations()
    
    # Generate remediation plan
    remediation_actions = remediation_engine.generate_remediation_plan(correlations)
    
    print(f"\n📋 Generated {len(remediation_actions)} remediation actions:")
    print("=" * 60)
    
    total_risk_reduction = 0
    total_time_minutes = 0
    
    for i, action in enumerate(remediation_actions, 1):
        print(f"\n{i}. {action.title}")
        print(f"   Priority: {action.priority}")
        print(f"   Type: {action.action_type.replace('_', ' ').title()}")
        print(f"   Estimated Time: {action.estimated_time}")
        print(f"   Risk Reduction: {action.risk_reduction}/10")
        print(f"   Description: {action.description}")
        
        print(f"   Commands:")
        for cmd in action.commands:
            print(f"     - {cmd}")
        
        print(f"   Verification:")
        for verify in action.verification_steps:
            print(f"     - {verify}")
        
        total_risk_reduction += action.risk_reduction
        
        # Extract time in minutes
        time_str = action.estimated_time
        if 'minute' in time_str:
            minutes = int(time_str.split()[0])
            total_time_minutes += minutes
    
    print(f"\n📊 Remediation Plan Summary:")
    print(f"   Total Actions: {len(remediation_actions)}")
    print(f"   Estimated Time: {total_time_minutes} minutes")
    print(f"   Average Risk Reduction: {total_risk_reduction/len(remediation_actions):.1f}/10")
    
    return remediation_actions

def demonstrate_powershell_generation(remediation_actions):
    """Demonstrate PowerShell script generation"""
    print("\n💻 Generating PowerShell Remediation Script...")
    print("=" * 60)
    
    remediation_engine = create_remediation_engine("demo_company")
    powershell_script = remediation_engine.generate_powershell_script(remediation_actions)
    
    # Save script to file
    script_filename = f"remediation_demo_{datetime.now().strftime('%Y%m%d_%H%M%S')}.ps1"
    with open(script_filename, 'w') as f:
        f.write(powershell_script)
    
    print(f"✅ PowerShell script saved to: {script_filename}")
    print(f"📄 Script contains {len(remediation_actions)} remediation actions")
    
    # Show sample of script
    lines = powershell_script.split('\n')
    print(f"\n📋 Sample PowerShell Script (first 20 lines):")
    print("-" * 50)
    for line in lines[:20]:
        print(line)
    if len(lines) > 20:
        print("... (truncated)")
    
    return script_filename

def demonstrate_bash_generation(remediation_actions):
    """Demonstrate Bash script generation"""
    print("\n🐧 Generating Bash Remediation Script...")
    print("=" * 60)
    
    remediation_engine = create_remediation_engine("demo_company")
    bash_script = remediation_engine.generate_bash_script(remediation_actions)
    
    # Save script to file
    script_filename = f"remediation_demo_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sh"
    with open(script_filename, 'w') as f:
        f.write(bash_script)
    
    print(f"✅ Bash script saved to: {script_filename}")
    print(f"📄 Script contains Linux equivalents for {len(remediation_actions)} actions")
    
    # Show sample of script
    lines = bash_script.split('\n')
    print(f"\n📋 Sample Bash Script (first 15 lines):")
    print("-" * 50)
    for line in lines[:15]:
        print(line)
    if len(lines) > 15:
        print("... (truncated)")
    
    return script_filename

def demonstrate_json_export(remediation_actions):
    """Demonstrate JSON export capabilities"""
    print("\n📤 Demonstrating JSON Export...")
    print("=" * 60)
    
    remediation_engine = create_remediation_engine("demo_company")
    json_export = remediation_engine.export_remediation_plan(remediation_actions)
    
    # Save to file
    export_filename = f"remediation_plan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(export_filename, 'w') as f:
        f.write(json_export)
    
    print(f"✅ Remediation plan exported to: {export_filename}")
    print(f"📊 Export contains {len(remediation_actions)} actions with full details")
    
    # Show sample of exported data
    import json
    export_data = json.loads(json_export)
    if export_data:
        sample = export_data[0]
        print(f"\n📋 Sample exported action:")
        print(f"   ID: {sample['action_id']}")
        print(f"   Title: {sample['title']}")
        print(f"   Priority: {sample['priority']}")
        print(f"   Risk Reduction: {sample['risk_reduction']}")
        print(f"   Commands: {len(sample['commands'])} commands")
    
    return export_filename

def demonstrate_remediation_templates():
    """Demonstrate available remediation templates"""
    print("\n📚 Available Remediation Templates:")
    print("=" * 60)
    
    remediation_engine = create_remediation_engine("demo_company")
    templates = remediation_engine.remediation_templates
    
    for template_name, template_config in templates.items():
        print(f"\n🔧 {template_name.replace('_', ' ').title()}")
        print(f"   Title: {template_config['title']}")
        print(f"   Time: {template_config['time']}")
        print(f"   Risk Reduction: {template_config['risk_reduction']}/10")
        print(f"   Commands: {len(template_config['commands'])} commands")
        print(f"   Verification: {len(template_config['verification'])} steps")

def demonstrate_integration_capabilities():
    """Demonstrate integration capabilities"""
    print("\n🔗 Integration Capabilities:")
    print("=" * 50)
    
    print("✅ Cross-Scan Correlation Integration")
    print("   - Automatically generates remediation from correlation findings")
    print("   - Maps vulnerabilities to specific remediation templates")
    print("   - Prioritizes actions based on risk scores")
    
    print("\n✅ Multi-Platform Script Generation")
    print("   - PowerShell scripts for Windows environments")
    print("   - Bash scripts for Linux environments")
    print("   - Registry modifications and service configurations")
    
    print("\n✅ Configuration Management")
    print("   - Structured configuration changes")
    print("   - Verification steps for each action")
    print("   - Rollback guidance and safety checks")
    
    print("\n✅ Export and Automation")
    print("   - JSON export for integration with other tools")
    print("   - Executable scripts for immediate deployment")
    print("   - Documentation and audit trails")

def main():
    """Main demo function"""
    print("🚀 Automated Remediation Engine Demo")
    print("=" * 50)
    
    try:
        # Step 1: Generate remediation plan
        remediation_actions = demonstrate_remediation_generation()
        
        # Step 2: Generate PowerShell script
        if remediation_actions:
            ps_filename = demonstrate_powershell_generation(remediation_actions)
        
        # Step 3: Generate Bash script
        if remediation_actions:
            bash_filename = demonstrate_bash_generation(remediation_actions)
        
        # Step 4: Export JSON
        if remediation_actions:
            json_filename = demonstrate_json_export(remediation_actions)
        
        # Step 5: Show available templates
        demonstrate_remediation_templates()
        
        # Step 6: Show integration capabilities
        demonstrate_integration_capabilities()
        
        print("\n🎉 Automated Remediation Demo Complete!")
        print("\n💡 Key Benefits Demonstrated:")
        print("   ✅ Automated remediation plan generation")
        print("   ✅ Multi-platform script generation (PowerShell/Bash)")
        print("   ✅ Specific configuration fixes and commands")
        print("   ✅ Risk-based prioritization")
        print("   ✅ Verification and validation steps")
        print("   ✅ Export capabilities for integration")
        
        print(f"\n📊 Demo Results:")
        print(f"   - Generated {len(remediation_actions) if remediation_actions else 0} remediation actions")
        print(f"   - Created executable PowerShell and Bash scripts")
        print(f"   - Provided specific configuration changes")
        print(f"   - Included verification and rollback guidance")
        
        print(f"\n📁 Generated Files:")
        if remediation_actions:
            print(f"   - PowerShell: {ps_filename}")
            print(f"   - Bash: {bash_filename}")
            print(f"   - JSON: {json_filename}")
        
    except Exception as e:
        print(f"❌ Demo error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()