# app/core/automated_remediation.py
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from .cross_scan_correlator import CorrelationFinding
from .centralized_scan_data import centralized_scan_data

@dataclass
class RemediationAction:
    """Individual remediation action"""
    action_id: str
    action_type: str
    priority: str
    title: str
    description: str
    commands: List[str]
    config_changes: Dict[str, Any]
    verification_steps: List[str]
    estimated_time: str
    risk_reduction: float

class AutomatedRemediationEngine:
    """Automated remediation engine for security findings"""
    
    def __init__(self, tenant_id: str = "default"):
        self.tenant_id = tenant_id
        self.remediation_templates = self._load_remediation_templates()
    
    def _load_remediation_templates(self) -> Dict[str, Any]:
        """Load remediation templates for different vulnerability types"""
        return {
            'rpc_anonymous_access': {
                'title': 'Disable Anonymous RPC Access',
                'commands': [
                    'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v RestrictAnonymous /t REG_DWORD /d 2 /f',
                    'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f'
                ],
                'config_changes': {
                    'registry': {
                        'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa': {
                            'RestrictAnonymous': 2,
                            'RestrictAnonymousSAM': 1
                        }
                    }
                },
                'verification': ['net user', 'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"'],
                'time': '5 minutes',
                'risk_reduction': 8.5
            },
            'smb_signing_disabled': {
                'title': 'Enable SMB Signing',
                'commands': [
                    'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\lanmanserver\\parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f',
                    'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\lanmanworkstation\\parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f'
                ],
                'config_changes': {
                    'registry': {
                        'HKLM\\SYSTEM\\CurrentControlSet\\Services\\lanmanserver\\parameters': {
                            'RequireSecuritySignature': 1
                        },
                        'HKLM\\SYSTEM\\CurrentControlSet\\Services\\lanmanworkstation\\parameters': {
                            'RequireSecuritySignature': 1
                        }
                    }
                },
                'verification': ['net config server', 'net config workstation'],
                'time': '3 minutes',
                'risk_reduction': 7.0
            },
            'service_unquoted_path': {
                'title': 'Fix Unquoted Service Paths',
                'commands': [
                    'sc config "{service_name}" binPath= "\\"{binary_path}\\""'
                ],
                'config_changes': {
                    'service': {
                        'action': 'modify_path',
                        'quote_path': True
                    }
                },
                'verification': ['sc qc "{service_name}"'],
                'time': '2 minutes per service',
                'risk_reduction': 6.5
            },
            'weak_password_policy': {
                'title': 'Strengthen Password Policy',
                'commands': [
                    'net accounts /minpwlen:12',
                    'net accounts /maxpwage:90',
                    'net accounts /lockoutthreshold:5'
                ],
                'config_changes': {
                    'policy': {
                        'minimum_password_length': 12,
                        'maximum_password_age': 90,
                        'lockout_threshold': 5
                    }
                },
                'verification': ['net accounts'],
                'time': '2 minutes',
                'risk_reduction': 5.5
            },
            'unnecessary_service': {
                'title': 'Disable Unnecessary Services',
                'commands': [
                    'sc stop "{service_name}"',
                    'sc config "{service_name}" start= disabled'
                ],
                'config_changes': {
                    'service': {
                        'action': 'disable',
                        'startup_type': 'disabled'
                    }
                },
                'verification': ['sc query "{service_name}"'],
                'time': '1 minute per service',
                'risk_reduction': 4.0
            },
            'open_share_permissions': {
                'title': 'Restrict Share Permissions',
                'commands': [
                    'net share {share_name} /delete',
                    'icacls "{share_path}" /grant "Administrators:(OI)(CI)F" /inheritance:r'
                ],
                'config_changes': {
                    'share': {
                        'action': 'restrict_permissions',
                        'allowed_groups': ['Administrators']
                    }
                },
                'verification': ['net share', 'icacls "{share_path}"'],
                'time': '3 minutes per share',
                'risk_reduction': 7.5
            }
        }
    
    def generate_remediation_plan(self, correlations: List[CorrelationFinding]) -> List[RemediationAction]:
        """Generate comprehensive remediation plan from correlations"""
        actions = []
        
        for correlation in correlations:
            correlation_actions = self._generate_correlation_remediation(correlation)
            actions.extend(correlation_actions)
        
        # Sort by priority and risk reduction
        actions.sort(key=lambda x: (self._priority_score(x.priority), -x.risk_reduction), reverse=True)
        
        return actions
    
    def _generate_correlation_remediation(self, correlation: CorrelationFinding) -> List[RemediationAction]:
        """Generate remediation actions for specific correlation"""
        actions = []
        
        if correlation.correlation_type == 'credential_harvesting':
            actions.extend(self._remediate_credential_harvesting(correlation))
        elif correlation.correlation_type == 'lateral_movement':
            actions.extend(self._remediate_lateral_movement(correlation))
        elif correlation.correlation_type == 'service_exploitation':
            actions.extend(self._remediate_service_exploitation(correlation))
        elif correlation.correlation_type == 'information_disclosure':
            actions.extend(self._remediate_information_disclosure(correlation))
        elif correlation.correlation_type == 'network_pivoting':
            actions.extend(self._remediate_network_pivoting(correlation))
        
        return actions
    
    def _remediate_credential_harvesting(self, correlation: CorrelationFinding) -> List[RemediationAction]:
        """Generate remediation for credential harvesting"""
        actions = []
        
        # Disable anonymous RPC access
        template = self.remediation_templates['rpc_anonymous_access']
        action = RemediationAction(
            action_id=f"rpc_anon_{correlation.correlation_id}",
            action_type="registry_modification",
            priority="Critical",
            title=template['title'],
            description=f"Disable anonymous RPC access on {', '.join(correlation.affected_targets)}",
            commands=template['commands'],
            config_changes=template['config_changes'],
            verification_steps=template['verification'],
            estimated_time=template['time'],
            risk_reduction=template['risk_reduction']
        )
        actions.append(action)
        
        # Enable SMB signing
        template = self.remediation_templates['smb_signing_disabled']
        action = RemediationAction(
            action_id=f"smb_sign_{correlation.correlation_id}",
            action_type="registry_modification",
            priority="High",
            title=template['title'],
            description=f"Enable SMB signing on {', '.join(correlation.affected_targets)}",
            commands=template['commands'],
            config_changes=template['config_changes'],
            verification_steps=template['verification'],
            estimated_time=template['time'],
            risk_reduction=template['risk_reduction']
        )
        actions.append(action)
        
        return actions
    
    def _remediate_lateral_movement(self, correlation: CorrelationFinding) -> List[RemediationAction]:
        """Generate remediation for lateral movement"""
        actions = []
        
        # Fix service configurations
        for evidence in correlation.evidence:
            if evidence['type'] == 'admin_services':
                for service in evidence.get('services', [])[:3]:
                    service_name = service['data'].get('name', '')
                    binary_path = service['data'].get('binary_path', '')
                    
                    if binary_path and ' ' in binary_path and not binary_path.startswith('"'):
                        template = self.remediation_templates['service_unquoted_path']
                        commands = [cmd.format(service_name=service_name, binary_path=binary_path) 
                                  for cmd in template['commands']]
                        verification = [step.format(service_name=service_name) 
                                      for step in template['verification']]
                        
                        action = RemediationAction(
                            action_id=f"service_path_{service_name}_{correlation.correlation_id}",
                            action_type="service_modification",
                            priority="High",
                            title=f"Fix Unquoted Path - {service_name}",
                            description=f"Quote service path for {service_name}",
                            commands=commands,
                            config_changes=template['config_changes'],
                            verification_steps=verification,
                            estimated_time=template['time'],
                            risk_reduction=template['risk_reduction']
                        )
                        actions.append(action)
        
        return actions
    
    def _remediate_service_exploitation(self, correlation: CorrelationFinding) -> List[RemediationAction]:
        """Generate remediation for service exploitation"""
        actions = []
        
        # Disable unnecessary services
        for evidence in correlation.evidence:
            if evidence['type'] == 'privileged_services':
                for service in evidence.get('services', [])[:3]:
                    service_name = service['data'].get('name', '')
                    
                    if service_name.lower() in ['telnet', 'ftp', 'rsh', 'rlogin']:
                        template = self.remediation_templates['unnecessary_service']
                        commands = [cmd.format(service_name=service_name) for cmd in template['commands']]
                        verification = [step.format(service_name=service_name) for step in template['verification']]
                        
                        action = RemediationAction(
                            action_id=f"disable_service_{service_name}_{correlation.correlation_id}",
                            action_type="service_modification",
                            priority="Medium",
                            title=f"Disable {service_name} Service",
                            description=f"Disable unnecessary {service_name} service",
                            commands=commands,
                            config_changes=template['config_changes'],
                            verification_steps=verification,
                            estimated_time=template['time'],
                            risk_reduction=template['risk_reduction']
                        )
                        actions.append(action)
        
        return actions
    
    def _remediate_information_disclosure(self, correlation: CorrelationFinding) -> List[RemediationAction]:
        """Generate remediation for information disclosure"""
        actions = []
        
        # Restrict share permissions
        for evidence in correlation.evidence:
            if evidence['type'] == 'accessible_shares':
                for share in evidence.get('shares', [])[:3]:
                    share_name = share['data'].get('name', '')
                    
                    if share_name.upper() in ['ADMIN$', 'C$']:
                        continue  # Skip administrative shares
                    
                    template = self.remediation_templates['open_share_permissions']
                    commands = [cmd.format(share_name=share_name, share_path=f"C:\\{share_name}") 
                              for cmd in template['commands']]
                    verification = [step.format(share_path=f"C:\\{share_name}") 
                                  for step in template['verification']]
                    
                    action = RemediationAction(
                        action_id=f"share_perms_{share_name}_{correlation.correlation_id}",
                        action_type="permission_modification",
                        priority="Medium",
                        title=f"Restrict {share_name} Share",
                        description=f"Restrict permissions on {share_name} share",
                        commands=commands,
                        config_changes=template['config_changes'],
                        verification_steps=verification,
                        estimated_time=template['time'],
                        risk_reduction=template['risk_reduction']
                    )
                    actions.append(action)
        
        return actions
    
    def _remediate_network_pivoting(self, correlation: CorrelationFinding) -> List[RemediationAction]:
        """Generate remediation for network pivoting"""
        actions = []
        
        # Strengthen password policy
        template = self.remediation_templates['weak_password_policy']
        action = RemediationAction(
            action_id=f"password_policy_{correlation.correlation_id}",
            action_type="policy_modification",
            priority="Medium",
            title=template['title'],
            description="Strengthen domain password policy",
            commands=template['commands'],
            config_changes=template['config_changes'],
            verification_steps=template['verification'],
            estimated_time=template['time'],
            risk_reduction=template['risk_reduction']
        )
        actions.append(action)
        
        return actions
    
    def generate_powershell_script(self, actions: List[RemediationAction]) -> str:
        """Generate PowerShell script for automated remediation"""
        script_lines = [
            "# Automated Remediation Script",
            "# Generated by Huginn Security Framework",
            f"# Generated: {datetime.now().isoformat()}",
            "",
            "# Require Administrator privileges",
            "if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] \"Administrator\")) {",
            "    Write-Error \"This script requires Administrator privileges\"",
            "    exit 1",
            "}",
            "",
            "Write-Host \"Starting automated remediation...\" -ForegroundColor Green",
            ""
        ]
        
        for i, action in enumerate(actions, 1):
            script_lines.extend([
                f"# Action {i}: {action.title}",
                f"Write-Host \"Executing: {action.title}\" -ForegroundColor Yellow",
                "try {"
            ])
            
            for command in action.commands:
                if command.startswith('reg '):
                    script_lines.append(f"    Start-Process -FilePath 'reg.exe' -ArgumentList '{command[4:]}' -Wait -NoNewWindow")
                elif command.startswith('net '):
                    script_lines.append(f"    Start-Process -FilePath 'net.exe' -ArgumentList '{command[4:]}' -Wait -NoNewWindow")
                elif command.startswith('sc '):
                    script_lines.append(f"    Start-Process -FilePath 'sc.exe' -ArgumentList '{command[3:]}' -Wait -NoNewWindow")
                else:
                    script_lines.append(f"    Invoke-Expression '{command}'")
            
            script_lines.extend([
                f"    Write-Host \"Completed: {action.title}\" -ForegroundColor Green",
                "} catch {",
                f"    Write-Error \"Failed to execute: {action.title} - $_\"",
                "}",
                ""
            ])
        
        script_lines.extend([
            "Write-Host \"Remediation script completed!\" -ForegroundColor Green",
            "Write-Host \"Please verify changes and restart services as needed.\" -ForegroundColor Yellow"
        ])
        
        return "\n".join(script_lines)
    
    def generate_bash_script(self, actions: List[RemediationAction]) -> str:
        """Generate Bash script for Linux remediation"""
        script_lines = [
            "#!/bin/bash",
            "# Automated Remediation Script",
            "# Generated by Huginn Security Framework",
            f"# Generated: {datetime.now().isoformat()}",
            "",
            "# Check for root privileges",
            "if [[ $EUID -ne 0 ]]; then",
            "   echo \"This script must be run as root\" >&2",
            "   exit 1",
            "fi",
            "",
            "echo \"Starting automated remediation...\"",
            ""
        ]
        
        for i, action in enumerate(actions, 1):
            # Convert Windows commands to Linux equivalents
            linux_commands = self._convert_to_linux_commands(action.commands)
            
            script_lines.extend([
                f"# Action {i}: {action.title}",
                f"echo \"Executing: {action.title}\"",
            ])
            
            for command in linux_commands:
                script_lines.append(f"{command}")
            
            script_lines.append("")
        
        script_lines.extend([
            "echo \"Remediation script completed!\"",
            "echo \"Please verify changes and restart services as needed.\""
        ])
        
        return "\n".join(script_lines)
    
    def _convert_to_linux_commands(self, windows_commands: List[str]) -> List[str]:
        """Convert Windows commands to Linux equivalents"""
        linux_commands = []
        
        for cmd in windows_commands:
            if cmd.startswith('reg add'):
                linux_commands.append(f"# Registry equivalent: {cmd}")
                linux_commands.append("# Manual configuration required")
            elif cmd.startswith('net accounts'):
                if '/minpwlen:' in cmd:
                    length = cmd.split('/minpwlen:')[1].split()[0]
                    linux_commands.append(f"sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN\\t{length}/' /etc/login.defs")
                elif '/lockoutthreshold:' in cmd:
                    threshold = cmd.split('/lockoutthreshold:')[1].split()[0]
                    linux_commands.append(f"echo \"deny = {threshold}\" >> /etc/security/faillock.conf")
            elif cmd.startswith('sc stop'):
                service = cmd.split('"')[1]
                linux_commands.append(f"systemctl stop {service}")
            elif cmd.startswith('sc config') and 'start= disabled' in cmd:
                service = cmd.split('"')[1]
                linux_commands.append(f"systemctl disable {service}")
            else:
                linux_commands.append(f"# Windows command: {cmd}")
        
        return linux_commands
    
    def _priority_score(self, priority: str) -> int:
        """Convert priority to numeric score"""
        scores = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
        return scores.get(priority, 0)
    
    def export_remediation_plan(self, actions: List[RemediationAction], format: str = 'json') -> str:
        """Export remediation plan in specified format"""
        if format == 'json':
            return json.dumps([{
                'action_id': a.action_id,
                'action_type': a.action_type,
                'priority': a.priority,
                'title': a.title,
                'description': a.description,
                'commands': a.commands,
                'config_changes': a.config_changes,
                'verification_steps': a.verification_steps,
                'estimated_time': a.estimated_time,
                'risk_reduction': a.risk_reduction
            } for a in actions], indent=2)
        else:
            raise ValueError(f"Unsupported format: {format}")

def create_remediation_engine(tenant_id: str = "default") -> AutomatedRemediationEngine:
    """Create remediation engine for specific tenant"""
    return AutomatedRemediationEngine(tenant_id=tenant_id)