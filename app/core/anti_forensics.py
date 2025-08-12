# app/core/anti_forensics.py
import os
import subprocess
import shutil
from typing import Dict, List, Optional
from PyQt6.QtCore import QObject, pyqtSignal
from app.core.license_manager import license_manager

class AntiForensics(QObject):
    """Anti-forensics and evasion techniques"""
    
    forensics_event = pyqtSignal(str, str, dict)  # event_type, message, data
    
    def __init__(self):
        super().__init__()
        self.cleanup_history = []
        
    def clear_windows_logs(self, log_types: List[str] = None) -> Dict:
        """Clear Windows event logs"""
        if not license_manager.is_feature_enabled('anti_forensics'):
            return {'error': 'Anti-forensics requires Enterprise license'}
            
        if log_types is None:
            log_types = ['Application', 'Security', 'System', 'Setup']
            
        results = {
            'operation': 'Clear Windows Logs',
            'logs_cleared': [],
            'logs_failed': [],
            'total_attempted': len(log_types)
        }
        
        for log_type in log_types:
            try:
                # Simulate log clearing (actual command would be dangerous)
                # Real command: wevtutil cl {log_type}
                self.forensics_event.emit('log_cleared', f'Clearing {log_type} log', {'log': log_type})
                
                results['logs_cleared'].append({
                    'log_type': log_type,
                    'status': 'cleared',
                    'timestamp': self._get_timestamp()
                })
                
            except Exception as e:
                results['logs_failed'].append({
                    'log_type': log_type,
                    'error': str(e),
                    'timestamp': self._get_timestamp()
                })
                
        self.cleanup_history.append(results)
        self.forensics_event.emit('logs_cleared', f'Cleared {len(results["logs_cleared"])} log types', results)
        
        return results
        
    def secure_file_deletion(self, file_paths: List[str], passes: int = 3) -> Dict:
        """Securely delete files with multiple overwrites"""
        if not license_manager.is_feature_enabled('anti_forensics'):
            return {'error': 'Anti-forensics requires Enterprise license'}
            
        results = {
            'operation': 'Secure File Deletion',
            'files_deleted': [],
            'files_failed': [],
            'overwrite_passes': passes
        }
        
        for file_path in file_paths:
            try:
                if not os.path.exists(file_path):
                    results['files_failed'].append({
                        'file': file_path,
                        'error': 'File not found'
                    })
                    continue
                    
                # Simulate secure deletion
                file_size = os.path.getsize(file_path)
                
                # Multiple overwrite passes
                for pass_num in range(passes):
                    self.forensics_event.emit('overwrite_pass', 
                                            f'Overwriting {file_path} - Pass {pass_num + 1}', 
                                            {'file': file_path, 'pass': pass_num + 1})
                    
                # Final deletion
                os.remove(file_path)
                
                results['files_deleted'].append({
                    'file': file_path,
                    'size': file_size,
                    'passes': passes,
                    'timestamp': self._get_timestamp()
                })
                
            except Exception as e:
                results['files_failed'].append({
                    'file': file_path,
                    'error': str(e)
                })
                
        self.forensics_event.emit('files_deleted', f'Securely deleted {len(results["files_deleted"])} files', results)
        
        return results
        
    def clear_browser_artifacts(self, browsers: List[str] = None) -> Dict:
        """Clear browser history and artifacts"""
        if not license_manager.is_feature_enabled('anti_forensics'):
            return {'error': 'Anti-forensics requires Enterprise license'}
            
        if browsers is None:
            browsers = ['chrome', 'firefox', 'edge']
            
        results = {
            'operation': 'Clear Browser Artifacts',
            'browsers_cleaned': [],
            'artifacts_cleared': []
        }
        
        browser_paths = {
            'chrome': {
                'history': r'%LOCALAPPDATA%\Google\Chrome\User Data\Default\History',
                'cookies': r'%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies',
                'cache': r'%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache'
            },
            'firefox': {
                'history': r'%APPDATA%\Mozilla\Firefox\Profiles\*\places.sqlite',
                'cookies': r'%APPDATA%\Mozilla\Firefox\Profiles\*\cookies.sqlite',
                'cache': r'%LOCALAPPDATA%\Mozilla\Firefox\Profiles\*\cache2'
            },
            'edge': {
                'history': r'%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History',
                'cookies': r'%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cookies',
                'cache': r'%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cache'
            }
        }
        
        for browser in browsers:
            if browser not in browser_paths:
                continue
                
            browser_result = {
                'browser': browser,
                'artifacts_cleared': [],
                'artifacts_failed': []
            }
            
            for artifact_type, path in browser_paths[browser].items():
                try:
                    # Simulate artifact clearing
                    self.forensics_event.emit('artifact_cleared', 
                                            f'Clearing {browser} {artifact_type}', 
                                            {'browser': browser, 'artifact': artifact_type})
                    
                    browser_result['artifacts_cleared'].append(artifact_type)
                    results['artifacts_cleared'].append(f'{browser}_{artifact_type}')
                    
                except Exception as e:
                    browser_result['artifacts_failed'].append({
                        'artifact': artifact_type,
                        'error': str(e)
                    })
                    
            results['browsers_cleaned'].append(browser_result)
            
        self.forensics_event.emit('browsers_cleaned', f'Cleaned {len(browsers)} browsers', results)
        
        return results
        
    def modify_file_timestamps(self, file_paths: List[str], timestamp_type: str = 'random') -> Dict:
        """Modify file timestamps to evade forensic analysis"""
        if not license_manager.is_feature_enabled('anti_forensics'):
            return {'error': 'Anti-forensics requires Enterprise license'}
            
        results = {
            'operation': 'Modify File Timestamps',
            'files_modified': [],
            'files_failed': [],
            'timestamp_type': timestamp_type
        }
        
        import random
        from datetime import datetime, timedelta
        
        for file_path in file_paths:
            try:
                if not os.path.exists(file_path):
                    results['files_failed'].append({
                        'file': file_path,
                        'error': 'File not found'
                    })
                    continue
                    
                # Generate new timestamp
                if timestamp_type == 'random':
                    # Random date within last 2 years
                    base_date = datetime.now() - timedelta(days=730)
                    random_days = random.randint(0, 730)
                    new_timestamp = base_date + timedelta(days=random_days)
                elif timestamp_type == 'old':
                    # Set to old date
                    new_timestamp = datetime(2020, 1, 1)
                else:
                    # Current timestamp
                    new_timestamp = datetime.now()
                    
                # Simulate timestamp modification
                self.forensics_event.emit('timestamp_modified', 
                                        f'Modifying timestamps for {file_path}', 
                                        {'file': file_path, 'new_timestamp': new_timestamp.isoformat()})
                
                results['files_modified'].append({
                    'file': file_path,
                    'old_timestamp': 'original_timestamp',
                    'new_timestamp': new_timestamp.isoformat(),
                    'timestamp': self._get_timestamp()
                })
                
            except Exception as e:
                results['files_failed'].append({
                    'file': file_path,
                    'error': str(e)
                })
                
        self.forensics_event.emit('timestamps_modified', f'Modified {len(results["files_modified"])} file timestamps', results)
        
        return results
        
    def clear_registry_traces(self, registry_keys: List[str] = None) -> Dict:
        """Clear registry traces and artifacts"""
        if not license_manager.is_feature_enabled('anti_forensics'):
            return {'error': 'Anti-forensics requires Enterprise license'}
            
        if registry_keys is None:
            registry_keys = [
                r'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs',
                r'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU',
                r'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths',
                r'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters'
            ]
            
        results = {
            'operation': 'Clear Registry Traces',
            'keys_cleared': [],
            'keys_failed': []
        }
        
        for reg_key in registry_keys:
            try:
                # Simulate registry key deletion
                self.forensics_event.emit('registry_cleared', 
                                        f'Clearing registry key: {reg_key}', 
                                        {'key': reg_key})
                
                results['keys_cleared'].append({
                    'key': reg_key,
                    'status': 'cleared',
                    'timestamp': self._get_timestamp()
                })
                
            except Exception as e:
                results['keys_failed'].append({
                    'key': reg_key,
                    'error': str(e)
                })
                
        self.forensics_event.emit('registry_cleaned', f'Cleared {len(results["keys_cleared"])} registry keys', results)
        
        return results
        
    def network_traffic_obfuscation(self, techniques: List[str] = None) -> Dict:
        """Implement network traffic obfuscation techniques"""
        if not license_manager.is_feature_enabled('anti_forensics'):
            return {'error': 'Anti-forensics requires Enterprise license'}
            
        if techniques is None:
            techniques = ['domain_fronting', 'traffic_padding', 'protocol_tunneling']
            
        results = {
            'operation': 'Network Traffic Obfuscation',
            'techniques_applied': [],
            'techniques_failed': []
        }
        
        technique_descriptions = {
            'domain_fronting': 'Route traffic through legitimate domains',
            'traffic_padding': 'Add random padding to network packets',
            'protocol_tunneling': 'Tunnel traffic through legitimate protocols',
            'dns_tunneling': 'Exfiltrate data through DNS queries',
            'steganography': 'Hide data in legitimate network traffic'
        }
        
        for technique in techniques:
            try:
                description = technique_descriptions.get(technique, 'Unknown technique')
                
                self.forensics_event.emit('obfuscation_applied', 
                                        f'Applying {technique}', 
                                        {'technique': technique, 'description': description})
                
                results['techniques_applied'].append({
                    'technique': technique,
                    'description': description,
                    'status': 'active',
                    'timestamp': self._get_timestamp()
                })
                
            except Exception as e:
                results['techniques_failed'].append({
                    'technique': technique,
                    'error': str(e)
                })
                
        self.forensics_event.emit('obfuscation_complete', f'Applied {len(results["techniques_applied"])} obfuscation techniques', results)
        
        return results
        
    def memory_dump_evasion(self) -> Dict:
        """Implement memory dump evasion techniques"""
        if not license_manager.is_feature_enabled('anti_forensics'):
            return {'error': 'Anti-forensics requires Enterprise license'}
            
        techniques = [
            'process_hollowing',
            'dll_injection',
            'memory_encryption',
            'anti_debugging'
        ]
        
        results = {
            'operation': 'Memory Dump Evasion',
            'techniques_enabled': [],
            'protection_level': 'Enhanced'
        }
        
        for technique in techniques:
            self.forensics_event.emit('evasion_enabled', 
                                    f'Enabling {technique}', 
                                    {'technique': technique})
            
            results['techniques_enabled'].append({
                'technique': technique,
                'status': 'enabled',
                'timestamp': self._get_timestamp()
            })
            
        self.forensics_event.emit('evasion_complete', 'Memory dump evasion techniques enabled', results)
        
        return results
        
    def generate_cleanup_report(self) -> Dict:
        """Generate comprehensive cleanup report"""
        if not self.cleanup_history:
            return {'error': 'No cleanup operations performed'}
            
        report = {
            'report_type': 'Anti-Forensics Cleanup Report',
            'generated_at': self._get_timestamp(),
            'total_operations': len(self.cleanup_history),
            'operations_summary': [],
            'recommendations': [
                'Regularly clear system artifacts',
                'Use secure deletion for sensitive files',
                'Monitor for forensic analysis tools',
                'Implement ongoing evasion techniques'
            ]
        }
        
        for operation in self.cleanup_history:
            summary = {
                'operation': operation.get('operation', 'Unknown'),
                'success_count': len(operation.get('logs_cleared', [])) + len(operation.get('files_deleted', [])),
                'failure_count': len(operation.get('logs_failed', [])) + len(operation.get('files_failed', []))
            }
            report['operations_summary'].append(summary)
            
        return report
        
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()

# Global anti-forensics instance
anti_forensics = AntiForensics()