"""
Database Enumeration Scanner
Provides database service enumeration capabilities for MSSQL and Oracle
"""

import socket
import logging
from typing import Dict, List, Optional, Any
import subprocess
import re

logger = logging.getLogger(__name__)

class DatabaseScanner:
    """Database enumeration scanner for MSSQL and Oracle"""
    
    def __init__(self):
        self.timeout = 10
        
    def scan_mssql_basic(self, target: str, port: int = 1433) -> Dict[str, Any]:
        """Basic MSSQL service detection"""
        results = {
            'target': target,
            'port': port,
            'service': 'mssql',
            'accessible': False,
            'version': None,
            'error': None
        }
        
        try:
            # Test basic connectivity
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                results['accessible'] = True
                # Try nmap version detection
                version_info = self._nmap_version_scan(target, port)
                if version_info:
                    results['version'] = version_info
            else:
                results['error'] = f"Port {port} closed or filtered"
                
        except Exception as e:
            results['error'] = str(e)
            logger.error(f"MSSQL basic scan error for {target}:{port} - {e}")
            
        return results
    
    def scan_mssql_scripts(self, target: str, port: int = 1433, username: str = None, 
                          password: str = None) -> Dict[str, Any]:
        """Run MSSQL nmap scripts"""
        results = {
            'target': target,
            'port': port,
            'scripts': {},
            'error': None
        }
        
        try:
            if username and password:
                # Authenticated scripts
                scripts = ['ms-sql-info', 'ms-sql-hasdbaccess', 'ms-sql-dump-hashes']
                script_args = f"mssql.username={username},mssql.password={password}"
            else:
                # Unauthenticated scripts
                scripts = ['ms-sql-info', 'ms-sql-brute', 'ms-sql-empty-password']
                script_args = None
            
            for script in scripts:
                script_result = self._run_nmap_script(target, port, script, script_args)
                results['scripts'][script] = script_result
                
        except Exception as e:
            results['error'] = str(e)
            logger.error(f"MSSQL scripts error for {target}:{port} - {e}")
            
        return results
    
    def mssql_query(self, target: str, port: int = 1433, username: str = None,
                   password: str = None, query: str = None) -> Dict[str, Any]:
        """Execute custom MSSQL query"""
        results = {
            'target': target,
            'port': port,
            'query': query,
            'result': None,
            'error': None
        }
        
        if not username or not password or not query:
            results['error'] = "Username, password, and query required"
            return results
        
        try:
            script_args = f"mssql.username={username},mssql.password={password},mssql.query=\"{query}\""
            result = self._run_nmap_script(target, port, 'ms-sql-query', script_args)
            results['result'] = result
            
        except Exception as e:
            results['error'] = str(e)
            logger.error(f"MSSQL query error for {target}:{port} - {e}")
            
        return results
    
    def scan_oracle_basic(self, target: str, port: int = 1521) -> Dict[str, Any]:
        """Basic Oracle service detection"""
        results = {
            'target': target,
            'port': port,
            'service': 'oracle',
            'accessible': False,
            'error': None
        }
        
        try:
            # Test basic connectivity
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                results['accessible'] = True
            else:
                results['error'] = f"Port {port} closed or filtered"
                
        except Exception as e:
            results['error'] = str(e)
            logger.error(f"Oracle basic scan error for {target}:{port} - {e}")
            
        return results
    
    def scan_oracle_odat(self, target: str, port: int = 1521) -> Dict[str, Any]:
        """Oracle enumeration using ODAT"""
        results = {
            'target': target,
            'port': port,
            'odat_available': False,
            'results': None,
            'error': None
        }
        
        try:
            # Check if odat is available
            if not self._check_tool_available('odat'):
                results['error'] = "ODAT tool not available"
                return results
            
            results['odat_available'] = True
            
            # Run ODAT all modules
            cmd = ['odat', 'all', '-s', target, '-p', str(port)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                results['results'] = result.stdout
            else:
                results['error'] = result.stderr or "ODAT scan failed"
                
        except subprocess.TimeoutExpired:
            results['error'] = "ODAT scan timeout"
        except Exception as e:
            results['error'] = str(e)
            logger.error(f"Oracle ODAT scan error for {target}:{port} - {e}")
            
        return results
    
    def oracle_brute_force(self, target: str, port: int = 1521, sid: str = "DB11g") -> Dict[str, Any]:
        """Oracle brute force using nmap"""
        results = {
            'target': target,
            'port': port,
            'sid': sid,
            'results': None,
            'error': None
        }
        
        try:
            script_args = f"oracle-brute-stealth.sid={sid}"
            result = self._run_nmap_script(target, port, 'oracle-brute-stealth', script_args)
            results['results'] = result
            
        except Exception as e:
            results['error'] = str(e)
            logger.error(f"Oracle brute force error for {target}:{port} - {e}")
            
        return results
    
    def _nmap_version_scan(self, target: str, port: int) -> Optional[str]:
        """Run nmap version detection"""
        try:
            cmd = ['nmap', '-sV', '-p', str(port), target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                # Parse version info from output
                lines = result.stdout.split('\n')
                for line in lines:
                    if str(port) in line and 'open' in line:
                        return line.strip()
            return None
            
        except Exception as e:
            logger.error(f"Nmap version scan error: {e}")
            return None
    
    def _run_nmap_script(self, target: str, port: int, script: str, 
                        script_args: str = None) -> Optional[str]:
        """Run specific nmap script"""
        try:
            cmd = ['nmap', '-p', str(port), '--script', script]
            
            if script_args:
                cmd.extend(['--script-args', script_args])
            
            cmd.append(target)
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                return result.stdout
            else:
                return result.stderr or "Script execution failed"
                
        except subprocess.TimeoutExpired:
            return "Script execution timeout"
        except Exception as e:
            logger.error(f"Nmap script error: {e}")
            return f"Error: {str(e)}"
    
    def _check_tool_available(self, tool_name: str) -> bool:
        """Check if external tool is available"""
        try:
            result = subprocess.run([tool_name, '--help'], 
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0 or 'usage' in result.stdout.lower()
        except:
            return False

# Global scanner instance
db_scanner = DatabaseScanner()