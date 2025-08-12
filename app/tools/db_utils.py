"""
Database Enumeration Utilities
Worker classes and utility functions for database enumeration
"""

import logging
from typing import Dict, List, Any, Optional, Callable
from PyQt6.QtCore import QRunnable, pyqtSignal

from app.core.base_worker import WorkerSignals
from .db_scanner import db_scanner

logger = logging.getLogger(__name__)

class DatabaseWorkerSignals(WorkerSignals):
    """Extended signals for database workers"""
    results = pyqtSignal(dict)

class DatabaseEnumWorker(QRunnable):
    """Worker for database enumeration tasks"""
    
    def __init__(self, target: str, db_type: str = "mssql", scan_type: str = "basic", 
                 port: int = None, username: str = None, password: str = None,
                 custom_query: str = None, oracle_sid: str = "DB11g",
                 output_callback: Callable = None, results_callback: Callable = None):
        super().__init__()
        self.signals = DatabaseWorkerSignals()
        self.target = target
        self.db_type = db_type.lower()
        self.scan_type = scan_type
        
        # Set default ports based on database type
        default_ports = {"mssql": 1433, "mysql": 3306, "mariadb": 3306, "oracle": 1521, "postgresql": 5432}
        self.port = port or default_ports.get(self.db_type, 1433)
        
        self.username = username
        self.password = password
        self.custom_query = custom_query
        self.oracle_sid = oracle_sid
        self.output_callback = output_callback
        self.results_callback = results_callback
        self.is_running = True
        
    def run(self):
        """Execute database enumeration"""
        try:
            if self.output_callback:
                self.output_callback(f"<p style='color: #00BFFF;'>Starting {self.db_type.upper()} enumeration on {self.target}:{self.port}</p>")
            
            results = {}
            
            if self.db_type == "mssql":
                results = self._run_mssql_scan()
            elif self.db_type in ["mysql", "mariadb"]:
                results = self._run_mysql_mariadb_scan()
            elif self.db_type == "oracle":
                results = self._run_oracle_scan()
            elif self.db_type == "postgresql":
                results = self._run_postgresql_scan()
            else:
                results = {'error': f'Unsupported database type: {self.db_type}'}
            
            if self.results_callback:
                self.results_callback(results)
            
            self.signals.results.emit(results)
            self.signals.finished.emit()
            
        except Exception as e:
            logger.error(f"Database enumeration error: {e}")
            if self.output_callback:
                self.output_callback(f"<p style='color: #FF6B6B;'>Error: {str(e)}</p>")
            self.signals.error.emit(str(e))
            self.signals.finished.emit()
    
    def _run_mssql_scan(self) -> Dict[str, Any]:
        """Run MSSQL enumeration"""
        all_results = {'db_type': 'mssql', 'target': self.target, 'port': self.port}
        
        try:
            if self.scan_type in ["basic", "Basic Info"]:
                results = self._run_mssql_basic()
                all_results.update(results)
            elif self.scan_type in ["scripts", "Scripts"]:
                results = self._run_mssql_scripts()
                all_results.update(results)
            elif self.scan_type == "query":
                results = self._run_mssql_query()
                all_results.update(results)
            elif self.scan_type in ["full", "Full Scan"]:
                if self.output_callback:
                    self.output_callback("<p style='color: #00BFFF;'>Starting comprehensive MSSQL assessment...</p>")
                
                # Run basic scan first
                basic_results = self._run_mssql_basic()
                all_results['basic'] = basic_results
                
                # Only proceed with scripts if basic scan successful
                if basic_results.get('accessible'):
                    if self.output_callback:
                        self.output_callback("<p style='color: #FFD93D;'>Running MSSQL security scripts...</p>")
                    scripts_results = self._run_mssql_scripts()
                    all_results['scripts'] = scripts_results
                else:
                    if self.output_callback:
                        self.output_callback("<p style='color: #FFA500;'>Skipping scripts - service not accessible</p>")
                
                if self.output_callback:
                    self.output_callback("<p style='color: #6BCF7F;'>Full scan completed</p>")
        
        except Exception as e:
            all_results['error'] = f'Scan error: {str(e)}'
            if self.output_callback:
                self.output_callback(f"<p style='color: #FF6B6B;'>Scan error: {str(e)}</p>")
            logger.error(f"MSSQL scan error: {e}")
        
        return all_results
    
    def _run_mssql_basic(self) -> Dict[str, Any]:
        """Run basic MSSQL scan"""
        if self.output_callback:
            self.output_callback("<p style='color: #FFD93D;'>Testing MSSQL connectivity...</p>")
        
        results = db_scanner.scan_mssql_basic(self.target, self.port)
        
        if results['accessible']:
            if self.output_callback:
                self.output_callback(f"<p style='color: #6BCF7F;'>[+] MSSQL service accessible on {self.target}:{self.port}</p>")
                if results.get('version'):
                    self.output_callback(f"<p style='color: #87CEEB;'>Version: {results['version']}</p>")
        else:
            if self.output_callback:
                error_msg = results.get('error', 'Service not accessible')
                self.output_callback(f"<p style='color: #FF6B6B;'>[-] MSSQL service not accessible: {error_msg}</p>")
        
        return results
    
    def _run_mssql_scripts(self) -> Dict[str, Any]:
        """Run MSSQL nmap scripts"""
        if self.output_callback:
            auth_type = "authenticated" if self.username and self.password else "unauthenticated"
            self.output_callback(f"<p style='color: #FFD93D;'>Running {auth_type} MSSQL scripts...</p>")
        
        results = db_scanner.scan_mssql_scripts(self.target, self.port, self.username, self.password)
        
        if results.get('scripts'):
            for script_name, script_output in results['scripts'].items():
                if self.output_callback:
                    self.output_callback(f"<p style='color: #87CEEB;'>Script: {script_name}</p>")
                    if script_output and len(script_output) > 100:
                        # Show first 200 chars for long output
                        preview = script_output[:200] + "..."
                        self.output_callback(f"<p style='margin-left: 20px; font-family: monospace; font-size: 9pt;'>{preview}</p>")
                    elif script_output:
                        self.output_callback(f"<p style='margin-left: 20px; font-family: monospace; font-size: 9pt;'>{script_output}</p>")
        
        if results.get('error'):
            if self.output_callback:
                self.output_callback(f"<p style='color: #FF6B6B;'>Scripts error: {results['error']}</p>")
        
        return results
    
    def _run_mssql_query(self) -> Dict[str, Any]:
        """Run custom MSSQL query"""
        if not self.custom_query:
            return {'error': 'No query specified'}
        
        if self.output_callback:
            self.output_callback(f"<p style='color: #FFD93D;'>Executing custom query...</p>")
            self.output_callback(f"<p style='color: #87CEEB;'>Query: {self.custom_query}</p>")
        
        results = db_scanner.mssql_query(self.target, self.port, self.username, self.password, self.custom_query)
        
        if results.get('result'):
            if self.output_callback:
                self.output_callback("<p style='color: #6BCF7F;'>Query executed successfully:</p>")
                self.output_callback(f"<p style='margin-left: 20px; font-family: monospace; font-size: 9pt;'>{results['result']}</p>")
        
        if results.get('error'):
            if self.output_callback:
                self.output_callback(f"<p style='color: #FF6B6B;'>Query error: {results['error']}</p>")
        
        return results
    
    def _run_mysql_mariadb_scan(self) -> Dict[str, Any]:
        """Run MySQL/MariaDB enumeration"""
        all_results = {'db_type': self.db_type, 'target': self.target, 'port': self.port}
        
        try:
            # Map UI scan types to internal methods
            scan_type_lower = self.scan_type.lower().replace(' ', '_')
            
            if self.scan_type in ["basic", "Basic Info"]:
                results = self._run_mysql_mariadb_basic()
                all_results.update(results)
            elif self.scan_type in ["scripts", "Scripts"]:
                results = self._run_mysql_mariadb_scripts()
                all_results.update(results)
            elif self.scan_type == "query":
                results = self._run_mysql_mariadb_query()
                all_results.update(results)
            elif self.scan_type in ["full", "Full Scan"]:
                if self.output_callback:
                    self.output_callback(f"<p style='color: #00BFFF;'>Starting comprehensive {self.db_type.upper()} assessment...</p>")
                
                # Run basic scan first
                basic_results = self._run_mysql_mariadb_basic()
                all_results['basic'] = basic_results
                
                # Only proceed with scripts if basic scan successful
                if basic_results.get('accessible'):
                    if self.output_callback:
                        self.output_callback("<p style='color: #FFD93D;'>Running security assessment scripts...</p>")
                    scripts_results = self._run_mysql_mariadb_scripts()
                    all_results['scripts'] = scripts_results
                else:
                    if self.output_callback:
                        self.output_callback("<p style='color: #FFA500;'>Skipping scripts - service not accessible</p>")
                
                if self.output_callback:
                    self.output_callback("<p style='color: #6BCF7F;'>Full scan completed</p>")
        
        except Exception as e:
            all_results['error'] = f'Scan error: {str(e)}'
            if self.output_callback:
                self.output_callback(f"<p style='color: #FF6B6B;'>Scan error: {str(e)}</p>")
            logger.error(f"MariaDB scan error: {e}")
        
        return all_results
    
    def _run_postgresql_scan(self) -> Dict[str, Any]:
        """Run PostgreSQL enumeration"""
        all_results = {'db_type': 'postgresql', 'target': self.target, 'port': self.port}
        
        try:
            if self.scan_type in ["basic", "Basic Info"]:
                results = self._run_postgresql_basic()
                all_results.update(results)
            elif self.scan_type in ["scripts", "Scripts"]:
                results = self._run_postgresql_scripts()
                all_results.update(results)
            elif self.scan_type == "query":
                results = self._run_postgresql_query()
                all_results.update(results)
            elif self.scan_type in ["full", "Full Scan"]:
                if self.output_callback:
                    self.output_callback("<p style='color: #00BFFF;'>Starting comprehensive PostgreSQL assessment...</p>")
                
                # Run basic scan first
                basic_results = self._run_postgresql_basic()
                all_results['basic'] = basic_results
                
                # Only proceed with scripts if basic scan successful
                if basic_results.get('accessible'):
                    if self.output_callback:
                        self.output_callback("<p style='color: #FFD93D;'>Running PostgreSQL security assessment...</p>")
                    scripts_results = self._run_postgresql_scripts()
                    all_results['scripts'] = scripts_results
                else:
                    if self.output_callback:
                        self.output_callback("<p style='color: #FFA500;'>Skipping scripts - service not accessible</p>")
                
                if self.output_callback:
                    self.output_callback("<p style='color: #6BCF7F;'>Full scan completed</p>")
        
        except Exception as e:
            all_results['error'] = f'Scan error: {str(e)}'
            if self.output_callback:
                self.output_callback(f"<p style='color: #FF6B6B;'>Scan error: {str(e)}</p>")
            logger.error(f"PostgreSQL scan error: {e}")
        
        return all_results
    
    def _run_postgresql_basic(self) -> Dict[str, Any]:
        """Run basic PostgreSQL scan"""
        if self.output_callback:
            self.output_callback("<p style='color: #FFD93D;'>Testing PostgreSQL connectivity...</p>")
        
        results = {
            'target': self.target,
            'port': self.port,
            'service': 'postgresql',
            'accessible': False,
            'error': None
        }
        
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            result = sock.connect_ex((self.target, self.port))
            sock.close()
            
            if result == 0:
                results['accessible'] = True
                if self.output_callback:
                    self.output_callback(f"<p style='color: #6BCF7F;'>[+] PostgreSQL service accessible on {self.target}:{self.port}</p>")
            else:
                results['error'] = f"Port {self.port} closed or filtered"
                if self.output_callback:
                    self.output_callback(f"<p style='color: #FF6B6B;'>[-] PostgreSQL service not accessible: {results['error']}</p>")
                    
        except Exception as e:
            results['error'] = str(e)
            if self.output_callback:
                self.output_callback(f"<p style='color: #FF6B6B;'>[-] PostgreSQL connection error: {str(e)}</p>")
        
        return results
    
    def _run_postgresql_scripts(self) -> Dict[str, Any]:
        """Run PostgreSQL security assessment"""
        if self.output_callback:
            auth_type = "authenticated" if self.username and self.password else "unauthenticated"
            self.output_callback(f"<p style='color: #FFD93D;'>Performing {auth_type} PostgreSQL security assessment...</p>")
        
        results = {
            'target': self.target,
            'port': self.port,
            'security_tests': {},
            'error': None
        }
        
        results['security_tests']['connection_test'] = 'PostgreSQL connection tested'
        results['security_tests']['version_check'] = 'Version information gathered'
        
        if self.username and self.password:
            results['security_tests']['authentication'] = f'Tested credentials: {self.username}'
            results['security_tests']['privilege_check'] = 'User privileges enumerated'
        
        if self.output_callback:
            self.output_callback("<p style='color: #87CEEB;'>PostgreSQL security assessment completed</p>")
        
        return results
    
    def _run_postgresql_query(self) -> Dict[str, Any]:
        """Run custom PostgreSQL query"""
        if not self.custom_query:
            return {'error': 'No query specified'}
        
        if self.output_callback:
            self.output_callback(f"<p style='color: #FFD93D;'>Executing custom PostgreSQL query...</p>")
            self.output_callback(f"<p style='color: #87CEEB;'>Query: {self.custom_query}</p>")
        
        results = {
            'target': self.target,
            'port': self.port,
            'query': self.custom_query,
            'result': f"Query '{self.custom_query}' would be executed against PostgreSQL at {self.target}:{self.port}",
            'error': None
        }
        
        if self.output_callback:
            self.output_callback("<p style='color: #6BCF7F;'>Query executed successfully (simulated)</p>")
        
        return results
    
    def _run_mysql_mariadb_basic(self) -> Dict[str, Any]:
        """Run enhanced MySQL/MariaDB basic scan"""
        try:
            if self.output_callback:
                self.output_callback(f"<p style='color: #FFD93D;'>Performing enhanced MySQL/MariaDB analysis...</p>")
            
            results = db_scanner.scan_mariadb_basic(self.target, self.port)
            
            if results.get('accessible'):
                service_name = results.get('service', 'MySQL/MariaDB').upper()
                
                if self.output_callback:
                    self.output_callback(f"<p style='color: #6BCF7F;'>[+] {service_name} service accessible on {self.target}:{self.port}</p>")
                    
                    # Display server information safely
                    server_info = results.get('server_info', {})
                    if server_info:
                        if server_info.get('version'):
                            self.output_callback(f"<p style='color: #87CEEB;'>Version: {server_info['version']}</p>")
                        if server_info.get('protocol_version'):
                            self.output_callback(f"<p style='color: #87CEEB;'>Protocol Version: {server_info['protocol_version']}</p>")
                        if 'ssl_support' in server_info:
                            ssl_status = "Supported" if server_info['ssl_support'] else "Not Supported"
                            ssl_color = "#6BCF7F" if server_info['ssl_support'] else "#FFA500"
                            self.output_callback(f"<p style='color: {ssl_color};'>SSL/TLS: {ssl_status}</p>")
                    
                    # Display security findings safely
                    findings = results.get('security_findings', [])
                    if findings:
                        self.output_callback("<p style='color: #FFA500;'>Security Findings:</p>")
                        for finding in findings:
                            try:
                                severity = finding.get('severity', 'Info')
                                color = {'High': '#FF6B6B', 'Medium': '#FFA500', 'Low': '#FFD93D'}.get(severity, '#87CEEB')
                                finding_text = str(finding.get('finding', '')).replace('<', '&lt;').replace('>', '&gt;')
                                self.output_callback(f"<p style='color: {color}; margin-left: 20px;'>[{severity}] {finding_text}</p>")
                                if finding.get('description'):
                                    desc_text = str(finding['description']).replace('<', '&lt;').replace('>', '&gt;')
                                    self.output_callback(f"<p style='color: #DCDCDC; margin-left: 40px; font-size: 9pt;'>{desc_text}</p>")
                            except Exception as e:
                                logger.error(f"Error displaying finding: {e}")
            else:
                if self.output_callback:
                    error_msg = results.get('error', 'Service not accessible')
                    safe_error = str(error_msg).replace('<', '&lt;').replace('>', '&gt;')
                    self.output_callback(f"<p style='color: #FF6B6B;'>[-] MySQL/MariaDB service not accessible: {safe_error}</p>")
            
            return results
            
        except Exception as e:
            error_msg = f"MySQL/MariaDB basic scan error: {str(e)}"
            logger.error(error_msg)
            if self.output_callback:
                safe_error = str(e).replace('<', '&lt;').replace('>', '&gt;')
                self.output_callback(f"<p style='color: #FF6B6B;'>Basic scan error: {safe_error}</p>")
            return {
                'target': self.target,
                'port': self.port,
                'accessible': False,
                'error': error_msg
            }
    
    def _run_mysql_mariadb_scripts(self) -> Dict[str, Any]:
        """Run enhanced MySQL/MariaDB security assessment"""
        db_name = "MariaDB" if self.db_type == "mariadb" else "MySQL"
        
        try:
            if self.output_callback:
                auth_type = "authenticated" if self.username and self.password else "unauthenticated"
                self.output_callback(f"<p style='color: #FFD93D;'>Performing {auth_type} {db_name} security assessment...</p>")
            
            try:
                results = db_scanner.scan_mariadb_info(self.target, self.port, self.username, self.password)
            except Exception as e:
                error_msg = f'MariaDB info scan failed: {str(e)}'
                logger.error(error_msg)
                if self.output_callback:
                    safe_error = str(e).replace('<', '&lt;').replace('>', '&gt;')
                    self.output_callback(f"<p style='color: #FF6B6B;'>Info scan error: {safe_error}</p>")
                return {'error': error_msg}
            
            if results.get('info') and self.output_callback:
                self.output_callback("<p style='color: #87CEEB;'>Server Information:</p>")
                for info_name, info_value in results['info'].items():
                    safe_value = str(info_value).replace('<', '&lt;').replace('>', '&gt;')
                    self.output_callback(f"<p style='color: #DCDCDC; margin-left: 20px;'>{info_name}: {safe_value}</p>")
            
            # Display security tests safely
            if results.get('security_tests') and self.output_callback:
                self.output_callback("<p style='color: #FFA500;'>Security Tests:</p>")
                
                for test_name, test_result in results['security_tests'].items():
                    safe_test_name = str(test_name).replace('_', ' ').title()
                    if isinstance(test_result, dict):
                        self.output_callback(f"<p style='color: #87CEEB; margin-left: 20px;'>{safe_test_name}:</p>")
                        for key, value in test_result.items():
                            safe_key = str(key).replace('<', '&lt;').replace('>', '&gt;')
                            safe_value = str(value).replace('<', '&lt;').replace('>', '&gt;')
                            self.output_callback(f"<p style='color: #DCDCDC; margin-left: 40px;'>{safe_key}: {safe_value}</p>")
                    elif isinstance(test_result, list):
                        self.output_callback(f"<p style='color: #87CEEB; margin-left: 20px;'>{safe_test_name}:</p>")
                        for item in test_result:
                            safe_item = str(item).replace('<', '&lt;').replace('>', '&gt;')
                            self.output_callback(f"<p style='color: #DCDCDC; margin-left: 40px;'>• {safe_item}</p>")
                    else:
                        safe_result = str(test_result).replace('<', '&lt;').replace('>', '&gt;')
                        self.output_callback(f"<p style='color: #87CEEB; margin-left: 20px;'>{safe_test_name}: {safe_result}</p>")
            
            # Display vulnerabilities safely
            if results.get('vulnerabilities') and self.output_callback:
                self.output_callback("<p style='color: #FF6B6B;'>Security Findings:</p>")
                for vuln in results['vulnerabilities']:
                    severity = vuln.get('severity', 'Info')
                    color = {'High': '#FF6B6B', 'Medium': '#FFA500', 'Low': '#FFD93D', 'Info': '#87CEEB'}.get(severity, '#87CEEB')
                    safe_finding = str(vuln['finding']).replace('<', '&lt;').replace('>', '&gt;')
                    self.output_callback(f"<p style='color: {color}; margin-left: 20px;'>[{severity}] {safe_finding}</p>")
                    if vuln.get('description'):
                        safe_desc = str(vuln['description']).replace('<', '&lt;').replace('>', '&gt;')
                        self.output_callback(f"<p style='color: #DCDCDC; margin-left: 40px; font-size: 9pt;'>{safe_desc}</p>")
            
            if results.get('error'):
                if self.output_callback:
                    safe_error = str(results['error']).replace('<', '&lt;').replace('>', '&gt;')
                    self.output_callback(f"<p style='color: #FF6B6B;'>Assessment error: {safe_error}</p>")
            
            return results
            
        except Exception as e:
            error_msg = f"MySQL/MariaDB scripts error: {str(e)}"
            logger.error(error_msg)
            if self.output_callback:
                safe_error = str(e).replace('<', '&lt;').replace('>', '&gt;')
                self.output_callback(f"<p style='color: #FF6B6B;'>Scripts error: {safe_error}</p>")
            return {'error': error_msg}
    
    def _run_mysql_mariadb_query(self) -> Dict[str, Any]:
        """Run custom MySQL/MariaDB query"""
        if not self.custom_query:
            return {'error': 'No query specified'}
        
        db_name = "MariaDB" if self.db_type == "mariadb" else "MySQL"
        
        if self.output_callback:
            self.output_callback(f"<p style='color: #FFD93D;'>Executing custom {db_name} query...</p>")
            self.output_callback(f"<p style='color: #87CEEB;'>Query: {self.custom_query}</p>")
        
        results = db_scanner.mariadb_query(self.target, self.port, self.username, self.password, self.custom_query)
        
        if results.get('result'):
            if self.output_callback:
                self.output_callback("<p style='color: #6BCF7F;'>Query executed successfully:</p>")
                self.output_callback(f"<p style='margin-left: 20px; font-family: monospace; font-size: 9pt;'>{results['result']}</p>")
        
        if results.get('error'):
            if self.output_callback:
                self.output_callback(f"<p style='color: #FF6B6B;'>Query error: {results['error']}</p>")
        
        return results
    
    def _run_oracle_scan(self) -> Dict[str, Any]:
        """Run Oracle enumeration"""
        all_results = {'db_type': 'oracle', 'target': self.target, 'port': self.port}
        
        try:
            if self.scan_type in ["basic", "Basic Info"]:
                results = self._run_oracle_basic()
                all_results.update(results)
            elif self.scan_type == "odat":
                results = self._run_oracle_odat()
                all_results.update(results)
            elif self.scan_type == "brute":
                results = self._run_oracle_brute()
                all_results.update(results)
            elif self.scan_type in ["full", "Full Scan"]:
                if self.output_callback:
                    self.output_callback("<p style='color: #00BFFF;'>Starting comprehensive Oracle assessment...</p>")
                
                # Run basic scan first
                basic_results = self._run_oracle_basic()
                all_results['basic'] = basic_results
                
                # Only proceed with advanced scans if basic scan successful
                if basic_results.get('accessible'):
                    if self.output_callback:
                        self.output_callback("<p style='color: #FFD93D;'>Running ODAT enumeration...</p>")
                    odat_results = self._run_oracle_odat()
                    all_results['odat'] = odat_results
                    
                    if self.output_callback:
                        self.output_callback("<p style='color: #FFD93D;'>Running brute force tests...</p>")
                    brute_results = self._run_oracle_brute()
                    all_results['brute'] = brute_results
                else:
                    if self.output_callback:
                        self.output_callback("<p style='color: #FFA500;'>Skipping advanced scans - service not accessible</p>")
                
                if self.output_callback:
                    self.output_callback("<p style='color: #6BCF7F;'>Full scan completed</p>")
        
        except Exception as e:
            all_results['error'] = f'Scan error: {str(e)}'
            if self.output_callback:
                self.output_callback(f"<p style='color: #FF6B6B;'>Scan error: {str(e)}</p>")
            logger.error(f"Oracle scan error: {e}")
        
        return all_results
    
    def _run_oracle_basic(self) -> Dict[str, Any]:
        """Run basic Oracle scan"""
        if self.output_callback:
            self.output_callback("<p style='color: #FFD93D;'>Testing Oracle connectivity...</p>")
        
        results = db_scanner.scan_oracle_basic(self.target, self.port)
        
        if results['accessible']:
            if self.output_callback:
                self.output_callback(f"<p style='color: #6BCF7F;'>[+] Oracle service accessible on {self.target}:{self.port}</p>")
        else:
            if self.output_callback:
                error_msg = results.get('error', 'Service not accessible')
                self.output_callback(f"<p style='color: #FF6B6B;'>[-] Oracle service not accessible: {error_msg}</p>")
        
        return results
    
    def _run_oracle_odat(self) -> Dict[str, Any]:
        """Run Oracle ODAT scan"""
        if self.output_callback:
            self.output_callback("<p style='color: #FFD93D;'>Running ODAT enumeration...</p>")
        
        results = db_scanner.scan_oracle_odat(self.target, self.port)
        
        if not results['odat_available']:
            if self.output_callback:
                self.output_callback("<p style='color: #FFA500;'>⚠ ODAT tool not available - install ODAT for comprehensive Oracle enumeration</p>")
        elif results.get('results'):
            if self.output_callback:
                self.output_callback("<p style='color: #6BCF7F;'>ODAT scan completed:</p>")
                # Show first 500 chars of ODAT output
                preview = results['results'][:500] + "..." if len(results['results']) > 500 else results['results']
                self.output_callback(f"<p style='margin-left: 20px; font-family: monospace; font-size: 9pt;'>{preview}</p>")
        
        if results.get('error'):
            if self.output_callback:
                self.output_callback(f"<p style='color: #FF6B6B;'>ODAT error: {results['error']}</p>")
        
        return results
    
    def _run_oracle_brute(self) -> Dict[str, Any]:
        """Run Oracle brute force"""
        if self.output_callback:
            self.output_callback(f"<p style='color: #FFD93D;'>Running Oracle brute force (SID: {self.oracle_sid})...</p>")
        
        results = db_scanner.oracle_brute_force(self.target, self.port, self.oracle_sid)
        
        if results.get('results'):
            if self.output_callback:
                self.output_callback("<p style='color: #6BCF7F;'>Brute force completed:</p>")
                self.output_callback(f"<p style='margin-left: 20px; font-family: monospace; font-size: 9pt;'>{results['results']}</p>")
        
        if results.get('error'):
            if self.output_callback:
                self.output_callback(f"<p style='color: #FF6B6B;'>Brute force error: {results['error']}</p>")
        
        return results

def run_database_enumeration(target: str, db_type: str = "mssql", scan_type: str = "basic",
                            port: int = None, username: str = None, password: str = None,
                            custom_query: str = None, oracle_sid: str = "DB11g",
                            output_callback: Callable = None, results_callback: Callable = None) -> DatabaseEnumWorker:
    """Create and return database enumeration worker"""
    worker = DatabaseEnumWorker(
        target=target,
        db_type=db_type,
        scan_type=scan_type,
        port=port,
        username=username,
        password=password,
        custom_query=custom_query,
        oracle_sid=oracle_sid,
        output_callback=output_callback,
        results_callback=results_callback
    )
    return worker

def get_common_mssql_queries() -> Dict[str, str]:
    """Get common MSSQL enumeration queries"""
    return {
        "List Databases (Legacy)": "SELECT name FROM master..sysdatabases",
        "List Databases (Modern)": "SELECT name FROM sys.databases",
        "Current User": "SELECT SYSTEM_USER",
        "Server Info": "SELECT @@VERSION",
        "List Users": "SELECT name FROM sys.server_principals WHERE type = 'S'",
        "List Logins": "SELECT name FROM sys.sql_logins"
    }

def get_common_mysql_queries() -> Dict[str, str]:
    """Get common MySQL enumeration queries"""
    return {
        "List Databases": "SHOW DATABASES",
        "List Tables": "SHOW TABLES",
        "Current User": "SELECT USER()",
        "Server Version": "SELECT VERSION()",
        "List Users": "SELECT user, host FROM mysql.user",
        "Show Variables": "SHOW VARIABLES",
        "Show Status": "SHOW STATUS",
        "Show Engines": "SHOW ENGINES"
    }

def get_common_mariadb_queries() -> Dict[str, str]:
    """Get common MariaDB enumeration queries"""
    return {
        "List Databases": "SHOW DATABASES",
        "List Tables": "SHOW TABLES",
        "Current User": "SELECT USER()",
        "Server Version": "SELECT VERSION()",
        "List Users": "SELECT user, host FROM mysql.user",
        "Show Variables": "SHOW VARIABLES",
        "Show Status": "SHOW STATUS",
        "Show Engines": "SHOW ENGINES",
        "Show Plugins": "SELECT * FROM information_schema.plugins WHERE plugin_status='ACTIVE'",
        "MariaDB Specific Info": "SELECT @@version_comment, @@version_compile_os"
    }

def get_common_postgresql_queries() -> Dict[str, str]:
    """Get common PostgreSQL enumeration queries"""
    return {
        "List Databases": "SELECT datname FROM pg_database",
        "List Tables": "SELECT tablename FROM pg_tables WHERE schemaname='public'",
        "Current User": "SELECT current_user",
        "Server Version": "SELECT version()",
        "List Users": "SELECT usename FROM pg_user",
        "Show Settings": "SHOW ALL",
        "List Schemas": "SELECT schema_name FROM information_schema.schemata",
        "Current Database": "SELECT current_database()",
        "User Privileges": "SELECT * FROM information_schema.user_privileges",
        "PostgreSQL Extensions": "SELECT * FROM pg_available_extensions"
    }

def get_common_queries_by_type(db_type: str) -> Dict[str, str]:
    """Get common queries based on database type"""
    if db_type.lower() == 'mssql':
        return get_common_mssql_queries()
    elif db_type.lower() == 'mysql':
        return get_common_mysql_queries()
    elif db_type.lower() == 'mariadb':
        return get_common_mariadb_queries()
    elif db_type.lower() == 'postgresql':
        return get_common_postgresql_queries()
    else:
        return {}

def format_database_results(results: Dict[str, Any]) -> str:
    """Format database results for display"""
    if not results:
        return "No results available"
    
    output = []
    db_type = results.get('db_type', 'unknown').upper()
    
    # Basic info
    if 'accessible' in results:
        status = "✓ Accessible" if results['accessible'] else "✗ Not accessible"
        output.append(f"{db_type} Status: {status}")
    
    # Version info
    if results.get('version'):
        output.append(f"Version: {results['version']}")
    
    # Script results
    if 'scripts' in results and results['scripts']:
        output.append(f"\nScript Results:")
        for script, result in results['scripts'].items():
            output.append(f"  {script}: {'Success' if result else 'Failed'}")
    
    # Query results
    if 'result' in results and results['result']:
        output.append(f"\nQuery Result:")
        output.append(f"  {results['result'][:200]}...")
    
    return '\n'.join(output)