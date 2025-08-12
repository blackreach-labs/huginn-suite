"""
Database Enumeration Utilities
Worker classes and utility functions for database enumeration
"""

import logging
from typing import Dict, List, Any, Optional, Callable
from PyQt6.QtCore import QRunnable

from app.core.base_worker import WorkerSignals
from .db_scanner import db_scanner

logger = logging.getLogger(__name__)

class DatabaseWorkerSignals(WorkerSignals):
    """Extended signals for database workers"""
    pass

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
        self.port = port or (1433 if self.db_type == "mssql" else 1521)
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
            self.signals.progress_start.emit("Starting database enumeration...")
            
            if self.output_callback:
                self.output_callback(f"<p style='color: #00BFFF;'>Starting {self.db_type.upper()} enumeration on {self.target}:{self.port}</p>")
            
            results = {}
            
            if self.db_type == "mssql":
                results = self._run_mssql_scan()
            elif self.db_type == "oracle":
                results = self._run_oracle_scan()
            else:
                results = {'error': f'Unsupported database type: {self.db_type}'}
            
            if self.results_callback:
                self.results_callback(results)
                
            self.signals.finished.emit()
            
        except Exception as e:
            logger.error(f"Database enumeration error: {e}")
            if self.output_callback:
                self.output_callback(f"<p style='color: #FF6B6B;'>Error: {str(e)}</p>")
            self.signals.error.emit(str(e))
    
    def _run_mssql_scan(self) -> Dict[str, Any]:
        """Run MSSQL enumeration"""
        all_results = {'db_type': 'mssql', 'target': self.target, 'port': self.port}
        
        if self.scan_type == "basic":
            results = self._run_mssql_basic()
            all_results.update(results)
        elif self.scan_type == "scripts":
            results = self._run_mssql_scripts()
            all_results.update(results)
        elif self.scan_type == "query":
            results = self._run_mssql_query()
            all_results.update(results)
        elif self.scan_type == "full":
            # Run all scan types
            basic_results = self._run_mssql_basic()
            all_results['basic'] = basic_results
            
            if basic_results.get('accessible'):
                scripts_results = self._run_mssql_scripts()
                all_results['scripts'] = scripts_results
        
        return all_results
    
    def _run_mssql_basic(self) -> Dict[str, Any]:
        """Run basic MSSQL scan"""
        if self.output_callback:
            self.output_callback("<p style='color: #FFD93D;'>Testing MSSQL connectivity...</p>")
        
        results = db_scanner.scan_mssql_basic(self.target, self.port)
        
        if results['accessible']:
            if self.output_callback:
                self.output_callback(f"<p style='color: #6BCF7F;'>✓ MSSQL service accessible on {self.target}:{self.port}</p>")
                if results.get('version'):
                    self.output_callback(f"<p style='color: #87CEEB;'>Version: {results['version']}</p>")
        else:
            if self.output_callback:
                error_msg = results.get('error', 'Service not accessible')
                self.output_callback(f"<p style='color: #FF6B6B;'>✗ MSSQL service not accessible: {error_msg}</p>")
        
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
    
    def _run_oracle_scan(self) -> Dict[str, Any]:
        """Run Oracle enumeration"""
        all_results = {'db_type': 'oracle', 'target': self.target, 'port': self.port}
        
        if self.scan_type == "basic":
            results = self._run_oracle_basic()
            all_results.update(results)
        elif self.scan_type == "odat":
            results = self._run_oracle_odat()
            all_results.update(results)
        elif self.scan_type == "brute":
            results = self._run_oracle_brute()
            all_results.update(results)
        elif self.scan_type == "full":
            # Run all scan types
            basic_results = self._run_oracle_basic()
            all_results['basic'] = basic_results
            
            if basic_results.get('accessible'):
                odat_results = self._run_oracle_odat()
                all_results['odat'] = odat_results
                
                brute_results = self._run_oracle_brute()
                all_results['brute'] = brute_results
        
        return all_results
    
    def _run_oracle_basic(self) -> Dict[str, Any]:
        """Run basic Oracle scan"""
        if self.output_callback:
            self.output_callback("<p style='color: #FFD93D;'>Testing Oracle connectivity...</p>")
        
        results = db_scanner.scan_oracle_basic(self.target, self.port)
        
        if results['accessible']:
            if self.output_callback:
                self.output_callback(f"<p style='color: #6BCF7F;'>✓ Oracle service accessible on {self.target}:{self.port}</p>")
        else:
            if self.output_callback:
                error_msg = results.get('error', 'Service not accessible')
                self.output_callback(f"<p style='color: #FF6B6B;'>✗ Oracle service not accessible: {error_msg}</p>")
        
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