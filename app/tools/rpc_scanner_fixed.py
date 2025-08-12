# app/tools/rpc_scanner_fixed.py
import subprocess
import re
import socket
from typing import Dict, List, Optional
from PyQt6.QtCore import QObject, pyqtSignal, QRunnable

class RPCWorkerSignals(QObject):
    output = pyqtSignal(str)
    finished = pyqtSignal()
    results = pyqtSignal(dict)
    table_data = pyqtSignal(dict)
    graph_data = pyqtSignal(dict)
    progress_start = pyqtSignal(int, str)
    progress_update = pyqtSignal(int, int, str)

class RPCWorker(QRunnable):
    def __init__(self, target: str, scan_type: str, auth_type: str, username: str = "", 
                 password: str = "", ntlm_hash: str = "", service_name: str = "", 
                 ticket_path: str = "", domain: str = "", tenant_id: Optional[str] = None):
        super().__init__()
        self.target = target
        self.scan_type = scan_type
        self.auth_type = auth_type
        self.username = username
        self.password = password
        self.ntlm_hash = ntlm_hash
        self.service_name = service_name
        self.ticket_path = ticket_path
        self.domain = domain
        self.tenant_id = tenant_id or "default"
        self.signals = RPCWorkerSignals()
        self.is_running = True
        self.data_collector = None
        
    def run(self):
        """Main execution method for RPC scanning"""
        try:
            # Initialize data collector
            self._initialize_data_collector()
            
            # Determine scan steps
            total_steps = self._calculate_total_steps()
            self.signals.progress_start.emit(total_steps, f"RPC {self.scan_type}")
            
            # Start scan
            scan_id = self._start_scan_session()
            self.signals.output.emit(f"<p style='color: #87CEEB;'>Starting RPC enumeration on {self.target}...</p><br>")
            self.signals.output.emit(f"<p style='color: #87CEEB;'>Authentication: {self.auth_type}</p><br>")
            self.signals.output.emit(f"<p style='color: #87CEEB;'>Scan ID: {scan_id}</p><br>")
            
            # Execute scan
            results = self._execute_scan()
            
            # Process results
            if results:
                self._process_results(results)
                self.signals.results.emit(results)
                self.signals.output.emit("<p style='color: #00FF41;'>✅ RPC enumeration completed successfully</p><br>")
            else:
                self.signals.output.emit("<p style='color: #FF6B6B;'>❌ RPC enumeration failed</p><br>")
                
        except Exception as e:
            self._handle_error(f"RPC scan failed: {str(e)}")
        finally:
            self._cleanup()
            self.signals.finished.emit()
    
    def _initialize_data_collector(self):
        """Initialize the centralized data collector"""
        try:
            from ..core.rpc_data_collector import create_rpc_collector
            self.data_collector = create_rpc_collector(self.tenant_id)
        except ImportError as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>Warning: Data collector not available: {e}</p><br>")
    
    def _calculate_total_steps(self) -> int:
        """Calculate total steps based on scan type"""
        if self.scan_type == "Complete Assessment":
            return 6
        elif self.scan_type == "Vulnerability Scan":
            return 4
        elif self.scan_type == "Full Enumeration":
            return 3
        else:  # Basic Info
            return 2
    
    def _start_scan_session(self) -> str:
        """Start a new scan session"""
        if self.data_collector:
            return self.data_collector.start_rpc_scan(
                target=self.target,
                scanner=f"rpc_scanner_{self.scan_type.lower().replace(' ', '_')}",
                scan_subtype=self.scan_type.lower().replace(' ', '_')
            )
        return f"rpc_scan_{hash(self.target)}_{self.scan_type}"
    
    def _execute_scan(self) -> Dict:
        """Execute the main RPC scan logic"""
        results = {
            'target': self.target,
            'scan_type': self.scan_type,
            'auth_type': self.auth_type,
            'endpoints': [],
            'services': [],
            'rpc_endpoints': [],
            'vulnerabilities': [],
            'errors': []
        }
        
        current_step = 0
        
        # Step 1: Basic connectivity and RPC endpoint enumeration
        self.signals.progress_update.emit(current_step, 0, "Testing RPC connectivity...")
        if self._test_rpc_connectivity(results):
            self.signals.output.emit("<p style='color: #00FF41;'>✅ RPC connectivity confirmed</p><br>")
        else:
            self.signals.output.emit("<p style='color: #FFAA00;'>⚠️ Limited RPC connectivity</p><br>")
        
        current_step += 1
        
        # Step 2: Service enumeration
        self.signals.progress_update.emit(current_step, 0, "Enumerating services...")
        self._enumerate_services(results)
        current_step += 1
        
        # Step 3: Registry enumeration (if Full Enumeration or Complete Assessment)
        if self.scan_type in ["Full Enumeration", "Complete Assessment"]:
            self.signals.progress_update.emit(current_step, 0, "Accessing registry...")
            self._enumerate_registry(results)
            current_step += 1
        
        # Step 4+: Vulnerability scanning (if Vulnerability Scan or Complete Assessment)
        if self.scan_type in ["Vulnerability Scan", "Complete Assessment"]:
            self.signals.progress_update.emit(current_step, 0, "Scanning for vulnerabilities...")
            self._scan_vulnerabilities(results)
            current_step += 1
            
            if self.scan_type == "Complete Assessment":
                self.signals.progress_update.emit(current_step, 0, "Advanced security analysis...")
                self._advanced_security_analysis(results)
                current_step += 1
        
        return results
    
    def _test_rpc_connectivity(self, results: Dict) -> bool:
        """Test basic RPC connectivity"""
        try:
            # Test port 135 (RPC endpoint mapper)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.target, 135))
            sock.close()
            
            if result == 0:
                results['endpoints'].append({
                    'port': 135,
                    'service': 'RPC Endpoint Mapper',
                    'protocol': 'tcp',
                    'status': 'open'
                })
                
                # Test additional RPC-related ports
                rpc_ports = [445, 139, 593]
                for port in rpc_ports:
                    if self._test_port(port):
                        service_map = {
                            445: 'SMB/RPC over Named Pipes',
                            139: 'NetBIOS Session Service',
                            593: 'RPC over HTTP'
                        }
                        results['endpoints'].append({
                            'port': port,
                            'service': service_map[port],
                            'protocol': 'tcp',
                            'status': 'open'
                        })
                
                return True
            else:
                results['errors'].append("RPC endpoint mapper (port 135) not accessible")
                return False
                
        except Exception as e:
            results['errors'].append(f"RPC connectivity test failed: {str(e)}")
            return False
    
    def _test_port(self, port: int) -> bool:
        """Test if a specific port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((self.target, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def _enumerate_services(self, results: Dict):
        """Enumerate Windows services via RPC"""
        try:
            if self.auth_type == "Anonymous":
                self._enumerate_services_anonymous(results)
            else:
                self._enumerate_services_authenticated(results)
                
        except Exception as e:
            results['errors'].append(f"Service enumeration failed: {str(e)}")
    
    def _enumerate_services_anonymous(self, results: Dict):
        """Enumerate services without authentication"""
        try:
            cmd = ["sc", f"\\\\{self.target}", "query"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 and result.stdout:
                services = self._parse_service_output(result.stdout)
                results['services'] = services
                self.signals.output.emit(f"<p style='color: #00FF41;'>Found {len(services)} services</p><br>")
                
                # Show sample services
                for service in services[:5]:
                    name = service.get('name', 'Unknown')
                    state = service.get('state', 'Unknown')
                    self.signals.output.emit(f"<p>• {name}: {state}</p><br>")
                    
                if len(services) > 5:
                    self.signals.output.emit(f"<p>... and {len(services) - 5} more services</p><br>")
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>Service enumeration failed or access denied</p><br>")
                
        except subprocess.TimeoutExpired:
            results['errors'].append("Service enumeration timed out")
        except Exception as e:
            results['errors'].append(f"Anonymous service enumeration failed: {str(e)}")
    
    def _enumerate_services_authenticated(self, results: Dict):
        """Enumerate services with authentication"""
        try:
            # First establish authenticated session
            if self._establish_authenticated_session():
                self._enumerate_services_anonymous(results)  # Use same enumeration method
            else:
                results['errors'].append("Authentication failed")
                
        except Exception as e:
            results['errors'].append(f"Authenticated service enumeration failed: {str(e)}")
    
    def _establish_authenticated_session(self) -> bool:
        """Establish authenticated session with target"""
        try:
            if self.auth_type == "NTLM" and self.username and self.password:
                user_format = f"{self.domain}\\{self.username}" if self.domain else self.username
                cmd = ["net", "use", f"\\\\{self.target}\\IPC$", self.password, f"/user:{user_format}"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                return result.returncode == 0
            else:
                return False
                
        except Exception:
            return False
    
    def _parse_service_output(self, output: str) -> List[Dict]:
        """Parse sc query output into service list"""
        services = []
        lines = output.split('\n')
        current_service = {}
        
        for line in lines:
            line = line.strip()
            if line.startswith('SERVICE_NAME:'):
                if current_service:
                    services.append(current_service)
                current_service = {'name': line.split(':', 1)[1].strip()}
            elif line.startswith('DISPLAY_NAME:'):
                current_service['display_name'] = line.split(':', 1)[1].strip()
            elif line.startswith('STATE'):
                state_info = line.split(':', 1)[1].strip()
                current_service['state'] = state_info.split()[0] if state_info else 'UNKNOWN'
        
        if current_service:
            services.append(current_service)
            
        return services
    
    def _enumerate_registry(self, results: Dict):
        """Enumerate registry information"""
        try:
            if self.auth_type == "Anonymous":
                self.signals.output.emit("<p style='color: #FFD700;'>Skipping registry enumeration (Anonymous mode)</p><br>")
                return
            
            cmd = ["reg", "query", f"\\\\{self.target}\\HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "/v", "ProductName"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0 and "ProductName" in result.stdout:
                self.signals.output.emit("<p style='color: #00FF41;'>✅ Remote registry access successful</p><br>")
                results['registry_access'] = True
                
                # Extract OS info
                match = re.search(r'ProductName\s+REG_SZ\s+(.+)', result.stdout)
                if match:
                    os_name = match.group(1).strip()
                    results['os_info'] = os_name
                    self.signals.output.emit(f"<p>OS: {os_name}</p><br>")
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>Remote registry access denied</p><br>")
                results['registry_access'] = False
                
        except subprocess.TimeoutExpired:
            results['errors'].append("Registry enumeration timed out")
        except Exception as e:
            results['errors'].append(f"Registry enumeration failed: {str(e)}")
    
    def _scan_vulnerabilities(self, results: Dict):
        """Scan for RPC-related vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Check for Print Spooler vulnerability
            if self._check_print_spooler_vulnerability():
                vulnerabilities.append({
                    'name': 'PrintNightmare (CVE-2021-1675)',
                    'severity': 'Critical',
                    'description': 'Print Spooler service vulnerable to privilege escalation',
                    'cve': 'CVE-2021-1675',
                    'remediation': 'Apply security updates or disable Print Spooler service'
                })
                self.signals.output.emit("<p style='color: #FF0000;'>🚨 CRITICAL: PrintNightmare vulnerability detected</p><br>")
            
            # Check for anonymous RPC access
            if self.auth_type == "Anonymous" and results.get('services'):
                vulnerabilities.append({
                    'name': 'Anonymous RPC Access',
                    'severity': 'Medium',
                    'description': 'RPC services accessible without authentication',
                    'remediation': 'Implement proper authentication for RPC services'
                })
                self.signals.output.emit("<p style='color: #FFA500;'>⚠️ MEDIUM: Anonymous RPC access detected</p><br>")
            
            results['vulnerabilities'] = vulnerabilities
            
            if vulnerabilities:
                self.signals.output.emit(f"<p style='color: #FF6B6B;'>Found {len(vulnerabilities)} vulnerabilities</p><br>")
            else:
                self.signals.output.emit("<p style='color: #00FF41;'>✅ No obvious vulnerabilities detected</p><br>")
                
        except Exception as e:
            results['errors'].append(f"Vulnerability scanning failed: {str(e)}")
    
    def _check_print_spooler_vulnerability(self) -> bool:
        """Check for Print Spooler vulnerability"""
        try:
            cmd = ["sc", f"\\\\{self.target}", "query", "spooler"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return result.returncode == 0 and "RUNNING" in result.stdout
        except Exception:
            return False
    
    def _advanced_security_analysis(self, results: Dict):
        """Perform advanced security analysis for Complete Assessment"""
        try:
            # Analyze service configurations
            self._analyze_service_security(results)
            
            # Check for privilege escalation paths
            self._check_privilege_escalation(results)
            
            # Generate risk score
            risk_score = self._calculate_risk_score(results)
            results['risk_score'] = risk_score
            
            self.signals.output.emit(f"<p style='color: #87CEEB;'>Risk Score: {risk_score}/100</p><br>")
            
        except Exception as e:
            results['errors'].append(f"Advanced security analysis failed: {str(e)}")
    
    def _analyze_service_security(self, results: Dict):
        """Analyze service security configurations"""
        try:
            services = results.get('services', [])
            security_issues = []
            
            for service in services:
                name = service.get('name', '').lower()
                state = service.get('state', '').upper()
                
                # Check for potentially dangerous services
                if name in ['telnet', 'ftp', 'rsh', 'rlogin'] and state == 'RUNNING':
                    security_issues.append({
                        'service': service.get('name'),
                        'issue': 'Insecure service running',
                        'severity': 'High',
                        'recommendation': f'Disable {service.get("name")} service if not needed'
                    })
            
            results['security_issues'] = security_issues
            
            if security_issues:
                self.signals.output.emit(f"<p style='color: #FFA500;'>Found {len(security_issues)} security issues</p><br>")
                
        except Exception as e:
            results['errors'].append(f"Service security analysis failed: {str(e)}")
    
    def _check_privilege_escalation(self, results: Dict):
        """Check for privilege escalation opportunities"""
        try:
            escalation_paths = []
            
            # Check if we have service enumeration access
            if results.get('services'):
                escalation_paths.append({
                    'method': 'Service Enumeration',
                    'description': 'Ability to enumerate services may reveal attack vectors',
                    'severity': 'Low'
                })
            
            # Check registry access
            if results.get('registry_access'):
                escalation_paths.append({
                    'method': 'Registry Access',
                    'description': 'Remote registry access may expose sensitive information',
                    'severity': 'Medium'
                })
            
            results['escalation_paths'] = escalation_paths
            
        except Exception as e:
            results['errors'].append(f"Privilege escalation check failed: {str(e)}")
    
    def _calculate_risk_score(self, results: Dict) -> int:
        """Calculate overall risk score (0-100)"""
        try:
            score = 0
            
            # Base score for RPC access
            if results.get('endpoints'):
                score += 10
            
            # Service enumeration access
            if results.get('services'):
                score += 15
            
            # Registry access
            if results.get('registry_access'):
                score += 20
            
            # Vulnerabilities
            vulnerabilities = results.get('vulnerabilities', [])
            for vuln in vulnerabilities:
                severity = vuln.get('severity', '').lower()
                if severity == 'critical':
                    score += 30
                elif severity == 'high':
                    score += 20
                elif severity == 'medium':
                    score += 10
                else:
                    score += 5
            
            # Anonymous access penalty
            if self.auth_type == "Anonymous":
                score += 15
            
            return min(score, 100)
            
        except Exception:
            return 0
    
    def _process_results(self, results: Dict):
        """Process and format results for UI consumption"""
        try:
            # Prepare table data
            table_data = self._prepare_table_data(results)
            results['table_data'] = table_data
            
            # Prepare graph data
            graph_data = self._prepare_graph_data(results)
            results['graph_data'] = graph_data
            
            # Store data in centralized system
            if self.data_collector:
                self._store_centralized_data(results)
                
        except Exception as e:
            results['errors'].append(f"Result processing failed: {str(e)}")
    
    def _prepare_table_data(self, results: Dict) -> Dict:
        """Prepare data for table display"""
        table_data = {}
        
        # Services table
        services = results.get('services', [])
        if services:
            table_data['services'] = [{
                'Service Name': s.get('name', 'Unknown'),
                'Display Name': s.get('display_name', ''),
                'State': s.get('state', 'Unknown')
            } for s in services]
        
        # Endpoints table
        endpoints = results.get('endpoints', [])
        if endpoints:
            table_data['endpoints'] = [{
                'Port': ep.get('port', 'Unknown'),
                'Service': ep.get('service', 'Unknown'),
                'Protocol': ep.get('protocol', 'tcp'),
                'Status': ep.get('status', 'unknown')
            } for ep in endpoints]
        
        # Vulnerabilities table
        vulnerabilities = results.get('vulnerabilities', [])
        if vulnerabilities:
            table_data['vulnerabilities'] = [{
                'Vulnerability': v.get('name', 'Unknown'),
                'Severity': v.get('severity', 'Unknown'),
                'CVE': v.get('cve', ''),
                'Description': v.get('description', '')
            } for v in vulnerabilities]
        
        return table_data
    
    def _prepare_graph_data(self, results: Dict) -> Dict:
        """Prepare data for graph/tree display"""
        graph_data = {}
        
        # Services breakdown
        services = results.get('services', [])
        if services:
            running_services = [s for s in services if s.get('state', '').upper() == 'RUNNING']
            stopped_services = [s for s in services if s.get('state', '').upper() == 'STOPPED']
            
            graph_data['Windows Services'] = {
                'count': len(services),
                'details': f"Total services enumerated",
                'children': {
                    'Running': {
                        'count': len(running_services),
                        'details': f"{len(running_services)} running services"
                    },
                    'Stopped': {
                        'count': len(stopped_services),
                        'details': f"{len(stopped_services)} stopped services"
                    }
                }
            }
        
        # Network endpoints
        endpoints = results.get('endpoints', [])
        if endpoints:
            graph_data['Network Endpoints'] = {
                'count': len(endpoints),
                'details': f"Accessible network endpoints",
                'children': {f"Port {ep.get('port')}": {
                    'count': 1,
                    'details': ep.get('service', 'Unknown service')
                } for ep in endpoints}
            }
        
        # Security assessment
        vulnerabilities = results.get('vulnerabilities', [])
        security_issues = results.get('security_issues', [])
        
        if vulnerabilities or security_issues:
            graph_data['Security Assessment'] = {
                'count': len(vulnerabilities) + len(security_issues),
                'details': f"Security findings",
                'children': {
                    'Vulnerabilities': {
                        'count': len(vulnerabilities),
                        'details': f"{len(vulnerabilities)} vulnerabilities found"
                    },
                    'Security Issues': {
                        'count': len(security_issues),
                        'details': f"{len(security_issues)} configuration issues"
                    }
                }
            }
        
        return graph_data
    
    def _store_centralized_data(self, results: Dict):
        """Store results in centralized data system"""
        try:
            if not self.data_collector:
                return
            
            # Store endpoints
            endpoints = results.get('endpoints', [])
            if endpoints:
                self.data_collector.collect_network_endpoints(self.target, endpoints)
            
            # Store services
            services = results.get('services', [])
            if services:
                self.data_collector.collect_rpc_services(self.target, services)
            
            # Store vulnerabilities
            vulnerabilities = results.get('vulnerabilities', [])
            if vulnerabilities:
                self.data_collector.collect_rpc_vulnerabilities(self.target, vulnerabilities)
            
            # Complete scan
            total_results = len(endpoints) + len(services) + len(vulnerabilities)
            self.data_collector.complete_rpc_scan(total_results=total_results)
            
        except Exception as e:
            results['errors'].append(f"Data storage failed: {str(e)}")
    
    def _handle_error(self, error_message: str):
        """Handle scan errors"""
        self.signals.output.emit(f"<p style='color: #FF6B6B;'>Error: {error_message}</p><br>")
        if self.data_collector:
            try:
                self.data_collector.complete_rpc_scan(error_message=error_message)
            except Exception:
                pass
    
    def _cleanup(self):
        """Cleanup resources"""
        try:
            # Clean up any authenticated sessions
            if self.auth_type != "Anonymous":
                subprocess.run(["net", "use", f"\\\\{self.target}", "/delete", "/y"], 
                             capture_output=True, timeout=5)
        except Exception:
            pass