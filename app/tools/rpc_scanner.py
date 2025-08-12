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
            self.signals.output.emit("<p style='color: #87CEEB;'>RPC Scanner starting...</p><br>")
            
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
            self.signals.output.emit("<p style='color: #87CEEB;'>Executing scan...</p><br>")
            results = self._execute_scan()
            
            # Process results
            if results:
                self._process_results(results)
                
                # Emit table and graph data signals
                if hasattr(self, 'signals'):
                    if hasattr(self.signals, 'table_data'):
                        table_data = results.get('table_data', {})
                        if table_data:
                            self.signals.table_data.emit(table_data)
                    
                    if hasattr(self.signals, 'graph_data'):
                        graph_data = results.get('graph_data', {})
                        if graph_data:
                            self.signals.graph_data.emit(graph_data)
                
                self.signals.results.emit(results)
                self.signals.output.emit("<p style='color: #00FF41;'>✅ RPC enumeration completed successfully</p><br>")
            else:
                self.signals.output.emit("<p style='color: #FF6B6B;'>❌ RPC enumeration failed</p><br>")
                
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF6B6B;'>Exception in run(): {str(e)}</p><br>")
            self._handle_error(f"RPC scan failed: {str(e)}")
        finally:
            self.signals.output.emit("<p style='color: #87CEEB;'>RPC Scanner finishing...</p><br>")
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
        
        # Step 1: Try native RPC enumeration first (like legacy version)
        self.signals.progress_update.emit(current_step, 0, "Running native RPC enumeration...")
        native_results = self._native_rpc_enumeration()
        
        if native_results:
            results.update(native_results)
            self.signals.output.emit("<p style='color: #00FF41;'>✅ Native RPC enumeration completed successfully</p><br>")
            return results
        
        # Fallback to basic methods if native enumeration fails
        self.signals.output.emit("<p style='color: #FFD700;'>Falling back to basic enumeration methods...</p><br>")
        
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
        """Enumerate services without authentication using enhanced RPC enumeration"""
        try:
            # Try enhanced RPC enumeration first
            enhanced_results = self._try_enhanced_rpc_enumeration()
            if enhanced_results:
                # Merge enhanced results
                if enhanced_results.get('services'):
                    results['services'] = enhanced_results['services']
                    self.signals.output.emit(f"<p style='color: #00FF41;'>Found {len(enhanced_results['services'])} services via RPC</p><br>")
                    
                    # Show sample services
                    for service in enhanced_results['services'][:5]:
                        name = service.get('name', 'Unknown')
                        state = service.get('state', 'Unknown')
                        self.signals.output.emit(f"<p>• {name}: {state}</p><br>")
                        
                    if len(enhanced_results['services']) > 5:
                        self.signals.output.emit(f"<p>... and {len(enhanced_results['services']) - 5} more services</p><br>")
                
                # Add RPC endpoints if found
                if enhanced_results.get('rpc_endpoints'):
                    results['rpc_endpoints'] = enhanced_results['rpc_endpoints']
                    self.signals.output.emit(f"<p style='color: #00FF41;'>Discovered {len(enhanced_results['rpc_endpoints'])} RPC endpoints</p><br>")
                
                # Add shares if found
                if enhanced_results.get('shares'):
                    results['shares'] = enhanced_results['shares']
                    self.signals.output.emit(f"<p style='color: #00FF41;'>Found {len(enhanced_results['shares'])} SMB shares</p><br>")
                    for share in enhanced_results['shares'][:3]:
                        name = share.get('name', 'Unknown')
                        share_type = share.get('type', 'Unknown')
                        self.signals.output.emit(f"<p>• {name} ({share_type})</p><br>")
                
                return
            
            # Fallback to basic sc command
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
                # Check if it's an access denied error
                if result.returncode == 5 or "Access is denied" in result.stderr:
                    self.signals.output.emit("<p style='color: #FFAA00;'>⚠️ Anonymous access denied - target is properly secured</p><br>")
                    self.signals.output.emit("<p style='color: #87CEEB;'>💡 Try using authenticated scan with valid credentials</p><br>")
                    
                    # Still try to get basic network connectivity info
                    self._test_basic_connectivity(results)
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
        
        # RPC Endpoints table
        rpc_endpoints = results.get('rpc_endpoints', [])
        if rpc_endpoints:
            table_data['rpc_endpoints'] = [{
                'Protocol': ep.get('protocol', 'Unknown'),
                'UUID': ep.get('uuid', 'Unknown'),
                'Port': ep.get('port', 'N/A'),
                'Description': ep.get('description', '')
            } for ep in rpc_endpoints]
        
        # Network Endpoints table
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
    
    def _try_enhanced_rpc_enumeration(self) -> Dict:
        """Try enhanced RPC enumeration using the windows_rpc_client"""
        try:
            from ..core.windows_rpc_client import enumerate_target_rpc
            
            # Resolve target to IP
            target_ip = self._resolve_target(self.target)
            
            # Use enhanced RPC enumeration with proper credentials
            domain = self.domain or ""
            username = self.username or ""
            password = self.password or ""
            
            # Only extract domain from username if no domain field provided
            if not domain and username:
                if '\\' in username:
                    domain, username = username.split('\\', 1)
                elif '@' in username:
                    username, domain = username.split('@', 1)
            
            results = enumerate_target_rpc(target_ip, domain, username, password)
            return results
            
        except ImportError:
            # windows_rpc_client not available, return None
            return None
        except Exception as e:
            # Enhanced enumeration failed, return None to fallback
            return None
    
    def _resolve_target(self, target: str) -> str:
        """Simple target resolution - use IP directly"""
        try:
            # Check if target is already an IP address
            socket.inet_aton(target)
            return target  # Already an IP
        except socket.error:
            pass
        
        try:
            # Simple system DNS resolution
            resolved_ip = socket.gethostbyname(target)
            return resolved_ip
        except Exception:
            return target
    
    def _test_basic_connectivity(self, results: Dict):
        """Test basic network connectivity when RPC access is denied"""
        try:
            self.signals.output.emit("<p style='color: #FFD700;'>Testing basic network connectivity...</p><br>")
            
            # Test common ports
            test_ports = [135, 445, 139, 3389, 53, 88, 389]
            open_ports = []
            
            for port in test_ports:
                if self._test_port(port):
                    service_map = {
                        135: 'RPC Endpoint Mapper',
                        445: 'SMB/CIFS',
                        139: 'NetBIOS Session Service',
                        3389: 'Remote Desktop',
                        53: 'DNS',
                        88: 'Kerberos',
                        389: 'LDAP'
                    }
                    
                    open_ports.append({
                        'port': port,
                        'service': service_map.get(port, f'Service on port {port}'),
                        'protocol': 'tcp',
                        'status': 'open'
                    })
            
            if open_ports:
                results['endpoints'] = open_ports
                self.signals.output.emit(f"<p style='color: #00FF41;'>✅ Found {len(open_ports)} accessible network services:</p><br>")
                
                for endpoint in open_ports:
                    port = endpoint['port']
                    service = endpoint['service']
                    
                    # Highlight important services
                    if port in [135, 445]:
                        self.signals.output.emit(f"<p style='color: #FFD700;'>🔑 Port {port}: {service} (RPC/SMB available)</p><br>")
                    elif port == 3389:
                        self.signals.output.emit(f"<p style='color: #87CEEB;'>🖥️ Port {port}: {service}</p><br>")
                    elif port in [88, 389]:
                        self.signals.output.emit(f"<p style='color: #90EE90;'>🏢 Port {port}: {service} (Domain services)</p><br>")
                    else:
                        self.signals.output.emit(f"<p>• Port {port}: {service}</p><br>")
                
                # Provide recommendations based on open ports
                if any(ep['port'] in [135, 445] for ep in open_ports):
                    self.signals.output.emit("<p style='color: #87CEEB;'>💡 RPC/SMB services detected - authenticated enumeration recommended</p><br>")
                
                if any(ep['port'] in [88, 389] for ep in open_ports):
                    self.signals.output.emit("<p style='color: #87CEEB;'>💡 Domain Controller services detected</p><br>")
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>No common network services accessible</p><br>")
                
        except Exception as e:
            results['errors'].append(f"Basic connectivity test failed: {str(e)}")
    
    def _cleanup(self):
        """Cleanup resources"""
        try:
            # Clean up any authenticated sessions
            if self.auth_type != "Anonymous":
                subprocess.run(["net", "use", f"\\\\{self.target}", "/delete", "/y"], 
                             capture_output=True, timeout=5)
        except Exception:
            pass
    
    def _native_rpc_enumeration(self) -> dict:
        """Perform native RPC enumeration using enhanced Windows RPC client (from legacy version)"""
        try:
            self.signals.output.emit("<p style='color: #FFD700;'>Initializing native RPC enumeration...</p><br>")
            
            # Import here to avoid issues
            from ..core.windows_rpc_client import enumerate_target_rpc
            
            # Use the domain field directly, don't try to extract from target
            domain = self.domain or ""
            username = self.username or ""
            
            # Only extract domain from username if no domain field provided
            if not domain and username:
                if '\\' in username:
                    domain, username = username.split('\\', 1)
                elif '@' in username:
                    username, domain = username.split('@', 1)
            
            # Resolve hostname to IP if needed
            target_ip = self._resolve_target(self.target)
            
            # Debug output
            self.signals.output.emit(f"<p style='color: #87CEEB;'>Target: {self.target} -> {target_ip}</p><br>")
            self.signals.output.emit(f"<p style='color: #87CEEB;'>Scan type: {self.scan_type}</p><br>")
            
            # For anonymous access, skip auth test
            if self.auth_type == "Anonymous":
                self.signals.output.emit(f"<p style='color: #FFD700;'>Using anonymous access...</p><br>")
            elif username and self.password:
                self.signals.output.emit(f"<p style='color: #87CEEB;'>Domain: {domain or 'None'}</p><br>")
                self.signals.output.emit(f"<p style='color: #87CEEB;'>Username: {username}</p><br>")
                if domain:
                    self.signals.output.emit(f"<p style='color: #00FF41;'>Using domain credentials: {domain}\\{username}</p><br>")
            
            # For RPC enumeration, use resolved IP regardless of auth type
            self.signals.output.emit("<p style='color: #87CEEB;'>Calling enumerate_target_rpc...</p><br>")
            results = enumerate_target_rpc(target_ip, domain, username, self.password)
            # Process enumeration results
            
            if results.get('errors'):
                for error in results['errors']:
                    self.signals.output.emit(f"<p style='color: #FFAA00;'>Warning: {error}</p><br>")
            
            # Display RPC endpoints first
            rpc_endpoints = results.get('rpc_endpoints', [])
            if rpc_endpoints:
                # Collect RPC endpoints data
                if self.data_collector:
                    self.data_collector.collect_rpc_endpoints(self.target, rpc_endpoints)
                
                self.signals.output.emit(f"<p style='color: #00FF41;'>Discovered {len(rpc_endpoints)} RPC endpoints:</p><br>")
                for endpoint in rpc_endpoints:
                    protocol = endpoint.get('protocol', 'Unknown')
                    uuid_str = endpoint.get('uuid', 'N/A')
                    port_info = f" (port {endpoint.get('port', 'unknown')})" if 'port' in endpoint else ""
                    
                    # Highlight critical RPC services
                    if any(critical in protocol.lower() for critical in ['service control', 'registry', 'lsa']):
                        self.signals.output.emit(f"<p style='color: #FFD700;'>• {protocol}: {uuid_str}{port_info}</p><br>")
                    else:
                        self.signals.output.emit(f"<p>• {protocol}: {uuid_str}{port_info}</p><br>")
            
            # Display network endpoints
            endpoints = results.get('endpoints', [])
            if endpoints:
                # Collect network endpoints data
                if self.data_collector:
                    self.data_collector.collect_network_endpoints(self.target, endpoints)
                
                self.signals.output.emit(f"<p style='color: #00FF41;'>Network endpoints accessible: {len(endpoints)}</p><br>")
                for endpoint in endpoints:
                    self.signals.output.emit(f"<p>• Port {endpoint['port']}: {endpoint['service']}</p><br>")
            
            # Display services with enhanced formatting
            services = results.get('services', [])
            if services:
                # Collect services data
                if self.data_collector:
                    self.data_collector.collect_rpc_services(self.target, services)
                
                self.signals.output.emit(f"<p style='color: #00FF41;'>Enumerated {len(services)} Windows services:</p><br>")
                
                # Group services by state
                running_services = [s for s in services if s.get('state', '').upper() == 'RUNNING']
                stopped_services = [s for s in services if s.get('state', '').upper() == 'STOPPED']
                
                if running_services:
                    self.signals.output.emit(f"<p style='color: #90EE90;'>Running services ({len(running_services)}):</p><br>")
                    for service in running_services[:15]:  # Show first 15
                        name = service.get('name', 'Unknown')
                        display_name = service.get('display_name', '')
                        if display_name and display_name != name:
                            self.signals.output.emit(f"<p>• {name} ({display_name})</p><br>")
                        else:
                            self.signals.output.emit(f"<p>• {name}</p><br>")
                    
                    if len(running_services) > 15:
                        self.signals.output.emit(f"<p>... and {len(running_services) - 15} more running services</p><br>")
                        self.signals.output.emit(f"<p style='color: #87CEEB;'>💡 Switch to Table view to see all {len(running_services)} services</p><br>")
            
            # Display SAMR information
            samr_info = results.get('samr_info', {})
            if samr_info:
                # Collect SAMR data
                if self.data_collector:
                    self.data_collector.collect_samr_data(self.target, samr_info)
                
                domains = samr_info.get('domains', [])
                users = samr_info.get('sample_users', [])
                
                self.signals.output.emit(f"<p style='color: #00FF41;'>SAMR Enumeration Results:</p><br>")
                self.signals.output.emit(f"<p>• Domains: {len(domains)}</p><br>")
                for domain in domains:
                    name = domain.get('name', 'Unknown')
                    user_count = domain.get('users_count', 0)
                    self.signals.output.emit(f"<p>  - {name}: {user_count} users</p><br>")
                
                if users:
                    self.signals.output.emit(f"<p>• Sample Users ({len(users)}):</p><br>")
                    for user in users[:3]:  # Show first 3
                        name = user.get('name', 'Unknown')
                        rid = user.get('rid', 0)
                        enabled = '[+]' if user.get('enabled') else '[-]'
                        self.signals.output.emit(f"<p>  - {name} (RID: {rid}) {enabled}</p><br>")
            
            # Display LSA information
            lsa_info = results.get('lsa_info', {})
            if lsa_info:
                # Collect LSA data
                if self.data_collector:
                    self.data_collector.collect_lsa_data(self.target, lsa_info)
                
                domain_name = lsa_info.get('domain_name', 'Unknown')
                trusted_domains = lsa_info.get('trusted_domains', [])
                
                self.signals.output.emit(f"<p style='color: #00FF41;'>LSA Policy Information:</p><br>")
                self.signals.output.emit(f"<p>• Domain: {domain_name}</p><br>")
                if trusted_domains:
                    self.signals.output.emit(f"<p>• Trusted Domains: {', '.join(trusted_domains)}</p><br>")
            
            # Display shares information if available
            shares_info = results.get('shares', [])
            if shares_info:
                if self.data_collector:
                    self.data_collector.collect_shares_data(self.target, shares_info)
                self.signals.output.emit(f"<p style='color: #00FF41;'>SMB Shares Found ({len(shares_info)}):</p><br>")
                for share in shares_info:
                    share_name = share.get('name', 'Unknown')
                    share_type = share.get('type', 'Unknown')
                    permissions = share.get('permissions', 'Unknown')
                    self.signals.output.emit(f"<p>• {share_name} ({share_type}) - {permissions}</p><br>")
            
            # Display registry information
            registry_data = results.get('registry', {})
            if registry_data:
                # Collect registry data
                if self.data_collector:
                    self.data_collector.collect_registry_data(self.target, registry_data)
                
                os_info = registry_data.get('os_info', {})
                if os_info:
                    self.signals.output.emit(f"<p style='color: #00FF41;'>System Information:</p><br>")
                    # Prioritize important OS information
                    important_keys = ['ProductName', 'CurrentVersion', 'CurrentBuild', 'ReleaseId']
                    for key in important_keys:
                        if key in os_info and os_info[key]:
                            self.signals.output.emit(f"<p>• {key}: {os_info[key]}</p><br>")
            
            self.signals.output.emit("<p style='color: #00FF41;'>Native RPC enumeration completed</p><br>")
            return results
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF6B6B;'>Native RPC enumeration failed: {str(e)}</p><br>")
            import traceback
            self.signals.output.emit(f"<p style='color: #FF6B6B;'>Traceback: {traceback.format_exc()}</p><br>")
            return None