# app/tools/rpc_scanner.py
import subprocess
import re
import socket
from PyQt6.QtCore import QObject, pyqtSignal, QRunnable
from ..core.rpc_enum import RPCEnumerator
from ..core.windows_rpc_client import enumerate_target_rpc
from ..core.dns_settings import dns_settings
from ..core.secure_credential_manager import secure_credential_manager
from ..core.kerberos_auth import KerberosAuth
from ..core.secrets_extractor import SecretsExtractor
from ..core.rpc_protocol import RPCFuzzer, RPCCoercionAttacks, RPCRelayEngine
from ..core.rpc_service_impersonation import RPCServiceDiscovery, RPCHoneypot
from ..core.vulnerability_database import VulnerabilityCollector, vuln_db
from app.core.html_utils import h
import logging

class RPCWorkerSignals(QObject):
    output = pyqtSignal(str)
    finished = pyqtSignal()
    results = pyqtSignal(dict)
    table_data = pyqtSignal(dict)
    graph_data = pyqtSignal(dict)
    progress_start = pyqtSignal(int, str)
    progress_update = pyqtSignal(int, int, str)

class RPCWorker(QRunnable):
    def __init__(self, target, scan_type, auth_type, username="", password="", ntlm_hash="", service_name="", ticket_path="", domain=""):
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
        self.signals = RPCWorkerSignals()
        self.is_running = True
        self.kerberos_auth = KerberosAuth()
        self.secrets_extractor = SecretsExtractor()
        self.vuln_collector = None
    
    def run(self):
        try:
            # Determine total steps based on scan type
            total_steps = 1  # Basic connectivity
            if self.scan_type in ["Full Enumeration", "Complete Assessment"]:
                total_steps += 1  # Registry enumeration
            if self.scan_type in ["Vulnerability Scan", "Complete Assessment"]:
                total_steps += 3  # Service enumeration + vulnerability probing + RPC signing + NTLM relay
            if self.scan_type == "Complete Assessment" and self.auth_type not in ["Anonymous"]:
                total_steps += 1  # Secrets extraction
            
            self.signals.progress_start.emit(total_steps, f"RPC {self.scan_type}")
            
            # Initialize vulnerability collector
            self.vuln_collector = VulnerabilityCollector(self.target, f"RPC {self.scan_type}")
            
            self.signals.output.emit(f"<p style='color: #87CEEB;'>Starting native RPC enumeration on {h(self.target)}...</p><br>")
            self.signals.output.emit(f"<p style='color: #87CEEB;'>Authentication: {h(self.auth_type)}</p><br>")
            
            results = {}
            current_step = 0
            
            # Handle Kerberos authentication
            if self.auth_type == "Kerberos Ticket" and self.ticket_path:
                if self.kerberos_auth.authenticate_with_ticket(self.ticket_path, self.target):
                    self.signals.output.emit(f"<p style='color: #00FF41;'>Kerberos ticket authentication successful</p><br>")
                else:
                    self.signals.output.emit(f"<p style='color: #FF6B6B;'>Kerberos ticket authentication failed</p><br>")
                    return
            elif self.auth_type == "Kerberos Password" and self.username and self.password and self.domain:
                # Resolve target first using RPC scanner's DNS logic
                resolved_target = self._resolve_target(self.target)
                kerberos_success = self.kerberos_auth.authenticate_with_password(self.username, self.password, self.domain, resolved_target)
                if kerberos_success:
                    self.signals.output.emit(f"<p style='color: #00FF41;'>Kerberos password authentication successful</p><br>")
                else:
                    self.signals.output.emit(f"<p style='color: #FF6B6B;'>Kerberos password authentication failed</p><br>")
                    self.signals.output.emit(f"<p style='color: #FFD700;'>Continuing with fallback enumeration methods...</p><br>")
                # Store result for later use
                self._kerberos_success = kerberos_success
            
            # Get credentials from secure manager if using stored credentials
            elif self.auth_type == "Stored Credentials" and self.service_name:
                credential = secure_credential_manager.get_credential(self.service_name)
                if credential:
                    self.username = credential.username
                    self.password = credential.password
                    if credential.domain:
                        self.username = f"{credential.domain}\\{credential.username}"
                    self.signals.output.emit(f"<p style='color: #00FF41;'>Using stored credentials for service: {h(self.service_name)}</p><br>")
                else:
                    self.signals.output.emit(f"<p style='color: #FF6B6B;'>Error: Credentials not found for service: {h(self.service_name)}</p><br>")
                    return
            
            # Skip native RPC enumeration if Kerberos auth failed
            kerberos_failed = (self.auth_type == "Kerberos Password" and not getattr(self, '_kerberos_success', False))
            
            # Try native RPC enumeration first
            if self.auth_type not in ["Anonymous"] and self.username and not kerberos_failed:
                self.signals.progress_update.emit(current_step, 0, "Running native RPC enumeration...")
                native_results = self._native_rpc_enumeration()
                if native_results:
                    results.update(native_results)
                    # Update progress through the steps for native enumeration
                    current_step = 1
                    self.signals.progress_update.emit(current_step, len(results.get('rpc_endpoints', [])), "RPC endpoints discovered")
                    
                    if self.scan_type in ["Full Enumeration", "Complete Assessment"]:
                        current_step += 1
                        self.signals.progress_update.emit(current_step, 0, "Registry access completed")
                    
                    if self.scan_type in ["Vulnerability Scan", "Complete Assessment"]:
                        current_step += 1
                        self.signals.progress_update.emit(current_step, 0, "Services enumerated")
                        current_step += 1
                        self.signals.progress_update.emit(current_step, 0, "Vulnerability paths probed")
                        current_step += 1
                        self.signals.progress_update.emit(current_step, 0, "RPC signing tested")
                        current_step += 1
                        self.signals.progress_update.emit(current_step, 0, "NTLM relay surface scanned")
                    
                    if self.scan_type == "Complete Assessment" and self.auth_type not in ["Anonymous"]:
                        current_step += 1
                        self.signals.progress_update.emit(current_step, 0, "Secrets extraction completed")
                    
                    self.signals.results.emit(results)
                    self.signals.output.emit(f"<p style='color: #00FF41;'>Native RPC enumeration completed.</p><br>")
                    return
            
            # Fallback to legacy methods
            self.signals.output.emit("<p style='color: #FFD700;'>Falling back to legacy enumeration methods...</p><br>")
            
            # Basic RPC endpoint enumeration
            if self.scan_type in ["Basic Info", "Full Enumeration", "Complete Assessment"]:
                self.signals.progress_update.emit(current_step, 0, "Enumerating RPC endpoints...")
                self._enumerate_rpc_endpoints(results)
                current_step += 1
                self.signals.progress_update.emit(current_step, 0, "RPC endpoints enumerated")
            
            # Registry enumeration
            if self.scan_type in ["Full Enumeration", "Complete Assessment"]:
                self.signals.progress_update.emit(current_step, 0, "Accessing remote registry...")
                self._enumerate_registry(results)
                current_step += 1
                self.signals.progress_update.emit(current_step, 0, "Registry enumeration completed")
            
            # Service enumeration
            if self.scan_type in ["Vulnerability Scan", "Complete Assessment"]:
                self.signals.progress_update.emit(current_step, 0, "Enumerating services...")
                self._enumerate_services(results)
                current_step += 1
            
            # Vulnerability path probing
            if self.scan_type in ["Vulnerability Scan", "Complete Assessment"]:
                self.signals.progress_update.emit(current_step, 0, "Probing vulnerability paths...")
                self._probe_vulnerability_paths(results)
                current_step += 1
            
            # RPC signing/sealing detection
            if self.scan_type in ["Vulnerability Scan", "Complete Assessment"]:
                self.signals.progress_update.emit(current_step, 0, "Testing RPC signing/sealing...")
                self._test_rpc_signing_sealing(results)
                current_step += 1
            
            # NTLM relay attack surface scanning
            if self.scan_type in ["Vulnerability Scan", "Complete Assessment"]:
                self.signals.progress_update.emit(current_step, 0, "Scanning NTLM relay attack surface...")
                self._scan_ntlm_relay_surface(results)
                current_step += 1
            
            # Secrets extraction (privileged only)
            if self.scan_type == "Complete Assessment" and self.auth_type not in ["Anonymous"] and self.username:
                self.signals.progress_update.emit(current_step, 0, "Extracting secrets...")
                self._extract_secrets(results)
                current_step += 1
            
            self.signals.results.emit(results)
            self.signals.output.emit(f"<p style='color: #00FF41;'>RPC enumeration completed.</p><br>")
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF6B6B;'>Error: {h(str(e))}</p><br>")
        finally:
            self.signals.finished.emit()
    
    def _enumerate_rpc_endpoints(self, results):
        """Enumerate RPC endpoints using Windows tools"""
        try:
            self.signals.output.emit("<p style='color: #FFD700;'>Checking RPC endpoint mapper (port 135)...</p><br>")
            
            # Use netstat to check for RPC ports
            cmd = ["netstat", "-an"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            rpc_ports = set()  # Use set to avoid duplicates
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if ':135' in line and 'LISTENING' in line:
                        rpc_ports.add('135 (RPC Endpoint Mapper)')
                    elif ':445' in line and 'LISTENING' in line:
                        rpc_ports.add('445 (SMB over TCP)')
                    elif ':139' in line and 'LISTENING' in line:
                        rpc_ports.add('139 (NetBIOS Session)')
                
                rpc_ports = list(rpc_ports)  # Convert back to list
            
            if rpc_ports:
                results['rpc_ports'] = rpc_ports
                self.signals.output.emit(f"<p style='color: #00FF41;'>Found {len(rpc_ports)} RPC-related ports</p><br>")
                for port in rpc_ports:
                    self.signals.output.emit(f"<p>Port: {port}</p><br>")
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>No RPC ports detected</p><br>")
                
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>RPC enumeration failed: {h(str(e))}</p><br>")
    
    def _enumerate_registry(self, results):
        """Enumerate registry if credentials provided"""
        if self.auth_type == "Anonymous":
            self.signals.output.emit("<p style='color: #FFD700;'>Skipping registry enumeration (Anonymous mode)</p><br>")
            return
        
        try:
            self.signals.output.emit("<p style='color: #FFD700;'>Attempting remote registry access...</p><br>")
            
            # Try to query remote registry
            cmd = ["reg", "query", f"\\\\{self.target}\\HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "/v", "ProductName"]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0 and "ProductName" in result.stdout:
                self.signals.output.emit("<p style='color: #00FF41;'>Remote registry access successful</p><br>")
                results['registry_access'] = True
                
                # Extract OS info
                match = re.search(r'ProductName\s+REG_SZ\s+(.+)', result.stdout)
                if match:
                    os_name = match.group(1).strip()
                    results['os_info'] = os_name
                    self.signals.output.emit(f"<p>OS: {h(os_name)}</p><br>")
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>Remote registry access denied or unavailable</p><br>")
                results['registry_access'] = False
                    
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>Registry enumeration failed: {h(str(e))}</p><br>")
    
    def _enumerate_services(self, results):
        """Enumerate services using Windows sc command"""
        try:
            self.signals.output.emit("<p style='color: #FFD700;'>Enumerating remote services...</p><br>")
            
            # Try to enumerate services
            cmd = ["sc", f"\\\\{self.target}", "query"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 and result.stdout:
                services = []
                lines = result.stdout.split('\n')
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
                        current_service['state'] = line.split(':', 1)[1].strip()
                
                if current_service:
                    services.append(current_service)
                
                results['services'] = services
                self.signals.output.emit(f"<p style='color: #00FF41;'>Found {len(services)} services</p><br>")
                
                # Show first few services
                for i, svc in enumerate(services[:5]):
                    name = svc.get('name', 'Unknown')
                    state = svc.get('state', 'Unknown')
                    self.signals.output.emit(f"<p>Service: {h(name)} - State: {h(state)}</p><br>")
                
                if len(services) > 5:
                    self.signals.output.emit(f"<p>... and {len(services) - 5} more services</p><br>")
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>Service enumeration failed or access denied</p><br>")
                
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>Service enumeration failed: {h(str(e))}</p><br>")
    
    def _native_rpc_enumeration(self) -> dict:
        """Perform native RPC enumeration using enhanced Windows RPC client"""
        try:
            self.signals.output.emit("<p style='color: #FFD700;'>Initializing native RPC enumeration...</p><br>")
            
            # Use the domain field directly, don't try to extract from target
            domain = self.domain or ""
            username = self.username
            
            # Only extract domain from username if no domain field provided
            if not domain:
                if '\\' in username:
                    domain, username = username.split('\\', 1)
                elif '@' in username:
                    username, domain = username.split('@', 1)
            
            # Resolve hostname to IP if needed
            target_ip = self._resolve_target(self.target)
            
            # Debug output
            self.signals.output.emit(f"<p style='color: #87CEEB;'>Target: {h(self.target)} -> {h(target_ip)}</p><br>")
            self.signals.output.emit(f"<p style='color: #87CEEB;'>Domain: {h(domain or 'None')}</p><br>")
            self.signals.output.emit(f"<p style='color: #87CEEB;'>Username: {h(username)}</p><br>")
            self.signals.output.emit(f"<p style='color: #87CEEB;'>Password: {'*' * len(self.password) if self.password else 'None'}</p><br>")
            if domain:
                self.signals.output.emit(f"<p style='color: #00FF41;'>Using domain credentials: {h(domain)}\\{h(username)}</p><br>")
            
            # Use enhanced Windows RPC enumeration based on scan type
            self.signals.output.emit(f"<p style='color: #87CEEB;'>Scan type: {h(self.scan_type)}</p><br>")
            
            # Skip Windows auth test for Kerberos since it already succeeded
            if self.auth_type == "Kerberos Password" and getattr(self, '_kerberos_success', False):
                auth_test = True
                self.signals.output.emit(f"<p style='color: #00FF41;'>Using successful Kerberos authentication</p><br>")
            else:
                # Try direct Windows authentication test first
                self.signals.output.emit(f"<p style='color: #FFD700;'>Testing Windows authentication...</p><br>")
                auth_test = self._test_windows_auth(target_ip, domain, username, self.password)
                if not auth_test:
                    self.signals.output.emit(f"<p style='color: #FFAA00;'>Windows authentication test failed, trying RPC enumeration anyway...</p><br>")
            
            # For RPC enumeration, use resolved IP regardless of auth type
            results = enumerate_target_rpc(target_ip, domain, username, self.password)
            
            # Filter results based on scan type
            if self.scan_type == "Basic Info":
                # Show only basic connectivity and RPC endpoints
                filtered_results = {
                    'endpoints': results.get('endpoints', []),
                    'rpc_endpoints': results.get('rpc_endpoints', []),
                    'errors': results.get('errors', [])
                }
                results = filtered_results
            elif self.scan_type == "Full Enumeration":
                # Show everything except detailed service analysis
                pass  # Use all results
            elif self.scan_type == "Vulnerability Scan":
                # Focus on services and potential security issues
                services = results.get('services', [])
                # Highlight potentially vulnerable services
                vulnerable_services = []
                for service in services:
                    name = service.get('name', '').lower()
                    if any(vuln in name for vuln in ['telnet', 'ftp', 'rsh', 'rlogin', 'snmp', 'tftp']):
                        vulnerable_services.append(service)
                results['vulnerable_services'] = vulnerable_services
            # Complete Assessment uses all results
            
            if results.get('errors'):
                for error in results['errors']:
                    self.signals.output.emit(f"<p style='color: #FFAA00;'>Warning: {h(error)}</p><br>")
            
            # Display RPC endpoints first
            rpc_endpoints = results.get('rpc_endpoints', [])
            if rpc_endpoints:
                self.signals.output.emit(f"<p style='color: #00FF41;'>Discovered {len(rpc_endpoints)} RPC endpoints:</p><br>")
                for endpoint in rpc_endpoints:
                    protocol = endpoint.get('protocol', 'Unknown')
                    uuid_str = endpoint.get('uuid', 'N/A')
                    port_info = f" (port {endpoint.get('port', 'unknown')})" if 'port' in endpoint else ""
                    
                    # Highlight critical RPC services
                    if any(critical in protocol.lower() for critical in ['service control', 'registry', 'lsa']):
                        self.signals.output.emit(f"<p style='color: #FFD700;'>• {h(protocol)}: {h(uuid_str)}{port_info}</p><br>")
                    else:
                        self.signals.output.emit(f"<p>• {h(protocol)}: {h(uuid_str)}{port_info}</p><br>")
            
            # Display network endpoints
            endpoints = results.get('endpoints', [])
            if endpoints:
                self.signals.output.emit(f"<p style='color: #00FF41;'>Network endpoints accessible: {len(endpoints)}</p><br>")
                for endpoint in endpoints:
                    self.signals.output.emit(f"<p>• Port {h(endpoint['port'])}: {h(endpoint['service'])}</p><br>")
            
            # Display services with enhanced formatting
            services = results.get('services', [])
            vulnerable_services = results.get('vulnerable_services', [])
            
            if self.scan_type == "Vulnerability Scan" and vulnerable_services:
                self.signals.output.emit(f"<p style='color: #FF6B6B;'>Potentially vulnerable services found ({len(vulnerable_services)}):</p><br>")
                for service in vulnerable_services:
                    name = service.get('name', 'Unknown')
                    state = service.get('state', 'Unknown')
                    self.signals.output.emit(f"<p style='color: #FFAA00;'>⚠ {h(name)} - State: {h(state)}</p><br>")
            
            if services and self.scan_type != "Basic Info":
                self.signals.output.emit(f"<p style='color: #00FF41;'>Enumerated {len(services)} Windows services:</p><br>")
                
                # Group services by state
                running_services = [s for s in services if s.get('state', '').startswith('4')]
                stopped_services = [s for s in services if s.get('state', '').startswith('1')]
                
                if running_services:
                    self.signals.output.emit(f"<p style='color: #90EE90;'>Running services ({len(running_services)}):</p><br>")
                    for service in running_services:
                        name = service.get('name', 'Unknown')
                        display_name = service.get('display_name', '')
                        if display_name and display_name != name:
                            self.signals.output.emit(f"<p>• {h(name)} ({h(display_name)})</p><br>")
                        else:
                            self.signals.output.emit(f"<p>• {h(name)}</p><br>")
                
                if stopped_services and self.scan_type == "Complete Assessment":
                    self.signals.output.emit(f"<p style='color: #FFB6C1;'>Stopped services ({len(stopped_services)}):</p><br>")
                    for service in stopped_services:
                        name = service.get('name', 'Unknown')
                        display_name = service.get('display_name', '')
                        if display_name and display_name != name:
                            self.signals.output.emit(f"<p>• {h(name)} ({h(display_name)})</p><br>")
                        else:
                            self.signals.output.emit(f"<p>• {h(name)}</p><br>")
            
            # Display registry information
            registry_data = results.get('registry', {})
            if registry_data and self.scan_type in ["Full Enumeration", "Complete Assessment"]:
                os_info = registry_data.get('os_info', {})
                if os_info:
                    self.signals.output.emit(f"<p style='color: #00FF41;'>System Information:</p><br>")
                    # Prioritize important OS information
                    important_keys = ['ProductName', 'CurrentVersion', 'CurrentBuild', 'ReleaseId']
                    for key in important_keys:
                        if key in os_info and os_info[key]:
                            self.signals.output.emit(f"<p>• {h(key)}: {h(os_info[key])}</p><br>")
                    
                    # Show other registry values
                    other_keys = [k for k in os_info.keys() if k not in important_keys]
                    for key in other_keys:
                        if key and os_info[key]:
                            self.signals.output.emit(f"<p>• {h(key)}: {h(os_info[key])}</p><br>")
                
                self.signals.output.emit(f"<p style='color: #00FF41;'>Remote registry access: Successful</p><br>")
            elif registry_data:
                self.signals.output.emit(f"<p style='color: #00FF41;'>Remote registry: Accessible</p><br>")
            
            # Summary based on scan type
            if self.scan_type == "Basic Info":
                total_findings = len(rpc_endpoints) + len(endpoints)
                self.signals.output.emit(f"<p style='color: #87CEEB;'>Basic enumeration complete: {total_findings} endpoint categories discovered</p><br>")
            elif self.scan_type == "Vulnerability Scan":
                vuln_count = len(vulnerable_services)
                if vuln_count > 0:
                    self.signals.output.emit(f"<p style='color: #FF6B6B;'>Vulnerability scan complete: {h(vuln_count)} potentially vulnerable services identified</p><br>")
                else:
                    self.signals.output.emit(f"<p style='color: #00FF41;'>Vulnerability scan complete: No obvious vulnerable services detected</p><br>")
            else:
                total_findings = len(rpc_endpoints) + len(endpoints) + len(services) + (1 if registry_data else 0)
                self.signals.output.emit(f"<p style='color: #87CEEB;'>Enumeration complete: {total_findings} categories of information gathered</p><br>")
            
            # Run additional vulnerability tests for vulnerability scans
            if self.scan_type in ["Vulnerability Scan", "Complete Assessment"]:
                self._probe_vulnerability_paths(results)
                self._test_rpc_signing_sealing(results)
                self._scan_ntlm_relay_surface(results)
                self._analyze_print_spooler_attack_surface(results)
                self._audit_privileged_interfaces(results)
                self._enumerate_trust_relationships(results)
                self._test_service_creation_path(results)
                self._enhanced_os_fingerprinting(results)
                self._real_endpoint_mapper_scan(results)
                self._raw_lsa_sam_enumeration(results)
                self._dcom_uuid_scanning(results)
                # Skip problematic tests that cause server blocking
                self._advanced_rpc_discovery(results)
                # self._rpc_coercion_testing(results)
                # self._rpc_fuzzing_assessment(results)
            
            # Calculate risk score for target prioritization
            risk_score = self._calculate_risk_score(results)
            results['risk_score'] = risk_score
            self.signals.output.emit(f"<p style='color: #87CEEB;'>Target Risk Score: {risk_score}/100</p><br>")
            
            # Prepare structured data for graph and table views
            self._prepare_structured_data(results)
            
            return results
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF6B6B;'>Native RPC enumeration failed: {h(str(e))}</p><br>")
            return None
    
    def _prepare_structured_data(self, results):
        """Prepare structured data for graph and table views"""
        try:
            # RPC Endpoints Table Data
            rpc_endpoints = results.get('rpc_endpoints', [])
            if rpc_endpoints:
                results['table_data'] = {
                    'rpc_endpoints': [
                        {
                            'Protocol': endpoint.get('protocol', 'Unknown'),
                            'UUID': endpoint.get('uuid', 'N/A'),
                            'Port': endpoint.get('port', 'unknown'),
                            'Status': 'Active'
                        } for endpoint in rpc_endpoints
                    ]
                }
            
            # Services Table Data
            services = results.get('services', [])
            if services:
                running_services = [s for s in services if s.get('state', '').startswith('4')]
                stopped_services = [s for s in services if s.get('state', '').startswith('1')]
                
                results['table_data'] = results.get('table_data', {})
                results['table_data']['services'] = [
                    {
                        'Service Name': service.get('name', 'Unknown'),
                        'Display Name': service.get('display_name', ''),
                        'State': 'Running' if service.get('state', '').startswith('4') else 'Stopped',
                        'Type': service.get('type', 'Unknown')
                    } for service in services
                ]
                
                # Service statistics for graph
                results['graph_data'] = {
                    'service_stats': {
                        'Running': len(running_services),
                        'Stopped': len(stopped_services),
                        'Total': len(services)
                    }
                }
            
            # Network Endpoints Table Data
            endpoints = results.get('endpoints', [])
            if endpoints:
                results['table_data'] = results.get('table_data', {})
                results['table_data']['network_endpoints'] = [
                    {
                        'Port': endpoint.get('port', 'Unknown'),
                        'Protocol': endpoint.get('protocol', 'tcp'),
                        'Service': endpoint.get('service', 'Unknown'),
                        'Status': endpoint.get('status', 'open')
                    } for endpoint in endpoints
                ]
            
            # Registry Information Table Data
            registry_data = results.get('registry', {})
            if registry_data:
                os_info = registry_data.get('os_info', {})
                if os_info:
                    results['table_data'] = results.get('table_data', {})
                    results['table_data']['system_info'] = [
                        {
                            'Property': key,
                            'Value': value
                        } for key, value in os_info.items() if value
                    ]
            
            # Graph data for RPC endpoints by port
            if rpc_endpoints:
                port_counts = {}
                for endpoint in rpc_endpoints:
                    port = str(endpoint.get('port', 'unknown'))
                    port_counts[port] = port_counts.get(port, 0) + 1
                
                results['graph_data'] = results.get('graph_data', {})
                results['graph_data']['rpc_ports'] = port_counts
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>Warning: Failed to prepare structured data: {h(str(e))}</p><br>")
    
    def _test_windows_auth(self, target_ip: str, domain: str, username: str, password: str) -> bool:
        """Test Windows authentication before RPC enumeration"""
        try:
            # Try multiple authentication methods using IP address
            user_format = f'{domain}\\{username}' if domain else username
            auth_methods = [
                ['net', 'use', f'\\\\{target_ip}\\IPC$', password, f'/user:{user_format}'],
                ['net', 'use', f'\\\\{target_ip}\\IPC$', f'/user:{user_format}', password],
            ]
            
            for i, cmd in enumerate(auth_methods):
                try:
                    self.signals.output.emit(f"<p style='color: #87CEEB;'>Auth method {h(i+1)}: {' '.join(cmd[:3])} [credentials]</p><br>")
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
                    
                    if result.returncode == 0:
                        self.signals.output.emit(f"<p style='color: #00FF41;'>Authentication successful with method {h(i+1)}</p><br>")
                        # Clean up the connection
                        try:
                            subprocess.run(['net', 'use', f'\\\\{target_ip}\\IPC$', '/delete'], capture_output=True, timeout=2)
                        except Exception as _exc:
                            pass
                            logging.debug("Suppressed exception", exc_info=True)
                        return True
                    else:
                        self.signals.output.emit(f"<p style='color: #FFAA00;'>Method {h(i+1)} failed: {h(result.stderr.strip())}</p><br>")
                except Exception as e:
                    self.signals.output.emit(f"<p style='color: #FFAA00;'>Method {h(i+1)} error: {h(str(e))}</p><br>")
            
            # Try reg query as alternative test
            try:
                self.signals.output.emit(f"<p style='color: #87CEEB;'>Testing with reg query...</p><br>")
                cmd = ['reg', 'query', f'\\\\{target_ip}\\HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion', '/v', 'ProductName']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                
                if result.returncode == 0 and 'ProductName' in result.stdout:
                    self.signals.output.emit(f"<p style='color: #00FF41;'>Registry access successful - authentication working</p><br>")
                    return True
                else:
                    self.signals.output.emit(f"<p style='color: #FFAA00;'>Registry access failed: {h(result.stderr.strip())}</p><br>")
            except Exception as e:
                self.signals.output.emit(f"<p style='color: #FFAA00;'>Registry test error: {h(str(e))}</p><br>")
            
            return False
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF6B6B;'>Authentication test failed: {h(str(e))}</p><br>")
            return False
    
    def _test_rpc_signing_sealing(self, results):
        """Test RPC signing and sealing enforcement"""
        try:
            self.signals.output.emit("<p style='color: #FFD700;'>Testing RPC signing/sealing enforcement...</p><br>")
            
            signing_issues = []
            
            # Test critical RPC interfaces for signing enforcement
            critical_interfaces = [
                ('svcctl', 'Service Control Manager'),
                ('winreg', 'Remote Registry'),
                ('samr', 'Security Account Manager'),
                ('lsarpc', 'Local Security Authority'),
                ('eventlog', 'Event Log Service')
            ]
            
            for interface, description in critical_interfaces:
                if self._test_unsigned_rpc_access(interface):
                    issue = {
                        'interface': interface,
                        'description': description,
                        'severity': 'High',
                        'issue': 'Accepts unsigned RPC calls',
                        'risk': 'MITM and relay attacks possible'
                    }
                    signing_issues.append(issue)
                    self.signals.output.emit(f"<p style='color: #FFA500;'>⚠️ HIGH: {h(description)} ({h(interface)}) accepts unsigned RPC</p><br>")
                    
                    # Add to vulnerability database
                    if self.vuln_collector:
                        self.vuln_collector.add_rpc_signing_issue(
                            interface=interface,
                            description=f"{description} accepts unsigned RPC calls - MITM and relay attacks possible"
                        )
            
            results['rpc_signing_issues'] = signing_issues
            
            if signing_issues:
                self.signals.output.emit(f"<p style='color: #FF6B6B;'>Found {len(signing_issues)} RPC signing/sealing issues</p><br>")
            else:
                self.signals.output.emit(f"<p style='color: #00FF41;'>RPC signing/sealing properly enforced</p><br>")
                
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>RPC signing test failed: {h(str(e))}</p><br>")
    
    def _test_unsigned_rpc_access(self, interface):
        """Test if RPC interface accepts unsigned calls"""
        try:
            # Test different interface access methods
            if interface == 'svcctl':
                # Try to query services without authentication
                cmd = ["sc", f"\\\\{self.target}", "query", "state=", "all"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                return result.returncode == 0
            
            elif interface == 'winreg':
                # Try registry access without authentication
                cmd = ["reg", "query", f"\\\\{self.target}\\HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "/v", "ProductName"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                return result.returncode == 0 and "ProductName" in result.stdout
            
            elif interface == 'eventlog':
                # Try to access event log service
                cmd = ["wevtutil", "el", f"/r:{self.target}"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                return result.returncode == 0
            
            # For samr and lsarpc, these typically require authentication
            # but we can test if they're accessible with null sessions
            elif interface in ['samr', 'lsarpc']:
                # Test null session access
                cmd = ["net", "use", f"\\\\{self.target}\\IPC$", "", "/user:"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    # Clean up null session
                    subprocess.run(["net", "use", f"\\\\{self.target}\\IPC$", "/delete"], capture_output=True, timeout=2)
                    return True
            
            return False
            
        except Exception:
            return False
    
    def _scan_ntlm_relay_surface(self, results):
        """Scan for NTLM relay attack surface"""
        try:
            self.signals.output.emit("<p style='color: #FFD700;'>Scanning NTLM relay attack surface...</p><br>")
            
            relay_vectors = []
            
            # Check for relay-vulnerable RPC interfaces
            relay_interfaces = [
                ('spoolss', 'Print Spooler', 'PrinterBug/SpoolSample'),
                ('efsr', 'Encrypting File System', 'PetitPotam'),
                ('dfsnm', 'DFS Namespace Management', 'DFSCoerce'),
                ('eventlog', 'Event Log Service', 'EventLogCoerce'),
                ('lsarpc', 'LSA RPC', 'LSA Coercion'),
                ('samr', 'Security Account Manager', 'SAMR Coercion')
            ]
            
            for interface, description, attack_method in relay_interfaces:
                if self._test_relay_interface(interface):
                    vector = {
                        'interface': interface,
                        'description': description,
                        'attack_method': attack_method,
                        'severity': 'Critical' if interface in ['spoolss', 'efsr'] else 'High',
                        'transport': self._detect_interface_transport(interface)
                    }
                    relay_vectors.append(vector)
                    
                    severity_color = '#FF0000' if vector['severity'] == 'Critical' else '#FFA500'
                    self.signals.output.emit(f"<p style='color: {severity_color};'>⚠️ {h(vector['severity'].upper())}: {h(description)} relay vector ({h(attack_method)})</p><br>")
                    
                    # Add to vulnerability database
                    if self.vuln_collector:
                        self.vuln_collector.add_ntlm_relay_vector(
                            interface=interface,
                            attack_method=attack_method,
                            severity=vector['severity']
                        )
            
            results['ntlm_relay_vectors'] = relay_vectors
            
            if relay_vectors:
                critical_count = len([v for v in relay_vectors if v['severity'] == 'Critical'])
                high_count = len([v for v in relay_vectors if v['severity'] == 'High'])
                self.signals.output.emit(f"<p style='color: #FF6B6B;'>NTLM relay surface: {critical_count} Critical, {high_count} High severity vectors</p><br>")
            else:
                self.signals.output.emit(f"<p style='color: #00FF41;'>No obvious NTLM relay vectors detected</p><br>")
                
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>NTLM relay scan failed: {h(str(e))}</p><br>")
    
    def _test_relay_interface(self, interface):
        """Test if interface is accessible for relay attacks"""
        try:
            if interface == 'spoolss':
                # Test both TCP and named pipe access
                tcp_test = self._check_spoolss_interface()
                pipe_test = self._test_named_pipe_access('spoolss')
                return tcp_test or pipe_test
            
            elif interface == 'efsr':
                # Test EFS RPC interface
                return self._test_named_pipe_access('efsrpc')
            
            elif interface == 'dfsnm':
                # Test DFS namespace management
                return self._test_named_pipe_access('netdfs')
            
            elif interface == 'eventlog':
                # Test event log service
                cmd = ["wevtutil", "el", f"/r:{self.target}"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                return result.returncode == 0
            
            elif interface == 'lsarpc':
                return self._check_lsarpc_interface()
            
            elif interface == 'samr':
                # Test SAMR interface access
                cmd = ["net", "user", f"/domain:{self.target}"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                return result.returncode == 0
            
            return False
            
        except Exception:
            return False
    
    def _test_named_pipe_access(self, pipe_name):
        """Test access to named pipe"""
        try:
            # Try to connect to named pipe
            import os
            pipe_path = f"\\\\{self.target}\\pipe\\{pipe_name}"
            
            # Use dir command to test pipe existence
            cmd = ["dir", pipe_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            
            # Named pipes typically return "Access is denied" rather than "not found"
            return "Access is denied" in result.stderr or result.returncode == 0
            
        except Exception:
            return False
    
    def _detect_interface_transport(self, interface):
        """Detect transport method for RPC interface"""
        transports = []
        
        # Test TCP transport (port 135/445)
        if self._test_tcp_rpc_access(interface):
            transports.append('TCP')
        
        # Test named pipe transport
        pipe_names = {
            'spoolss': 'spoolss',
            'efsr': 'efsrpc', 
            'dfsnm': 'netdfs',
            'lsarpc': 'lsarpc',
            'samr': 'samr'
        }
        
        if interface in pipe_names and self._test_named_pipe_access(pipe_names[interface]):
            transports.append('Named Pipe')
        
        return ', '.join(transports) if transports else 'Unknown'
    
    def _test_tcp_rpc_access(self, interface):
        """Test TCP-based RPC access"""
        try:
            # Test if RPC endpoint mapper is accessible
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((self._resolve_target(self.target), 135))
            sock.close()
            return result == 0
        except:
            return False
    
    def _check_spoolss_named_pipe(self):
        """Check if Print Spooler is accessible via named pipe"""
        try:
            # Test spoolss named pipe access
            pipe_accessible = self._test_named_pipe_access('spoolss')
            if pipe_accessible:
                # Try to enumerate printers via named pipe
                cmd = ["wmic", f"/node:{self.target}", "printer", "list", "brief"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                return result.returncode == 0 or "Access is denied" in result.stderr
            return False
        except:
            return False
    
    def _analyze_print_spooler_attack_surface(self, results):
        """Analyze Print Spooler attack surface across transports"""
        try:
            self.signals.output.emit("<p style='color: #FFD700;'>Analyzing Print Spooler attack surface...</p><br>")
            
            tcp_accessible = self._check_spoolss_interface()
            pipe_accessible = self._check_spoolss_named_pipe()
            
            spooler_analysis = {
                'tcp_accessible': tcp_accessible,
                'pipe_accessible': pipe_accessible,
                'attack_vectors': []
            }
            
            if tcp_accessible and pipe_accessible:
                spooler_analysis['attack_vectors'].append({
                    'vector': 'PrintNightmare (CVE-2021-1675)',
                    'transport': 'TCP + Named Pipe',
                    'severity': 'Critical',
                    'description': 'Print Spooler accessible via both TCP and named pipe'
                })
                self.signals.output.emit(f"<p style='color: #FF0000;'>🚨 CRITICAL: Print Spooler accessible via TCP AND named pipe</p><br>")
                
            elif pipe_accessible and not tcp_accessible:
                spooler_analysis['attack_vectors'].append({
                    'vector': 'PrintNightmare Bypass',
                    'transport': 'Named Pipe Only',
                    'severity': 'Critical',
                    'description': 'Print Spooler patched on TCP but vulnerable via named pipe'
                })
                self.signals.output.emit(f"<p style='color: #FF0000;'>🚨 CRITICAL: Print Spooler TCP patched but named pipe VULNERABLE</p><br>")
                
            elif tcp_accessible and not pipe_accessible:
                spooler_analysis['attack_vectors'].append({
                    'vector': 'PrintNightmare (CVE-2021-1675)',
                    'transport': 'TCP Only',
                    'severity': 'Critical',
                    'description': 'Print Spooler accessible via TCP'
                })
                self.signals.output.emit(f"<p style='color: #FF0000;'>🚨 CRITICAL: Print Spooler accessible via TCP</p><br>")
                
            else:
                self.signals.output.emit(f"<p style='color: #00FF41;'>✅ Print Spooler properly secured on both TCP and named pipe</p><br>")
            
            # Test for PrinterBug/SpoolSample vectors
            if pipe_accessible or tcp_accessible:
                spooler_analysis['attack_vectors'].append({
                    'vector': 'PrinterBug/SpoolSample',
                    'transport': 'Named Pipe' if pipe_accessible else 'TCP',
                    'severity': 'High',
                    'description': 'Coercion attacks possible via Print Spooler'
                })
                self.signals.output.emit(f"<p style='color: #FFA500;'>⚠️ HIGH: PrinterBug/SpoolSample coercion possible</p><br>")
            
            results['print_spooler_analysis'] = spooler_analysis
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>Print Spooler analysis failed: {h(str(e))}</p><br>")
    
    def _check_spoolss_interface(self):
        """Check if Print Spooler service (spoolss) is accessible via TCP"""
        try:
            # Check if spoolss service is running
            cmd = ["sc", f"\\\\{self.target}", "query", "spooler"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0 and "RUNNING" in result.stdout:
                return True
            return False
        except:
            return False
    
    def _resolve_target(self, target: str) -> str:
        """Resolve hostname to IP using configured DNS server"""
        try:
            # Check if target is already an IP address
            socket.inet_aton(target)
            return target  # Already an IP
        except socket.error as _exc:
            pass
            logging.debug("Suppressed exception", exc_info=True)
        
        try:
            # Get current DNS configuration
            current_dns = dns_settings.get_current_dns()
            
            if current_dns == "LocalDNS":
                # Use local DNS server
                local_dns_port = getattr(dns_settings, 'local_dns_port', 53530)
                self.signals.output.emit(f"<p style='color: #87CEEB;'>Using LocalDNS server on port {h(local_dns_port)}</p><br>")
                
                # Try to resolve using local DNS
                resolved_ip = self._query_local_dns(target, local_dns_port)
                if resolved_ip:
                    self.signals.output.emit(f"<p style='color: #00FF41;'>Resolved {h(target)} -> {h(resolved_ip)} via LocalDNS</p><br>")
                    return resolved_ip
                else:
                    self.signals.output.emit(f"<p style='color: #FFAA00;'>LocalDNS resolution failed, trying system DNS</p><br>")
            elif current_dns != "Default DNS":
                # Use specific DNS server IP
                resolved_ip = self._query_dns_server(target, current_dns)
                if resolved_ip:
                    self.signals.output.emit(f"<p style='color: #00FF41;'>Resolved {h(target)} -> {h(resolved_ip)} via DNS server {h(current_dns)}</p><br>")
                    return resolved_ip
                else:
                    self.signals.output.emit(f"<p style='color: #FFAA00;'>DNS server query failed, trying system DNS</p><br>")
            
            # Fallback to system DNS resolution
            resolved_ip = socket.gethostbyname(target)
            self.signals.output.emit(f"<p style='color: #00FF41;'>Resolved {h(target)} -> {h(resolved_ip)} via system DNS</p><br>")
            return resolved_ip
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>DNS resolution failed: {h(str(e))}, using original target</p><br>")
            return target
    
    def _query_local_dns(self, hostname: str, dns_port: int) -> str:
        """Query local DNS server for hostname resolution"""
        try:
            import struct
            
            # Create DNS query packet
            query_id = 0x1234
            flags = 0x0100  # Standard query
            questions = 1
            
            # DNS header
            header = struct.pack('>HHHHHH', query_id, flags, questions, 0, 0, 0)
            
            # DNS question
            question = b''
            for part in hostname.split('.'):
                question += struct.pack('B', len(part)) + part.encode()
            question += b'\x00'  # End of name
            question += struct.pack('>HH', 1, 1)  # Type A, Class IN
            
            dns_query = header + question
            
            # Send query to local DNS server
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(dns_query, ('127.0.0.1', dns_port))
            
            response, _ = sock.recvfrom(512)
            sock.close()
            
            # Parse response (simplified)
            if len(response) > 12:
                # Skip header and question, look for answer
                # This is a simplified parser - full DNS parsing would be more complex
                offset = len(dns_query)
                if offset < len(response) - 4:
                    # Extract IP from answer section (simplified)
                    ip_bytes = response[-4:]
                    if len(ip_bytes) == 4:
                        ip = '.'.join(str(b) for b in ip_bytes)
                        return ip
            
            return None
            
        except Exception:
            return None
    
    def _query_dns_server(self, hostname: str, dns_server: str) -> str:
        """Query specific DNS server"""
        try:
            import struct
            
            # Create DNS query packet
            query_id = 0x1234
            flags = 0x0100
            questions = 1
            
            header = struct.pack('>HHHHHH', query_id, flags, questions, 0, 0, 0)
            
            question = b''
            for part in hostname.split('.'):
                question += struct.pack('B', len(part)) + part.encode()
            question += b'\x00'
            question += struct.pack('>HH', 1, 1)
            
            dns_query = header + question
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(dns_query, (dns_server, 53))
            
            response, _ = sock.recvfrom(512)
            sock.close()
            
            # Parse response - handle multiple A records
            if len(response) > 12:
                # Parse DNS response properly to get all A records
                pos = 12  # Skip header
                
                # Skip question section
                while pos < len(response):
                    length = response[pos]
                    if length == 0:
                        pos += 5  # Skip null terminator + type + class
                        break
                    pos += length + 1
                
                # Parse answer section
                ips = []
                while pos + 12 < len(response):
                    # Skip name (2 bytes compression pointer)
                    pos += 2
                    # Read type, class, ttl, data length
                    rr_type, rr_class, ttl, data_len = struct.unpack('>HHIH', response[pos:pos+10])
                    pos += 10
                    
                    if rr_type == 1 and data_len == 4:  # A record
                        ip_bytes = response[pos:pos+4]
                        ip = '.'.join(str(b) for b in ip_bytes)
                        ips.append(ip)
                    
                    pos += data_len
                
                # Prefer IP in 192.168.1.x subnet
                for ip in ips:
                    if ip.startswith('192.168.1.'):
                        return ip
                
                # Return first IP if no preferred subnet match
                if ips:
                    return ips[0]
            
            return None
        except:
            return None
    
    def _extract_secrets(self, results):
        """Extract secrets with privilege confirmation"""
        try:
            self.signals.output.emit("\n<p style='color: #FFD700;'>⚠️ Attempting privileged secrets extraction...</p><br>")
            
            # Use the domain field directly
            domain = self.domain or ""
            username = self.username
            
            # Only extract domain from username if no domain field provided
            if not domain:
                if '\\' in username:
                    domain, username = username.split('\\', 1)
                elif '@' in username:
                    username, domain = username.split('@', 1)
            
            # Use the secrets extractor with proper credentials
            success = self.secrets_extractor.extract_secrets(
                self.target, username, self.password, domain=domain,
                extract_sam=True, extract_lsa=True, extract_cached=True
            )
            
            if success:
                self.signals.output.emit(f"<p style='color: #00FF41;'>Secrets extraction completed successfully</p><br>")
                results['secrets_extracted'] = True
            else:
                self.signals.output.emit(f"<p style='color: #FFAA00;'>Secrets extraction failed or returned no results</p><br>")
                results['secrets_extracted'] = False
            
            # Note: Error handling is done within the secrets extractor itself
                    
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF6B6B;'>Secrets extraction failed: {h(str(e))}</p><br>")
    
    def _probe_vulnerability_paths(self, results):
        """Probe for known RPC-based vulnerability paths"""
        try:
            self.signals.output.emit("<p style='color: #FFD700;'>Probing for RPC vulnerability paths...</p><br>")
            
            vulnerabilities = []
            
            # Check for PrintNightmare (CVE-2021-1675) - spoolss interface
            if self._check_spoolss_interface():
                vuln = {
                    'name': 'PrintNightmare (CVE-2021-1675)',
                    'interface': 'spoolss',
                    'severity': 'Critical',
                    'description': 'Print Spooler service vulnerable to privilege escalation',
                    'port': 445
                }
                vulnerabilities.append(vuln)
                self.signals.output.emit(f"<p style='color: #FF6B6B;'>⚠️ CRITICAL: {h(vuln['name'])} - {h(vuln['description'])}</p><br>")
                
                # Add to vulnerability database
                if self.vuln_collector:
                    self.vuln_collector.add_rpc_vulnerability(
                        name="PrintNightmare (CVE-2021-1675)",
                        severity="Critical",
                        description="Print Spooler service vulnerable to privilege escalation",
                        cve_id="CVE-2021-1675",
                        evidence="Print Spooler service (spoolss) is accessible and vulnerable",
                        remediation="Apply security updates, disable Print Spooler if not needed"
                    )
            
            # Check for PetitPotam (CVE-2021-36942) - lsarpc/efsr interface
            if self._check_lsarpc_interface():
                vuln = {
                    'name': 'PetitPotam (CVE-2021-36942)',
                    'interface': 'lsarpc/efsr',
                    'severity': 'High',
                    'description': 'NTLM relay attack vector via LSA RPC calls',
                    'port': 445
                }
                vulnerabilities.append(vuln)
                self.signals.output.emit(f"<p style='color: #FFA500;'>⚠️ HIGH: {h(vuln['name'])} - {h(vuln['description'])}</p><br>")
                
                # Add to vulnerability database
                if self.vuln_collector:
                    self.vuln_collector.add_rpc_vulnerability(
                        name="PetitPotam (CVE-2021-36942)",
                        severity="High",
                        description="NTLM relay attack vector via LSA RPC calls",
                        cve_id="CVE-2021-36942",
                        evidence="LSA RPC interface accessible for coercion attacks",
                        remediation="Apply security updates, enable EPA for LDAP"
                    )
            
            # Check for Service Control abuse - svcctl interface
            if self._check_svcctl_interface():
                vuln = {
                    'name': 'Service Control Interface Abuse',
                    'interface': 'svcctl',
                    'severity': 'Medium',
                    'description': 'Service control interface may allow unauthorized service manipulation',
                    'port': 445
                }
                vulnerabilities.append(vuln)
                self.signals.output.emit(f"<p style='color: #FFFF00;'>⚠️ MEDIUM: {h(vuln['name'])} - {h(vuln['description'])}</p><br>")
            
            # Check for Registry manipulation - winreg interface
            if self._check_winreg_interface():
                vuln = {
                    'name': 'Remote Registry Access',
                    'interface': 'winreg',
                    'severity': 'Medium',
                    'description': 'Remote registry access may expose sensitive configuration',
                    'port': 445
                }
                vulnerabilities.append(vuln)
                self.signals.output.emit(f"<p style='color: #FFFF00;'>⚠️ MEDIUM: {h(vuln['name'])} - {h(vuln['description'])}</p><br>")
            
            results['vulnerabilities'] = vulnerabilities
            
            if vulnerabilities:
                critical_count = len([v for v in vulnerabilities if v['severity'] == 'Critical'])
                high_count = len([v for v in vulnerabilities if v['severity'] == 'High'])
                medium_count = len([v for v in vulnerabilities if v['severity'] == 'Medium'])
                
                self.signals.output.emit(f"<p style='color: #FF6B6B;'>Vulnerability summary: {critical_count} Critical, {high_count} High, {medium_count} Medium</p><br>")
            else:
                self.signals.output.emit(f"<p style='color: #00FF41;'>No obvious RPC vulnerability paths detected</p><br>")
                
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>Vulnerability probing failed: {h(str(e))}</p><br>")
    

    
    def _check_lsarpc_interface(self):
        """Check if LSA RPC interface is accessible"""
        try:
            # Try to access LSA policy
            cmd = ["net", "use", f"\\\\{self.target}\\IPC$"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except:
            return False
    
    def _check_svcctl_interface(self):
        """Check if Service Control Manager is accessible"""
        try:
            # Try to query services
            cmd = ["sc", f"\\\\{self.target}", "query", "state=", "all"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except:
            return False
    
    def _check_winreg_interface(self):
        """Check if remote registry is accessible"""
        try:
            # Try to access remote registry
            cmd = ["reg", "query", f"\\\\{self.target}\\HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "/v", "ProductName"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.returncode == 0 and "ProductName" in result.stdout
        except:
            return False
    
    def _audit_privileged_interfaces(self, results):
        """Audit access to privileged RPC interfaces"""
        try:
            self.signals.output.emit("<p style='color: #FFD700;'>Auditing privileged interface access...</p><br>")
            
            privilege_issues = []
            
            # Test SAMR interface access (should require admin)
            if self._test_samr_access():
                issue = {
                    'interface': 'SAMR',
                    'description': 'Security Account Manager RPC',
                    'severity': 'High',
                    'issue': 'Non-admin access to user enumeration',
                    'risk': 'User enumeration and password policy disclosure'
                }
                privilege_issues.append(issue)
                self.signals.output.emit(f"<p style='color: #FFA500;'>⚠️ HIGH: SAMR interface accessible - user enumeration possible</p><br>")
            
            # Test LSA RPC access (should require admin)
            if self._test_lsa_access():
                issue = {
                    'interface': 'LSARPC',
                    'description': 'Local Security Authority RPC',
                    'severity': 'Critical',
                    'issue': 'Non-admin access to LSA secrets',
                    'risk': 'Domain trust enumeration and policy access'
                }
                privilege_issues.append(issue)
                self.signals.output.emit(f"<p style='color: #FF0000;'>🚨 CRITICAL: LSARPC interface accessible - domain secrets at risk</p><br>")
            
            # Test Service Control Manager access
            if self._test_svcctl_privileged_access():
                issue = {
                    'interface': 'SVCCTL',
                    'description': 'Service Control Manager',
                    'severity': 'Critical',
                    'issue': 'Service creation/modification possible',
                    'risk': 'Privilege escalation via service manipulation'
                }
                privilege_issues.append(issue)
                self.signals.output.emit(f"<p style='color: #FF0000;'>🚨 CRITICAL: Service Control Manager - service creation possible</p><br>")
            
            results['privilege_audit'] = privilege_issues
            
            if privilege_issues:
                critical_count = len([i for i in privilege_issues if i['severity'] == 'Critical'])
                high_count = len([i for i in privilege_issues if i['severity'] == 'High'])
                self.signals.output.emit(f"<p style='color: #FF6B6B;'>Privilege audit: {critical_count} Critical, {high_count} High privilege issues</p><br>")
            else:
                self.signals.output.emit(f"<p style='color: #00FF41;'>✅ Privileged interfaces properly restricted</p><br>")
                
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>Privilege audit failed: {h(str(e))}</p><br>")
    
    def _test_samr_access(self):
        """Test SAMR interface access for user enumeration"""
        try:
            cmd = ["net", "user", f"/domain:{self.target}"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return result.returncode == 0 and "User accounts for" in result.stdout
        except:
            return False
    
    def _test_lsa_access(self):
        """Test LSA RPC access for policy enumeration"""
        try:
            cmd = ["nltest", f"/server:{self.target}", "/domain_trusts"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def _test_svcctl_privileged_access(self):
        """Test if service creation is possible"""
        try:
            test_service = f"HuginnTest{hash(self.target) % 10000}"
            cmd = ["sc", f"\\\\{self.target}", "create", test_service, "binPath=", "C:\\Windows\\System32\\calc.exe", "start=", "disabled"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                subprocess.run(["sc", f"\\\\{self.target}", "delete", test_service], capture_output=True, timeout=3)
                return True
            return False
        except:
            return False
    
    def _enumerate_trust_relationships(self, results):
        """Enumerate domain trust relationships"""
        try:
            self.signals.output.emit("<p style='color: #FFD700;'>Enumerating domain trust relationships...</p><br>")
            
            trust_data = {
                'domain_trusts': [],
                'forest_trusts': [],
                'trust_risks': []
            }
            
            # Enumerate domain trusts
            domain_trusts = self._get_domain_trusts()
            if domain_trusts:
                trust_data['domain_trusts'] = domain_trusts
                self.signals.output.emit(f"<p style='color: #00FF41;'>Found {len(domain_trusts)} domain trust(s):</p><br>")
                
                for trust in domain_trusts:
                    trust_type = trust.get('type', 'Unknown')
                    trust_direction = trust.get('direction', 'Unknown')
                    trusted_domain = trust.get('domain', 'Unknown')
                    
                    # Assess trust risk
                    risk_level = self._assess_trust_risk(trust)
                    color = '#FF0000' if risk_level == 'Critical' else '#FFA500' if risk_level == 'High' else '#FFFF00'
                    
                    self.signals.output.emit(f"<p style='color: {color};'>• {h(trusted_domain)} ({h(trust_type)}, {h(trust_direction)}) - Risk: {risk_level}</p><br>")
                    
                    if risk_level in ['Critical', 'High']:
                        trust_data['trust_risks'].append({
                            'domain': trusted_domain,
                            'type': trust_type,
                            'direction': trust_direction,
                            'risk': risk_level,
                            'reason': self._get_trust_risk_reason(trust)
                        })
            
            # Enumerate forest trusts
            forest_trusts = self._get_forest_trusts()
            if forest_trusts:
                trust_data['forest_trusts'] = forest_trusts
                self.signals.output.emit(f"<p style='color: #87CEEB;'>Found {len(forest_trusts)} forest trust(s)</p><br>")
            
            results['trust_relationships'] = trust_data
            
            # Summary
            total_risks = len(trust_data['trust_risks'])
            if total_risks > 0:
                self.signals.output.emit(f"<p style='color: #FF6B6B;'>Trust analysis: {total_risks} high-risk trust relationship(s) identified</p><br>")
            else:
                self.signals.output.emit(f"<p style='color: #00FF41;'>✅ No high-risk trust relationships detected</p><br>")
                
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>Trust enumeration failed: {h(str(e))}</p><br>")
    
    def _get_domain_trusts(self):
        """Get domain trust information"""
        try:
            # Use nltest to enumerate domain trusts
            cmd = ["nltest", f"/server:{self.target}", "/domain_trusts"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                return []
            
            trusts = []
            lines = result.stdout.split('\n')
            
            for line in lines:
                line = line.strip()
                if 'Domain:' in line and 'Flags:' in line:
                    # Parse trust information
                    domain_match = re.search(r'Domain:\s*(\S+)', line)
                    flags_match = re.search(r'Flags:\s*0x([0-9A-Fa-f]+)', line)
                    
                    if domain_match and flags_match:
                        domain = domain_match.group(1)
                        flags = int(flags_match.group(1), 16)
                        
                        trust = {
                            'domain': domain,
                            'flags': flags,
                            'type': self._parse_trust_type(flags),
                            'direction': self._parse_trust_direction(flags),
                            'attributes': self._parse_trust_attributes(flags)
                        }
                        trusts.append(trust)
            
            return trusts
            
        except Exception:
            return []
    
    def _get_forest_trusts(self):
        """Get forest trust information"""
        try:
            # Use nltest to enumerate forest trusts
            cmd = ["nltest", f"/server:{self.target}", "/trusted_domains"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                return []
            
            forest_trusts = []
            lines = result.stdout.split('\n')
            
            for line in lines:
                line = line.strip()
                if line and not line.startswith('The command completed'):
                    forest_trusts.append({'domain': line})
            
            return forest_trusts
            
        except Exception:
            return []
    
    def _parse_trust_type(self, flags):
        """Parse trust type from flags"""
        if flags & 0x00000001:  # TRUST_TYPE_DOWNLEVEL
            return "NT4/Downlevel"
        elif flags & 0x00000002:  # TRUST_TYPE_UPLEVEL  
            return "Active Directory"
        elif flags & 0x00000008:  # TRUST_TYPE_FOREST
            return "Forest"
        else:
            return "Unknown"
    
    def _parse_trust_direction(self, flags):
        """Parse trust direction from flags"""
        if flags & 0x00000001 and flags & 0x00000002:
            return "Bidirectional"
        elif flags & 0x00000001:
            return "Outbound"
        elif flags & 0x00000002:
            return "Inbound"
        else:
            return "Unknown"
    
    def _parse_trust_attributes(self, flags):
        """Parse trust attributes from flags"""
        attributes = []
        if flags & 0x00000020:  # TRUST_ATTRIBUTE_WITHIN_FOREST
            attributes.append("Within Forest")
        if flags & 0x00000040:  # TRUST_ATTRIBUTE_FOREST_TRANSITIVE
            attributes.append("Forest Transitive")
        if flags & 0x00000200:  # TRUST_ATTRIBUTE_CROSS_ORGANIZATION
            attributes.append("Cross Organization")
        return attributes
    
    def _assess_trust_risk(self, trust):
        """Assess risk level of trust relationship"""
        flags = trust.get('flags', 0)
        trust_type = trust.get('type', '')
        direction = trust.get('direction', '')
        
        # Forest trusts are generally higher risk
        if 'Forest' in trust_type:
            return 'Critical'
        
        # Bidirectional trusts allow lateral movement both ways
        if direction == 'Bidirectional':
            return 'High'
        
        # Outbound trusts allow privilege escalation
        if direction == 'Outbound':
            return 'High'
        
        # Cross-organization trusts are risky
        if flags & 0x00000200:  # TRUST_ATTRIBUTE_CROSS_ORGANIZATION
            return 'Critical'
        
        return 'Medium'
    
    def _get_trust_risk_reason(self, trust):
        """Get reason for trust risk assessment"""
        trust_type = trust.get('type', '')
        direction = trust.get('direction', '')
        flags = trust.get('flags', 0)
        
        if 'Forest' in trust_type:
            return "Forest trust allows cross-forest privilege escalation"
        elif direction == 'Bidirectional':
            return "Bidirectional trust enables lateral movement in both directions"
        elif direction == 'Outbound':
            return "Outbound trust may allow privilege escalation to trusted domain"
        elif flags & 0x00000200:
            return "Cross-organization trust spans security boundaries"
        else:
            return "Standard trust relationship"
    
    def _calculate_risk_score(self, results):
        """Calculate risk score (0-100) for target prioritization"""
        try:
            score = 0
            
            # Critical RPC interfaces exposed (+20 each)
            critical_interfaces = ['spoolss', 'lsarpc', 'samr', 'svcctl']
            rpc_endpoints = results.get('rpc_endpoints', [])
            for endpoint in rpc_endpoints:
                protocol = endpoint.get('protocol', '').lower()
                if any(critical in protocol for critical in critical_interfaces):
                    score += 20
            
            # Print Spooler analysis (+30 for critical findings)
            spooler_analysis = results.get('print_spooler_analysis', {})
            for vector in spooler_analysis.get('attack_vectors', []):
                if vector.get('severity') == 'Critical':
                    score += 30
                elif vector.get('severity') == 'High':
                    score += 15
            
            # NTLM relay vectors (+25 for critical, +15 for high)
            relay_vectors = results.get('ntlm_relay_vectors', [])
            for vector in relay_vectors:
                if vector.get('severity') == 'Critical':
                    score += 25
                elif vector.get('severity') == 'High':
                    score += 15
            
            # RPC signing issues (+20 each)
            signing_issues = results.get('rpc_signing_issues', [])
            score += len(signing_issues) * 20
            
            # Privilege audit issues (+25 for critical, +15 for high)
            privilege_issues = results.get('privilege_audit', [])
            for issue in privilege_issues:
                if issue.get('severity') == 'Critical':
                    score += 25
                elif issue.get('severity') == 'High':
                    score += 15
            
            # Trust relationship risks (+20 for critical, +10 for high)
            trust_risks = results.get('trust_relationships', {}).get('trust_risks', [])
            for risk in trust_risks:
                if risk.get('risk') == 'Critical':
                    score += 20
                elif risk.get('risk') == 'High':
                    score += 10
            
            # Anonymous RPC access (+15)
            if results.get('anonymous_access'):
                score += 15
            
            # Remote registry access (+10)
            if results.get('registry_access'):
                score += 10
            
            # Legacy ports (+5 each)
            endpoints = results.get('endpoints', [])
            legacy_ports = [139, 445, 135]
            for endpoint in endpoints:
                if endpoint.get('port') in legacy_ports:
                    score += 5
            
            # Vulnerable services (+10 each)
            vulnerable_services = results.get('vulnerable_services', [])
            score += len(vulnerable_services) * 10
            
            # Cap at 100
            return min(score, 100)
            
        except Exception:
            return 0
    
    def _test_service_creation_path(self, results):
        """Test service creation capabilities for privilege escalation paths"""
        try:
            self.signals.output.emit("<p style='color: #FFD700;'>Testing service creation exploit paths...</p><br>")
            
            service_exploit_paths = []
            
            # Test SC_MANAGER_ALL_ACCESS permissions
            sc_manager_access = self._test_sc_manager_permissions()
            if sc_manager_access:
                service_exploit_paths.append({
                    'method': 'Service Control Manager',
                    'access_level': sc_manager_access,
                    'severity': 'Critical',
                    'exploit_potential': 'PsExec-style service creation',
                    'description': 'Full service control permissions available'
                })
                self.signals.output.emit(f"<p style='color: #FF0000;'>🚨 CRITICAL: SC_MANAGER access level: {h(sc_manager_access)}</p><br>")
            
            # Test service modification permissions
            service_modify_access = self._test_service_modification()
            if service_modify_access:
                for service_info in service_modify_access:
                    service_exploit_paths.append({
                        'method': 'Service Modification',
                        'service': service_info['name'],
                        'permissions': service_info['permissions'],
                        'severity': 'High',
                        'exploit_potential': 'Service binary hijacking',
                        'description': f"Modify existing service: {service_info['name']}"
                    })
                    self.signals.output.emit(f"<p style='color: #FFA500;'>⚠️ HIGH: Service modification possible: {h(service_info['name'])}</p><br>")
            
            # Test unquoted service paths
            unquoted_services = self._find_unquoted_service_paths()
            if unquoted_services:
                for service in unquoted_services:
                    service_exploit_paths.append({
                        'method': 'Unquoted Service Path',
                        'service': service['name'],
                        'path': service['path'],
                        'severity': 'Medium',
                        'exploit_potential': 'DLL hijacking via unquoted paths',
                        'description': f"Unquoted path: {service['path']}"
                    })
                    self.signals.output.emit(f"<p style='color: #FFFF00;'>⚠️ MEDIUM: Unquoted service path: {h(service['name'])}</p><br>")
            
            # Test service binary permissions
            writable_binaries = self._test_service_binary_permissions()
            if writable_binaries:
                for binary in writable_binaries:
                    service_exploit_paths.append({
                        'method': 'Service Binary Overwrite',
                        'service': binary['service'],
                        'binary_path': binary['path'],
                        'severity': 'High',
                        'exploit_potential': 'Direct binary replacement',
                        'description': f"Writable service binary: {binary['path']}"
                    })
                    self.signals.output.emit(f"<p style='color: #FFA500;'>⚠️ HIGH: Writable service binary: {h(binary['service'])}</p><br>")
            
            results['service_exploit_paths'] = service_exploit_paths
            
            # Summary
            if service_exploit_paths:
                critical_count = len([p for p in service_exploit_paths if p['severity'] == 'Critical'])
                high_count = len([p for p in service_exploit_paths if p['severity'] == 'High'])
                medium_count = len([p for p in service_exploit_paths if p['severity'] == 'Medium'])
                
                self.signals.output.emit(f"<p style='color: #FF6B6B;'>Service exploit paths: {critical_count} Critical, {high_count} High, {medium_count} Medium</p><br>")
            else:
                self.signals.output.emit(f"<p style='color: #00FF41;'>✅ No obvious service-based privilege escalation paths</p><br>")
                
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>Service creation test failed: {h(str(e))}</p><br>")
    
    def _test_sc_manager_permissions(self):
        """Test Service Control Manager permissions"""
        try:
            # Test service creation (dry run)
            test_service = f"HuginnDryRun{hash(self.target) % 10000}"
            cmd = ["sc", f"\\\\{self.target}", "create", test_service, "binPath=", "C:\\Windows\\System32\\calc.exe", "start=", "disabled"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                # Immediately delete the test service
                subprocess.run(["sc", f"\\\\{self.target}", "delete", test_service], capture_output=True, timeout=3)
                return "SC_MANAGER_ALL_ACCESS"
            
            # Test service enumeration permissions
            cmd = ["sc", f"\\\\{self.target}", "query", "state=", "all"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                return "SC_MANAGER_ENUMERATE_SERVICE"
            
            return None
            
        except Exception:
            return None
    
    def _test_service_modification(self):
        """Test service modification permissions"""
        try:
            modifiable_services = []
            
            # Get list of services
            cmd = ["sc", f"\\\\{self.target}", "query", "state=", "all"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                return []
            
            # Parse service names
            service_names = []
            lines = result.stdout.split('\n')
            for line in lines:
                if line.strip().startswith('SERVICE_NAME:'):
                    service_name = line.split(':', 1)[1].strip()
                    service_names.append(service_name)
            
            # Test modification permissions on a few key services
            test_services = ['Spooler', 'BITS', 'Themes', 'Fax']  # Common targets
            
            for service in test_services:
                if service in service_names:
                    # Test service configuration query (indicates some access)
                    cmd = ["sc", f"\\\\{self.target}", "qc", service]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                    
                    if result.returncode == 0:
                        # Test if we can change service config (dry run)
                        cmd = ["sc", f"\\\\{self.target}", "config", service, "start=", "auto"]
                        test_result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                        
                        if test_result.returncode == 0:
                            # Revert the change immediately
                            subprocess.run(["sc", f"\\\\{self.target}", "config", service, "start=", "demand"], capture_output=True, timeout=3)
                            
                            modifiable_services.append({
                                'name': service,
                                'permissions': 'SERVICE_CHANGE_CONFIG'
                            })
            
            return modifiable_services
            
        except Exception:
            return []
    
    def _find_unquoted_service_paths(self):
        """Find services with unquoted paths containing spaces"""
        try:
            unquoted_services = []
            
            # Query service configurations
            cmd = ["wmic", f"/node:{self.target}", "service", "get", "name,pathname", "/format:csv"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode != 0:
                return []
            
            lines = result.stdout.split('\n')
            for line in lines[1:]:  # Skip header
                if line.strip() and ',' in line:
                    parts = line.split(',')
                    if len(parts) >= 3:
                        service_name = parts[1].strip()
                        path = parts[2].strip()
                        
                        # Check for unquoted paths with spaces
                        if path and ' ' in path and not (path.startswith('"') and path.endswith('"')):
                            # Exclude system paths that are typically safe
                            if not path.lower().startswith('c:\\windows\\system32'):
                                unquoted_services.append({
                                    'name': service_name,
                                    'path': path
                                })
            
            return unquoted_services
            
        except Exception:
            return []
    
    def _test_service_binary_permissions(self):
        """Test if service binaries are writable"""
        try:
            writable_binaries = []
            
            # Get a few service paths to test
            cmd = ["sc", f"\\\\{self.target}", "qc", "Spooler"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                # Parse binary path from sc output
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'BINARY_PATH_NAME' in line:
                        path_match = re.search(r'BINARY_PATH_NAME\s*:\s*(.+)', line)
                        if path_match:
                            binary_path = path_match.group(1).strip()
                            
                            # Test write access (dry run - just check permissions)
                            cmd = ["icacls", f"\\\\{self.target}\\{binary_path}"]
                            perm_result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                            
                            if perm_result.returncode == 0 and ('(F)' in perm_result.stdout or '(M)' in perm_result.stdout):
                                writable_binaries.append({
                                    'service': 'Spooler',
                                    'path': binary_path
                                })
            
            return writable_binaries
            
        except Exception:
            return []
    
    def _enhanced_os_fingerprinting(self, results):
        """Enhanced Windows version fingerprinting"""
        try:
            self.signals.output.emit("<p style='color: #FFD700;'>Performing enhanced OS fingerprinting...</p><br>")
            
            fingerprint_data = {
                'os_version': None,
                'build_number': None,
                'server_role': None,
                'smb_version': None,
                'rpc_version': None,
                'ttl_analysis': None,
                'confidence': 0
            }
            
            # Registry-based OS detection (most accurate)
            registry_os = self._get_registry_os_info()
            if registry_os:
                fingerprint_data.update(registry_os)
                fingerprint_data['confidence'] += 40
            
            # SMB dialect negotiation
            smb_info = self._detect_smb_version()
            if smb_info:
                fingerprint_data['smb_version'] = smb_info
                fingerprint_data['confidence'] += 20
            
            # RPC UUID version probing
            rpc_version = self._probe_rpc_version()
            if rpc_version:
                fingerprint_data['rpc_version'] = rpc_version
                fingerprint_data['confidence'] += 15
            
            # TTL-based OS inference
            ttl_info = self._analyze_ttl_fingerprint()
            if ttl_info:
                fingerprint_data['ttl_analysis'] = ttl_info
                fingerprint_data['confidence'] += 10
            
            # Server role detection
            server_role = self._detect_server_role(results)
            if server_role:
                fingerprint_data['server_role'] = server_role
                fingerprint_data['confidence'] += 15
            
            results['os_fingerprint'] = fingerprint_data
            
            # Display results
            if fingerprint_data['os_version']:
                confidence_color = '#00FF41' if fingerprint_data['confidence'] > 70 else '#FFFF00' if fingerprint_data['confidence'] > 40 else '#FFA500'
                self.signals.output.emit(f"<p style='color: {h(confidence_color)};'>OS Fingerprint: {h(fingerprint_data['os_version'])} (Confidence: {h(fingerprint_data['confidence'])}%)</p><br>")
                
                if fingerprint_data['server_role']:
                    self.signals.output.emit(f"<p style='color: #87CEEB;'>Server Role: {h(fingerprint_data['server_role'])}</p><br>")
                
                if fingerprint_data['smb_version']:
                    self.signals.output.emit(f"<p style='color: #87CEEB;'>SMB Version: {h(fingerprint_data['smb_version'])}</p><br>")
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>OS fingerprinting failed: {h(str(e))}</p><br>")
    
    def _get_registry_os_info(self):
        """Get detailed OS info from registry"""
        try:
            cmd = ["reg", "query", f"\\\\{self.target}\\HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                return None
            
            os_info = {}
            lines = result.stdout.split('\n')
            
            for line in lines:
                if 'ProductName' in line:
                    match = re.search(r'ProductName\s+REG_SZ\s+(.+)', line)
                    if match:
                        os_info['os_version'] = match.group(1).strip()
                
                elif 'CurrentBuild' in line:
                    match = re.search(r'CurrentBuild\s+REG_SZ\s+(.+)', line)
                    if match:
                        os_info['build_number'] = match.group(1).strip()
                
                elif 'InstallationType' in line:
                    match = re.search(r'InstallationType\s+REG_SZ\s+(.+)', line)
                    if match:
                        install_type = match.group(1).strip()
                        if install_type == 'Server Core':
                            os_info['server_core'] = True
            
            return os_info if os_info else None
            
        except Exception:
            return None
    
    def _detect_smb_version(self):
        """Detect SMB version through dialect negotiation"""
        try:
            import socket
            
            # Connect to SMB port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            target_ip = self._resolve_target(self.target)
            sock.connect((target_ip, 445))
            
            # SMB negotiate request for SMB2/3
            negotiate_req = (
                b"\\x00\\x00\\x00\\x54"  # NetBIOS header
                b"\\xfe\\x53\\x4d\\x42"  # SMB2 signature
                b"\\x40\\x00\\x00\\x00"  # Header
                b"\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"
                b"\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"
                b"\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"
                b"\\x00\\x00\\x00\\x00"
                b"\\x24\\x00\\x05\\x00\\x00\\x00\\x00\\x00"
                b"\\x7f\\x00\\x00\\x00\\x00\\x00\\x00\\x00"
                b"\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"
                b"\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"
                b"\\x02\\x02\\x10\\x02\\x00\\x03\\x02\\x03"
            )
            
            sock.send(negotiate_req)
            response = sock.recv(1024)
            sock.close()
            
            if len(response) > 70:
                # Parse SMB version from response
                if b"\\x02\\x02" in response:
                    return "SMB 2.0"
                elif b"\\x02\\x10" in response:
                    return "SMB 2.1"
                elif b"\\x03\\x00" in response:
                    return "SMB 3.0"
                elif b"\\x03\\x02" in response:
                    return "SMB 3.02"
                elif b"\\x03\\x11" in response:
                    return "SMB 3.11"
            
            return "SMB 1.0/2.x"
            
        except Exception:
            return None
    
    def _probe_rpc_version(self):
        """Probe RPC version through endpoint mapper"""
        try:
            import socket
            
            # Connect to RPC endpoint mapper
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            target_ip = self._resolve_target(self.target)
            sock.connect((target_ip, 135))
            
            # Simple RPC version probe
            rpc_probe = b"\\x05\\x00\\x0b\\x03\\x10\\x00\\x00\\x00\\x48\\x00\\x00\\x00"
            sock.send(rpc_probe)
            response = sock.recv(512)
            sock.close()
            
            if len(response) > 10:
                # Basic RPC version detection
                if response[0:2] == b"\\x05\\x00":
                    return "RPC 5.0"
            
            return "RPC Unknown"
            
        except Exception:
            return None
    
    def _analyze_ttl_fingerprint(self):
        """Analyze TTL for OS inference"""
        try:
            import subprocess
            import re
            
            # Ping target to get TTL
            cmd = ["ping", "-n", "1", self.target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                ttl_match = re.search(r'TTL=(\d+)', result.stdout)
                if ttl_match:
                    ttl = int(ttl_match.group(1))
                    
                    # TTL-based OS inference
                    if ttl <= 64:
                        return f"Linux/Unix-like (TTL: {ttl})"
                    elif ttl <= 128:
                        return f"Windows (TTL: {ttl})"
                    else:
                        return f"Unknown OS (TTL: {ttl})"
            
            return None
            
        except Exception:
            return None
    
    def _detect_server_role(self, results):
        """Detect Windows server role based on services"""
        try:
            services = results.get('services', [])
            running_services = [s.get('name', '').lower() for s in services if s.get('state', '').startswith('4')]
            
            roles = []
            
            # Domain Controller
            if 'ntds' in running_services and 'kdc' in running_services:
                roles.append('Domain Controller')
            
            # DNS Server
            if 'dns' in running_services:
                roles.append('DNS Server')
            
            # DHCP Server
            if 'dhcpserver' in running_services:
                roles.append('DHCP Server')
            
            # File Server
            if 'lanmanserver' in running_services and 'dfs' in running_services:
                roles.append('File Server')
            
            # Print Server
            if 'spooler' in running_services:
                roles.append('Print Server')
            
            # Web Server (IIS)
            if 'w3svc' in running_services or 'iisadmin' in running_services:
                roles.append('Web Server (IIS)')
            
            # SQL Server
            if any('sql' in svc for svc in running_services):
                roles.append('SQL Server')
            
            # Exchange Server
            if any('msexchange' in svc for svc in running_services):
                roles.append('Exchange Server')
            
            return ', '.join(roles) if roles else 'Member Server'
            
        except Exception:
            return None
    
    def _real_endpoint_mapper_scan(self, results):
        """Real RPC Endpoint Mapper scanning"""
        try:
            from ..core.rpc_endpoint_mapper import RPCEndpointMapper
            
            self.signals.output.emit("<p style='color: #FFD700;'>Performing real RPC endpoint mapper scan...</p><br>")
            
            epm = RPCEndpointMapper(self._resolve_target(self.target))
            epm_results = epm.enumerate_all_endpoints()
            
            if epm_results:
                # Separate real endpoints from security issues
                real_endpoints = [ep for ep in epm_results if not ep.get('severity')]
                security_issues = [ep for ep in epm_results if ep.get('severity')]
                
                results['real_rpc_endpoints'] = real_endpoints
                results['epm_security_issues'] = security_issues
                
                if real_endpoints:
                    self.signals.output.emit(f"<p style='color: #00FF41;'>Real EPM scan found {len(real_endpoints)} RPC endpoints:</p><br>")
                    
                    # Show unique UUIDs and their details
                    unique_uuids = {}
                    for endpoint in real_endpoints:
                        uuid_str = endpoint.get('uuid', 'Unknown')
                        if uuid_str not in unique_uuids:
                            unique_uuids[uuid_str] = endpoint
                    
                    for uuid_str, endpoint in unique_uuids.items():
                        version = f"v{endpoint.get('version_major', 0)}.{endpoint.get('version_minor', 0)}"
                        protocol = endpoint.get('protocol', 'unknown')
                        self.signals.output.emit(f"<p>• {h(uuid_str)} ({h(version)}, {h(protocol)})</p><br>")
                
                # Report security issues
                for issue in security_issues:
                    severity_color = '#FF0000' if issue.get('severity') == 'High' else '#FFA500'
                    self.signals.output.emit(f"<p style='color: {severity_color};'>⚠️ {h(issue.get('severity', 'UNKNOWN').upper())}: {h(issue.get('description', 'Unknown issue'))}</p><br>")
                
                if not real_endpoints and not security_issues:
                    self.signals.output.emit("<p style='color: #FFAA00;'>EPM scan completed but no endpoints discovered</p><br>")
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>EPM connection failed or no endpoints found</p><br>")
                
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>Real EPM scan failed: {h(str(e))}</p><br>")
    
    def _raw_lsa_sam_enumeration(self, results):
        """Raw LSA and SAM RPC enumeration"""
        try:
            from ..core.rpc_lsa_sam_client import RPCLSASAMClient
            
            self.signals.output.emit("<p style='color: #FFD700;'>Performing raw LSA/SAM RPC enumeration...</p><br>")
            
            client = RPCLSASAMClient(self.target, self.username, self.password, self.domain)
            
            # LSA account enumeration
            lsa_accounts = client.enumerate_lsa_accounts()
            if lsa_accounts:
                results['lsa_accounts'] = lsa_accounts
                self.signals.output.emit(f"<p style='color: #00FF41;'>LSA accounts discovered: {len(lsa_accounts)}</p><br>")
                
                for account in lsa_accounts[:5]:  # Show first 5
                    name = account.get('name', 'Unknown')
                    acc_type = account.get('type', 'Unknown')
                    self.signals.output.emit(f"<p>• {h(name)} ({h(acc_type)})</p><br>")
            
            # SAM user enumeration
            sam_users = client.enumerate_sam_users()
            if sam_users:
                results['sam_users'] = sam_users
                self.signals.output.emit(f"<p style='color: #00FF41;'>SAM users discovered: {len(sam_users)}</p><br>")
                
                for user in sam_users[:5]:  # Show first 5
                    name = user.get('name', 'Unknown')
                    rid = user.get('rid', 'Unknown')
                    self.signals.output.emit(f"<p>• {h(name)} (RID: {h(rid)})</p><br>")
            
            # RID brute force (limited range)
            if self.scan_type == "Complete Assessment":
                rid_results = client.brute_force_rids(500, 520)
                if rid_results:
                    results['rid_bruteforce'] = rid_results
                    found_rids = [r for r in rid_results if r.get('status') == 'Found']
                    if found_rids:
                        self.signals.output.emit(f"<p style='color: #FFA500;'>RID brute force found {len(found_rids)} accounts:</p><br>")
                        for rid_info in found_rids:
                            name = rid_info.get('name', 'Unknown')
                            rid = rid_info.get('rid', 'Unknown')
                            self.signals.output.emit(f"<p>• RID {h(rid)}: {h(name)}</p><br>")
            
            # Find orphaned users
            orphaned = client.find_orphaned_users()
            if orphaned:
                results['orphaned_users'] = orphaned
                self.signals.output.emit(f"<p style='color: #FF6B6B;'>⚠️ Found {len(orphaned)} orphaned user(s):</p><br>")
                
                for orphan in orphaned:
                    name = orphan.get('name', 'Unknown')
                    issue = orphan.get('issue', 'Unknown issue')
                    self.signals.output.emit(f"<p style='color: #FFA500;'>• {h(name)}: {h(issue)}</p><br>")
            
            if not lsa_accounts and not sam_users:
                self.signals.output.emit("<p style='color: #FFAA00;'>LSA/SAM enumeration failed - insufficient privileges or access denied</p><br>")
                
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>Raw LSA/SAM enumeration failed: {h(str(e))}</p><br>")
    
    def _dcom_uuid_scanning(self, results):
        """DCOM UUID scanning for execution vectors"""
        try:
            from ..core.dcom_uuid_scanner import DCOMUUIDScanner
            
            self.signals.output.emit("<p style='color: #FFD700;'>Scanning DCOM interfaces for execution vectors...</p><br>")
            
            scanner = DCOMUUIDScanner(self.target, self.username, self.password, self.domain)
            
            # Scan accessible DCOM interfaces
            dcom_interfaces = scanner.scan_dcom_interfaces()
            if dcom_interfaces:
                results['dcom_interfaces'] = dcom_interfaces
                
                # Categorize by risk level
                critical_interfaces = [i for i in dcom_interfaces if i.get('risk') == 'Critical']
                high_interfaces = [i for i in dcom_interfaces if i.get('risk') == 'High']
                medium_interfaces = [i for i in dcom_interfaces if i.get('risk') == 'Medium']
                
                if critical_interfaces:
                    self.signals.output.emit(f"<p style='color: #FF0000;'>🚨 CRITICAL: {len(critical_interfaces)} high-risk DCOM interface(s):</p><br>")
                    for interface in critical_interfaces:
                        name = interface.get('name', 'Unknown')
                        exploitation = interface.get('exploitation', 'Unknown')
                        self.signals.output.emit(f"<p style='color: #FF0000;'>• {h(name)}: {h(exploitation)}</p><br>")
                
                if high_interfaces:
                    self.signals.output.emit(f"<p style='color: #FFA500;'>⚠️ HIGH: {len(high_interfaces)} DCOM interface(s):</p><br>")
                    for interface in high_interfaces:
                        name = interface.get('name', 'Unknown')
                        exploitation = interface.get('exploitation', 'Unknown')
                        self.signals.output.emit(f"<p style='color: #FFA500;'>• {h(name)}: {h(exploitation)}</p><br>")
                
                if medium_interfaces:
                    self.signals.output.emit(f"<p style='color: #FFFF00;'>⚠️ MEDIUM: {len(medium_interfaces)} DCOM interface(s) accessible</p><br>")
            
            # Test DCOM permissions
            if self.scan_type == "Complete Assessment":
                permissions = scanner.test_dcom_permissions()
                if permissions:
                    results['dcom_permissions'] = permissions
                    
                    launch_level = permissions.get('launch_permissions', {}).get('level', 'Unknown')
                    auth_level = permissions.get('authentication_level', 'Unknown')
                    
                    if launch_level == 'Weak':
                        self.signals.output.emit(f"<p style='color: #FF6B6B;'>⚠️ Weak DCOM launch permissions detected</p><br>")
                    
                    self.signals.output.emit(f"<p style='color: #87CEEB;'>DCOM Auth Level: {h(auth_level)}</p><br>")
                
                # Check for weak ACLs
                weak_acls = scanner.detect_weak_dcom_acls()
                if weak_acls:
                    results['dcom_weak_acls'] = weak_acls
                    self.signals.output.emit(f"<p style='color: #FF6B6B;'>⚠️ Found {len(weak_acls)} weak DCOM ACL(s)</p><br>")
            
            if not dcom_interfaces:
                self.signals.output.emit("<p style='color: #00FF41;'>✅ No accessible high-risk DCOM interfaces detected</p><br>")
                
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>DCOM UUID scanning failed: {h(str(e))}</p><br>")
    
    def _advanced_rpc_discovery(self, results):
        """Advanced RPC service discovery"""
        try:
            self.signals.output.emit("<p style='color: #FFD700;'>Performing advanced RPC service discovery...</p><br>")
            
            discovery = RPCServiceDiscovery(self._resolve_target(self.target))
            discovered_services = discovery.discover_all_services()
            
            if discovered_services:
                results['advanced_rpc_services'] = discovered_services
                
                # Categorize services
                high_value = discovery.get_high_value_services()
                
                self.signals.output.emit(f"<p style='color: #00FF41;'>Advanced discovery found {len(discovered_services)} RPC services:</p><br>")
                
                for service in discovered_services[:10]:  # Show first 10
                    name = service.get('name', 'Unknown')
                    uuid = service.get('uuid', 'N/A')[:8] + '...'
                    port = service.get('port', 'Unknown')
                    
                    if service in high_value:
                        self.signals.output.emit(f"<p style='color: #FF6B6B;'>🎯 HIGH VALUE: {h(name)} ({h(uuid)}) - Port {port}</p><br>")
                    else:
                        self.signals.output.emit(f"<p>• {h(name)} ({h(uuid)}) - Port {port}</p><br>")
                
                if len(discovered_services) > 10:
                    self.signals.output.emit(f"<p>... and {len(discovered_services) - 10} more services</p><br>")
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>No additional RPC services discovered</p><br>")
                
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>Advanced RPC discovery failed: {h(str(e))}</p><br>")
    
    def _rpc_coercion_testing(self, results):
        """Test RPC coercion attack vectors"""
        try:
            self.signals.output.emit("<p style='color: #FFD700;'>Testing RPC coercion attack vectors...</p><br>")
            
            coercion = RPCCoercionAttacks(self._resolve_target(self.target))
            
            # Test different coercion attacks
            coercion_tests = [
                ('PrinterBug', 'printerbug'),
                ('PetitPotam', 'petitpotam'),
                ('DFSCoerce', 'dfscoerce'),
                ('ShadowCoerce', 'shadowcoerce')
            ]
            
            coercion_vectors = []
            
            for attack_name, attack_type in coercion_tests:
                # Add delay between coercion attempts
                import time
                time.sleep(1.0)
                # Use a dummy listener IP for testing
                test_result = coercion.execute_coercion_attack(attack_type, '192.168.1.100')
                
                if test_result.get('success'):
                    vector = {
                        'attack': attack_name,
                        'type': attack_type,
                        'severity': 'Critical' if attack_type in ['printerbug', 'petitpotam'] else 'High',
                        'description': f'{attack_name} coercion attack possible'
                    }
                    coercion_vectors.append(vector)
                    
                    severity_color = '#FF0000' if vector['severity'] == 'Critical' else '#FFA500'
                    self.signals.output.emit(f"<p style='color: {severity_color};'>🚨 {h(vector['severity'].upper())}: {h(attack_name)} coercion possible</p><br>")
            
            results['rpc_coercion_vectors'] = coercion_vectors
            
            if coercion_vectors:
                critical_count = len([v for v in coercion_vectors if v['severity'] == 'Critical'])
                high_count = len([v for v in coercion_vectors if v['severity'] == 'High'])
                self.signals.output.emit(f"<p style='color: #FF6B6B;'>RPC coercion vectors: {critical_count} Critical, {high_count} High</p><br>")
            else:
                self.signals.output.emit(f"<p style='color: #00FF41;'>✅ No RPC coercion vectors detected</p><br>")
                
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>RPC coercion testing failed: {h(str(e))}</p><br>")
    
    def _rpc_fuzzing_assessment(self, results):
        """Perform limited RPC fuzzing assessment"""
        try:
            if self.scan_type != "Complete Assessment":
                return  # Only run fuzzing on complete assessment
            
            self.signals.output.emit("<p style='color: #FFD700;'>Performing RPC fuzzing assessment...</p><br>")
            
            fuzzer = RPCFuzzer(self._resolve_target(self.target))
            
            # Test common vulnerable interfaces
            fuzz_targets = [
                ('spoolss', '12345678-1234-abcd-ef00-0123456789ab', (1, 0)),
                ('samr', '12345778-1234-abcd-ef00-0123456789ac', (1, 0))
            ]
            
            fuzzing_results = []
            
            for name, uuid, version in fuzz_targets:
                self.signals.output.emit(f"<p style='color: #87CEEB;'>Fuzzing {h(name)} interface...</p><br>")
                
                # Limited fuzzing (only 10 operations to avoid disruption)
                fuzz_result = fuzzer.fuzz_interface(uuid, version, max_opnum=10)
                
                if fuzz_result.get('crashes'):
                    fuzzing_results.append({
                        'interface': name,
                        'crashes': len(fuzz_result['crashes']),
                        'interesting': len(fuzz_result.get('interesting', [])),
                        'severity': 'Critical'
                    })
                    
                    self.signals.output.emit(f"<p style='color: #FF0000;'>🚨 CRITICAL: {h(name)} interface crashes detected ({len(fuzz_result['crashes'])})</p><br>")
                elif fuzz_result.get('interesting'):
                    fuzzing_results.append({
                        'interface': name,
                        'crashes': 0,
                        'interesting': len(fuzz_result['interesting']),
                        'severity': 'High'
                    })
                    
                    self.signals.output.emit(f"<p style='color: #FFA500;'>⚠️ HIGH: {h(name)} interface anomalies detected ({len(fuzz_result['interesting'])})</p><br>")
            
            results['rpc_fuzzing_results'] = fuzzing_results
            
            if fuzzing_results:
                total_crashes = sum(r['crashes'] for r in fuzzing_results)
                total_interesting = sum(r['interesting'] for r in fuzzing_results)
                self.signals.output.emit(f"<p style='color: #FF6B6B;'>RPC fuzzing: {total_crashes} crashes, {total_interesting} anomalies</p><br>")
            else:
                self.signals.output.emit(f"<p style='color: #00FF41;'>✅ RPC fuzzing found no obvious vulnerabilities</p><br>")
                
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>RPC fuzzing assessment failed: {h(str(e))}</p><br>")