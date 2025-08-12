# app/tools/smb_scanner.py
import subprocess
from PyQt6.QtCore import QObject, pyqtSignal, QRunnable
from ..core.smb_data_collector import create_smb_collector

class SMBWorkerSignals(QObject):
    output = pyqtSignal(str)
    finished = pyqtSignal()
    results = pyqtSignal(dict)
    status = pyqtSignal(str)
    results_ready = pyqtSignal(dict)

class SMBWorker(QRunnable):
    def __init__(self, target, scan_type="Basic Info", auth_type="Anonymous", domain="", username="", password="", wordlist_path=None, tenant_id="default"):
        super().__init__()
        self.target = target
        self.scan_type = scan_type
        self.auth_type = auth_type
        self.domain = domain
        self.username = username
        self.password = password
        self.wordlist_path = wordlist_path
        self.tenant_id = tenant_id
        self.signals = SMBWorkerSignals()
        self.is_running = True
        self.data_collector = create_smb_collector(tenant_id)
    
    def run(self):
        try:
            self.signals.output.emit(f"<p style='color: #87CEEB;'>Starting SMB enumeration on {self.target}...</p><br>")
            
            # Start scan in centralized data
            scan_id = self.data_collector.start_smb_scan(self.target, "smb_scanner")
            
            results = {}
            total_results = 0
            
            # Check SMB availability
            self._check_smb_ports(results)
            if 'smb_ports' in results:
                self.data_collector.collect_ports(self.target, results['smb_ports'])
                total_results += len(results['smb_ports'])
            
            # Enumerate shares based on scan type
            if self.scan_type in ["Share Enumeration", "Vulnerability Scan"]:
                self._enumerate_shares(results)
                if 'shares' in results:
                    self.data_collector.collect_shares(self.target, results['shares'])
                    total_results += len(results['shares'])
                
                # If Share Enumeration and wordlist provided, do brute force
                if self.scan_type == "Share Enumeration" and self.wordlist_path:
                    self._bruteforce_shares(results)
                    if 'bruteforce_shares' in results:
                        self.data_collector.collect_shares(self.target, results['bruteforce_shares'])
                        total_results += len(results['bruteforce_shares'])
            
            # Check for vulnerabilities
            self._check_vulnerabilities(results)
            if 'vulnerabilities' in results:
                self.data_collector.collect_vulnerabilities(self.target, results['vulnerabilities'])
                total_results += len(results['vulnerabilities'])
            
            # Complete scan
            self.data_collector.complete_smb_scan(total_results)
            
            # Update asset inventory
            from ..core.scan_asset_integration import scan_asset_integrator
            # Add target IP to results for asset processing
            results['target_ip'] = self.target
            scan_asset_integrator.process_smb_results(results)
            
            self.signals.results.emit(results)
            self.signals.output.emit(f"<p style='color: #00FF41;'>SMB enumeration completed. {total_results} results collected and assets updated.</p><br>")
            
        except Exception as e:
            self.data_collector.complete_smb_scan(0, str(e))
            self.signals.output.emit(f"<p style='color: #FF6B6B;'>Error: {str(e)}</p><br>")
        finally:
            self.signals.finished.emit()
    
    def _check_smb_ports(self, results):
        """Check SMB ports availability"""
        try:
            self.signals.output.emit("<p style='color: #FFD700;'>Checking SMB ports...</p><br>")
            
            # Use nmap or telnet to check ports on target
            import socket
            smb_ports = []
            
            # Check common SMB ports
            ports_to_check = [445, 139]
            
            for port in ports_to_check:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    result = sock.connect_ex((self.target, port))
                    sock.close()
                    
                    if result == 0:
                        if port == 445:
                            smb_ports.append('445 (SMB over TCP)')
                        elif port == 139:
                            smb_ports.append('139 (NetBIOS Session)')
                except:
                    pass
            
            if smb_ports:
                results['smb_ports'] = smb_ports
                self.signals.output.emit(f"<p style='color: #00FF41;'>Found SMB ports: {', '.join(smb_ports)}</p><br>")
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>No SMB ports detected on target</p><br>")
                
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>Port check failed: {str(e)}</p><br>")
    
    def _enumerate_shares(self, results):
        """Enumerate SMB shares"""
        try:
            self.signals.output.emit("<p style='color: #FFD700;'>Enumerating SMB shares...</p><br>")
            
            # Build command based on auth type
            if self.auth_type == "Credentials" and self.username and self.password:
                # Use domain\username format if domain is provided
                if self.domain:
                    user_format = f"{self.domain}\\{self.username}"
                else:
                    user_format = self.username
                
                # First establish connection with credentials
                auth_cmd = ["net", "use", f"\\\\{self.target}\\IPC$", self.password, f"/USER:{user_format}"]
                auth_result = subprocess.run(auth_cmd, capture_output=True, text=True, timeout=10)
                
                if auth_result.returncode != 0:
                    self.signals.output.emit(f"<p style='color: #FFAA00;'>Authentication failed: {auth_result.stderr.strip()}</p><br>")
                    return
                
                # Now enumerate shares
                cmd = ["net", "view", f"\\\\{self.target}"]
            else:
                cmd = ["net", "view", f"\\\\{self.target}"]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 and result.stdout:
                shares = []
                lines = result.stdout.split('\n')
                in_shares_section = False
                
                for line in lines:
                    line = line.strip()
                    if 'Shared resources' in line:
                        in_shares_section = True
                        continue
                    if in_shares_section and line and not line.startswith('-') and not line.startswith('The command'):
                        parts = line.split()
                        if len(parts) >= 1 and not parts[0].startswith('\\'):
                            share_name = parts[0]
                            if share_name not in ['Name', 'Type', 'Used', 'Comment']:
                                shares.append(share_name)
                
                if shares:
                    results['shares'] = shares
                    self.signals.output.emit(f"<p style='color: #00FF41;'>Found {len(shares)} shares</p><br>")
                    for share in shares:
                        self.signals.output.emit(f"<p>Share: {share}</p><br>")
                else:
                    self.signals.output.emit("<p style='color: #FFAA00;'>No shares found</p><br>")
            else:
                error_msg = result.stderr.strip() if result.stderr else "Access denied or target unreachable"
                self.signals.output.emit(f"<p style='color: #FFAA00;'>Share enumeration failed: {error_msg}</p><br>")
            
            # Clean up authenticated connection if used
            if self.auth_type == "Credentials" and self.username and self.password:
                try:
                    subprocess.run(["net", "use", f"\\\\{self.target}\\IPC$", "/delete"], 
                                 capture_output=True, timeout=5)
                except:
                    pass
                
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>Share enumeration failed: {str(e)}</p><br>")
    
    def _check_vulnerabilities(self, results):
        """Check for common SMB vulnerabilities"""
        try:
            self.signals.output.emit("<p style='color: #FFD700;'>Checking SMB vulnerabilities...</p><br>")
            
            vulnerabilities = []
            
            # Only check for null session if not using credentials
            if self.auth_type == "Anonymous":
                try:
                    # Check for null session
                    cmd = ["net", "use", f"\\\\{self.target}\\IPC$", "", "/user:"]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                    
                    if result.returncode == 0:
                        vulnerabilities.append({
                            'name': 'Null Session Access',
                            'severity': 'medium',
                            'description': 'SMB allows null session connections'
                        })
                        self.signals.output.emit("<p style='color: #FFAA00;'>Null session access detected</p><br>")
                        # Clean up the connection
                        subprocess.run(["net", "use", f"\\\\{self.target}\\IPC$", "/delete"], 
                                     capture_output=True, timeout=5)
                    
                    # Check for guest access
                    cmd = ["net", "use", f"\\\\{self.target}\\IPC$", "", "/user:guest"]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                    
                    if result.returncode == 0:
                        vulnerabilities.append({
                            'name': 'Guest Account Access',
                            'severity': 'low',
                            'description': 'SMB allows guest account access'
                        })
                        self.signals.output.emit("<p style='color: #FFAA00;'>Guest account access detected</p><br>")
                        # Clean up the connection
                        subprocess.run(["net", "use", f"\\\\{self.target}\\IPC$", "/delete"], 
                                     capture_output=True, timeout=5)
                except subprocess.TimeoutExpired:
                    self.signals.output.emit("<p style='color: #FFAA00;'>Vulnerability check timed out</p><br>")
                except Exception as vuln_e:
                    self.signals.output.emit(f"<p style='color: #FFAA00;'>Vulnerability check error: {str(vuln_e)}</p><br>")
            
            if vulnerabilities:
                results['vulnerabilities'] = vulnerabilities
                self.signals.output.emit(f"<p style='color: #FF6B6B;'>Found {len(vulnerabilities)} potential vulnerabilities</p><br>")
            else:
                self.signals.output.emit("<p style='color: #00FF41;'>No obvious vulnerabilities detected</p><br>")
                
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>Vulnerability check failed: {str(e)}</p><br>")
    
    def _bruteforce_shares(self, results):
        """Brute force SMB shares using wordlist"""
        try:
            self.signals.output.emit("<p style='color: #FFD700;'>Brute forcing SMB shares with wordlist...</p><br>")
            
            if not self.wordlist_path:
                # Use default share names
                share_names = ['ADMIN$', 'C$', 'D$', 'E$', 'IPC$', 'NETLOGON', 'SYSVOL', 'print$', 'fax$', 'Users', 'Public']
            else:
                # Read wordlist file
                try:
                    with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                        share_names = [line.strip() for line in f if line.strip()]
                except:
                    share_names = ['ADMIN$', 'C$', 'IPC$', 'NETLOGON', 'SYSVOL']
            
            found_shares = []
            
            for share_name in share_names[:50]:  # Limit to first 50 to avoid too many requests
                if not self.is_running:
                    break
                
                try:
                    # Test share access
                    if self.auth_type == "Credentials" and self.username and self.password:
                        if self.domain:
                            user_format = f"{self.domain}\\{self.username}"
                        else:
                            user_format = self.username
                        cmd = ["net", "use", f"\\\\{self.target}\\{share_name}", self.password, f"/user:{user_format}"]
                    else:
                        cmd = ["net", "use", f"\\\\{self.target}\\{share_name}"]
                    
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
                    
                    if result.returncode == 0:
                        found_shares.append(share_name)
                        self.signals.output.emit(f"<p style='color: #00FF41;'>Found share: {share_name}</p><br>")
                        # Clean up connection
                        subprocess.run(["net", "use", f"\\\\{self.target}\\{share_name}", "/delete"], 
                                     capture_output=True, timeout=3)
                    
                except subprocess.TimeoutExpired:
                    continue
                except Exception:
                    continue
            
            if found_shares:
                results['bruteforce_shares'] = found_shares
                self.signals.output.emit(f"<p style='color: #00FF41;'>Brute force found {len(found_shares)} additional shares</p><br>")
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>No additional shares found via brute force</p><br>")
                
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>Share brute force failed: {str(e)}</p><br>")

# Alias for backward compatibility
class SMBEnumWorker(SMBWorker):
    """Backward compatibility alias for SMBWorker"""
    def __init__(self, target, username="", password="", scan_type="basic", tenant_id="default"):
        # Map old scan_type parameter to new parameters
        if scan_type == "basic":
            new_scan_type = "Basic Info"
            auth_type = "Anonymous" if not username else "Credentials"
        elif scan_type == "shares":
            new_scan_type = "Share Enumeration"
            auth_type = "Anonymous" if not username else "Credentials"
        elif scan_type == "vuln":
            new_scan_type = "Vulnerability Scan"
            auth_type = "Anonymous" if not username else "Credentials"
        else:
            new_scan_type = "Basic Info"
            auth_type = "Anonymous" if not username else "Credentials"
        
        super().__init__(
            target=target,
            scan_type=new_scan_type,
            auth_type=auth_type,
            domain="",
            username=username,
            password=password,
            wordlist_path=None,
            tenant_id=tenant_id
        )
    
    def run(self):
        """Override run to emit additional signals for compatibility"""
        # Connect internal signals to compatibility signals
        self.signals.results.connect(self.signals.results_ready)
        
        # Emit status updates
        self.signals.status.emit(f"Starting SMB enumeration on {self.target}")
        
        # Call parent run method
        super().run()
        
        # Emit final status
        self.signals.status.emit("SMB enumeration completed")