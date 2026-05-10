# app/tools/smb_scanner.py
import socket
import asyncio
from concurrent.futures import ThreadPoolExecutor
from PyQt6.QtCore import QObject, pyqtSignal, QRunnable
from ..core.smb_data_collector import create_smb_collector
from .smb_raw_proto import enumerate_smb_comprehensive, scan_smb_ports, SMBRawClient, _probe_smb1_support
from app.core.html_utils import h

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
            self.signals.output.emit(f"<p style='color: #87CEEB;'>🚀 Starting advanced SMB enumeration with hardened DC detection on {h(self.target)}...</p><br>")
            
            # Start scan in centralized data
            scan_id = self.data_collector.start_smb_scan(self.target, "smb_scanner")
            
            results = {}
            total_results = 0
            
            # Stage 1: Advanced SMB2/3 Protocol Negotiation with Hardened DC Detection
            self._perform_smb_protocol_analysis(results)
            if 'smb_ports' in results:
                self.data_collector.collect_ports(self.target, results['smb_ports'])
                total_results += len(results['smb_ports'])
            
            # Collect SMB metadata and assessment results
            if 'metadata' in results:
                metadata = results['metadata']
                if metadata.get('negotiated_dialect'):
                    self.data_collector.collect_smb_capabilities(self.target, metadata)
                    total_results += 1
            
            # Collect domain information from NTLM handshake
            if 'domain_info' in results and results['domain_info']:
                domain_info = results['domain_info']
                if domain_info.get('domain_name') or domain_info.get('dns_domain'):
                    self.signals.output.emit(f"<p style='color: #00BFFF;'>🏛️ Domain Discovery via NTLM:</p>")
                    if domain_info.get('domain_name'):
                        self.signals.output.emit(f"<p style='color: #87CEEB;'>• NetBIOS Domain: {h(domain_info['domain_name'])}</p>")
                    if domain_info.get('dns_domain'):
                        self.signals.output.emit(f"<p style='color: #87CEEB;'>• DNS Domain: {h(domain_info['dns_domain'])}</p>")
                    if domain_info.get('forest_name'):
                        self.signals.output.emit(f"<p style='color: #87CEEB;'>• Forest Name: {h(domain_info['forest_name'])}</p>")
                    if domain_info.get('computer_name'):
                        self.signals.output.emit(f"<p style='color: #87CEEB;'>• Computer Name: {h(domain_info['computer_name'])}</p>")
                    self.signals.output.emit("<br>")
                    total_results += 1
            
            # Enumerate shares for Share Enumeration scan type
            if self.scan_type == "Share Enumeration":
                self._enumerate_shares(results)
                if 'shares' in results:
                    self.data_collector.collect_shares(self.target, results['shares'])
                    total_results += len(results['shares'])
                
                # Brute force shares if wordlist provided
                if self.wordlist_path:
                    self._bruteforce_shares(results)
                    if 'bruteforce_shares' in results:
                        bf_shares = results['bruteforce_shares']
                        self.data_collector.collect_shares(self.target, bf_shares)
                        total_results += len(bf_shares)
            
            # Stage 2: Advanced vulnerability assessment (already done in protocol analysis)
            if 'vulnerabilities' in results:
                self.data_collector.collect_vulnerabilities(self.target, results['vulnerabilities'])
                total_results += len(results['vulnerabilities'])
            
            # Complete scan
            self.data_collector.complete_smb_scan(total_results)
            
            # Update asset inventory
            from ..core.scan_asset_integration import scan_asset_integrator
            results['target_ip'] = self.target
            scan_asset_integrator.process_smb_results(results)
            
            self.signals.results.emit(results)
            if results.get('metadata', {}).get('smb_blocked') or results.get('metadata', {}).get('connection_reset'):
                self.signals.output.emit(f"<p style='color: #00FF41;'>✅ SMB security assessment completed. Target demonstrates excellent security posture with SMB properly blocked.</p><br>")
            else:
                self.signals.output.emit(f"<p style='color: #00FF41;'>✅ Advanced SMB enumeration completed. {total_results} results collected and assets updated.</p><br>")
            
        except Exception as e:
            self.data_collector.complete_smb_scan(0, str(e))
            self.signals.output.emit(f"<p style='color: #FF6B6B;'>❌ Error: {h(str(e))}</p><br>")
        finally:
            self.signals.finished.emit()
    
    def _perform_smb_protocol_analysis(self, results):
        """Perform comprehensive SMB2/3 protocol analysis with security assessment"""
        try:
            self.signals.output.emit("<p style='color: #FFD700;'>🔍 Stage 1: Advanced SMB Protocol Intelligence (Hardened DC Detection)...</p><br>")
            
            # Comprehensive SMB security assessment
            assessment = enumerate_smb_comprehensive(self.target, timeout=3.0)
            
            # Port information
            port_scan = scan_smb_ports(self.target, timeout=2.0)
            if port_scan['tcp_ports']:
                port_info = [f"{port} (SMB/TCP)" for port in port_scan['tcp_ports']]
                results['smb_ports'] = port_info
                
                if port_scan['quic_detected']:
                    self.signals.output.emit("<p style='color: #00BFFF;'>🚀 SMB over QUIC detected (Windows Server 2025+ feature)</p><br>")
            
            # Display overall risk assessment
            risk_level = assessment.get('overall_risk', 'UNKNOWN')
            risk_colors = {'CRITICAL': '#FF0000', 'HIGH': '#FF6600', 'MEDIUM': '#FFAA00', 'LOW': '#00FF41'}
            risk_color = risk_colors.get(risk_level, '#CCCCCC')
            
            self.signals.output.emit(f"<p style='color: {risk_color};'>🎯 Target: {h(assessment.get('target', self.target))}</p>")
            self.signals.output.emit(f"<p style='color: {risk_color};'>🛡️ Overall Risk: {risk_level}</p>")
            
            if assessment.get('risk_summary'):
                self.signals.output.emit(f"<p style='color: {risk_color};'>📊 {h(assessment['risk_summary'])}</p><br>")
            
            # Handle SMB blocking detection
            if assessment.get('metadata', {}).get('smb_blocked') or assessment.get('metadata', {}).get('connection_reset'):
                self.signals.output.emit("<p style='color: #00FF41;'>🛡️ SMB Security Analysis:</p>")
                blocking_method = assessment.get('metadata', {}).get('blocking_method', 'unknown')
                if blocking_method == 'immediate_reset':
                    self.signals.output.emit("<p style='color: #00FF41;'>• ✅ Advanced SMB Blocking: Connection reset on SMB traffic</p>")
                elif blocking_method == 'port_closed':
                    self.signals.output.emit("<p style='color: #00FF41;'>• ✅ SMB Port Closed: Port 445 is not accessible</p>")
                
                security_posture = assessment.get('metadata', {}).get('security_posture', 'unknown')
                if security_posture == 'hardened':
                    self.signals.output.emit("<p style='color: #00FF41;'>• ✅ Security Posture: Hardened (Excellent)</p>")
                
                self.signals.output.emit("<p style='color: #00FF41;'>• ✅ Attack Prevention: SMB enumeration and lateral movement blocked</p>")
                self.signals.output.emit("<br>")
                
                # Skip further analysis since SMB is blocked
                results.update(assessment)
                return
            
            # Display protocol intelligence (only if SMB is not blocked)
            metadata = assessment.get('metadata', {})
            if metadata and not metadata.get('smb_blocked') and not metadata.get('connection_reset'):
                self.signals.output.emit("<p style='color: #00BFFF;'>📋 Advanced SMB Protocol Intelligence:</p>")
                
                if metadata.get('negotiated_dialect'):
                    dialect = metadata['negotiated_dialect']
                    if dialect == '3.1.1' and metadata.get('hardened_negotiate'):
                        self.signals.output.emit(f"<p style='color: #00FF41;'>• Negotiated Dialect: SMB {h(dialect)} (Hardened Detection)</p>")
                    else:
                        self.signals.output.emit(f"<p style='color: #87CEEB;'>• Negotiated Dialect: SMB {h(dialect)}</p>")
                
                signing_status = "✅ Required" if metadata.get('signing_required') else "⚠️ Optional"
                signing_color = "#00FF41" if metadata.get('signing_required') else "#FFAA00"
                self.signals.output.emit(f"<p style='color: {h(signing_color)};'>• SMB Signing: {h(signing_status)}</p>")
                
                if metadata.get('encryption_required'):
                    self.signals.output.emit(f"<p style='color: #00FF41;'>• SMB Encryption: ✅ Required</p>")
                elif '3.' in str(metadata.get('negotiated_dialect', '')):
                    self.signals.output.emit(f"<p style='color: #FFAA00;'>• SMB Encryption: ⚠️ Optional</p>")
                
                if metadata.get('preauth_integrity'):
                    self.signals.output.emit(f"<p style='color: #00FF41;'>• Preauth Integrity: ✅ SHA-512 Enabled</p>")
                
                # Show hardened detection status
                if metadata.get('hardened_negotiate'):
                    self.signals.output.emit(f"<p style='color: #00FF41;'>• Hardened DC Detection: ✅ Successfully bypassed strict policies</p>")
                
                if metadata.get('smb1_enabled'):
                    self.signals.output.emit(f"<p style='color: #FF0000;'>• SMB1 Support: 🔴 ENABLED (Critical Risk)</p>")
                
                self.signals.output.emit("<br>")
            
            # Display domain intelligence (only if SMB is not blocked)
            domain_info = metadata.get('domain_info', {})
            if domain_info and not domain_info.get('error') and not metadata.get('smb_blocked') and not metadata.get('connection_reset'):
                self.signals.output.emit("<p style='color: #00BFFF;'>🏛️ Enhanced Domain Intelligence (NTLM Type-2 Parsing):</p>")
                if domain_info.get('domain_name'):
                    self.signals.output.emit(f"<p style='color: #87CEEB;'>• NetBIOS Domain: {h(domain_info['domain_name'])}</p>")
                if domain_info.get('dns_domain'):
                    self.signals.output.emit(f"<p style='color: #87CEEB;'>• DNS Domain: {h(domain_info['dns_domain'])}</p>")
                if domain_info.get('computer_name'):
                    self.signals.output.emit(f"<p style='color: #87CEEB;'>• Computer Name: {h(domain_info['computer_name'])}</p>")
                if domain_info.get('forest_name'):
                    self.signals.output.emit(f"<p style='color: #87CEEB;'>• Forest Name: {h(domain_info['forest_name'])}</p>")
                
                # Show if this was obtained via hardened method
                if metadata.get('hardened_negotiate'):
                    self.signals.output.emit(f"<p style='color: #00FF41;'>• Intelligence Source: Hardened SMB 3.1.1 + Signed SESSION_SETUP</p>")
                
                self.signals.output.emit("<br>")
            
            # Display share enumeration results (only if SMB is not blocked)
            shares = metadata.get('shares', [])
            if shares and not isinstance(shares, dict) and not metadata.get('smb_blocked') and not metadata.get('connection_reset'):
                self.signals.output.emit("<p style='color: #00BFFF;'>📁 Share Enumeration:</p>")
                accessible_shares = []
                for share in shares:
                    if isinstance(share, dict):
                        share_name = share.get('name', 'Unknown')
                        if share.get('accessible'):
                            accessible_shares.append(share_name)
                            self.signals.output.emit(f"<p style='color: #00FF41;'>• ✅ {h(share_name)} - Accessible</p>")
                        elif share.get('exists'):
                            self.signals.output.emit(f"<p style='color: #FFAA00;'>• 🔒 {h(share_name)} - Access Denied</p>")
                        else:
                            self.signals.output.emit(f"<p style='color: #888888;'>• ❓ {h(share_name)} - Not Found</p>")
                
                if accessible_shares:
                    results['accessible_shares'] = accessible_shares
                
                results['shares'] = shares
                self.signals.output.emit("<br>")
            
            # Display security vulnerabilities (only if SMB is not blocked)
            vulnerabilities = assessment.get('vulnerabilities', [])
            if vulnerabilities and not metadata.get('smb_blocked') and not metadata.get('connection_reset'):
                self.signals.output.emit("<p style='color: #FF6B6B;'>🚨 Security Vulnerabilities:</p>")
                for vuln in vulnerabilities:
                    severity = vuln.get('severity', 'UNKNOWN')
                    severity_colors = {'CRITICAL': '#FF0000', 'HIGH': '#FF6600', 'MEDIUM': '#FFAA00', 'LOW': '#0099FF'}
                    severity_color = severity_colors.get(severity, '#CCCCCC')
                    
                    self.signals.output.emit(f"<p style='color: {severity_color};'>• 🔴 {h(vuln.get('type', 'Unknown Vulnerability'))} [{h(severity)}]</p>")
                    if vuln.get('description'):
                        self.signals.output.emit(f"<p style='color: #CCCCCC;'>  Description: {h(vuln['description'])}</p>")
                    if vuln.get('cve'):
                        self.signals.output.emit(f"<p style='color: #CCCCCC;'>  CVE: {h(vuln['cve'])}</p>")
                
                results['vulnerabilities'] = vulnerabilities
                self.signals.output.emit("<br>")
            
            # Display security findings
            findings = assessment.get('security_findings', [])
            if findings:
                self.signals.output.emit("<p style='color: #00BFFF;'>🔍 Security Assessment:</p>")
                for finding in findings:
                    severity = finding.get('severity', 'INFO')
                    severity_colors = {'HIGH': '#FF6600', 'MEDIUM': '#FFAA00', 'LOW': '#0099FF', 'INFO': '#87CEEB'}
                    severity_color = severity_colors.get(severity, '#CCCCCC')
                    
                    self.signals.output.emit(f"<p style='color: {severity_color};'>• ℹ️ {h(finding.get('type', 'Security Finding'))}</p>")
                    if finding.get('description'):
                        self.signals.output.emit(f"<p style='color: #CCCCCC;'>  {h(finding['description'])}</p>")
                
                self.signals.output.emit("<br>")
            
            # Display recommendations
            recommendations = assessment.get('recommendations', [])
            if recommendations:
                rec_color = '#00FF41' if metadata.get('smb_blocked') or metadata.get('connection_reset') else '#00BFFF'
                self.signals.output.emit(f"<p style='color: {h(rec_color)};'>💡 Security Assessment:</p>")
                for rec in recommendations:
                    self.signals.output.emit(f"<p style='color: #87CEEB;'>• {h(rec)}</p>")
                self.signals.output.emit("<br>")
            
            # Store assessment results
            results.update(assessment)
            
            # Error handling
            if 'error' in assessment:
                self.signals.output.emit(f"<p style='color: #FF6B6B;'>❌ {h(assessment['error'])}</p><br>")
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF6B6B;'>❌ Advanced SMB protocol analysis failed: {h(str(e))}</p><br>")
            # Try fallback to basic detection
            try:
                self.signals.output.emit("<p style='color: #FFAA00;'>🔄 Attempting fallback to basic SMB detection...</p><br>")
                from .smb_raw_proto import SMBRawClient
                client = SMBRawClient(self.target, timeout=2.0)
                client.connect()
                basic_result = client._negotiate_smb302_simple()
                if basic_result.get('dialect') != 'Unknown':
                    self.signals.output.emit(f"<p style='color: #87CEEB;'>✅ Fallback successful: SMB {h(basic_result['dialect'])} detected</p><br>")
                    results['metadata'] = {'negotiated_dialect': basic_result['dialect'], 'fallback_method': True}
                client.close()
            except Exception:
                import traceback
                self.signals.output.emit(f"<p style='color: #888888;'>Debug: {h(traceback.format_exc())}</p><br>")
    
    def _enumerate_shares(self, results):
        """Enhanced SMB share enumeration using existing protocol analysis results"""
        try:
            # Check if SMB is blocked first
            if results.get('metadata', {}).get('smb_blocked') or results.get('metadata', {}).get('connection_reset'):
                self.signals.output.emit("<p style='color: #FFAA00;'>⚠️ Share enumeration skipped - SMB traffic is blocked by security policy</p><br>")
                return
            
            self.signals.output.emit("<p style='color: #FFD700;'>📂 Stage 2: Advanced SMB Share Enumeration (Hardened DC Compatible)...</p><br>")
            
            # Use shares already discovered in protocol analysis
            if 'shares' in results:
                shares_data = results['shares']
                accessible_shares = [s['name'] for s in shares_data if s.get('accessible', False)]
                
                # Detailed share analysis
                for share_info in shares_data:
                    share_name = share_info['name']
                    accessible = share_info.get('accessible', False)
                    exists = share_info.get('exists', False)
                    description = share_info.get('description', 'Unknown status')
                    
                    if accessible:
                        self.signals.output.emit(f"<p style='color: #00FF41;'>✅ {h(share_name)}: Accessible (Anonymous) - {h(description)}</p>")
                    elif exists:
                        self.signals.output.emit(f"<p style='color: #FFAA00;'>🔒 {h(share_name)}: Exists (Access Denied) - {h(description)}</p>")
                    else:
                        self.signals.output.emit(f"<p style='color: #888888;'>❌ {h(share_name)}: Not Found - {h(description)}</p>")
                
                # Security assessment
                if accessible_shares:
                    self.signals.output.emit(f"<p style='color: #FF6B6B;'>⚠️ Security Risk: {len(accessible_shares)} shares allow anonymous access</p>")
                    self.signals.output.emit(f"<p style='color: #FF6B6B;'>• Accessible shares: {', '.join(accessible_shares)}</p>")
                
                self.signals.output.emit("<br>")
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>⚠️ No share information available from protocol analysis</p><br>")
                
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>❌ Advanced share enumeration error: {h(str(e))}</p><br>")
    
    def _get_status_description(self, status_code: int) -> str:
        """Get human-readable status description"""
        status_map = {
            0x00000000: "Success",
            0xC0000022: "Access Denied",
            0xC0000034: "Object Not Found",
            0xC000006D: "Logon Failure",
            0xC0000001: "Unsuccessful"
        }
        return status_map.get(status_code, f"Unknown (0x{status_code:08x})")
    
    def _bruteforce_shares(self, results):
        """Advanced share discovery using wordlist"""
        try:
            # Check if SMB is blocked first
            if results.get('metadata', {}).get('smb_blocked') or results.get('metadata', {}).get('connection_reset'):
                self.signals.output.emit("<p style='color: #FFAA00;'>⚠️ Share discovery skipped - SMB traffic is blocked by security policy</p><br>")
                return
            
            self.signals.output.emit("<p style='color: #FFD700;'>🔍 Stage 3: Advanced Share Discovery (Hardened DC Compatible)...</p><br>")
            
            if not self.wordlist_path:
                self.signals.output.emit("<p style='color: #FFAA00;'>⚠️ No wordlist provided for share discovery</p><br>")
                return
            
            # Read wordlist
            try:
                with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                    wordlist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                
                if not wordlist:
                    self.signals.output.emit("<p style='color: #FFAA00;'>⚠️ Wordlist is empty</p><br>")
                    return
                    
                self.signals.output.emit(f"<p style='color: #87CEEB;'>📄 Testing {len(wordlist)} share names with hardened detection...</p><br>")
                
            except Exception as e:
                self.signals.output.emit(f"<p style='color: #FFAA00;'>❌ Failed to read wordlist: {h(str(e))}</p><br>")
                return
            
            # Use SMB client for probing
            found_shares = []
            tested_count = 0
            
            try:
                client = SMBRawClient(self.target, timeout=1.5)
                client.connect()
                # Try hardened negotiate first
                negotiate_result = client.negotiate_dialects()
                
                if negotiate_result.get('metadata', {}).get('hardened_negotiate'):
                    self.signals.output.emit("<p style='color: #00FF41;'>✅ Using hardened SMB 3.1.1 for share discovery</p><br>")
                
                for share_name in wordlist[:100]:  # Limit to first 100 for performance
                    if not self.is_running:
                        break
                    
                    tested_count += 1
                    tree_id, status = client.tree_connect(share_name)
                    
                    if status in (0, 0xC0000022):  # SUCCESS or ACCESS_DENIED
                        accessible = (status == 0)
                        found_shares.append({
                            'name': share_name,
                            'exists': True,
                            'accessible': accessible,
                            'status': status
                        })
                        
                        status_text = "Accessible" if accessible else "Access Denied"
                        color = "#00FF41" if accessible else "#FFAA00"
                        self.signals.output.emit(f"<p style='color: {color};'>✅ {h(share_name)}: {h(status_text)}</p>")
                
                client.close()
                
            except Exception as e:
                self.signals.output.emit(f"<p style='color: #FFAA00;'>⚠️ Share discovery error: {h(str(e))}</p><br>")
                return
            
            # Results
            if found_shares:
                results['bruteforce_shares'] = found_shares
                accessible_count = len([s for s in found_shares if s['accessible']])
                self.signals.output.emit(f"<p style='color: #00FF41;'>🎉 Found {len(found_shares)} additional shares, {h(accessible_count)} accessible</p><br>")
            else:
                self.signals.output.emit(f"<p style='color: #FFAA00;'>🔍 No additional shares found (tested {h(tested_count)} names)</p><br>")
                
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>❌ Advanced share discovery error: {h(str(e))}</p><br>")
    
    def stop(self):
        """Stop the SMB enumeration"""
        self.is_running = False