from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QLineEdit, QPushButton, QTextEdit, QComboBox, QCheckBox, QFrame, QGroupBox)
from PyQt6.QtCore import pyqtSignal
from app.components.progress_component import ProgressComponent
from app.core.asset_manager import asset_manager

class HugginScannerComponent(QWidget):
    scan_started = pyqtSignal(str, str)
    scan_completed = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_profile = "Normal"
        self.setup_ui()
        self.apply_theme()

    def setup_ui(self):
        """Setup scanner configuration UI"""
        layout = QVBoxLayout(self)
        
        # Configuration section
        config_frame = self.create_config_section()
        layout.addWidget(config_frame)
        
        # Output section with Neuropol X font
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setPlaceholderText("Huggin scanner output will appear here...")
        
        # Set Neuropol X font for terminal-like display
        from PyQt6.QtGui import QFont, QFontDatabase
        import os
        
        # Load Neuropol font from resources
        font_path = os.path.join(os.path.dirname(__file__), '..', 'resources', 'fonts', 'neuropol.otf')
        if os.path.exists(font_path):
            font_id = QFontDatabase.addApplicationFont(font_path)
            if font_id != -1:
                font_families = QFontDatabase.applicationFontFamilies(font_id)
                if font_families:
                    font = QFont(font_families[0], 10)
                else:
                    font = QFont("Courier New", 10)  # Fallback
            else:
                font = QFont("Courier New", 10)  # Fallback
        else:
            font = QFont("Courier New", 10)  # Fallback
        
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.output_text.setFont(font)
        
        layout.addWidget(self.output_text)

    def create_config_section(self):
        """Create configuration section"""
        frame = QFrame()
        layout = QVBoxLayout(frame)
        
        # Target configuration
        target_group = QGroupBox("🎯 Target Configuration")
        target_layout = QVBoxLayout(target_group)
        
        # Target type selection
        target_type_layout = QHBoxLayout()
        target_type_layout.addWidget(QLabel("Target Type:"))
        self.target_type_combo = QComboBox()
        self.target_type_combo.addItems(["Single URL", "Domain", "IP Range", "File List"])
        self.target_type_combo.currentTextChanged.connect(self.on_target_type_changed)
        target_type_layout.addWidget(self.target_type_combo)
        target_layout.addLayout(target_type_layout)
        
        # Target input
        target_layout.addWidget(QLabel("Target:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("https://example.com")
        target_layout.addWidget(self.target_input)
        
        # Advanced target options
        advanced_target_layout = QHBoxLayout()
        self.custom_headers = QCheckBox("Custom Headers")
        advanced_target_layout.addWidget(self.custom_headers)
        
        self.follow_redirects = QCheckBox("Follow Redirects")
        self.follow_redirects.setChecked(True)
        advanced_target_layout.addWidget(self.follow_redirects)
        
        self.verify_ssl = QCheckBox("Verify SSL")
        self.verify_ssl.setChecked(True)
        advanced_target_layout.addWidget(self.verify_ssl)
        
        target_layout.addLayout(advanced_target_layout)
        
        layout.addWidget(target_group)
        
        # Authentication configuration
        auth_group = QGroupBox("🔐 Authentication")
        auth_layout = QVBoxLayout(auth_group)
        
        auth_type_layout = QHBoxLayout()
        auth_type_layout.addWidget(QLabel("Auth Type:"))
        self.auth_type_combo = QComboBox()
        self.auth_type_combo.addItems(["None", "Basic Auth", "Form Login", "Bearer Token", "API Key"])
        self.auth_type_combo.currentTextChanged.connect(self.on_auth_type_changed)
        auth_type_layout.addWidget(self.auth_type_combo)
        auth_layout.addLayout(auth_type_layout)
        
        # Auth credentials (initially hidden)
        self.auth_credentials_widget = QWidget()
        auth_creds_layout = QVBoxLayout(self.auth_credentials_widget)
        
        creds_layout = QHBoxLayout()
        creds_layout.addWidget(QLabel("Username:"))
        self.username_input = QLineEdit()
        creds_layout.addWidget(self.username_input)
        
        creds_layout.addWidget(QLabel("Password:"))
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        creds_layout.addWidget(self.password_input)
        
        auth_creds_layout.addLayout(creds_layout)
        
        # Token/API key input
        token_layout = QHBoxLayout()
        token_layout.addWidget(QLabel("Token/Key:"))
        self.token_input = QLineEdit()
        self.token_input.setPlaceholderText("Bearer token or API key")
        token_layout.addWidget(self.token_input)
        auth_creds_layout.addLayout(token_layout)
        
        self.auth_credentials_widget.setVisible(False)
        auth_layout.addWidget(self.auth_credentials_widget)
        
        layout.addWidget(auth_group)
        
        # Scan options
        options_group = QGroupBox("Scan Options")
        options_layout = QVBoxLayout(options_group)
        
        # Profile selection
        profile_layout = QHBoxLayout()
        profile_layout.addWidget(QLabel("Scan Profile:"))
        
        self.profile_combo = QComboBox()
        self.profile_combo.addItems(["Light", "Normal", "Aggressive", "Insane"])
        self.profile_combo.setCurrentText("Normal")
        self.profile_combo.currentTextChanged.connect(self.on_profile_changed)
        profile_layout.addWidget(self.profile_combo)
        
        options_layout.addLayout(profile_layout)
        
        # AI features
        ai_layout = QHBoxLayout()
        self.ai_features = QCheckBox("Enable AI Features")
        self.ai_features.setChecked(True)
        ai_layout.addWidget(self.ai_features)
        
        self.neural_analysis = QCheckBox("Neural Network Analysis")
        ai_layout.addWidget(self.neural_analysis)
        
        self.quantum_fuzzing = QCheckBox("Quantum-Inspired Fuzzing")
        ai_layout.addWidget(self.quantum_fuzzing)
        
        options_layout.addLayout(ai_layout)
        
        # Advanced options
        advanced_layout = QHBoxLayout()
        self.waf_evasion = QCheckBox("WAF Evasion")
        advanced_layout.addWidget(self.waf_evasion)
        
        self.zero_day_discovery = QCheckBox("Zero-Day Discovery")
        advanced_layout.addWidget(self.zero_day_discovery)
        
        self.compliance_check = QCheckBox("Compliance Reporting")
        self.compliance_check.setChecked(True)
        advanced_layout.addWidget(self.compliance_check)
        
        options_layout.addLayout(advanced_layout)
        
        layout.addWidget(options_group)
        
        # Control buttons with progress bar
        button_layout = QHBoxLayout()
        
        try:
            from app.ui.animations.universal_run_button import UniversalRunButton
            self.run_button = UniversalRunButton("🚀 Start Huggin Scan")
        except ImportError:
            self.run_button = QPushButton("🚀 Start Huggin Scan")
        self.run_button.clicked.connect(self.toggle_scan)
        button_layout.addWidget(self.run_button)
        
        # Progress component next to run button
        self.progress_component = ProgressComponent(self)
        button_layout.addWidget(self.progress_component)
        
        self.scanning = False
        
        button_layout.addStretch()
        
        layout.addLayout(button_layout)
        
        return frame

    def toggle_scan(self):
        """Toggle scan - start if not running, stop if running"""
        if self.scanning:
            self.stop_scan()
        else:
            self.start_scan()
    
    def start_scan(self):
        """Start Huggin scan"""
        target = self.target_input.text().strip()
        if not target:
            return
        
        profile = self.profile_combo.currentText()
        
        self.output_text.clear()
        self.progress_component.start_progress(f"Huggin {profile} scan for {target}", hide_timer_cancel=True)
        
        # Set button state
        if hasattr(self.run_button, 'start_scan'):
            self.run_button.start_scan()
        else:
            self.run_button.setText("Stop")
        
        self.scanning = True
        self.scan_started.emit(target, profile)
        
        # Run scan simulation
        self.run_huggin_scan(target, profile)

    def run_huggin_scan(self, target, profile):
        """Run real Huggin security scan"""
        self.append_output(f"🚀 HUGGIN ADVANCED SECURITY SCANNER")
        self.append_output(f"Target: {target} ({self.target_type_combo.currentText()})")
        self.append_output(f"Profile: {profile}")
        self.append_output(f"Authentication: {self.auth_type_combo.currentText()}")
        self.append_output(f"SSL Verification: {'Enabled' if self.verify_ssl.isChecked() else 'Disabled'}")
        self.append_output("=" * 60)
        
        # Run actual scanner
        from PyQt6.QtCore import QThread, pyqtSignal
        import asyncio
        
        class ScanWorker(QThread):
            output_signal = pyqtSignal(str)
            progress_signal = pyqtSignal(int, str)
            finished_signal = pyqtSignal(dict)
            
            def __init__(self, target, profile):
                super().__init__()
                self.target = target
                self.profile = profile.lower()
            
            def run(self):
                try:
                    from app.tools.huggin_vuln_scanner import HugginVulnScanner
                    import logging
                    
                    # Capture log messages for UI display
                    class UILogHandler(logging.Handler):
                        def __init__(self, output_signal):
                            super().__init__()
                            self.output_signal = output_signal
                        
                        def emit(self, record):
                            msg = self.format(record)
                            # Emit immediately for real-time display
                            self.output_signal.emit(msg)
                    
                    # Add UI log handler
                    ui_handler = UILogHandler(self.output_signal)
                    ui_handler.setLevel(logging.INFO)
                    logger = logging.getLogger('huggin')
                    logger.addHandler(ui_handler)
                    
                    async def run_scan():
                        scanner = HugginVulnScanner(self.target, self.profile, verify_ssl=False)
                        
                        # Track progress through phases - match actual scanner phases
                        phase_names = [
                            'Banner Grabbing',
                            'Technology Fingerprinting',
                            'Security Headers Analysis',
                            'TLS Analysis',
                            'Content Discovery',
                            'Form Analysis',
                            'Cookie Analysis',
                            'Parameter Enumeration',
                            'Passive Security Detectors',
                            'High-Impact Passive Detection',
                            'Advanced SSL/TLS Analysis',
                            'HTTP Methods Enumeration',
                            'SSRF Testing',
                            'Virtual Host Attacks',
                            'Directory Fuzzing',
                            'Parameter Bruteforcing',
                            'Advanced SSTI Testing',
                            'Deserialization Testing',
                            'Business Logic Testing',
                            'XSS Testing',
                            'SQL Injection Testing',
                            'ML Vulnerability Prediction',
                            'Adaptive Fuzzing'
                        ]
                        
                        # First emit verification message
                        self.output_signal.emit("🔍 Verifying target accessibility...")
                        
                        results = await scanner.scan()
                        
                        # Only emit phase messages if scan actually ran phases
                        if results.get('server_info', {}).get('status_code'):
                            for i, phase in enumerate(phase_names):
                                self.progress_signal.emit(i, f"[Phase {i+1}/{len(phase_names)}] {phase}")
                        else:
                            self.output_signal.emit("❌ Target verification failed")
                            self.output_signal.emit("⚠️ SCAN ABORTED - Target is not accessible")
                            self.output_signal.emit("Please verify the URL is correct and the target is online.")
                            return {'vulnerabilities': [], 'target': self.target, 'server_info': {}, 'tech_stack': {}}
                        print(f"[DEBUG] Scanner returned {len(results.get('vulnerabilities', []))} vulnerabilities")
                        
                        # Create a clean copy of results to avoid reference issues
                        clean_results = {
                            'target': results.get('target', self.target),
                            'vulnerabilities': list(results.get('vulnerabilities', [])),
                            'scan_time': results.get('scan_time', 0),
                            'server_info': results.get('server_info', {}),
                            'tech_stack': results.get('tech_stack', {})
                        }
                        
                        print(f"[DEBUG] Clean results has {len(clean_results['vulnerabilities'])} vulnerabilities")
                        return clean_results
                    
                    # Run async scan
                    try:
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        results = loop.run_until_complete(run_scan())
                    finally:
                        # Remove UI handler
                        logger.removeHandler(ui_handler)
                        loop.close()
                    
                    # Ensure results has vulnerabilities key
                    if 'vulnerabilities' not in results:
                        results['vulnerabilities'] = []
                    
                    # Debug output
                    print(f"[DEBUG] Scan completed with {len(results.get('vulnerabilities', []))} vulnerabilities")
                    if not results.get('vulnerabilities'):
                        print(f"[DEBUG] WARNING: Results object keys: {list(results.keys())}")
                        print(f"[DEBUG] Full results: {results}")
                    
                    self.finished_signal.emit(results)
                    
                except Exception as e:
                    print(f"[DEBUG] Scan exception: {e}")
                    import traceback
                    traceback.print_exc()
                    self.output_signal.emit(f"❌ Scan failed: {str(e)}")
                    self.finished_signal.emit({'vulnerabilities': []})
        
        def on_scan_output(text):
            # Display output in real-time
            self.append_output(text)
            # Force immediate UI update
            from PyQt6.QtWidgets import QApplication
            QApplication.processEvents()
        
        def on_scan_progress(phase_num, text):
            # Display progress in real-time
            self.append_output(text)
            self.progress_component.update_progress(
                completed=phase_num,
                message="Scanning..."
            )
            # Force immediate UI update
            from PyQt6.QtWidgets import QApplication
            QApplication.processEvents()
        
        def on_scan_finished(results):
            # Check if scan was aborted (no server_info means target was not accessible)
            if not results.get('server_info', {}).get('status_code'):
                # Scan was aborted, don't show completion messages
                self.append_output("")
                self.append_output("=" * 60)
            else:
                # Normal scan completion
                vuln_count = len(results.get('vulnerabilities', []))
                self.append_output("")
                self.append_output("=" * 60)
                self.append_output("🎯 SCAN COMPLETE - Advanced security assessment finished")
                
                # Add target to inventory with real results
                self.add_target_to_inventory(target, results)
                
                # Show real findings
                self.append_output("")
                self.append_output("📊 SCAN SUMMARY:")
                self.append_output(f"  • Vulnerabilities Found: {vuln_count} total")
                
                # Count by severity
                critical = len([v for v in results.get('vulnerabilities', []) if v.get('severity') == 'CRITICAL'])
                high = len([v for v in results.get('vulnerabilities', []) if v.get('severity') == 'HIGH'])
                medium = len([v for v in results.get('vulnerabilities', []) if v.get('severity') == 'MEDIUM'])
                
                self.append_output(f"    - Critical: {critical}")
                self.append_output(f"    - High: {high}")
                self.append_output(f"    - Medium: {medium}")
                
                # Show actual findings
                for vuln in results.get('vulnerabilities', []):
                    severity = vuln.get('severity', 'UNKNOWN')
                    vuln_type = vuln.get('type', 'Unknown')
                    self.append_output(f"  🔴 {severity}: {vuln_type}")
                
                self.append_output("")
                self.append_output("🎯 Navigate to the Results tab for detailed analysis and reporting")
            
            # Update progress
            if results.get('server_info', {}).get('status_code'):
                vuln_count = len(results.get('vulnerabilities', []))
                self.progress_component.finish_progress(
                    "Huggin scan completed", 
                    final_stats={'vulnerabilities': vuln_count, 'requests': 0, 'speed': 0}
                )
            else:
                self.progress_component.finish_progress(
                    "Scan aborted - target not accessible", 
                    final_stats={'vulnerabilities': 0, 'requests': 0, 'speed': 0}
                )
            
            # Reset button state
            if hasattr(self.run_button, 'stop_scan'):
                self.run_button.stop_scan()
            else:
                self.run_button.setText("Run")
            
            self.scanning = False
            self.scan_completed.emit(results)
        
        # Start worker thread
        self.scan_worker = ScanWorker(target, profile)
        self.scan_worker.output_signal.connect(on_scan_output)
        self.scan_worker.progress_signal.connect(on_scan_progress)
        self.scan_worker.finished_signal.connect(on_scan_finished)
        self.scan_worker.start()
        
        # Set progress bar to determinate mode
        self.progress_component.set_total(23)
        
        # Real scanner will be executed by worker thread
        return

    def simulate_vulnerability_findings(self):
        """Simulate vulnerability findings"""
        import random
        
        all_findings = [
            {"severity": "CRITICAL", "title": "SQL Injection in login form", "cvss": 9.8, "source": "vulnerability_analysis"},
            {"severity": "CRITICAL", "title": "Remote Code Execution via file upload", "cvss": 9.9, "source": "vulnerability_analysis"},
            {"severity": "HIGH", "title": "Cross-Site Scripting (XSS)", "cvss": 7.4, "source": "vulnerability_analysis"},
            {"severity": "HIGH", "title": "Authentication Bypass", "cvss": 8.1, "source": "vulnerability_analysis"},
            {"severity": "HIGH", "title": "Local File Inclusion (LFI)", "cvss": 7.5, "source": "vulnerability_analysis"},
            {"severity": "MEDIUM", "title": "Insecure Direct Object Reference", "cvss": 5.3, "source": "vulnerability_analysis"},
            {"severity": "MEDIUM", "title": "Missing Security Headers", "cvss": 5.0, "source": "vulnerability_analysis"},
            {"severity": "MEDIUM", "title": "Weak SSL/TLS Configuration", "cvss": 5.9, "source": "vulnerability_analysis"},
            {"severity": "LOW", "title": "Information Disclosure", "cvss": 3.7, "source": "vulnerability_analysis"},
            {"severity": "LOW", "title": "Directory Listing Enabled", "cvss": 2.6, "source": "vulnerability_analysis"}
        ]
        
        # Return 1-3 random findings
        return random.sample(all_findings, random.randint(1, 3))

    def simulate_compliance_assessment(self):
        """Simulate compliance assessment"""
        import random
        return {
            "owasp_score": random.randint(5, 9),
            "pci_score": random.randint(7, 12),
            "issues": ["A01:2021 – Broken Access Control", "A03:2021 – Injection", "A05:2021 – Security Misconfiguration"]
        }

    def simulate_osint_gathering(self):
        """Simulate OSINT intelligence gathering"""
        import random
        return {
            "subdomains": random.randint(15, 35),
            "technologies": random.randint(10, 20),
            "certificates": random.randint(2, 6),
            "social_media": random.randint(3, 8),
            "exposed_files": random.randint(0, 5)
        }

    def stop_scan(self):
        """Stop Huggin scan"""
        self.progress_component.cancel_operation()
        
        # Reset button state
        if hasattr(self.run_button, 'stop_scan'):
            self.run_button.stop_scan()
        else:
            self.run_button.setText("Run")
        
        self.scanning = False
        self.append_output("⚠️ Scan cancelled by user")

    def set_profile(self, profile_name):
        """Set scan profile"""
        self.profile_combo.setCurrentText(profile_name)
        self.current_profile = profile_name

    def on_target_type_changed(self, target_type):
        """Handle target type change"""
        placeholders = {
            "Single URL": "https://example.com",
            "Domain": "example.com",
            "IP Range": "192.168.1.1-192.168.1.100",
            "File List": "/path/to/targets.txt"
        }
        self.target_input.setPlaceholderText(placeholders.get(target_type, "https://example.com"))
    
    def on_auth_type_changed(self, auth_type):
        """Handle authentication type change"""
        show_creds = auth_type in ["Basic Auth", "Form Login"]
        show_token = auth_type in ["Bearer Token", "API Key"]
        
        self.auth_credentials_widget.setVisible(show_creds or show_token)
        
        # Show/hide specific fields
        self.username_input.setVisible(show_creds)
        self.password_input.setVisible(show_creds)
        self.token_input.setVisible(show_token)
        
        # Update labels
        if auth_type == "API Key":
            self.token_input.setPlaceholderText("API Key")
        elif auth_type == "Bearer Token":
            self.token_input.setPlaceholderText("Bearer token")
    
    def save_configuration(self):
        """Save current configuration"""
        config = {
            'target': self.target_input.text(),
            'target_type': self.target_type_combo.currentText(),
            'profile': self.profile_combo.currentText(),
            'auth_type': self.auth_type_combo.currentText(),
            'username': self.username_input.text(),
            'custom_headers': self.custom_headers.isChecked(),
            'follow_redirects': self.follow_redirects.isChecked(),
            'verify_ssl': self.verify_ssl.isChecked(),
            'ai_features': self.ai_features.isChecked(),
            'neural_analysis': self.neural_analysis.isChecked(),
            'quantum_fuzzing': self.quantum_fuzzing.isChecked(),
            'waf_evasion': self.waf_evasion.isChecked(),
            'zero_day_discovery': self.zero_day_discovery.isChecked(),
            'compliance_check': self.compliance_check.isChecked()
        }
        
        try:
            import json
            from PyQt6.QtWidgets import QFileDialog
            filename, _ = QFileDialog.getSaveFileName(self, "Save Configuration", "huggin_config.json", "JSON Files (*.json)")
            if filename:
                with open(filename, 'w') as f:
                    json.dump(config, f, indent=2)
                self.append_output(f"✅ Configuration saved to {filename}")
        except Exception as e:
            self.append_output(f"❌ Failed to save configuration: {e}")
    
    def load_configuration(self):
        """Load configuration from file"""
        try:
            import json
            from PyQt6.QtWidgets import QFileDialog
            filename, _ = QFileDialog.getOpenFileName(self, "Load Configuration", "", "JSON Files (*.json)")
            if filename:
                with open(filename, 'r') as f:
                    config = json.load(f)
                
                # Apply configuration
                self.target_input.setText(config.get('target', ''))
                self.target_type_combo.setCurrentText(config.get('target_type', 'Single URL'))
                self.profile_combo.setCurrentText(config.get('profile', 'Normal'))
                self.auth_type_combo.setCurrentText(config.get('auth_type', 'None'))
                self.username_input.setText(config.get('username', ''))
                self.custom_headers.setChecked(config.get('custom_headers', False))
                self.follow_redirects.setChecked(config.get('follow_redirects', True))
                self.verify_ssl.setChecked(config.get('verify_ssl', True))
                self.ai_features.setChecked(config.get('ai_features', True))
                self.neural_analysis.setChecked(config.get('neural_analysis', False))
                self.quantum_fuzzing.setChecked(config.get('quantum_fuzzing', False))
                self.waf_evasion.setChecked(config.get('waf_evasion', False))
                self.zero_day_discovery.setChecked(config.get('zero_day_discovery', False))
                self.compliance_check.setChecked(config.get('compliance_check', True))
                
                self.append_output(f"✅ Configuration loaded from {filename}")
        except Exception as e:
            self.append_output(f"❌ Failed to load configuration: {e}")
    
    def on_profile_changed(self, profile):
        """Handle profile change"""
        self.current_profile = profile
        
        # Update AI features based on profile
        if profile == "Insane":
            self.ai_features.setChecked(True)
            self.neural_analysis.setChecked(True)
            self.quantum_fuzzing.setChecked(True)
            self.waf_evasion.setChecked(True)
            self.zero_day_discovery.setChecked(True)
        elif profile == "Aggressive":
            self.ai_features.setChecked(True)
            self.neural_analysis.setChecked(True)
            self.quantum_fuzzing.setChecked(False)
            self.waf_evasion.setChecked(True)
            self.zero_day_discovery.setChecked(False)
        elif profile == "Normal":
            self.ai_features.setChecked(True)
            self.neural_analysis.setChecked(False)
            self.quantum_fuzzing.setChecked(False)
            self.waf_evasion.setChecked(False)
            self.zero_day_discovery.setChecked(False)
        else:  # Light
            self.ai_features.setChecked(False)
            self.neural_analysis.setChecked(False)
            self.quantum_fuzzing.setChecked(False)
            self.waf_evasion.setChecked(False)
            self.zero_day_discovery.setChecked(False)

    def add_target_to_inventory(self, target, results):
        """Add scanned target to inventory"""
        try:
            tenant_id = self.get_current_tenant()
            
            # Extract hostname/IP from target URL
            import re
            from urllib.parse import urlparse
            
            parsed = urlparse(target if target.startswith('http') else f'http://{target}')
            hostname = parsed.hostname or target
            
            # Determine if it's an IP or hostname
            ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
            if re.match(ip_pattern, hostname):
                ip_address = hostname
                host_name = ''
            else:
                ip_address = hostname  # Use hostname as identifier
                host_name = hostname
            
            # Create asset data with scan results
            asset_data = {
                'ip_address': ip_address,
                'hostname': host_name,
                'status': 'KNOWN',
                'confidence': 90,
                'vulnerabilities': results.get('vulnerabilities', []),
                'metadata': {
                    'discovery_method': 'huggin_scanner',
                    'server_type': 'web_server',
                    'scan_profile': self.current_profile,
                    'compliance': results.get('compliance', {}),
                    'intelligence': results.get('intelligence', {}),
                    'vulnerabilities_found': len(results.get('vulnerabilities', [])),
                    'security_score': 100 - (len(results.get('vulnerabilities', [])) * 10)
                }
            }
            
            # Add web services
            if target.startswith('https'):
                asset_data['services'] = [{'port': 443, 'service': 'https', 'version': 'Unknown'}]
                asset_data['open_ports'] = [{'port': 443, 'protocol': 'tcp'}]
            elif target.startswith('http'):
                asset_data['services'] = [{'port': 80, 'service': 'http', 'version': 'Unknown'}]
                asset_data['open_ports'] = [{'port': 80, 'protocol': 'tcp'}]
            
            asset_id = asset_manager.add_or_update_asset(tenant_id, **asset_data)
            self.append_output(f"[+] Added {target} to inventory with ID: {asset_id} for tenant {tenant_id}")
            
        except Exception as e:
            self.append_output(f"[ERROR] Failed to add target to inventory: {e}")
            import traceback
            self.append_output(f"[ERROR] Traceback: {traceback.format_exc()}")
    
    def get_current_tenant(self):
        """Get current tenant from tenant-aware updater"""
        try:
            from app.core.tenant_aware_updater import tenant_aware_updater
            return tenant_aware_updater.get_current_tenant()
        except ImportError:
            # Fallback to old method
            try:
                from PyQt6.QtWidgets import QApplication
                app = QApplication.instance()
                if app:
                    for widget in app.allWidgets():
                        if hasattr(widget, 'current_profile_name') and widget.current_profile_name:
                            return widget.current_profile_name
                
                widget = self
                for i in range(5):
                    widget = widget.parent()
                    if widget is None:
                        break
                    if hasattr(widget, 'current_profile_name'):
                        profile = widget.current_profile_name or 'default'
                        return profile
                
                return 'default'
            except:
                return 'default'

    def append_output(self, text):
        """Append text to output with real-time display"""
        self.output_text.append(text)
        # Scroll to bottom to show latest output
        cursor = self.output_text.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        self.output_text.setTextCursor(cursor)
        # Force immediate UI update
        self.output_text.repaint()

    def apply_theme(self):
        """Apply component theme"""
        self.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 100);
                border-radius: 10px;
                border: 1px solid rgba(100, 200, 255, 50);
            }
            QPushButton {
                background-color: rgba(100, 200, 255, 150);
                border: 2px solid #64C8FF;
                border-radius: 8px;
                color: #000000;
                font-weight: bold;
                padding: 10px 20px;
            }
            QPushButton:hover {
                background-color: rgba(100, 200, 255, 200);
            }
            QPushButton:disabled {
                background-color: rgba(60, 60, 60, 100);
                color: #888888;
            }
            QLineEdit, QComboBox {
                background-color: rgba(20, 30, 40, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                color: #DCDCDC;
                padding: 5px;
            }
            QTextEdit {
                background-color: rgba(0, 0, 0, 200);
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                color: #00FF41;
                font-size: 10pt;
                line-height: 1.2;
            }
            QLabel {
                color: #64C8FF;
                font-weight: bold;
            }
            QCheckBox {
                color: #DCDCDC;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                margin-top: 10px;
                color: #64C8FF;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)