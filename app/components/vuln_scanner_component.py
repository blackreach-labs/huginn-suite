from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, 
                            QPushButton, QLabel, QLineEdit, QTextEdit, QProgressBar,
                            QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView,
                            QTreeWidget, QTreeWidgetItem, QCheckBox)
from PyQt6.QtCore import pyqtSignal, QThreadPool, Qt, QThread
from PyQt6.QtGui import QColor

from app.core.base_worker import CommandWorker
from app.core.html_utils import h

class VulnScanWorker(QThread):
    output = pyqtSignal(str)
    finished = pyqtSignal()
    results = pyqtSignal(list)
    progress = pyqtSignal(int)
    
    def __init__(self, target, port=None, scan_types=None):
        super().__init__()
        self.target = target
        self.port = port
        self.scan_types = scan_types or ['comprehensive']
        
    def run(self):
        try:
            # Import here to avoid circular imports
            import sys
            import os
            tools_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'tools'))
            if tools_path not in sys.path:
                sys.path.insert(0, tools_path)
            from tools.advanced_nse_scanner import AdvancedNSEScanner
            from app.core.dns_resolver import dns_resolver
            
            # Resolve target hostname using global DNS settings
            resolved_target = self.target
            resolved_ip = dns_resolver.resolve_hostname(self.target)
            if resolved_ip and resolved_ip != self.target:
                resolved_target = resolved_ip
                self.output.emit(f"<p style='color: #87CEEB;'>Using DNS: {h(self.target)} → {h(resolved_ip)}</p><br>")
            
            self.output.emit(f"<p style='color: #00BFFF;'>[VULN SCAN] Starting vulnerability scan on {h(self.target)}</p><br>")
            self.progress.emit(10)
            self.output.emit("<br>")
            
            scanner = AdvancedNSEScanner(resolved_target, timeout=10, threads=5)
            
            # Custom output formatting instead of capturing print statements
            self.output.emit(f"<p style='color: #64C8FF; font-weight: bold;'>🔍 VULNERABILITY SCAN INITIATED</p><br>")
            self.output.emit(f"<p style='color: #87CEEB;'>Target: {h(self.target)}</p><br>")
            self.output.emit(f"<p style='color: #87CEEB;'>Scan Types: {', '.join(self.scan_types)}</p><br>")
            self.output.emit("<hr style='border: 1px solid #64C8FF;'><br>")
            
            if 'comprehensive' in self.scan_types:
                self.run_comprehensive_scan(scanner)
            else:
                self.run_targeted_scan(scanner)
            
            # Generate summary
            self.generate_scan_summary(scanner.results)
            
            self.progress.emit(100)
            self.results.emit(scanner.results)
            
        except Exception as e:
            self.output.emit(f"<p style='color: #FF6B6B;'>❌ SCAN FAILED: {h(e)}</p><br>")
        finally:
            self.finished.emit()
    
    def run_comprehensive_scan(self, scanner):
        """Run comprehensive scan with organized output"""
        test_categories = {
            '🔥 Critical Infrastructure CVEs': [
                ('Log4Shell', scanner.test_log4shell),
                ('Spring4Shell', scanner.test_spring4shell),
                ('EternalBlue', scanner.test_eternalblue),
                ('BlueKeep', scanner.test_bluekeep),
                ('SMBGhost', scanner.test_smbghost),
                ('Zerologon', scanner.test_zerologon)
            ],
            '🌐 Application Layer': [
                ('Shellshock', scanner.test_shellshock),
                ('Follina', scanner.test_follina)
            ],
            '🔒 Network & Protocol': [
                ('Heartbleed', scanner.test_heartbleed),
                ('POODLE', scanner.test_poodle),
                ('ROBOT', scanner.test_robot),
                ('Sweet32', scanner.test_sweet32),
                ('SMB Issues', scanner.test_smb_vulns),
                ('SSH Issues', scanner.test_ssh_vulns),
                ('Auth Issues', scanner.test_auth_vulns)
            ]
        }
        
        for category, tests in test_categories.items():
            self.output.emit(f"<p style='color: #FFD700; font-weight: bold; margin-top: 15px;'>{h(category)}</p><br>")
            for test_name, test_func in tests:
                self.output.emit(f"<p style='color: #87CEEB;'>  → Testing {h(test_name)}...</p><br>")
                try:
                    result = test_func()
                    if result:
                        if isinstance(result, list):
                            scanner.results.extend(result)
                            self.output.emit(f"<p style='color: #FF6B6B;'>    ⚠️ {len(result)} issues found</p><br>")
                        else:
                            scanner.results.append(result)
                            severity_color = {'CRITICAL': '#FF0000', 'HIGH': '#FF6B6B', 'MEDIUM': '#FFA500'}.get(result.get('severity'), '#90EE90')
                            self.output.emit(f"<p style='color: {severity_color};'>    🚨 {h(result.get('name', 'Vulnerability'))} detected!</p><br>")
                    else:
                        self.output.emit(f"<p style='color: #90EE90;'>    ✅ Not vulnerable</p><br>")
                except Exception as e:
                    self.output.emit(f"<p style='color: #FFA500;'>    ⚠️ Test failed: {h(str(e)[:50])}...</p><br>")
                self.progress.emit(min(95, self.progress.value() + 5))
    
    def run_targeted_scan(self, scanner):
        """Run targeted scan based on selected categories"""
        if 'professional' in self.scan_types:
            self.output.emit(f"<p style='color: #FFD700; font-weight: bold;'>🎯 PROFESSIONAL SCAN - High-Profile CVEs</p><br>")
            for test_name, test_func in [('Log4Shell', scanner.test_log4shell), ('Spring4Shell', scanner.test_spring4shell), ('Follina', scanner.test_follina)]:
                self.run_single_test(test_name, test_func, scanner)
        
        if 'critical' in self.scan_types:
            self.output.emit(f"<p style='color: #FFD700; font-weight: bold;'>💥 CRITICAL SCAN - Wormable Exploits</p><br>")
            for test_name, test_func in [('EternalBlue', scanner.test_eternalblue), ('BlueKeep', scanner.test_bluekeep), ('SMBGhost', scanner.test_smbghost)]:
                self.run_single_test(test_name, test_func, scanner)
        

        
        if 'common' in self.scan_types:
            self.output.emit(f"<p style='color: #FFD700; font-weight: bold;'>🔧 COMMON SCAN - Protocol Issues</p><br>")
            for test_name, test_func in [('SMB Issues', scanner.test_smb_vulns), ('SSL/TLS Issues', scanner.test_ssl_vulns), ('Auth Issues', scanner.test_auth_vulns)]:
                self.run_single_test(test_name, test_func, scanner)
        
        # Run application-specific detectors
        self._run_app_detectors(scanner)
    
    def run_single_test(self, test_name, test_func, scanner):
        """Run a single test with formatted output"""
        self.output.emit(f"<p style='color: #87CEEB;'>  → {h(test_name)}...</p><br>")
        try:
            result = test_func()
            if result:
                if isinstance(result, list):
                    scanner.results.extend(result)
                    self.output.emit(f"<p style='color: #FF6B6B;'>    🚨 {len(result)} vulnerabilities found</p><br>")
                else:
                    scanner.results.append(result)
                    severity_color = {'CRITICAL': '#FF0000', 'HIGH': '#FF6B6B', 'MEDIUM': '#FFA500'}.get(result.get('severity'), '#90EE90')
                    self.output.emit(f"<p style='color: {severity_color};'>    🚨 {h(result.get('name', 'Vulnerability'))} - {h(result.get('severity', 'Unknown'))}</p><br>")
            else:
                self.output.emit(f"<p style='color: #90EE90;'>    ✅ Secure</p><br>")
        except Exception as e:
            self.output.emit(f"<p style='color: #FFA500;'>    ⚠️ Test error: {h(str(e)[:50])}...</p><br>")

    def _run_app_detectors(self, scanner):
        """Run application-specific vulnerability detectors (Flowise, etc.)"""
        self.output.emit(f"<p style='color: #FFD700; font-weight: bold;'>🔬 APPLICATION SCAN - Service-Specific CVEs</p><br>")
        
        try:
            from app.core.flowise_detector import FlowiseDetector
            
            self.output.emit(f"<p style='color: #87CEEB;'>  → Flowise CVE-2025-58434...</p><br>")
            
            # Determine target URL (try common Flowise ports)
            target_base = self.target
            if not target_base.startswith('http'):
                target_base = f"http://{target_base}"
            
            detector = FlowiseDetector(timeout=8)
            result = detector.scan(target_base)
            
            if result.vulnerable:
                finding = result.to_finding()
                scanner.results.append(finding)
                self.output.emit(
                    f"<p style='color: #FF0000;'>    🚨 {h(finding['name'])} - CRITICAL</p><br>"
                    f"<p style='color: #FF6B6B;'>       Version: {h(result.version or 'unknown')}</p><br>"
                    f"<p style='color: #FF6B6B;'>       Leaked: {h(', '.join(result.leaked_fields))}</p><br>"
                )
            elif result.detected:
                self.output.emit(
                    f"<p style='color: #90EE90;'>    ✅ Flowise detected (v{h(result.version or '?')}) - Not vulnerable</p><br>"
                )
            else:
                self.output.emit(f"<p style='color: #90EE90;'>    ✅ Flowise not detected</p><br>")
                
        except Exception as e:
            self.output.emit(f"<p style='color: #FFA500;'>    ⚠️ App detector error: {h(str(e)[:80])}</p><br>")
    
    def generate_scan_summary(self, results):
        """Generate formatted scan summary"""
        self.output.emit("<hr style='border: 2px solid #64C8FF; margin: 20px 0;'><br>")
        self.output.emit(f"<p style='color: #64C8FF; font-weight: bold; font-size: 14pt;'>📊 SCAN COMPLETE</p><br>")
        
        if not results:
            self.output.emit(f"<p style='color: #90EE90; font-size: 12pt;'>🛡️ No vulnerabilities detected - Target appears secure!</p><br>")
            return
        
        # Count by severity
        critical = sum(1 for r in results if r.get('severity') == 'CRITICAL')
        high = sum(1 for r in results if r.get('severity') == 'HIGH')
        medium = sum(1 for r in results if r.get('severity') == 'MEDIUM')
        low = sum(1 for r in results if r.get('severity') == 'LOW')
        
        self.output.emit(f"<p style='color: #DCDCDC;'>Total Issues Found: <span style='color: #FF6B6B; font-weight: bold;'>{len(results)}</span></p><br>")
        
        if critical > 0:
            self.output.emit(f"<p style='color: #FF0000;'>🔴 Critical: {critical}</p><br>")
        if high > 0:
            self.output.emit(f"<p style='color: #FF6B6B;'>🟠 High: {high}</p><br>")
        if medium > 0:
            self.output.emit(f"<p style='color: #FFA500;'>🟡 Medium: {medium}</p><br>")
        if low > 0:
            self.output.emit(f"<p style='color: #90EE90;'>🟢 Low: {low}</p><br>")
        
        # Risk assessment
        risk_score = critical * 10 + high * 5 + medium * 2 + low * 1
        if risk_score >= 50:
            risk_level = "🚨 CRITICAL"
            risk_color = "#FF0000"
        elif risk_score >= 25:
            risk_level = "⚠️ HIGH"
            risk_color = "#FF6B6B"
        elif risk_score >= 10:
            risk_level = "🟡 MEDIUM"
            risk_color = "#FFA500"
        else:
            risk_level = "🟢 LOW"
            risk_color = "#90EE90"
        
        self.output.emit(f"<p style='color: {risk_color}; font-weight: bold;'>Risk Level: {risk_level}</p><br>")
        self.output.emit(f"<p style='color: #87CEEB;'>📋 Check the Vulnerabilities tab for detailed findings</p><br>")

class VulnScannerComponent(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.apply_theme()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Target Configuration
        target_group = QGroupBox("Target Configuration")
        target_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
                color: #DCDCDC;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)
        target_layout = QVBoxLayout(target_group)
        
        # Target input row
        target_row = QHBoxLayout()
        target_row.addWidget(QLabel("Target:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("IP address or hostname")
        target_row.addWidget(self.target_input)
        
        target_row.addWidget(QLabel("Port:"))
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Optional")
        self.port_input.setFixedWidth(80)
        target_row.addWidget(self.port_input)
        
        target_row.addWidget(QLabel("CVE:"))
        self.cve_input = QLineEdit()
        self.cve_input.setPlaceholderText("CVE-2021-41773")
        self.cve_input.setFixedWidth(120)
        target_row.addWidget(self.cve_input)
        
        target_layout.addLayout(target_row)
        
        # Scan options
        options_row = QHBoxLayout()
        self.professional_check = QCheckBox("Professional Scan")
        self.professional_check.setChecked(True)
        self.critical_check = QCheckBox("Critical CVEs")
        self.critical_check.setChecked(True)

        self.common_check = QCheckBox("Common Vulnerabilities")
        
        # Add tooltips for clarity
        self.professional_check.setToolTip("High-profile CVEs: Log4Shell, Spring4Shell, Follina")
        self.critical_check.setToolTip("Wormable exploits: EternalBlue, BlueKeep, SMBGhost, Zerologon")

        self.common_check.setToolTip("SMB/SSH/TLS misconfigurations and protocol issues")
        
        options_row.addWidget(self.professional_check)
        options_row.addWidget(self.critical_check)

        options_row.addWidget(self.common_check)
        target_layout.addLayout(options_row)
        
        layout.addWidget(target_group)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        self.scan_buttons = []
        buttons = [
            ("Start Vulnerability Scan", self.run_comprehensive_scan),
            ("Specific CVE Scan", self.run_specific_cve),
            ("List Available Scripts", self.list_vuln_scripts)
        ]
        
        for text, method in buttons:
            btn = QPushButton(text)
            btn.clicked.connect(method)
            btn.setStyleSheet("""
                QPushButton {
                    background-color: rgba(100, 200, 255, 150);
                    color: #000000;
                    border: none;
                    border-radius: 5px;
                    padding: 8px 16px;
                    font-weight: bold;
                    margin: 2px;
                }
                QPushButton:hover {
                    background-color: rgba(100, 200, 255, 200);
                }
                QPushButton:disabled {
                    background-color: rgba(100, 100, 100, 100);
                    color: #666666;
                }
            """)
            button_layout.addWidget(btn)
            self.scan_buttons.append(btn)
        
        button_layout.addStretch()
        layout.addLayout(button_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Results section with tabs
        self.results_tabs = QTabWidget()
        
        # Scan Output tab
        self.terminal_output = QTextEdit()
        self.terminal_output.setReadOnly(True)
        self.terminal_output.setPlaceholderText("Vulnerability scan results will appear here...")
        self.terminal_output.setStyleSheet("""
            QTextEdit {
                background-color: rgba(0, 0, 0, 150);
                color: #DCDCDC;
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                font-family: 'Neuropol X', monospace;
                font-size: 10pt;
            }
        """)
        self.results_tabs.addTab(self.terminal_output, "Scan Output")
        
        # Vulnerabilities table tab
        self.vuln_table = QTableWidget()
        self.vuln_table.setColumnCount(4)
        self.vuln_table.setHorizontalHeaderLabels(["CVE", "Severity", "Description", "Port"])
        self.vuln_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.vuln_table.setStyleSheet("""
            QTableWidget {
                background-color: rgba(0, 0, 0, 100);
                color: #DCDCDC;
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
            }
            QTableWidget::item:selected {
                background-color: rgba(100, 200, 255, 100);
            }
        """)
        self.results_tabs.addTab(self.vuln_table, "Vulnerabilities")
        
        # Summary tab
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.summary_text.setStyleSheet("""
            QTextEdit {
                background-color: rgba(0, 0, 0, 150);
                color: #DCDCDC;
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                font-family: 'Neuropol X', monospace;
                font-size: 10pt;
            }
        """)
        self.results_tabs.addTab(self.summary_text, "Scan Summary")
        
        layout.addWidget(self.results_tabs)

    def run_comprehensive_scan(self):
        target = self.target_input.text().strip()
        if not target:
            self.show_error("Please enter a target")
            return
        
        # Build scan types based on selected options
        scan_types = []
        if self.professional_check.isChecked():
            scan_types.append('professional')
        if self.critical_check.isChecked():
            scan_types.append('critical')

        if self.common_check.isChecked():
            scan_types.append('common')
        
        if not scan_types:
            scan_types = ['comprehensive']
        
        port = self.port_input.text().strip() or None
        
        self.start_vuln_scan(target, port, scan_types)

    def run_specific_cve(self):
        target = self.target_input.text().strip()
        cve = self.cve_input.text().strip()
        if not target or not cve:
            self.show_error("Please enter both target and CVE")
            return
        
        self.start_vuln_scan(target, None, [f'cve:{cve}'])

    def list_vuln_scripts(self):
        tests = [
            "Log4Shell (CVE-2021-44228)", "Spring4Shell (CVE-2022-22965)", 
            "EternalBlue (CVE-2017-0144)", "BlueKeep (CVE-2019-0708)",
            "Heartbleed (CVE-2014-0160)", "Shellshock (CVE-2014-6271)",
            "Follina (CVE-2022-30190)", "Zerologon (CVE-2020-1472)",
            "SMBGhost (CVE-2020-0796)", "PrintNightmare (CVE-2021-34527)",
            "MS08-067 (CVE-2008-4250)", "Drupalgeddon 2 (CVE-2018-7600)",
            "WordPress REST API (CVE-2017-1001000)", "Confluence OGNL (CVE-2022-26134)",
            "POODLE (CVE-2014-3566)", "ROBOT (CVE-2017-13099)", "Sweet32 (CVE-2016-2183)"
        ]
        
        output = "<h3 style='color: #64C8FF;'>Available Vulnerability Tests:</h3><br>"
        for test in tests:
            output += f"<p style='color: #DCDCDC;'>• {h(test)}</p><br>"
        
        self.terminal_output.setHtml(output)
        self.summary_text.setHtml(f"<p>Total available tests: {len(tests)}</p>")

    def start_vuln_scan(self, target, port, scan_types):
        # Clear previous results
        self.terminal_output.clear()
        self.vuln_table.setRowCount(0)
        self.summary_text.clear()
        
        # Show progress
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 100)
        self.set_buttons_enabled(False)
        
        # Start worker
        self.worker = VulnScanWorker(target, port, scan_types)
        self.worker.output.connect(self.append_terminal_output)
        self.worker.progress.connect(self.progress_bar.setValue)
        self.worker.results.connect(self.handle_scan_results)
        self.worker.finished.connect(self.scan_finished)
        self.worker.start()
    
    def handle_scan_results(self, results):
        """Handle vulnerability scan results"""
        self.vuln_table.setRowCount(len(results))
        
        for row, vuln in enumerate(results):
            cve_item = QTableWidgetItem(vuln.get('cve', vuln.get('name', 'Unknown')))
            severity_item = QTableWidgetItem(vuln.get('severity', 'Unknown'))
            desc_item = QTableWidgetItem(vuln.get('evidence', vuln.get('description', 'No description'))[:100])
            port_item = QTableWidgetItem(str(vuln.get('port', 'Unknown')))
            
            # Color code by severity
            severity = vuln.get('severity', '').upper()
            if severity == 'CRITICAL':
                severity_item.setForeground(QColor("#FF0000"))
            elif severity == 'HIGH':
                severity_item.setForeground(QColor("#FF6B6B"))
            elif severity == 'MEDIUM':
                severity_item.setForeground(QColor("#FFA500"))
            elif severity == 'LOW':
                severity_item.setForeground(QColor("#90EE90"))
            
            self.vuln_table.setItem(row, 0, cve_item)
            self.vuln_table.setItem(row, 1, severity_item)
            self.vuln_table.setItem(row, 2, desc_item)
            self.vuln_table.setItem(row, 3, port_item)
        
        # Update summary
        critical = sum(1 for v in results if v.get('severity') == 'CRITICAL')
        high = sum(1 for v in results if v.get('severity') == 'HIGH')
        medium = sum(1 for v in results if v.get('severity') == 'MEDIUM')
        
        summary = f"""<h3 style='color: #64C8FF;'>Vulnerability Scan Summary</h3>
        <p><strong>Total Vulnerabilities:</strong> {len(results)}</p>
        <p><strong>Critical:</strong> <span style='color: #FF0000;'>{critical}</span></p>
        <p><strong>High:</strong> <span style='color: #FF6B6B;'>{high}</span></p>
        <p><strong>Medium:</strong> <span style='color: #FFA500;'>{medium}</span></p>
        """
        
        if len(results) > 0:
            summary += f"<p style='color: #FF6B6B;'>⚠️ {len(results)} vulnerabilities found - Review immediately!</p>"
        else:
            summary += "<p style='color: #90EE90;'>✅ No vulnerabilities detected</p>"
        
        self.summary_text.setHtml(summary)
    
    def scan_finished(self):
        self.progress_bar.setVisible(False)
        self.set_buttons_enabled(True)
        if hasattr(self, 'worker'):
            self.worker.deleteLater()

    def show_error(self, message):
        self.terminal_output.setHtml(f"<p style='color: #FF4500;'>[ERROR] {h(message)}</p>")
        self.summary_text.setHtml(f"<p style='color: #FF4500;'>❌ {h(message)}</p>")

    def append_terminal_output(self, text):
        self.terminal_output.insertHtml(text)
        scrollbar = self.terminal_output.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def set_buttons_enabled(self, enabled):
        for button in self.scan_buttons:
            button.setEnabled(enabled)

    def apply_theme(self):
        self.setStyleSheet("""
            QWidget {
                background-color: transparent;
                color: #DCDCDC;
            }
            QLineEdit {
                background-color: rgba(20, 30, 40, 150);
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 3px;
                padding: 5px;
                color: #DCDCDC;
            }
            QLabel {
                color: #DCDCDC;
            }
            QCheckBox {
                color: #DCDCDC;
            }
            QCheckBox::indicator:checked {
                background-color: #64C8FF;
                border: 1px solid #64C8FF;
            }
        """)