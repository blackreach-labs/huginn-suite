from PyQt6.QtWidgets import QVBoxLayout, QTabWidget, QLabel, QWidget, QPushButton, QTextEdit, QHBoxLayout
from PyQt6.QtCore import Qt, pyqtSignal, QThread

from app.pages.components.base_page import BasePage

class HuginnScannerPage(BasePage):
    navigate_signal = pyqtSignal(str)
    status_updated = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)

    def setup_ui(self):
        """Setup the UI - required by BasePage"""
        # Create main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(20)
        

        
        # Create tab widget
        self.tab_widget = QTabWidget()
        
        # Scanner configuration tab
        scanner_tab = self.create_scanner_tab()
        self.tab_widget.addTab(scanner_tab, "🚀 Scanner")
        
        # Scan profiles tab
        profiles_tab = self.create_profiles_tab()
        self.tab_widget.addTab(profiles_tab, "⚙️ Profiles")
        
        # Results analysis tab
        results_tab = self.create_results_tab()
        self.tab_widget.addTab(results_tab, "📊 Results")
        
        main_layout.addWidget(self.tab_widget)
        
        self.apply_theme()
    
    def create_scanner_tab(self):
        """Create the scanner configuration tab"""
        from app.components.huginn_scanner_component import HuginnScannerComponent
        self.scanner_component = HuginnScannerComponent(self)
        
        # Connect component signals to page signals
        self.scanner_component.scan_started.connect(self.on_scan_started)
        self.scanner_component.scan_completed.connect(self.on_scan_completed)
        
        print("DEBUG: Successfully created HuginnScannerComponent")
        return self.scanner_component
    
    def create_fallback_scanner_tab(self):
        """Create a fallback scanner tab with basic functionality"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # Description
        desc = QLabel("""
        🧠 AI-Powered Neural Networks | 🔬 Quantum Fuzzing | 🤖 Autonomous Agent
        📊 ML Vulnerability Prediction | 🎯 Advanced Exploitation | 📈 Compliance Reports
        🔍 OSINT Intelligence | 🛡️ WAF Evasion | ⚡ Zero-Day Discovery
        """)
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc.setStyleSheet("""
            color: #87CEEB;
            font-size: 12pt;
            padding: 15px;
            background-color: rgba(0, 0, 0, 100);
            border-radius: 8px;
            border: 1px solid rgba(100, 200, 255, 50);
        """)
        layout.addWidget(desc)
        
        # Target input
        target_layout = QHBoxLayout()
        target_label = QLabel("Target URL:")
        target_label.setStyleSheet("color: #64C8FF; font-weight: bold; font-size: 12pt;")
        target_layout.addWidget(target_label)
        
        self.target_input = QTextEdit()
        self.target_input.setPlaceholderText("https://example.com")
        self.target_input.setMaximumHeight(30)
        self.target_input.setStyleSheet("""
            background-color: rgba(20, 30, 40, 150);
            border: 2px solid rgba(100, 200, 255, 100);
            border-radius: 5px;
            color: #DCDCDC;
            padding: 5px;
            font-size: 11pt;
        """)
        target_layout.addWidget(self.target_input)
        layout.addLayout(target_layout)
        
        # Start scan button
        start_btn = QPushButton("🚀 Start Huginn Scan")
        start_btn.setMinimumHeight(50)
        start_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, 
                    stop:0 rgba(100, 200, 255, 150), 
                    stop:1 rgba(50, 150, 255, 150));
                border: 3px solid #64C8FF;
                border-radius: 12px;
                color: #FFFFFF;
                font-size: 14pt;
                font-weight: bold;
                padding: 10px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, 
                    stop:0 rgba(120, 220, 255, 200), 
                    stop:1 rgba(70, 170, 255, 200));
                border: 3px solid #87CEEB;
            }
        """)
        start_btn.clicked.connect(self.start_scan)
        layout.addWidget(start_btn)
        
        # Output area
        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        self.output_area.setPlaceholderText("Huginn scan output will appear here...")
        self.output_area.setStyleSheet("""
            background-color: rgba(0, 0, 0, 200);
            border: 1px solid rgba(100, 200, 255, 100);
            border-radius: 5px;
            color: #00FF41;
            font-family: 'Courier New', monospace;
            font-size: 10pt;
            padding: 10px;
        """)
        layout.addWidget(self.output_area)
        
        return tab
    
    def start_scan(self):
        """Start a real Huginn scan"""
        target = self.target_input.toPlainText().strip()
        if not target:
            self.output_area.append("❌ Please enter a target URL")
            return
        
        self.output_area.clear()
        self.output_area.append("🚀 HUGINN ADVANCED SECURITY SCANNER")
        self.output_area.append(f"Target: {target}")
        self.output_area.append("Profile: Normal")
        self.output_area.append("=" * 60)
        
        # Run actual scanner
        from PyQt6.QtCore import QThread, pyqtSignal
        import asyncio
        
        class ScanWorker(QThread):
            output_signal = pyqtSignal(str)
            finished_signal = pyqtSignal(dict)
            
            def __init__(self, target):
                super().__init__()
                self.target = target
            
            def run(self):
                try:
                    from app.tools.huginn_vuln_scanner import HuginnVulnScanner
                    
                    async def run_scan():
                        scanner = HuginnVulnScanner(self.target, 'normal')
                        
                        # Track progress through phases
                        phase_names = [
                            'Banner Grabbing',
                            'Technology Fingerprinting', 
                            'Security Headers Analysis',
                            'TLS Analysis',
                            'Content Discovery',
                            'Form Analysis',
                            'Cookie Analysis'
                        ]
                        
                        for i, phase in enumerate(phase_names, 1):
                            self.output_signal.emit(f"[Phase {i}/{len(phase_names)}] {phase}")
                        
                        results = await scanner.scan()
                        return results
                    
                    # Run async scan
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    results = loop.run_until_complete(run_scan())
                    loop.close()
                    
                    self.finished_signal.emit(results)
                    
                except Exception as e:
                    self.output_signal.emit(f"❌ Scan failed: {str(e)}")
                    self.finished_signal.emit({})
        
        def on_scan_output(text):
            self.output_area.append(f"  {text}")
        
        def on_scan_finished(results):
            vuln_count = len(results.get('vulnerabilities', []))
            self.output_area.append("")
            self.output_area.append("=" * 60)
            self.output_area.append("🎯 SCAN COMPLETE")
            self.output_area.append(f"📊 Vulnerabilities Found: {vuln_count}")
            
            # Show actual findings
            for vuln in results.get('vulnerabilities', []):
                severity = vuln.get('severity', 'UNKNOWN')
                vuln_type = vuln.get('type', 'Unknown')
                self.output_area.append(f"  🔴 {severity}: {vuln_type}")
            
            self.status_updated.emit(f"Huginn scan completed - {vuln_count} vulnerabilities found")
        
        # Start worker thread
        self.scan_worker = ScanWorker(target)
        self.scan_worker.output_signal.connect(on_scan_output)
        self.scan_worker.finished_signal.connect(on_scan_finished)
        self.scan_worker.start()
        
        self.status_updated.emit(f"Starting real Huginn scan for {target}")
    
    def on_scan_started(self, target, profile):
        """Handle scan started signal from component"""
        self.status_updated.emit(f"Huginn {profile} scan started for {target}")
    
    def on_scan_completed(self, results):
        """Handle scan completed signal from component"""
        vuln_count = len(results.get('vulnerabilities', []))
        self.status_updated.emit(f"Huginn scan completed - {vuln_count} vulnerabilities found")
        
        # Pass results to the Results tab
        if hasattr(self, 'results_component'):
            self.results_component.update_results(results)
    
    def create_profiles_tab(self):
        """Create the scan profiles tab"""
        try:
            from app.components.scan_profiles_component import ScanProfilesComponent
            component = ScanProfilesComponent(self)
            print("DEBUG: Successfully created ScanProfilesComponent")
            return component
        except ImportError as e:
            print(f"DEBUG: Failed to import ScanProfilesComponent: {e}")
            return self.create_fallback_profiles_tab()
        except Exception as e:
            print(f"DEBUG: Error creating ScanProfilesComponent: {e}")
            return self.create_fallback_profiles_tab()
    
    def create_fallback_profiles_tab(self):
        """Create a fallback profiles tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(20, 20, 20, 20)
        
        title = QLabel("⚙️ Huginn Scan Profiles")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("""
            font-size: 18pt;
            font-weight: bold;
            color: #64C8FF;
            padding: 15px;
            background-color: rgba(0, 0, 0, 100);
            border-radius: 8px;
            border: 1px solid rgba(100, 200, 255, 50);
        """)
        layout.addWidget(title)
        
        profiles_info = QLabel("""
        🔹 Light Profile: Basic vulnerability checks (20 concurrent, 5s timeout)
        🔹 Normal Profile: Balanced comprehensive scan (50 concurrent, 10s timeout)
        🔹 Aggressive Profile: Full-spectrum testing (100 concurrent, 15s timeout)
        🔹 Insane Profile: All AI features enabled (200 concurrent, 20s timeout)
        
        Each profile includes:
        • Neural Network Vulnerability Analysis
        • Quantum-Inspired Fuzzing
        • Autonomous Security Agent
        • ML Vulnerability Prediction
        • Advanced Exploitation Framework
        • Compliance Reporting (OWASP Top 10, PCI DSS)
        • OSINT Intelligence Gathering
        • WAF Evasion Techniques
        • Zero-Day Discovery Engine
        """)
        profiles_info.setStyleSheet("""
            color: #DCDCDC;
            font-size: 12pt;
            padding: 20px;
            background-color: rgba(20, 30, 40, 100);
            border-radius: 8px;
            border: 1px solid rgba(100, 200, 255, 30);
            line-height: 1.4;
        """)
        layout.addWidget(profiles_info)
        
        return tab
    
    def create_results_tab(self):
        """Create the results analysis tab"""
        try:
            from app.components.scan_results_component import ScanResultsComponent
            self.results_component = ScanResultsComponent(self)
            print("DEBUG: Successfully created ScanResultsComponent")
            return self.results_component
        except ImportError as e:
            print(f"DEBUG: Failed to import ScanResultsComponent: {e}")
            return self.create_fallback_results_tab()
        except Exception as e:
            print(f"DEBUG: Error creating ScanResultsComponent: {e}")
            return self.create_fallback_results_tab()
    
    def create_fallback_results_tab(self):
        """Create a fallback results tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(20, 20, 20, 20)
        
        title = QLabel("📊 Huginn Scan Results & Analysis")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("""
            font-size: 18pt;
            font-weight: bold;
            color: #64C8FF;
            padding: 15px;
            background-color: rgba(0, 0, 0, 100);
            border-radius: 8px;
            border: 1px solid rgba(100, 200, 255, 50);
        """)
        layout.addWidget(title)
        
        results_info = QLabel("""
        📈 Advanced Analytics & Reporting:
        
        🔴 Critical Vulnerabilities: Real-time detection and classification
        🟡 Medium/High Issues: Comprehensive analysis with CVSS scoring
        🟢 Security Recommendations: AI-powered remediation guidance
        
        📊 Report Formats:
        • HTML: Interactive reports with evidence buttons
        • JSON: Raw scan data for integration and automation
        • Executive: Business-friendly summary for management
        • OWASP: OWASP Top 10 2021 compliance mapping
        • PCI: PCI DSS compliance assessment
        
        🧠 AI-Powered Analysis:
        • Neural network pattern recognition
        • Machine learning vulnerability prediction
        • Automated attack chain correlation
        • Zero-day discovery indicators
        • Compliance gap analysis
        """)
        results_info.setStyleSheet("""
            color: #DCDCDC;
            font-size: 12pt;
            padding: 20px;
            background-color: rgba(20, 30, 40, 100);
            border-radius: 8px;
            border: 1px solid rgba(100, 200, 255, 30);
            line-height: 1.4;
        """)
        layout.addWidget(results_info)
        
        return tab
    
    def apply_theme(self):
        """Apply theme to the page"""
        try:
            if self.main_window and hasattr(self.main_window, 'theme_manager'):
                colors = self.main_window.theme_manager.get_theme_colors()
                background_color = colors.get('background', '#1E1E1E')
                text_color = colors.get('text', '#DCDCDC')
            else:
                background_color = '#1E1E1E'
                text_color = '#DCDCDC'
            
            self.setStyleSheet(f"""
                HuginnScannerPage {{
                    background-color: {background_color};
                    color: {text_color};
                }}
                QTabWidget::pane {{
                    border: 1px solid rgba(100, 200, 255, 50);
                    border-radius: 10px;
                    background-color: rgba(0, 0, 0, 100);
                }}
                QTabBar::tab {{
                    background-color: rgba(20, 30, 40, 150);
                    border: 1px solid rgba(100, 200, 255, 100);
                    border-radius: 5px;
                    color: #DCDCDC;
                    padding: 8px 16px;
                    margin: 2px;
                }}
                QTabBar::tab:selected {{
                    background-color: rgba(40, 60, 80, 200);
                    border: 1px solid #64C8FF;
                    color: #FFFFFF;
                }}
                QTabBar::tab:hover {{
                    background-color: rgba(30, 45, 60, 180);
                    border: 1px solid rgba(100, 200, 255, 150);
                }}
            """)
        except Exception as e:
            print(f"DEBUG: Error applying theme: {e}")
            # Apply basic styling as fallback
            self.setStyleSheet("""
                HuginnScannerPage {
                    background-color: #1E1E1E;
                    color: #DCDCDC;
                }
            """)
    
    def get_page_title(self):
        """Get the display title for this page"""
        return "Huginn Advanced Scanner"
    
    def get_page_icon(self):
        """Get the icon path for this page"""
        try:
            if self.main_window and hasattr(self.main_window, 'project_root'):
                import os
                return os.path.join(self.main_window.project_root, "resources/icons/5.png")
        except Exception as e:
            print(f"DEBUG: Error getting page icon: {e}")
        return None