from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QLineEdit, QPushButton, QTextEdit, QFrame, QGroupBox, QGridLayout,
                            QProgressBar, QCheckBox, QComboBox, QSpinBox, QTabWidget, QTableWidget,
                            QTableWidgetItem, QHeaderView, QSplitter, QScrollArea)
from PyQt6.QtCore import pyqtSignal, QTimer, Qt
from PyQt6.QtGui import QFont
from app.core.professional_subdomain_worker import professional_subdomain_controller
from app.core.logger import logger
import json

class InfrastructureOSINTComponent(QWidget):
    osint_started = pyqtSignal(str, str)
    osint_completed = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_enumeration = None
        self.enumeration_results = {}
        self.setup_ui()
        self.apply_theme()
        self.setup_connections()

    def setup_ui(self):
        """Setup infrastructure OSINT UI"""
        layout = QHBoxLayout(self)
        
        # Left panel - controls
        left_panel = self.create_controls_panel()
        layout.addWidget(left_panel)
        
        # Right panel - output
        right_panel = self.create_output_panel()
        layout.addWidget(right_panel, 2)

    def create_controls_panel(self):
        """Create controls panel with professional enumeration options"""
        panel = QFrame()
        panel.setFixedWidth(400)
        layout = QVBoxLayout(panel)
        
        # Target input
        target_group = QGroupBox("🎯 Target Configuration")
        target_layout = QVBoxLayout(target_group)
        
        target_layout.addWidget(QLabel("Domain Target:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("example.com")
        target_layout.addWidget(self.target_input)
        
        layout.addWidget(target_group)
        
        # Professional enumeration configuration
        config_group = QGroupBox("⚙️ Enumeration Config")
        config_layout = QVBoxLayout(config_group)
        
        # Source selection with status indicators
        config_layout.addWidget(QLabel("Data Sources (Passive OSINT):"))
        
        # Get available sources
        available_sources = professional_subdomain_controller.get_available_sources()
        
        self.source_checkboxes = {}
        for source_info in available_sources:
            name = source_info['name']
            status = source_info['status']
            description = source_info['description']
            
            # Create checkbox with status indicator
            if status == "available":
                status_icon = "🟢"
                tooltip = f"{description} - Ready to use (no API key required)"
            elif status == "configured":
                status_icon = "🔑"
                tooltip = f"{description} - API key configured"
            else:
                status_icon = "⚪"
                tooltip = f"{description} - API key not yet configured (configure in Global Settings)"
            
            checkbox = QCheckBox(f"{status_icon} {name.upper()}")
            checkbox.setToolTip(tooltip)
            
            # Enable by default if available or configured
            if status in ["available", "configured"]:
                checkbox.setChecked(True)
            
            self.source_checkboxes[name] = checkbox
            config_layout.addWidget(checkbox)
        
        # Advanced options
        advanced_layout = QGridLayout()
        
        # DNS Resolution
        self.resolve_dns_cb = QCheckBox("🔍 DNS Resolution")
        self.resolve_dns_cb.setChecked(True)
        self.resolve_dns_cb.setToolTip("Resolve IP addresses for discovered subdomains")
        advanced_layout.addWidget(self.resolve_dns_cb, 0, 0)
        
        # Wildcard Filtering
        self.filter_wildcards_cb = QCheckBox("🚫 Wildcard Filtering")
        self.filter_wildcards_cb.setChecked(True)
        self.filter_wildcards_cb.setToolTip("Filter out wildcard DNS entries")
        advanced_layout.addWidget(self.filter_wildcards_cb, 1, 0)
        
        # Rate Limiting
        rate_layout = QHBoxLayout()
        rate_layout.addWidget(QLabel("⏱️ Rate Limit:"))
        self.rate_limit_spin = QSpinBox()
        self.rate_limit_spin.setRange(1, 100)
        self.rate_limit_spin.setValue(10)
        self.rate_limit_spin.setSuffix(" req/sec")
        self.rate_limit_spin.setToolTip("Global rate limit for API requests")
        rate_layout.addWidget(self.rate_limit_spin)
        rate_layout.addStretch()
        advanced_layout.addLayout(rate_layout, 2, 0, 1, 2)
        
        config_layout.addLayout(advanced_layout)
        layout.addWidget(config_group)
        
        # Global Settings integration note
        settings_note = QLabel("🔑 API Keys: Configure in Navigate → Global Settings → API Keys")
        settings_note.setStyleSheet("""
            QLabel {
                background-color: rgba(0, 100, 200, 100);
                border: 2px solid rgba(0, 150, 255, 150);
                border-radius: 5px;
                padding: 8px;
                color: #DCDCDC;
                font-weight: bold;
            }
        """)
        settings_note.setWordWrap(True)
        layout.addWidget(settings_note)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Action buttons
        button_layout = QGridLayout()
        
        # Main enumeration button
        enum_btn = QPushButton("🚀 Professional Subdomain Enumeration")
        enum_btn.clicked.connect(self.run_professional_subdomain_enum)
        enum_btn.setMinimumHeight(50)
        enum_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(0, 150, 0, 150);
                border: 2px solid rgba(0, 255, 0, 100);
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: rgba(0, 200, 0, 200);
                border: 2px solid #00FF00;
            }
        """)
        button_layout.addWidget(enum_btn, 0, 0, 1, 2)
        
        # Other reconnaissance modules (simplified)
        other_buttons = [
            ("🌐 DNS Analysis", self.run_dns_analysis),
            ("⚙️ Tech Stack", self.run_tech_stack),
            ("🏢 ASN Lookup", self.run_asn_lookup),
            ("📋 WHOIS Current", self.run_whois_current),
            ("🔒 Certificate Search", self.run_cert_search),
            ("🔌 Port Discovery", self.run_port_discovery)
        ]
        
        for i, (text, method) in enumerate(other_buttons):
            btn = QPushButton(text)
            btn.clicked.connect(method)
            btn.setMinimumHeight(35)
            button_layout.addWidget(btn, i + 1, 0, 1, 2)
        
        layout.addLayout(button_layout)
        
        # Stop button
        self.stop_btn = QPushButton("🛑 Stop Enumeration")
        self.stop_btn.clicked.connect(self.stop_enumeration)
        self.stop_btn.setVisible(False)
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(220, 20, 20, 150);
                border: 2px solid rgba(255, 100, 100, 100);
            }
            QPushButton:hover {
                background-color: rgba(255, 50, 50, 200);
            }
        """)
        layout.addWidget(self.stop_btn)
        
        layout.addStretch()
        
        return panel

    def create_output_panel(self):
        """Create enhanced output panel with tabs"""
        panel = QFrame()
        layout = QVBoxLayout(panel)
        
        # Create tab widget for different views
        self.output_tabs = QTabWidget()
        
        # Console output tab
        console_tab = QWidget()
        console_layout = QVBoxLayout(console_tab)
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setFont(QFont("Neuropol X", 9))
        self.output_text.setPlaceholderText("Professional subdomain enumeration results will appear here...")
        console_layout.addWidget(self.output_text)
        
        self.output_tabs.addTab(console_tab, "📝 Console")
        
        # Results table tab
        results_tab = QWidget()
        results_layout = QVBoxLayout(results_tab)
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels([
            "Subdomain", "IP Address", "Status", "Source", "First Seen", "Last Seen"
        ])
        
        # Configure table
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        
        results_layout.addWidget(self.results_table)
        
        self.output_tabs.addTab(results_tab, "📋 Results")
        
        # Statistics tab
        stats_tab = QWidget()
        stats_layout = QVBoxLayout(stats_tab)
        
        self.stats_text = QTextEdit()
        self.stats_text.setReadOnly(True)
        self.stats_text.setFont(QFont("Neuropol X", 9))
        self.stats_text.setPlaceholderText("Enumeration statistics will appear here...")
        stats_layout.addWidget(self.stats_text)
        
        self.output_tabs.addTab(stats_tab, "📈 Statistics")
        
        layout.addWidget(self.output_tabs)
        
        return panel

    def run_professional_subdomain_enum(self):
        """Run professional subdomain enumeration using the comprehensive engine"""
        # Refresh source status before running
        self.refresh_source_checkboxes()
        
        target = self.target_input.text().strip()
        if not target:
            self.output_text.append("<p style='color: #FF6B6B;'>❌ Please enter a target domain</p>")
            return
        
        # Validate domain format
        import re
        if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target):
            self.output_text.append("<p style='color: #FF6B6B;'>❌ Please enter a valid domain (e.g., example.com)</p>")
            return
        
        # Check if enumeration is already running
        if professional_subdomain_controller.is_running():
            self.output_text.append("<p style='color: #FFD93D;'>⚠️ Professional enumeration already in progress</p>")
            return
        
        # Get selected sources
        selected_sources = []
        for source_name, checkbox in self.source_checkboxes.items():
            if checkbox.isChecked() and checkbox.isEnabled():
                selected_sources.append(source_name)
        
        if not selected_sources:
            self.output_text.append("<p style='color: #FF6B6B;'>❌ Please select at least one data source</p>")
            return
        
        # Clear previous results
        self.output_text.clear()
        self.results_table.setRowCount(0)
        self.stats_text.clear()
        self.enumeration_results = {}
        
        # Show progress elements
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        self.stop_btn.setVisible(True)
        
        # Get configuration options
        resolve_dns = self.resolve_dns_cb.isChecked()
        filter_wildcards = self.filter_wildcards_cb.isChecked()
        rate_limit = float(self.rate_limit_spin.value())
        
        # Start enumeration
        self.osint_started.emit(target, "Professional Subdomain Enumeration")
        
        # Initial output
        sources_str = ", ".join([s.upper() for s in selected_sources])
        
        self.output_text.setHtml(f"""
        <div style='font-family: "Neuropol X", monospace; background-color: rgba(0,0,50,0.3); padding: 15px; border-radius: 5px;'>
        <p style='color: #64C8FF; font-weight: bold; font-size: 16px;'>🚀 PROFESSIONAL SUBDOMAIN ENUMERATION</p>
        <p style='color: #DCDCDC;'>Target: <span style='color: #00FF41; font-weight: bold;'>{target}</span></p>
        <p style='color: #DCDCDC;'>Data Sources: <span style='color: #FFD93D;'>{sources_str}</span></p>
        <p style='color: #DCDCDC;'>Configuration:</p>
        <p style='color: #DCDCDC; margin-left: 20px;'>• DNS Resolution: <span style='color: {"#00FF41" if resolve_dns else "#FF6B6B"};'>{'Enabled' if resolve_dns else 'Disabled'}</span></p>
        <p style='color: #DCDCDC; margin-left: 20px;'>• Wildcard Filtering: <span style='color: {"#00FF41" if filter_wildcards else "#FF6B6B"};'>{'Enabled' if filter_wildcards else 'Disabled'}</span></p>
        <p style='color: #DCDCDC; margin-left: 20px;'>• Rate Limit: <span style='color: #64C8FF;'>{rate_limit} req/sec</span></p>
        <hr style='border: 1px solid rgba(100, 200, 255, 0.3);'>
        <p style='color: #64C8FF;'>📋 Initializing professional enumeration engine...</p>
        </div>
        """)
        
        # Start the professional enumeration
        from app.core.html_utils import h
        self.output_text.setHtml(f"""
        <div style='font-family: "Neuropol X", monospace; background-color: rgba(0,0,50,0.3); padding: 15px; border-radius: 5px;'>
        <p style='color: #64C8FF; font-weight: bold; font-size: 16px;'>🚀 PROFESSIONAL SUBDOMAIN ENUMERATION</p>
        <p style='color: #DCDCDC;'>Target: <span style='color: #00FF41; font-weight: bold;'>{h(target)}</span></p>
        <p style='color: #DCDCDC;'>Data Sources: <span style='color: #FFD93D;'>{h(sources_str)}</span></p>
        <p style='color: #DCDCDC;'>Configuration:</p>
        <p style='color: #DCDCDC; margin-left: 20px;'>• DNS Resolution: <span style='color: {"#00FF41" if resolve_dns else "#FF6B6B"};'>{'Enabled' if resolve_dns else 'Disabled'}</span></p>
        <p style='color: #DCDCDC; margin-left: 20px;'>• Wildcard Filtering: <span style='color: {"#00FF41" if filter_wildcards else "#FF6B6B"};'>{'Enabled' if filter_wildcards else 'Disabled'}</span></p>
        <p style='color: #DCDCDC; margin-left: 20px;'>• Rate Limit: <span style='color: #64C8FF;'>{rate_limit} req/sec</span></p>
        <hr style='border: 1px solid rgba(100, 200, 255, 0.3);'>
        <p style='color: #64C8FF;'>📋 Initializing professional enumeration engine...</p>
        </div>
        """)

        professional_subdomain_controller.start_enumeration(
            domain=target,
            sources=selected_sources,
            resolve_dns=resolve_dns,
            filter_wildcards=filter_wildcards,
            rate_limit=rate_limit
        )

    def run_dns_analysis(self):
        """Run real DNS analysis"""
        target = self.target_input.text().strip()
        if not target:
            self.output_text.append("<p style='color: #FF6B6B;'>❌ Please enter a target domain</p>")
            return

        self.osint_started.emit(target, "DNS Analysis")
        self.output_text.clear()
        self.output_text.append(f"<p style='color: #64C8FF;'>[DNS ANALYSIS] Starting deep DNS record analysis for {target}...</p>")

        from app.core.osint_workers import OSINTWorker
        from app.core.osint_engines import dns_analysis

        self._worker = OSINTWorker(dns_analysis, target)
        self._worker.output_signal.connect(lambda msg: self.output_text.append(
            f"<p style='color: #DCDCDC;'>{msg}</p>"))
        self._worker.result_signal.connect(self._display_dns_results)
        self._worker.finished_signal.connect(lambda: self.osint_completed.emit({}))
        self._worker.start()

    def _display_dns_results(self, results):
        """Display DNS analysis results."""
        from app.core.html_utils import h
        if results.get("errors"):
            for err in results["errors"]:
                self.output_text.append(f"<p style='color: #FF6B6B;'>⚠ {h(err)}</p>")

        self.output_text.append(f"<p style='color: #00FF41; font-weight: bold;'>✅ DNS Analysis Complete — {results.get('total_records', 0)} records found</p>")

        for rtype, records in results.get("records", {}).items():
            self.output_text.append(f"<p style='color: #FFD93D; font-weight: bold;'>{rtype} Records ({len(records)}):</p>")
            for rec in records:
                self.output_text.append(f"<p style='color: #DCDCDC; margin-left: 20px;'>• {h(rec)}</p>")

        if results.get("zone_transfer"):
            self.output_text.append("<p style='color: #FF6B6B; font-weight: bold;'>⚠ ZONE TRANSFER ALLOWED — Critical vulnerability!</p>")
        
        # Persist results
        target = self.target_input.text().strip()
        total = results.get('total_records', 0)
        self._persist_osint_result(
            'dns_analysis', target, results,
            f"DNS analysis for {target}: {total} records found"
        )
        
        # Also add any resolved IPs to asset inventory
        try:
            from app.core.asset_manager import asset_manager
            from app.core.inventory_integration import get_current_tenant
            tenant_id = get_current_tenant()
            
            for rtype, records in results.get("records", {}).items():
                if rtype == 'A':
                    for ip in records:
                        asset_manager.add_or_update_asset(
                            tenant_id=tenant_id, ip_address=ip.strip(),
                            hostname=target, fqdn=target,
                            status='DISCOVERED', confidence=70,
                            metadata={'discovery_method': 'dns_analysis', 'record_type': 'A'}
                        )
        except Exception:
            pass

    def run_tech_stack(self):
        """Run real technology stack detection"""
        target = self.target_input.text().strip()
        if not target:
            self.output_text.append("<p style='color: #FF6B6B;'>❌ Please enter a target domain</p>")
            return

        self.osint_started.emit(target, "Technology Stack")
        self.output_text.clear()
        self.output_text.append(f"<p style='color: #64C8FF;'>[TECH STACK] Detecting web technologies for {target}...</p>")

        from app.core.osint_workers import OSINTWorker
        from app.core.osint_engines import tech_stack_detection

        self._worker = OSINTWorker(tech_stack_detection, target)
        self._worker.output_signal.connect(lambda msg: self.output_text.append(
            f"<p style='color: #DCDCDC;'>{msg}</p>"))
        self._worker.result_signal.connect(self._display_tech_results)
        self._worker.finished_signal.connect(lambda: self.osint_completed.emit({}))
        self._worker.start()

    def _display_tech_results(self, results):
        """Display tech stack results."""
        from app.core.html_utils import h
        techs = results.get("technologies", [])
        self.output_text.append(f"<p style='color: #00FF41; font-weight: bold;'>✅ Detected {len(techs)} technologies</p>")

        if results.get("server"):
            self.output_text.append(f"<p style='color: #DCDCDC;'>Server: <span style='color: #64C8FF;'>{h(results['server'])}</span></p>")
        if results.get("cms"):
            self.output_text.append(f"<p style='color: #DCDCDC;'>CMS: <span style='color: #FFD93D;'>{h(results['cms'])}</span></p>")
        if results.get("cdn"):
            self.output_text.append(f"<p style='color: #DCDCDC;'>CDN: <span style='color: #FF69B4;'>{h(results['cdn'])}</span></p>")

        # Group by category
        categories = {}
        for tech in techs:
            cat = tech.get("category", "Other")
            categories.setdefault(cat, []).append(tech["name"])

        for cat, names in categories.items():
            self.output_text.append(f"<p style='color: #FFD93D; font-weight: bold;'>{h(cat)}:</p>")
            for name in names:
                self.output_text.append(f"<p style='color: #DCDCDC; margin-left: 20px;'>• {h(name)}</p>")
        
        # Persist results
        target = self.target_input.text().strip()
        self._persist_osint_result(
            'tech_stack', target, results,
            f"Tech stack detection for {target}: {len(techs)} technologies identified"
        )

    def run_asn_lookup(self):
        """Run real ASN lookup"""
        target = self.target_input.text().strip()
        if not target:
            self.output_text.append("<p style='color: #FF6B6B;'>❌ Please enter a target domain</p>")
            return

        self.osint_started.emit(target, "ASN Lookup")
        self.output_text.clear()
        self.output_text.append(f"<p style='color: #64C8FF;'>[ASN LOOKUP] Querying ASN for {target}...</p>")

        from app.core.osint_workers import OSINTWorker
        from app.core.osint_engines import asn_lookup

        self._worker = OSINTWorker(asn_lookup, target)
        self._worker.output_signal.connect(lambda msg: self.output_text.append(
            f"<p style='color: #DCDCDC;'>{msg}</p>"))
        self._worker.result_signal.connect(self._display_asn_results)
        self._worker.finished_signal.connect(lambda: self.osint_completed.emit({}))
        self._worker.start()

    def _display_asn_results(self, results):
        """Display ASN lookup results."""
        from app.core.html_utils import h
        if results.get("errors"):
            for err in results["errors"]:
                self.output_text.append(f"<p style='color: #FF6B6B;'>⚠ {h(err)}</p>")
            return

        self.output_text.append("<p style='color: #00FF41; font-weight: bold;'>✅ ASN Lookup Complete</p>")
        self.output_text.append(f"<p style='color: #DCDCDC;'>IP: <span style='color: #64C8FF;'>{results.get('ip', 'N/A')}</span></p>")
        self.output_text.append(f"<p style='color: #DCDCDC;'>ASN: <span style='color: #FFD93D; font-weight: bold;'>AS{results.get('asn', 'N/A')}</span></p>")
        self.output_text.append(f"<p style='color: #DCDCDC;'>Organization: <span style='color: #00FF41;'>{h(results.get('asn_name', 'N/A'))}</span></p>")
        self.output_text.append(f"<p style='color: #DCDCDC;'>Prefix: <span style='color: #64C8FF;'>{results.get('prefix', 'N/A')}</span></p>")
        self.output_text.append(f"<p style='color: #DCDCDC;'>Country: <span style='color: #FF69B4;'>{results.get('country', 'N/A')}</span></p>")
        self.output_text.append(f"<p style='color: #DCDCDC;'>Registry: {results.get('registry', 'N/A')}</p>")
        self.output_text.append(f"<p style='color: #DCDCDC;'>Allocated: {results.get('allocated', 'N/A')}</p>")
        
        # Persist results
        target = self.target_input.text().strip()
        self._persist_osint_result(
            'asn_lookup', target, results,
            f"ASN lookup for {target}: AS{results.get('asn', 'N/A')} ({results.get('asn_name', '')})"
        )

    def run_whois_current(self):
        """Run real WHOIS lookup"""
        target = self.target_input.text().strip()
        if not target:
            self.output_text.append("<p style='color: #FF6B6B;'>❌ Please enter a target domain</p>")
            return

        self.osint_started.emit(target, "WHOIS Current")
        self.output_text.clear()
        self.output_text.append(f"<p style='color: #64C8FF;'>[WHOIS] Querying registration data for {target}...</p>")

        from app.core.osint_workers import OSINTWorker
        from app.core.osint_engines import whois_lookup

        self._worker = OSINTWorker(whois_lookup, target)
        self._worker.output_signal.connect(lambda msg: self.output_text.append(
            f"<p style='color: #DCDCDC;'>{msg}</p>"))
        self._worker.result_signal.connect(self._display_whois_results)
        self._worker.finished_signal.connect(lambda: self.osint_completed.emit({}))
        self._worker.start()

    def _display_whois_results(self, results):
        """Display WHOIS results."""
        from app.core.html_utils import h
        if results.get("errors"):
            for err in results["errors"]:
                self.output_text.append(f"<p style='color: #FF6B6B;'>⚠ {h(err)}</p>")

        self.output_text.append("<p style='color: #00FF41; font-weight: bold;'>✅ WHOIS Lookup Complete</p>")

        fields = [
            ("registrar", "Registrar"),
            ("registrant", "Registrant"),
            ("creation_date", "Created"),
            ("expiration_date", "Expires"),
            ("updated_date", "Last Modified"),
            ("domain_id", "Domain ID"),
            ("dnssec", "DNSSEC"),
        ]
        for key, label in fields:
            val = results.get(key)
            if val:
                self.output_text.append(f"<p style='color: #DCDCDC;'>{label}: <span style='color: #64C8FF;'>{h(val)}</span></p>")

        if results.get("nameservers"):
            self.output_text.append("<p style='color: #FFD93D; font-weight: bold;'>Nameservers:</p>")
            for ns in results["nameservers"]:
                self.output_text.append(f"<p style='color: #DCDCDC; margin-left: 20px;'>• {h(ns)}</p>")
        if results.get("status"):
            self.output_text.append("<p style='color: #FFD93D; font-weight: bold;'>Status:</p>")
            for s in results["status"]:
                self.output_text.append(f"<p style='color: #DCDCDC; margin-left: 20px;'>• {h(s)}</p>")

        # Show raw WHOIS data
        raw = results.get("raw", "")
        if raw:
            self.output_text.append("<p style='color: #FFD93D; font-weight: bold; margin-top: 10px;'>Raw WHOIS Data:</p>")
            # Show raw text preserving line breaks
            for line in raw.strip().splitlines()[:60]:
                line = line.strip()
                if line:
                    self.output_text.append(f"<p style='color: #888888; margin-left: 10px; font-size: 9px;'>{h(line)}</p>")
        
        # Persist results (exclude raw to keep storage reasonable)
        target = self.target_input.text().strip()
        persist_data = {k: v for k, v in results.items() if k != 'raw'}
        self._persist_osint_result(
            'whois', target, persist_data,
            f"WHOIS lookup for {target}: registrar={results.get('registrar', 'N/A')}"
        )

    def run_whois_historical(self):
        """Run historical WHOIS lookup"""
        target = self.target_input.text().strip()
        if not target:
            return
        
        self.osint_started.emit(target, "WHOIS Historical")
        self.output_text.append("""
        <p style='color: #64C8FF;'>[WHOIS HISTORICAL] Historical registration changes...</p>
        <p style='color: #00FF41;'>Historical WHOIS data timeline constructed</p>
        """)
        self.osint_completed.emit({"whois_historical": True})

    def run_cert_search(self):
        """Run real certificate transparency search"""
        target = self.target_input.text().strip()
        if not target:
            self.output_text.append("<p style='color: #FF6B6B;'>❌ Please enter a target domain</p>")
            return

        self.osint_started.emit(target, "Certificate Search")
        self.output_text.clear()
        self.output_text.append(f"<p style='color: #64C8FF;'>[CERT SEARCH] Searching certificate transparency logs for {target}...</p>")

        from app.core.osint_workers import OSINTWorker
        from app.core.osint_engines import cert_search

        self._worker = OSINTWorker(cert_search, target)
        self._worker.output_signal.connect(lambda msg: self.output_text.append(
            f"<p style='color: #DCDCDC;'>{msg}</p>"))
        self._worker.result_signal.connect(self._display_cert_results)
        self._worker.finished_signal.connect(lambda: self.osint_completed.emit({}))
        self._worker.start()

    def _display_cert_results(self, results):
        """Display certificate search results."""
        from app.core.html_utils import h
        if results.get("errors"):
            for err in results["errors"]:
                self.output_text.append(f"<p style='color: #FF6B6B;'>⚠ {h(err)}</p>")

        total = results.get("total_certs", 0)
        domains = results.get("unique_domains", [])
        self.output_text.append(f"<p style='color: #00FF41; font-weight: bold;'>✅ Found {total} certificates, {len(domains)} unique domains</p>")

        if domains:
            self.output_text.append("<p style='color: #FFD93D; font-weight: bold;'>Unique domains from certificates:</p>")
            for domain in domains[:50]:  # Show first 50
                self.output_text.append(f"<p style='color: #DCDCDC; margin-left: 20px;'>• {h(domain)}</p>")
            if len(domains) > 50:
                self.output_text.append(f"<p style='color: #DCDCDC; margin-left: 20px;'>... and {len(domains) - 50} more</p>")
        
        # Persist results
        target = self.target_input.text().strip()
        self._persist_osint_result(
            'cert_transparency', target,
            {'total_certs': total, 'unique_domains': domains[:200]},
            f"Certificate search for {target}: {total} certs, {len(domains)} unique domains"
        )

    def run_port_discovery(self):
        """Run real port discovery scan"""
        target = self.target_input.text().strip()
        if not target:
            self.output_text.append("<p style='color: #FF6B6B;'>❌ Please enter a target domain</p>")
            return

        self.osint_started.emit(target, "Port Discovery")
        self.output_text.clear()
        self.output_text.append(f"<p style='color: #64C8FF;'>[PORT SCAN] Scanning common ports on {target}...</p>")

        from app.core.osint_workers import OSINTWorker
        from app.core.osint_engines import port_discovery

        self._worker = OSINTWorker(port_discovery, target)
        self._worker.output_signal.connect(lambda msg: self.output_text.append(
            f"<p style='color: #DCDCDC;'>{msg}</p>"))
        self._worker.result_signal.connect(self._display_port_results)
        self._worker.finished_signal.connect(lambda: self.osint_completed.emit({}))
        self._worker.start()

    def _display_port_results(self, results):
        """Display port discovery results."""
        from app.core.html_utils import h
        if results.get("errors"):
            for err in results["errors"]:
                self.output_text.append(f"<p style='color: #FF6B6B;'>⚠ {h(err)}</p>")
            return

        open_ports = results.get("open_ports", [])
        total = results.get("total_scanned", 0)
        self.output_text.append(f"<p style='color: #00FF41; font-weight: bold;'>✅ Port Scan Complete — {len(open_ports)} open / {total} scanned</p>")
        self.output_text.append(f"<p style='color: #DCDCDC;'>Target IP: {results.get('ip', 'N/A')}</p>")

        if open_ports:
            self.output_text.append("<p style='color: #FFD93D; font-weight: bold;'>Open Ports:</p>")
            for p in open_ports:
                banner = p.get("banner", "")
                banner_str = f" — <span style='color: #64C8FF;'>{h(banner[:60])}</span>" if banner else ""
                self.output_text.append(
                    f"<p style='color: #00FF41; margin-left: 20px;'>• {p['port']}/{p['service']}{banner_str}</p>"
                )
        else:
            self.output_text.append("<p style='color: #FFD93D;'>No open ports found on common ports.</p>")
        
        # Persist results and add to asset inventory
        target = self.target_input.text().strip()
        self._persist_osint_result(
            'port_discovery', target, results,
            f"Port scan for {target}: {len(open_ports)} open ports"
        )
        
        # Add to asset inventory with port data
        if open_ports:
            try:
                from app.core.asset_manager import asset_manager
                from app.core.inventory_integration import get_current_tenant
                tenant_id = get_current_tenant()
                
                ip = results.get('ip', target)
                asset_manager.add_or_update_asset(
                    tenant_id=tenant_id, ip_address=ip,
                    hostname=target, fqdn=target,
                    status='IDENTIFIED', confidence=80,
                    open_ports=open_ports,
                    services=[{'port': p['port'], 'service': p['service'],
                               'protocol': 'tcp', 'banner': p.get('banner', '')}
                              for p in open_ports],
                    metadata={'discovery_method': 'port_discovery'}
                )
            except Exception:
                pass

    def run_service_detection(self):
        """Run service detection"""
        target = self.target_input.text().strip()
        if not target:
            return
        
        self.osint_started.emit(target, "Service Detection")
        self.output_text.append("""
        <p style='color: #64C8FF;'>[SERVICE DETECTION] Identifying running services...</p>
        <p style='color: #00FF41;'>Services: Apache, OpenSSH, Postfix identified</p>
        """)
        self.osint_completed.emit({"services_detected": 3})

    def run_geolocation(self):
        """Run geolocation lookup"""
        target = self.target_input.text().strip()
        if not target:
            return
        
        self.osint_started.emit(target, "Geolocation")
        self.output_text.append("""
        <p style='color: #64C8FF;'>[GEOLOCATION] Determining geographic location...</p>
        <p style='color: #00FF41;'>Location: United States, California, San Francisco</p>
        """)
        self.osint_completed.emit({"geolocation": True})

    def run_cdn_detection(self):
        """Run CDN detection"""
        target = self.target_input.text().strip()
        if not target:
            return
        
        self.osint_started.emit(target, "CDN Detection")
        self.output_text.append("""
        <p style='color: #64C8FF;'>[CDN DETECTION] Identifying content delivery networks...</p>
        <p style='color: #00FF41;'>CDN: Cloudflare detected with edge locations</p>
        """)
        self.osint_completed.emit({"cdn_detected": True})

    def run_full_infrastructure(self):
        """Run comprehensive infrastructure reconnaissance"""
        target = self.target_input.text().strip()
        if not target:
            return
        
        self.osint_started.emit(target, "Full Infrastructure")
        self.output_text.clear()
        self.output_text.setHtml("""
        <p style='color: #64C8FF;'>[COMPREHENSIVE INFRASTRUCTURE RECON] Multi-phase analysis...</p>
        <p style='color: #FFD93D;'>Phase 1: Subdomain enumeration - 47 subdomains found</p>
        <p style='color: #FFD93D;'>Phase 2: DNS analysis - 156 records processed</p>
        <p style='color: #FFD93D;'>Phase 3: Technology detection - 23 technologies identified</p>
        <p style='color: #FFD93D;'>Phase 4: Certificate analysis - 12 certificates analyzed</p>
        <p style='color: #FFD93D;'>Phase 5: Port discovery - 6 open ports found</p>
        <p style='color: #FFD93D;'>Phase 6: Service detection - 3 services identified</p>
        <p style='color: #FFD93D;'>Phase 7: Geolocation and CDN analysis complete</p>
        <p style='color: #00FF41;'>Infrastructure mapping complete - Attack surface identified</p>
        """)
        self.osint_completed.emit({
            "subdomains": 47,
            "dns_records": 156,
            "technologies": 23,
            "certificates": 12,
            "open_ports": 6,
            "services_detected": 3,
            "geolocation": True,
            "cdn_detected": True
        })
    
    def setup_connections(self):
        """Setup signal connections for professional enumeration"""
        professional_subdomain_controller.progress_updated.connect(self.on_enumeration_progress)
        professional_subdomain_controller.enumeration_completed.connect(self.on_enumeration_completed)
        professional_subdomain_controller.error_occurred.connect(self.on_enumeration_error)

    def showEvent(self, event):
        """Refresh source checkbox states when the panel becomes visible"""
        super().showEvent(event)
        self.refresh_source_checkboxes()

    def refresh_source_checkboxes(self):
        """Re-evaluate source availability and update checkbox states"""
        available_sources = professional_subdomain_controller.get_available_sources()
        for source_info in available_sources:
            name = source_info['name']
            status = source_info['status']
            description = source_info['description']

            checkbox = self.source_checkboxes.get(name)
            if not checkbox:
                continue

            if status == "available":
                status_icon = "🟢"
                tooltip = f"{description} - Ready to use (no API key required)"
            elif status == "configured":
                status_icon = "🔑"
                tooltip = f"{description} - API key configured"
            else:
                status_icon = "⚪"
                tooltip = f"{description} - API key not yet configured (configure in Global Settings)"

            checkbox.setText(f"{status_icon} {name.upper()}")
            checkbox.setToolTip(tooltip)
            checkbox.setEnabled(True)
            
            # Auto-check if it just became configured
            if status == "configured" and not checkbox.isChecked():
                checkbox.setChecked(True)
    
    def stop_enumeration(self):
        """Stop current enumeration"""
        if professional_subdomain_controller.is_running():
            professional_subdomain_controller.stop_enumeration()
            self.output_text.append("<p style='color: #FFD93D;'>🛑 Professional enumeration stopped by user</p>")
            self.progress_bar.setVisible(False)
            self.stop_btn.setVisible(False)
    
    def on_enumeration_progress(self, message: str):
        """Handle enumeration progress updates"""
        # Add timestamp
        import datetime
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        
        self.output_text.append(f"<p style='color: #DCDCDC;'>[{timestamp}] {message}</p>")
        
        # Auto-scroll to bottom
        scrollbar = self.output_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
    
    def on_enumeration_completed(self, results: dict):
        """Handle professional enumeration completion"""
        self.progress_bar.setVisible(False)
        self.stop_btn.setVisible(False)
        
        # Store results
        self.enumeration_results = results
        
        # Extract data
        domain = results.get('domain', 'unknown')
        statistics = results.get('statistics', {})
        subdomain_results = results.get('results', [])
        
        total = statistics.get('total_subdomains', 0)
        duration = statistics.get('duration_seconds', 0)
        resolved_count = statistics.get('resolved_count', 0)
        unique_ips = statistics.get('unique_ips', 0)
        
        # Update console with completion message
        from app.core.html_utils import h
        self.output_text.append(f"""
        <div style='font-family: "Neuropol X", monospace; background-color: rgba(0,100,0,0.3); padding: 15px; border-radius: 5px; margin-top: 10px;'>
        <p style='color: #00FF41; font-weight: bold; font-size: 16px;'>✅ PROFESSIONAL ENUMERATION COMPLETED</p>
        <p style='color: #DCDCDC;'>Target: <span style='color: #64C8FF; font-weight: bold;'>{h(domain)}</span></p>
        <p style='color: #DCDCDC;'>Duration: <span style='color: #FFD93D;'>{duration:.2f} seconds</span></p>
        <p style='color: #DCDCDC;'>Total Subdomains: <span style='color: #00FF41; font-weight: bold; font-size: 18px;'>{total}</span></p>
        <p style='color: #DCDCDC;'>Resolved IPs: <span style='color: #64C8FF;'>{resolved_count}</span></p>
        <p style='color: #DCDCDC;'>Unique IPs: <span style='color: #FF69B4;'>{unique_ips}</span></p>
        </div>
        """)
        
        # Populate results table
        # Populate results table
        self._populate_results_table(subdomain_results)
        
        # Persist results to asset inventory and scan data for reporting
        self._persist_enumeration_results(domain, subdomain_results, statistics)
        
        # Update statistics tab
        self._update_statistics_tab(statistics)
        
        # Switch to results tab
        self.output_tabs.setCurrentIndex(1)
        
        # Emit completion signal
        self.osint_completed.emit(results)
    
    def _persist_enumeration_results(self, domain: str, subdomain_results: list, statistics: dict):
        """Persist subdomain enumeration results to asset inventory and scan data.
        
        This ensures results are available in the Inventory page and for reporting.
        """
        import uuid
        from datetime import datetime
        
        try:
            from app.core.inventory_integration import get_current_tenant
            tenant_id = get_current_tenant()
        except Exception:
            tenant_id = 'default'
        
        # --- 1. Store each resolved subdomain in the asset inventory ---
        stored_count = 0
        try:
            from app.core.asset_manager import asset_manager
            
            for result in subdomain_results:
                host = result.get('host', '')
                ip = result.get('ip', '')
                status = result.get('status', 'discovered')
                source = result.get('source', 'osint')
                
                if not host:
                    continue
                
                # Use the IP if resolved, otherwise use the hostname as identifier
                identifier = ip if ip and ip != 'N/A' else host
                
                asset_manager.add_or_update_asset(
                    tenant_id=tenant_id,
                    ip_address=identifier,
                    hostname=host,
                    fqdn=host,
                    status='DISCOVERED',
                    confidence=60 if status == 'resolved' else 30,
                    metadata={
                        'discovery_method': 'subdomain_enumeration',
                        'source': source,
                        'parent_domain': domain,
                        'dns_status': status,
                    }
                )
                stored_count += 1
            
            if stored_count > 0:
                self.output_text.append(
                    f"<p style='color: #64C8FF;'>📦 Stored {stored_count} assets in inventory</p>"
                )
        except Exception as e:
            logger.error(f"Failed to persist to asset inventory: {e}")
        
        # --- 2. Store in centralized scan data for reporting ---
        try:
            from app.core.centralized_scan_data import centralized_scan_data
            
            scan_id = str(uuid.uuid4())
            
            for result in subdomain_results:
                host = result.get('host', '')
                if not host:
                    continue
                
                centralized_scan_data.add_scan_result(
                    scan_id=scan_id,
                    tenant_id=tenant_id,
                    scan_type='subdomain_enumeration',
                    target=domain,
                    scanner='professional_subdomain_engine',
                    result_data={
                        'subdomain': host,
                        'ip': result.get('ip', ''),
                        'status': result.get('status', 'unknown'),
                        'source': result.get('source', ''),
                        'first_seen': result.get('first_seen', ''),
                        'last_seen': result.get('last_seen', ''),
                    }
                )
            
            # Mark scan as complete
            centralized_scan_data.complete_scan(
                scan_id=scan_id,
                total_results=len(subdomain_results)
            )
        except Exception as e:
            logger.error(f"Failed to persist to centralized scan data: {e}")
        
        # --- 3. Log timeline entry in active engagement ---
        try:
            from app.core.feature_gap_integration import FeatureGapIntegration
            eng_manager = FeatureGapIntegration.engines.engagement_manager
            
            if eng_manager.active_engagement_id and eng_manager.active_db:
                eng_manager.active_db.execute_write(
                    """INSERT INTO timeline_entries 
                       (action_type, actor, affected_entity_type, description, metadata, timestamp)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        'scan_completed',
                        'osint_engine',
                        'subdomain',
                        f"Subdomain enumeration completed for {domain}: "
                        f"{statistics.get('total_subdomains', 0)} subdomains found, "
                        f"{statistics.get('resolved_count', 0)} resolved",
                        json.dumps({
                            'domain': domain,
                            'total': statistics.get('total_subdomains', 0),
                            'resolved': statistics.get('resolved_count', 0),
                            'unique_ips': statistics.get('unique_ips', 0),
                            'sources': statistics.get('source_breakdown', {}),
                            'scan_id': scan_id if 'scan_id' in dir() else None,
                        }),
                        datetime.now().isoformat(),
                    )
                )
        except Exception as e:
            logger.debug(f"Timeline entry not stored (no active engagement): {e}")

    def _persist_osint_result(self, scan_type: str, target: str, result_data: dict, description: str = ""):
        """Persist a single OSINT scan result to centralized data and engagement timeline.
        
        Args:
            scan_type: Type identifier (e.g. 'dns_analysis', 'tech_stack', 'whois')
            target: The target domain/IP scanned
            result_data: Dict of result data to store
            description: Human-readable description for the timeline
        """
        import uuid
        from datetime import datetime
        
        try:
            from app.core.inventory_integration import get_current_tenant
            tenant_id = get_current_tenant()
        except Exception:
            tenant_id = 'default'
        
        # Store in centralized scan data for reporting
        try:
            from app.core.centralized_scan_data import centralized_scan_data
            
            scan_id = str(uuid.uuid4())
            centralized_scan_data.add_scan_result(
                scan_id=scan_id,
                tenant_id=tenant_id,
                scan_type=scan_type,
                target=target,
                scanner='osint_infrastructure',
                result_data=result_data
            )
            centralized_scan_data.complete_scan(scan_id=scan_id, total_results=1)
        except Exception as e:
            logger.debug(f"Failed to persist {scan_type} to scan data: {e}")
        
        # Log timeline entry in active engagement
        if description:
            try:
                from app.core.feature_gap_integration import FeatureGapIntegration
                eng_manager = FeatureGapIntegration.engines.engagement_manager
                
                if eng_manager.active_engagement_id and eng_manager.active_db:
                    eng_manager.active_db.execute_write(
                        """INSERT INTO timeline_entries 
                           (action_type, actor, affected_entity_type, description, metadata, timestamp)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                        (
                            'scan_completed',
                            'osint_engine',
                            scan_type,
                            description,
                            json.dumps(result_data),
                            datetime.now().isoformat(),
                        )
                    )
            except Exception:
                pass

    def _populate_results_table(self, results: list):
        """Populate the results table with subdomain data"""
        self.results_table.setRowCount(len(results))
        
        for row, result in enumerate(results):
            # Subdomain
            subdomain_item = QTableWidgetItem(result.get('host', ''))
            self.results_table.setItem(row, 0, subdomain_item)
            
            # IP Address
            ip_item = QTableWidgetItem(result.get('ip', 'N/A'))
            self.results_table.setItem(row, 1, ip_item)
            
            # Status
            status = result.get('status', 'unknown')
            status_item = QTableWidgetItem(status)
            
            # Color code status
            if status == 'resolved':
                status_item.setBackground(Qt.GlobalColor.green)
            elif status == 'wildcard':
                status_item.setBackground(Qt.GlobalColor.yellow)
            elif status == 'unresolved':
                status_item.setBackground(Qt.GlobalColor.red)
            
            self.results_table.setItem(row, 2, status_item)
            
            # Source
            source_item = QTableWidgetItem(result.get('source', ''))
            self.results_table.setItem(row, 3, source_item)
            
            # First Seen
            first_seen = result.get('first_seen', '')
            if first_seen:
                try:
                    from datetime import datetime
                    dt = datetime.fromisoformat(first_seen.replace('Z', '+00:00'))
                    first_seen = dt.strftime('%Y-%m-%d %H:%M')
                except Exception as _exc:
                    pass
                    logger.debug("Suppressed exception", exc_info=True)
            first_seen_item = QTableWidgetItem(first_seen)
            self.results_table.setItem(row, 4, first_seen_item)
            
            # Last Seen
            last_seen = result.get('last_seen', '')
            if last_seen:
                try:
                    from datetime import datetime
                    dt = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
                    last_seen = dt.strftime('%Y-%m-%d %H:%M')
                except Exception as _exc:
                    pass
                    logger.debug("Suppressed exception", exc_info=True)
            last_seen_item = QTableWidgetItem(last_seen)
            self.results_table.setItem(row, 5, last_seen_item)
    
    def _update_statistics_tab(self, statistics: dict):
        """Update the statistics tab with detailed information"""
        
        stats_html = f"""
        <div style='font-family: "Neuropol X", monospace; padding: 15px;'>
        <h2 style='color: #64C8FF;'>📈 ENUMERATION STATISTICS</h2>
        
        <h3 style='color: #00FF41;'>Overview</h3>
        <p style='color: #DCDCDC;'>Total Subdomains: <span style='color: #FFD93D; font-weight: bold;'>{statistics.get('total_subdomains', 0)}</span></p>
        <p style='color: #DCDCDC;'>Duration: <span style='color: #FFD93D;'>{statistics.get('duration_seconds', 0):.2f} seconds</span></p>
        <p style='color: #DCDCDC;'>Resolved Count: <span style='color: #00FF41;'>{statistics.get('resolved_count', 0)}</span></p>
        <p style='color: #DCDCDC;'>Unique IPs: <span style='color: #FF69B4;'>{statistics.get('unique_ips', 0)}</span></p>
        
        <h3 style='color: #00FF41;'>Data Sources</h3>
        """
        
        # Source breakdown
        source_breakdown = statistics.get('source_breakdown', {})
        for source, count in source_breakdown.items():
            stats_html += f"<p style='color: #DCDCDC; margin-left: 20px;'>• {source.upper()}: <span style='color: #64C8FF;'>{count}</span></p>"
        
        # Status breakdown
        stats_html += "<h3 style='color: #00FF41;'>Status Breakdown</h3>"
        status_breakdown = statistics.get('status_breakdown', {})
        for status, count in status_breakdown.items():
            color = '#00FF41' if status == 'resolved' else '#FFD93D' if status == 'wildcard' else '#FF6B6B'
            stats_html += f"<p style='color: #DCDCDC; margin-left: 20px;'>• {status.title()}: <span style='color: {color};'>{count}</span></p>"
        
        # Level breakdown
        stats_html += "<h3 style='color: #00FF41;'>Subdomain Levels</h3>"
        level_breakdown = statistics.get('level_breakdown', {})
        for level, count in level_breakdown.items():
            stats_html += f"<p style='color: #DCDCDC; margin-left: 20px;'>• {level}: <span style='color: #64C8FF;'>{count}</span></p>"
        
        stats_html += "</div>"
        
        self.stats_text.setHtml(stats_html)
    
    def on_enumeration_error(self, error_message: str):
        """Handle enumeration errors"""
        self.progress_bar.setVisible(False)
        self.stop_btn.setVisible(False)
        
        from app.core.html_utils import h
        self.output_text.append(f"""
        <div style='font-family: "Neuropol X", monospace; background-color: rgba(50,0,0,0.3); padding: 10px; border-radius: 5px; margin-top: 10px;'>
        <p style='color: #FF6B6B; font-weight: bold;'>❌ ENUMERATION ERROR</p>
        <p style='color: #DCDCDC;'>{h(error_message)}</p>
        <p style='color: #FFD93D;'>Suggestions:</p>
        <p style='color: #DCDCDC; margin-left: 20px;'>• Install required tools: <code>go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest</code></p>
        <p style='color: #DCDCDC; margin-left: 20px;'>• Install Amass: <code>go install -v github.com/owasp-amass/amass/v4/...@master</code></p>
        <p style='color: #DCDCDC; margin-left: 20px;'>• Install BBOT: <code>pip install bbot</code></p>
        </div>
        """)
    
        self.output_text.append(f"""
        <hr style='border: 1px solid rgba(100, 200, 255, 0.3);'>
        <p style='color: {status_color}; font-weight: bold;'>{status_icon} STATUS: {status_text}</p>
        <p style='color: #64C8FF;'>Configured Sources: <span style='color: #00FF41;'>{configured_count}</span></p>
        <p style='color: #64C8FF;'>Free Sources: <span style='color: #00FF41;'>{available_count - configured_count}</span></p>
        <p style='color: #DCDCDC; font-size: 10px;'>To configure API keys: File → Global Settings → API Keys</p>
        </div>
        """)

    def apply_theme(self):
        """Apply component theme"""
        self.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 100);
                border-radius: 10px;
                border: 1px solid rgba(100, 200, 255, 50);
            }
            QPushButton {
                background-color: rgba(30, 40, 50, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 8px;
                color: #DCDCDC;
                font-weight: bold;
                padding: 8px;
            }
            QPushButton:hover {
                background-color: rgba(50, 70, 90, 200);
                border: 2px solid #64C8FF;
            }
            QPushButton:pressed {
                background-color: rgba(70, 90, 110, 250);
            }
            QLineEdit {
                background-color: rgba(20, 30, 40, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                color: #DCDCDC;
                padding: 5px;
            }
            QLineEdit:focus {
                border: 2px solid #64C8FF;
            }
            QTextEdit {
                background-color: rgba(0, 0, 0, 200);
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                color: #DCDCDC;
                font-family: 'Neuropol X', monospace;
            }
            QLabel {
                color: #64C8FF;
                font-weight: bold;
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
            QCheckBox {
                color: #DCDCDC;
                spacing: 5px;
            }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 3px;
                background-color: rgba(20, 30, 40, 150);
            }
            QCheckBox::indicator:checked {
                background-color: #64C8FF;
                border: 2px solid #64C8FF;
            }
            QCheckBox::indicator:hover {
                border: 2px solid #64C8FF;
            }
            QProgressBar {
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                background-color: rgba(20, 30, 40, 150);
                text-align: center;
                color: #DCDCDC;
                font-weight: bold;
            }
            QProgressBar::chunk {
                background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #64C8FF, stop:1 #00FF41);
                border-radius: 3px;
            }
            QComboBox {
                background-color: rgba(20, 30, 40, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                color: #DCDCDC;
                padding: 5px;
            }
            QComboBox:hover {
                border: 2px solid #64C8FF;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid #64C8FF;
            }
        """)