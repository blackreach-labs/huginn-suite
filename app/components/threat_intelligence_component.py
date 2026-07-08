from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QLineEdit, QPushButton, QTextEdit, QFrame, QGroupBox)
from PyQt6.QtCore import pyqtSignal

class ThreatIntelligenceComponent(QWidget):
    intel_started = pyqtSignal(str, str)
    intel_completed = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._worker = None
        self.setup_ui()
        self.apply_theme()

    def setup_ui(self):
        """Setup threat intelligence UI"""
        layout = QHBoxLayout(self)
        
        left_panel = self.create_controls_panel()
        layout.addWidget(left_panel)
        
        right_panel = self.create_output_panel()
        layout.addWidget(right_panel, 2)

    def create_controls_panel(self):
        """Create controls panel"""
        panel = QFrame()
        panel.setFixedWidth(300)
        layout = QVBoxLayout(panel)
        
        target_group = QGroupBox("Target Configuration")
        target_layout = QVBoxLayout(target_group)
        target_layout.addWidget(QLabel("IOC/Domain/IP:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("malicious.com or 192.168.1.1")
        target_layout.addWidget(self.target_input)
        layout.addWidget(target_group)
        
        modules_group = QGroupBox("Threat Intelligence")
        modules_layout = QVBoxLayout(modules_group)
        
        buttons = [
            ("VirusTotal Scan", self.run_virustotal_scan),
            ("Shodan Lookup", self.run_shodan_lookup),
            ("URLScan Reputation", self.run_urlvoid_check),
            ("AlienVault OTX", self.run_alienvault_otx),
            ("ThreatFox", self.run_threatfox),
            ("Malware Bazaar", self.run_malware_bazaar),
            ("Full Threat Intel", self.run_full_threat_intel),
        ]
        
        for text, method in buttons:
            btn = QPushButton(text)
            btn.clicked.connect(method)
            btn.setMinimumHeight(30)
            modules_layout.addWidget(btn)
        
        layout.addWidget(modules_group)
        layout.addStretch()
        
        return panel

    def create_output_panel(self):
        """Create output panel"""
        panel = QFrame()
        layout = QVBoxLayout(panel)
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setPlaceholderText("Threat intelligence results will appear here...")
        layout.addWidget(self.output_text)
        
        return panel

    def _run_module(self, func, name):
        """Run a threat intel module in background."""
        target = self.target_input.text().strip()
        if not target:
            self.output_text.setHtml("<p style='color: #FFA500;'>⚠ Please enter a target</p>")
            return

        self.intel_started.emit(target, name)
        self.output_text.clear()
        self.output_text.append(f"<p style='color: #64C8FF;'>[{name.upper()}] Querying for {target}...</p>")

        from app.core.osint_workers import OSINTWorker
        self._worker = OSINTWorker(func, target)
        self._worker.output_signal.connect(lambda msg: self.output_text.append(f"<p style='color: #DCDCDC;'>{msg}</p>"))
        self._worker.result_signal.connect(lambda r: self._display_results(r, name))
        self._worker.finished_signal.connect(lambda: self.intel_completed.emit({}))
        self._worker.start()

    def run_virustotal_scan(self):
        from app.core.threat_intel_engine import virustotal_scan
        self._run_module(virustotal_scan, "VirusTotal")

    def run_shodan_lookup(self):
        from app.core.threat_intel_engine import shodan_lookup
        self._run_module(shodan_lookup, "Shodan")

    def run_urlvoid_check(self):
        from app.core.threat_intel_engine import urlvoid_check
        self._run_module(urlvoid_check, "URLScan")

    def run_alienvault_otx(self):
        from app.core.threat_intel_engine import alienvault_otx
        self._run_module(alienvault_otx, "AlienVault OTX")

    def run_threatfox(self):
        from app.core.threat_intel_engine import threatfox_lookup
        self._run_module(threatfox_lookup, "ThreatFox")

    def run_malware_bazaar(self):
        from app.core.threat_intel_engine import malware_bazaar
        self._run_module(malware_bazaar, "Malware Bazaar")

    def run_full_threat_intel(self):
        from app.core.threat_intel_engine import full_threat_intel
        target = self.target_input.text().strip()
        if not target:
            self.output_text.setHtml("<p style='color: #FFA500;'>⚠ Please enter a target</p>")
            return

        self.intel_started.emit(target, "Full Threat Intel")
        self.output_text.clear()
        self.output_text.append(f"<p style='color: #64C8FF; font-weight: bold;'>[FULL THREAT INTEL] Comprehensive analysis for {target}...</p>")

        from app.core.osint_workers import OSINTWorker
        self._worker = OSINTWorker(full_threat_intel, target)
        self._worker.output_signal.connect(lambda msg: self.output_text.append(f"<p style='color: #DCDCDC;'>{msg}</p>"))
        self._worker.result_signal.connect(self._display_full_results)
        self._worker.finished_signal.connect(lambda: self.intel_completed.emit({}))
        self._worker.start()

    def _display_results(self, results, module_name):
        """Display results from a single module."""
        from app.core.html_utils import h

        errors = results.get("errors", [])
        if errors:
            for err in errors:
                self.output_text.append(f"<p style='color: #FF6B6B;'>⚠ {h(err)}</p>")
            if not any(k for k in results if k not in ("target", "errors") and results[k]):
                return

        self.output_text.append(f"<p style='color: #00FF41; font-weight: bold;'>✅ {module_name} Complete</p>")

        # VirusTotal
        if "detections" in results:
            det = results["detections"]
            total = results.get("total_engines", 0)
            color = "#FF6B6B" if det > 5 else "#FFA500" if det > 0 else "#00FF41"
            self.output_text.append(f"<p style='color: {color}; font-weight: bold;'>Detections: {det}/{total}</p>")
            for d in results.get("details", [])[:10]:
                self.output_text.append(f"<p style='color: #FF6B6B; margin-left: 15px;'>• {h(d['engine'])}: {h(d['result'])}</p>")

        # Shodan
        if "ports" in results and results["ports"]:
            self.output_text.append(f"<p style='color: #DCDCDC;'>IP: {results.get('ip', 'N/A')} | Org: {h(results.get('org', 'N/A'))}</p>")
            self.output_text.append(f"<p style='color: #FFD93D;'>Open Ports: {', '.join(str(p) for p in results['ports'][:20])}</p>")
            if results.get("vulns"):
                self.output_text.append(f"<p style='color: #FF6B6B; font-weight: bold;'>Vulnerabilities: {', '.join(results['vulns'][:10])}</p>")
            for svc in results.get("services", [])[:8]:
                self.output_text.append(f"<p style='color: #DCDCDC; margin-left: 15px;'>• {svc['port']}/{svc['transport']} — {h(svc.get('product', ''))} {h(svc.get('version', ''))}</p>")

        # URLScan
        if "total_scans" in results:
            self.output_text.append(f"<p style='color: #DCDCDC;'>Total scans: {results['total_scans']}</p>")
            if results.get("verdicts"):
                self.output_text.append(f"<p style='color: #FF6B6B;'>Malicious verdicts: {len(results['verdicts'])}</p>")

        # OTX
        if "pulse_count" in results:
            count = results["pulse_count"]
            color = "#FF6B6B" if count > 5 else "#FFA500" if count > 0 else "#00FF41"
            self.output_text.append(f"<p style='color: {color};'>Threat Pulses: {count}</p>")
            for pulse in results.get("pulses", [])[:5]:
                self.output_text.append(f"<p style='color: #DCDCDC; margin-left: 15px;'>• {h(pulse['name'][:60])}</p>")

        # ThreatFox
        if "iocs" in results:
            total = results.get("total", 0)
            if total > 0:
                self.output_text.append(f"<p style='color: #FF6B6B;'>IOCs found: {total}</p>")
                for ioc in results["iocs"][:8]:
                    self.output_text.append(f"<p style='color: #DCDCDC; margin-left: 15px;'>• {h(ioc.get('threat_type', ''))} — {h(ioc.get('malware', 'unknown'))} (confidence: {ioc.get('confidence', 0)}%)</p>")
                if results.get("tags"):
                    self.output_text.append(f"<p style='color: #FFD93D;'>Tags: {', '.join(results['tags'][:10])}</p>")
            else:
                self.output_text.append("<p style='color: #00FF41;'>No threat IOCs found — target appears clean</p>")

        # Malware Bazaar
        if "samples" in results and results["samples"]:
            self.output_text.append(f"<p style='color: #FF6B6B;'>Malware Samples: {results['total']}</p>")
            for s in results["samples"][:5]:
                self.output_text.append(f"<p style='color: #DCDCDC; margin-left: 15px;'>• {h(s.get('signature', 'unknown'))} — {h(s.get('file_type', ''))} ({s.get('first_seen', '')[:10]})</p>")

    def _display_full_results(self, results):
        """Display comprehensive threat intel results."""
        self.output_text.append("<p style='color: #00FF41; font-weight: bold; font-size: 14px;'>✅ COMPREHENSIVE THREAT INTEL COMPLETE</p>")

        modules = [
            ("virustotal", "VirusTotal"),
            ("shodan", "Shodan"),
            ("urlscan", "URLScan"),
            ("otx", "AlienVault OTX"),
            ("threatfox", "ThreatFox"),
            ("malware_bazaar", "Malware Bazaar"),
        ]

        for key, name in modules:
            module_results = results.get(key, {})
            if module_results:
                self.output_text.append(f"<p style='color: #64C8FF; font-weight: bold; margin-top: 8px;'>━━ {name} ━━</p>")
                self._display_results(module_results, name)

    def apply_theme(self):
        """Theme is applied globally by UnifiedThemeManager."""
        pass
