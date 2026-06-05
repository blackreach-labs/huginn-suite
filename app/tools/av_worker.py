# app/tools/av_worker.py
"""
AV/Firewall Detection Worker - Dispatcher
Routes detection requests to specialized worker modules based on detection_type.

Maintains the same signal interface (output, finished, results, error) for
backward compatibility with service_scanners.py UI integration.
"""

from PyQt6.QtCore import QObject, pyqtSignal, QRunnable
from app.tools.av_firewall_scanner import av_firewall_scanner
from app.tools.av_firewall_utils import parse_port_list
import logging
from app.core.html_utils import h

logger = logging.getLogger(__name__)


# =============================================================================
# Port Presets (Requirement 7.4)
# =============================================================================

TOP_20_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080
]

TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
    113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
    513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
    1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000,
    2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009,
    5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001,
    6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000,
    32768, 49152, 49153, 49154, 49155, 49156, 49157
]

TOP_1000_PORTS = list(range(1, 1001))


class AVFirewallWorkerSignals(QObject):
    """Signals for AV/Firewall detection worker"""
    output = pyqtSignal(str)
    finished = pyqtSignal()
    results = pyqtSignal(dict)
    error = pyqtSignal(str)
    progress_start = pyqtSignal(int)        # Total probe count
    progress_update = pyqtSignal(int, int)  # (completed, findings)


class AVFirewallWorker(QRunnable):
    """
    AV/Firewall detection dispatcher worker.

    Routes detection requests to specialized workers based on detection_type:
      - "WAF Detection" → av_firewall_scanner.detect_waf()
      - "Firewall Detection" → FirewallDetectorWorker
      - "Evasion Testing" → EvasionProfilerWorker
      - "AV Payload Generation" → PayloadGeneratorWorker
      - "IDS/IPS Detection" → IDSIPSDetectorWorker

    Maintains the same signal interface (output, finished, results, error) for
    backward compatibility with service_scanners.py.
    """

    def __init__(self, target, detection_type="WAF Detection", port=80,
                 port_preset="top-20", custom_ports="", timeout=3.0,
                 max_workers=50):
        super().__init__()
        self.target = target
        self.detection_type = detection_type
        self.port = int(port)
        self.port_preset = port_preset
        self.custom_ports = custom_ports
        self.timeout = timeout
        self.max_workers = max_workers
        self.signals = AVFirewallWorkerSignals()
        self.is_running = True
        self._child_worker = None

    def _resolve_ports(self):
        """Resolve port list from preset or custom specification."""
        if self.custom_ports and self.custom_ports.strip():
            try:
                return parse_port_list(self.custom_ports)
            except ValueError as e:
                self.signals.output.emit(
                    f"<p style='color: #FFAA00;'>[WARNING] Invalid port spec: {h(str(e))}. "
                    f"Falling back to preset '{h(self.port_preset)}'.</p><br>"
                )

        preset_map = {
            "top-20": TOP_20_PORTS,
            "top-100": TOP_100_PORTS,
            "top-1000": TOP_1000_PORTS,
        }
        return preset_map.get(self.port_preset, TOP_20_PORTS)

    def run(self):
        """Execute AV/Firewall detection by dispatching to specialized workers."""
        try:
            self.signals.output.emit(
                f"<p style='color: #00BFFF;'>[AV DETECTION] Starting "
                f"{h(self.detection_type)} on {h(self.target)}</p><br>"
            )

            if not self.is_running:
                return

            if self.detection_type == "WAF Detection":
                self._run_waf_detection()
            elif self.detection_type == "Firewall Detection":
                self._run_firewall_detection()
            elif self.detection_type in ("Evasion Testing", "Evasion Test"):
                self._run_evasion_testing()
            elif self.detection_type in ("AV Payload Generation", "AV Payload Gen"):
                self._run_payload_generation()
            elif self.detection_type == "IDS/IPS Detection":
                self._run_ids_ips_detection()
            elif self.detection_type == "Full Detection":
                self._run_firewall_detection()
            else:
                error_msg = f"Unknown detection type: {self.detection_type}"
                self.signals.error.emit(error_msg)
                self.signals.output.emit(
                    f"<p style='color: #FF6B6B;'>[ERROR] {h(error_msg)}</p><br>"
                )

        except Exception as e:
            error_msg = f"AV/Firewall detection failed: {str(e)}"
            logger.error(error_msg)
            self.signals.error.emit(error_msg)
            self.signals.output.emit(
                f"<p style='color: #FF6B6B;'>[ERROR] {h(error_msg)}</p><br>"
            )
        finally:
            self.signals.finished.emit()

    def _run_waf_detection(self):
        """Run WAF detection using the existing av_firewall_scanner."""
        self.signals.output.emit(
            f"<p style='color: #87CEEB;'>Testing for Web Application Firewall...</p><br>"
        )

        waf_results = av_firewall_scanner.detect_waf(self.target, self.port)

        results = {
            'target': self.target,
            'detection_type': self.detection_type,
            'scan_type': 'waf_detection',
            'port': self.port,
            'detections': [],
            'detected_security_products': [],
            'filtered_ports': [],
            'successful_evasion_techniques': [],
            'confidence_scores': {},
            'recommended_next_steps': [],
            'error': None,
        }

        if waf_results.get('error'):
            self.signals.output.emit(
                f"<p style='color: #FF6B6B;'>[ERROR] {h(waf_results['error'])}</p><br>"
            )
            results['error'] = waf_results['error']
        else:
            if waf_results.get('waf_detected'):
                waf_type = waf_results.get('waf_type', 'Unknown')
                self.signals.output.emit(
                    f"<p style='color: #FF6B6B;'>WAF DETECTED: {h(waf_type)}</p><br>"
                )
                results['detected_security_products'].append({
                    'type': 'WAF',
                    'name': waf_type,
                })
                results['confidence_scores']['waf_detection'] = (
                    waf_results.get('confidence', 80)
                )
                for indicator in waf_results.get('indicators', []):
                    self.signals.output.emit(
                        f"<p style='color: #FFAA00;'>  - {h(indicator)}</p><br>"
                    )
            else:
                self.signals.output.emit(
                    f"<p style='color: #00FF41;'>No WAF detected</p><br>"
                )

        # Include raw WAF results as additional context
        for key, value in waf_results.items():
            if key not in results:
                results[key] = value

        # Sync detections with detected_security_products for UI compatibility
        results['detections'] = results['detected_security_products']

        self._emit_summary(results)
        self.signals.results.emit(results)

    def _run_firewall_detection(self):
        """Run native firewall detection via FirewallDetectorWorker."""
        from app.tools.firewall_detector import FirewallDetectorWorker

        ports = self._resolve_ports()
        self.signals.output.emit(
            f"<p style='color: #87CEEB;'>Starting native firewall detection "
            f"({len(ports)} ports, timeout={self.timeout}s)...</p><br>"
        )

        worker = FirewallDetectorWorker(
            target=self.target,
            ports=ports,
            timeout=self.timeout,
            max_workers=self.max_workers
        )
        self._child_worker = worker

        # Connect child signals to parent signals
        worker.signals.output.connect(self.signals.output.emit)
        worker.signals.progress_start.connect(self.signals.progress_start.emit)
        worker.signals.progress_update.connect(self._on_progress_update)

        # Capture results emitted by child worker via signal
        captured_results = {}
        worker.signals.results_ready.connect(lambda data: captured_results.update(data))

        # Run synchronously within this worker's thread
        worker.run()

        # Normalize to standard ScanResult format
        results = self._normalize_results(captured_results, "Firewall Detection")
        self._emit_summary(results)
        self.signals.results.emit(results)

    def _run_evasion_testing(self):
        """Run native evasion profiling via EvasionProfilerWorker."""
        from app.tools.evasion_profiler import EvasionProfilerWorker

        ports = self._resolve_ports()
        self.signals.output.emit(
            f"<p style='color: #87CEEB;'>Starting evasion profiling "
            f"({len(ports)} ports, timeout={self.timeout}s)...</p><br>"
        )

        worker = EvasionProfilerWorker(
            target=self.target,
            ports=ports,
            timeout=self.timeout,
            max_workers=self.max_workers
        )
        self._child_worker = worker

        # Connect child signals to parent signals
        worker.signals.output.connect(self.signals.output.emit)
        worker.signals.progress_start.connect(self.signals.progress_start.emit)
        worker.signals.progress_update.connect(self._on_progress_update)

        # Capture results emitted by child worker via signal
        captured_results = {}
        worker.signals.results_ready.connect(lambda data: captured_results.update(data))

        # Run synchronously
        worker.run()

        # Normalize to standard ScanResult format
        results = self._normalize_results(captured_results, "Evasion Testing")
        self._emit_summary(results)
        self.signals.results.emit(results)

    def _run_payload_generation(self):
        """Run native payload generation via PayloadGeneratorWorker."""
        from app.tools.payload_generator import PayloadGeneratorWorker

        self.signals.output.emit(
            f"<p style='color: #87CEEB;'>Generating AV test payload...</p><br>"
        )

        worker = PayloadGeneratorWorker(
            payload_type="reverse_tcp",
            payload_format="raw",
            architecture="x64",
            encoding="xor",
            lhost=self.target,
            lport=self.port if self.port != 80 else 4444,
            staged=False
        )
        self._child_worker = worker

        # Connect child signals to parent signals
        worker.signals.output.connect(self.signals.output.emit)

        # Capture results emitted by child worker via signal
        captured_results = {}
        worker.signals.results_ready.connect(lambda data: captured_results.update(data))

        # Run synchronously
        worker.run()

        # Normalize to standard ScanResult format
        results = self._normalize_results(captured_results, "AV Payload Generation")
        self._emit_summary(results)
        self.signals.results.emit(results)

    def _run_ids_ips_detection(self):
        """Run IDS/IPS behavioral detection via IDSIPSDetectorWorker."""
        from app.tools.ids_ips_detector import IDSIPSDetectorWorker

        ports = self._resolve_ports()
        self.signals.output.emit(
            f"<p style='color: #87CEEB;'>Starting IDS/IPS behavioral detection "
            f"({len(ports)} ports, timeout={self.timeout}s)...</p><br>"
        )

        worker = IDSIPSDetectorWorker(
            target=self.target,
            ports=ports,
            timeout=self.timeout
        )
        self._child_worker = worker

        # Connect child signals to parent signals
        worker.signals.output.connect(self.signals.output.emit)
        worker.signals.progress_start.connect(self.signals.progress_start.emit)
        worker.signals.progress_update.connect(self._on_progress_update)

        # Capture results emitted by child worker via signal
        captured_results = {}
        worker.signals.results_ready.connect(lambda data: captured_results.update(data))

        # Run synchronously
        worker.run()

        # Normalize to standard ScanResult format
        results = self._normalize_results(captured_results, "IDS/IPS Detection")
        self._emit_summary(results)
        self.signals.results.emit(results)

    def _normalize_results(self, raw_results, scan_type):
        """Normalize child worker results to the standard ScanResult output format.

        Ensures all required keys exist per Requirement 8.1:
        target, scan_type, detected_security_products, filtered_ports,
        successful_evasion_techniques, confidence_scores, error,
        recommended_next_steps, detection_type, detections.

        When filtered_ports is non-empty, includes recommended_next_steps
        per Requirement 8.3.
        """
        # Build the normalized result with all required keys
        detected_products = raw_results.get('detected_security_products', [])
        results = {
            'target': self.target,
            'detection_type': scan_type,
            'scan_type': raw_results.get('scan_type', scan_type.lower().replace(' ', '_')),
            'port': self.port,
            'detections': detected_products,
            'detected_security_products': detected_products,
            'filtered_ports': raw_results.get('filtered_ports', []),
            'successful_evasion_techniques': raw_results.get('successful_evasion_techniques', []),
            'confidence_scores': raw_results.get('confidence_scores', {}),
            'recommended_next_steps': raw_results.get('recommended_next_steps', []),
            'error': raw_results.get('error', None),
        }

        # Merge all child-specific keys
        for key, value in raw_results.items():
            if key not in results:
                results[key] = value

        # Requirement 8.3: When filtered_ports is non-empty, ensure
        # recommended_next_steps is populated
        if results['filtered_ports'] and not results['recommended_next_steps']:
            # Build recommended next steps based on scan type
            filtered_display = ', '.join(
                str(p) for p in results['filtered_ports'][:10]
            )
            results['recommended_next_steps'] = [
                "Run evasion testing against filtered ports",
                f"Prioritize filtered ports for exploitation: {filtered_display}",
            ]
            # Add evasion techniques not yet attempted
            if scan_type != "Evasion Testing":
                results['recommended_next_steps'].append(
                    "Test source port, timing, and TCP window size evasion techniques"
                )

        # Requirement 8.5: On failure, ensure error is set and detections empty
        if results['error']:
            results['detected_security_products'] = (
                results.get('detected_security_products') or []
            )
            results['detections'] = results['detected_security_products']

        # Requirement 8.6: When no products detected, ensure empty lists
        if not results['detected_security_products']:
            results['detected_security_products'] = []
            results['detections'] = []

        return results

    def _emit_summary(self, results):
        """Emit a summary message based on detection results."""
        detection_count = len(results.get('detections', []))
        if detection_count > 0:
            self.signals.output.emit(
                f"<p style='color: #00FF41;'>[COMPLETE] Detection completed - "
                f"{h(str(detection_count))} findings</p><br>"
            )
        else:
            self.signals.output.emit(
                f"<p style='color: #FFAA00;'>[COMPLETE] Detection completed - "
                f"no security measures detected</p><br>"
            )

    def _on_progress_update(self, completed, findings):
        """Forward progress updates from child worker to the progress widget."""
        self.signals.progress_update.emit(completed, findings)

    def cancel(self):
        """Cancel the running detection by setting is_running to False on self and child."""
        self.is_running = False
        if self._child_worker and hasattr(self._child_worker, 'is_running'):
            self._child_worker.is_running = False
