"""
IDS/IPS Behavioral Detection via Traffic Analysis

Implements IDSIPSDetectorWorker - a QRunnable that detects Intrusion Detection
and Prevention Systems through behavioral analysis: signature-based detection,
timing anomaly analysis, and rate-limiting threshold detection.

Uses raw socket connections for HTTP requests to have precise control over
timing and connection behavior.
"""

import logging
import socket
import time
from typing import Dict, List, Optional, Tuple

from PyQt6.QtCore import QRunnable

from app.core.html_utils import h
from app.tools.av_firewall_utils import (
    AVFWWorkerSignals,
    IDSResult,
    COLOR_SUCCESS,
    COLOR_ERROR,
    COLOR_INFO,
    COLOR_WARNING,
    validate_target,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Attack Signature Payloads
# =============================================================================

_SQLI_PAYLOAD = "GET /?id=1'%20OR%20'1'='1 HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
_XSS_PAYLOAD = "GET /?q=<script>alert(1)</script> HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
_PATH_TRAVERSAL_PAYLOAD = "GET /../../etc/passwd HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"

_BENIGN_REQUEST = "GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\n\r\n"

# Attack categories mapped to their payloads
_ATTACK_SIGNATURES = {
    "sqli": _SQLI_PAYLOAD,
    "xss": _XSS_PAYLOAD,
    "path_traversal": _PATH_TRAVERSAL_PAYLOAD,
}

# Rate limiting test rates (connections per second)
_RATE_LEVELS = [1, 5, 10, 20, 50]

# Number of connections to send at each rate level
_CONNECTIONS_PER_RATE = 10


class IDSIPSDetectorWorker(QRunnable):
    """
    IDS/IPS behavioral detection worker.

    Detects Intrusion Detection and Prevention Systems through:
    1. Signature-based detection: Send benign then attack requests, observe resets/timeouts
    2. Timing analysis: Compare baseline vs attack response times for IPS inspection
    3. Rate limiting: Send connections at increasing rates to find threshold

    Signals:
        output(str): HTML-formatted scan output
        status(str): Status bar text
        finished(): Scan complete
        results_ready(dict): Structured IDSResult as dict
        progress_start(int): Total phase count
        progress_update(int, int): (completed_phases, findings_count)
    """

    def __init__(self, target: str, ports: List[int], timeout: float = 3.0):
        super().__init__()
        self.signals = AVFWWorkerSignals()
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.is_running = True

    def run(self):
        """Execute IDS/IPS behavioral detection."""
        # Validate target
        if not validate_target(self.target):
            self.signals.output.emit(
                f"<p style='color: {COLOR_ERROR};'>[ERROR] Invalid target: "
                f"target cannot be empty or None</p>"
            )
            self.signals.finished.emit()
            return

        # Resolve hostname
        try:
            resolved_target = socket.gethostbyname(self.target)
        except socket.gaierror as e:
            self.signals.output.emit(
                f"<p style='color: {COLOR_ERROR};'>[ERROR] DNS resolution failed for "
                f"{h(self.target)}: {h(str(e))}</p>"
            )
            self.signals.finished.emit()
            return

        self.signals.status.emit(f"Starting IDS/IPS detection on {self.target}...")
        self.signals.output.emit(
            f"<p style='color: {COLOR_INFO};'>[*] IDS/IPS Behavioral Detection - "
            f"Target: {h(self.target)} ({h(resolved_target)})</p>"
        )
        self.signals.output.emit(
            f"<p style='color: {COLOR_INFO};'>[*] Ports to test: "
            f"{len(self.ports)} | Timeout: {self.timeout}s</p>"
        )

        # Phase 1: Find open ports by sending benign requests
        open_ports = self._find_open_ports(resolved_target)

        if not self.is_running:
            self._emit_cancelled()
            return

        # Requirement 6.6: Abort if no open ports found
        if not open_ports:
            self.signals.output.emit(
                f"<p style='color: {COLOR_WARNING};'>[!] No open ports found on target. "
                f"IDS/IPS detection requires at least one accessible port. Aborting.</p>"
            )
            result = IDSResult(
                detected=False,
                detection_method="none",
                confidence="low",
                indicators=[],
                affected_ports=[],
                triggering_signatures=[],
                baseline_avg_ms=0.0,
                attack_avg_ms=0.0,
                rate_limit_threshold=None,
            )
            self._emit_results(result)
            return

        self.signals.output.emit(
            f"<p style='color: {COLOR_SUCCESS};'>[+] Found {len(open_ports)} "
            f"open port(s): {', '.join(str(p) for p in open_ports)}</p>"
        )

        # Total phases: baseline + attack + rate_limiting per open port
        total_phases = len(open_ports) * 3
        self.signals.progress_start.emit(total_phases)

        # Collect indicators across all ports
        indicators: List[Dict] = []
        affected_ports: List[int] = []
        triggering_signatures: List[str] = []
        all_baseline_times: List[float] = []
        all_attack_times: List[float] = []
        rate_limit_threshold: Optional[int] = None
        completed_phases = 0

        for port in open_ports:
            if not self.is_running:
                break

            self.signals.output.emit(
                f"<p style='color: {COLOR_INFO};'>[*] Testing port {port}...</p>"
            )

            # Phase 2: Establish baseline
            baseline_result = self.establish_baseline(port, resolved_target)
            completed_phases += 1
            self.signals.progress_update.emit(completed_phases, len(indicators))

            if not self.is_running:
                break

            if baseline_result is None:
                # Baseline failed, port not reliably accessible
                self.signals.output.emit(
                    f"<p style='color: {COLOR_WARNING};'>[!] Baseline failed for port "
                    f"{port}, skipping.</p>"
                )
                completed_phases += 2  # Skip attack and rate phases
                self.signals.progress_update.emit(completed_phases, len(indicators))
                continue

            baseline_times = baseline_result["times"]
            all_baseline_times.extend(baseline_times)

            # Phase 3: Send attack signatures
            attack_result = self.send_attack_signatures(port, resolved_target, baseline_times)
            completed_phases += 1
            self.signals.progress_update.emit(completed_phases, len(indicators))

            if not self.is_running:
                break

            if attack_result["ids_detected"]:
                indicators.append({
                    "type": "signature_based",
                    "port": port,
                    "detail": "Connection resets/timeouts on attack signatures",
                    "triggering_categories": attack_result["triggering_categories"],
                })
                affected_ports.append(port)
                triggering_signatures.extend(attack_result["triggering_categories"])

            if attack_result["ips_timing_detected"]:
                indicators.append({
                    "type": "timing_anomaly",
                    "port": port,
                    "detail": "Attack response time > 200% of baseline",
                    "baseline_avg_ms": attack_result["baseline_avg_ms"],
                    "attack_avg_ms": attack_result["attack_avg_ms"],
                })
                if port not in affected_ports:
                    affected_ports.append(port)

            all_attack_times.extend(attack_result.get("attack_times", []))

            # Phase 4: Rate limiting detection
            rate_result = self.detect_rate_limiting(port, resolved_target)
            completed_phases += 1
            self.signals.progress_update.emit(completed_phases, len(indicators))

            if not self.is_running:
                break

            if rate_result["detected"]:
                indicators.append({
                    "type": "rate_limiting",
                    "port": port,
                    "detail": f"Rate limiting detected at {rate_result['threshold']} conn/sec",
                    "threshold": rate_result["threshold"],
                })
                if port not in affected_ports:
                    affected_ports.append(port)
                # Use the lowest threshold found
                if rate_limit_threshold is None or rate_result["threshold"] < rate_limit_threshold:
                    rate_limit_threshold = rate_result["threshold"]

        if not self.is_running:
            self._emit_cancelled()
            return

        # Calculate overall averages
        baseline_avg_ms = (
            sum(all_baseline_times) / len(all_baseline_times)
            if all_baseline_times
            else 0.0
        )
        attack_avg_ms = (
            sum(all_attack_times) / len(all_attack_times)
            if all_attack_times
            else 0.0
        )

        # Determine confidence from indicator count
        confidence = self._compute_confidence(len(indicators))

        # Determine detection method
        detection_method = self._determine_detection_method(indicators)

        detected = len(indicators) > 0

        # Deduplicate triggering signatures
        triggering_signatures = list(set(triggering_signatures))

        result = IDSResult(
            detected=detected,
            detection_method=detection_method,
            confidence=confidence,
            indicators=indicators,
            affected_ports=sorted(set(affected_ports)),
            triggering_signatures=triggering_signatures,
            baseline_avg_ms=round(baseline_avg_ms, 2),
            attack_avg_ms=round(attack_avg_ms, 2),
            rate_limit_threshold=rate_limit_threshold,
        )

        self._emit_results(result)

    def establish_baseline(self, port: int, target: str = None) -> Optional[Dict]:
        """
        Send ≥3 benign HTTP requests to establish a response baseline.

        Args:
            port: Target port number.
            target: Resolved IP address (defaults to self.target).

        Returns:
            Dict with 'times' (list of response times in ms) and 'responses' count,
            or None if baseline could not be established (port not accessible).
        """
        if target is None:
            target = self.target

        host = self.target  # Use original hostname for Host header
        request = _BENIGN_REQUEST.format(host=host)
        times: List[float] = []
        successes = 0

        self.signals.output.emit(
            f"<p style='color: {COLOR_INFO};'>  [*] Establishing baseline on port "
            f"{port} (3 benign requests)...</p>"
        )

        for i in range(3):
            if not self.is_running:
                return None

            response_time, success = self._send_http_request(target, port, request)

            if success:
                successes += 1
                times.append(response_time)

        # Baseline requires all 3 requests to succeed
        if successes < 3:
            return None

        avg_ms = sum(times) / len(times) if times else 0.0
        self.signals.output.emit(
            f"<p style='color: {COLOR_SUCCESS};'>  [+] Baseline established: "
            f"avg {avg_ms:.1f}ms ({successes}/3 successful)</p>"
        )

        return {"times": times, "successes": successes}

    def send_attack_signatures(self, port: int, target: str = None,
                               baseline_times: List[float] = None) -> Dict:
        """
        Send attack signature requests (SQLi, XSS, path traversal) and detect IDS/IPS.

        Detection logic:
        - IDS inferred if ≥2 consecutive attack requests get reset/timeout
        - IPS flagged if attack avg response time > 200% of baseline avg

        Args:
            port: Target port number.
            target: Resolved IP address.
            baseline_times: List of baseline response times in ms.

        Returns:
            Dict with detection results.
        """
        if target is None:
            target = self.target
        if baseline_times is None:
            baseline_times = []

        host = self.target
        attack_times: List[float] = []
        consecutive_failures = 0
        max_consecutive_failures = 0
        triggering_categories: List[str] = []
        ids_detected = False

        self.signals.output.emit(
            f"<p style='color: {COLOR_INFO};'>  [*] Sending attack signatures to port "
            f"{port}...</p>"
        )

        for category, payload_template in _ATTACK_SIGNATURES.items():
            if not self.is_running:
                break

            payload = payload_template.format(host=host)
            response_time, success = self._send_http_request(target, port, payload)

            if success:
                attack_times.append(response_time)
                consecutive_failures = 0
            else:
                # Reset or timeout on attack request
                consecutive_failures += 1
                if consecutive_failures > max_consecutive_failures:
                    max_consecutive_failures = consecutive_failures

                if consecutive_failures >= 2:
                    ids_detected = True
                    if category not in triggering_categories:
                        triggering_categories.append(category)

        # Also track which categories triggered if IDS detected
        if ids_detected and not triggering_categories:
            # If detection happened across categories, note all failed ones
            triggering_categories = list(_ATTACK_SIGNATURES.keys())

        # Timing analysis: check if attack avg > 200% of baseline avg
        baseline_avg = sum(baseline_times) / len(baseline_times) if baseline_times else 0.0
        attack_avg = sum(attack_times) / len(attack_times) if attack_times else 0.0
        ips_timing_detected = False

        if baseline_avg > 0 and attack_avg > (baseline_avg * 2.0):
            ips_timing_detected = True
            self.signals.output.emit(
                f"<p style='color: {COLOR_WARNING};'>  [!] Timing anomaly: attack avg "
                f"{attack_avg:.1f}ms vs baseline avg {baseline_avg:.1f}ms "
                f"(>{200}% threshold) - inline IPS suspected</p>"
            )

        if ids_detected:
            self.signals.output.emit(
                f"<p style='color: {COLOR_WARNING};'>  [!] IDS detected on port {port}: "
                f"{max_consecutive_failures} consecutive resets/timeouts "
                f"(triggers: {', '.join(triggering_categories)})</p>"
            )

        if not ids_detected and not ips_timing_detected:
            self.signals.output.emit(
                f"<p style='color: {COLOR_INFO};'>  [-] No IDS/IPS indicators on port "
                f"{port} from signature testing</p>"
            )

        return {
            "ids_detected": ids_detected,
            "ips_timing_detected": ips_timing_detected,
            "max_consecutive_failures": max_consecutive_failures,
            "triggering_categories": triggering_categories,
            "baseline_avg_ms": round(baseline_avg, 2),
            "attack_avg_ms": round(attack_avg, 2),
            "attack_times": attack_times,
        }

    def detect_rate_limiting(self, port: int, target: str = None) -> Dict:
        """
        Detect rate limiting by sending connections at increasing rates.

        Sends connections at 1, 5, 10, 20, 50 per second. At each rate,
        sends 10 connections and checks success rate. When success rate
        drops below 50%, that rate is the threshold.

        Args:
            port: Target port number.
            target: Resolved IP address.

        Returns:
            Dict with 'detected' (bool) and 'threshold' (int or None).
        """
        if target is None:
            target = self.target

        self.signals.output.emit(
            f"<p style='color: {COLOR_INFO};'>  [*] Testing rate limiting on port "
            f"{port}...</p>"
        )

        detected = False
        threshold: Optional[int] = None

        for rate in _RATE_LEVELS:
            if not self.is_running:
                break

            successes = 0
            delay = 1.0 / rate  # Inter-connection delay for target rate

            for i in range(_CONNECTIONS_PER_RATE):
                if not self.is_running:
                    break

                success = self._attempt_tcp_connection(target, port)
                if success:
                    successes += 1

                # Sleep to maintain target rate (except after last connection)
                if i < _CONNECTIONS_PER_RATE - 1 and delay > 0.001:
                    time.sleep(delay)

            success_rate = successes / _CONNECTIONS_PER_RATE

            if success_rate < 0.5:
                # Rate limiting detected at this rate
                detected = True
                threshold = rate
                self.signals.output.emit(
                    f"<p style='color: {COLOR_WARNING};'>  [!] Rate limiting detected "
                    f"at {rate} conn/sec (success rate: {success_rate:.0%})</p>"
                )
                break
            else:
                self.signals.output.emit(
                    f"<p style='color: {COLOR_INFO};'>  [-] Rate {rate}/sec: "
                    f"{successes}/{_CONNECTIONS_PER_RATE} succeeded "
                    f"({success_rate:.0%})</p>"
                )

        if not detected:
            self.signals.output.emit(
                f"<p style='color: {COLOR_INFO};'>  [-] No rate limiting detected "
                f"up to {_RATE_LEVELS[-1]} conn/sec on port {port}</p>"
            )

        return {"detected": detected, "threshold": threshold}

    def _find_open_ports(self, resolved_target: str) -> List[int]:
        """
        Identify open ports by attempting a TCP connection to each port.

        Returns:
            List of port numbers that accepted a TCP connection.
        """
        open_ports: List[int] = []

        for port in self.ports:
            if not self.is_running:
                break

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((resolved_target, port))
                sock.close()

                if result == 0:
                    open_ports.append(port)
            except (socket.timeout, OSError):
                pass

        return open_ports

    def _send_http_request(self, target: str, port: int,
                           request: str) -> Tuple[float, bool]:
        """
        Send an HTTP request via raw socket and measure response time.

        Args:
            target: Target IP address.
            port: Target port number.
            request: HTTP request string to send.

        Returns:
            Tuple of (response_time_ms, success). Success is True if a
            response was received without reset or timeout.
        """
        start_time = time.perf_counter()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            sock.sendall(request.encode("utf-8", errors="replace"))

            # Try to receive a response
            response = sock.recv(4096)
            elapsed_ms = (time.perf_counter() - start_time) * 1000

            sock.close()

            if response:
                return elapsed_ms, True
            else:
                return elapsed_ms, False

        except ConnectionResetError:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return elapsed_ms, False
        except socket.timeout:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return elapsed_ms, False
        except OSError:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return elapsed_ms, False

    def _attempt_tcp_connection(self, target: str, port: int) -> bool:
        """
        Attempt a simple TCP connection to check if the port is accessible.

        Args:
            target: Target IP address.
            port: Target port number.

        Returns:
            True if connection succeeded, False otherwise.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            return result == 0
        except (socket.timeout, OSError):
            return False

    def _compute_confidence(self, indicator_count: int) -> str:
        """
        Map indicator count to confidence level.

        1 indicator → "low"
        2 indicators → "medium"
        3+ indicators → "high"

        Args:
            indicator_count: Number of behavioral indicators detected.

        Returns:
            Confidence string: "low", "medium", or "high".
        """
        if indicator_count >= 3:
            return "high"
        elif indicator_count == 2:
            return "medium"
        elif indicator_count == 1:
            return "low"
        else:
            return "low"

    def _determine_detection_method(self, indicators: List[Dict]) -> str:
        """
        Determine the primary detection method from collected indicators.

        Returns:
            "signature", "timing", "rate_limiting", "multiple", or "none".
        """
        if not indicators:
            return "none"

        types = set(ind["type"] for ind in indicators)

        if len(types) > 1:
            return "multiple"
        elif "signature_based" in types:
            return "signature"
        elif "timing_anomaly" in types:
            return "timing"
        elif "rate_limiting" in types:
            return "rate_limiting"
        else:
            return "none"

    def _emit_cancelled(self):
        """Emit results for a cancelled scan."""
        self.signals.output.emit(
            f"<p style='color: {COLOR_WARNING};'>[!] IDS/IPS detection cancelled.</p>"
        )
        self.signals.results_ready.emit({
            "target": self.target,
            "scan_type": "ids_ips_detection",
            "detected": False,
            "detection_method": "none",
            "confidence": "low",
            "indicators": [],
            "affected_ports": [],
            "triggering_signatures": [],
            "baseline_avg_ms": 0.0,
            "attack_avg_ms": 0.0,
            "rate_limit_threshold": None,
            "partial": True,
            "error": None,
        })
        self.signals.finished.emit()

    def _emit_results(self, result: IDSResult):
        """Format and emit final IDS/IPS detection results."""
        self.signals.output.emit(
            f"<p style='color: {COLOR_INFO};'>{'─' * 40}</p>"
        )
        self.signals.output.emit(
            f"<p style='color: {COLOR_INFO};'>[*] IDS/IPS Detection Summary</p>"
        )

        if result.detected:
            self.signals.output.emit(
                f"<p style='color: {COLOR_WARNING};'>[!] IDS/IPS DETECTED</p>"
            )
            self.signals.output.emit(
                f"<p style='color: {COLOR_INFO};'>[*] Detection method: "
                f"{h(result.detection_method)}</p>"
            )
            self.signals.output.emit(
                f"<p style='color: {COLOR_INFO};'>[*] Confidence: "
                f"{h(result.confidence)}</p>"
            )
            self.signals.output.emit(
                f"<p style='color: {COLOR_INFO};'>[*] Affected ports: "
                f"{', '.join(str(p) for p in result.affected_ports)}</p>"
            )

            if result.triggering_signatures:
                self.signals.output.emit(
                    f"<p style='color: {COLOR_INFO};'>[*] Triggering signatures: "
                    f"{', '.join(h(s) for s in result.triggering_signatures)}</p>"
                )

            if result.rate_limit_threshold is not None:
                self.signals.output.emit(
                    f"<p style='color: {COLOR_INFO};'>[*] Rate limit threshold: "
                    f"{result.rate_limit_threshold} conn/sec</p>"
                )

            # Display indicators
            for ind in result.indicators:
                self.signals.output.emit(
                    f"<p style='color: {COLOR_WARNING};'>  [!] {h(ind['type'])}: "
                    f"{h(ind['detail'])}</p>"
                )
        else:
            self.signals.output.emit(
                f"<p style='color: {COLOR_SUCCESS};'>[+] No IDS/IPS detected</p>"
            )

        self.signals.output.emit(
            f"<p style='color: {COLOR_INFO};'>[*] Baseline avg: "
            f"{result.baseline_avg_ms:.1f}ms | Attack avg: "
            f"{result.attack_avg_ms:.1f}ms</p>"
        )

        # Build structured result dict
        result_dict = {
            "target": self.target,
            "scan_type": "ids_ips_detection",
            "detected": result.detected,
            "detection_method": result.detection_method,
            "confidence": result.confidence,
            "indicators": result.indicators,
            "affected_ports": result.affected_ports,
            "triggering_signatures": result.triggering_signatures,
            "baseline_avg_ms": result.baseline_avg_ms,
            "attack_avg_ms": result.attack_avg_ms,
            "rate_limit_threshold": result.rate_limit_threshold,
            "detected_security_products": (
                [{"type": "ids_ips", "name": result.detection_method}]
                if result.detected
                else []
            ),
            "filtered_ports": [],
            "successful_evasion_techniques": [],
            "confidence_scores": (
                {"ids_ips_detection": {"low": 33, "medium": 66, "high": 90}.get(result.confidence, 0)}
                if result.detected
                else {}
            ),
            "recommended_next_steps": (
                [
                    "Use encrypted channels (HTTPS/TLS) to evade signature inspection",
                    "Fragment attack payloads to bypass pattern matching",
                    "Test evasion techniques at detected rate threshold",
                ]
                if result.detected
                else []
            ),
            "error": None,
        }

        self.signals.results_ready.emit(result_dict)
        self.signals.status.emit("IDS/IPS detection completed")
        self.signals.finished.emit()
