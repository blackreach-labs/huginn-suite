"""
Native Firewall Detection via TCP Probe Analysis

Implements FirewallDetectorWorker - a QRunnable that detects network firewalls
by analyzing TCP connect probe responses (open, closed, filtered) across a
target's port range.

Uses socket.connect_ex() to classify ports without requiring elevated privileges,
following the same pattern as PortScanWorker.
"""

import errno
import logging
import math
import random
import socket
import sys
import time
import concurrent.futures
from typing import Dict, List, Optional, Tuple

from PyQt6.QtCore import QRunnable

from app.core.html_utils import h
from app.tools.av_firewall_utils import (
    AVFWWorkerSignals,
    PortState,
    ProbeResult,
    FirewallResult,
    TimingFingerprint,
    COLOR_SUCCESS,
    COLOR_ERROR,
    COLOR_INFO,
    COLOR_WARNING,
    validate_target,
    validate_params,
)

logger = logging.getLogger(__name__)


# Platform-specific ECONNREFUSED errno
_ECONNREFUSED = 10061 if sys.platform == "win32" else errno.ECONNREFUSED
# Linux ECONNREFUSED is 111, but errno.ECONNREFUSED handles it portably

# Standard OS TTL defaults used for hop count estimation
_TTL_DEFAULTS = (64, 128, 255)


def _estimate_hop_count(ttl: int) -> int:
    """
    Estimate hop count by finding the nearest standard TTL default above
    the observed TTL and computing the difference.

    Standard defaults: 64 (Linux/macOS), 128 (Windows), 255 (network devices).

    Args:
        ttl: Observed TTL value (1-255).

    Returns:
        Estimated number of hops traversed.
    """
    if ttl <= 0:
        return 0
    # Find the smallest standard default >= observed TTL
    for default in _TTL_DEFAULTS:
        if ttl <= default:
            return default - ttl
    # If TTL is somehow > 255, assume 255 as the base
    return 255 - ttl


def _try_extract_ttl(sock: socket.socket) -> Optional[int]:
    """
    Attempt to extract TTL from a connected socket.

    Uses socket.IP_TTL option to read the TTL value. This works on some
    platforms for connected TCP sockets but is not universally available.

    Args:
        sock: A connected socket.

    Returns:
        TTL value if extraction succeeded, None otherwise.
    """
    try:
        ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
        if isinstance(ttl, int) and 0 < ttl <= 255:
            return ttl
    except (OSError, AttributeError, TypeError):
        pass
    return None


def _compute_mean(values: List[int]) -> float:
    """Compute arithmetic mean of a list of integers. Returns 0.0 if empty."""
    if not values:
        return 0.0
    return sum(values) / len(values)


def _compute_stddev(values: List[int]) -> float:
    """Compute population standard deviation of a list of integers. Returns 0.0 if fewer than 2 values."""
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    variance = sum((x - mean) ** 2 for x in values) / len(values)
    return math.sqrt(variance)


class FirewallDetectorWorker(QRunnable):
    """
    Native firewall detection worker using TCP connect probes.

    Classifies ports as open/closed/filtered via socket.connect_ex(),
    analyzes filtered ratio to determine firewall presence, and performs
    ACK-style probes on ephemeral ports to differentiate stateful vs
    packet-filter firewalls.

    Signals:
        output(str): HTML-formatted scan output
        status(str): Status bar text
        finished(): Scan complete
        results_ready(dict): Structured FirewallResult as dict
        progress_start(int): Total probe count
        progress_update(int, int): (completed, findings_count)
    """

    def __init__(self, target: str, ports: List[int], timeout: float = 3.0,
                 max_workers: int = 50):
        super().__init__()
        self.signals = AVFWWorkerSignals()
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.max_workers = min(max_workers, 50)  # Cap at 50 per Requirement 5.9
        self.is_running = True

    def run(self):
        """Execute the firewall detection scan."""
        # Validate target
        if not validate_target(self.target):
            self.signals.output.emit(
                f"<p style='color: {COLOR_ERROR};'>[ERROR] Invalid target: "
                f"target cannot be empty or None</p>"
            )
            self.signals.finished.emit()
            return

        # Validate parameters
        error = validate_params(self.timeout, self.max_workers, self.ports)
        if error:
            self.signals.output.emit(
                f"<p style='color: {COLOR_ERROR};'>[ERROR] {h(error)}</p>"
            )
            self.signals.finished.emit()
            return

        # Resolve hostname to validate target is reachable (DNS check)
        try:
            resolved_target = socket.gethostbyname(self.target)
        except socket.gaierror as e:
            self.signals.output.emit(
                f"<p style='color: {COLOR_ERROR};'>[ERROR] DNS resolution failed for "
                f"{h(self.target)}: {h(str(e))}</p>"
            )
            self.signals.finished.emit()
            return

        self.signals.status.emit(f"Starting firewall detection on {self.target}...")
        self.signals.output.emit(
            f"<p style='color: {COLOR_INFO};'>[*] Firewall Detection - "
            f"Probing {len(self.ports)} ports on {h(self.target)} "
            f"({h(resolved_target)})</p>"
        )
        self.signals.output.emit(
            f"<p style='color: {COLOR_INFO};'>[*] Timeout: {self.timeout}s | "
            f"Workers: {self.max_workers}</p>"
        )
        # Total includes port probes + 10 for ACK probe phase
        self._ack_probe_count = 10
        self.signals.progress_start.emit(len(self.ports) + self._ack_probe_count)

        # Perform port classification
        probe_results = self._probe_ports(resolved_target)

        # If cancelled mid-scan, emit partial results
        if not self.is_running:
            self._emit_partial_results(probe_results, resolved_target)
            return

        # Analyze firewall presence
        fw_result = self.analyze_firewall_presence(probe_results)

        # Perform timing and TTL analysis (Requirement 2)
        timing_fingerprint = self.analyze_timing(probe_results)
        if timing_fingerprint:
            fw_result.timing_fingerprint = timing_fingerprint
            self.signals.output.emit(
                f"<p style='color: {COLOR_INFO};'>[*] Timing analysis: "
                f"{h(timing_fingerprint.inferred_device_type)} "
                f"(confidence: {timing_fingerprint.confidence:.0%})</p>"
            )

        # Perform ACK probe if filtered ports exist
        if fw_result.filtered_ports and self.is_running:
            fw_type = self.perform_ack_probe(fw_result.filtered_ports, resolved_target)
            fw_result.firewall_type = fw_type
        else:
            # No ACK probe needed — advance progress to completion
            self.signals.progress_update.emit(
                len(self.ports) + self._ack_probe_count, 0
            )

        # Emit final results
        self._emit_results(fw_result)

    def classify_port(self, port: int, target: str = None) -> ProbeResult:
        """
        Classify a single port using socket.connect_ex().

        Returns:
            ProbeResult with state (OPEN, CLOSED, FILTERED) and response time in ms.
            TTL is extracted on a best-effort basis when platform supports it.
        """
        if target is None:
            target = self.target

        start_time = time.perf_counter()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result_code = sock.connect_ex((target, port))
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)

            # Attempt TTL extraction for connected sockets
            ttl = None
            if result_code == 0:
                ttl = _try_extract_ttl(sock)

            sock.close()

            if result_code == 0:
                return ProbeResult(
                    port=port,
                    state=PortState.OPEN,
                    response_time_ms=elapsed_ms,
                    ttl=ttl,
                    error_code=result_code,
                )
            elif result_code == _ECONNREFUSED:
                return ProbeResult(
                    port=port,
                    state=PortState.CLOSED,
                    response_time_ms=elapsed_ms,
                    ttl=None,
                    error_code=result_code,
                )
            else:
                # Any other error code treated as filtered
                return ProbeResult(
                    port=port,
                    state=PortState.FILTERED,
                    response_time_ms=elapsed_ms,
                    ttl=None,
                    error_code=result_code,
                )

        except socket.timeout:
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            return ProbeResult(
                port=port,
                state=PortState.FILTERED,
                response_time_ms=elapsed_ms,
                ttl=None,
                error_code=None,
            )
        except OSError as e:
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            # Network unreachable or other OS-level errors → filtered
            return ProbeResult(
                port=port,
                state=PortState.FILTERED,
                response_time_ms=elapsed_ms,
                ttl=None,
                error_code=e.errno,
            )

    def analyze_firewall_presence(self, results: List[ProbeResult]) -> FirewallResult:
        """
        Analyze probe results to determine firewall presence.

        Rules:
            - All ports unreachable (no open or closed) → "host unreachable"
            - filtered_ratio > 0.50 → "detected"
            - 0.20 < filtered_ratio <= 0.50 → "likely"
            - filtered_ratio <= 0.20 → "not detected"

        Returns:
            FirewallResult with firewall_status, ports lists, and confidence score.
        """
        open_ports = [r.port for r in results if r.state == PortState.OPEN]
        closed_ports = [r.port for r in results if r.state == PortState.CLOSED]
        filtered_ports = [r.port for r in results if r.state == PortState.FILTERED]

        total = len(results)

        # Handle edge case: no results
        if total == 0:
            return FirewallResult(
                target=self.target,
                firewall_status="host unreachable",
                firewall_type=None,
                confidence_score=0,
                filtered_ports=[],
                open_ports=[],
                closed_ports=[],
                filtered_ratio=0.0,
            )

        # All ports unreachable: no open AND no closed → host unreachable
        if len(open_ports) == 0 and len(closed_ports) == 0:
            return FirewallResult(
                target=self.target,
                firewall_status="host unreachable",
                firewall_type=None,
                confidence_score=0,
                filtered_ports=filtered_ports,
                open_ports=[],
                closed_ports=[],
                filtered_ratio=1.0 if total > 0 else 0.0,
            )

        filtered_ratio = len(filtered_ports) / total

        # Determine firewall status based on filtered ratio
        if filtered_ratio > 0.50:
            firewall_status = "detected"
            confidence_score = min(100, int(filtered_ratio * 100))
        elif filtered_ratio > 0.20:
            firewall_status = "likely"
            confidence_score = min(100, int(filtered_ratio * 150))
        else:
            firewall_status = "not detected"
            confidence_score = max(0, int((1.0 - filtered_ratio) * 20))

        return FirewallResult(
            target=self.target,
            firewall_status=firewall_status,
            firewall_type=None,  # Determined later by ACK probe
            confidence_score=confidence_score,
            filtered_ports=filtered_ports,
            open_ports=open_ports,
            closed_ports=closed_ports,
            filtered_ratio=filtered_ratio,
        )

    def perform_ack_probe(self, filtered_ports: List[int],
                          target: str = None) -> Optional[str]:
        """
        Perform ACK-style probe on ephemeral port range (49152–65535) to
        differentiate stateful vs packet-filter firewalls.

        Logic:
            - Probe 5-10 random ephemeral ports
            - If ephemeral ports are ALSO filtered → "stateful" (inspects all traffic)
            - If ephemeral ports are CLOSED (RST received) → "packet-filter" (blocks specific ports)

        Returns:
            "stateful", "packet-filter", or None if inconclusive.
        """
        if target is None:
            target = self.target

        # Select 5-10 random ports in ephemeral range
        num_probes = min(10, max(5, len(filtered_ports)))
        ephemeral_ports = random.sample(range(49152, 65536), num_probes)

        self.signals.output.emit(
            f"<p style='color: {COLOR_INFO};'>[*] ACK probe: testing "
            f"{num_probes} ephemeral ports (49152-65535)...</p>"
        )

        ephemeral_results = []
        base_progress = len(self.ports)  # Port probing already completed
        for i, port in enumerate(ephemeral_ports):
            if not self.is_running:
                break
            result = self.classify_port(port, target)
            ephemeral_results.append(result)
            # Update progress for ACK probe phase
            self.signals.progress_update.emit(
                base_progress + i + 1,
                sum(1 for r in ephemeral_results if r.state == PortState.FILTERED)
            )

        if not ephemeral_results:
            return None

        filtered_count = sum(
            1 for r in ephemeral_results if r.state == PortState.FILTERED
        )
        closed_count = sum(
            1 for r in ephemeral_results if r.state == PortState.CLOSED
        )

        total_probed = len(ephemeral_results)

        # If most ephemeral ports are filtered → stateful firewall
        if filtered_count > total_probed * 0.5:
            self.signals.output.emit(
                f"<p style='color: {COLOR_WARNING};'>[!] Ephemeral ports filtered - "
                f"stateful firewall inferred</p>"
            )
            return "stateful"
        # If most are closed (RST) → packet-filter on specific ports
        elif closed_count > total_probed * 0.5:
            self.signals.output.emit(
                f"<p style='color: {COLOR_INFO};'>[*] Ephemeral ports closed (RST) - "
                f"packet-filter inferred</p>"
            )
            return "packet-filter"

        return None

    def analyze_timing(self, probe_results: List[ProbeResult],
                       threshold_ms: float = 500.0) -> Optional[TimingFingerprint]:
        """
        Analyze timing and TTL data from probe results to produce a fingerprint.

        Computes mean and standard deviation of response times per port state
        (open, closed, filtered) when at least 5 ports have been probed total.
        Infers "active filtering" when |mean_filtered - mean_closed| exceeds
        the configured threshold.

        Attempts TTL-based hop count estimation and flags intermediate devices
        when hop count difference between port states is >= 2.

        Args:
            probe_results: List of ProbeResult from port probing.
            threshold_ms: Threshold in ms for active filtering inference.
                         Default 500ms, valid range 100-10000ms.

        Returns:
            TimingFingerprint if at least 5 ports were probed, None otherwise.
        """
        if len(probe_results) < 5:
            return None

        # Clamp threshold to valid range
        threshold_ms = max(100.0, min(10000.0, threshold_ms))

        # Separate response times by state
        open_times = [r.response_time_ms for r in probe_results if r.state == PortState.OPEN]
        closed_times = [r.response_time_ms for r in probe_results if r.state == PortState.CLOSED]
        filtered_times = [r.response_time_ms for r in probe_results if r.state == PortState.FILTERED]

        # Compute mean and stddev per category
        mean_open = _compute_mean(open_times)
        mean_closed = _compute_mean(closed_times)
        mean_filtered = _compute_mean(filtered_times)

        stddev_open = _compute_stddev(open_times)
        stddev_closed = _compute_stddev(closed_times)
        stddev_filtered = _compute_stddev(filtered_times)

        # TTL hop count analysis
        ttl_hop_counts = self._analyze_ttl_hops(probe_results)

        # Infer device type and confidence
        inferred_device_type, confidence = self._infer_device_type(
            mean_open, mean_closed, mean_filtered,
            filtered_times, closed_times,
            ttl_hop_counts, threshold_ms
        )

        # Build ports_sampled dict
        ports_sampled = {
            "open": len(open_times),
            "closed": len(closed_times),
            "filtered": len(filtered_times),
        }

        return TimingFingerprint(
            inferred_device_type=inferred_device_type,
            confidence=confidence,
            mean_open_ms=mean_open,
            mean_closed_ms=mean_closed,
            mean_filtered_ms=mean_filtered,
            stddev_open_ms=stddev_open,
            stddev_closed_ms=stddev_closed,
            stddev_filtered_ms=stddev_filtered,
            ttl_hop_counts=ttl_hop_counts,
            ports_sampled=ports_sampled,
        )

    def _analyze_ttl_hops(self, probe_results: List[ProbeResult]) -> Optional[Dict[str, int]]:
        """
        Analyze TTL values from probe results to estimate hop counts per state.

        Groups TTL values by port state, computes average hop count per group.
        Returns None if no TTL data is available.

        Args:
            probe_results: List of ProbeResult with optional TTL data.

        Returns:
            Dict mapping state name to average hop count, or None if no TTL data.
        """
        open_ttls = [r.ttl for r in probe_results if r.state == PortState.OPEN and r.ttl is not None]
        closed_ttls = [r.ttl for r in probe_results if r.state == PortState.CLOSED and r.ttl is not None]
        filtered_ttls = [r.ttl for r in probe_results if r.state == PortState.FILTERED and r.ttl is not None]

        # If no TTL data available at all, skip TTL analysis (Requirement 2.6)
        if not open_ttls and not closed_ttls and not filtered_ttls:
            return None

        hop_counts: Dict[str, int] = {}

        if open_ttls:
            avg_ttl = sum(open_ttls) // len(open_ttls)
            hop_counts["open"] = _estimate_hop_count(avg_ttl)

        if closed_ttls:
            avg_ttl = sum(closed_ttls) // len(closed_ttls)
            hop_counts["closed"] = _estimate_hop_count(avg_ttl)

        if filtered_ttls:
            avg_ttl = sum(filtered_ttls) // len(filtered_ttls)
            hop_counts["filtered"] = _estimate_hop_count(avg_ttl)

        return hop_counts if hop_counts else None

    def _infer_device_type(self, mean_open: float, mean_closed: float,
                           mean_filtered: float, filtered_times: List[int],
                           closed_times: List[int],
                           ttl_hop_counts: Optional[Dict[str, int]],
                           threshold_ms: float) -> Tuple[str, float]:
        """
        Infer device type and confidence based on timing and TTL analysis.

        Logic:
            - If |mean_filtered - mean_closed| > threshold → "active filtering device"
            - If TTL hop difference between filtered and open/closed >= 2 → "intermediate device"
            - Otherwise → "no device detected"

        Confidence:
            - Both timing and TTL indicate device → 0.9
            - Only timing indicates device → 0.7
            - Only TTL indicates device → 0.6
            - No indicators → 0.1

        Returns:
            Tuple of (device_type_string, confidence_float).
        """
        timing_indicates_device = False
        ttl_indicates_device = False

        # Check timing-based active filtering inference
        if filtered_times and closed_times:
            timing_diff = abs(mean_filtered - mean_closed)
            if timing_diff > threshold_ms:
                timing_indicates_device = True

        # Check TTL-based intermediate device detection
        if ttl_hop_counts:
            # Compare filtered hops with open/closed hops
            filtered_hops = ttl_hop_counts.get("filtered")
            open_hops = ttl_hop_counts.get("open")
            closed_hops = ttl_hop_counts.get("closed")

            reference_hops = open_hops if open_hops is not None else closed_hops

            if filtered_hops is not None and reference_hops is not None:
                hop_diff = abs(filtered_hops - reference_hops)
                if hop_diff >= 2:
                    ttl_indicates_device = True

        # Determine device type and confidence
        if timing_indicates_device and ttl_indicates_device:
            return ("active filtering device (timing + TTL confirmed)", 0.9)
        elif timing_indicates_device:
            return ("active filtering device", 0.7)
        elif ttl_indicates_device:
            return ("intermediate filtering device", 0.6)
        else:
            return ("no device detected", 0.1)

    def _probe_ports(self, resolved_target: str) -> List[ProbeResult]:
        """Probe all ports using ThreadPoolExecutor for parallel scanning."""
        probe_results: List[ProbeResult] = []
        completed = 0
        findings = 0

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_workers
        ) as executor:
            # Submit probes, checking cancellation before each submission
            future_to_port: Dict[concurrent.futures.Future, int] = {}
            for port in self.ports:
                if not self.is_running:
                    break
                future = executor.submit(self.classify_port, port, resolved_target)
                future_to_port[future] = port

            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_port):
                if not self.is_running:
                    # Collect any already-completed results before breaking
                    try:
                        result = future.result(timeout=0.1)
                        probe_results.append(result)
                    except Exception:
                        pass
                    break

                try:
                    result = future.result()
                    probe_results.append(result)
                    completed += 1

                    # Emit per-port output
                    if result.state == PortState.OPEN:
                        findings += 1
                        self.signals.output.emit(
                            f"<p style='color: {COLOR_SUCCESS};'>[+] Port {result.port}/tcp "
                            f"OPEN ({result.response_time_ms}ms)</p>"
                        )
                    elif result.state == PortState.CLOSED:
                        self.signals.output.emit(
                            f"<p style='color: {COLOR_INFO};'>[-] Port {result.port}/tcp "
                            f"CLOSED ({result.response_time_ms}ms)</p>"
                        )
                    # Filtered ports logged in summary to avoid noise

                    # Progress update for each probe completed
                    self.signals.progress_update.emit(completed, findings)

                except Exception:
                    completed += 1

        return probe_results

    def _emit_partial_results(self, probe_results: List[ProbeResult],
                              resolved_target: str):
        """Emit partial results when scan is cancelled."""
        self.signals.output.emit(
            f"<p style='color: {COLOR_WARNING};'>[!] Scan cancelled - "
            f"emitting partial results ({len(probe_results)} ports probed)</p>"
        )

        if probe_results:
            fw_result = self.analyze_firewall_presence(probe_results)
            self._emit_results(fw_result, partial=True)
        else:
            self.signals.results_ready.emit({
                "target": self.target,
                "scan_type": "firewall_detection",
                "firewall_status": "cancelled",
                "partial": True,
                "detected_security_products": [],
                "filtered_ports": [],
                "successful_evasion_techniques": [],
                "confidence_scores": {},
                "error": None,
            })
            self.signals.finished.emit()

    def _emit_results(self, fw_result: FirewallResult, partial: bool = False):
        """Format and emit final scan results."""
        # Summary output
        self.signals.output.emit(
            f"<p style='color: {COLOR_INFO};'>{'─' * 40}</p>"
        )
        self.signals.output.emit(
            f"<p style='color: {COLOR_INFO};'>[*] Firewall Detection Summary</p>"
        )

        # Status line with appropriate color
        if fw_result.firewall_status == "detected":
            status_color = COLOR_WARNING
        elif fw_result.firewall_status == "likely":
            status_color = COLOR_WARNING
        elif fw_result.firewall_status == "host unreachable":
            status_color = COLOR_ERROR
        else:
            status_color = COLOR_SUCCESS

        self.signals.output.emit(
            f"<p style='color: {status_color};'>[{'!' if fw_result.firewall_status in ('detected', 'likely') else '*'}] "
            f"Firewall Status: {h(fw_result.firewall_status.upper())}</p>"
        )

        if fw_result.firewall_type:
            self.signals.output.emit(
                f"<p style='color: {COLOR_INFO};'>[*] Firewall Type: "
                f"{h(fw_result.firewall_type)}</p>"
            )

        self.signals.output.emit(
            f"<p style='color: {COLOR_INFO};'>[*] Confidence: "
            f"{fw_result.confidence_score}%</p>"
        )

        # Port breakdown
        self.signals.output.emit(
            f"<p style='color: {COLOR_SUCCESS};'>[+] Open ports: "
            f"{len(fw_result.open_ports)}</p>"
        )
        self.signals.output.emit(
            f"<p style='color: {COLOR_INFO};'>[-] Closed ports: "
            f"{len(fw_result.closed_ports)}</p>"
        )
        self.signals.output.emit(
            f"<p style='color: {COLOR_WARNING};'>[!] Filtered ports: "
            f"{len(fw_result.filtered_ports)}</p>"
        )

        if fw_result.filtered_ports:
            filtered_display = ", ".join(str(p) for p in sorted(fw_result.filtered_ports)[:20])
            if len(fw_result.filtered_ports) > 20:
                filtered_display += f" ... (+{len(fw_result.filtered_ports) - 20} more)"
            self.signals.output.emit(
                f"<p style='color: {COLOR_WARNING};'>    Filtered: {h(filtered_display)}</p>"
            )

        self.signals.output.emit(
            f"<p style='color: {COLOR_INFO};'>[*] Filtered ratio: "
            f"{fw_result.filtered_ratio:.1%}</p>"
        )

        if partial:
            self.signals.output.emit(
                f"<p style='color: {COLOR_WARNING};'>[!] Results are partial "
                f"(scan was cancelled)</p>"
            )

        # Build structured result dict
        detections = []
        if fw_result.firewall_status in ("detected", "likely"):
            detection_entry = {
                "type": "firewall",
                "name": fw_result.firewall_type or "unknown",
            }
            detections.append(detection_entry)

        # Recommended next steps when filtered ports exist
        recommended_next_steps = []
        if fw_result.filtered_ports:
            recommended_next_steps.append("Run evasion testing against filtered ports")
            recommended_next_steps.append(
                f"Prioritize filtered ports for exploitation: "
                f"{', '.join(str(p) for p in sorted(fw_result.filtered_ports)[:10])}"
            )

        result_dict = {
            "target": self.target,
            "scan_type": "firewall_detection",
            "firewall_status": fw_result.firewall_status,
            "firewall_type": fw_result.firewall_type,
            "confidence_score": fw_result.confidence_score,
            "filtered_ratio": fw_result.filtered_ratio,
            "open_ports": fw_result.open_ports,
            "closed_ports": fw_result.closed_ports,
            "filtered_ports": [str(p) for p in fw_result.filtered_ports],
            "detected_security_products": detections,
            "successful_evasion_techniques": [],
            "confidence_scores": {"firewall_detection": fw_result.confidence_score},
            "recommended_next_steps": recommended_next_steps,
            "partial": partial,
            "error": None,
        }

        # Include timing fingerprint in results if available
        if fw_result.timing_fingerprint:
            tf = fw_result.timing_fingerprint
            result_dict["timing_fingerprint"] = {
                "inferred_device_type": tf.inferred_device_type,
                "confidence": tf.confidence,
                "mean_open_ms": tf.mean_open_ms,
                "mean_closed_ms": tf.mean_closed_ms,
                "mean_filtered_ms": tf.mean_filtered_ms,
                "stddev_open_ms": tf.stddev_open_ms,
                "stddev_closed_ms": tf.stddev_closed_ms,
                "stddev_filtered_ms": tf.stddev_filtered_ms,
                "ttl_hop_counts": tf.ttl_hop_counts,
                "ports_sampled": tf.ports_sampled,
            }

        self.signals.results_ready.emit(result_dict)
        self.signals.status.emit(
            f"Firewall detection {'completed' if not partial else 'cancelled (partial results)'}"
        )
        self.signals.finished.emit()
