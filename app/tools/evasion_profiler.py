"""
Native Firewall Evasion Profiling

Implements EvasionProfilerWorker - a QRunnable that tests various firewall
evasion techniques against filtered ports to identify which bypass methods
succeed.

Techniques tested:
- Source port variation (53, 80, 443, 88 + 4 random)
- Timing variation (0ms, 1000ms, 5000ms, 15000ms delays)
- TCP window size manipulation (SO_SNDBUF: 1024, 4096, 16384, 65535)
- Connection pattern variation (sequential vs randomized)
- TCP flag manipulation (FIN, NULL, Xmas via raw sockets)
"""

import errno
import random
import socket
import struct
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
    TechniqueResult,
    EvasionSummary,
    COLOR_SUCCESS,
    COLOR_ERROR,
    COLOR_INFO,
    COLOR_WARNING,
    validate_target,
    validate_params,
)


# Platform-specific ECONNREFUSED errno
_ECONNREFUSED = 10061 if sys.platform == "win32" else errno.ECONNREFUSED

# Privileged source ports commonly allowed through firewalls
_PRIVILEGED_SOURCE_PORTS = [53, 80, 443, 88]

# Timing delays to test (in milliseconds)
_TIMING_DELAYS_MS = [0, 1000, 5000, 15000]

# Window (SO_SNDBUF) sizes to test
_WINDOW_SIZES = [1024, 4096, 16384, 65535]

# Success threshold: at least 2 of 3 attempts must succeed
_SUCCESS_THRESHOLD = 2
_ATTEMPTS_PER_PROBE = 3


class EvasionProfilerWorker(QRunnable):
    """
    Native firewall evasion profiling worker.

    Establishes a baseline of filtered ports then tests various evasion
    techniques to identify which methods can bypass the filtering.

    Signals:
        output(str): HTML-formatted scan output
        status(str): Status bar text
        finished(): Scan complete
        results_ready(dict): Structured EvasionSummary as dict
        progress_start(int): Total technique count
        progress_update(int, int): (completed_techniques, successful_count)
    """

    def __init__(self, target: str, ports: List[int], timeout: float = 3.0,
                 max_workers: int = 50):
        super().__init__()
        self.signals = AVFWWorkerSignals()
        self.target = target
        self.ports = ports
        self.timeout = timeout
        # Use a shorter timeout for evasion probes since we're testing bypass, not discovery
        self.evasion_timeout = min(timeout, 1.0)
        self.max_workers = min(max_workers, 50)
        self.is_running = True
        # Limit filtered ports tested per technique to keep scans reasonable
        self._max_filtered_ports = 5

    def run(self):
        """Execute the evasion profiling scan."""
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

        # Resolve hostname
        try:
            self._resolved_target = socket.gethostbyname(self.target)
        except socket.gaierror as e:
            self.signals.output.emit(
                f"<p style='color: {COLOR_ERROR};'>[ERROR] DNS resolution failed for "
                f"{h(self.target)}: {h(str(e))}</p>"
            )
            self.signals.finished.emit()
            return

        self.signals.status.emit(f"Starting evasion profiling on {self.target}...")
        self.signals.output.emit(
            f"<p style='color: {COLOR_INFO};'>[*] Evasion Profiler - "
            f"Testing {len(self.ports)} ports on {h(self.target)} "
            f"({h(self._resolved_target)})</p>"
        )

        # 5 techniques total for progress tracking
        self.signals.progress_start.emit(5)

        # Step 1: Establish baseline
        baseline = self.establish_baseline()
        filtered_ports = [
            port for port, state in baseline.items()
            if state == PortState.FILTERED
        ]

        if not self.is_running:
            self._emit_cancelled()
            return

        if not filtered_ports:
            self.signals.output.emit(
                f"<p style='color: {COLOR_SUCCESS};'>[+] No filtered ports found in "
                f"baseline - no evasion testing needed</p>"
            )
            summary = EvasionSummary(
                target=self.target,
                baseline_filtered_ports=[],
                techniques=[],
                successful_count=0,
                failed_count=0,
                skipped_count=0,
            )
            self._emit_results(summary)
            return

        self.signals.output.emit(
            f"<p style='color: {COLOR_WARNING};'>[!] Baseline: "
            f"{len(filtered_ports)} filtered ports identified for evasion testing</p>"
        )

        # Limit filtered ports to test per technique (most common/interesting ports first)
        test_ports = filtered_ports[:self._max_filtered_ports]
        if len(filtered_ports) > self._max_filtered_ports:
            self.signals.output.emit(
                f"<p style='color: {COLOR_INFO};'>[*] Testing top "
                f"{self._max_filtered_ports} filtered ports for evasion</p>"
            )

        # Step 2: Run evasion techniques
        techniques: List[TechniqueResult] = []
        completed_techniques = 0

        # Technique 1: Source port evasion
        if self.is_running:
            self.signals.output.emit(
                f"<p style='color: {COLOR_INFO};'>[*] Testing source port evasion...</p>"
            )
            result = self.test_source_port_evasion(test_ports)
            techniques.append(result)
            completed_techniques += 1
            self.signals.progress_update.emit(
                completed_techniques,
                sum(1 for t in techniques if t.classification == "successful")
            )

        # Technique 2: Timing evasion
        if self.is_running:
            self.signals.output.emit(
                f"<p style='color: {COLOR_INFO};'>[*] Testing timing evasion...</p>"
            )
            result = self.test_timing_evasion(test_ports)
            techniques.append(result)
            completed_techniques += 1
            self.signals.progress_update.emit(
                completed_techniques,
                sum(1 for t in techniques if t.classification == "successful")
            )

        # Technique 3: Window size evasion
        if self.is_running:
            self.signals.output.emit(
                f"<p style='color: {COLOR_INFO};'>[*] Testing window size evasion...</p>"
            )
            result = self.test_window_size_evasion(test_ports)
            techniques.append(result)
            completed_techniques += 1
            self.signals.progress_update.emit(
                completed_techniques,
                sum(1 for t in techniques if t.classification == "successful")
            )

        # Technique 4: Pattern evasion
        if self.is_running:
            self.signals.output.emit(
                f"<p style='color: {COLOR_INFO};'>[*] Testing pattern evasion...</p>"
            )
            result = self.test_pattern_evasion(test_ports)
            techniques.append(result)
            completed_techniques += 1
            self.signals.progress_update.emit(
                completed_techniques,
                sum(1 for t in techniques if t.classification == "successful")
            )

        # Technique 5: Flag manipulation
        if self.is_running:
            self.signals.output.emit(
                f"<p style='color: {COLOR_INFO};'>[*] Testing flag manipulation...</p>"
            )
            result = self.test_flag_manipulation(test_ports)
            techniques.append(result)
            completed_techniques += 1
            self.signals.progress_update.emit(
                completed_techniques,
                sum(1 for t in techniques if t.classification == "successful")
            )

        # Build summary
        successful_count = sum(
            1 for t in techniques if t.classification == "successful"
        )
        failed_count = sum(
            1 for t in techniques if t.classification == "failed"
        )
        skipped_count = sum(
            1 for t in techniques if t.classification == "skipped"
        )

        summary = EvasionSummary(
            target=self.target,
            baseline_filtered_ports=filtered_ports,
            techniques=techniques,
            successful_count=successful_count,
            failed_count=failed_count,
            skipped_count=skipped_count,
        )

        self._emit_results(summary)

    def establish_baseline(self) -> Dict[int, PortState]:
        """
        Perform a baseline connect-scan to identify currently filtered ports.

        Returns:
            Dictionary mapping port numbers to their PortState classification.
        """
        self.signals.output.emit(
            f"<p style='color: {COLOR_INFO};'>[*] Establishing baseline - "
            f"probing {len(self.ports)} ports...</p>"
        )

        baseline: Dict[int, PortState] = {}

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_workers
        ) as executor:
            future_to_port: Dict[concurrent.futures.Future, int] = {}
            for port in self.ports:
                if not self.is_running:
                    break
                future = executor.submit(self._classify_port, port)
                future_to_port[future] = port

            for future in concurrent.futures.as_completed(future_to_port):
                if not self.is_running:
                    break
                try:
                    result = future.result()
                    baseline[result.port] = result.state
                except Exception:
                    port = future_to_port[future]
                    baseline[port] = PortState.FILTERED

        open_count = sum(1 for s in baseline.values() if s == PortState.OPEN)
        closed_count = sum(1 for s in baseline.values() if s == PortState.CLOSED)
        filtered_count = sum(1 for s in baseline.values() if s == PortState.FILTERED)

        self.signals.output.emit(
            f"<p style='color: {COLOR_INFO};'>[*] Baseline results: "
            f"{open_count} open, {closed_count} closed, "
            f"{filtered_count} filtered</p>"
        )

        return baseline

    def test_source_port_evasion(self, filtered_ports: List[int]) -> TechniqueResult:
        """
        Test source port evasion by binding to commonly-allowed source ports.

        Binds to ports 53, 80, 443, 88 plus 4 random ports in 1024-65535.
        For each source port, attempts 3 connections per filtered target port.
        Handles EACCES gracefully for privileged ports.

        Args:
            filtered_ports: List of ports classified as filtered in baseline.

        Returns:
            TechniqueResult with classification and evidence.
        """
        # Generate 4 random source ports in unprivileged range
        random_source_ports = random.sample(range(1024, 65536), 4)
        all_source_ports = _PRIVILEGED_SOURCE_PORTS + random_source_ports

        ports_accessible: List[int] = []
        evidence: List[Dict] = []
        skipped_sources: List[int] = []

        for target_port in filtered_ports:
            if not self.is_running:
                break

            port_successes = {}  # source_port -> success count

            for source_port in all_source_ports:
                if not self.is_running:
                    break

                successes = 0
                for attempt in range(_ATTEMPTS_PER_PROBE):
                    if not self.is_running:
                        break

                    result = self._probe_with_source_port(
                        target_port, source_port
                    )
                    if result is None:
                        # Permission denied for this source port
                        if source_port not in skipped_sources:
                            skipped_sources.append(source_port)
                            self.signals.output.emit(
                                f"<p style='color: {COLOR_WARNING};'>    [!] Cannot bind to "
                                f"source port {source_port} (permission denied) - skipping</p>"
                            )
                        break
                    elif result:
                        successes += 1

                port_successes[source_port] = successes

            # Check if any source port achieved the success threshold
            for source_port, successes in port_successes.items():
                if successes >= _SUCCESS_THRESHOLD:
                    if target_port not in ports_accessible:
                        ports_accessible.append(target_port)
                    evidence.append({
                        "technique": "source_port",
                        "target_port": target_port,
                        "source_port": source_port,
                        "successes": successes,
                        "attempts": _ATTEMPTS_PER_PROBE,
                    })

        # Classify result
        if not self.is_running:
            classification = "skipped"
        elif ports_accessible:
            classification = "successful"
            self.signals.output.emit(
                f"<p style='color: {COLOR_SUCCESS};'>    [+] Source port evasion: "
                f"{len(ports_accessible)} ports became accessible</p>"
            )
        else:
            classification = "failed"
            self.signals.output.emit(
                f"<p style='color: {COLOR_INFO};'>    [-] Source port evasion: "
                f"no ports became accessible</p>"
            )

        error_msg = None
        if skipped_sources:
            error_msg = (
                f"Could not bind to privileged ports: "
                f"{', '.join(str(p) for p in skipped_sources)}"
            )

        return TechniqueResult(
            technique_name="source_port",
            classification=classification,
            ports_accessible=ports_accessible,
            evidence=evidence,
            error=error_msg,
        )

    def test_timing_evasion(self, filtered_ports: List[int]) -> TechniqueResult:
        """
        Test timing evasion by varying inter-probe delays.

        Delays: 0ms, 1000ms, 5000ms, 15000ms.
        Re-probes all filtered ports at each delay interval.

        Args:
            filtered_ports: List of ports classified as filtered in baseline.

        Returns:
            TechniqueResult with classification and evidence.
        """
        ports_accessible: List[int] = []
        evidence: List[Dict] = []

        for delay_ms in _TIMING_DELAYS_MS:
            if not self.is_running:
                break

            delay_sec = delay_ms / 1000.0

            self.signals.output.emit(
                f"<p style='color: {COLOR_INFO};'>    [*] Testing delay: "
                f"{delay_ms}ms...</p>"
            )

            for target_port in filtered_ports:
                if not self.is_running:
                    break

                # Apply inter-probe delay
                if delay_sec > 0:
                    time.sleep(delay_sec)

                successes = 0
                for attempt in range(_ATTEMPTS_PER_PROBE):
                    if not self.is_running:
                        break
                    result = self._classify_port(target_port)
                    if result.state == PortState.OPEN:
                        successes += 1

                if successes >= _SUCCESS_THRESHOLD:
                    if target_port not in ports_accessible:
                        ports_accessible.append(target_port)
                    evidence.append({
                        "technique": "timing",
                        "target_port": target_port,
                        "delay_ms": delay_ms,
                        "successes": successes,
                        "attempts": _ATTEMPTS_PER_PROBE,
                    })

        # Classify result
        if not self.is_running:
            classification = "skipped"
        elif ports_accessible:
            classification = "successful"
            self.signals.output.emit(
                f"<p style='color: {COLOR_SUCCESS};'>    [+] Timing evasion: "
                f"{len(ports_accessible)} ports became accessible</p>"
            )
        else:
            classification = "failed"
            self.signals.output.emit(
                f"<p style='color: {COLOR_INFO};'>    [-] Timing evasion: "
                f"no ports became accessible</p>"
            )

        return TechniqueResult(
            technique_name="timing",
            classification=classification,
            ports_accessible=ports_accessible,
            evidence=evidence,
        )

    def test_window_size_evasion(self, filtered_ports: List[int]) -> TechniqueResult:
        """
        Test window size evasion by setting SO_SNDBUF before connecting.

        Window sizes: 1024, 4096, 16384, 65535 bytes.

        Args:
            filtered_ports: List of ports classified as filtered in baseline.

        Returns:
            TechniqueResult with classification and evidence.
        """
        ports_accessible: List[int] = []
        evidence: List[Dict] = []

        for window_size in _WINDOW_SIZES:
            if not self.is_running:
                break

            self.signals.output.emit(
                f"<p style='color: {COLOR_INFO};'>    [*] Testing SO_SNDBUF: "
                f"{window_size} bytes...</p>"
            )

            for target_port in filtered_ports:
                if not self.is_running:
                    break

                successes = 0
                for attempt in range(_ATTEMPTS_PER_PROBE):
                    if not self.is_running:
                        break
                    result = self._probe_with_window_size(
                        target_port, window_size
                    )
                    if result:
                        successes += 1

                if successes >= _SUCCESS_THRESHOLD:
                    if target_port not in ports_accessible:
                        ports_accessible.append(target_port)
                    evidence.append({
                        "technique": "window_size",
                        "target_port": target_port,
                        "window_size": window_size,
                        "successes": successes,
                        "attempts": _ATTEMPTS_PER_PROBE,
                    })

        # Classify result
        if not self.is_running:
            classification = "skipped"
        elif ports_accessible:
            classification = "successful"
            self.signals.output.emit(
                f"<p style='color: {COLOR_SUCCESS};'>    [+] Window size evasion: "
                f"{len(ports_accessible)} ports became accessible</p>"
            )
        else:
            classification = "failed"
            self.signals.output.emit(
                f"<p style='color: {COLOR_INFO};'>    [-] Window size evasion: "
                f"no ports became accessible</p>"
            )

        return TechniqueResult(
            technique_name="window_size",
            classification=classification,
            ports_accessible=ports_accessible,
            evidence=evidence,
        )

    def test_pattern_evasion(self, filtered_ports: List[int]) -> TechniqueResult:
        """
        Test pattern evasion by comparing sequential vs randomized port ordering.

        Checks if probing ports in random order yields different results
        than sequential order (detects pattern-based filtering).

        Args:
            filtered_ports: List of ports classified as filtered in baseline.

        Returns:
            TechniqueResult with classification and evidence.
        """
        ports_accessible: List[int] = []
        evidence: List[Dict] = []

        # Test 1: Sequential ordering (baseline was already sequential,
        # so this tests consistency)
        sequential_results: Dict[int, int] = {}  # port -> successes

        self.signals.output.emit(
            f"<p style='color: {COLOR_INFO};'>    [*] Testing sequential ordering...</p>"
        )

        for target_port in filtered_ports:
            if not self.is_running:
                break
            successes = 0
            for attempt in range(_ATTEMPTS_PER_PROBE):
                if not self.is_running:
                    break
                result = self._classify_port(target_port)
                if result.state == PortState.OPEN:
                    successes += 1
            sequential_results[target_port] = successes

        # Test 2: Randomized ordering
        randomized_results: Dict[int, int] = {}  # port -> successes
        shuffled_ports = list(filtered_ports)
        random.shuffle(shuffled_ports)

        self.signals.output.emit(
            f"<p style='color: {COLOR_INFO};'>    [*] Testing randomized ordering...</p>"
        )

        for target_port in shuffled_ports:
            if not self.is_running:
                break
            successes = 0
            for attempt in range(_ATTEMPTS_PER_PROBE):
                if not self.is_running:
                    break
                result = self._classify_port(target_port)
                if result.state == PortState.OPEN:
                    successes += 1
            randomized_results[target_port] = successes

        # Analyze: check if randomized order opened any ports
        for target_port in filtered_ports:
            if not self.is_running:
                break

            seq_successes = sequential_results.get(target_port, 0)
            rand_successes = randomized_results.get(target_port, 0)

            # Port is accessible if either ordering achieved the threshold
            if rand_successes >= _SUCCESS_THRESHOLD:
                if target_port not in ports_accessible:
                    ports_accessible.append(target_port)
                evidence.append({
                    "technique": "pattern",
                    "target_port": target_port,
                    "ordering": "randomized",
                    "successes": rand_successes,
                    "attempts": _ATTEMPTS_PER_PROBE,
                    "sequential_successes": seq_successes,
                })
            elif seq_successes >= _SUCCESS_THRESHOLD:
                if target_port not in ports_accessible:
                    ports_accessible.append(target_port)
                evidence.append({
                    "technique": "pattern",
                    "target_port": target_port,
                    "ordering": "sequential",
                    "successes": seq_successes,
                    "attempts": _ATTEMPTS_PER_PROBE,
                    "randomized_successes": rand_successes,
                })

        # Classify result
        if not self.is_running:
            classification = "skipped"
        elif ports_accessible:
            classification = "successful"
            self.signals.output.emit(
                f"<p style='color: {COLOR_SUCCESS};'>    [+] Pattern evasion: "
                f"{len(ports_accessible)} ports became accessible</p>"
            )
        else:
            classification = "failed"
            self.signals.output.emit(
                f"<p style='color: {COLOR_INFO};'>    [-] Pattern evasion: "
                f"no ports became accessible</p>"
            )

        return TechniqueResult(
            technique_name="pattern",
            classification=classification,
            ports_accessible=ports_accessible,
            evidence=evidence,
        )

    def test_flag_manipulation(self, filtered_ports: List[int]) -> TechniqueResult:
        """
        Test TCP flag manipulation using raw sockets (FIN, NULL, Xmas probes).

        Falls back to connect-scan if raw socket creation is denied.

        Args:
            filtered_ports: List of ports classified as filtered in baseline.

        Returns:
            TechniqueResult with classification and evidence.
        """
        ports_accessible: List[int] = []
        evidence: List[Dict] = []
        raw_socket_available = True
        error_msg = None

        # Attempt to create a raw socket to check permissions
        try:
            test_sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP
            )
            test_sock.close()
        except (PermissionError, OSError):
            raw_socket_available = False
            error_msg = (
                "Raw socket access denied - advanced flag manipulation requires "
                "elevated privileges. Falling back to connect-scan."
            )
            self.signals.output.emit(
                f"<p style='color: {COLOR_WARNING};'>    [!] {h(error_msg)}</p>"
            )

        if raw_socket_available:
            # Define flag probes: (name, flags_byte)
            # TCP flags: FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20
            flag_probes = [
                ("FIN", 0x01),           # FIN scan
                ("NULL", 0x00),          # NULL scan (no flags)
                ("Xmas", 0x29),          # FIN + PSH + URG
            ]

            for probe_name, flags in flag_probes:
                if not self.is_running:
                    break

                self.signals.output.emit(
                    f"<p style='color: {COLOR_INFO};'>    [*] Testing {probe_name} "
                    f"probe...</p>"
                )

                for target_port in filtered_ports:
                    if not self.is_running:
                        break

                    successes = 0
                    for attempt in range(_ATTEMPTS_PER_PROBE):
                        if not self.is_running:
                            break
                        result = self._raw_probe(target_port, flags)
                        if result:
                            successes += 1

                    if successes >= _SUCCESS_THRESHOLD:
                        if target_port not in ports_accessible:
                            ports_accessible.append(target_port)
                        evidence.append({
                            "technique": "flag_manipulation",
                            "target_port": target_port,
                            "probe_type": probe_name,
                            "flags": flags,
                            "successes": successes,
                            "attempts": _ATTEMPTS_PER_PROBE,
                        })
        else:
            # Fallback: use connect-scan with different socket options
            # as a best-effort flag manipulation substitute
            self.signals.output.emit(
                f"<p style='color: {COLOR_INFO};'>    [*] Using connect-scan "
                f"fallback for flag manipulation testing...</p>"
            )

            for target_port in filtered_ports:
                if not self.is_running:
                    break

                successes = 0
                for attempt in range(_ATTEMPTS_PER_PROBE):
                    if not self.is_running:
                        break
                    result = self._classify_port(target_port)
                    if result.state == PortState.OPEN:
                        successes += 1

                if successes >= _SUCCESS_THRESHOLD:
                    if target_port not in ports_accessible:
                        ports_accessible.append(target_port)
                    evidence.append({
                        "technique": "flag_manipulation",
                        "target_port": target_port,
                        "probe_type": "connect_scan_fallback",
                        "successes": successes,
                        "attempts": _ATTEMPTS_PER_PROBE,
                    })

        # Classify result
        if not self.is_running:
            classification = "skipped"
        elif ports_accessible:
            classification = "successful"
            self.signals.output.emit(
                f"<p style='color: {COLOR_SUCCESS};'>    [+] Flag manipulation: "
                f"{len(ports_accessible)} ports became accessible</p>"
            )
        else:
            classification = "failed"
            self.signals.output.emit(
                f"<p style='color: {COLOR_INFO};'>    [-] Flag manipulation: "
                f"no ports became accessible</p>"
            )

        return TechniqueResult(
            technique_name="flag_manipulation",
            classification=classification,
            ports_accessible=ports_accessible,
            evidence=evidence,
            error=error_msg,
        )

    # =========================================================================
    # Private helper methods
    # =========================================================================

    def _classify_port(self, port: int) -> ProbeResult:
        """
        Classify a single port using socket.connect_ex().

        Returns:
            ProbeResult with state and timing information.
        """
        start_time = time.perf_counter()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result_code = sock.connect_ex((self._resolved_target, port))
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            sock.close()

            if result_code == 0:
                return ProbeResult(
                    port=port,
                    state=PortState.OPEN,
                    response_time_ms=elapsed_ms,
                    error_code=result_code,
                )
            elif result_code == _ECONNREFUSED:
                return ProbeResult(
                    port=port,
                    state=PortState.CLOSED,
                    response_time_ms=elapsed_ms,
                    error_code=result_code,
                )
            else:
                return ProbeResult(
                    port=port,
                    state=PortState.FILTERED,
                    response_time_ms=elapsed_ms,
                    error_code=result_code,
                )

        except socket.timeout:
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            return ProbeResult(
                port=port,
                state=PortState.FILTERED,
                response_time_ms=elapsed_ms,
                error_code=None,
            )
        except OSError as e:
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            return ProbeResult(
                port=port,
                state=PortState.FILTERED,
                response_time_ms=elapsed_ms,
                error_code=e.errno,
            )

    def _probe_with_source_port(
        self, target_port: int, source_port: int
    ) -> Optional[bool]:
        """
        Attempt a connection from a specific source port.

        Args:
            target_port: The target port to connect to.
            source_port: The local port to bind to.

        Returns:
            True if connection succeeded (port open).
            False if connection failed (port still filtered/closed).
            None if binding to the source port was denied (EACCES).
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.evasion_timeout)

            # Attempt to bind to source port
            try:
                sock.bind(("", source_port))
            except PermissionError:
                sock.close()
                return None
            except OSError as e:
                # EACCES on Windows is errno 10013, on Linux it's EACCES (13)
                if e.errno in (errno.EACCES, 10013):
                    sock.close()
                    return None
                # EADDRINUSE - port already in use, skip it
                if e.errno in (errno.EADDRINUSE, 10048):
                    sock.close()
                    return False
                sock.close()
                return False

            # Attempt connection
            result_code = sock.connect_ex((self._resolved_target, target_port))
            sock.close()

            return result_code == 0

        except socket.timeout:
            try:
                sock.close()
            except Exception:
                pass
            return False
        except OSError:
            try:
                sock.close()
            except Exception:
                pass
            return False

    def _probe_with_window_size(self, target_port: int, window_size: int) -> bool:
        """
        Attempt a connection with a specific SO_SNDBUF size.

        Args:
            target_port: The target port to connect to.
            window_size: The SO_SNDBUF size to set.

        Returns:
            True if connection succeeded (port open), False otherwise.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.evasion_timeout)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, window_size)
            result_code = sock.connect_ex((self._resolved_target, target_port))
            sock.close()
            return result_code == 0
        except (socket.timeout, OSError):
            try:
                sock.close()
            except Exception:
                pass
            return False

    def _raw_probe(self, target_port: int, flags: int) -> bool:
        """
        Send a raw TCP probe with specified flags.

        Constructs a TCP packet with the given flags and sends it via raw socket.
        A response (RST or SYN-ACK) indicates the port is not filtered.

        Args:
            target_port: The target port to probe.
            flags: TCP flags byte to set in the packet.

        Returns:
            True if a response was received (port responding), False otherwise.
        """
        try:
            # Create raw socket
            sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP
            )
            sock.settimeout(self.evasion_timeout)

            # Build TCP header
            source_port = random.randint(32768, 60999)
            seq_num = random.randint(0, 0xFFFFFFFF)
            ack_num = 0
            data_offset = 5  # 5 x 32-bit words = 20 bytes (no options)
            offset_and_reserved = (data_offset << 4) | 0
            window = socket.htons(1024)
            checksum = 0
            urgent_ptr = 0

            # Pack TCP header
            tcp_header = struct.pack(
                "!HHIIBBHHH",
                source_port,
                target_port,
                seq_num,
                ack_num,
                offset_and_reserved,
                flags,
                window,
                checksum,
                urgent_ptr,
            )

            # Calculate checksum with pseudo-header
            source_ip = socket.gethostbyname(socket.gethostname())
            source_ip_packed = socket.inet_aton(source_ip)
            dest_ip_packed = socket.inet_aton(self._resolved_target)

            # Pseudo header for checksum
            placeholder = 0
            protocol = socket.IPPROTO_TCP
            tcp_length = len(tcp_header)
            pseudo_header = struct.pack(
                "!4s4sBBH",
                source_ip_packed,
                dest_ip_packed,
                placeholder,
                protocol,
                tcp_length,
            )

            # Compute checksum
            checksum = self._compute_checksum(pseudo_header + tcp_header)
            tcp_header = struct.pack(
                "!HHIIBBHHH",
                source_port,
                target_port,
                seq_num,
                ack_num,
                offset_and_reserved,
                flags,
                window,
                checksum,
                urgent_ptr,
            )

            # Send packet
            sock.sendto(tcp_header, (self._resolved_target, 0))

            # Wait for response
            try:
                data, addr = sock.recvfrom(1024)
                sock.close()
                # Any response means the port is not completely filtered
                return True
            except socket.timeout:
                sock.close()
                return False

        except (PermissionError, OSError):
            try:
                sock.close()
            except Exception:
                pass
            return False

    @staticmethod
    def _compute_checksum(data: bytes) -> int:
        """
        Compute the Internet checksum (RFC 1071) for the given data.

        Args:
            data: Bytes to compute checksum over.

        Returns:
            16-bit checksum value.
        """
        if len(data) % 2 != 0:
            data += b"\x00"

        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word

        # Add carry bits
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)

        return ~checksum & 0xFFFF

    def _emit_cancelled(self):
        """Emit cancellation output and signal."""
        self.signals.output.emit(
            f"<p style='color: {COLOR_WARNING};'>[!] Evasion profiling cancelled</p>"
        )
        self.signals.results_ready.emit({
            "target": self.target,
            "scan_type": "evasion_profiling",
            "partial": True,
            "detected_security_products": [],
            "filtered_ports": [],
            "successful_evasion_techniques": [],
            "confidence_scores": {},
            "error": "Scan cancelled",
        })
        self.signals.status.emit("Evasion profiling cancelled")
        self.signals.finished.emit()

    def _emit_results(self, summary: EvasionSummary):
        """Format and emit final evasion profiling results."""
        # Output summary
        self.signals.output.emit(
            f"<p style='color: {COLOR_INFO};'>{'─' * 40}</p>"
        )
        self.signals.output.emit(
            f"<p style='color: {COLOR_INFO};'>[*] Evasion Profiling Summary</p>"
        )
        self.signals.output.emit(
            f"<p style='color: {COLOR_INFO};'>[*] Baseline filtered ports: "
            f"{len(summary.baseline_filtered_ports)}</p>"
        )

        # Per-technique summary
        for technique in summary.techniques:
            if technique.classification == "successful":
                color = COLOR_SUCCESS
                icon = "+"
            elif technique.classification == "skipped":
                color = COLOR_WARNING
                icon = "!"
            else:
                color = COLOR_INFO
                icon = "-"

            self.signals.output.emit(
                f"<p style='color: {color};'>[{icon}] {h(technique.technique_name)}: "
                f"{h(technique.classification)} "
                f"({len(technique.ports_accessible)} ports accessible)</p>"
            )

            if technique.ports_accessible:
                ports_display = ", ".join(
                    str(p) for p in sorted(technique.ports_accessible)[:10]
                )
                if len(technique.ports_accessible) > 10:
                    ports_display += (
                        f" ... (+{len(technique.ports_accessible) - 10} more)"
                    )
                self.signals.output.emit(
                    f"<p style='color: {color};'>    Ports: {h(ports_display)}</p>"
                )

            if technique.error:
                self.signals.output.emit(
                    f"<p style='color: {COLOR_WARNING};'>    Note: "
                    f"{h(technique.error)}</p>"
                )

        # Overall counts
        self.signals.output.emit(
            f"<p style='color: {COLOR_INFO};'>[*] Results: "
            f"{summary.successful_count} successful, "
            f"{summary.failed_count} failed, "
            f"{summary.skipped_count} skipped</p>"
        )

        # Build structured result dict
        successful_techniques = [
            t.technique_name for t in summary.techniques
            if t.classification == "successful"
        ]

        all_accessible_ports = set()
        for t in summary.techniques:
            all_accessible_ports.update(t.ports_accessible)

        detections = []
        if summary.successful_count > 0:
            detections.append({
                "type": "firewall_evasion",
                "name": f"{summary.successful_count} techniques bypassed filtering",
            })

        recommended_next_steps = []
        if successful_techniques:
            recommended_next_steps.append(
                f"Exploit accessible ports using: "
                f"{', '.join(successful_techniques)}"
            )
        if summary.baseline_filtered_ports:
            recommended_next_steps.append(
                "Consider testing from a different network position"
            )

        confidence_scores = {}
        for t in summary.techniques:
            if t.classification == "successful":
                confidence_scores[t.technique_name] = min(
                    100,
                    int(len(t.ports_accessible) / max(1, len(summary.baseline_filtered_ports)) * 100)
                )
            elif t.classification == "failed":
                confidence_scores[t.technique_name] = 0
            # skipped techniques not included in confidence

        result_dict = {
            "target": self.target,
            "scan_type": "evasion_profiling",
            "baseline_filtered_ports": [
                str(p) for p in summary.baseline_filtered_ports
            ],
            "detected_security_products": detections,
            "filtered_ports": [str(p) for p in summary.baseline_filtered_ports],
            "successful_evasion_techniques": successful_techniques,
            "confidence_scores": confidence_scores,
            "recommended_next_steps": recommended_next_steps,
            "techniques": [
                {
                    "name": t.technique_name,
                    "classification": t.classification,
                    "ports_accessible": t.ports_accessible,
                    "evidence": t.evidence,
                    "error": t.error,
                }
                for t in summary.techniques
            ],
            "summary": {
                "successful_count": summary.successful_count,
                "failed_count": summary.failed_count,
                "skipped_count": summary.skipped_count,
            },
            "error": None,
        }

        self.signals.results_ready.emit(result_dict)
        self.signals.status.emit("Evasion profiling completed")
        self.signals.finished.emit()
