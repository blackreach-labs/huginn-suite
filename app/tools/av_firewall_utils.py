"""
AV/Firewall Detection Utilities
Shared data models, signal infrastructure, and utility functions for AV/Firewall detection workers.
"""

import logging
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Callable

from PyQt6.QtCore import QObject, pyqtSignal, QRunnable

logger = logging.getLogger(__name__)


# =============================================================================
# HTML Color Constants (Requirement 5.7)
# =============================================================================

COLOR_SUCCESS = "#00FF41"
COLOR_ERROR = "#FF6B6B"
COLOR_INFO = "#00BFFF"
COLOR_WARNING = "#FFAA00"


# =============================================================================
# Data Models (Requirement 8.1)
# =============================================================================

class PortState(Enum):
    """Classification of a port's response state."""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


@dataclass
class ProbeResult:
    """Result of a single TCP probe to a port."""
    port: int
    state: PortState
    response_time_ms: int
    ttl: Optional[int] = None
    error_code: Optional[int] = None


@dataclass
class TimingFingerprint:
    """Timing and TTL analysis fingerprint for firewall identification."""
    inferred_device_type: str
    confidence: float  # 0.0 to 1.0
    mean_open_ms: float
    mean_closed_ms: float
    mean_filtered_ms: float
    stddev_open_ms: float
    stddev_closed_ms: float
    stddev_filtered_ms: float
    ttl_hop_counts: Optional[Dict[str, int]] = None
    ports_sampled: Dict[str, int] = field(default_factory=dict)


@dataclass
class FirewallResult:
    """Result of firewall detection analysis."""
    target: str
    firewall_status: str  # "detected", "likely", "not detected", "host unreachable"
    firewall_type: Optional[str]  # "stateful", "packet-filter", None
    confidence_score: int  # 0-100
    filtered_ports: List[int]
    open_ports: List[int]
    closed_ports: List[int]
    filtered_ratio: float
    timing_fingerprint: Optional[TimingFingerprint] = None


@dataclass
class TechniqueResult:
    """Result of a single evasion technique test."""
    technique_name: str
    classification: str  # "successful", "failed", "skipped"
    ports_accessible: List[int]
    evidence: List[Dict[str, Any]]
    error: Optional[str] = None


@dataclass
class EvasionSummary:
    """Summary of all evasion technique results."""
    target: str
    baseline_filtered_ports: List[int]
    techniques: List[TechniqueResult]
    successful_count: int
    failed_count: int
    skipped_count: int


@dataclass
class PayloadConfig:
    """Configuration for payload generation."""
    payload_type: str  # "reverse_tcp", "bind_tcp", "cmd_exec"
    payload_format: str  # "raw", "exe", "dll", "powershell"
    architecture: str  # "x86", "x64"
    encoding: str  # "xor", "base64", "substitution"
    xor_key_length: int  # 1-32
    lhost: str
    lport: int
    staged: bool


@dataclass
class PayloadResult:
    """Result of payload generation."""
    payload_bytes: bytes
    stager_bytes: Optional[bytes]
    format_used: str
    architecture: str
    encoding_layers: int
    detection_score: int  # 0-100
    size_bytes: int


@dataclass
class IDSResult:
    """Result of IDS/IPS behavioral detection."""
    detected: bool
    detection_method: str  # "signature", "timing", "rate_limiting"
    confidence: str  # "low", "medium", "high"
    indicators: List[Dict[str, Any]]
    affected_ports: List[int]
    triggering_signatures: List[str]
    baseline_avg_ms: float
    attack_avg_ms: float
    rate_limit_threshold: Optional[int] = None


@dataclass
class ScanResult:
    """Unified scan result output structure."""
    target: str
    scan_type: str
    detected_security_products: List[Dict[str, str]]
    filtered_ports: List[str]
    successful_evasion_techniques: List[str]
    confidence_scores: Dict[str, int]
    recommended_next_steps: List[str]
    error: Optional[str] = None


# =============================================================================
# Worker Signals (Requirement 5.1)
# =============================================================================

class AVFWWorkerSignals(QObject):
    """
    Standard signal interface for all AV/Firewall detection workers.
    Matches the PortScannerSignals pattern for uniform UI integration.
    """
    output = pyqtSignal(str)            # HTML-formatted output
    status = pyqtSignal(str)            # Status bar text
    finished = pyqtSignal()             # Scan complete
    results_ready = pyqtSignal(dict)    # Structured results
    progress_start = pyqtSignal(int)    # Total probe count
    progress_update = pyqtSignal(int, int)  # (completed, findings)


# =============================================================================
# Port List Parser (Requirement 7.4)
# =============================================================================

def parse_port_list(spec: str) -> List[int]:
    """
    Parse a port specification string into a deduplicated list of port numbers.

    Supports:
      - Comma-separated ports: "80,443,8080"
      - Hyphenated ranges: "8000-8100"
      - Mixed: "80,443,8000-8100"

    Validates each port is in range 1-65535, deduplicates, and caps at 10000 ports.

    Args:
        spec: Port specification string.

    Returns:
        Sorted, deduplicated list of port integers.

    Raises:
        ValueError: If any port is outside 1-65535, a range is invalid,
                    or the total exceeds 10000 ports.
    """
    if not spec or not spec.strip():
        raise ValueError("Port specification cannot be empty")

    ports = set()
    parts = spec.split(",")

    for part in parts:
        part = part.strip()
        if not part:
            continue

        if "-" in part:
            # Handle hyphenated range
            range_parts = part.split("-", 1)
            if len(range_parts) != 2:
                raise ValueError(f"Invalid port range: '{part}'")

            try:
                start = int(range_parts[0].strip())
                end = int(range_parts[1].strip())
            except ValueError:
                raise ValueError(f"Invalid port range: '{part}' - ports must be integers")

            if start > end:
                raise ValueError(
                    f"Invalid port range: '{part}' - start ({start}) must be <= end ({end})"
                )

            if start < 1 or end > 65535:
                raise ValueError(
                    f"Port out of range in '{part}': ports must be between 1 and 65535"
                )

            for p in range(start, end + 1):
                ports.add(p)
        else:
            # Handle single port
            try:
                port = int(part)
            except ValueError:
                raise ValueError(f"Invalid port number: '{part}' - must be an integer")

            if port < 1 or port > 65535:
                raise ValueError(
                    f"Port {port} out of range: must be between 1 and 65535"
                )

            ports.add(port)

        # Early cap check to avoid excessive memory use with huge ranges
        if len(ports) > 10000:
            raise ValueError(
                f"Port list exceeds maximum of 10000 ports (got at least {len(ports)})"
            )

    if len(ports) == 0:
        raise ValueError("Port specification resulted in no valid ports")

    if len(ports) > 10000:
        raise ValueError(
            f"Port list exceeds maximum of 10000 ports (got {len(ports)})"
        )

    return sorted(ports)


# =============================================================================
# Input Validation (Requirement 7.6)
# =============================================================================

def validate_target(target: str) -> bool:
    """
    Validate that a target string is non-empty and not None.

    Args:
        target: Target IP address or hostname string.

    Returns:
        True if the target is valid (non-empty, non-None), False otherwise.
    """
    if target is None:
        return False
    if not isinstance(target, str):
        return False
    if not target.strip():
        return False
    return True


def validate_params(timeout: float, max_workers: int, ports: List[int]) -> Optional[str]:
    """
    Validate scan parameters are within acceptable ranges.

    Args:
        timeout: Probe timeout in seconds (valid range: 1-30).
        max_workers: Maximum concurrent threads (valid range: 1-200).
        ports: List of port numbers (each must be 1-65535).

    Returns:
        None if all parameters are valid, or an error message string
        identifying the specific invalid parameter.
    """
    # Validate timeout
    if not isinstance(timeout, (int, float)):
        return "Invalid timeout: must be a number"
    if timeout < 1 or timeout > 30:
        return f"Invalid timeout: {timeout} - must be between 1 and 30 seconds"

    # Validate max_workers
    if not isinstance(max_workers, int):
        return "Invalid max_workers: must be an integer"
    if max_workers < 1 or max_workers > 200:
        return f"Invalid max_workers: {max_workers} - must be between 1 and 200"

    # Validate ports
    if not isinstance(ports, list):
        return "Invalid ports: must be a list"
    if len(ports) == 0:
        return "Invalid ports: port list cannot be empty"

    for port in ports:
        if not isinstance(port, int):
            return f"Invalid port: {port} - must be an integer"
        if port < 1 or port > 65535:
            return f"Invalid port: {port} - must be between 1 and 65535"

    return None


# =============================================================================
# Backward-Compatible Legacy Functions
# (Preserved for existing imports; will be removed in task 7.1)
# =============================================================================

class AVFirewallEnumWorker(QRunnable):
    """Legacy worker for AV/Firewall detection tasks (backward compatibility)."""

    def __init__(self, target: str, scan_type: str = "waf", port: int = 80,
                 payload_type: str = "msfvenom", output_callback: Callable = None,
                 results_callback: Callable = None):
        super().__init__()
        self.signals = AVFWWorkerSignals()
        self.target = target
        self.scan_type = scan_type
        self.port = port
        self.payload_type = payload_type
        self.output_callback = output_callback
        self.results_callback = results_callback
        self.is_running = True

    def run(self):
        """Execute AV/Firewall detection (legacy dispatch).

        Routes to the new specialized workers for firewall/evasion/payload,
        and directly to av_firewall_scanner for WAF detection.
        """
        try:
            if self.output_callback:
                self.output_callback(
                    f"<p style='color: {COLOR_INFO};'>Starting {self.scan_type.upper()} "
                    f"detection on {self.target}</p>"
                )

            results = {}

            if self.scan_type == "waf":
                from .av_firewall_scanner import av_firewall_scanner
                results = av_firewall_scanner.detect_waf(self.target, self.port)
            elif self.scan_type == "firewall":
                from .firewall_detector import FirewallDetectorWorker
                worker = FirewallDetectorWorker(
                    target=self.target, ports=[self.port], timeout=3.0
                )
                worker.run()
                results = getattr(worker, 'scan_results', {}) or {}
            elif self.scan_type == "evasion":
                from .evasion_profiler import EvasionProfilerWorker
                worker = EvasionProfilerWorker(
                    target=self.target, ports=[self.port], timeout=3.0
                )
                worker.run()
                results = getattr(worker, 'scan_results', {}) or {}
            elif self.scan_type == "payload":
                from .payload_generator import PayloadGeneratorWorker
                worker = PayloadGeneratorWorker(
                    payload_type="reverse_tcp",
                    payload_format="raw",
                    lhost=self.target,
                    lport=4444
                )
                worker.run()
                results = getattr(worker, 'scan_results', {}) or {}

            if self.results_callback:
                self.results_callback(results)

            self.signals.finished.emit()

        except Exception as e:
            logger.error(f"AV/Firewall detection error: {e}")
            if self.output_callback:
                self.output_callback(
                    f"<p style='color: {COLOR_ERROR};'>Error: {str(e)}</p>"
                )
            self.signals.finished.emit()


def run_av_firewall_detection(target: str, scan_type: str = "waf", port: int = 80,
                             payload_type: str = "msfvenom", output_callback: Callable = None,
                             results_callback: Callable = None) -> AVFirewallEnumWorker:
    """Create and return AV/Firewall detection worker (legacy function)."""
    worker = AVFirewallEnumWorker(
        target=target,
        scan_type=scan_type,
        port=port,
        payload_type=payload_type,
        output_callback=output_callback,
        results_callback=results_callback
    )
    return worker


def get_nmap_evasion_techniques() -> Dict[str, str]:
    """Get nmap firewall evasion techniques (legacy function)."""
    return {
        "Fragmentation": "nmap -f <target>",
        "Decoy Scan": "nmap -D RND:10 <target>",
        "Source Port": "nmap --source-port 53 <target>",
        "Timing": "nmap -T1 <target>",
        "FIN Scan": "nmap -sF <target>",
        "NULL Scan": "nmap -sN <target>",
        "Xmas Scan": "nmap -sX <target>",
        "ACK Scan": "nmap -sA <target>",
        "Spoof MAC": "nmap --spoof-mac 0 <target>"
    }


def format_av_firewall_results(results: Dict[str, Any]) -> str:
    """Format AV/Firewall results for display (legacy function)."""
    if not results:
        return "No results available"

    output = []

    if 'waf_detected' in results:
        status = "Detected" if results['waf_detected'] else "Not Detected"
        output.append(f"WAF Status: {status}")
        if results.get('waf_type'):
            output.append(f"WAF Type: {results['waf_type']}")

    if 'firewall_detected' in results:
        status = "Detected" if results['firewall_detected'] else "Not Detected"
        output.append(f"Firewall Status: {status}")
        if results.get('filtered_ports'):
            ports = ', '.join(results['filtered_ports'])
            output.append(f"Filtered Ports: {ports}")

    if 'successful_techniques' in results:
        count = len(results['successful_techniques'])
        output.append(f"Successful Evasion Techniques: {count}")
        for technique in results['successful_techniques'][:5]:
            output.append(f"  • {technique}")

    return '\n'.join(output)
