"""
Unit tests for TTL and timing analysis in FirewallDetectorWorker.

Tests analyze_timing(), _estimate_hop_count(), _try_extract_ttl(),
_compute_mean(), _compute_stddev(), and device inference logic.

Covers Requirements 2.1-2.7.
"""

import sys
import os
import math
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.tools.firewall_detector import (
    FirewallDetectorWorker,
    _estimate_hop_count,
    _try_extract_ttl,
    _compute_mean,
    _compute_stddev,
)
from app.tools.av_firewall_utils import PortState, ProbeResult, TimingFingerprint


# =============================================================================
# _estimate_hop_count tests
# =============================================================================

class TestEstimateHopCount:
    """Tests for hop count estimation from TTL values."""

    def test_ttl_64_zero_hops(self):
        """TTL of 64 means 0 hops (Linux default)."""
        assert _estimate_hop_count(64) == 0

    def test_ttl_128_zero_hops(self):
        """TTL of 128 means 0 hops (Windows default)."""
        assert _estimate_hop_count(128) == 0

    def test_ttl_255_zero_hops(self):
        """TTL of 255 means 0 hops (network device default)."""
        assert _estimate_hop_count(255) == 0

    def test_ttl_60_four_hops(self):
        """TTL of 60 means 4 hops from default 64."""
        assert _estimate_hop_count(60) == 4

    def test_ttl_120_eight_hops(self):
        """TTL of 120 means 8 hops from default 128."""
        assert _estimate_hop_count(120) == 8

    def test_ttl_250_five_hops(self):
        """TTL of 250 means 5 hops from default 255."""
        assert _estimate_hop_count(250) == 5

    def test_ttl_1_sixty_three_hops(self):
        """TTL of 1 means 63 hops from default 64."""
        assert _estimate_hop_count(1) == 63

    def test_ttl_65_sixty_three_hops(self):
        """TTL of 65 means 63 hops from default 128 (nearest above)."""
        assert _estimate_hop_count(65) == 63

    def test_ttl_zero_returns_zero(self):
        """TTL of 0 should return 0 hops (edge case)."""
        assert _estimate_hop_count(0) == 0

    def test_ttl_negative_returns_zero(self):
        """Negative TTL should return 0 hops."""
        assert _estimate_hop_count(-1) == 0


# =============================================================================
# _try_extract_ttl tests
# =============================================================================

class TestTryExtractTtl:
    """Tests for TTL extraction from sockets."""

    def test_successful_extraction(self):
        """Should return TTL when getsockopt returns valid value."""
        mock_sock = MagicMock()
        mock_sock.getsockopt.return_value = 64

        result = _try_extract_ttl(mock_sock)
        assert result == 64

    def test_returns_none_on_oserror(self):
        """Should return None when getsockopt raises OSError."""
        mock_sock = MagicMock()
        mock_sock.getsockopt.side_effect = OSError("not supported")

        result = _try_extract_ttl(mock_sock)
        assert result is None

    def test_returns_none_on_zero_ttl(self):
        """Should return None when getsockopt returns 0."""
        mock_sock = MagicMock()
        mock_sock.getsockopt.return_value = 0

        result = _try_extract_ttl(mock_sock)
        assert result is None

    def test_returns_none_on_invalid_ttl(self):
        """Should return None when TTL > 255."""
        mock_sock = MagicMock()
        mock_sock.getsockopt.return_value = 300

        result = _try_extract_ttl(mock_sock)
        assert result is None

    def test_returns_none_on_mock_value(self):
        """Should return None when getsockopt returns a MagicMock (graceful)."""
        mock_sock = MagicMock()
        # Default MagicMock() return from getsockopt is another MagicMock
        result = _try_extract_ttl(mock_sock)
        assert result is None

    def test_boundary_ttl_1(self):
        """TTL of 1 is valid."""
        mock_sock = MagicMock()
        mock_sock.getsockopt.return_value = 1

        result = _try_extract_ttl(mock_sock)
        assert result == 1

    def test_boundary_ttl_255(self):
        """TTL of 255 is valid."""
        mock_sock = MagicMock()
        mock_sock.getsockopt.return_value = 255

        result = _try_extract_ttl(mock_sock)
        assert result == 255


# =============================================================================
# _compute_mean and _compute_stddev tests
# =============================================================================

class TestComputeMean:
    """Tests for mean computation."""

    def test_empty_list(self):
        assert _compute_mean([]) == 0.0

    def test_single_value(self):
        assert _compute_mean([100]) == 100.0

    def test_multiple_values(self):
        assert _compute_mean([10, 20, 30]) == 20.0

    def test_all_same_values(self):
        assert _compute_mean([50, 50, 50, 50]) == 50.0


class TestComputeStddev:
    """Tests for standard deviation computation."""

    def test_empty_list(self):
        assert _compute_stddev([]) == 0.0

    def test_single_value(self):
        assert _compute_stddev([100]) == 0.0

    def test_all_same_values(self):
        assert _compute_stddev([50, 50, 50]) == 0.0

    def test_known_values(self):
        # Population stddev of [2, 4, 4, 4, 5, 5, 7, 9] = 2.0
        result = _compute_stddev([2, 4, 4, 4, 5, 5, 7, 9])
        assert abs(result - 2.0) < 0.001

    def test_two_values(self):
        # Population stddev of [0, 10] = 5.0
        result = _compute_stddev([0, 10])
        assert abs(result - 5.0) < 0.001


# =============================================================================
# analyze_timing tests
# =============================================================================

class TestAnalyzeTiming:
    """Tests for FirewallDetectorWorker.analyze_timing()."""

    def setup_method(self):
        self.worker = FirewallDetectorWorker(
            target="192.168.1.1", ports=[80], timeout=3.0
        )

    def _make_results(self, open_times=None, closed_times=None,
                      filtered_times=None, open_ttls=None):
        """Helper to create probe results with specified timing data."""
        results = []
        port = 1

        for t in (open_times or []):
            ttl = None
            if open_ttls and (port - 1) < len(open_ttls):
                ttl = open_ttls[port - 1]
            results.append(ProbeResult(
                port=port, state=PortState.OPEN, response_time_ms=t, ttl=ttl
            ))
            port += 1

        for t in (closed_times or []):
            results.append(ProbeResult(
                port=port, state=PortState.CLOSED, response_time_ms=t
            ))
            port += 1

        for t in (filtered_times or []):
            results.append(ProbeResult(
                port=port, state=PortState.FILTERED, response_time_ms=t
            ))
            port += 1

        return results

    def test_returns_none_fewer_than_5_probes(self):
        """Should return None when fewer than 5 ports probed."""
        results = self._make_results(open_times=[10, 20], closed_times=[5, 6])
        assert self.worker.analyze_timing(results) is None

    def test_returns_fingerprint_with_5_probes(self):
        """Should return TimingFingerprint when exactly 5 ports probed."""
        results = self._make_results(
            open_times=[10, 20, 30],
            closed_times=[5, 6]
        )
        fp = self.worker.analyze_timing(results)
        assert fp is not None
        assert isinstance(fp, TimingFingerprint)

    def test_mean_open_computed_correctly(self):
        """Mean open ms should be arithmetic mean of open port times."""
        results = self._make_results(
            open_times=[10, 20, 30],
            closed_times=[5, 5]
        )
        fp = self.worker.analyze_timing(results)
        assert fp.mean_open_ms == 20.0

    def test_mean_closed_computed_correctly(self):
        """Mean closed ms should be arithmetic mean of closed port times."""
        results = self._make_results(
            open_times=[10, 20, 30],
            closed_times=[100, 200]
        )
        fp = self.worker.analyze_timing(results)
        assert fp.mean_closed_ms == 150.0

    def test_mean_filtered_computed_correctly(self):
        """Mean filtered ms should be arithmetic mean of filtered port times."""
        results = self._make_results(
            open_times=[10, 10],
            filtered_times=[3000, 3000, 3000]
        )
        fp = self.worker.analyze_timing(results)
        assert fp.mean_filtered_ms == 3000.0

    def test_stddev_with_variance(self):
        """Stddev should be non-zero when times vary."""
        results = self._make_results(
            open_times=[0, 10, 20, 30, 40]
        )
        fp = self.worker.analyze_timing(results)
        assert fp.stddev_open_ms > 0

    def test_stddev_zero_when_all_same(self):
        """Stddev should be 0 when all times are identical."""
        results = self._make_results(
            open_times=[100, 100, 100, 100, 100]
        )
        fp = self.worker.analyze_timing(results)
        assert fp.stddev_open_ms == 0.0

    def test_ports_sampled_counts(self):
        """ports_sampled should report correct counts per state."""
        results = self._make_results(
            open_times=[10, 20],
            closed_times=[5, 5, 5],
            filtered_times=[3000]
        )
        # 6 total probes >= 5
        fp = self.worker.analyze_timing(results)
        assert fp.ports_sampled == {"open": 2, "closed": 3, "filtered": 1}

    def test_active_filtering_detected_above_threshold(self):
        """Should infer active filtering when |mean_filtered - mean_closed| > threshold."""
        # Closed ports respond fast (5ms), filtered ports timeout (3000ms)
        # Difference = 2995ms > 500ms default threshold
        results = self._make_results(
            open_times=[10],
            closed_times=[5, 5],
            filtered_times=[3000, 3000]
        )
        fp = self.worker.analyze_timing(results)
        assert "active filtering" in fp.inferred_device_type

    def test_no_device_when_within_threshold(self):
        """Should not infer device when timing difference <= threshold."""
        # All response times similar
        results = self._make_results(
            open_times=[10, 12],
            closed_times=[8, 9],
            filtered_times=[11]
        )
        fp = self.worker.analyze_timing(results)
        assert "no device detected" in fp.inferred_device_type

    def test_custom_threshold(self):
        """Should use custom threshold for active filtering inference."""
        # Difference is 200ms (mean_filtered=250, mean_closed=50).
        # Default threshold 500ms → no device.
        # With threshold 150ms → should detect since 200 > 150.
        results = self._make_results(
            open_times=[10, 10],
            closed_times=[50, 50],
            filtered_times=[250]
        )
        fp = self.worker.analyze_timing(results, threshold_ms=150.0)
        assert "active filtering" in fp.inferred_device_type

    def test_threshold_clamped_minimum(self):
        """Threshold below 100ms should be clamped to 100ms."""
        # Difference is 50ms. Threshold 10ms would be clamped to 100ms → no device
        results = self._make_results(
            open_times=[10, 10],
            closed_times=[50, 50],
            filtered_times=[100]
        )
        fp = self.worker.analyze_timing(results, threshold_ms=10.0)
        assert "no device detected" in fp.inferred_device_type

    def test_threshold_clamped_maximum(self):
        """Threshold above 10000ms should be clamped to 10000ms."""
        # Difference is 5000ms. Threshold 20000ms would be clamped to 10000ms → no device at 5000 diff
        results = self._make_results(
            open_times=[10, 10],
            closed_times=[100, 100],
            filtered_times=[5100]
        )
        fp = self.worker.analyze_timing(results, threshold_ms=20000.0)
        assert "no device detected" in fp.inferred_device_type

    def test_no_ttl_data_returns_none_for_ttl_hop_counts(self):
        """When no TTL data available, ttl_hop_counts should be None."""
        results = self._make_results(
            open_times=[10, 20, 30, 40, 50]
        )
        fp = self.worker.analyze_timing(results)
        assert fp.ttl_hop_counts is None

    def test_ttl_data_produces_hop_counts(self):
        """When TTL data is available, hop counts should be computed."""
        results = [
            ProbeResult(port=1, state=PortState.OPEN, response_time_ms=10, ttl=60),
            ProbeResult(port=2, state=PortState.OPEN, response_time_ms=10, ttl=60),
            ProbeResult(port=3, state=PortState.CLOSED, response_time_ms=5, ttl=None),
            ProbeResult(port=4, state=PortState.FILTERED, response_time_ms=3000, ttl=55),
            ProbeResult(port=5, state=PortState.FILTERED, response_time_ms=3000, ttl=55),
        ]
        fp = self.worker.analyze_timing(results)
        assert fp.ttl_hop_counts is not None
        assert fp.ttl_hop_counts["open"] == 4  # 64 - 60
        assert fp.ttl_hop_counts["filtered"] == 9  # 64 - 55

    def test_intermediate_device_flagged_when_hop_diff_ge_2(self):
        """Should flag intermediate device when hop diff >= 2."""
        results = [
            ProbeResult(port=1, state=PortState.OPEN, response_time_ms=10, ttl=62),
            ProbeResult(port=2, state=PortState.OPEN, response_time_ms=10, ttl=62),
            ProbeResult(port=3, state=PortState.CLOSED, response_time_ms=5),
            ProbeResult(port=4, state=PortState.FILTERED, response_time_ms=100, ttl=58),
            ProbeResult(port=5, state=PortState.FILTERED, response_time_ms=100, ttl=58),
        ]
        fp = self.worker.analyze_timing(results)
        # Open hops: 64-62=2, Filtered hops: 64-58=6, diff=4 >= 2
        assert "intermediate" in fp.inferred_device_type or "filtering" in fp.inferred_device_type

    def test_no_intermediate_device_when_hop_diff_lt_2(self):
        """Should not flag intermediate device when hop diff < 2."""
        results = [
            ProbeResult(port=1, state=PortState.OPEN, response_time_ms=10, ttl=62),
            ProbeResult(port=2, state=PortState.OPEN, response_time_ms=10, ttl=62),
            ProbeResult(port=3, state=PortState.CLOSED, response_time_ms=5),
            ProbeResult(port=4, state=PortState.FILTERED, response_time_ms=100, ttl=61),
            ProbeResult(port=5, state=PortState.FILTERED, response_time_ms=100, ttl=61),
        ]
        fp = self.worker.analyze_timing(results)
        # Open hops: 64-62=2, Filtered hops: 64-61=3, diff=1 < 2
        # Only TTL-based, and hop diff < 2, so no intermediate device
        assert "no device detected" in fp.inferred_device_type

    def test_confidence_both_timing_and_ttl(self):
        """Confidence should be 0.9 when both timing and TTL indicate device."""
        results = [
            ProbeResult(port=1, state=PortState.OPEN, response_time_ms=10, ttl=62),
            ProbeResult(port=2, state=PortState.OPEN, response_time_ms=10, ttl=62),
            ProbeResult(port=3, state=PortState.CLOSED, response_time_ms=5),
            ProbeResult(port=4, state=PortState.FILTERED, response_time_ms=3000, ttl=55),
            ProbeResult(port=5, state=PortState.FILTERED, response_time_ms=3000, ttl=55),
        ]
        fp = self.worker.analyze_timing(results)
        # Timing: |3000 - 5| = 2995 > 500 → timing device
        # TTL: open hops=2, filtered hops=9, diff=7 >= 2 → TTL device
        assert fp.confidence == 0.9

    def test_confidence_timing_only(self):
        """Confidence should be 0.7 when only timing indicates device."""
        results = self._make_results(
            open_times=[10],
            closed_times=[5, 5],
            filtered_times=[3000, 3000]
        )
        fp = self.worker.analyze_timing(results)
        assert fp.confidence == 0.7

    def test_confidence_no_indicators(self):
        """Confidence should be 0.1 when no indicators present."""
        results = self._make_results(
            open_times=[10, 10, 10, 10, 10]
        )
        fp = self.worker.analyze_timing(results)
        assert fp.confidence == 0.1

    def test_empty_filtered_and_closed_no_timing_indicator(self):
        """No timing inference when either filtered or closed times are empty."""
        results = self._make_results(
            open_times=[10, 20, 30, 40, 50]
        )
        fp = self.worker.analyze_timing(results)
        # Only open times, no closed/filtered → can't compare
        assert fp.confidence == 0.1


# =============================================================================
# TTL extraction in classify_port
# =============================================================================

class TestClassifyPortTtl:
    """Tests for TTL extraction in classify_port."""

    def setup_method(self):
        self.worker = FirewallDetectorWorker(
            target="192.168.1.1", ports=[80], timeout=3.0
        )

    @patch("app.tools.firewall_detector.socket.socket")
    def test_ttl_extracted_on_open_port(self, mock_socket_class):
        """TTL should be extracted when port is open and getsockopt works."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_sock.getsockopt.return_value = 64
        mock_socket_class.return_value = mock_sock

        result = self.worker.classify_port(80, "192.168.1.1")

        assert result.state == PortState.OPEN
        assert result.ttl == 64

    @patch("app.tools.firewall_detector.socket.socket")
    def test_ttl_none_on_closed_port(self, mock_socket_class):
        """TTL should be None for closed ports (no connection established)."""
        from app.tools.firewall_detector import _ECONNREFUSED
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = _ECONNREFUSED
        mock_socket_class.return_value = mock_sock

        result = self.worker.classify_port(80, "192.168.1.1")

        assert result.state == PortState.CLOSED
        assert result.ttl is None

    @patch("app.tools.firewall_detector.socket.socket")
    def test_ttl_none_on_filtered_port(self, mock_socket_class):
        """TTL should be None for filtered ports."""
        import socket as s
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = s.timeout("timeout")
        mock_socket_class.return_value = mock_sock

        result = self.worker.classify_port(80, "192.168.1.1")

        assert result.state == PortState.FILTERED
        assert result.ttl is None

    @patch("app.tools.firewall_detector.socket.socket")
    def test_ttl_none_when_getsockopt_fails(self, mock_socket_class):
        """TTL should be None when getsockopt raises an error (graceful skip)."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_sock.getsockopt.side_effect = OSError("not supported")
        mock_socket_class.return_value = mock_sock

        result = self.worker.classify_port(80, "192.168.1.1")

        assert result.state == PortState.OPEN
        assert result.ttl is None


# =============================================================================
# Integration: analyze_timing called in run()
# =============================================================================

class TestRunTimingIntegration:
    """Tests that timing analysis is integrated into run() method."""

    @patch("app.tools.firewall_detector.socket.gethostbyname")
    @patch("app.tools.firewall_detector.socket.socket")
    def test_timing_fingerprint_in_results(self, mock_socket_class, mock_resolve):
        """run() should include timing_fingerprint in result dict when ≥5 ports."""
        mock_resolve.return_value = "192.168.1.1"

        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_sock.getsockopt.return_value = 60
        mock_socket_class.return_value = mock_sock

        worker = FirewallDetectorWorker(
            target="192.168.1.1",
            ports=[80, 443, 8080, 8443, 9090],
            timeout=3.0,
        )
        worker.signals = MagicMock()

        worker.run()

        result_dict = worker.signals.results_ready.emit.call_args[0][0]
        assert "timing_fingerprint" in result_dict
        tf = result_dict["timing_fingerprint"]
        assert "inferred_device_type" in tf
        assert "confidence" in tf
        assert "ports_sampled" in tf

    @patch("app.tools.firewall_detector.socket.gethostbyname")
    @patch("app.tools.firewall_detector.socket.socket")
    def test_no_timing_fingerprint_fewer_than_5_ports(self, mock_socket_class, mock_resolve):
        """run() should NOT include timing_fingerprint when < 5 ports probed."""
        mock_resolve.return_value = "192.168.1.1"

        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_class.return_value = mock_sock

        worker = FirewallDetectorWorker(
            target="192.168.1.1",
            ports=[80, 443, 8080],  # Only 3 ports
            timeout=3.0,
        )
        worker.signals = MagicMock()

        worker.run()

        result_dict = worker.signals.results_ready.emit.call_args[0][0]
        assert "timing_fingerprint" not in result_dict
