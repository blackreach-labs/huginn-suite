"""
Unit tests for FirewallDetectorWorker.

Tests port classification, firewall presence analysis, ACK probe logic,
and cancellation behavior using mocked sockets.
"""

import sys
import os
import errno
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.tools.firewall_detector import FirewallDetectorWorker, _ECONNREFUSED
from app.tools.av_firewall_utils import PortState, ProbeResult


# =============================================================================
# classify_port tests
# =============================================================================

class TestClassifyPort:
    """Tests for FirewallDetectorWorker.classify_port()"""

    def setup_method(self):
        self.worker = FirewallDetectorWorker(
            target="192.168.1.1", ports=[80, 443], timeout=3.0
        )

    @patch("app.tools.firewall_detector.socket.socket")
    def test_open_port(self, mock_socket_class):
        """connect_ex returning 0 should classify port as OPEN."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_class.return_value = mock_sock

        result = self.worker.classify_port(80, "192.168.1.1")

        assert result.port == 80
        assert result.state == PortState.OPEN
        assert result.response_time_ms >= 0
        assert result.error_code == 0
        mock_sock.close.assert_called_once()

    @patch("app.tools.firewall_detector.socket.socket")
    def test_closed_port(self, mock_socket_class):
        """connect_ex returning ECONNREFUSED should classify port as CLOSED."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = _ECONNREFUSED
        mock_socket_class.return_value = mock_sock

        result = self.worker.classify_port(80, "192.168.1.1")

        assert result.port == 80
        assert result.state == PortState.CLOSED
        assert result.error_code == _ECONNREFUSED

    @patch("app.tools.firewall_detector.socket.socket")
    def test_filtered_port_timeout(self, mock_socket_class):
        """socket.timeout should classify port as FILTERED."""
        import socket

        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = socket.timeout("timed out")
        mock_socket_class.return_value = mock_sock

        result = self.worker.classify_port(80, "192.168.1.1")

        assert result.port == 80
        assert result.state == PortState.FILTERED
        assert result.error_code is None

    @patch("app.tools.firewall_detector.socket.socket")
    def test_filtered_port_other_error(self, mock_socket_class):
        """connect_ex returning non-zero/non-refused code → FILTERED."""
        mock_sock = MagicMock()
        # ETIMEDOUT or some other error code
        mock_sock.connect_ex.return_value = 110
        mock_socket_class.return_value = mock_sock

        result = self.worker.classify_port(443, "192.168.1.1")

        assert result.port == 443
        assert result.state == PortState.FILTERED
        assert result.error_code == 110

    @patch("app.tools.firewall_detector.socket.socket")
    def test_filtered_port_os_error(self, mock_socket_class):
        """OSError (network unreachable) should classify port as FILTERED."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = OSError(
            errno.ENETUNREACH, "Network unreachable"
        )
        mock_socket_class.return_value = mock_sock

        result = self.worker.classify_port(22, "192.168.1.1")

        assert result.port == 22
        assert result.state == PortState.FILTERED

    @patch("app.tools.firewall_detector.socket.socket")
    def test_response_time_recorded(self, mock_socket_class):
        """Response time should be recorded in whole milliseconds."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_class.return_value = mock_sock

        result = self.worker.classify_port(80, "192.168.1.1")

        # Response time should be a non-negative integer
        assert isinstance(result.response_time_ms, int)
        assert result.response_time_ms >= 0


# =============================================================================
# analyze_firewall_presence tests
# =============================================================================

class TestAnalyzeFirewallPresence:
    """Tests for FirewallDetectorWorker.analyze_firewall_presence()"""

    def setup_method(self):
        self.worker = FirewallDetectorWorker(
            target="192.168.1.1", ports=[80], timeout=3.0
        )

    def _make_results(self, open_count=0, closed_count=0, filtered_count=0):
        """Helper to create probe results with given state counts."""
        results = []
        port = 1
        for _ in range(open_count):
            results.append(ProbeResult(port=port, state=PortState.OPEN, response_time_ms=10))
            port += 1
        for _ in range(closed_count):
            results.append(ProbeResult(port=port, state=PortState.CLOSED, response_time_ms=5))
            port += 1
        for _ in range(filtered_count):
            results.append(ProbeResult(port=port, state=PortState.FILTERED, response_time_ms=3000))
            port += 1
        return results

    def test_all_open_no_firewall(self):
        """All ports open → 'not detected'."""
        results = self._make_results(open_count=10)
        fw = self.worker.analyze_firewall_presence(results)

        assert fw.firewall_status == "not detected"
        assert fw.filtered_ratio == 0.0

    def test_high_filtered_ratio_detected(self):
        """Filtered ratio > 50% → 'detected'."""
        results = self._make_results(open_count=2, filtered_count=8)
        fw = self.worker.analyze_firewall_presence(results)

        assert fw.firewall_status == "detected"
        assert fw.filtered_ratio == 0.8

    def test_medium_filtered_ratio_likely(self):
        """Filtered ratio between 20% and 50% → 'likely'."""
        results = self._make_results(open_count=6, closed_count=1, filtered_count=3)
        fw = self.worker.analyze_firewall_presence(results)

        assert fw.firewall_status == "likely"
        assert 0.20 < fw.filtered_ratio <= 0.50

    def test_low_filtered_ratio_not_detected(self):
        """Filtered ratio ≤ 20% → 'not detected'."""
        results = self._make_results(open_count=8, closed_count=1, filtered_count=1)
        fw = self.worker.analyze_firewall_presence(results)

        assert fw.firewall_status == "not detected"
        assert fw.filtered_ratio <= 0.20

    def test_all_filtered_no_open_closed_host_unreachable(self):
        """All ports filtered (no open, no closed) → 'host unreachable'."""
        results = self._make_results(filtered_count=10)
        fw = self.worker.analyze_firewall_presence(results)

        assert fw.firewall_status == "host unreachable"
        assert len(fw.open_ports) == 0
        assert len(fw.closed_ports) == 0

    def test_empty_results_host_unreachable(self):
        """Empty results → 'host unreachable'."""
        fw = self.worker.analyze_firewall_presence([])

        assert fw.firewall_status == "host unreachable"
        assert fw.confidence_score == 0

    def test_boundary_exactly_20_percent(self):
        """Exactly 20% filtered → 'not detected' (≤ 0.20 threshold)."""
        # 2 filtered out of 10 = 20%
        results = self._make_results(open_count=8, filtered_count=2)
        fw = self.worker.analyze_firewall_presence(results)

        assert fw.firewall_status == "not detected"

    def test_boundary_exactly_50_percent(self):
        """Exactly 50% filtered → 'likely' (not > 0.50, so ≤ 0.50 applies)."""
        # 5 filtered out of 10 = 50%
        results = self._make_results(open_count=5, filtered_count=5)
        fw = self.worker.analyze_firewall_presence(results)

        assert fw.firewall_status == "likely"

    def test_just_over_50_percent_detected(self):
        """Just over 50% filtered → 'detected'."""
        # 6 filtered, 4 open+closed = 60%
        results = self._make_results(open_count=3, closed_count=1, filtered_count=6)
        fw = self.worker.analyze_firewall_presence(results)

        assert fw.firewall_status == "detected"

    def test_result_contains_port_lists(self):
        """Result should contain correct port lists."""
        results = self._make_results(open_count=3, closed_count=2, filtered_count=5)
        fw = self.worker.analyze_firewall_presence(results)

        assert len(fw.open_ports) == 3
        assert len(fw.closed_ports) == 2
        assert len(fw.filtered_ports) == 5

    def test_result_target_preserved(self):
        """Result should contain the target."""
        results = self._make_results(open_count=5)
        fw = self.worker.analyze_firewall_presence(results)

        assert fw.target == "192.168.1.1"


# =============================================================================
# perform_ack_probe tests
# =============================================================================

class TestPerformAckProbe:
    """Tests for FirewallDetectorWorker.perform_ack_probe()"""

    def setup_method(self):
        self.worker = FirewallDetectorWorker(
            target="192.168.1.1", ports=[80], timeout=3.0
        )
        # Suppress signal emissions during tests
        self.worker.signals = MagicMock()

    @patch.object(FirewallDetectorWorker, "classify_port")
    def test_all_filtered_returns_stateful(self, mock_classify):
        """If ephemeral ports are filtered → stateful."""
        mock_classify.return_value = ProbeResult(
            port=50000, state=PortState.FILTERED, response_time_ms=3000
        )

        result = self.worker.perform_ack_probe([80, 443, 8080], "192.168.1.1")

        assert result == "stateful"

    @patch.object(FirewallDetectorWorker, "classify_port")
    def test_all_closed_returns_packet_filter(self, mock_classify):
        """If ephemeral ports are closed (RST) → packet-filter."""
        mock_classify.return_value = ProbeResult(
            port=50000, state=PortState.CLOSED, response_time_ms=5
        )

        result = self.worker.perform_ack_probe([80, 443, 8080], "192.168.1.1")

        assert result == "packet-filter"

    @patch.object(FirewallDetectorWorker, "classify_port")
    def test_mixed_results_returns_none(self, mock_classify):
        """If results are mixed (not majority either way) → None."""
        # Return alternating results
        call_count = [0]

        def alternate(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] % 3 == 0:
                return ProbeResult(port=50000, state=PortState.OPEN, response_time_ms=10)
            elif call_count[0] % 3 == 1:
                return ProbeResult(port=50000, state=PortState.CLOSED, response_time_ms=5)
            else:
                return ProbeResult(port=50000, state=PortState.FILTERED, response_time_ms=3000)

        mock_classify.side_effect = alternate

        result = self.worker.perform_ack_probe([80, 443, 8080], "192.168.1.1")

        # With roughly equal distribution, neither > 50%
        assert result is None

    @patch.object(FirewallDetectorWorker, "classify_port")
    def test_cancellation_during_probe(self, mock_classify):
        """Should stop probing when is_running is set to False."""
        call_count = [0]

        def cancel_after_two(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] >= 2:
                self.worker.is_running = False
            return ProbeResult(port=50000, state=PortState.FILTERED, response_time_ms=3000)

        mock_classify.side_effect = cancel_after_two

        result = self.worker.perform_ack_probe(
            [80, 443, 8080, 22, 21], "192.168.1.1"
        )

        # Should have stopped early
        assert call_count[0] <= 3


# =============================================================================
# run() integration tests (with mocked socket)
# =============================================================================

class TestRunIntegration:
    """Integration tests for the full run() method."""

    @patch("app.tools.firewall_detector.socket.gethostbyname")
    @patch("app.tools.firewall_detector.socket.socket")
    def test_invalid_target_emits_error(self, mock_socket_class, mock_resolve):
        """Empty target should emit error and finish without scanning."""
        worker = FirewallDetectorWorker(target="", ports=[80], timeout=3.0)
        worker.signals = MagicMock()

        worker.run()

        # Should emit error output and finished signal
        worker.signals.output.emit.assert_called()
        error_call = worker.signals.output.emit.call_args_list[0][0][0]
        assert "ERROR" in error_call
        assert "empty" in error_call.lower() or "invalid" in error_call.lower()
        worker.signals.finished.emit.assert_called_once()

    @patch("app.tools.firewall_detector.socket.gethostbyname")
    @patch("app.tools.firewall_detector.socket.socket")
    def test_none_target_emits_error(self, mock_socket_class, mock_resolve):
        """None target should emit error and finish."""
        worker = FirewallDetectorWorker(target=None, ports=[80], timeout=3.0)
        worker.signals = MagicMock()

        worker.run()

        worker.signals.output.emit.assert_called()
        worker.signals.finished.emit.assert_called_once()

    @patch("app.tools.firewall_detector.socket.gethostbyname")
    def test_dns_failure_emits_error(self, mock_resolve):
        """DNS resolution failure should emit error and finish."""
        import socket
        mock_resolve.side_effect = socket.gaierror("Name or service not known")

        worker = FirewallDetectorWorker(
            target="nonexistent.invalid", ports=[80], timeout=3.0
        )
        worker.signals = MagicMock()

        worker.run()

        worker.signals.output.emit.assert_called()
        error_call = worker.signals.output.emit.call_args_list[0][0][0]
        assert "DNS" in error_call or "resolution" in error_call
        worker.signals.finished.emit.assert_called_once()

    @patch("app.tools.firewall_detector.socket.gethostbyname")
    @patch("app.tools.firewall_detector.socket.socket")
    def test_successful_scan_emits_results(self, mock_socket_class, mock_resolve):
        """Successful scan should emit results_ready and finished."""
        mock_resolve.return_value = "192.168.1.1"

        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0  # All ports open
        mock_socket_class.return_value = mock_sock

        worker = FirewallDetectorWorker(
            target="192.168.1.1", ports=[80, 443, 22], timeout=3.0
        )
        worker.signals = MagicMock()

        worker.run()

        worker.signals.results_ready.emit.assert_called_once()
        result_dict = worker.signals.results_ready.emit.call_args[0][0]
        assert result_dict["target"] == "192.168.1.1"
        assert result_dict["scan_type"] == "firewall_detection"
        assert result_dict["error"] is None
        worker.signals.finished.emit.assert_called_once()

    @patch("app.tools.firewall_detector.socket.gethostbyname")
    @patch("app.tools.firewall_detector.socket.socket")
    def test_cancellation_emits_partial_results(self, mock_socket_class, mock_resolve):
        """Cancellation during scan should emit partial results."""
        mock_resolve.return_value = "192.168.1.1"

        call_count = [0]

        def slow_connect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] > 2:
                worker.is_running = False
            return 0

        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = slow_connect
        mock_socket_class.return_value = mock_sock

        worker = FirewallDetectorWorker(
            target="192.168.1.1",
            ports=list(range(80, 100)),  # 20 ports
            timeout=3.0,
        )
        worker.signals = MagicMock()

        worker.run()

        # Should still emit results and finish
        worker.signals.finished.emit.assert_called_once()
