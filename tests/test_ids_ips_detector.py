"""
Unit tests for IDSIPSDetectorWorker.

Tests baseline establishment, attack signature detection, rate limiting,
confidence mapping, and cancellation behavior using mocked sockets.
"""

import sys
import os
import socket
from unittest.mock import patch, MagicMock, call

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.tools.ids_ips_detector import IDSIPSDetectorWorker


# =============================================================================
# establish_baseline tests
# =============================================================================

class TestEstablishBaseline:
    """Tests for IDSIPSDetectorWorker.establish_baseline()"""

    def setup_method(self):
        self.worker = IDSIPSDetectorWorker(
            target="192.168.1.1", ports=[80, 443], timeout=3.0
        )
        self.worker.signals = MagicMock()

    @patch("app.tools.ids_ips_detector.socket.socket")
    def test_successful_baseline(self, mock_socket_class):
        """All 3 benign requests succeed → returns times dict."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"HTTP/1.1 200 OK\r\n\r\n"
        mock_socket_class.return_value = mock_sock

        result = self.worker.establish_baseline(80, "192.168.1.1")

        assert result is not None
        assert "times" in result
        assert len(result["times"]) == 3
        assert result["successes"] == 3

    @patch("app.tools.ids_ips_detector.socket.socket")
    def test_baseline_fails_all_timeouts(self, mock_socket_class):
        """All requests timeout → returns None."""
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = socket.timeout("timed out")
        mock_socket_class.return_value = mock_sock

        result = self.worker.establish_baseline(80, "192.168.1.1")

        assert result is None

    @patch("app.tools.ids_ips_detector.socket.socket")
    def test_baseline_fails_partial_success(self, mock_socket_class):
        """Only 2 out of 3 requests succeed → returns None (requires all 3)."""
        mock_sock = MagicMock()
        call_count = [0]

        def mock_recv(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] <= 2:
                return b"HTTP/1.1 200 OK\r\n\r\n"
            raise socket.timeout("timed out")

        mock_sock.recv.side_effect = mock_recv
        mock_socket_class.return_value = mock_sock

        result = self.worker.establish_baseline(80, "192.168.1.1")

        assert result is None

    @patch("app.tools.ids_ips_detector.socket.socket")
    def test_baseline_cancelled(self, mock_socket_class):
        """Returns None when is_running becomes False."""
        self.worker.is_running = False

        result = self.worker.establish_baseline(80, "192.168.1.1")

        assert result is None


# =============================================================================
# send_attack_signatures tests
# =============================================================================

class TestSendAttackSignatures:
    """Tests for IDSIPSDetectorWorker.send_attack_signatures()"""

    def setup_method(self):
        self.worker = IDSIPSDetectorWorker(
            target="192.168.1.1", ports=[80], timeout=3.0
        )
        self.worker.signals = MagicMock()

    @patch("app.tools.ids_ips_detector.socket.socket")
    def test_no_ids_when_all_succeed(self, mock_socket_class):
        """No IDS detection when all attack requests get responses."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"HTTP/1.1 200 OK\r\n\r\n"
        mock_socket_class.return_value = mock_sock

        result = self.worker.send_attack_signatures(
            80, "192.168.1.1", baseline_times=[10.0, 12.0, 11.0]
        )

        assert result["ids_detected"] is False
        assert result["triggering_categories"] == []

    @patch("app.tools.ids_ips_detector.socket.socket")
    def test_ids_detected_two_consecutive_resets(self, mock_socket_class):
        """IDS inferred when ≥2 consecutive attack requests get reset."""
        mock_sock = MagicMock()
        call_count = [0]

        def mock_connect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] >= 2:
                raise ConnectionResetError("Connection reset by peer")

        mock_sock.connect.side_effect = mock_connect
        mock_sock.recv.return_value = b"HTTP/1.1 200 OK\r\n\r\n"
        mock_socket_class.return_value = mock_sock

        result = self.worker.send_attack_signatures(
            80, "192.168.1.1", baseline_times=[10.0, 12.0, 11.0]
        )

        assert result["ids_detected"] is True
        assert result["max_consecutive_failures"] >= 2

    @patch("app.tools.ids_ips_detector.socket.socket")
    def test_ids_detected_two_consecutive_timeouts(self, mock_socket_class):
        """IDS inferred when ≥2 consecutive attack requests timeout."""
        mock_sock = MagicMock()
        call_count = [0]

        def mock_connect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] >= 2:
                raise socket.timeout("timed out")

        mock_sock.connect.side_effect = mock_connect
        mock_sock.recv.return_value = b"HTTP/1.1 200 OK\r\n\r\n"
        mock_socket_class.return_value = mock_sock

        result = self.worker.send_attack_signatures(
            80, "192.168.1.1", baseline_times=[10.0, 12.0, 11.0]
        )

        assert result["ids_detected"] is True

    @patch("app.tools.ids_ips_detector.socket.socket")
    @patch("app.tools.ids_ips_detector.time.perf_counter")
    def test_ips_timing_detected(self, mock_perf_counter, mock_socket_class):
        """IPS flagged when attack avg > 200% of baseline avg."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"HTTP/1.1 200 OK\r\n\r\n"
        mock_socket_class.return_value = mock_sock

        # Simulate slow responses: each call pair is (start, end)
        # 3 attack signatures → 3 requests → 6 perf_counter calls
        # Make each response take ~300ms (0.3s)
        times = []
        t = 0.0
        for _ in range(3):
            times.append(t)        # start
            times.append(t + 0.3)  # end (300ms)
            t += 0.5
        mock_perf_counter.side_effect = times

        # Baseline avg is 10ms, attack will be 300ms → > 200%
        result = self.worker.send_attack_signatures(
            80, "192.168.1.1", baseline_times=[10.0, 10.0, 10.0]
        )

        assert result["ips_timing_detected"] is True
        assert result["attack_avg_ms"] > 20.0  # > 200% of 10ms baseline

    @patch("app.tools.ids_ips_detector.socket.socket")
    def test_no_ips_when_timing_normal(self, mock_socket_class):
        """No IPS when attack response times are within normal range."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"HTTP/1.1 200 OK\r\n\r\n"
        mock_socket_class.return_value = mock_sock

        # Baseline avg is large enough that attack won't exceed 200%
        result = self.worker.send_attack_signatures(
            80, "192.168.1.1", baseline_times=[500.0, 500.0, 500.0]
        )

        assert result["ips_timing_detected"] is False


# =============================================================================
# detect_rate_limiting tests
# =============================================================================

class TestDetectRateLimiting:
    """Tests for IDSIPSDetectorWorker.detect_rate_limiting()"""

    def setup_method(self):
        self.worker = IDSIPSDetectorWorker(
            target="192.168.1.1", ports=[80], timeout=3.0
        )
        self.worker.signals = MagicMock()

    @patch("app.tools.ids_ips_detector.time.sleep")
    @patch("app.tools.ids_ips_detector.socket.socket")
    def test_no_rate_limiting(self, mock_socket_class, mock_sleep):
        """No rate limiting when all connections succeed at all rates."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_class.return_value = mock_sock

        result = self.worker.detect_rate_limiting(80, "192.168.1.1")

        assert result["detected"] is False
        assert result["threshold"] is None

    @patch("app.tools.ids_ips_detector.time.sleep")
    @patch("app.tools.ids_ips_detector.socket.socket")
    def test_rate_limiting_at_20_per_sec(self, mock_socket_class, mock_sleep):
        """Rate limiting detected when success drops below 50% at 20/sec."""
        mock_sock = MagicMock()
        total_calls = [0]

        def mock_connect_ex(*args, **kwargs):
            total_calls[0] += 1
            # First 30 calls (rates 1, 5, 10 → 10 each) succeed
            # After that, fail (rate 20)
            if total_calls[0] <= 30:
                return 0
            else:
                return 110  # ETIMEDOUT

        mock_sock.connect_ex.side_effect = mock_connect_ex
        mock_socket_class.return_value = mock_sock

        result = self.worker.detect_rate_limiting(80, "192.168.1.1")

        assert result["detected"] is True
        assert result["threshold"] == 20

    @patch("app.tools.ids_ips_detector.time.sleep")
    @patch("app.tools.ids_ips_detector.socket.socket")
    def test_rate_limiting_at_first_rate(self, mock_socket_class, mock_sleep):
        """Rate limiting at 1/sec when port immediately rejects."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 110  # Always fails
        mock_socket_class.return_value = mock_sock

        result = self.worker.detect_rate_limiting(80, "192.168.1.1")

        assert result["detected"] is True
        assert result["threshold"] == 1


# =============================================================================
# confidence mapping tests
# =============================================================================

class TestConfidenceMapping:
    """Tests for _compute_confidence method."""

    def setup_method(self):
        self.worker = IDSIPSDetectorWorker(
            target="192.168.1.1", ports=[80], timeout=3.0
        )

    def test_zero_indicators_low(self):
        """0 indicators → low confidence."""
        assert self.worker._compute_confidence(0) == "low"

    def test_one_indicator_low(self):
        """1 indicator → low confidence."""
        assert self.worker._compute_confidence(1) == "low"

    def test_two_indicators_medium(self):
        """2 indicators → medium confidence."""
        assert self.worker._compute_confidence(2) == "medium"

    def test_three_indicators_high(self):
        """3 indicators → high confidence."""
        assert self.worker._compute_confidence(3) == "high"

    def test_many_indicators_high(self):
        """5+ indicators → high confidence."""
        assert self.worker._compute_confidence(5) == "high"
        assert self.worker._compute_confidence(10) == "high"


# =============================================================================
# detection method determination tests
# =============================================================================

class TestDetectionMethod:
    """Tests for _determine_detection_method."""

    def setup_method(self):
        self.worker = IDSIPSDetectorWorker(
            target="192.168.1.1", ports=[80], timeout=3.0
        )

    def test_no_indicators_none(self):
        """Empty indicators → 'none'."""
        assert self.worker._determine_detection_method([]) == "none"

    def test_single_signature(self):
        """Single signature indicator → 'signature'."""
        indicators = [{"type": "signature_based", "detail": "test"}]
        assert self.worker._determine_detection_method(indicators) == "signature"

    def test_single_timing(self):
        """Single timing indicator → 'timing'."""
        indicators = [{"type": "timing_anomaly", "detail": "test"}]
        assert self.worker._determine_detection_method(indicators) == "timing"

    def test_single_rate_limiting(self):
        """Single rate_limiting indicator → 'rate_limiting'."""
        indicators = [{"type": "rate_limiting", "detail": "test"}]
        assert self.worker._determine_detection_method(indicators) == "rate_limiting"

    def test_multiple_types(self):
        """Multiple different indicator types → 'multiple'."""
        indicators = [
            {"type": "signature_based", "detail": "test"},
            {"type": "timing_anomaly", "detail": "test"},
        ]
        assert self.worker._determine_detection_method(indicators) == "multiple"


# =============================================================================
# run() integration tests
# =============================================================================

class TestRunIntegration:
    """Integration tests for the full run() method."""

    def test_invalid_target_emits_error(self):
        """Empty target should emit error and finish."""
        worker = IDSIPSDetectorWorker(target="", ports=[80], timeout=3.0)
        worker.signals = MagicMock()

        worker.run()

        worker.signals.output.emit.assert_called()
        error_call = worker.signals.output.emit.call_args_list[0][0][0]
        assert "ERROR" in error_call
        worker.signals.finished.emit.assert_called_once()

    def test_none_target_emits_error(self):
        """None target should emit error and finish."""
        worker = IDSIPSDetectorWorker(target=None, ports=[80], timeout=3.0)
        worker.signals = MagicMock()

        worker.run()

        worker.signals.output.emit.assert_called()
        worker.signals.finished.emit.assert_called_once()

    @patch("app.tools.ids_ips_detector.socket.gethostbyname")
    def test_dns_failure_emits_error(self, mock_resolve):
        """DNS resolution failure should emit error and finish."""
        mock_resolve.side_effect = socket.gaierror("Name not known")

        worker = IDSIPSDetectorWorker(
            target="nonexistent.invalid", ports=[80], timeout=3.0
        )
        worker.signals = MagicMock()

        worker.run()

        worker.signals.output.emit.assert_called()
        error_call = worker.signals.output.emit.call_args_list[0][0][0]
        assert "DNS" in error_call
        worker.signals.finished.emit.assert_called_once()

    @patch("app.tools.ids_ips_detector.socket.gethostbyname")
    @patch("app.tools.ids_ips_detector.socket.socket")
    def test_no_open_ports_aborts(self, mock_socket_class, mock_resolve):
        """No open ports found → abort with message (Req 6.6)."""
        mock_resolve.return_value = "192.168.1.1"

        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 110  # All filtered
        mock_socket_class.return_value = mock_sock

        worker = IDSIPSDetectorWorker(
            target="192.168.1.1", ports=[80, 443], timeout=3.0
        )
        worker.signals = MagicMock()

        worker.run()

        # Should emit the "no open ports" message
        output_calls = [c[0][0] for c in worker.signals.output.emit.call_args_list]
        assert any("No open ports" in msg or "no open ports" in msg.lower()
                   for msg in output_calls)

        # Should still emit results and finish
        worker.signals.results_ready.emit.assert_called_once()
        result = worker.signals.results_ready.emit.call_args[0][0]
        assert result["detected"] is False
        worker.signals.finished.emit.assert_called_once()

    @patch("app.tools.ids_ips_detector.socket.gethostbyname")
    @patch("app.tools.ids_ips_detector.socket.socket")
    def test_successful_detection_emits_results(self, mock_socket_class, mock_resolve):
        """Full scan with IDS detection should emit proper results."""
        mock_resolve.return_value = "192.168.1.1"

        mock_sock = MagicMock()
        connect_count = [0]

        def mock_connect_ex(*args, **kwargs):
            # Port check: first calls are for _find_open_ports
            return 0  # All open

        def mock_connect(*args, **kwargs):
            connect_count[0] += 1
            # First 3 are baseline (succeed)
            if connect_count[0] <= 3:
                return
            # Attack signatures: 2nd and 3rd fail
            if connect_count[0] >= 5:
                raise ConnectionResetError("reset")

        mock_sock.connect_ex.side_effect = mock_connect_ex
        mock_sock.connect.side_effect = mock_connect
        mock_sock.recv.return_value = b"HTTP/1.1 200 OK\r\n\r\n"
        mock_socket_class.return_value = mock_sock

        worker = IDSIPSDetectorWorker(
            target="192.168.1.1", ports=[80], timeout=3.0
        )
        worker.signals = MagicMock()

        worker.run()

        worker.signals.results_ready.emit.assert_called_once()
        result = worker.signals.results_ready.emit.call_args[0][0]
        assert result["scan_type"] == "ids_ips_detection"
        assert result["error"] is None
        worker.signals.finished.emit.assert_called_once()

    @patch("app.tools.ids_ips_detector.socket.gethostbyname")
    @patch("app.tools.ids_ips_detector.socket.socket")
    def test_cancellation_emits_partial(self, mock_socket_class, mock_resolve):
        """Cancellation should emit partial results."""
        mock_resolve.return_value = "192.168.1.1"

        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_sock.recv.return_value = b"HTTP/1.1 200 OK\r\n\r\n"
        mock_socket_class.return_value = mock_sock

        worker = IDSIPSDetectorWorker(
            target="192.168.1.1", ports=[80, 443, 22], timeout=3.0
        )
        worker.signals = MagicMock()

        # Cancel immediately after start
        original_find = worker._find_open_ports

        def cancel_after_find(*args, **kwargs):
            result = original_find(*args, **kwargs)
            worker.is_running = False
            return result

        worker._find_open_ports = cancel_after_find

        worker.run()

        worker.signals.finished.emit.assert_called_once()
