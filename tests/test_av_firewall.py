#!/usr/bin/env python3
"""
Test script for AV/Firewall enumeration functionality.

Tests the refactored architecture:
  - av_firewall_scanner.py: WAF-only detection
  - av_worker.py: Dispatcher routing to specialized workers
  - av_firewall_utils.py: Legacy backward-compat functions
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.tools.av_firewall_scanner import av_firewall_scanner
from app.tools.av_firewall_utils import run_av_firewall_detection, get_nmap_evasion_techniques


def test_av_firewall_scanner():
    """Test AV/Firewall scanner basic functionality (WAF-only)"""
    print("Testing AV/Firewall Scanner (WAF-only)...")

    # Test WAF detection
    print("\n1. Testing WAF detection...")
    results = av_firewall_scanner.detect_waf("example.com", 80)
    print(f"WAF detection results: {results}")

    # Verify ssl_verify attribute exists
    print("\n2. Verifying ssl_verify attribute...")
    assert hasattr(av_firewall_scanner, 'ssl_verify'), "ssl_verify attribute missing"
    assert av_firewall_scanner.ssl_verify is True, "ssl_verify should default to True"
    print(f"  ssl_verify = {av_firewall_scanner.ssl_verify}")

    # Verify removed methods no longer exist
    print("\n3. Verifying removed methods are gone...")
    assert not hasattr(av_firewall_scanner, 'detect_firewall_nmap'), \
        "detect_firewall_nmap should be removed"
    assert not hasattr(av_firewall_scanner, 'firewall_evasion_scan'), \
        "firewall_evasion_scan should be removed"
    assert not hasattr(av_firewall_scanner, 'generate_av_test_payload'), \
        "generate_av_test_payload should be removed"
    assert not hasattr(av_firewall_scanner, '_check_nmap_available'), \
        "_check_nmap_available should be removed"
    assert not hasattr(av_firewall_scanner, '_run_nmap_scan'), \
        "_run_nmap_scan should be removed"
    assert not hasattr(av_firewall_scanner, '_extract_filtered_ports'), \
        "_extract_filtered_ports should be removed"
    print("  All removed methods confirmed absent")

    # Test evasion techniques (legacy utility function still works)
    print("\n4. Testing legacy evasion techniques function...")
    techniques = get_nmap_evasion_techniques()
    for name, cmd in techniques.items():
        print(f"  {name}: {cmd}")

    print("\n[OK] AV/Firewall scanner tests completed!")


def test_output_callback(text):
    """Test output callback"""
    print(f"OUTPUT: {text}")


def test_results_callback(results):
    """Test results callback"""
    print(f"RESULTS: {results}")


def test_av_firewall_worker():
    """Test AV/Firewall worker functionality"""
    print("\nTesting AV/Firewall Worker (legacy compat)...")

    # Test WAF detection worker
    worker = run_av_firewall_detection(
        target="example.com",
        scan_type="waf",
        port=80,
        output_callback=test_output_callback,
        results_callback=test_results_callback
    )

    print(f"WAF Detection Worker created: {worker}")

    # Test payload generation worker (now routes to PayloadGeneratorWorker)
    worker = run_av_firewall_detection(
        target="example.com",
        scan_type="payload",
        payload_type="msfvenom",
        output_callback=test_output_callback,
        results_callback=test_results_callback
    )

    print(f"Payload Generation Worker created: {worker}")
    print("[OK] AV/Firewall worker test completed!")


def test_dispatcher_worker():
    """Test the AVFirewallWorker dispatcher"""
    print("\nTesting AVFirewallWorker dispatcher...")

    from app.tools.av_worker import AVFirewallWorker, TOP_20_PORTS, TOP_100_PORTS

    # Verify port presets are defined
    assert len(TOP_20_PORTS) == 20, f"Expected 20 ports, got {len(TOP_20_PORTS)}"
    assert len(TOP_100_PORTS) == 100, f"Expected 100 ports, got {len(TOP_100_PORTS)}"
    print(f"  TOP_20_PORTS: {len(TOP_20_PORTS)} ports")
    print(f"  TOP_100_PORTS: {len(TOP_100_PORTS)} ports")

    # Verify worker can be created with various detection types
    for detection_type in ["WAF Detection", "Firewall Detection", "Evasion Testing",
                           "AV Payload Generation", "IDS/IPS Detection"]:
        worker = AVFirewallWorker(
            target="192.168.1.1",
            detection_type=detection_type,
            port=80
        )
        assert worker.detection_type == detection_type
        assert worker.is_running is True
        assert hasattr(worker.signals, 'output')
        assert hasattr(worker.signals, 'finished')
        assert hasattr(worker.signals, 'results')
        assert hasattr(worker.signals, 'error')
        print(f"  {detection_type}: worker created OK")

    # Verify cancel propagation
    worker = AVFirewallWorker(target="192.168.1.1", detection_type="Firewall Detection")
    worker.cancel()
    assert worker.is_running is False
    print("  Cancellation: OK")

    print("[OK] AVFirewallWorker dispatcher tests completed!")


if __name__ == "__main__":
    print("AV/Firewall Detection Test Suite")
    print("=" * 40)

    try:
        test_av_firewall_scanner()
        test_av_firewall_worker()
        test_dispatcher_worker()
        print("\n[SUCCESS] All tests passed!")
    except Exception as e:
        print(f"\n[ERROR] Test failed: {e}")
        import traceback
        traceback.print_exc()
