# Implementation Plan: AV/Firewall Service Enumeration - Native Implementation

## Overview

This plan decomposes the monolithic `AVFirewallScanner` into focused native Python workers, eliminating nmap and msfvenom dependencies. Each task builds incrementally—shared data models and utilities first, then individual detection workers, then integration wiring. The existing WAF detection remains unchanged.

## Tasks

- [x] 1. Set up shared data models, utilities, and signal infrastructure
  - [x] 1.1 Create shared data models and port list parser in `app/tools/av_firewall_utils.py`
    - Define `PortState` enum (OPEN, CLOSED, FILTERED)
    - Define dataclasses: `ProbeResult`, `FirewallResult`, `TimingFingerprint`, `TechniqueResult`, `EvasionSummary`, `PayloadConfig`, `PayloadResult`, `IDSResult`, `ScanResult`
    - Implement `parse_port_list(spec: str) -> List[int]` that handles comma-separated ports, hyphenated ranges, validates 1–65535, deduplicates, and caps at 10000
    - Implement shared `WorkerSignals(QObject)` class with the 6 standard signals (output, status, finished, results_ready, progress_start, progress_update)
    - Implement `validate_target(target: str) -> bool` for empty/None checks
    - Implement `validate_params(timeout, max_workers, ports)` for range validation
    - _Requirements: 5.1, 5.7, 7.4, 7.6, 8.1_

  - [ ]* 1.2 Write property tests for port list parser and input validation
    - **Property 17: Port List Parsing** — verify comma-separated and range parsing produces correct ports in 1–65535, no duplicates, max 10000
    - **Property 12: Input Validation and Rejection** — verify invalid ports/timeout/threads are rejected with specific error messages
    - **Validates: Requirements 7.4, 7.6**

- [x] 2. Implement FirewallDetectorWorker
  - [x] 2.1 Create `app/tools/firewall_detector.py` with port classification and firewall presence analysis
    - Implement `FirewallDetectorWorker(QRunnable)` with `__init__(target, ports, timeout=3.0, max_workers=50)`
    - Implement `classify_port(port)` using `socket.connect_ex()`: return code 0 → OPEN, ECONNREFUSED (10061 on Windows) → CLOSED, timeout → FILTERED
    - Record response time in whole milliseconds per probe
    - Implement `analyze_firewall_presence(results)`: filtered_ratio > 0.50 → "detected", 0.20–0.50 → "likely", ≤ 0.20 → "not detected"
    - All ports unreachable (no open/closed) → "host unreachable"
    - Implement `perform_ack_probe(filtered_ports)` using ephemeral port range 49152–65535 to differentiate stateful vs packet-filter
    - Use `concurrent.futures.ThreadPoolExecutor(max_workers=50)` for parallel probing
    - Emit HTML-formatted output with color scheme (#00FF41 success, #FF6B6B error, #00BFFF info, #FFAA00 warning)
    - Support cancellation via `is_running` flag checked before each probe submission and inside futures loop
    - Emit partial results on cancellation
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 1.10, 5.1, 5.4, 5.5, 5.6, 5.7, 5.8, 5.9_

  - [x] 2.2 Add TTL and timing analysis to `firewall_detector.py`
    - Implement `analyze_timing(probe_results)` computing mean and stddev per port state when ≥5 ports probed
    - Infer "active filtering" when |mean_filtered - mean_closed| > configurable threshold (default 500ms)
    - Attempt TTL extraction via socket API where available; skip gracefully if unavailable
    - Estimate hop count from TTL vs standard defaults (64, 128, 255); flag intermediate device when hop difference ≥ 2
    - Produce `TimingFingerprint` dataclass with all fields
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7_

  - [ ]* 2.3 Write property tests for port classification and firewall presence
    - **Property 1: Port State Classification** — connect_ex return code mapping to open/closed/filtered
    - **Property 2: Firewall Presence Ratio Classification** — threshold-based presence determination
    - **Property 3: Host Unreachable vs Firewall Distinction** — all-timeout case yields "host unreachable"
    - **Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 1.9**

  - [ ]* 2.4 Write property tests for timing analysis and TTL
    - **Property 4: Timing Statistics and Active Filtering Inference** — mean/stddev correctness and threshold comparison
    - **Property 5: TTL Hop Count Estimation** — hop count from TTL and intermediate device flagging
    - **Validates: Requirements 2.3, 2.4, 2.5**

- [x] 3. Implement EvasionProfilerWorker
  - [x] 3.1 Create `app/tools/evasion_profiler.py` with baseline and evasion techniques
    - Implement `EvasionProfilerWorker(QRunnable)` with `__init__(target, ports, timeout=3.0, max_workers=50)`
    - Implement `establish_baseline()` performing connect-scan to identify filtered ports
    - Implement `test_source_port_evasion(filtered_ports)`: bind to ports 53, 80, 443, 88 + 4 random; 3 attempts per source port per target port; handle EACCES gracefully for privileged ports
    - Implement `test_timing_evasion(filtered_ports)`: delays 0ms, 1000ms, 5000ms, 15000ms; re-probe all filtered ports per delay
    - Implement `test_window_size_evasion(filtered_ports)`: SO_SNDBUF sizes 1024, 4096, 16384, 65535
    - Implement `test_pattern_evasion(filtered_ports)`: sequential vs randomized port ordering
    - Implement `test_flag_manipulation(filtered_ports)`: raw sockets for FIN, NULL, Xmas probes; fall back to connect-scan if permission denied
    - Success threshold: ≥2 of 3 attempts result in connection to previously-filtered port
    - Produce `EvasionSummary` with per-technique classification and evidence
    - Support cancellation via `is_running` checked between technique iterations
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 3.10, 5.2, 5.8, 5.9_

  - [ ]* 3.2 Write property tests for evasion logic
    - **Property 6: Evasion Technique Success Classification** — ≥2/3 success → "successful"
    - **Property 7: Evasion Summary Completeness** — all techniques present with classification
    - **Validates: Requirements 3.2, 3.4, 3.7, 3.8**

- [x] 4. Implement PayloadGeneratorWorker
  - [x] 4.1 Create `app/tools/payload_generator.py` with shellcode generation and encoding
    - Implement `PayloadGeneratorWorker(QRunnable)` with `__init__(payload_type, payload_format, architecture, encoding, lhost, lport, staged)`
    - Default architecture to x64 when not specified
    - Implement `generate_shellcode()` for reverse_tcp, bind_tcp, cmd_exec using `struct.pack()` for x86 and x64
    - Implement `apply_encoding(shellcode)`: XOR (random key 1–32 bytes with decoder stub), base64, byte substitution
    - Implement `format_output(encoded)`: raw bytes, PE exe (MZ header + .text section), PE DLL (DllMain entry), PowerShell (base64 cradle)
    - Implement `calculate_detection_score(payload, encoding_layers)`: integer 0–100, monotonically decreasing with more layers
    - Implement `generate_staged()`: separate stager (connection/download logic) and main payload; neither alone is complete
    - Reject unsupported formats/types with specific error messages
    - No network access, no subprocess calls
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 4.9, 4.10, 5.3, 5.8_

  - [ ]* 4.2 Write property tests for payload generation
    - **Property 8: Payload Format Conformance** — exe/dll starts with MZ, powershell is valid script, raw is non-empty
    - **Property 9: Encoding Round-Trip** — encode then decode produces identical shellcode
    - **Property 10: Detection Score Calculation** — score is 0–100, monotonically decreasing with encoding layers
    - **Property 11: Staged Payload Component Separation** — neither stager nor main payload alone is complete
    - **Validates: Requirements 4.1, 4.2, 4.4, 4.5, 4.6**

- [x] 5. Implement IDSIPSDetectorWorker
  - [x] 5.1 Create `app/tools/ids_ips_detector.py` with behavioral and rate-limiting detection
    - Implement `IDSIPSDetectorWorker(QRunnable)` with `__init__(target, ports, timeout=3.0)`
    - Implement `establish_baseline(port)`: send ≥3 benign HTTP requests, record response times
    - Abort if no open ports found, emitting appropriate message
    - Implement `send_attack_signatures(port)`: SQLi, XSS, path traversal patterns; infer IDS if ≥2 consecutive resets/timeouts
    - Flag inline IPS when attack avg response time > 200% baseline avg
    - Implement `detect_rate_limiting(port)`: connections at 1, 5, 10, 20, 50/sec; detect threshold where rejection begins
    - Confidence mapping: 1 indicator → low, 2 → medium, 3+ → high
    - Produce `IDSResult` dataclass with detection_method, confidence, indicators, affected_ports
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 5.8_

  - [ ]* 5.2 Write property tests for IDS/IPS detection
    - **Property 14: IDS/IPS Behavioral Inference** — 2+ consecutive failures after successful baseline → IDS detected
    - **Property 15: IDS Confidence Level Mapping** — N indicators maps to correct confidence level
    - **Property 16: Rate Limiting Threshold Detection** — rate at which rejection begins is reported
    - **Validates: Requirements 6.2, 6.3, 6.4, 6.5**

- [x] 6. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 7. Refactor existing scanner and wire workers into dispatcher
  - [x] 7.1 Refactor `app/tools/av_firewall_scanner.py` to WAF-only
    - Remove `detect_firewall_nmap()`, `firewall_evasion_scan()`, `generate_av_test_payload()` methods
    - Remove `_check_nmap_available()`, `_run_nmap_scan()`, `_extract_filtered_ports()` helper methods
    - Keep `detect_waf()` unchanged
    - Keep `ssl_verify` attribute and global `av_firewall_scanner` instance
    - _Requirements: 5.4 (WAF unchanged)_

  - [x] 7.2 Refactor `app/tools/av_worker.py` as dispatcher routing to new workers
    - Update `AVFirewallWorker` to instantiate and delegate to the appropriate new worker based on `detection_type`
    - "WAF Detection" → use existing `av_firewall_scanner.detect_waf()` (unchanged)
    - "Firewall Detection" → instantiate and run `FirewallDetectorWorker`
    - "Evasion Testing" → instantiate and run `EvasionProfilerWorker`
    - "AV Payload Generation" → instantiate and run `PayloadGeneratorWorker`
    - "IDS/IPS Detection" → instantiate and run `IDSIPSDetectorWorker`
    - Accept configurable parameters: port list/preset, timeout, max_workers, scan type
    - Implement port preset handling: top-20, top-100, top-1000, custom
    - Forward cancellation (`is_running = False`) to child workers within 2 seconds
    - Emit progress updates at least every 10 probes
    - Emit partial results on cancellation in same format as completed scan
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 8.1, 8.4, 8.5, 8.6_

  - [x] 7.3 Implement structured result formatting and recommended next steps
    - Ensure all workers emit `ScanResult`-compatible dictionaries with required keys: target, scan_type, detected_security_products, filtered_ports, successful_evasion_techniques, confidence_scores, error
    - When filtered_ports is non-empty, include `recommended_next_steps` list
    - Format HTML output using the color scheme for UI display
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6_

  - [ ]* 7.4 Write property tests for result structure and HTML output
    - **Property 13: HTML Output Formatting** — all emitted strings are valid `<p>` elements with correct inline color
    - **Property 18: Result Structure Validation** — emitted result dicts contain all required keys with correct types
    - **Validates: Requirements 5.7, 8.1, 8.2, 8.3**

- [x] 8. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- Unit tests validate specific examples and edge cases
- All workers follow the same QRunnable + signals pattern as the existing `PortScanWorker`
- Socket mocking (`unittest.mock.patch`) is used for all network-level tests to avoid real connections
- The existing WAF detection in `av_firewall_scanner.py` remains completely unchanged

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["1.2", "2.1"] },
    { "id": 2, "tasks": ["2.2", "2.3", "3.1", "4.1", "5.1"] },
    { "id": 3, "tasks": ["2.4", "3.2", "4.2", "5.2"] },
    { "id": 4, "tasks": ["7.1", "7.2"] },
    { "id": 5, "tasks": ["7.3"] },
    { "id": 6, "tasks": ["7.4"] }
  ]
}
```
