# Requirements Document

## Introduction

This feature replaces all external tool dependencies (nmap, msfvenom) in the Huginn AV/Firewall Service Enumeration module with native Python implementations. The module currently has four detection modes: WAF Detection (already native), Firewall Detection (uses nmap), Evasion Testing (uses nmap), and AV Payload Generation (uses msfvenom). The goal is to achieve full native capability by leveraging existing Huginn infrastructure (PortScanWorker, EnhancedPortScanWorker, socket-based scanning) and building new pure-Python detection logic where needed.

## Glossary

- **AV_FW_Scanner**: The AV/Firewall detection scanner module (`AVFirewallScanner` class in `app/tools/av_firewall_scanner.py`)
- **Firewall_Detector**: The native Python component responsible for detecting network firewalls through TCP probe analysis
- **Evasion_Profiler**: The native Python component responsible for testing firewall bypass techniques
- **Payload_Generator**: The native Python component responsible for generating AV evasion test payloads without msfvenom
- **WAF_Detector**: The existing native WAF detection component (unchanged)
- **Port_Scanner**: The existing native port scanning infrastructure (`PortScanWorker` / `EnhancedPortScanWorker` in `app/tools/port_scanner.py`)
- **TCP_Probe**: A raw or connect-level TCP packet sent to a target port to observe response behavior (SYN-ACK, RST, timeout/drop)
- **Port_State**: The classification of a port as open (SYN-ACK received), closed (RST received), or filtered (no response / timeout)
- **Evasion_Technique**: A method of altering packet characteristics (fragmentation, timing, flag manipulation) to bypass firewall rules
- **Shellcode**: Machine code payload bytes designed to execute on a target system
- **Worker**: A PyQt6 QRunnable that executes scan logic on a background thread and emits signals for progress and results

## Requirements

### Requirement 1: Native Firewall Detection via TCP Probe Analysis

**User Story:** As a penetration tester, I want to detect network firewalls using native Python socket operations, so that I do not need nmap installed to identify filtered ports and firewall presence.

#### Acceptance Criteria

1. WHEN a target IP address and port list are provided, THE Firewall_Detector SHALL send TCP SYN-equivalent connect probes to each port using socket.connect_ex() and classify the response as open, closed, or filtered based on connection result and timeout behavior
2. WHEN a port responds with a successful connection (SYN-ACK equivalent), THE Firewall_Detector SHALL classify that port as open
3. WHEN a port responds with a connection refused error (RST equivalent), THE Firewall_Detector SHALL classify that port as closed
4. WHEN a port does not respond within the configured timeout period (default: 3 seconds, configurable between 1 and 30 seconds), THE Firewall_Detector SHALL classify that port as filtered
5. WHEN the scan completes, THE Firewall_Detector SHALL determine firewall presence by analyzing the ratio of filtered ports to total ports scanned, reporting firewall as "detected" when the filtered ratio exceeds 50%, "likely" between 20% and 50%, and "not detected" below 20%
6. WHEN filtered ports are detected, THE Firewall_Detector SHALL report the list of filtered ports, the inferred firewall type (stateful or packet-filter), and a confidence score expressed as a percentage from 0 to 100
7. WHEN the scan completes with at least one filtered port, THE Firewall_Detector SHALL perform an ACK-style probe (TCP connect to ports in the 49152–65535 ephemeral range) to differentiate stateful firewalls from simple packet filters based on whether ephemeral port probes are also filtered
8. THE Firewall_Detector SHALL use the existing Port_Scanner thread pool pattern (concurrent.futures.ThreadPoolExecutor with max_workers=50) for parallel port probing
9. IF the target IP address is unreachable on all probed ports (all connections fail with timeout or network-unreachable error), THEN THE Firewall_Detector SHALL report a "host unreachable" status and not infer firewall presence
10. IF the user cancels the scan while probing is in progress, THEN THE Firewall_Detector SHALL stop all pending probes within 3 seconds and report partial results for ports already classified

### Requirement 2: Native TTL and Timing Analysis for Firewall Fingerprinting

**User Story:** As a penetration tester, I want to analyze TTL values and response timing from TCP probes, so that I can fingerprint the type of firewall device in the network path.

#### Acceptance Criteria

1. WHEN a TCP connection is established to an open port, THE Firewall_Detector SHALL record the response time in whole milliseconds, measured from the moment the connection attempt begins (connect_ex call) to the moment the connection result is returned
2. WHEN a port does not respond within the configured timeout, THE Firewall_Detector SHALL record the elapsed time until timeout as the response time for that filtered port
3. WHEN at least 5 ports have been probed, THE Firewall_Detector SHALL calculate the mean response time and standard deviation separately for open ports, closed ports, and filtered ports
4. WHEN the mean response time for filtered ports differs from the mean response time for closed ports by more than a configurable threshold (default: 500 milliseconds, range: 100 to 10000 milliseconds), THE Firewall_Detector SHALL infer an active filtering device rather than an unreachable host
5. WHEN available through the socket API, THE Firewall_Detector SHALL extract TTL values from responses and compare the observed TTL against standard OS defaults (64, 128, 255) to estimate hop count, flagging a potential intermediate filtering device when the estimated hop count for filtered ports differs from open ports by 2 or more hops
6. IF TTL extraction is not available on the platform, THEN THE Firewall_Detector SHALL skip TTL analysis and rely on timing-based detection only
7. WHEN timing and TTL analysis is complete, THE Firewall_Detector SHALL produce a fingerprint result containing: inferred device type, confidence score (0.0 to 1.0), mean response times per port state, TTL-derived hop counts (if available), and the number of ports sampled per category

### Requirement 3: Native Firewall Evasion Testing

**User Story:** As a penetration tester, I want to test firewall evasion techniques using native Python, so that I can map which bypass methods succeed without requiring nmap.

#### Acceptance Criteria

1. WHEN evasion testing is initiated, THE Evasion_Profiler SHALL first perform a baseline connect-scan against the target port list using default parameters to identify which ports are currently classified as filtered (no response within the configured timeout), then test the following techniques against those filtered ports: varied source ports, timing variation, TCP window size manipulation, and connection pattern variation
2. WHEN testing source port evasion, THE Evasion_Profiler SHALL attempt connections from commonly-allowed source ports (53, 80, 443, 88) and compare results against connections from 4 randomly-selected ports in the range 1024-65535, performing 3 connection attempts per source port per target port to confirm consistency
3. IF binding to a privileged source port (below 1024) fails due to insufficient permissions, THEN THE Evasion_Profiler SHALL skip that source port, log the failure in the summary, and continue testing with the remaining source ports
4. WHEN testing timing evasion, THE Evasion_Profiler SHALL vary the inter-probe delay (0ms, 1000ms, 5000ms, 15000ms) and for each delay value re-probe all baseline-filtered ports, classifying a port as accessible if a TCP connection completes (SYN-ACK received) within the configured probe timeout
5. WHEN testing TCP window size manipulation, THE Evasion_Profiler SHALL attempt connections using socket send buffer sizes of 1024, 4096, 16384, and 65535 bytes and compare filtered-port accessibility against the baseline
6. WHEN testing connection pattern variation, THE Evasion_Profiler SHALL alternate between sequential port ordering and randomized port ordering across the filtered port set to detect pattern-based filtering
7. WHEN a technique results in a previously-filtered port responding with a successful TCP connection (SYN-ACK) on at least 2 out of 3 attempts, THE Evasion_Profiler SHALL classify that technique as successful and record the evidence including: the technique name, the target port number, the source port used (if applicable), the delay value (if applicable), and the number of successful connections out of attempts
8. THE Evasion_Profiler SHALL produce a summary indicating each technique tested, its classification (successful, failed, or skipped), the count of ports that became accessible per technique, and the list of specific ports that changed state from filtered to accessible
9. WHEN testing TCP flag manipulation, THE Evasion_Profiler SHALL attempt FIN, NULL (no flags), and Xmas (FIN+PSH+URG) style probes using raw sockets where platform permissions allow
10. IF raw socket access is denied by the operating system, THEN THE Evasion_Profiler SHALL fall back to connect-scan-based evasion techniques only and report that advanced flag manipulation requires elevated privileges

### Requirement 4: Native AV Test Payload Generation

**User Story:** As a penetration tester, I want to generate AV evasion test payloads natively in Python, so that I do not need msfvenom or external payload generators.

#### Acceptance Criteria

1. WHEN payload generation is requested, THE Payload_Generator SHALL produce executable shellcode bytes using pure Python (struct packing, XOR encoding, and polymorphic wrapper generation) and return output within 10 seconds
2. WHEN a payload format is specified (exe, dll, raw, powershell), THE Payload_Generator SHALL output the payload in the requested format as a byte sequence or string that conforms to the format's structure (PE header for exe/dll, raw bytes for raw, valid PowerShell script syntax for powershell)
3. THE Payload_Generator SHALL support at minimum the following payload types: reverse TCP shell, bind TCP shell, and command execution
4. WHEN generating a payload, THE Payload_Generator SHALL apply configurable encoding (XOR with a random key of 1 to 32 bytes, base64, custom byte substitution) to evade signature-based AV detection
5. WHEN a payload is generated, THE Payload_Generator SHALL calculate and display the detection likelihood score as an integer from 0 (least likely detected) to 100 (most likely detected), derived from the number of encoding layers applied and the percentage of payload bytes matching known static AV signature byte sequences
6. THE Payload_Generator SHALL provide a staged payload option that outputs two separate components: a loader (stager) containing only connection and download logic, and a main payload containing the execution logic, such that neither component alone contains the full shellcode
7. IF the target architecture is specified (x86, x64), THEN THE Payload_Generator SHALL generate architecture-appropriate shellcode using the corresponding instruction set and register widths
8. THE Payload_Generator SHALL never require network access or external binary execution to produce payloads
9. IF no target architecture is specified, THEN THE Payload_Generator SHALL default to x64 shellcode generation
10. IF an unsupported payload format or payload type is requested, THEN THE Payload_Generator SHALL reject the request and display an error message indicating the supported formats (exe, dll, raw, powershell) and supported types (reverse TCP shell, bind TCP shell, command execution)

### Requirement 5: Integration with Existing Port Scanner Infrastructure

**User Story:** As a developer, I want the new native detection modules to reuse the existing Port_Scanner patterns, so that the codebase remains consistent and maintainable.

#### Acceptance Criteria

1. THE Firewall_Detector SHALL implement the QRunnable interface with a signals object containing pyqtSignal declarations for: output(str), status(str), finished(), results_ready(dict), progress_start(int), and progress_update(int, int)
2. THE Evasion_Profiler SHALL implement the QRunnable interface with a signals object containing pyqtSignal declarations for: output(str), status(str), finished(), results_ready(dict), progress_start(int), and progress_update(int, int)
3. THE Payload_Generator SHALL implement the QRunnable interface with a signals object containing pyqtSignal declarations for: output(str), status(str), finished(), results_ready(dict), progress_start(int), and progress_update(int, int)
4. WHEN the Firewall_Detector requires port scanning, THE Firewall_Detector SHALL invoke the scan_port method from Port_Scanner (socket.AF_INET, socket.SOCK_STREAM, connect_ex pattern) rather than reimplementing socket connection logic
5. THE Firewall_Detector SHALL accept a target parameter as a single IP address string or hostname string, matching the Port_Scanner target parameter format
6. IF the Firewall_Detector receives an empty string or None as the target parameter, THEN THE Firewall_Detector SHALL emit an output signal containing an error message indicating the target is invalid, followed by emitting the finished signal without performing any scan operations
7. WHEN results are emitted, THE Firewall_Detector SHALL format the output signal strings as HTML paragraph elements with inline style color attributes, using the existing color scheme: #00FF41 for success, #FF6B6B for errors, #00BFFF for informational, and #FFAA00 for warnings
8. THE Firewall_Detector, Evasion_Profiler, and Payload_Generator SHALL each expose an is_running boolean flag that, when set to False, causes the worker to cease processing within the current iteration and emit the finished signal
9. WHEN parallel operations are performed within a worker, THE worker SHALL use concurrent.futures.ThreadPoolExecutor with a max_workers value no greater than 50

### Requirement 6: IDS/IPS Behavioral Detection

**User Story:** As a penetration tester, I want to detect Intrusion Detection and Prevention Systems through behavioral analysis, so that I can identify when my traffic is being inspected beyond simple port filtering.

#### Acceptance Criteria

1. WHEN IDS/IPS detection is initiated, THE Firewall_Detector SHALL send a minimum of 3 benign HTTP requests to each open port to establish a response baseline, followed by requests containing at least 3 attack signature categories (SQL injection patterns, XSS payloads, and path traversal sequences)
2. WHEN a port that responded successfully to all baseline requests returns connection resets or timeouts on 2 or more consecutive attack-signature requests, THE Firewall_Detector SHALL infer IDS/IPS presence and record the triggering signature category
3. WHEN average response time for attack-pattern requests exceeds 200% of the established baseline average response time for the same port, THE Firewall_Detector SHALL flag potential inline IPS inspection
4. WHEN rate-limiting detection is initiated, THE Firewall_Detector SHALL send connections at increasing rates (1, 5, 10, 20, 50 connections per second) and detect rate-limiting when a previously accessible port begins rejecting or dropping connections at a specific rate threshold
5. WHEN IDS/IPS is detected, THE Firewall_Detector SHALL report the detection method, a confidence level on a scale of low (single indicator), medium (2 indicators), or high (3 or more indicators), and the observed behavioral indicators including affected ports and triggering signatures
6. IF no open ports are found on the target during the initial baseline phase, THEN THE Firewall_Detector SHALL abort IDS/IPS detection and report that detection requires at least one accessible port

### Requirement 7: Scan Configuration and Cancellation

**User Story:** As a user, I want to configure scan parameters and cancel running scans, so that I can control resource usage and tailor detection to my engagement scope.

#### Acceptance Criteria

1. THE AV_FW_Scanner SHALL accept configurable parameters: target IP/hostname, port list (or preset), timeout per probe in the range of 1 to 30 seconds (default 3 seconds), maximum concurrent threads in the range of 1 to 200 (default 50), and scan type selection from WAF Detection, Firewall Detection, Evasion Testing, AV Payload Generation, and IDS/IPS Detection
2. WHEN a user requests scan cancellation, THE AV_FW_Scanner SHALL stop all active probe threads within 2 seconds by setting the is_running flag to False
3. WHEN a scan is cancelled, THE AV_FW_Scanner SHALL emit partial results containing all findings collected up to the cancellation point in the same format as a completed scan result
4. THE AV_FW_Scanner SHALL provide preset port lists: top-20, top-100, top-1000, and custom list accepting comma-separated port numbers or hyphenated ranges (e.g., "80,443,8000-8100") with a maximum of 10000 ports per scan
5. WHILE a scan is running, THE AV_FW_Scanner SHALL emit progress updates at least every 10 completed probes indicating the percentage of probes completed and current findings count
6. IF the user provides an invalid target (unresolvable hostname or malformed IP), a port number outside 1-65535, or a timeout/thread value outside its valid range, THEN THE AV_FW_Scanner SHALL reject the scan request and display an error message indicating which parameter is invalid

### Requirement 8: Result Reporting and Export

**User Story:** As a penetration tester, I want structured scan results with export capability, so that I can document findings and feed them into subsequent attack phases.

#### Acceptance Criteria

1. WHEN a scan completes, THE AV_FW_Scanner SHALL produce a structured results dictionary containing the following keys: target (string), scan_type (string matching the detection_type used), detected_security_products (list of detection entries each with type and name), filtered_ports (list of port number strings), successful_evasion_techniques (list of technique name strings), and confidence_scores (integer values from 0 to 100 representing detection certainty percentage for each finding)
2. THE AV_FW_Scanner SHALL format results as HTML using inline color styles (success: #00FF41, error: #FF6B6B, info: #00BFFF, warning: #FFAA00) for display in the Huginn UI output panel
3. WHEN results include firewall detection with at least one filtered port, THE AV_FW_Scanner SHALL include a recommended_next_steps list containing: evasion techniques not yet attempted against the target, and filtered port numbers to prioritize for exploitation
4. THE AV_FW_Scanner SHALL emit results via the results signal as a Python dictionary containing at minimum the keys target, scan_type, detections, and error (set to None on success or an error description string on failure)
5. IF the scan fails due to a connection error or timeout, THEN THE AV_FW_Scanner SHALL emit a results dictionary with the error key set to a string describing the failure reason, the detections key set to an empty list, and SHALL display an error-styled HTML message in the output panel
6. WHEN a scan completes with no security products detected and no filtered ports found, THE AV_FW_Scanner SHALL emit a results dictionary with detected_security_products as an empty list, filtered_ports as an empty list, and successful_evasion_techniques as an empty list
