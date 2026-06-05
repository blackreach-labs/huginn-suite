# AV/Firewall Detection Tool

The AV/FW tool is located under **Recon & Enumeration → Service Enumeration → 🛡️ AV/FW**. It provides five detection modes for identifying and profiling network security devices without requiring external tools like nmap or msfvenom — everything runs natively in Python.

## Detection Types

### WAF Detection

Identifies Web Application Firewalls by analyzing HTTP response headers and behaviors.

- **Input**: Target host + port (default 80)
- **Method**: Sends crafted HTTP requests with known WAF-triggering payloads and analyzes response headers, status codes, and body content for WAF signatures
- **Output**: WAF product name, confidence score, and indicator list
- **Use case**: Determine if a web target is behind Cloudflare, AWS WAF, ModSecurity, etc.

### Firewall Detection

Detects network firewalls by analyzing TCP port response patterns.

- **Input**: Target host (port field hidden — scans top 20 ports automatically)
- **Method**:
  1. **Port probing** — Classifies 20 common ports as OPEN, CLOSED, or FILTERED using `socket.connect_ex()`
  2. **Timing analysis** — Analyzes response time patterns to fingerprint the device type
  3. **ACK probe** — Tests 10 random ephemeral ports (49152–65535) to differentiate stateful firewalls from packet filters
- **Classification**:
  - `filtered_ratio > 50%` → Firewall DETECTED
  - `20% < filtered_ratio ≤ 50%` → Firewall LIKELY
  - `filtered_ratio ≤ 20%` → Not detected
- **Firewall type**:
  - Ephemeral ports also filtered → **Stateful** (inspects all traffic)
  - Ephemeral ports closed (RST) → **Packet-filter** (blocks specific ports only)
- **Output**: Firewall status, type, confidence %, open/closed/filtered port breakdown

### Evasion Test

Tests bypass techniques against filtered ports to identify which evasion methods succeed.

- **Input**: Target host (port field hidden — uses top 20 ports for baseline)
- **Method**:
  1. **Baseline** — Establishes which ports are filtered
  2. **Source port evasion** — Binds to commonly-allowed ports (53, 80, 443, 88) to see if the firewall allows traffic from "trusted" source ports
  3. **Timing evasion** — Varies connection delays (0ms, 1s, 5s, 15s) to bypass rate-based rules
  4. **Window size evasion** — Manipulates TCP SO_SNDBUF (1024–65535) to fingerprint filtering behavior
  5. **Pattern evasion** — Randomizes connection order vs sequential scanning
  6. **Flag manipulation** — Sends FIN/NULL/Xmas TCP flags via raw sockets
- **Performance**: Tests top 5 filtered ports per technique with a 1-second timeout to keep scans under a few minutes
- **Output**: Per-technique pass/fail classification, ports that became accessible, evidence details

### AV Payload Gen

Generates test payloads for AV evasion testing — entirely in Python with no external tools.

- **Input**: Target IP (used as LHOST for reverse shells) + port (used as LPORT)
- **Method**:
  1. **Generate shellcode** — Builds architecture-specific (x86/x64) shellcode via `struct.pack()` templates
  2. **Encode** — Applies XOR encoding with random key + decode stub
  3. **Format** — Wraps as raw bytes, PE EXE, PE DLL, or PowerShell cradle
- **Payload types**: `reverse_tcp`, `bind_tcp`, `cmd_exec`
- **Encoding options**: XOR, base64, substitution cipher
- **Output formats**: raw, exe, dll, powershell
- **Detection score**: Estimates AV detection likelihood (0–100) based on entropy, known signatures, and encoding layers
- **Output**: Payload bytes, size, detection score, optional stager for staged delivery

### Full Detection

Runs the Firewall Detection scan. (Reserved for future expansion to chain multiple detection types sequentially.)

## UI Features

- **Independent results per detection type** — Each detection type has its own terminal output and table view. Switching between detection types preserves results.
- **Real-time progress bar** — Updates per-probe during firewall and evasion scans.
- **Text / Table views** — Toggle between terminal output and structured grid view for findings.
- **Clear Output (Ctrl-L)** — Clears the terminal for the currently selected detection type only.
- **Export** — Export results as JSON, CSV, XML, or HTML.

## Architecture

```
UI (service_scanners.py)
  └─ AVFirewallWorker (av_worker.py) — dispatcher
       ├─ WAF Detection      → av_firewall_scanner.detect_waf()
       ├─ Firewall Detection  → FirewallDetectorWorker (firewall_detector.py)
       ├─ Evasion Test        → EvasionProfilerWorker (evasion_profiler.py)
       ├─ AV Payload Gen      → PayloadGeneratorWorker (payload_generator.py)
       └─ IDS/IPS Detection   → IDSIPSDetectorWorker (ids_ips_detector.py)
```

All workers are `QRunnable` instances executed on `QThreadPool`. They communicate via Qt signals (`output`, `finished`, `results`, `progress_start`, `progress_update`, `error`) for thread-safe UI updates.

## No External Dependencies

The tool requires no external binaries. All scanning uses:
- `socket.connect_ex()` for TCP probing
- `socket.SOCK_RAW` for flag manipulation (requires admin on Windows)
- `struct.pack()` for shellcode/PE generation
- HTTP request/response analysis for WAF detection
