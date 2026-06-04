# VIDEO 25: Scan Configuration
### Target Setup, Scope Definition & Custom Profiles
**Suggested length:** 14–18 minutes
**License Tier:** Free
**Certification Relevance:** OSCP: Vulnerability Scanning | CEH: Scanning Networks

---

## INTRO (0:00 – 1:30)

**[Screen: Huginn splash screen with Section 4 title card "Vulnerability Scanning"]**

> "In the last video we ran all four scan profiles and saw the difference in findings, speed, and detection risk (see Video 24: Scanner Overview & Profiles). Now we need to configure those scans properly — because a perfectly tuned scanner aimed at the wrong target or missing scope boundaries is worse than useless. It's dangerous."

**[Screen: Slide showing the three configuration pillars — Target Definition, Scope Boundaries, Scan Parameters]**

> "Scan configuration has three pillars. Target definition — telling the scanner what to scan. Scope boundaries — telling it what NOT to scan. And scan parameters — timing, port ranges, credentials, and output formats. Today we'll configure a scan against the TryHackMe Vulnversity machine, covering every configuration option Huginn offers. By the end, you'll be able to set up a scan for any engagement scenario."

---

## SECTION 1: Target Input Methods (1:30 – 3:30)

**[Screen: Huginn Scanner page — target input field highlighted, showing placeholder text "Enter target IP, hostname, or CIDR range"]**

> "The target field in Huginn accepts four input formats. Single IP addresses like 10.10.10.245. Hostnames that resolve to IPs. CIDR notation for network ranges like 10.10.10.0/24. And comma-separated lists combining any of these. The scanner resolves hostnames automatically and expands CIDR ranges into individual host addresses."

**[Screen: Entering the THM Vulnversity target IP — showing DNS resolution indicator]**

> "For our demo, we're targeting the TryHackMe Vulnversity machine. Enter the machine's IP address — THM assigns a dynamic IP when you deploy the room, so yours will differ from mine. The key point is that you enter exactly what's in scope for your engagement — nothing more."

```bash
# Target input examples:
Single IP:       10.10.245.120
Hostname:        vulnversity.thm
CIDR Range:      10.10.245.0/24
Multiple:        10.10.245.120, 10.10.245.121, webapp.thm
```

**[Screen: Demonstrating CIDR expansion — entering 10.10.245.0/24 and showing the scanner calculating 254 hosts]**

> "Be careful with CIDR ranges. A /24 expands to 254 hosts. Running even a Light scan against 254 hosts takes considerably longer than scanning one. If you enter a /16, that's over 65,000 hosts — probably not what you intended. In CTF and exam scenarios, you'll typically scan individual IPs. In real engagements, you might scan a /24 subnet but rarely larger without breaking it into phases."

---

## SECTION 2: Scope Manager (3:30 – 6:00)

**[Screen: Navigating to the Scope Manager panel — showing In-Scope and Out-of-Scope text areas]**

> "The Scope Manager is your safety net. It defines what the scanner is allowed to touch and explicitly blocks everything else. This maps directly to your engagement's rules of engagement document. In Huginn, navigate to the scope configuration — you'll see two panels: In-Scope and Out-of-Scope."

**[Screen: Entering in-scope targets — typing "10.10.245.120" in the In-Scope field]**

> "Add your target IP to the In-Scope field. The scope manager accepts the same formats as the target field — IPs, hostnames, CIDR ranges. Once defined, any scan request that tries to reach a target outside this scope gets blocked with a clear warning. This prevents accidental scanning of production systems, shared hosting neighbors, or out-of-scope infrastructure."

```bash
# Scope configuration for Vulnversity engagement:
In-Scope:
  10.10.245.120

Out-of-Scope:
  10.10.245.1          # Gateway
  10.10.0.0/16         # THM infrastructure (except our target)
```

**[Screen: Demonstrating scope validation — entering an out-of-scope IP and showing the rejection message "Target not in defined scope"]**

> "Watch what happens if I try to scan 10.10.245.1 — the gateway. The scope manager blocks it immediately: 'Target 10.10.245.1 is not in defined scope.' This is critical in real engagements where scanning the wrong IP could violate your contract or even break laws. The scope manager supports wildcard domains too — adding *.example.com covers all subdomains."

**[Screen: Scope summary view showing the active scope configuration with validation status]**

> "The scope summary shows your active configuration at a glance. Huginn also validates scope on every individual request during a scan — not just at the start. If the scanner discovers a redirect to an out-of-scope domain, it stops following that redirect and logs the attempt. This prevents scope creep during automated scanning."

---

## SECTION 3: Port Range Configuration (6:00 – 8:00)

**[Screen: Port range configuration panel — showing presets dropdown (Top 100, Top 1000, Full Range, Custom)]**

> "Port range determines which ports the scanner checks for web services and vulnerable endpoints. The presets cover common scenarios — Top 100 for quick checks, Top 1000 for standard scanning, Full Range for comprehensive coverage. But custom ranges are where the real value is."

**[Screen: Entering custom port range "80,3333,8080,8443,8888" — showing validation checkmark]**

> "For Vulnversity, we already know from our reconnaissance (see Video 6: Port Scanning) that the web server runs on port 3333, not the standard port 80. Enter a custom range: 80, 3333, 8080, 8443, 8888. This focuses the scanner on known web ports plus the non-standard port we discovered. Don't waste scan time probing ports you already know are closed."

```bash
# Port range configuration:
Preset: Custom
Ports: 80, 3333, 8080, 8443, 8888

# Why these ports:
# 80    - Standard HTTP (verify if active)
# 3333  - Vulnversity web server (confirmed open)
# 8080  - Common alternative HTTP
# 8443  - Common alternative HTTPS
# 8888  - Development server port
```

**[Screen: Showing the port range impact on scan time — comparison between "All ports" (65535) vs custom (5 ports)]**

> "The difference in scan time is dramatic. Scanning all 65,535 ports for web services would take the scanner through tens of thousands of connection attempts. Our custom range of 5 ports focuses the scanner precisely where we know services exist. In practice, always run port scanning first (see Video 6: Port Scanning) and feed those results into your vulnerability scan configuration."

---

## SECTION 4: Timing and Rate Limiting (8:00 – 10:00)

**[Screen: Timing configuration panel — showing requests per second slider, concurrent threads slider, and delay settings]**

> "Timing controls how fast the scanner sends requests. There are three parameters: requests per second, concurrent threads, and delay between requests. These interact with the scan profile — the profile sets defaults, but you can override them here for specific situations."

**[Screen: Rate limiter configuration — showing 10 req/s default, adjusting to 5 req/s for a more conservative scan]**

> "The rate limiter caps overall request volume. The default is 10 requests per second with 50 concurrent threads. For the OSCP exam or CTF environments where targets are shared infrastructure, dial this back — 5 requests per second prevents overwhelming the target and avoids connection throttling that could make your scan results unreliable."

```bash
# Timing configuration for Vulnversity:
Requests per Second: 10
Concurrent Threads: 50
Delay Between Requests: 0.1s
Burst Limit: 20

# Conservative (shared environments):
Requests per Second: 5
Concurrent Threads: 25
Delay Between Requests: 0.2s
```

**[Screen: Showing the stealth engine integration — rate limiter updating from stealth mode settings]**

> "If you've configured Stealth Mode (covered later in Video 41: Stealth Mode), the rate limiter automatically adjusts based on your evasion level. Paranoid mode drops to 1 request every 5 seconds. Sneaky mode runs at 1 request per 15 seconds. The scanner respects these limits regardless of what profile you select — stealth settings always take priority over scan profile speed settings."

**[Screen: Thread count recommendation — showing the formula "recommended threads = min(configured, rate × 2)"]**

> "Huginn calculates a recommended thread count based on your rate limit. If you set 5 requests per second, it recommends no more than 10 threads — any more would queue up waiting for rate limit slots. This prevents thread starvation and ensures consistent scan pacing."

---

## SECTION 5: Credential-Based Scanning (10:00 – 12:00)

**[Screen: Credentials panel — showing fields for username, password, authentication type dropdown (Basic, Form, Bearer Token)]**

> "Unauthenticated scanning only sees what anonymous users see. Authenticated scanning — also called credentialed scanning — logs into the application and tests everything behind the login wall. For a thorough assessment, you need both. The credentials panel supports Basic HTTP auth, form-based login, and Bearer token authentication."

**[Screen: Configuring form-based auth — entering login URL, username field, password field, and credentials]**

> "For Vulnversity, configure form-based authentication if the application has a login page. Enter the login URL, the form field names for username and password, and the credentials. Huginn will authenticate before scanning and maintain the session throughout. This reveals vulnerabilities in authenticated functionality that anonymous scans can't reach."

```bash
# Credential configuration:
Auth Type: Form-Based
Login URL: http://10.10.245.120:3333/login
Username Field: username
Password Field: password
Credentials: admin / admin

# Session handling:
Session Maintenance: Enabled
Re-auth on expiry: Enabled
Cookie Storage: Automatic
```

**[Screen: Demonstrating the difference — authenticated scan finding additional endpoints not visible to anonymous users]**

> "The practical impact is significant. An unauthenticated scan of a typical web application might discover 20 endpoints. An authenticated scan of the same application might find 80 — admin panels, user settings, file upload forms, API endpoints. Many critical vulnerabilities live behind authentication. If your engagement scope includes credentialed testing, always configure this."

---

## SECTION 6: Live Configuration Demo (12:00 – 14:30)

**[Screen: Complete configuration form filled out for Vulnversity — reviewing all settings before starting]**

> "Let's put it all together. Here's our complete configuration for Vulnversity — target IP entered, scope defined, custom port range set to include port 3333, timing at 10 requests per second with 50 threads, and the Normal scan profile selected. Review the configuration summary at the bottom."

```bash
# Complete scan configuration:
Target: 10.10.245.120
Profile: Normal
Scope: 10.10.245.120 (in-scope), 10.10.245.1 (out-of-scope)
Ports: 80, 3333, 8080, 8443, 8888
Timing: 10 req/s, 50 threads, 0.1s delay
Auth: None (unauthenticated first pass)
Output: JSON + HTML report
```

**[Screen: Clicking Start Scan — showing the scan registering in the Scan Registry with a unique ID]**

> "Click Start Scan. Watch the scan register in the Running Scans panel — it gets a unique ID, shows the type, target, and real-time progress. The scan controller manages the execution state, and you can pause, resume, or stop at any time without losing results collected so far."

**[Screen: Running Scans panel — showing the scan in progress with progress bar, elapsed time, and findings counter]**

> "The scan is running. Progress shows how many endpoints have been tested. The findings counter increments as vulnerabilities are discovered. Elapsed time helps you gauge whether your timing configuration is appropriate — if the scan is running much longer than the profile's estimated time, your rate limiting might be too conservative."

**[Screen: Scan completing — results summary appearing with finding count and severity breakdown]**

> "Scan complete. Let's look at what we found on Vulnversity. The results show findings organized by severity — any Critical or High findings deserve immediate attention. Medium findings are worth investigating. Low and Informational provide context for your report. We'll dive deep into interpreting these results in the next video (see Video 26: Results Interpretation)."

---

## SECTION 7: Scan Management, Output, and Certification Tips (14:30 – 16:30)

**[Screen: Scan Registry view — showing multiple completed and running scans with status indicators]**

> "The Scan Registry tracks every scan you've run in this session. You can have multiple scans running simultaneously — useful when scanning different targets in parallel or running different profiles against the same target for comparison. Each scan has independent pause, resume, and stop controls."

**[Screen: Demonstrating pause and resume — clicking Pause, scan freezing, then Resume to continue]**

> "Pause is particularly useful when you notice the target becoming unresponsive or when you need to adjust scope mid-scan. Pausing freezes all outgoing requests immediately. Resume picks up exactly where it left off — no repeated work, no lost progress. Stop terminates the scan permanently but preserves all findings collected up to that point."

**[Screen: Export options — showing JSON, CSV, HTML, and XML output format selectors]**

> "Export your results in the format your workflow needs. JSON for programmatic processing and integration with other tools. CSV for spreadsheet analysis. HTML for readable reports with formatting. XML for tool interoperability. All formats include the full configuration metadata — target, profile, timing, scope — so results are fully reproducible."

```bash
# Output formats:
JSON  → Programmatic processing, tool integration
CSV   → Spreadsheet analysis, data comparison
HTML  → Readable reports, client deliverables
XML   → Tool interoperability, OWASP standards
```

**[Screen: Showing scan comparison feature — selecting two scans and viewing differences]**

> "One powerful feature — scan comparison. Run the same target with different profiles or at different times, then compare results side by side. This shows which vulnerabilities persist across scans, which were one-time findings, and how the target's security posture changes over time. We'll explore this further in Video 26."

**[Screen: Slide showing OSCP exam tip — "Scan smart, not hard: reconnaissance first, targeted scanning second"]**

> "For OSCP specifically — you have limited time and each machine matters. Don't start with a Full Range Insane scan. Run port scanning first, identify web services, then configure a targeted Normal scan against discovered ports only. This focused approach saves time and produces actionable results faster than a broad sweep."

**[Screen: Practice resource list — THM "Vulnversity", THM "Basic Pentesting", HTB "Nibbles", HTB "Bashed"]**

> "Practice scan configuration on these machines. TryHackMe Vulnversity — our demo target today — has a non-standard web port that tests your ability to configure custom port ranges. THM Basic Pentesting has multiple services requiring scope definition. HTB Nibbles and Bashed both have web services that respond well to Normal profile scanning. Each one exercises different configuration skills."

---

## OUTRO (16:30 – end)

**[Screen: Summary slide — Scan Configuration: Targets (IP/CIDR/hostname), Scope (in/out boundaries), Timing (rate/threads/delay), Credentials (auth scanning), Output (JSON/CSV/HTML/XML) | Next: Video 26 — Results Interpretation]**

> "That covers scan configuration — target input methods, scope boundaries to keep you safe, port range optimization, timing and rate limiting, and credential-based scanning for authenticated coverage. The theme is precision — configure your scanner to hit exactly what's in scope, at the right speed, with the right depth. In the next video, we'll interpret scan results — reviewing evidence, triaging false positives, assessing severity, and exporting findings for your engagement report. See you in Video 26."

