# VIDEO 24: Scanner Overview & Profiles
### Light, Normal, Aggressive & Insane Scan Modes
**Suggested length:** 14–18 minutes
**License Tier:** Free (Light, Normal, Aggressive); Enterprise (Insane + AI features)
**Certification Relevance:** OSCP: Vulnerability Scanning | CEH: Scanning Networks

---

## INTRO (0:00 – 1:30)

**[Screen: Huginn splash screen with Section 4 title card "Vulnerability Scanning"]**

> "Welcome to Section 4 — Vulnerability Scanning. This is where we shift from reconnaissance and enumeration into actively probing targets for weaknesses. In the previous sections we gathered information about what services are running and what technologies are in play (see Video 6: Port Scanning). Now we use that information to find exploitable vulnerabilities."

**[Screen: Slide showing the four scan profile icons — 🟢 Light, 🟡 Normal, 🟠 Aggressive, 🔴 Insane — arranged left to right with a gradient from green to red]**

> "Huginn's built-in vulnerability scanner has four distinct profiles — Light, Normal, Aggressive, and Insane. Each profile represents a different balance between speed, thoroughness, and detection risk. Today we'll run all four against DVWA on localhost at security level Low, so you can see exactly how they differ in what they find, how long they take, and how much noise they generate. By the end of this video, you'll know which profile to reach for in any engagement scenario."

---

## SECTION 1: Huginn Scanner Architecture (1:30 – 3:30)

**[Screen: Architecture diagram showing scanner_engine.py → adaptive_scanner.py → scan_controller.py with arrows indicating data flow]**

> "Before we run scans, let's understand what's happening under the hood. Huginn's scanner has three core layers. The Scanner Engine handles vulnerability detection — passive checks against responses, and active probing with payloads for injection flaws. The Adaptive Scanner learns from responses in real time, generating follow-up payloads based on what works. And the Scan Controller manages execution state — starting, pausing, resuming, and stopping scans with thread-safe coordination."

**[Screen: Code snippet showing PassiveScanner class checking security headers, error patterns, and sensitive data]**

> "The passive scanner fires on every HTTP response. It checks for missing security headers like Content-Security-Policy and HSTS, detects error messages that leak information — SQL errors, stack traces, PHP warnings — and flags sensitive data exposure like email addresses or card numbers. This runs regardless of which profile you choose."

**[Screen: Code snippet showing ActiveScanner class with payload categories — XSS, SQLi, LFI, Command Injection]**

> "The active scanner goes further — it injects payloads into parameters and analyzes responses for vulnerability indicators. XSS payloads look for reflection in the response body. SQL injection payloads trigger database errors. LFI payloads check for file content like /etc/passwd. The profile you select determines how many payloads get sent and how aggressively the scanner probes."

---

## SECTION 2: Understanding Scan Profiles (3:30 – 6:00)

**[Screen: Four-column comparison table — Light | Normal | Aggressive | Insane — with rows for Concurrent Requests, Timeout, Time Estimate, Detection Risk]**

> "Here's the profile comparison at a glance. Light runs 20 concurrent requests with 5-second timeouts — it's fast, finishing in 5 to 10 minutes, with minimal detection risk. Normal bumps to 50 concurrent requests and 10-second timeouts, taking 15 to 30 minutes with low detection risk. Aggressive uses 100 threads with 15-second timeouts, running 30 to 60 minutes with moderate detection risk. Insane maxes out at 200 concurrent requests and 20-second timeouts — 1 to 2 hours of thorough scanning that will almost certainly trigger security monitoring."

```
Profile Comparison:
┌──────────────┬─────────┬──────────┬──────────────┬─────────────────┐
│ Profile      │ Threads │ Timeout  │ Est. Time    │ Detection Risk  │
├──────────────┼─────────┼──────────┼──────────────┼─────────────────┤
│ 🟢 Light     │ 20      │ 5s       │ 5-10 min     │ Minimal         │
│ 🟡 Normal    │ 50      │ 10s      │ 15-30 min    │ Low             │
│ 🟠 Aggressive│ 100     │ 15s      │ 30-60 min    │ Moderate        │
│ 🔴 Insane    │ 200     │ 20s      │ 1-2 hours    │ High            │
└──────────────┴─────────┴──────────┴──────────────┴─────────────────┘
```

**[Screen: Feature breakdown — showing which checks each profile enables, expanding from Light (basic) to Insane (all AI features)]**

> "The profiles don't just differ in speed — they differ in depth. Light covers basic SQL injection, simple XSS, directory enumeration, authentication bypass, and security header analysis. Normal adds comprehensive vulnerability testing, business logic analysis, session management checks, OSINT gathering, and basic AI pattern recognition. Aggressive enables WAF evasion testing, binary response analysis, neural network analysis, and ML-based payload generation. Insane unlocks everything — quantum-inspired fuzzing, the autonomous security agent, zero-day discovery, and advanced exploitation framework features."

**[Screen: Slide showing trade-off triangle — Speed ↔ Thoroughness ↔ Stealth]**

> "Think of it as a triangle of trade-offs. Light maximizes speed and stealth at the cost of thoroughness — you might miss vulnerabilities. Insane maximizes thoroughness at the cost of speed and stealth — you'll find everything but take hours and trigger every alert in the SOC. Normal and Aggressive sit in between. Most real engagements start with Normal and escalate to Aggressive only on high-value targets where you need deeper coverage."

---

## SECTION 3: Demo Environment Setup (6:00 – 7:30)

**[Screen: DVWA login page at http://localhost/dvwa/login.php — entering admin/password credentials]**

> "Our target today is DVWA — the Damn Vulnerable Web Application — running locally on localhost. I've set the security level to Low, which disables most input filtering. This gives us a clean baseline to compare what each profile finds without filter bypasses complicating the picture."

**[Screen: DVWA Security page — showing security level set to "Low"]**

> "Confirm the security level by navigating to DVWA Security and checking the dropdown shows Low. This is important for reproducibility — the same profile will find different things at different security levels because the application's defenses change."

**[Screen: Navigating Huginn — clicking through to the Huginn Scanner page]**

> "In Huginn, navigate to the Huginn Scanner page. You'll see the profile selector on the left panel listing all four profiles with their color-coded icons. The scan target field is at the top, and the results panel fills the right side. Let's enter our target."

```bash
Target: http://localhost/dvwa/
Security Level: Low
Platform: DVWA (self-hosted)
Expected Services: HTTP (80), MySQL (3306), Apache/PHP
```

---

## SECTION 4: Light Profile Demo (7:30 – 10:00)

**[Screen: Selecting the 🟢 Light profile — profile details panel showing "Basic vulnerability checks with minimal resource usage"]**

> "Start with Light. Select the Light profile and you'll see the configuration summary — 20 concurrent requests, 5-second timeout, minimal detection risk. This is your quick reconnaissance scan. Click Start Scan."

**[Screen: Scan running — progress bar moving quickly, terminal output showing basic checks being performed]**

> "Watch how fast this moves. Light skips deep injection testing and focuses on low-hanging fruit — missing headers, obvious error disclosures, basic parameter testing. It's checking the most common vulnerability patterns without burning time on edge cases."

```bash
[SCAN] Light profile scan started against http://localhost/dvwa/
[SCAN] Concurrent threads: 20 | Timeout: 5s
[SCAN] Passive analysis: security headers, error patterns
[SCAN] Active testing: basic SQLi, simple XSS, directory enum

[FINDING] Missing Security Header: Content-Security-Policy (Medium)
[FINDING] Missing Security Header: X-Frame-Options (Medium)
[FINDING] Missing Security Header: Strict-Transport-Security (Medium)
[FINDING] Missing Security Header: X-Content-Type-Options (Medium)
[FINDING] SQL Injection: /dvwa/vulnerabilities/sqli/?id=1' (High)
[FINDING] XSS Reflected: /dvwa/vulnerabilities/xss_r/?name=<script> (High)
[FINDING] Directory Listing: /dvwa/docs/ (Low)

[SCAN] Light scan complete: 7 findings (2 High, 4 Medium, 1 Low)
[SCAN] Duration: 6 minutes 42 seconds
```

**[Screen: Results panel showing 7 findings — highlighting the 2 High severity items (SQLi and XSS)]**

> "Six minutes and 42 seconds. Seven findings — two High severity for SQL injection and reflected XSS, four Medium for missing security headers, and one Low for directory listing. Light found the obvious vulnerabilities quickly, but notice what's missing — it didn't test stored XSS, didn't find command injection, didn't explore authentication bypass paths, and didn't check for LFI. Those require deeper probing."

---

## SECTION 5: Normal Profile Demo (10:00 – 12:30)

**[Screen: Selecting the 🟡 Normal profile — details panel showing "Balanced comprehensive scan with moderate resource usage"]**

> "Now let's run Normal. This is the profile you'll use most often — it provides comprehensive coverage without being excessive. Select Normal, same target, and start the scan."

**[Screen: Scan running — progress bar moving at moderate pace, showing more categories of tests being executed]**

> "Immediately you can see more activity. Normal tests advanced injection techniques, probes session management, checks business logic flows, and runs basic AI pattern recognition against responses. It's sending more payloads per parameter and testing more endpoints."

```bash
[SCAN] Normal profile scan started against http://localhost/dvwa/
[SCAN] Concurrent threads: 50 | Timeout: 10s
[SCAN] AI: Basic pattern recognition enabled
[SCAN] Testing: comprehensive vuln, injection, session, business logic

[FINDING] Missing Security Header: Content-Security-Policy (Medium)
[FINDING] Missing Security Header: X-Frame-Options (Medium)
[FINDING] Missing Security Header: Strict-Transport-Security (Medium)
[FINDING] Missing Security Header: X-Content-Type-Options (Medium)
[FINDING] SQL Injection: /dvwa/vulnerabilities/sqli/?id=1' (High)
[FINDING] SQL Injection (Blind): /dvwa/vulnerabilities/sqli_blind/?id=1 (High)
[FINDING] XSS Reflected: /dvwa/vulnerabilities/xss_r/?name=<script> (High)
[FINDING] XSS Stored: /dvwa/vulnerabilities/xss_s/ (High)
[FINDING] Command Injection: /dvwa/vulnerabilities/exec/?ip=;id (High)
[FINDING] File Inclusion (LFI): /dvwa/vulnerabilities/fi/?page=../../ (High)
[FINDING] CSRF Weakness: /dvwa/vulnerabilities/csrf/ (Medium)
[FINDING] Weak Authentication: Brute-force susceptible login (Medium)
[FINDING] Directory Listing: /dvwa/docs/ (Low)
[FINDING] Session Management: No session timeout configured (Low)
[AI] Pattern detected: Multiple injection points suggest poor input validation

[SCAN] Normal scan complete: 14 findings (6 High, 6 Medium, 2 Low)
[SCAN] Duration: 18 minutes 15 seconds
```

**[Screen: Results panel showing 14 findings — comparison overlay showing Light found 7, Normal found 14]**

> "Eighteen minutes. Fourteen findings — double what Light found. We now have blind SQL injection, stored XSS, command injection, local file inclusion, CSRF, and weak authentication. The AI pattern recognition also flagged that multiple injection points suggest systematically poor input validation. This is the quality difference — Normal gives you a realistic picture of the target's security posture."

**[Screen: Side-by-side comparison — Light (7 findings, 6 min) vs Normal (14 findings, 18 min)]**

> "The trade-off is clear. Normal took three times as long but found twice as many vulnerabilities, including critical ones that Light missed entirely. For any real engagement, Normal should be your starting point."

---

## SECTION 6: Aggressive Profile Demo (12:30 – 15:00)

**[Screen: Selecting the 🟠 Aggressive profile — warning banner appearing about potential traffic generation]**

> "Aggressive is where things get serious. When you select this profile, Huginn shows a warning — this profile generates significant network traffic and may trigger security monitoring systems. In a real engagement, you'd only use this after confirming your rules of engagement permit noisy scanning."

**[Screen: Scan running — much higher activity in the terminal, showing WAF evasion attempts and neural network analysis]**

> "One hundred concurrent threads and advanced AI features. Aggressive tests WAF evasion techniques, runs neural network vulnerability analysis, uses ML-based payload generation, and performs behavioral anomaly detection. It's not just testing known patterns — it's learning what the application does and finding unique attack paths."

```bash
[SCAN] Aggressive profile scan started against http://localhost/dvwa/
[SCAN] Concurrent threads: 100 | Timeout: 15s
[SCAN] AI: Neural network analysis + ML payload generation enabled
[SCAN] Testing: deep vuln, WAF evasion, binary analysis, adaptive fuzzing

[FINDING] SQL Injection: /dvwa/vulnerabilities/sqli/?id=1' (High)
[FINDING] SQL Injection (Blind - Time Based): SLEEP(5) confirmed (High)
[FINDING] SQL Injection (UNION): 5-column UNION injection confirmed (Critical)
[FINDING] XSS Reflected: Multiple vectors confirmed (High)
[FINDING] XSS Stored: Persistent payload injection confirmed (High)
[FINDING] XSS DOM-Based: /dvwa/vulnerabilities/xss_d/ (High)
[FINDING] Command Injection: Multiple bypass techniques (Critical)
[FINDING] File Inclusion (LFI): /etc/passwd readable (High)
[FINDING] File Inclusion (RFI): Remote inclusion possible (Critical)
[FINDING] CSRF: Token bypass achievable (Medium)
[FINDING] File Upload: Unrestricted upload to /dvwa/hackable/uploads/ (Critical)
[FINDING] Brute Force: Weak credentials confirmed (admin/password) (High)
[FINDING] Missing Headers: 4 security headers absent (Medium)
[FINDING] Session Fixation: Session ID not rotated on login (Medium)
[FINDING] Insecure CAPTCHA: Bypass via direct request (Medium)
[AI-NEURAL] Attack path identified: SQLi → Data exfil → Admin creds
[AI-ML] Generated 12 adaptive payloads based on response patterns
[AI-ADAPTIVE] Fuzzing discovered encoding bypass: double-URL-encode

[SCAN] Aggressive scan complete: 19 findings (4 Critical, 8 High, 5 Medium, 2 Low)
[SCAN] Duration: 38 minutes 44 seconds
```

**[Screen: Results panel showing 19 findings — including 4 Critical severity items not found in previous profiles]**

> "Thirty-eight minutes. Nineteen findings with four at Critical severity. The AI found things manual payloads missed — UNION injection confirming five columns for data extraction, remote file inclusion, unrestricted file upload, and an encoding bypass through double URL encoding. The neural network also mapped an attack path from SQL injection to data exfiltration to admin credential extraction. This is the depth Aggressive provides."

**[Screen: Network traffic graph showing request volume spike compared to Light and Normal]**

> "But look at the traffic graph. Aggressive sent roughly five times more requests than Normal. On a monitored network, this volume would almost certainly trigger rate limiting or an IDS alert. Use Aggressive only when you have explicit permission for noisy testing or when the target has no active monitoring."

---

## SECTION 7: Insane Profile and Choosing the Right Profile (15:00 – 17:30)

**[Screen: Selecting the 🔴 Insane profile — large red warning banner about resource usage and potential service disruption]**

> "Finally, Insane. This is the kitchen sink — every feature Huginn has, running simultaneously. The warning is clear: this profile may cause service disruption. Two hundred concurrent threads with quantum-inspired fuzzing, an autonomous security agent, and zero-day discovery. Note: the Insane profile's AI features require an Enterprise tier license."

**[Screen: Scan running — showing autonomous agent decisions, quantum fuzzing states, and neural network analysis simultaneously]**

> "Watch the autonomous agent in action. It's making real-time decisions about what to test next based on what it's finding. The quantum fuzzing generates payload variants that don't follow predictable patterns — harder for WAFs to block. The neural network correlates findings across all test categories to identify complex vulnerability chains."

```bash
[SCAN] Insane profile scan started against http://localhost/dvwa/
[SCAN] Concurrent threads: 200 | Timeout: 20s
[SCAN] AI: ALL features enabled — Neural, ML, Quantum, Autonomous Agent
[SCAN] License: Enterprise tier required for AI features
[SCAN] Testing: full spectrum + zero-day discovery + exploit validation

[... 19 findings from Aggressive profile confirmed ...]

[AI-QUANTUM] Fuzzing state collapse: novel XSS vector via SVG+onload
[AI-AGENT] Autonomous decision: escalating file upload to RCE chain
[FINDING] Remote Code Execution: Upload → PHP webshell → command exec (Critical)
[FINDING] Privilege Escalation: MySQL LOAD_FILE() + INTO OUTFILE (Critical)
[AI-AGENT] Autonomous decision: chaining SQLi → file write → webshell
[FINDING] Full Compromise Chain: SQLi → File Write → RCE (Critical)
[FINDING] Information Disclosure: phpinfo() accessible (Low)
[FINDING] Backup File Exposure: /dvwa/config/config.inc.php.bak (High)
[AI-ZERO-DAY] Novel finding: Race condition in session handling (Medium)
[AI-NEURAL] Complete attack graph generated: 4 independent paths to RCE

[SCAN] Insane scan complete: 26 findings (7 Critical, 9 High, 6 Medium, 4 Low)
[SCAN] Duration: 1 hour 12 minutes
```

**[Screen: Comparison chart — all four profiles side by side: findings count, time, detection risk]**

> "Here's the full picture. Light: 7 findings in 6 minutes. Normal: 14 findings in 18 minutes. Aggressive: 19 findings in 38 minutes. Insane: 26 findings in 72 minutes. Each step up roughly doubles the time but yields diminishing returns on new findings. The jump from Light to Normal is the biggest value gain — doubling findings for three times the time. The jump from Aggressive to Insane adds 7 findings for nearly double the scan time."

**[Screen: Decision matrix — Engagement type mapped to recommended profile with rationale]**

> "So which profile should you use? For time-boxed assessments and OSCP exam scenarios, start with Light for a quick overview, then run Normal on hosts with open web services. For standard penetration tests with a week-long engagement window, Normal is your daily driver — comprehensive without being excessive. For high-value targets where you need maximum coverage and have permission for noisy testing, Aggressive gets you there. Reserve Insane for dedicated application security assessments where thoroughness matters more than stealth and you have explicit authorization for heavy testing."

```
Profile Selection Guide:
┌────────────────────────────┬──────────────┬─────────────────────────────┐
│ Scenario                   │ Profile      │ Rationale                   │
├────────────────────────────┼──────────────┼─────────────────────────────┤
│ OSCP exam / time-limited   │ Light→Normal │ Fast triage then targeted   │
│ Standard pentest           │ Normal       │ Best coverage/time ratio    │
│ Red team (stealth req.)    │ Light        │ Minimize detection risk     │
│ Full app security audit    │ Aggressive   │ Deep analysis permitted     │
│ Dedicated research/lab     │ Insane       │ Maximum thoroughness        │
└────────────────────────────┴──────────────┴─────────────────────────────┘
```

**[Screen: Certification mapping slide — OSCP: Vulnerability Scanning domain, CEH: Scanning Networks (Module 3)]**

> "For certification prep — both OSCP and CEH test your ability to identify vulnerabilities efficiently. The OSCP exam gives you limited time, so knowing when to use Light for speed versus Normal for depth is a real exam skill. Practice switching profiles based on what you find in initial reconnaissance. HTB machines like Shocker, Bashed, and Nibbles are excellent practice targets for vulnerability scanning methodology."

---

## OUTRO (17:30 – end)

**[Screen: Summary slide — Scanner Profiles: Light (speed), Normal (balance), Aggressive (depth), Insane (everything + Enterprise AI) | Next: Video 25 — Scan Configuration]**

> "That's the Huginn scanner and its four profiles. Light for speed, Normal for balance, Aggressive for depth, and Insane for maximum coverage with Enterprise-tier AI. The right choice depends on your engagement scope, time constraints, and authorization level. In the next video, we'll dig into scan configuration — setting up targets, defining scope boundaries, configuring port ranges, timing, and credentials for authenticated scanning. See you in Video 25."

