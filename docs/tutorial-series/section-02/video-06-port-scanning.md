# VIDEO 6: Port Scanning
### TCP/UDP Scanning, Service Detection & OS Fingerprinting
**Suggested length:** 15–20 minutes
**License Tier:** Free
**Certification Relevance:** OSCP: Information Gathering | CEH: Scanning Networks

---

## INTRO (0:00 – 1:30)

**[Screen: Huginn splash screen with Section 2 title card "Recon and Enumeration Tools"]**

> "Welcome back. In this video we cover port scanning — arguably the most fundamental skill in penetration testing. After DNS enumeration reveals hostnames and IP addresses (see Video 5: DNS Enumeration), port scanning tells us which services are actually listening and reachable on those hosts. Every open port is a potential entry point, and understanding what's behind each one is critical to planning your attack."

**[Screen: Slide showing TCP three-way handshake diagram — SYN, SYN-ACK, ACK]**

> "We'll cover the protocols behind port scanning, walk through Huginn's scanning interface, configure different scan types — TCP Connect, SYN stealth, and UDP — run service version detection and OS fingerprinting against our authorized target, and interpret what the results mean for your engagement. Our target today is scanme.nmap.org at 45.33.32.156 — explicitly authorized for scanning by the Nmap project."

---

## SECTION 1: Port Scanning Fundamentals (1:30 – 4:00)

**[Screen: Animated diagram showing TCP three-way handshake — SYN → SYN-ACK → ACK for open port]**

> "Port scanning exploits the TCP three-way handshake. When you send a SYN packet to an open port, the server responds with SYN-ACK — acknowledging it's ready to connect. A closed port responds with RST — resetting the connection. A filtered port gives you nothing back — the packet was silently dropped by a firewall."

**[Screen: Diagram showing three port states — Open (SYN-ACK), Closed (RST), Filtered (no response/ICMP unreachable)]**

> "These three states — open, closed, and filtered — are the foundation of port scanning. Open means a service is listening and accepting connections. Closed means the port is accessible but nothing is listening. Filtered means a firewall or network device is blocking our probe and we can't determine the port state."

**[Screen: Comparison table — TCP Connect scan vs SYN scan vs UDP scan]**

> "There are three primary scan types. A TCP Connect scan completes the full three-way handshake — it's reliable but noisy because the connection is fully established and logged. A SYN scan — also called half-open or stealth scan — only sends the initial SYN and reads the response without completing the handshake. It's faster and harder to detect. A UDP scan sends empty UDP packets or protocol-specific payloads to identify UDP services like DNS, SNMP, and DHCP."

**[Screen: Diagram showing 65535 total ports — well-known (0-1023), registered (1024-49151), dynamic (49152-65535)]**

> "There are 65,535 possible TCP ports and the same number for UDP. The well-known ports — zero through 1023 — host standard services like HTTP on 80, HTTPS on 443, SSH on 22, and SMB on 445. Scanning all 65,535 ports is thorough but time-consuming. In practice, you'll start with the top 1000 most common ports and expand from there based on what you find."

---

## SECTION 2: Huginn Port Scanning Interface (4:00 – 6:30)

**[Screen: Navigating Huginn — Recon & Enumeration → Port Scanning tab]**

> "In Huginn, navigate to Recon and Enumeration, then select the Port Scanning tab. The interface is divided into three panels: target configuration on the left, scan controls in the center, and results on the right."

**[Screen: Port Scanning page — highlighting the target input field with IP/hostname input and CIDR notation example]**

> "The target field accepts single IPs, hostnames, CIDR ranges like 192.168.1.0/24, or comma-separated lists. Below that you'll see the port range configuration — you can select common presets like Top 100, Top 1000, Full Range, or specify a custom range like 1-1024 or 80,443,8080."

**[Screen: Port Scanning page — highlighting scan type dropdown (TCP Connect, SYN Scan, UDP Scan) and timing options]**

> "The scan type dropdown offers TCP Connect, SYN Scan, and UDP Scan. Below that are timing controls — these map to nmap's timing templates from T0 (Paranoid) through T5 (Insane). The default T3 is a reasonable balance between speed and stealth. We'll use T4 today for our authorized target since detection isn't a concern."

**[Screen: Port Scanning page — showing advanced options panel (Service Detection checkbox, OS Fingerprinting checkbox, Script Scanning)]**

> "Expand the Advanced Options panel and you'll find three important toggles. Service Detection probes open ports to identify the software and version running behind them. OS Fingerprinting analyzes packet responses to determine the target's operating system. Script Scanning runs a set of default vulnerability checks against discovered services. For a thorough first scan, enable Service Detection and OS Fingerprinting."

---

## SECTION 3: Configuring the Scan (6:30 – 8:00)

**[Screen: Entering target — "scanme.nmap.org" (showing resolved IP 45.33.32.156)]**

> "Let's configure our scan. Enter scanme.nmap.org in the target field — Huginn resolves it to 45.33.32.156 automatically. For port range, select Top 1000. Set the scan type to SYN Scan for speed, and timing to T4."

```bash
Target: scanme.nmap.org (45.33.32.156)
Port Range: Top 1000
Scan Type: SYN Scan
Timing: T4 (Aggressive)
Service Detection: Enabled
OS Fingerprinting: Enabled
```

**[Screen: Reviewing the configuration summary before starting]**

> "Before we start, review the configuration summary at the bottom. It shows the effective command that will execute — this helps you understand what's happening under the hood and lets you reproduce the scan from the command line if needed."

**[Screen: Clicking "Start Scan" — the progress indicator begins with estimated time]**

> "Click Start Scan. The progress indicator shows estimated time remaining based on the port range and timing template. With Top 1000 ports and T4 timing against a single host, this should complete in about 30 to 60 seconds."

---

## SECTION 4: Live Demo — SYN Scan with Service Detection (8:00 – 11:30)

**[Screen: Terminal output showing scan progress — ports being probed, open ports highlighted in green]**

> "Watch the terminal output. Open ports appear highlighted in green as they're discovered. You can see SYN packets going out and SYN-ACK responses coming back for open ports. Closed ports return RST packets — those are logged but not highlighted."

```bash
[PORT] Starting SYN scan against 45.33.32.156
[PORT] Scanning 1000 most common ports...
[PORT] Timing template: T4 (aggressive)

[PORT] 22/tcp    open    ssh
[PORT] 80/tcp    open    http
[PORT] 9929/tcp  open    nping-echo
[PORT] 31337/tcp open    Elite

[PORT] Service detection starting on 4 open ports...
[PORT] 22/tcp    OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (protocol 2.0)
[PORT] 80/tcp    Apache httpd 2.4.7 ((Ubuntu))
[PORT] 9929/tcp  Nping echo service
[PORT] 31337/tcp tcpwrapped

[PORT] OS fingerprinting...
[PORT] OS Detection: Linux 3.x-4.x (96% confidence)
[PORT] OS Details: Linux 3.2 - 4.9

[PORT] Scan complete: 4 open, 993 closed, 3 filtered
[PORT] Scan duration: 42.3 seconds
```

**[Screen: Results table populating — Port, State, Service, Version columns]**

> "Four open ports discovered. Port 22 is SSH — specifically OpenSSH 6.6.1p1 on Ubuntu. Port 80 is HTTP running Apache 2.4.7. Port 9929 is the Nping echo service — that's a testing tool from the Nmap project. Port 31337 shows as tcpwrapped, meaning the connection completed but the service immediately closed it — this is sometimes used for honeypot-style detection."

**[Screen: Highlighting the OS Detection result — "Linux 3.x-4.x (96% confidence)"]**

> "OS fingerprinting identified the target as Linux 3.x to 4.x with 96 percent confidence. This is determined by analyzing subtle differences in how the TCP/IP stack responds — things like initial TTL values, window sizes, and TCP option ordering. Knowing the OS helps you narrow down which exploits and techniques are applicable."

**[Screen: Showing 3 filtered ports in the results]**

> "Notice the three filtered ports. These sent no response — meaning a firewall is silently dropping our packets to those ports. This tells us there's packet filtering in place, which is useful intelligence for understanding the target's security posture."

---

## SECTION 5: UDP Scanning (11:30 – 13:30)

**[Screen: Changing scan type to "UDP Scan" — port range changed to "53,161,500,123,1900"]**

> "Now let's run a UDP scan. UDP scanning is slower because there's no handshake — you send a packet and wait for a response or timeout. An open UDP port might respond with service-specific data, or it might say nothing. A closed port sends back an ICMP Port Unreachable message. Change the scan type to UDP Scan and set a targeted port range — 53 for DNS, 161 for SNMP, 500 for IKE, 123 for NTP, and 1900 for SSDP."

```bash
[PORT] Starting UDP scan against 45.33.32.156
[PORT] Scanning 5 specified UDP ports...
[PORT] Note: UDP scanning is slower — no handshake to confirm state

[PORT] 53/udp    open|filtered  dns
[PORT] 123/udp   open|filtered  ntp
[PORT] 161/udp   closed         snmp
[PORT] 500/udp   closed         isakmp
[PORT] 1900/udp  closed         ssdp

[PORT] UDP scan complete: 2 open|filtered, 3 closed
[PORT] Scan duration: 18.7 seconds
```

**[Screen: Results showing "open|filtered" state for some UDP ports]**

> "See the open-pipe-filtered state on ports 53 and 123. This is common with UDP scanning — when there's no response, we can't distinguish between an open port that silently accepted our packet and a filtered port that dropped it. This ambiguity is inherent to UDP. To confirm, you'd send protocol-specific probes — a DNS query to port 53, an NTP request to port 123 — and check for valid responses."

**[Screen: Comparison callout — TCP scan took 42 seconds for 1000 ports vs UDP scan took 18 seconds for 5 ports]**

> "Notice the time difference. TCP scanning 1000 ports took about 42 seconds. UDP scanning just 5 ports took 18 seconds. UDP is fundamentally slower because the protocol lacks the immediate feedback TCP provides. For comprehensive UDP coverage, you'll want to target specific ports rather than scanning the full range."

---

## SECTION 6: Scan Profiles and Timing (13:30 – 15:30)

**[Screen: Scan profiles panel — showing preset configurations (Quick, Standard, Thorough, Full)]**

> "Huginn includes scan profiles that bundle common configurations. Quick runs a SYN scan on the top 100 ports with T4 timing — fast reconnaissance in under 15 seconds. Standard covers the top 1000 with service detection. Thorough scans all 65535 TCP ports with service detection and OS fingerprinting. Full does everything — all TCP ports, top UDP ports, service detection, OS fingerprinting, and script scanning."

**[Screen: Timing template comparison table — T0 through T5 with packet rates and use cases]**

> "Timing templates control how aggressively Huginn sends packets. T0 Paranoid waits 5 minutes between probes — used to evade IDS in extremely slow but stealthy scans. T1 Sneaky waits 15 seconds. T2 Polite waits 0.4 seconds. T3 Normal is the default with no artificial delays. T4 Aggressive reduces timeouts and sends probes faster. T5 Insane is maximum speed with very short timeouts — it can miss ports on unreliable networks but finishes quickly."

```bash
Timing Templates:
  T0 (Paranoid)  — 5 min between probes  — IDS evasion
  T1 (Sneaky)    — 15 sec between probes — Low and slow
  T2 (Polite)    — 0.4 sec delay         — Bandwidth conscious
  T3 (Normal)    — Default, no delays     — Standard recon
  T4 (Aggressive)— Reduced timeouts       — Fast, reliable network
  T5 (Insane)    — Minimal timeouts       — Maximum speed
```

**[Screen: Scan profiles dropdown — selecting "Thorough" and showing expanded configuration]**

> "For a real engagement, you'd typically start with Quick or Standard to get an initial picture, then follow up with Thorough on interesting hosts. The Full profile is reserved for situations where you need complete coverage and have time — it can take 20 minutes or more per host scanning all 65535 ports with full detection."

---

## SECTION 7: Results Interpretation (15:30 – 17:30)

**[Screen: Full results view — table sorted by port number, service version details visible]**

> "Let's interpret our results strategically. Four open TCP ports on scanme.nmap.org. SSH on port 22 running OpenSSH 6.6.1p1 — that's an older version, which means potential vulnerabilities to investigate. Apache 2.4.7 on port 80 — also older. These version numbers are your next research targets. You'd cross-reference them against CVE databases and known exploit lists."

**[Screen: Highlighting the "Export" button — showing options for JSON, CSV, or feeding into other modules]**

> "The version information is particularly valuable. OpenSSH 6.6.1p1 on Ubuntu was released in 2014 — there are known vulnerabilities in that version range. Apache 2.4.7 has known issues with certain configurations. Document these findings and note them for the vulnerability scanning phase."

**[Screen: Tree view showing host → ports → services hierarchy]**

> "The tree view groups results by host, making it easy to see the full attack surface at a glance. Each open port is a branch showing the service, version, and any additional script output. You can right-click any port to feed it directly into Huginn's service-specific enumeration tools — for example, sending port 80 to HTTP fingerprinting or port 445 to SMB enumeration."

**[Screen: Export dialog — JSON and CSV options with metadata inclusion toggles]**

> "Export your results for documentation. The JSON export includes all metadata — scan configuration, timing, packet-level details. CSV is better for spreadsheet analysis and reporting. Both formats integrate with Huginn's findings management system for your final engagement report."

---

## SECTION 8: Certification Mapping and Practice (17:30 – 18:30)

**[Screen: Slide showing certification mapping — OSCP: Information Gathering, CEH: Scanning Networks (Module 3)]**

> "Port scanning maps to the OSCP Information Gathering domain and CEH Module 3 — Scanning Networks. On the OSCP exam, efficient port scanning is critical — you have limited time and need to identify services quickly. Tip: start with a fast scan of the top 1000 ports, note what's open, then do targeted version detection only on open ports. Don't waste exam time scanning all 65535 ports unless the quick scan comes up empty."

**[Screen: Slide listing practice resources — scanme.nmap.org, HTB Starting Point machines, THM "Nmap" room]**

> "For practice, scanme.nmap.org is always available for authorized scanning. The TryHackMe 'Nmap' room provides a structured walkthrough of scan types and timing. Hack The Box Starting Point machines give you realistic targets where port scanning is the first step in every attack path."

---

## OUTRO (18:30 – end)

**[Screen: Summary slide — Port Scanning: SYN/TCP/UDP Scans, Service Detection, OS Fingerprinting, Scan Profiles | Next: Video 7 — SMB Enumeration]**

> "That covers port scanning in Huginn. We ran SYN and UDP scans, configured service detection and OS fingerprinting, explored timing templates and scan profiles, and interpreted our results. In the next video, we'll use what we've discovered here — specifically open port 445 — to dive into SMB enumeration and extract user accounts, share listings, and configuration details from SMB services. See you in Video 7."
