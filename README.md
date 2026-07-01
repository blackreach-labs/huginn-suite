# Huginn Suite

Huginn is a desktop penetration testing framework built with PyQt6. It provides a unified GUI for reconnaissance, vulnerability scanning, exploitation, post-exploitation, and reporting — organized around a visual attack-chain methodology.

## Installation (Windows 11)

Open Terminal as Administrator.

### 1. Install git, python, and npcap

```powershell
winget source remove winget
winget source remove msstore
winget source add winget https://cdn.winget.microsoft.com/cache
winget source update
winget install --id Git.Git
winget install --id Python.Python.3.12
Invoke-WebRequest "https://npcap.com/dist/npcap-1.88.exe" -OutFile "$env:TEMP\npcap.exe"; Start-Process "$env:TEMP\npcap.exe"
```

Close and reopen Terminal as Administrator.

### 2. Add Windows Defender exclusion and download Huginn Suite

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
Add-MpPreference -ExclusionPath "$env:USERPROFILE\tools\huginn-suite"
mkdir ~/tools; cd ~/tools
git clone https://github.com/blackreach-labs/huginn-suite.git
cd huginn-suite
```

### 3. Create a virtual environment and install dependencies

```powershell
python -m venv venv; .\venv\Scripts\Activate.ps1; python -m pip install -r requirements.txt
```

### 4. Launch the application

```powershell
python main.py
```

## Installation (Linux)
```bash
mkdir ~/tools; cd ~/tools
git clone https://github.com/blackreach-labs/huginn-suite.git
cd huginn-suite
```

### 3. Create a virtual environment and install dependencies

```bash
python -m venv venv; source /venv/bin/activate; pip install -r requirements.txt
```

### 4. Launch the application

```bash
sudo python main.py
```


---

## UI Overview

The main window is divided into two areas:

- **Attack Chain Mindmap** — a horizontal navigation bar at the top with six methodology phases (Setup → Recon → Scan → Exploit → Elevate → Report). Clicking a phase navigates to the corresponding page.
- **Page Stack** — the content area below, which displays the active page.

A menu bar provides access to all pages, tools, view settings, and help.

### Navigation Modes

| Mode | Description |
|------|-------------|
| Advanced Mode | Full attack-chain mindmap with direct access to all pages |
| Guided Mode | Step-by-step penetration testing workflow with progress tracking |

---

## Pages

### Engagement Setup

Target profiling and scope definition.

| Tab | Purpose |
|-----|---------|
| Target Profiles | Define targets, scope, and engagement parameters |
| Credential Management | Store and manage credentials (passwords, NTLM hashes, Kerberos tickets) |
| Correlations | View cross-scan correlations and attack paths |

---

### Recon & Enumeration

Information gathering and enumeration across multiple protocols and services.

| Tab | Purpose |
|-----|---------|
| OSINT | Open-source intelligence gathering (people search, social media, infrastructure, threat intel) |
| Network Scanning | Host discovery, port scanning, cloud asset discovery |
| DNS | Subdomain enumeration, record lookups, zone transfers |
| Service Enumeration | Protocol-specific enumeration (HTTP, RPC, SMB, SMTP, LDAP, SNMP, API, Database, IKE, AV/Firewall) |
| AWS | AWS penetration testing tools |
| Azure | Azure penetration testing tools |
| Active Directory | AD enumeration and Kerberos tooling |
| Wireless | Bluetooth and Wi-Fi scanning |
| Social Engineering | Phishing and social engineering campaign tools |

---

### Vulnerability Analysis

Vulnerability identification and correlation.

| Tab | Purpose |
|-----|---------|
| Vulnerability Scanner | General vulnerability scanning with CVE detection |
| Web Application Scanner | Web-specific vulnerability testing |
| SSH Vulnerability Scanner | SSH service vulnerability assessment |
| Huginn Advanced Scanner | AI-powered scanner with multiple scan profiles (Light, Normal, Aggressive, Insane) |

---

### Exploitation

Active exploitation and initial access.

| Tab | Purpose |
|-----|---------|
| Web Exploits | XSS, SQLi, SSTI, deserialization, and other web attack vectors |
| HTTP Interceptor | Real-time HTTP/HTTPS traffic interception and modification (mitmproxy-based) |
| Auth Workflows | Authentication bypass and session manipulation |
| RPC Relay & MITM | NTLM relay, coercion attacks (PetitPotam, PrinterBug, DFSCoerce) |
| Zero-Day Fuzzing | Evolutionary fuzzing for unknown vulnerability discovery |
| Interactive Shell | Reverse/bind shell listener management and payload generation |
| OS Exploits | SSH brute-force and operating system exploitation |
| Runecraft | Payload generation framework with evasion, encoding, and delivery options |

---

### Post-Exploitation

Privilege escalation, lateral movement, and persistence.

| Tab | Purpose |
|-----|---------|
| Secrets Extraction | SAM/LSA dump, cached credentials, registry secrets |
| Persistence | Persistence mechanism deployment |
| Lateral Movement | Network pivoting and credential reuse with risk scoring |
| Hash Cracking | Offline hash cracking (integrated with GPU/OpenCL) |
| System Enumeration | Local system, network, and user enumeration |
| Windows Agent | Remote Windows agent with HMAC-authenticated tasking |
| Evidence Collector | Process snapshots, event logs, screenshots, file samples |
| C2 Orchestrator | Beacon management, payload generation, and task queuing |

---

### Reporting

Findings documentation, remediation, and analytics.

| Tab | Purpose |
|-----|---------|
| Common Findings | Searchable findings list with detailed evidence view |
| Advanced Reporting | Report generation in HTML, JSON, Executive, OWASP, and PCI formats |
| Remediation | Automated remediation planning and tracking |
| Dashboard | Real-time security metrics and monitoring |
| Analytics | Advanced analytics with trend analysis and pattern detection |

---

## Additional Pages

| Page | Access | Purpose |
|------|--------|---------|
| Inventory | Navigate menu / Ctrl+Shift+I | Discovered asset management with tenant isolation |
| Running Scans | Navigate menu / Ctrl+Shift+R | Monitor and control active scans |
| Sessions | Navigate menu / Ctrl+Shift+S | Session management and information |
| VPN Connection | Navigate menu | OpenVPN connection management |
| Global Settings | Tools menu / Ctrl+, | API keys, rate limits, and application configuration |
| Database Management | Tools menu / Ctrl+D | SQLite database browser and SQL queries |
| Script Editor | Tools menu | Write and save scripts or wordlists |
| Cracking | Tools menu | Password cracking and SSH key parsing |
| Stealth Mode | Tools menu | Evasion and anti-detection configuration |
| License Manager | Tools menu | Professional license management |

---

## Menu Bar

| Menu | Items |
|------|-------|
| File | Profiles (New/Load/Delete), Export Results, Exit |
| Navigate | Engagement Setup, Recon & Enumeration, Vulnerability Analysis, Exploitation, Post-Exploitation, Reporting, Inventory, VPN, Running Scans, Sessions |
| Tools | Stealth Mode, Script Editor, Cracking, Databases, Global Settings, License Manager |
| View | Navigation Style (Advanced/Guided), Themes, Minimize to Tray, Clear Output |
| Help | Tool Help (F1), About |

---

## Theming

Huginn supports multiple themes selectable from View → Themes. The default theme uses a dark terminal aesthetic with cyan accent colors. Custom themes are loaded from `resources/themes/`.

---

## Security

A full security review was completed in May 2025. All 8 identified issues (4 Critical, 2 High, 2 Medium) have been remediated.

| Document | Description |
|----------|-------------|
| [`docs/SECURITY.md`](docs/SECURITY.md) | Secure coding standards, contribution rules, known issues |
| [`docs/SECURITY_REVIEW.md`](docs/SECURITY_REVIEW.md) | Full review findings and remediation summary |

Key changes: SSL verification enabled by default, Fernet-encrypted credentials at rest, `shell=True` eliminated, SQL injection fixed, HMAC-SHA256 agent attestation, HTML output escaping, bare exception handlers replaced with logging, and simulation mode clearly labels synthetic data.

To report a security issue, see [`docs/SECURITY.md`](docs/SECURITY.md).
