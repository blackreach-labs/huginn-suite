# VIDEO 7: SMB Enumeration
### Share Discovery, User Enumeration & Null Sessions
**Suggested length:** 14–18 minutes
**License Tier:** Free
**Certification Relevance:** OSCP: Information Gathering | CEH: Enumeration

---

## INTRO (0:00 – 1:30)

**[Screen: Huginn splash screen with Section 2 title card "Recon and Enumeration Tools"]**

> "Welcome back to the Huginn tutorial series. In this video we cover SMB enumeration — one of the most information-rich protocols you'll encounter during a penetration test. SMB — Server Message Block — is the protocol Windows uses for file sharing, printer access, and inter-process communication. When misconfigured, it exposes user accounts, share names, group memberships, and even the operating system version without requiring any credentials."

**[Screen: Slide showing SMB protocol overview — ports 139 (NetBIOS) and 445 (Direct SMB), common services]**

> "In the previous video (see Video 6: Port Scanning), we discovered open services on target hosts. When you see ports 139 or 445 open, that's SMB — and it's time to enumerate. Today we'll work with Hack The Box's 'Lame' machine at 10.10.10.3, which runs an older Samba version with deliberate misconfigurations perfect for demonstrating enumeration techniques."

---

## SECTION 1: SMB Protocol Fundamentals (1:30 – 3:30)

**[Screen: Animated diagram showing SMB communication — client negotiation, session setup, tree connect, file operations]**

> "SMB operates on two ports. Port 445 is direct SMB over TCP — the modern approach. Port 139 is SMB over NetBIOS, which adds a session layer on top of TCP. Most modern systems use port 445, but older systems and Samba configurations may still expose port 139. Huginn probes both."

**[Screen: SMB version timeline — SMB1 (1983), SMB2 (2006), SMB3 (2012) with security features]**

> "SMB has evolved through several versions. SMBv1 — from 1983 — is the oldest and most insecure. It's the version targeted by EternalBlue. SMBv2 introduced message signing and improved performance. SMBv3 added encryption. The version running on a target tells you a lot about its age and security posture. Samba 3.0.20 on our target today uses SMBv1 — that's a red flag."

**[Screen: Diagram showing SMB enumeration targets — shares, users, groups, sessions, OS version, domain info]**

> "What can we enumerate through SMB? Share names reveal file storage and may include sensitive data. User lists give us valid usernames for brute-force attacks. Group memberships show privilege levels. Active sessions tell us who's logged in. The OS version and Samba version help identify known vulnerabilities. Domain and workgroup names reveal the network structure. All of this can be available through what's called a null session — an unauthenticated connection."

---

## SECTION 2: Huginn SMB Enumeration Interface (3:30 – 5:30)

**[Screen: Navigating Huginn — Recon & Enumeration → Service Scanners → SMB section]**

> "In Huginn, navigate to Recon and Enumeration, then find the SMB section under Service Scanners. The SMB enumeration interface has a target configuration panel, authentication options, and scan scope controls."

**[Screen: SMB enumeration page — highlighting target input, port selection (139/445), and authentication panel]**

> "At the top, enter your target IP or hostname. Below that, select which ports to probe — 445, 139, or both. The authentication panel lets you configure credentials if you have them. For null session enumeration — which is what we're doing first — leave the username and password fields empty. Huginn will attempt an anonymous connection."

**[Screen: SMB enumeration page — showing enumeration scope checkboxes (Shares, Users, Groups, Sessions, OS Info, Policies)]**

> "The enumeration scope section lets you select what to enumerate. Options include: Shares — discover available file shares. Users — enumerate valid user accounts. Groups — list groups and memberships. Sessions — show active user sessions. OS Info — detect operating system and SMB version. Policies — retrieve password and lockout policies. Check all of these for a comprehensive enumeration."

**[Screen: SMB enumeration page — showing the "SMB Version Detection" toggle and "Vulnerability Check" toggle]**

> "Two additional toggles: SMB Version Detection identifies the exact SMB dialect and Samba or Windows version. Vulnerability Check cross-references the detected version against known CVEs — for example, flagging if the target is vulnerable to EternalBlue or SambaCry. Enable both for a thorough assessment."

---

## SECTION 3: Configuring the SMB Scan (5:30 – 7:00)

**[Screen: Entering target "10.10.10.3" — HTB "Lame" machine]**

> "Let's configure our scan against HTB Lame at 10.10.10.3. Make sure you have your HTB VPN connected — this is a lab machine only accessible through the HTB network. Enter the IP in the target field."

```bash
Target: 10.10.10.3
Ports: 139, 445
Authentication: Anonymous (null session)
Scope: All (Shares, Users, Groups, Sessions, OS Info, Policies)
SMB Version Detection: Enabled
Vulnerability Check: Enabled
```

**[Screen: Port selection — both 139 and 445 checked]**

> "Check both ports 139 and 445. Leave authentication empty for a null session attempt. Select all enumeration scopes. Enable Version Detection and Vulnerability Check. This gives us maximum information from a single scan."

**[Screen: Clicking "Start Scan" — progress indicator begins]**

> "Click Start Scan. Huginn first establishes the connection — negotiating the SMB protocol version — then works through each enumeration scope in sequence. Watch the terminal output for the connection establishment."

---

## SECTION 4: Live Demo — Null Session Enumeration (7:00 – 10:30)

**[Screen: Terminal output showing SMB connection negotiation]**

> "First, the connection. Huginn sends an SMB negotiate request and the server responds with its supported dialect. We can see it's Samba 3.0.20 using the SMBv1 protocol — that's significant."

```bash
[SMB] Connecting to 10.10.10.3:445...
[SMB] Negotiation successful — SMBv1 dialect selected
[SMB] Server: Samba 3.0.20-Debian
[SMB] Session setup: Anonymous (null session)
[SMB] Null session ESTABLISHED — no credentials required

[SMB] === OS Information ===
[SMB] OS: Unix (Samba 3.0.20-Debian)
[SMB] Server: LAME
[SMB] Domain: WORKGROUP
[SMB] Signing: Disabled (not required)
```

**[Screen: Terminal showing share enumeration results]**

> "Now share enumeration. Huginn requests the list of available shares through the null session."

```bash
[SMB] === Share Enumeration ===
[SMB] Enumerating shares via null session...

  Share Name    Type      Comment
  ----------    ----      -------
  print$        Disk      Printer Drivers
  tmp           Disk      /tmp (oh no!)
  opt           Disk      
  IPC$          IPC       IPC Service (lame server)
  ADMIN$        IPC       IPC Service (lame server)

[SMB] 5 shares discovered (3 disk, 2 IPC)
[SMB] Attempting anonymous read access on each share...
[SMB]   tmp    — READ/WRITE access (anonymous)
[SMB]   opt    — ACCESS DENIED
[SMB]   print$ — ACCESS DENIED
```

**[Screen: Results table highlighting "tmp" share with READ/WRITE access]**

> "Five shares discovered. The critical finding here is the 'tmp' share — it maps to the /tmp directory and allows anonymous read and write access. That's a serious misconfiguration. An attacker could upload malicious files or read temporary data without any authentication. The 'opt' and 'print$' shares properly deny anonymous access. IPC$ and ADMIN$ are standard administrative shares."

**[Screen: Terminal showing user enumeration results]**

> "Next, user enumeration through RID cycling and standard queries."

```bash
[SMB] === User Enumeration ===
[SMB] Enumerating users via RID cycling (500-550, 1000-1050)...

  Username          RID     Description
  --------          ---     -----------
  root              500     Built-in account for system admin
  nobody            501     System nobody
  daemon            1000    
  user              1001    
  service           1002    SMB service account
  msfadmin          1003    
  ftp               1004    FTP user

[SMB] 7 users enumerated via null session
```

**[Screen: Results highlighting usernames like "msfadmin" and "service"]**

> "Seven users enumerated without any credentials. Notice 'msfadmin' — that's a Metasploit-related account, suggesting this system has Metasploit framework installed. The 'service' account is described as an SMB service account. These usernames are valuable for password attacks — you now have a valid user list for brute-force attempts against SSH or other services."

---

## SECTION 5: SMB Version Detection and Vulnerabilities (10:30 – 12:30)

**[Screen: Terminal showing version detection and vulnerability check results]**

> "Now the version detection and vulnerability check. Huginn identifies the exact Samba version and cross-references it against known CVEs."

```bash
[SMB] === Version Detection ===
[SMB] SMB Protocol: SMBv1
[SMB] Server Software: Samba 3.0.20-Debian
[SMB] Build Date: 2007-06-19
[SMB] Capabilities: Unicode, Large Files, NT SMBs, Raw Mode
[SMB] Message Signing: Disabled

[SMB] === Vulnerability Assessment ===
[SMB] Checking CVE database for Samba 3.0.20...

  CVE               Severity   Description
  ---               --------   -----------
  CVE-2007-2447     Critical   Samba username map script RCE
  CVE-2007-2446     High       Samba heap overflow (multiple)
  CVE-2007-0454     Medium     AFS ACL mapping VFS plugin

[SMB] WARNING: 3 known vulnerabilities detected
[SMB] CRITICAL: CVE-2007-2447 — Remote Code Execution via username
[SMB]   Affected: Samba 3.0.0 - 3.0.25rc3
[SMB]   Impact: Allows remote command execution as root
[SMB]   Exploit: Metasploit module available (exploit/multi/samba/usermap_script)
```

**[Screen: Results panel showing vulnerabilities in red — CVE-2007-2447 highlighted as Critical]**

> "Three known vulnerabilities found. The critical one is CVE-2007-2447 — a remote code execution vulnerability in the username map script functionality. This is the classic 'Lame' exploit — it allows an attacker to execute arbitrary commands as root by injecting shell metacharacters into the username field during authentication. Samba 3.0.20 falls within the affected range."

**[Screen: Showing the vulnerability details panel with CVSS score, affected versions, and remediation]**

> "Huginn displays the full vulnerability details — CVSS score, affected version range, available exploits, and recommended remediation. This is the bridge between enumeration and exploitation. You've identified the target, confirmed its version, and found a critical vulnerability — all without sending a single credential."

---

## SECTION 6: Group and Policy Enumeration (12:30 – 14:00)

**[Screen: Terminal showing group enumeration and password policy results]**

> "Let's look at the remaining enumeration results — groups and policies."

```bash
[SMB] === Group Enumeration ===
[SMB] Enumerating groups via null session...

  Group Name        RID     Members
  ----------        ---     -------
  Domain Admins     512     root
  Domain Users      513     user, msfadmin, ftp
  Domain Guests     514     nobody

[SMB] 3 groups enumerated

[SMB] === Password Policy ===
[SMB] Querying domain password policy...
  Minimum password length: 5
  Password history: 0 (no history enforced)
  Maximum password age: unlimited
  Minimum password age: 0
  Lockout threshold: 0 (no lockout)
  Lockout duration: 30 minutes
  Lockout observation window: 30 minutes

[SMB] WARNING: No account lockout configured — brute-force is viable
```

**[Screen: Results highlighting "Lockout threshold: 0 (no lockout)" in yellow warning]**

> "Two critical findings from this data. First, the group enumeration confirms 'root' is in Domain Admins — that's our high-value target account. Second, the password policy shows no lockout threshold — zero means accounts are never locked regardless of failed attempts. Combined with our user list, this means brute-force attacks are completely viable without risk of locking accounts. Document this for your report."

---

## SECTION 7: Results Interpretation and Next Steps (14:00 – 16:00)

**[Screen: Full results summary — table showing all discovered information categorized]**

> "Let's step back and review what we've gathered from this single SMB enumeration scan. We know the exact OS and Samba version — Samba 3.0.20 on Debian. We have a share with anonymous read/write access. We have seven valid usernames. We know there's no account lockout. And we've identified a critical RCE vulnerability. That's a complete attack path discovered entirely through enumeration."

**[Screen: Attack path diagram — Port scan → SMB enum → Version + CVE → Exploit path]**

> "The attack path writes itself. We started with a port scan that found 445 open. SMB enumeration revealed the Samba version. The vulnerability check confirmed CVE-2007-2447. The next step would be exploitation — which we'll cover in Section 6. For now, document all findings and move to the next service."

**[Screen: Export dialog — showing JSON/CSV export with full scan metadata]**

> "Export your results. The JSON export captures everything — shares, users, groups, policies, vulnerabilities, and the raw protocol exchanges. Feed this into Huginn's findings management to track these issues across your engagement. The discovered usernames automatically populate the credential lists available to other modules like SSH brute-force."

**[Screen: Showing how discovered hosts/services feed into other Huginn modules]**

> "Notice how results chain between modules. DNS enumeration found hostnames. Port scanning confirmed open services. SMB enumeration extracted detailed intelligence. Each module's output becomes the next module's input. This is the reconnaissance methodology in action — building a complete picture layer by layer."

---

## SECTION 8: Certification Mapping and Practice (16:00 – 17:00)

**[Screen: Slide showing certification mapping — OSCP: Information Gathering + Enumeration, CEH: Enumeration (Module 4)]**

> "SMB enumeration maps to both OSCP Information Gathering and CEH Module 4 — Enumeration. On the OSCP exam, SMB enumeration is almost always part of the attack path for Windows targets. The sequence is consistent: port scan finds 445, you enumerate shares and users, check for null sessions, and look for version-specific vulnerabilities. Practice this sequence until it's automatic."

**[Screen: Slide listing practice resources — HTB "Lame", HTB "Blue", THM "Network Services 2"]**

> "For practice, HTB Lame is the classic SMB enumeration target. HTB Blue focuses on EternalBlue — where SMB version detection is the key. The TryHackMe 'Network Services 2' room provides structured SMB enumeration exercises with guided questions. Practice null session enumeration, share access checks, and RID cycling until you can do them quickly and consistently."

---

## OUTRO (17:00 – end)

**[Screen: Summary slide — SMB Enumeration: Null Sessions, Share Discovery, User Enumeration, Version Detection, Vulnerability Checks | Next: Video 8 — SMTP Enumeration]**

> "That covers SMB enumeration in Huginn. We established null sessions to enumerate shares, users, and groups without credentials. We detected the SMB version and identified critical vulnerabilities. We extracted password policies that inform our brute-force strategy. In the next video, we'll cover SMTP enumeration — using mail server responses to verify valid email addresses and extract additional intelligence from the target's mail infrastructure. See you in Video 8."
