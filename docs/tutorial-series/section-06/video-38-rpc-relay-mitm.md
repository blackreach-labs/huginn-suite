# VIDEO 38: RPC Relay & MITM
### NTLM Relay, Token Impersonation & Relay Attack Chains
**Suggested length:** 16–18 minutes
**License Tier:** Free (Basic Relay Scanning) | Professional (Advanced Relay Exploitation & Token Impersonation)
**Certification Relevance:** OSCP: Network Exploitation | CEH: System Hacking

---

## INTRO (0:00 – 1:45)

**[Screen: Huginn splash screen with Section 6 title card "Network and OS Exploitation"]**

> "Welcome back to Section 6. This video covers one of the most powerful attack techniques in Active Directory environments — NTLM relay and man-in-the-middle attacks. These attacks exploit a fundamental weakness in Windows authentication: when a machine authenticates to a service, an attacker positioned between them can relay that authentication to a different target, gaining access as the victim. It's like intercepting someone's badge swipe and using it at a different door before they realize what happened."

**[Screen: Warning banner — red border, lock icon, "ISOLATED LAB ENVIRONMENT ONLY" text]**

> "Critical safety notice — relay attacks are performed exclusively against our isolated HTB Active lab machine. These techniques intercept authentication traffic and can cause service disruption, authentication failures, and unauthorized access in production environments. Never perform relay attacks on networks you don't own or have explicit written authorization to test. In many jurisdictions, intercepting authentication traffic without authorization carries criminal penalties beyond simple unauthorized access."

**[Screen: Slide showing video roadmap — NTLM Authentication → Relay Concepts → Huginn RPC Relay Interface → SMB Signing Check → LLMNR/NBNS Spoofing → Relay Demo → Token Impersonation → Tier Features]**

> "We'll start with how NTLM authentication works and why it's vulnerable to relay attacks, explore Huginn's RPC relay interface, check for SMB signing enforcement, demonstrate LLMNR poisoning to capture authentication, relay captured credentials to other services, and explore token impersonation. The basic relay scanning features are Free tier. Advanced exploitation — including active relay attacks and token impersonation — requires the Professional tier license. We'll clearly mark where each tier applies. This builds on Video 12 where we enumerated RPC endpoints (see Video 12: RPC Enumeration)."

---

## SECTION 1: NTLM Authentication and Relay Fundamentals (1:45 – 4:15)

**[Screen: Animated diagram showing NTLM challenge-response authentication — client → server: negotiate → server → client: challenge → client → server: authenticate]**

> "NTLM authentication uses a challenge-response mechanism. When a client wants to authenticate, it sends a Type 1 Negotiate message. The server responds with a Type 2 Challenge containing a random 8-byte nonce. The client proves identity by computing a response using the nonce and the user's password hash, then sends it as the Type 3 Authenticate message. The server verifies this response against its stored hash."

**[Screen: Diagram showing NTLM relay attack — victim → attacker (intercepts) → target: attacker forwards negotiate, relays challenge back, forwards authenticate to target]**

> "The relay vulnerability exists because NTLM doesn't bind the authentication to a specific service or channel. An attacker intercepts the Type 1 message from the victim, forwards it to a different target server, receives that target's challenge, relays the challenge back to the victim, receives the victim's authentication response, and forwards it to the target. The target sees a valid authentication and grants access — but the attacker is the one with the session."

**[Screen: Table showing relay requirements — 1. Victim initiates authentication, 2. Attacker positioned for interception, 3. Target accepts NTLM auth, 4. SMB signing not required]**

> "For relay to work, four conditions must be met. First, a victim must initiate an authentication attempt — we force this through name resolution poisoning. Second, we must be positioned to intercept the traffic — same network segment. Third, the target must accept NTLM authentication. Fourth, and critically, SMB signing must not be required on the target. If SMB signing is enforced, relayed sessions are rejected because the signing key is derived from the actual authenticating principal's password — which the attacker doesn't know."

**[Screen: Diagram showing LLMNR/NBT-NS name resolution poisoning — victim broadcasts "who is fileserver?" → attacker responds "I'm fileserver!" → victim authenticates to attacker]**

> "The most common way to trigger authentication attempts is through name resolution poisoning. When a Windows machine can't resolve a hostname via DNS, it falls back to broadcast protocols — LLMNR and NetBIOS Name Service. An attacker responds to these broadcasts claiming to be the requested resource. The victim then authenticates to the attacker thinking it's the legitimate service. This gives us the NTLM authentication traffic we need for relay."

---

## SECTION 2: Huginn RPC Relay Interface (4:15 – 6:15)

**[Screen: Huginn application — navigating from Home → OS Exploits → RPC Relay tab]**

> "Open Huginn and navigate to OS Exploits, then the RPC Relay tab. This interface combines relay vulnerability assessment and active exploitation into a workflow that progresses from discovery to attack. The left panel handles target configuration and relay chain mapping. The center shows live capture and relay status. The right panel contains the results and captured credentials."

**[Screen: RPC Relay component — highlighting target input, relay type dropdown (NTLM Relay, SMB Relay, LDAP Relay), attacker IP field]**

> "The relay type dropdown offers several attack variants — NTLM Relay for general credential relaying, SMB Relay for targeting file shares, and LDAP Relay for modifying Active Directory objects. The attacker IP field is important — this is your machine's IP on the target network, where poisoned responses and relay listeners will bind."

**[Screen: Highlighting the "Scan Relay Potential" button and the "Map MITM Surface" button]**

> "Two primary actions are available. Scan Relay Potential assesses whether targets are vulnerable to relay by checking SMB signing, available authentication services, and relay chain opportunities. Map MITM Surface identifies network positions suitable for interception. Both of these scanning functions are available on the Free tier. Let's start with the vulnerability assessment."

**[Screen: Free tier badge shown next to scanning functions; Professional tier badge next to exploitation functions]**

> "Notice the tier indicators. Relay scanning and vulnerability assessment — Free tier. Active poisoning, relay exploitation, and token impersonation — Professional tier. This distinction is important because scanning tells you the vulnerability exists, while exploitation actually performs the attack."

---

## SECTION 3: SMB Signing Assessment (6:15 – 8:15)

**[Screen: Entering target 10.10.10.100 (HTB Active), clicking "Scan Relay Potential"]**

> "Let's assess HTB Active for relay vulnerabilities. Enter 10.10.10.100 and click Scan Relay Potential. The first thing Huginn checks is SMB signing status — this is the make-or-break condition for relay attacks."

```bash
[RPC-RELAY] Scanning relay potential for 10.10.10.100...
[RPC-RELAY] 
[RPC-RELAY] === SMB Signing Assessment ===
[RPC-RELAY] Connecting to 10.10.10.100:445...
[RPC-RELAY] SMB Dialect: SMB 2.1
[RPC-RELAY] SMB Signing: SUPPORTED but NOT REQUIRED
[RPC-RELAY] ⚠ Target is VULNERABLE to SMB relay (signing not enforced)
[RPC-RELAY] 
[RPC-RELAY] === NTLM Authentication Services ===
[RPC-RELAY] [OPEN] SMB (445) — NTLM auth accepted
[RPC-RELAY] [OPEN] LDAP (389) — NTLM auth accepted
[RPC-RELAY] [OPEN] HTTP (80) — NTLM auth not detected
[RPC-RELAY] [OPEN] MSRPC (135) — NTLM auth accepted
[RPC-RELAY] [OPEN] Kerberos (88) — Kerberos only (no NTLM)
[RPC-RELAY] 
[RPC-RELAY] === Relay Chain Analysis ===
[RPC-RELAY] Viable relay targets from 10.10.10.100:
[RPC-RELAY]   SMB → SMB: VIABLE (signing not required)
[RPC-RELAY]   SMB → LDAP: VIABLE (no channel binding)
[RPC-RELAY]   LDAP → SMB: VIABLE (signing not required)
[RPC-RELAY]   RPC → SMB: VIABLE (signing not required)
[RPC-RELAY] 
[RPC-RELAY] Risk Level: HIGH
[RPC-RELAY] Relay chains available: 4
```

**[Screen: Results panel showing relay vulnerability assessment — color-coded risk indicators, relay chain diagram]**

> "Critical findings here. SMB signing is supported but not required — this is the default configuration for Windows member servers and workstations. Only domain controllers enforce signing by default. We have four viable relay chains. The SMB to LDAP chain is particularly dangerous because it allows modification of Active Directory objects if we relay a privileged user's authentication."

**[Screen: Relay chain diagram — visual showing source services on left, arrow through attacker in middle, target services on right]**

> "The relay chain diagram shows which source protocols can be relayed to which target services. Each viable chain represents a potential exploitation path. In a real Active Directory network with hundreds of machines, most member servers will have signing disabled — giving you a massive relay surface."

---

## SECTION 4: MITM Surface Mapping (8:15 – 10:00)

**[Screen: Clicking "Map MITM Surface" — showing network position analysis]**

> "Now let's map the man-in-the-middle surface. This function analyzes what name resolution protocols are active on the network and identifies opportunities for poisoning."

```bash
[RPC-RELAY] Mapping MITM surface for 10.10.10.100...
[RPC-RELAY] 
[RPC-RELAY] === Name Resolution Protocols ===
[RPC-RELAY] LLMNR (UDP 5355): Active on subnet
[RPC-RELAY] NBT-NS (UDP 137): Active on subnet
[RPC-RELAY] mDNS (UDP 5353): Not detected
[RPC-RELAY] 
[RPC-RELAY] === Spoofable Interfaces ===
[RPC-RELAY] Interface: eth0 (10.10.14.x/23)
[RPC-RELAY]   Can reach target: YES
[RPC-RELAY]   Broadcast domain: SHARED with target
[RPC-RELAY]   LLMNR poisoning: FEASIBLE
[RPC-RELAY]   NBT-NS poisoning: FEASIBLE
[RPC-RELAY] 
[RPC-RELAY] === Relay Interface Enumeration ===
[RPC-RELAY] RPC interfaces on target:
[RPC-RELAY]   [UUID] 12345778-1234-abcd-ef00-0123456789ab (LSA)
[RPC-RELAY]   [UUID] 12345778-1234-abcd-ef00-0123456789ac (SAMR)
[RPC-RELAY]   [UUID] e1af8308-5d1f-11c9-91a4-08002b14a0fa (EPM)
[RPC-RELAY] Access level: Anonymous enumeration permitted
[RPC-RELAY] 
[RPC-RELAY] === Mitigation Check ===
[RPC-RELAY] EPA (Extended Protection for Authentication): NOT configured
[RPC-RELAY] LDAP Channel Binding: NOT enforced
[RPC-RELAY] SMB Signing: NOT required (confirmed)
```

**[Screen: MITM surface map — showing network diagram with attack positions, poisonable protocols highlighted]**

> "Both LLMNR and NBT-NS are active — two broadcast protocols we can poison. Extended Protection for Authentication is not configured, and LDAP channel binding is not enforced. This target has zero relay mitigations in place. In Active Directory environments, this is unfortunately normal — most organizations never enable these protections because they're not configured by default and can break legacy applications."

---

## SECTION 5: LLMNR Poisoning and Hash Capture — Professional Tier (10:00 – 12:30)

**[Screen: Professional tier badge displayed — "The following features require Huginn Professional"]**

> "From this point forward, we're using Professional tier features for active exploitation. The scanning we just performed is Free tier — anyone can assess relay vulnerability. Active poisoning, credential interception, and relay execution require Professional."

**[Screen: RPC Relay Spoofer panel — configuring LLMNR poisoning: interface IP, target names (optional), starting spoofing]**

> "In the RPC Relay Spoofer panel, we configure our LLMNR and NBT-NS poisoner. Set the interface IP to our HTB VPN address. Target names can be left empty to poison all queries, or you can specify specific hostnames to target selectively. Click Start Spoofing."

```bash
[RELAY-SPOOF] Starting LLMNR/NBT-NS poisoner on 10.10.14.12...
[RELAY-SPOOF] LLMNR listener bound to 0.0.0.0:5355
[RELAY-SPOOF] NBT-NS listener bound to 0.0.0.0:137
[RELAY-SPOOF] SMB relay listener bound to 0.0.0.0:445
[RELAY-SPOOF] Waiting for broadcast name resolution queries...
[RELAY-SPOOF] 
[RELAY-SPOOF] [CAPTURED] LLMNR query from 10.10.10.100 for "SQLSERVER01"
[RELAY-SPOOF] [POISONED] Responded to 10.10.10.100 — directing to 10.10.14.12
[RELAY-SPOOF] [AUTH] Incoming SMB connection from 10.10.10.100
[RELAY-SPOOF] [AUTH] NTLM Type 1 (Negotiate) received
[RELAY-SPOOF] [AUTH] Sent Type 2 Challenge: 0x4a3b2c1d5e6f7a8b
[RELAY-SPOOF] [AUTH] NTLM Type 3 (Authenticate) received
[RELAY-SPOOF] 
[RELAY-SPOOF] ╔══════════════════════════════════════════════════╗
[RELAY-SPOOF] ║  NTLMv2 HASH CAPTURED                           ║
[RELAY-SPOOF] ║  User: ACTIVE\SVC_TGS                           ║
[RELAY-SPOOF] ║  Domain: ACTIVE                                  ║
[RELAY-SPOOF] ║  Source: 10.10.10.100                            ║
[RELAY-SPOOF] ║  Hash: SVC_TGS::ACTIVE:4a3b2c1d5e6f7a8b:       ║
[RELAY-SPOOF] ║    A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6:           ║
[RELAY-SPOOF] ║    0101000000000000...                           ║
[RELAY-SPOOF] ╚══════════════════════════════════════════════════╝
```

**[Screen: Captured hash displayed in the credentials panel — NTLMv2 hash with username, domain, challenge, response]**

> "We captured an NTLMv2 hash from the SVC_TGS service account. The machine broadcasted an LLMNR query looking for SQLSERVER01 — probably a scheduled task or service trying to connect to a server that no longer exists or isn't in DNS. We poisoned that query, the machine authenticated to us, and we captured the hash. This hash can be cracked offline (see Video 57: Hash Cracking) or relayed directly to another service."

---

## SECTION 6: NTLM Relay Attack Execution — Professional Tier (12:30 – 14:30)

**[Screen: NTLM Relay Client panel — configuring relay target, selecting relay destination (SMB → LDAP)]**

> "Rather than cracking the hash, let's relay it directly to another service. Configure the NTLM Relay Client with the relay target. We'll attempt an SMB to LDAP relay — forwarding the SMB authentication to the LDAP service on the same domain controller. If SVC_TGS has write permissions in Active Directory, this could allow us to modify objects."

```bash
[NTLM-RELAY] Configuring relay: SMB → LDAP
[NTLM-RELAY] Relay target: ldap://10.10.10.100
[NTLM-RELAY] Waiting for next authentication attempt to relay...
[NTLM-RELAY] 
[NTLM-RELAY] [RELAY] Incoming auth from 10.10.10.100 (ACTIVE\SVC_TGS)
[NTLM-RELAY] [RELAY] Forwarding Type 1 to ldap://10.10.10.100...
[NTLM-RELAY] [RELAY] Received Type 2 challenge from LDAP target
[NTLM-RELAY] [RELAY] Relaying challenge back to victim...
[NTLM-RELAY] [RELAY] Received Type 3 from victim, forwarding to LDAP...
[NTLM-RELAY] [RELAY] ✓ LDAP authentication successful via relay!
[NTLM-RELAY] [RELAY] Session established as ACTIVE\SVC_TGS on LDAP
[NTLM-RELAY] 
[NTLM-RELAY] === Relay Session Info ===
[NTLM-RELAY] Authenticated as: ACTIVE\SVC_TGS
[NTLM-RELAY] Target service: LDAP (10.10.10.100:389)
[NTLM-RELAY] Session type: LDAP bind
[NTLM-RELAY] Permissions: Read AD objects, limited write
```

**[Screen: Relay success notification — showing authenticated LDAP session, available actions]**

> "The relay succeeded. We now have an authenticated LDAP session as SVC_TGS without ever knowing the account's password. The LDAP session lets us read Active Directory objects and potentially modify them depending on the account's permissions. In larger environments, relaying a Domain Admin's authentication gives you full control over Active Directory."

**[Screen: Showing relay chain visualization — victim → attacker → target, with protocol labels at each hop]**

> "Look at the relay chain visualization. The victim authenticated to us over SMB, we relayed that authentication to the LDAP service on the domain controller, and LDAP accepted it. The victim has no idea their authentication was intercepted and relayed. This entire attack is silent from the victim's perspective."

---

## SECTION 7: Token Impersonation — Professional Tier (14:30 – 16:00)

**[Screen: Token Impersonation panel — showing token enumeration interface]**

> "The final Professional tier feature we'll demonstrate is token impersonation. When you have code execution on a Windows system — through xp_cmdshell (see Video 37: Database Attacks), a reverse shell, or any other method — Huginn's token impersonation module can enumerate and steal security tokens from running processes."

```bash
[TOKEN] Enumerating tokens on target system...
[TOKEN] 
[TOKEN] === Delegation Tokens Available ===
[TOKEN]   ACTIVE\Administrator     (Process: conhost.exe, PID: 2184)
[TOKEN]   ACTIVE\SVC_TGS           (Process: sqlservr.exe, PID: 1556)
[TOKEN]   NT AUTHORITY\SYSTEM       (Process: lsass.exe, PID: 672)
[TOKEN]   NT AUTHORITY\NETWORK      (Process: svchost.exe, PID: 844)
[TOKEN] 
[TOKEN] === Impersonation Tokens Available ===
[TOKEN]   ACTIVE\Administrator     (Process: explorer.exe, PID: 3012)
[TOKEN]   NT AUTHORITY\LOCAL SERVICE (Process: svchost.exe, PID: 756)
[TOKEN] 
[TOKEN] Elevated tokens found: 3
[TOKEN] SYSTEM token available: YES
```

**[Screen: Token list with "Impersonate" buttons next to each — Administrator token highlighted]**

> "Multiple tokens are available, including NT AUTHORITY\\SYSTEM and the domain Administrator. These tokens exist because those accounts have active sessions or processes running on this machine. With SeImpersonatePrivilege — which service accounts typically have — we can duplicate these tokens and create processes running as those users."

```bash
[TOKEN] Impersonating token: ACTIVE\Administrator (PID: 3012)
[TOKEN] Token duplicated successfully
[TOKEN] Impersonation active — current context: ACTIVE\Administrator
[TOKEN] 
[TOKEN] Verification:
[TOKEN] > whoami
[TOKEN]   active\administrator
[TOKEN] > whoami /groups
[TOKEN]   ACTIVE\Domain Admins
[TOKEN]   BUILTIN\Administrators
```

**[Screen: Confirmation showing elevated context — now running as Domain Administrator]**

> "We're now operating as the Domain Administrator through token impersonation. No password needed, no hash cracking, no brute-force — just stealing an existing session token. This demonstrates why defense-in-depth matters. Even if you prevent one attack vector, token impersonation provides an alternative escalation path whenever privileged processes run on compromised systems."

---

## SECTION 8: Mitigation Awareness (16:00 – 16:45)

**[Screen: Slide showing relay attack mitigations — SMB Signing, EPA, LDAP Channel Binding, disabling LLMNR/NBT-NS]**

> "Understanding mitigations is essential for both attackers and defenders. SMB signing prevents relay by binding the authentication cryptographically to the session — enable it via Group Policy on all systems, not just domain controllers. Extended Protection for Authentication adds channel binding tokens to HTTP and LDAP authentication. Disabling LLMNR and NBT-NS via Group Policy eliminates the most common poisoning vector entirely. For token impersonation, Credential Guard on Windows 10 and Server 2016 and newer protects cached tokens from theft."

---

## SECTION 9: Certification Mapping and Practice (16:45 – 17:15)

**[Screen: Slide showing OSCP: Network Exploitation (NTLM relay, Active Directory attacks), CEH: System Hacking (escalating privileges)]**

> "Relay attacks map to OSCP's Network Exploitation domain — understanding NTLM relay is critical for Active Directory environments in the exam. For CEH, this falls under System Hacking — specifically the Escalating Privileges and Maintaining Access phases. Token impersonation with tools like Incognito or through relay chains is a well-established exam technique."

**[Screen: Practice recommendations — HTB "Active" (this video), HTB "Forest" (AD exploitation), THM "Attacktive Directory" room]**

> "HTB Forest extends these concepts with DCSync and additional AD attack paths. The TryHackMe Attacktive Directory room provides guided practice with Kerberoasting and relay concepts in a safe environment. Both complement what we've covered here."

---

## OUTRO (17:15 – end)

**[Screen: Summary slide — RPC Relay & MITM: SMB Signing Check → MITM Surface Map → LLMNR Poisoning → Hash Capture → NTLM Relay → Token Impersonation | Free: Relay Scanning | Professional: Active Exploitation | Next: Video 39 — Exploit Database]**

> "That's RPC relay and man-in-the-middle attacks in Huginn. We assessed relay vulnerability through SMB signing checks and MITM surface mapping — both Free tier features. Then with Professional tier, we poisoned LLMNR queries to capture authentication hashes, relayed credentials to LDAP for unauthorized access, and demonstrated token impersonation for privilege escalation. The key takeaway: in Active Directory networks without signing and channel binding enforcement, a single network position can cascade into full domain compromise. In the next video, we'll explore Huginn's Exploit Database — matching discovered vulnerabilities to known exploits for automated exploitation. See you there."

---

## Section 6 Tier Quick-Reference (Videos 36–40)

| Video | Title | Required Tier |
|-------|-------|---------------|
| 36 | SSH Brute-Force & Vulnerability Scanning | Free |
| 37 | Database Attacks (MSSQL Client) | Free |
| 38 | RPC Relay & MITM | Free (Scanning) / Professional (Exploitation) |
| 39 | Exploit Database & CVE Matching | Enterprise |
| 40 | Hacking Mode (Framework Integration) | Professional (Basic) / Enterprise (Advanced) |
