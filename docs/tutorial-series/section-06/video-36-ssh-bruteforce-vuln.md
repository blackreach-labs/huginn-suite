# VIDEO 36: SSH Brute-Force & Vulnerability Scanning
### Credential Testing, Key-Based Auth & SSH Exploit Detection
**Suggested length:** 16–18 minutes
**License Tier:** Free
**Certification Relevance:** OSCP: Network Exploitation | CEH: System Hacking

---

## INTRO (0:00 – 1:30)

**[Screen: Huginn splash screen with Section 6 title card "Network and OS Exploitation"]**

> "Welcome to Section 6 — Network and OS Exploitation. This is where we move beyond reconnaissance and vulnerability scanning into active exploitation of network services. In this video, we're starting with SSH — the Secure Shell protocol. SSH is everywhere. It's the primary remote administration protocol for Linux servers, network devices, and increasingly Windows systems. When SSH is exposed, it becomes a high-value target for credential attacks and vulnerability exploitation."

**[Screen: Warning banner — red border, lock icon, "ISOLATED LAB ENVIRONMENT ONLY" text]**

> "Before we begin — an important safety notice. Everything demonstrated in this video is performed against an isolated Hack The Box lab machine. Never attempt brute-force attacks or vulnerability exploitation against systems you do not own or have explicit written authorization to test. Unauthorized access to computer systems is illegal in virtually every jurisdiction. These techniques are taught for authorized penetration testing and security assessments only."

**[Screen: Slide showing video roadmap — SSH Protocol Basics → Banner Analysis → Vulnerability Scanning → Brute-Force Configuration → Live Demo → User Enumeration → Results]**

> "We'll cover how SSH authentication works at a protocol level, analyze SSH banners for version-based vulnerabilities, configure brute-force credential attacks with intelligent rate limiting, demonstrate user enumeration techniques, and run everything live against HTB Lame. If you haven't already, watch Video 6 on Port Scanning to understand how we identify SSH services in the first place (see Video 6: Port Scanning)."

---

## SECTION 1: SSH Protocol and Authentication Fundamentals (1:30 – 4:00)

**[Screen: Animated diagram showing SSH connection flow — TCP handshake → protocol version exchange → key exchange → authentication → session]**

> "SSH operates over TCP, typically on port 22. When a client connects, the server immediately sends its protocol version banner — something like SSH-2.0-OpenSSH_7.2p2. This banner alone tells us the software, version, and sometimes the underlying operating system. After the version exchange, both sides negotiate encryption algorithms through key exchange, then the client authenticates."

**[Screen: Diagram showing SSH authentication methods — password, public key, keyboard-interactive, GSSAPI]**

> "SSH supports multiple authentication methods. Password authentication is the simplest — the client sends credentials over the encrypted channel. Public key authentication uses cryptographic key pairs — far more secure but often not enforced. Keyboard-interactive allows challenge-response flows like two-factor authentication. GSSAPI integrates with Kerberos for domain environments. For penetration testing, password authentication is our primary target because it's susceptible to brute-force attacks."

**[Screen: Table showing common SSH vulnerabilities — CVE-2018-15473 (user enumeration), CVE-2018-10933 (libssh auth bypass), CVE-2016-20012 (info disclosure)]**

> "Beyond credential attacks, SSH implementations have their own vulnerability history. CVE-2018-15473 in OpenSSH allows user enumeration through timing differences in authentication responses. CVE-2018-10933 in libssh allows complete authentication bypass — just tell the server you're already authenticated and it believes you. CVE-2016-20012 enables information disclosure through specific packet manipulation. Huginn's SSH audit engine checks for all of these automatically based on the server's banner version."

---

## SECTION 2: Huginn SSH Tools Interface (4:00 – 6:30)

**[Screen: Huginn application — navigating from Home → OS Exploits page → SSH Brute-Force tab]**

> "Let's open Huginn and navigate to the SSH exploitation tools. From the home screen, click OS Exploits in the sidebar. You'll see tabs across the top for different network exploitation modules. Click the SSH Brute-Force tab. This interface combines credential testing and vulnerability scanning into a single workflow."

**[Screen: SSH Brute-Force component — highlighting target input, port field, credential configuration panels]**

> "The interface has three main sections. On the left, target configuration — IP address and port. In the center, the credential configuration panel where you set up usernames, wordlists, and attack parameters. On the right, the live output terminal and results table. Below the brute-force section, you'll see the SSH Vulnerability Scanner tab — that's where banner analysis and CVE checking happen."

**[Screen: SSH Vulnerability Scanner component — showing audit options, baseline selection (CIS, NIST, PCI-DSS), and scan scope toggles]**

> "Switch to the SSH Vulnerability Scanner tab. This is Huginn's SSH audit engine. It performs comprehensive security assessments against SSH servers — checking protocol version, cryptographic algorithms, authentication configuration, and known vulnerabilities. You can select a compliance baseline — CIS benchmarks, NIST guidelines, or PCI-DSS requirements — and the engine reports deviations from that standard."

**[Screen: Highlighting configuration options — max threads, delay between attempts, max attempts per user, lockout detection]**

> "Back on the brute-force tab, notice the safety configuration options. Max threads controls parallelism — more threads mean faster attacks but also more noise and higher risk of triggering lockout. Delay between attempts adds a pause to avoid rate limiting. Max attempts per user prevents account lockout. These aren't just about stealth — they prevent you from accidentally locking out legitimate users during an authorized assessment."

---

## SECTION 3: Banner Analysis and Version Detection (6:30 – 8:30)

**[Screen: Huginn SSH Vulnerability Scanner — entering target 10.10.10.3 (HTB Lame), port 22]**

> "Let's start with passive analysis. Enter our target — HTB Lame at 10.10.10.3 — and run a banner grab first. This is the lowest-noise technique: we connect, read the SSH banner, then analyze it for known vulnerabilities without attempting any authentication."

```bash
Target: 10.10.10.3
Port: 22
Scan Type: Banner Analysis + Vulnerability Check
```

**[Screen: Terminal output showing banner grab and analysis results]**

> "The banner comes back: SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1. That's OpenSSH 4.7 on Debian-based Ubuntu. This version is ancient — released in 2007. Huginn's banner parser immediately cross-references this against the vulnerability database."

```bash
[SSH-AUDIT] Connecting to 10.10.10.3:22...
[SSH-AUDIT] Banner received: SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1
[SSH-AUDIT] Software: OpenSSH
[SSH-AUDIT] Version: 4.7p1
[SSH-AUDIT] OS Hint: Ubuntu (Debian-based)
[SSH-AUDIT] 
[SSH-AUDIT] === Vulnerability Analysis ===
[SSH-AUDIT] [CRITICAL] CVE-2008-5161: CBC mode cipher vulnerability (v4.7 affected)
[SSH-AUDIT] [HIGH] CVE-2016-20012: Information disclosure via timing side-channel
[SSH-AUDIT] [MEDIUM] Weak MAC algorithms supported: hmac-md5, hmac-sha1-96
[SSH-AUDIT] [INFO] User enumeration possible via CVE-2018-15473 (pre-auth timing)
[SSH-AUDIT] 
[SSH-AUDIT] Server supports: password, publickey, keyboard-interactive
[SSH-AUDIT] Root login: PERMITTED
[SSH-AUDIT] Password auth: ENABLED
[SSH-AUDIT] Empty passwords: DISABLED
```

**[Screen: Results panel showing vulnerability findings with severity ratings, CVE links]**

> "Multiple findings already. The server allows root login, supports password authentication, and runs a version with known cryptographic weaknesses. The CVE-2018-15473 finding tells us we can enumerate valid usernames before even attempting passwords. Root login permitted means we can target the root account directly — no need to find a regular user first and then escalate."

---

## SECTION 4: SSH Audit — Compliance Baseline Check (8:30 – 10:30)

**[Screen: Selecting CIS baseline in the audit configuration, clicking "Run Full Audit"]**

> "Let's run a full compliance audit against the CIS SSH benchmark. This checks not just vulnerabilities but overall security posture — algorithm strength, configuration hardening, rate limiting, and timeout settings."

```bash
[SSH-AUDIT] Running CIS Benchmark audit against 10.10.10.3:22...
[SSH-AUDIT] 
[SSH-AUDIT] === Cryptography Assessment ===
[SSH-AUDIT] [FAIL] Weak key exchange: diffie-hellman-group1-sha1 (1024-bit)
[SSH-AUDIT] [FAIL] Weak cipher: 3des-cbc, arcfour, blowfish-cbc
[SSH-AUDIT] [FAIL] Weak MAC: hmac-md5, hmac-ripemd160
[SSH-AUDIT] [PASS] AES-256-CTR supported
[SSH-AUDIT] [PASS] HMAC-SHA2-256 supported
[SSH-AUDIT] 
[SSH-AUDIT] === Authentication Assessment ===
[SSH-AUDIT] [FAIL] Root login permitted (CIS requires "no" or "prohibit-password")
[SSH-AUDIT] [FAIL] Password authentication enabled (CIS recommends key-only)
[SSH-AUDIT] [WARN] No login grace time limit detected
[SSH-AUDIT] [WARN] MaxAuthTries not restricted (default: 6)
[SSH-AUDIT] 
[SSH-AUDIT] === Security Features ===
[SSH-AUDIT] [FAIL] No connection rate limiting detected
[SSH-AUDIT] [FAIL] Banner does not suppress version information
[SSH-AUDIT] [WARN] TCP keepalive enabled (potential session hijack risk)
[SSH-AUDIT] 
[SSH-AUDIT] === Audit Summary ===
[SSH-AUDIT] Score: 23/100
[SSH-AUDIT] Status: NON-COMPLIANT
[SSH-AUDIT] Critical Findings: 4
[SSH-AUDIT] High Findings: 3
[SSH-AUDIT] Recommendations: 9
```

**[Screen: Audit results summary panel — score gauge showing 23/100, recommendation list]**

> "A score of 23 out of 100. This server fails on almost every CIS benchmark check. No rate limiting, root login permitted, password authentication enabled, weak ciphers supported. From an attacker's perspective, this is ideal — no brute-force protections exist. From a defender's perspective, every one of these findings represents a hardening opportunity. The lack of rate limiting is especially notable because it means we can run high-speed credential attacks without fear of lockout or throttling."

---

## SECTION 5: Configuring the Brute-Force Attack (10:30 – 12:30)

**[Screen: SSH Brute-Force tab — configuring target, username, wordlist selection]**

> "Now let's configure the credential attack. We know root login is allowed and there's no rate limiting, so we'll target root directly. Enter the target IP, set port 22, and in the username field, enter root. For the wordlist, Huginn ships with several built-in options."

```bash
Target: 10.10.10.3
Port: 22
Username: root
Wordlist: /wordlists/rockyou-top1000.txt
Max Threads: 10
Delay: 0.5s
Max Attempts: 1000
```

**[Screen: Wordlist dropdown showing options — "Top 100", "Top 1000", "RockYou-Full", "Custom..."]**

> "I'm selecting the RockYou top 1000 — a curated list of the most common passwords from the famous RockYou breach. In a real engagement, you'd choose your wordlist based on intelligence gathered during reconnaissance. If you discovered the organization uses a specific naming convention or found passwords in breach databases (see Video 19: Breach Intelligence), you'd build a custom targeted list."

**[Screen: Advanced options panel — showing timing configuration, lockout detection toggle, SSH key-based detection]**

> "In advanced options, we have lockout detection — Huginn monitors for lockout indicators and pauses automatically if detected. Since our audit showed no rate limiting, we can use a shorter delay. I'll set 0.5 seconds between attempts with 10 parallel threads. This balances speed with connection stability — too many simultaneous SSH connections can overwhelm the target's connection handler."

**[Screen: Additional configuration — SSH key detection option, banner re-check toggle]**

> "There's also an option to test for default SSH keys — checking if the server accepts well-known keys from appliances, IoT devices, or default installations. We won't use that here, but it's valuable against embedded systems and network devices."

---

## SECTION 6: Live Brute-Force Demonstration (12:30 – 14:30)

**[Screen: Clicking "Start Attack" — progress bar begins, live terminal output]**

> "Click Start Attack. Watch the terminal output — each attempt shows the username, the password tried, and the server's response. Most will show 'Authentication failed' but we're watching for that green success indicator."

```bash
[SSH-BRUTE] Starting brute-force against 10.10.10.3:22
[SSH-BRUTE] Target: root@10.10.10.3
[SSH-BRUTE] Wordlist: rockyou-top1000.txt (1000 entries)
[SSH-BRUTE] Threads: 10 | Delay: 0.5s
[SSH-BRUTE] 
[SSH-BRUTE] [001/1000] Trying: root:123456 — FAILED
[SSH-BRUTE] [002/1000] Trying: root:password — FAILED
[SSH-BRUTE] [003/1000] Trying: root:12345678 — FAILED
[SSH-BRUTE] [004/1000] Trying: root:qwerty — FAILED
[SSH-BRUTE] [005/1000] Trying: root:123456789 — FAILED
...
[SSH-BRUTE] [047/1000] Trying: root:master — FAILED
[SSH-BRUTE] [048/1000] Trying: root:dragon — FAILED
[SSH-BRUTE] [049/1000] Trying: root:login — FAILED
...
[SSH-BRUTE] [156/1000] Trying: root:msfadmin — SUCCESS ✓
[SSH-BRUTE] 
[SSH-BRUTE] ╔══════════════════════════════════════╗
[SSH-BRUTE] ║  CREDENTIAL FOUND                    ║
[SSH-BRUTE] ║  Username: root                      ║
[SSH-BRUTE] ║  Password: msfadmin                  ║
[SSH-BRUTE] ║  Target: 10.10.10.3:22               ║
[SSH-BRUTE] ║  Attempts: 156 of 1000               ║
[SSH-BRUTE] ║  Duration: 1m 18s                    ║
[SSH-BRUTE] ╚══════════════════════════════════════╝
```

**[Screen: Success notification — green banner with credential pair displayed, "Add to Findings" button highlighted]**

> "Found it — root:msfadmin. It took 156 attempts and about a minute and 18 seconds. This is a default credential from the Metasploitable project, which makes sense for this lab environment. In real-world engagements, you'll find default credentials, seasonal passwords like Summer2024, and organization-specific patterns far more often than you'd expect."

**[Screen: Clicking "Add to Findings" — showing the finding being catalogued with severity, evidence, timestamps]**

> "Click Add to Findings to document this credential discovery. Huginn automatically records the credential pair, target, timestamp, number of attempts, and categorizes it as a Critical finding. This goes into your engagement evidence for the final report."

---

## SECTION 7: SSH User Enumeration (14:30 – 16:00)

**[Screen: SSH User Enumeration tab — selecting enumeration method dropdown showing "Timing-Based", "CVE-2018-15473", "Response Analysis"]**

> "Beyond brute-forcing known usernames, Huginn can enumerate valid users on the SSH server. This is valuable when you don't know which accounts exist. The enumeration module offers three methods: timing-based analysis measures response time differences between valid and invalid usernames. CVE-2018-15473 exploits a specific OpenSSH vulnerability for reliable enumeration. Response analysis examines subtle differences in server responses."

```bash
[SSH-ENUM] Starting user enumeration against 10.10.10.3:22
[SSH-ENUM] Method: CVE-2018-15473 (OpenSSH < 7.7 user enumeration)
[SSH-ENUM] Username list: common-unix-users.txt (50 entries)
[SSH-ENUM] 
[SSH-ENUM] Testing: root — VALID ✓
[SSH-ENUM] Testing: admin — INVALID
[SSH-ENUM] Testing: user — VALID ✓
[SSH-ENUM] Testing: test — INVALID
[SSH-ENUM] Testing: ftp — VALID ✓
[SSH-ENUM] Testing: www-data — VALID ✓
[SSH-ENUM] Testing: nobody — VALID ✓
[SSH-ENUM] Testing: service — VALID ✓
[SSH-ENUM] Testing: mysql — VALID ✓
[SSH-ENUM] Testing: postgres — VALID ✓
...
[SSH-ENUM] Enumeration complete: 12 valid users found from 50 tested
[SSH-ENUM] Valid accounts: root, user, ftp, www-data, nobody, service, 
[SSH-ENUM]                 mysql, postgres, msfadmin, daemon, syslog, backup
```

**[Screen: Results table showing enumerated users — username, confidence level, method used]**

> "Twelve valid accounts discovered. Now we could run targeted brute-force attacks against each of these accounts instead of guessing usernames blindly. Notice service accounts like mysql, postgres, and ftp — these often have weak or default passwords because administrators assume they're not directly accessible. The msfadmin user confirms this is a Metasploitable-based system."

---

## SECTION 8: Password Spraying (16:00 – 17:00)

**[Screen: SSH Password Spray configuration — entering discovered usernames and a short password list]**

> "With our list of valid users, we can try password spraying — testing a small number of common passwords against all discovered accounts. This avoids lockout thresholds because each account only sees a few attempts. Huginn's password spray module adds configurable delays between rounds to mimic legitimate traffic patterns."

```bash
[SSH-SPRAY] Starting password spray against 10.10.10.3:22
[SSH-SPRAY] Users: 12 | Passwords: 5 | Delay between rounds: 30s
[SSH-SPRAY] 
[SSH-SPRAY] Round 1 — Password: "password"
[SSH-SPRAY]   root:password — FAILED
[SSH-SPRAY]   msfadmin:password — FAILED
[SSH-SPRAY]   user:user — FAILED
...
[SSH-SPRAY] Round 2 — Password: "{username}"
[SSH-SPRAY]   msfadmin:msfadmin — SUCCESS ✓
[SSH-SPRAY]   user:user — SUCCESS ✓
[SSH-SPRAY]   service:service — SUCCESS ✓
[SSH-SPRAY] 
[SSH-SPRAY] Spray complete: 3 credentials found
[SSH-SPRAY]   msfadmin:msfadmin | user:user | service:service
```

**[Screen: Results showing three successful credential pairs with "Add All to Findings" button]**

> "Three hits from password spraying — all accounts where the password matches the username. This is embarrassingly common in both lab environments and production systems. Each credential gives us a potential foothold, and the msfadmin account likely has elevated privileges worth investigating."

---

## SECTION 9: Certification Mapping and Practice (17:00 – 17:30)

**[Screen: Slide showing OSCP: Network Exploitation domain, CEH: System Hacking module]**

> "SSH brute-force and vulnerability assessment maps to OSCP's Network Exploitation domain — you'll encounter SSH services on exam machines regularly and need to recognize when credential attacks are appropriate versus when exploitation of version-specific vulnerabilities is the path forward. For CEH, this falls under System Hacking — specifically the Gaining Access phase using password attacks."

**[Screen: Practice recommendation — HTB "Lame" (this video), HTB "Shocker" (restricted shell), THM "Brute It" room]**

> "For more practice, HTB Shocker combines SSH with a restricted shell escape scenario. The TryHackMe Brute It room is purpose-built for practicing SSH brute-force methodology. Both are excellent follow-ups to reinforce these techniques in different scenarios."

---

## OUTRO (17:30 – end)

**[Screen: Summary slide — SSH Brute-Force: Banner Analysis → Vulnerability Check → User Enumeration → Credential Attack → Password Spray | Next: Video 37 — Database Attacks]**

> "That's SSH brute-force and vulnerability scanning in Huginn. We covered banner analysis for passive version detection, compliance auditing against security baselines, brute-force credential attacks with intelligent rate limiting, user enumeration via CVE-2018-15473, and password spraying across multiple accounts. In the next video, we move to database attacks — connecting to exposed MSSQL services and escalating from SQL access to operating system control. See you there."
