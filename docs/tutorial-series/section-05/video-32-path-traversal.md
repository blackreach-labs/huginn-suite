# VIDEO 32: Path Traversal
### Directory Traversal, File Inclusion & Null Byte Techniques
**Suggested length:** 14–18 minutes
**License Tier:** Free
**Certification Relevance:** OSCP: Web Application Attacks | CEH: Web Application Hacking

---

> ⚠️ **SAFETY WARNING:** All demonstrations in this video use DVWA (Damn Vulnerable Web Application) running locally in an isolated lab environment. Path traversal and local file inclusion attacks against systems without explicit written authorization is illegal and unethical. Never use these techniques outside of authorized penetration tests or dedicated practice labs.

---

## INTRO (0:00 – 1:30)

**[Screen: Huginn splash screen with Section 5 title card "Web Application Exploitation"]**

> "Welcome back to the Huginn tutorial series. This video covers path traversal and local file inclusion — two closely related vulnerabilities that let you read arbitrary files from the server. When a web application includes files based on user input without proper validation, you can manipulate the file path to escape the intended directory and access sensitive system files like /etc/passwd, configuration files with database credentials, or even achieve remote code execution through techniques like log poisoning and PHP wrappers."

**[Screen: Slide showing the relationship — Path Traversal (reading files) → LFI (including/executing files) → RCE (code execution via inclusion)]**

> "Path traversal and LFI exist on a spectrum. Basic path traversal reads file contents. Local file inclusion actually executes the file through the application's include mechanism — which means if you can control the contents of a file on the server, inclusion becomes code execution. We'll demonstrate the full chain against DVWA's File Inclusion module, starting at Security Level Low and escalating to Medium with encoding-based filter bypass. This builds on the injection concepts from Video 28 (see Video 28: SQL Injection) and the command injection techniques from the previous video (see Video 31: Command Injection)."

---

## SECTION 1: Path Traversal Fundamentals (1:30 – 3:30)

**[Screen: Diagram showing directory structure — web root at /var/www/html, traversal climbing up to /etc/passwd]**

> "Path traversal exploits how operating systems resolve relative file paths. The dot-dot-slash sequence — ../ — means 'go up one directory'. If an application includes a file like 'include.php?page=contact.php', it's reading from a specific directory — say /var/www/html/pages/. But if you replace the filename with '../../../etc/passwd', the path resolves to /var/www/html/pages/../../../etc/passwd, which normalizes to /etc/passwd. You've escaped the web root entirely."

**[Screen: Code showing vulnerable PHP include — include($_GET['page']); with no validation]**

> "The vulnerable pattern is straightforward. In PHP: include($_GET['page']). The developer expects values like 'home.php' or 'about.php'. They don't anticipate someone providing a path that traverses upward. On Windows systems, the same technique uses backslashes: '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts'. The principle is identical — climb the directory tree to reach sensitive files."

**[Screen: Table showing common target files — /etc/passwd, /etc/shadow, /proc/self/environ, application config files]**

> "Key files to target during path traversal: /etc/passwd reveals user accounts and sometimes hints at services. /etc/shadow contains password hashes if readable. /proc/self/environ exposes environment variables that might contain credentials. Application configuration files like wp-config.php, .env files, or database.yml contain database credentials. Apache and Nginx access/error logs are crucial for the log poisoning technique we'll cover later."

```
# High-value Linux targets:
/etc/passwd              # User accounts
/etc/shadow              # Password hashes (requires root)
/etc/hosts               # Network configuration
/proc/self/environ       # Environment variables
/var/log/apache2/access.log  # Apache access log (log poisoning)
/var/log/apache2/error.log   # Apache error log

# Application files:
../config/database.yml   # Database credentials
../.env                  # Environment configuration
../wp-config.php         # WordPress credentials

# Windows targets:
C:\windows\system32\drivers\etc\hosts
C:\windows\win.ini
C:\inetpub\wwwroot\web.config
```

---

## SECTION 2: Huginn Path Traversal Interface (3:30 – 5:30)

**[Screen: Huginn application — navigating to Web Exploits → Path Traversal / File Inclusion module]**

> "Open Huginn and navigate to the Web Exploits page. The Path Traversal tester is part of the file inclusion testing suite. Huginn's PathTraversalTester class combines three approaches: it scans form fields for file-related parameters, tests URL parameters for traversal, and uses content discovery to identify inclusion endpoints."

**[Screen: Path Traversal interface showing target URL, parameter detection, payload depth configuration, and results]**

> "The interface shows the target URL configuration at the top, detected parameters in the center — Huginn looks for field names containing 'file', 'path', 'dir', 'page', 'include', 'template', or 'doc' — and the results panel on the right. The payload configuration lets you set the traversal depth, choose between Unix and Windows path separators, and select encoding options for bypass attempts."

**[Screen: Payload configuration showing depth slider (1-10 levels), OS selection (Linux/Windows/Both), and encoding options]**

> "The tool tests multiple payload variants automatically. It starts with simple '../../../etc/passwd' and progresses to encoded versions — URL encoding, double encoding, and mixed-case variants. On Windows targets, it tests both forward and backslashes. The indicator detection checks response content for known file signatures: 'root:x:0:0:' for passwd, '[boot loader]' for win.ini, and other OS-specific markers."

---

## SECTION 3: DVWA Setup — File Inclusion at Low Security (5:30 – 7:00)

**[Screen: DVWA logged in → Security Level set to Low → navigating to File Inclusion module]**

> "In DVWA, navigate to the File Inclusion module. At Security Level Low, the application uses a completely unfiltered include statement. Notice the URL structure — it includes a 'page' parameter that determines which file gets loaded."

```
Target: http://localhost/dvwa/vulnerabilities/fi/
URL Pattern: ?page=include.php
Security Level: Low
```

**[Screen: DVWA File Inclusion page — showing URL with ?page=include.php, page content loaded normally]**

> "The default URL shows '?page=include.php' and the page displays some included content. The 'page' parameter is our injection point. At Low security, whatever value we put in that parameter gets passed directly to an include() call — no filtering, no path restriction, nothing. Let's start traversing."

---

## SECTION 4: Basic Path Traversal — Reading /etc/passwd (7:00 – 9:30)

**[Screen: Modifying URL to ?page=../../../etc/passwd → page displays passwd file contents]**

> "Replace the page parameter value with a traversal path. Start with '../../../etc/passwd'. The number of ../ sequences depends on how deep the web root is. Three levels is usually enough for a standard Apache installation at /var/www/html. If it doesn't work, add more levels — the filesystem can't traverse above root, so extra ../ sequences are harmless."

```bash
# Basic path traversal
URL: http://localhost/dvwa/vulnerabilities/fi/?page=../../../etc/passwd

# Response shows:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false
...
```

**[Screen: Browser showing /etc/passwd contents rendered in the page]**

> "The entire passwd file renders in the page. We can see all user accounts on the system — root, daemon, www-data, mysql. The www-data account confirms this is an Apache server. The mysql account tells us a database is running locally. Each of these is intelligence for the next phase of the attack."

**[Screen: Testing deeper traversal — ../../../../etc/passwd with varying depths]**

> "If three levels don't work, increase the depth. Five levels of traversal — '../../../../../etc/passwd' — works from virtually any web root location. Extra traversals past the filesystem root are simply ignored. This is why absolute path access — '/etc/passwd' — also works on many systems."

```bash
# Absolute path (works if include allows it)
URL: http://localhost/dvwa/vulnerabilities/fi/?page=/etc/passwd

# Deep traversal (always safe to over-traverse)
URL: http://localhost/dvwa/vulnerabilities/fi/?page=../../../../../etc/passwd
```

**[Screen: Huginn automated scan running against DVWA File Inclusion — showing CRITICAL LFI finding]**

> "Huginn's PathTraversalTester identifies this immediately. It detects the 'page' parameter by name — 'page' matches the keyword list — tests the traversal payload, and confirms the vulnerability when it finds 'root:x:0:0:' in the response. The finding is reported as CRITICAL severity with the exact payload that succeeded."

---

## SECTION 5: LFI to RCE — Log Poisoning (9:30 – 12:00)

**[Screen: Slide explaining log poisoning — "Inject PHP into logs → Include the log file → Code executes"]**

> "Reading files is useful for reconnaissance, but the real power of LFI is achieving code execution. Log poisoning is the most common technique. Here's the concept: Apache logs every HTTP request, including the User-Agent header. If we send a request with PHP code in the User-Agent, that code gets written to the access log. Then when we include the log file via LFI, PHP parses and executes our injected code."

**[Screen: Step 1 — Sending a request with PHP code in User-Agent header using curl]**

> "Step one: inject PHP into the Apache access log. We'll use curl to send a request with a crafted User-Agent header. The PHP code we inject is simple: a system() call that executes whatever command we pass via a query parameter."

```bash
# Step 1: Poison the Apache access log with PHP code
curl -A "<?php system(\$_GET['cmd']); ?>" http://localhost/dvwa/

# This writes the following to /var/log/apache2/access.log:
# 127.0.0.1 - - [date] "GET /dvwa/ HTTP/1.1" 200 ... "<?php system($_GET['cmd']); ?>"
```

**[Screen: Step 2 — Including the poisoned log file via LFI with a command parameter]**

> "Step two: include the log file through the LFI vulnerability, adding our command parameter. When PHP includes the log file, it encounters our injected PHP tag and executes it."

```bash
# Step 2: Include the poisoned log file with a command
URL: http://localhost/dvwa/vulnerabilities/fi/?page=../../../var/log/apache2/access.log&cmd=id

# Response contains (among log entries):
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**[Screen: Browser showing command output embedded within log file contents — "uid=33(www-data)"]**

> "We have code execution through file inclusion. The 'id' command output appears inline with the log entries. From here, we can run any command — read configuration files, establish a reverse shell, or enumerate the network. This turns a file-read vulnerability into complete server compromise."

**[Screen: Slide showing the complete attack chain — LFI → Log Poisoning → Webshell → Reverse Shell]**

> "The full exploitation chain: discover LFI, identify a writable log file accessible via traversal, inject PHP into the log through a controlled header, include the log to trigger execution, then upgrade to a proper reverse shell for persistent access. In OSCP, demonstrating this full chain is a strong indicator of web exploitation competence."

---

## SECTION 6: PHP Wrapper Techniques (12:00 – 14:00)

**[Screen: Slide showing PHP wrappers — php://filter, php://input, data://, expect://]**

> "PHP stream wrappers provide another path from LFI to information disclosure and code execution — without needing log poisoning. The php://filter wrapper lets you read source code files that would normally be executed rather than displayed. The php://input and data:// wrappers can achieve direct code execution if allow_url_include is enabled."

**[Screen: Using php://filter to read source code — base64 encoding the output]**

> "The php://filter wrapper is the most universally useful. When you include a PHP file normally, it executes and you only see the output. With php://filter, you can base64-encode the file contents before inclusion — bypassing execution entirely and revealing the source code."

```bash
# Read PHP source code using php://filter (base64 encoded)
URL: http://localhost/dvwa/vulnerabilities/fi/?page=php://filter/convert.base64-encode/resource=../../../var/www/html/dvwa/config/config.inc.php

# Response (base64 encoded):
PD9waHAKCiMgSWYgeW91IGFyZSBoYXZpbmcgcHJvYmxlbXMgY29ubmVjdGluZyB0byB0aGUg...

# Decode to reveal:
# <?php
# $DBMS = 'MySQL';
# $_DVWA['db_server']   = '127.0.0.1';
# $_DVWA['db_database'] = 'dvwa';
# $_DVWA['db_user']     = 'dvwa';
# $_DVWA['db_password'] = 'p@ssw0rd';
```

**[Screen: Decoded base64 showing DVWA config with database credentials]**

> "After base64 decoding, we have the complete DVWA configuration file — including database credentials. This is how you extract source code through LFI without executing it. In a real engagement, you'd target files like wp-config.php, .env, or custom application configuration files."

**[Screen: Using data:// wrapper for direct code execution]**

> "When allow_url_include is enabled — which it is in DVWA Low — the data:// wrapper achieves direct code execution without any file on disk:"

```bash
# Direct code execution via data:// wrapper (requires allow_url_include=On)
URL: http://localhost/dvwa/vulnerabilities/fi/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==

# base64 decodes to: <?php system('id'); ?>
# Output: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

> "The data:// wrapper embeds code directly in the URL — base64 encoded to avoid special character issues. This is cleaner than log poisoning when URL inclusion is permitted. In practice, allow_url_include is commonly disabled in production, making log poisoning the more reliable technique."

---

## SECTION 7: Filter Bypass — Medium Security (14:00 – 16:00)

**[Screen: DVWA Security page — changing to Medium → navigating back to File Inclusion]**

> "Change DVWA to Security Level Medium. The Medium level implements a basic filter to prevent path traversal. Let's see what it blocks and how to bypass it."

**[Screen: Testing "../../../etc/passwd" — showing it no longer works]**

> "Try our standard payload: '../../../etc/passwd'. The page loads but shows an error or blank content — the filter is stripping our traversal sequences. DVWA Medium uses str_replace() to remove '../' and '..\' from the input. But str_replace only runs once — it doesn't apply recursively."

```bash
# Blocked at Medium security:
Input: ../../../etc/passwd          → Stripped to "etc/passwd" (fails)
Input: ..\..\..\etc\passwd          → Stripped (fails)
```

**[Screen: Demonstrating double-encoding bypass — "....//....//....//etc/passwd"]**

> "The bypass is simple: nest the traversal sequences so that after the filter strips the inner pattern, the outer characters form a valid traversal. Use '....//....//....//etc/passwd'. When str_replace removes '../' from '..../', what remains is '../' — exactly what we need."

```bash
# Bypass with nested traversal:
Input: ....//....//....//etc/passwd

# Filter processing:
# "..../" → strips "../" from middle → leaves "../"
# Result after filtering: ../../../etc/passwd
# Successfully traverses!

# Alternative bypass with URL encoding:
Input: ..%2F..%2F..%2Fetc%2Fpasswd

# Double URL encoding:
Input: %2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

**[Screen: Successful traversal at Medium level — /etc/passwd displayed using nested bypass]**

> "And we're back — /etc/passwd displays successfully. URL encoding is another bypass vector. The sequence %2e%2e%2f decodes to '../'. If the filter checks before URL decoding, or if the web server decodes after the filter runs, encoding bypasses the check entirely. Double encoding — %252e%252e%252f — works against applications that decode twice."

**[Screen: Huginn scan results showing bypass payloads that succeeded at Medium security]**

> "Huginn's traversal tester includes these encoding variants automatically. It tests plain traversal first, then URL-encoded, double-encoded, and nested variants. Against DVWA Medium, it identifies the nested '....//....//....//etc/passwd' payload as successful and reports it alongside the blocked variants — showing you exactly which filter bypass technique works."

---

## SECTION 8: Certification Mapping and Practice (16:00 – 17:00)

**[Screen: Certification mapping — OSCP: Web Application Attacks (LFI/RFI), CEH: Module 14]**

> "Path traversal and LFI map to the OSCP Web Application Attacks domain — specifically the file inclusion subsection. On the OSCP exam, LFI-to-RCE via log poisoning is a well-known technique for the web application machine. For CEH, this covers Module 14 file inclusion attacks and directory traversal concepts."

**[Screen: Practice resources list — DVWA all levels, THM "File Inclusion" room, HTB machines]**

> "For practice, work through all DVWA File Inclusion security levels. High level uses a whitelist with a bypass — only 'file' prefix is allowed, so 'file:///etc/passwd' works. TryHackMe has the 'File Inclusion' room with step-by-step guidance. On Hack The Box, 'Nineveh' and 'Poison' feature LFI as key attack vectors. Practice the full chain: discover LFI, confirm with /etc/passwd, escalate to RCE through log poisoning or PHP wrappers."

---

## OUTRO (17:00 – end)

**[Screen: Summary slide — Path Traversal: ../ traversal, LFI to RCE (log poisoning, PHP wrappers), Filter bypass (encoding, nesting) | Next: Video 33 — SSRF]**

> "That's path traversal and local file inclusion in Huginn. We covered basic directory traversal to read system files, escalated LFI to remote code execution through log poisoning and PHP stream wrappers, and demonstrated encoding-based filter bypass against DVWA's Medium security. In the next video, we'll cover Server-Side Request Forgery — forcing the server to make requests on our behalf to access internal services and cloud metadata endpoints. See you there."
