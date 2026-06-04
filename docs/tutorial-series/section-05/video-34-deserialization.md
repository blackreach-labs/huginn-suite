# VIDEO 34: Deserialization Attacks
### Insecure Deserialization, Gadget Chains & Object Injection
**Suggested length:** 14–18 minutes
**License Tier:** Free
**Certification Relevance:** OSCP: Web Application Attacks | CEH: Web Application Hacking

---

## INTRO (0:00 – 1:30)

**[Screen: Huginn splash screen with Section 5 title card "Web Application Exploitation"]**

> "Welcome back to the Huginn tutorial series. In this video we're covering deserialization attacks — one of the most dangerous web application vulnerabilities you'll encounter. Insecure deserialization can lead directly to remote code execution without any authentication, and it consistently appears on the OWASP Top 10 for good reason."

**[Screen: Slide showing serialization concept — object in memory → byte stream → transmitted → byte stream → reconstructed object]**

> "Serialization is the process of converting an in-memory object into a format that can be stored or transmitted — a byte stream, a string, or structured data. Deserialization reverses that process. The vulnerability occurs when an application deserializes untrusted data without proper validation, allowing an attacker to inject malicious objects that execute code when reconstructed. We'll use Huginn's deserialization detection and testing modules to identify and exploit these vulnerabilities in our THM lab environment."

**[Screen: Safety warning banner — red border, lock icon]**

> "Before we begin — this is a lab-only demonstration. Everything you see here runs against the TryHackMe Intro to Web Hacking room in an isolated environment. Never test deserialization exploits against systems you don't have explicit written authorization to test. These techniques achieve remote code execution — that's full system compromise. Unauthorized use is a serious criminal offense."

---

## SECTION 1: Understanding Serialization Formats (1:30 – 3:30)

**[Screen: Split diagram showing four serialization formats — Java, PHP, Python, .NET — each with their object representation and serialized form]**

> "Different languages serialize objects differently, and recognizing the format is the first step in exploitation. Let's look at the four most common formats Huginn can detect."

**[Screen: Java serialization — hex bytes `ac ed 00 05` highlighted, base64 equivalent `rO0AB` shown]**

> "Java serialized objects always begin with the magic bytes ac ed 00 05 in hex. When base64-encoded — which is common in cookies and parameters — they start with rO0AB. If you see either of these patterns in HTTP traffic, you've found a Java serialization endpoint."

**[Screen: PHP serialization — example `O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}` with labels]**

> "PHP serialization uses a human-readable format. Objects start with a capital O followed by the class name length and name. Properties are listed with their types — s for string, i for integer, a for array. The structure is predictable and directly editable, which makes PHP object injection particularly accessible."

**[Screen: Python pickle — binary format with opcodes labeled, and .NET BinaryFormatter with ViewState example]**

> "Python uses pickle — a binary protocol with opcodes that can execute arbitrary code during deserialization. .NET uses BinaryFormatter or the ViewState mechanism in ASP.NET applications. The __VIEWSTATE field in web forms is a common attack surface. Huginn's detection module checks for signatures across all four formats automatically."

---

## SECTION 2: Huginn's Deserialization Detection Module (3:30 – 5:30)

**[Screen: Huginn application — navigating from Home to Web Exploits page, selecting Deserialization from the exploit categories]**

> "Let's open Huginn and navigate to the deserialization tools. From the home screen, go to Web Exploits, and you'll find Deserialization in the exploit category list. The module has two components — the Deserialization Detector for passive identification and the Deserialization Tester for active exploitation."

**[Screen: Deserialization Detector interface — showing cookie analysis panel with signature database]**

> "The Detector passively analyzes cookies, hidden form fields, and URL parameters for serialization signatures. It checks base64-encoded data against known magic bytes — Java's ac ed 00 05, PHP's O: and a: prefixes, Python's pickle opcodes, and .NET ViewState patterns. When it finds a match, it flags the parameter with severity and CVSS score."

```python
# Huginn's signature database (from deserialization_detector.py)
signatures = {
    'java': [b'\xac\xed\x00\x05', 'rO0AB'],
    'dotnet': ['__VIEWSTATE', 'System.', 'mscorlib'],
    'php': ['O:', 'a:', 's:', 'i:', 'b:', 'd:'],
    'python': ['pickle', 'cPickle', '\x80\x03']
}
```

**[Screen: Deserialization Tester interface — showing payload library with format selection dropdown]**

> "The Tester takes it further. Once a serialization endpoint is identified, it sends format-specific payloads to confirm the vulnerability and test for code execution. It includes pre-built payloads for Java, PHP, Python, and .NET — both detection payloads that trigger error messages and exploitation payloads that attempt command execution."

---

## SECTION 3: Lab Setup — THM Insecure Deserialization (5:30 – 7:00)

**[Screen: TryHackMe dashboard — navigating to "Intro to Web Hacking" room, Insecure Deserialization section]**

> "For our demonstration, we're using the TryHackMe Intro to Web Hacking room — specifically the Insecure Deserialization section. This room has intentionally vulnerable applications running both Java and PHP deserialization endpoints. Start the target machine and wait for the IP address."

**[Screen: THM room showing deployed machine IP address (e.g., 10.10.x.x)]**

> "The machine is up at 10.10.45.128. Let's configure Huginn with this target. In the target field, enter the machine's IP address with the web port."

```bash
Target: http://10.10.45.128
Port: 80
```

**[Screen: Huginn target configuration — entering the THM machine IP, selecting Deserialization scan mode]**

> "We'll start with the detection phase — running the Deserialization Detector against the application to identify serialized data in transit before we attempt any exploitation."

---

## SECTION 4: Identifying Serialized Objects (7:00 – 9:30)

**[Screen: Running the Deserialization Detector — scanning cookies and parameters on the target application]**

> "Click Start Scan. The detector crawls the application, captures cookies and form parameters, and analyzes each one against the signature database. Watch the results panel as findings come in."

```bash
[DESER] Scanning http://10.10.45.128 for serialized objects...
[DESER] Analyzing cookies...
[DESER] Cookie 'session_data': Base64 encoded, length 248
[DESER] DETECTED: Java serialized object in cookie 'session_data'
[DESER]   Magic bytes: ac ed 00 05 (Java ObjectInputStream)
[DESER]   Severity: CRITICAL | CVSS: 9.8
[DESER] Analyzing form parameters...
[DESER] POST /profile — parameter 'user_prefs': PHP serialized object detected
[DESER]   Pattern: O:4:"User":2:{...}
[DESER]   Severity: HIGH | CVSS: 8.1
[DESER] Scan complete: 2 serialization endpoints identified
```

**[Screen: Results panel showing two findings — Java cookie and PHP form parameter — with severity badges]**

> "We've found two serialization endpoints. The first is a Java serialized object stored in the session_data cookie — the detector identified the ac ed magic bytes after base64 decoding. That gets a Critical severity rating with a CVSS of 9.8 because Java deserialization commonly leads to RCE. The second is a PHP serialized object in the user_prefs POST parameter — the O: prefix gives it away immediately."

**[Screen: Expanding the Java finding — showing the raw base64 cookie value and decoded hex view]**

> "Let's look at the Java finding in detail. The cookie value starts with rO0AB when base64-encoded — that's our smoking gun. Huginn automatically decoded it and confirmed the serialization header. This tells us the server is using Java's ObjectInputStream to reconstruct objects from cookie data — a textbook insecure deserialization pattern."

---

## SECTION 5: Java Exploitation with ysoserial Payloads (9:30 – 12:00)

**[Screen: Switching to Deserialization Tester — selecting the Java finding, choosing payload type]**

> "Now we move to exploitation. Select the Java finding and switch to the Tester module. Huginn includes pre-built ysoserial-style payloads — serialized Java objects that leverage known library gadget chains to achieve code execution during deserialization."

**[Screen: Payload library — showing available Java gadget chains: CommonsCollections, Spring, Groovy]**

> "The payload library shows available gadget chains. CommonsCollections is the most common — it exploits the Apache Commons Collections library that's bundled with countless Java applications. Each chain targets specific library versions. Huginn tests them systematically."

**[Screen: Configuring the exploitation — selecting CommonsCollections chain, entering test command 'id']**

> "We'll start with a detection payload using the CommonsCollections chain. The command we want to execute is 'id' — this prints the current user context on Linux systems. If we see uid and gid in the response, we've confirmed remote code execution."

```bash
[DESER] Testing Java deserialization on cookie 'session_data'
[DESER] Payload: CommonsCollections (gadget chain)
[DESER] Command: id
[DESER] Encoding payload to base64...
[DESER] Sending modified cookie to http://10.10.45.128/dashboard
[DESER] Response analysis:
[DESER]   ✓ Command output detected in response
[DESER]   Response contains: uid=33(www-data) gid=33(www-data)
[DESER] CONFIRMED: Remote Code Execution via Java Deserialization
[DESER] Severity: CRITICAL
```

**[Screen: Response panel showing the command output — uid=33(www-data) visible in the page content]**

> "There it is — remote code execution confirmed. The server deserialized our malicious object, triggered the CommonsCollections gadget chain, and executed the id command. We're running as www-data — the web server user. From here, an attacker could read files, establish reverse shells, or pivot deeper into the network."

**[Screen: Showing the crafted payload in hex view and the modified cookie before/after]**

> "Let's look at what happened under the hood. Huginn replaced the legitimate session cookie with a crafted serialized object containing the gadget chain. When the server called ObjectInputStream.readObject() on our cookie, the chain of method calls ultimately invoked Runtime.exec() with our command. This is why Java deserialization is so dangerous — the execution happens automatically during reconstruction."

---

## SECTION 6: PHP Object Injection (12:00 – 14:30)

**[Screen: Switching to the PHP finding — user_prefs parameter on the /profile endpoint]**

> "Let's move to the PHP target. Select the user_prefs finding. PHP object injection works differently from Java — instead of binary gadget chains, we craft serialized PHP objects that manipulate class properties to achieve unintended behavior."

**[Screen: Showing the original PHP serialized value — `O:4:"User":2:{s:4:"name";s:7:"student";s:4:"role";s:4:"user";}`]**

> "Here's the original serialized object. It's a User object with name set to 'student' and role set to 'user'. The format is readable — we can directly modify properties. But the real power comes from injecting objects of different classes that have dangerous magic methods like __wakeup or __destruct."

**[Screen: Huginn crafting a PHP injection payload — modifying the serialized object to inject a privileged role]**

> "First, let's try a simple property manipulation. We'll change the role from 'user' to 'admin' and see if the application trusts the deserialized value without validation."

```bash
[DESER] Testing PHP deserialization on parameter 'user_prefs'
[DESER] Original: O:4:"User":2:{s:4:"name";s:7:"student";s:4:"role";s:4:"user";}
[DESER] Modified: O:4:"User":2:{s:4:"name";s:7:"student";s:4:"role";s:5:"admin";}
[DESER] Sending to POST http://10.10.45.128/profile
[DESER] Response: 200 OK — Page now shows "Welcome, admin" with elevated privileges
[DESER] CONFIRMED: PHP Object Injection — privilege escalation via property manipulation
```

**[Screen: Response showing the application now treats the user as admin — admin panel links visible]**

> "The application deserialized our modified object and used the role property directly for access control. We escalated from user to admin by changing five characters in a serialized string. This is insecure deserialization at its most basic — trusting client-supplied serialized data."

**[Screen: Attempting RCE via PHP magic methods — crafting object with __destruct calling system()]**

> "For code execution, Huginn attempts to inject objects with dangerous magic methods. If the application has a class with a __destruct or __wakeup method that processes user-controlled properties unsafely, we can chain that to system calls."

```bash
[DESER] Testing PHP RCE via magic methods...
[DESER] Payload: O:14:"DatabaseExport":1:{s:4:"file";s:23:"/tmp/test;id > /tmp/rce";}
[DESER] Response analysis: checking for command execution indicators...
[DESER] CONFIRMED: PHP deserialization RCE via __destruct() in DatabaseExport class
[DESER]   Output: uid=33(www-data) gid=33(www-data)
```

**[Screen: Results showing successful RCE — explaining the __destruct chain that led to code execution]**

> "The DatabaseExport class has a __destruct method that writes to a file path stored in the 'file' property. By injecting a path with a semicolon and command, we achieved command injection through deserialization. This is a two-step chain — deserialization leads to object creation, the destructor triggers file operations with our controlled input, and the shell metacharacter gives us execution."

---

## SECTION 7: Remediation and Findings Export (14:30 – 16:30)

**[Screen: Findings summary panel — showing both Java and PHP deserialization findings with CVSS scores]**

> "Let's review our findings. We have two confirmed deserialization vulnerabilities — a Critical Java RCE via CommonsCollections gadget chain and a High-severity PHP object injection leading to privilege escalation and RCE. Huginn assigns CVSS scores automatically — 9.8 for the Java finding and 8.1 for the PHP finding."

**[Screen: Remediation recommendations panel — showing language-specific fixes]**

> "The remediation guidance is language-specific. For Java — avoid ObjectInputStream with untrusted data entirely. Use allow-lists to restrict which classes can be deserialized, or switch to safer serialization formats like JSON. For PHP — never use unserialize() on user input. Use json_decode() instead, or implement signature verification (HMAC) on serialized data before deserializing."

```bash
# Huginn Remediation Summary:
# Java: Replace ObjectInputStream with JSON parsing, or implement class allow-listing
# PHP: Replace unserialize() with json_decode(), add HMAC validation
# General: Never deserialize untrusted data without cryptographic integrity checks
```

**[Screen: Exporting findings to JSON — clicking Export, selecting format]**

> "Export these findings for your engagement report. Click Export and choose JSON or CSV. The exported data includes the vulnerability type, affected endpoint, payload that confirmed the issue, CVSS score, and remediation steps. These findings flow directly into Huginn's reporting module covered later in Section 9."

---

## SECTION 8: Certification Mapping and Practice (16:30 – 17:30)

**[Screen: Slide showing certification mapping — OSCP: Web Application Attacks domain, CEH: Web Application Hacking module]**

> "Deserialization attacks map to the OSCP Web Application Attacks domain. While ysoserial payloads are less common on the OSCP exam itself, understanding serialization formats is critical for identifying attack surfaces. For CEH, this falls under Module 14 — Hacking Web Applications — covering session management attacks and input validation bypasses."

**[Screen: Practice resources — THM "Intro to Web Hacking" deserialization tasks, HTB machines with deserialization vectors]**

> "For additional practice, complete all the deserialization tasks in the THM room we used today. On Hack The Box, machines like 'Arkham' feature Java deserialization and 'Cereal' involves .NET deserialization. Practice identifying serialized data in cookies and parameters — pattern recognition is key."

---

## OUTRO (17:30 – end)

**[Screen: Summary slide — Deserialization Attacks: Format Identification, Java ysoserial, PHP Object Injection, RCE Chains | Next: Video 35 — HTTP Interceptor]**

> "That's deserialization attacks in Huginn. We identified serialized objects using signature detection, exploited Java deserialization through ysoserial gadget chains for RCE, and demonstrated PHP object injection for both privilege escalation and code execution. In the next video, we'll cover the HTTP Interceptor — Huginn's built-in proxy for request interception, modification, and replay. See you there."
