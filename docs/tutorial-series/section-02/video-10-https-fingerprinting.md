# VIDEO 10: HTTP/S Fingerprinting
### Technology Detection, Header Analysis & WAF Identification
**Suggested length:** 14–18 minutes
**License Tier:** Free
**Certification Relevance:** OSCP: Information Gathering | CEH: Enumeration

---

## INTRO (0:00 – 0:50)

**[Screen: Huginn main dashboard with the Recon & Enumeration page open. HTTP/S Fingerprinting panel visible.]**

> "Welcome back to the Huginn tutorial series. In this video we're covering HTTP and HTTPS fingerprinting — the process of identifying what technologies a web server is running without touching any application logic. When you find ports 80 or 443 open on a target, fingerprinting is your first step before launching any web exploitation. We'll analyze HTTP response headers, detect the technology stack — server software, frameworks, CMS platforms — and inspect SSL/TLS certificates for misconfigurations. Our target today is scanme.nmap.org, the Nmap project's authorized scanning target. Let's get into it."

---

## SECTION 1: Understanding HTTP/S Fingerprinting (0:50 – 3:00)

**[Screen: Diagram showing HTTP request/response cycle with headers highlighted — Server, X-Powered-By, Set-Cookie, Content-Type.]**

> "HTTP fingerprinting is about extracting information from how a web server responds, not what content it serves. Every HTTP response includes headers that can reveal the server software, programming language, framework, and even specific version numbers. Some servers are configured to suppress this information, but most leak enough for us to build a technology profile."

**[Screen: Table of common revealing headers — Server, X-Powered-By, X-AspNet-Version, X-Generator, Via, X-Cache.]**

> "The Server header is the most obvious — it typically identifies the web server software and version, like 'Apache/2.4.49' or 'nginx/1.21.4'. X-Powered-By reveals the backend language or framework — 'PHP/7.4.3' or 'Express'. Set-Cookie headers can identify session management frameworks through cookie naming patterns. Even error responses leak information — a 404 page styled by Apache looks different from one styled by nginx or IIS."

**[Screen: Slide showing technology fingerprinting methods — Header analysis, HTML pattern matching, JavaScript library detection, Cookie analysis, Error page fingerprinting.]**

> "Huginn combines multiple fingerprinting methods. Header analysis catches explicit declarations. HTML pattern matching looks for CMS signatures in the page source — WordPress leaves 'wp-content' paths everywhere, Joomla uses '/administrator/', React apps include specific script bundles. Cookie analysis identifies frameworks by their default cookie names. And TLS certificate inspection can reveal infrastructure details through certificate subject names, issuers, and Subject Alternative Names."

---

## SECTION 2: Huginn HTTP/S Fingerprinting Interface (3:00 – 5:00)

**[Screen: Huginn Recon & Enumeration page → Service Scanners tab → HTTP/S Fingerprinting selected from the protocol dropdown.]**

> "In Huginn, navigate to Recon and Enumeration, then Service Scanners, and select HTTP/S Fingerprinting from the protocol dropdown. This opens the fingerprinting panel with target and scan options."

**[Screen: Close-up of HTTP/S configuration panel showing Target URL, Port, Protocol (HTTP/HTTPS/Both), and Scan Depth dropdown.]**

> "The configuration is straightforward. Enter your target URL or IP — you can use a hostname or IP address. The Port field defaults to 80 for HTTP and 443 for HTTPS. The Protocol selector lets you choose HTTP only, HTTPS only, or Both to fingerprint both services. Scan Depth controls how thorough the fingerprinting is — Quick just checks headers, Standard adds HTML analysis and technology detection, and Deep includes full TLS inspection and security header auditing."

**[Screen: Scan Depth dropdown expanded showing: Quick (headers only), Standard (headers + tech detection), Deep (full analysis + TLS).]**

> "For this demo we'll use Deep to demonstrate all of Huginn's fingerprinting capabilities. In practice, Quick mode takes under a second and gives you the server software immediately. Standard adds maybe two seconds for technology pattern matching. Deep is still fast — usually under ten seconds — but adds the full TLS handshake analysis."

---

## SECTION 3: Configuration for Our Target (5:00 – 6:30)

**[Screen: HTTP/S panel configured — Target: scanme.nmap.org, Port: 80, Protocol: Both, Scan Depth: Deep.]**

> "Let's configure for scanme.nmap.org — the Nmap project's public target authorized for scanning demonstrations. We know from our port scan that port 80 is open (see Video 6: Port Scanning). I'll set protocol to Both so we can check if HTTPS is also available, and scan depth to Deep for the full analysis. This target is explicitly authorized for this kind of testing by the Nmap project."

**[Screen: Advanced options showing User-Agent string, Follow Redirects toggle, Custom Headers field, and Timeout.]**

> "Under advanced options, you can customize the User-Agent string — some WAFs block requests from scanning tools, so you might want to use a browser-like User-Agent. Follow Redirects controls whether Huginn follows 301/302 responses to fingerprint the final destination. Custom Headers lets you add authentication tokens if you're fingerprinting an authenticated endpoint. For a public target like scanme.nmap.org, defaults are fine."

---

## SECTION 4: Live Demonstration — Header Analysis (6:30 – 9:30)

**[Screen: Huginn HTTP/S scanner ready to run. Target: scanme.nmap.org. Start Scan button highlighted.]**

> "Let's start the fingerprinting scan and watch what Huginn discovers from the HTTP response alone."

```bash
# HTTP request to scanme.nmap.org
GET / HTTP/1.1
Host: scanme.nmap.org
User-Agent: Huginn/1.0

# HTTP response headers
HTTP/1.1 200 OK
Server: Apache/2.4.7 (Ubuntu)
Content-Type: text/html
Last-Modified: Mon, 12 Feb 2024 14:30:00 GMT
ETag: "2a4f-5f1234567890"
Accept-Ranges: bytes
Content-Length: 10831
Connection: Keep-Alive
```

**[Screen: Huginn output panel showing parsed headers with the Server header highlighted in green: "Apache/2.4.7 (Ubuntu)".]**

> "The Server header immediately tells us this is Apache version 2.4.7 running on Ubuntu. That's already actionable intelligence — we know the exact web server software and can look up known vulnerabilities for that version. Notice there's no X-Powered-By header, which means either no backend framework is exposed or the server is configured to suppress it. The ETag format and Accept-Ranges header are consistent with Apache's default behavior."

**[Screen: Huginn security headers analysis panel showing missing headers flagged in amber — no X-Frame-Options, no Content-Security-Policy, no Strict-Transport-Security.]**

> "Huginn also audits security headers. On scanme.nmap.org we see several missing security headers — no X-Frame-Options which could allow clickjacking, no Content-Security-Policy, and no Strict-Transport-Security. For a scanning target this is expected, but on a production application these gaps would be findings worth documenting. The security header analysis gives you a quick security posture assessment without any active testing."

---

## SECTION 5: Live Demonstration — Technology Detection (9:30 – 12:30)

**[Screen: Huginn technology detection panel showing identified technologies with confidence levels.]**

> "Now let's look at the technology detection results. Huginn scanned the HTML source and identified technologies through pattern matching."

```bash
# Technology fingerprinting results
Server Software: Apache/2.4.7 (Ubuntu)
Operating System: Ubuntu Linux (inferred from Server header)

# HTML source analysis
- No CMS detected (static HTML)
- No JavaScript frameworks detected
- No meta generator tag present

# Additional HTTP methods testing
OPTIONS / HTTP/1.1
Allow: GET, HEAD, POST, OPTIONS
```

**[Screen: Huginn tech fingerprinter results showing detected tech stack — Apache, Ubuntu, static HTML — with confidence percentages.]**

> "For scanme.nmap.org the results are straightforward — it's a simple static site on Apache with no CMS or framework. But let me show you what this looks like on a more complex target. Huginn's TechFingerprinter checks for WordPress signatures like wp-content paths, Joomla indicators like '/administrator/', React and Angular script patterns, and jQuery version strings. It also parses meta generator tags that CMS platforms love to inject. On a WordPress site, you'd see the CMS, theme name, and often the exact version — all from passive fingerprinting without sending a single exploit."

**[Screen: Huginn showing HTTP methods enumeration — GET, HEAD, POST, OPTIONS detected as allowed.]**

> "Huginn also tests allowed HTTP methods using an OPTIONS request. On this target we see GET, HEAD, POST, and OPTIONS are permitted. In some cases you'll find PUT or DELETE enabled — which could indicate a misconfigured WebDAV instance or a file upload vulnerability. Dangerous methods like TRACE can enable cross-site tracing attacks. This is low-cost reconnaissance that rounds out your technology profile."

---

## SECTION 6: Live Demonstration — SSL/TLS Inspection (12:30 – 15:00)

**[Screen: Huginn TLS analysis panel showing certificate information and protocol support.]**

> "The deep scan includes SSL/TLS inspection. Let's look at what Huginn's TLS analyzer reveals."

```bash
# TLS connection analysis
TLS Versions Supported:
  TLSv1.2: Supported
  TLSv1.3: Supported
  TLSv1.1: Not Supported (good - deprecated)
  TLSv1.0: Not Supported (good - deprecated)

# Certificate information
Subject: CN=scanme.nmap.org
Issuer: CN=Let's Encrypt Authority X3
Valid From: 2024-01-15
Valid Until: 2024-04-14
Key Size: 2048-bit RSA
Signature Algorithm: SHA-256 with RSA

# Subject Alternative Names (SANs)
DNS: scanme.nmap.org
DNS: www.scanme.nmap.org

# HSTS header check
Strict-Transport-Security: Not Present
```

**[Screen: Huginn TLS results panel with certificate details, supported protocols in green/red, and cipher suite list.]**

> "The TLS analysis tells us several things. First, protocol support — this server supports TLS 1.2 and 1.3 but has properly disabled the deprecated 1.0 and 1.1 versions. The certificate is issued by Let's Encrypt with a 90-day validity window, which is standard for automated certificate management. The 2048-bit RSA key meets current security requirements. The Subject Alternative Names show both the bare domain and www subdomain — on a larger infrastructure, SANs can reveal additional hostnames and subdomains you didn't know about."

**[Screen: Huginn flagging HSTS absence as a security finding with severity "Low".]**

> "Huginn flags that HSTS — HTTP Strict Transport Security — is not configured. Without HSTS, users could be downgraded to HTTP through a man-in-the-middle attack. The cipher suite analysis shows which encryption algorithms are supported — Huginn flags any weak ciphers like RC4 or export-grade ciphers as findings. For scanme.nmap.org the cipher configuration is solid, but you'll frequently find misconfigured TLS on older servers."

---

## SECTION 7: Results Interpretation and Integration (15:00 – 16:30)

**[Screen: Huginn complete results summary with all fingerprinting data organized into Technology Stack, Security Headers, TLS Configuration, and Findings tabs.]**

> "Let's pull it all together. The results summary gives you a complete technology profile of the target web server: what software it runs, what's missing from its security configuration, and the state of its TLS setup. This information directly informs your next steps — if you found WordPress 5.8, you'd look up CVEs for that version. If you found missing security headers, those go into your findings. If you found weak TLS, that's a reportable vulnerability."

**[Screen: Results being exported and cross-referenced with vulnerability databases.]**

> "These results feed into multiple downstream workflows in Huginn. The technology detection informs the vulnerability scanner about what checks are relevant — no point testing for WordPress vulnerabilities on a static site. Security header gaps can be exported directly to Findings. And the TLS configuration assessment feeds into compliance reporting if you're testing against PCI-DSS or similar standards. Export everything as JSON for your notes, or let Huginn integrate it automatically."

---

## SECTION 8: OSCP Exam Tips and Practice (16:30 – 17:30)

**[Screen: Slide showing "OSCP Relevance: Information Gathering — Web Application Enumeration" with exam tips.]**

> "For OSCP, HTTP fingerprinting is your first step after finding web services. The exam machines often run specific CMS versions with known exploits — identifying the exact version from headers or HTML patterns is the fastest path to exploitation. Key tip: always check the full response including cookies, headers, and HTML source. Version numbers hide in unexpected places — footer text, HTML comments, JavaScript file paths, and even CSS class names that include version strings."

**[Screen: Practice recommendations — scanme.nmap.org for basic Apache fingerprinting, HTB machines with web services for CMS detection.]**

> "Practice against scanme.nmap.org for basic server identification, then try any HTB machine with a web service — machines like 'Nibbles' run HexBlog which is identifiable through fingerprinting, and 'Bashed' has phpbash discoverable through directory enumeration after fingerprinting confirms PHP support (see Video 8: SMTP Enumeration for another service enumeration technique)."

---

## OUTRO (17:30 – end)

> "That covers HTTP and HTTPS fingerprinting in Huginn. We identified the web server software through header analysis, checked for technology stack signatures in the HTML source, audited security headers, inspected the TLS certificate configuration, and discussed how all of this feeds into your exploitation planning. Fingerprinting is passive, fast, and almost always reveals useful information — make it your first step against any web service. Next up we'll look at API enumeration, where we'll discover endpoints, test methods, and map out REST API attack surfaces. See you there."
