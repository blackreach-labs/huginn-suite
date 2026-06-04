# VIDEO 26: Results Interpretation
### Evidence Review, False Positive Triage & Severity Assessment
**Suggested length:** 16–20 minutes
**License Tier:** Free
**Certification Relevance:** OSCP: Vulnerability Scanning | CEH: Scanning Networks

---

## INTRO (0:00 – 1:30)

**[Screen: Huginn splash screen with Section 4 title card "Vulnerability Scanning"]**

> "In the last two videos we learned how to configure and run scans with different profiles (see Video 24: Scanner Overview & Profiles) and how to set up targets, scope, and timing (see Video 25: Scan Configuration). But running a scan is only half the job. The real skill — the one that separates a junior tester from a senior pentester — is interpreting what comes back. Today we're going to walk through scan results panel by panel, review evidence artifacts, identify false positives, assess severity accurately, and export validated findings into your engagement report."

**[Screen: Slide showing the results interpretation workflow — Raw Results → Evidence Review → False Positive Triage → Severity Assessment → Export to Findings]**

> "Our workflow has four stages. First, navigate the raw results and understand what the scanner found. Second, review the evidence — the actual HTTP requests, responses, and payloads that prove a vulnerability exists. Third, triage false positives — because every scanner produces them and your report credibility depends on filtering them out. Fourth, assess severity using CVSS context and export confirmed findings for your report. We'll do all of this against DVWA at security level Medium."

---

## SECTION 1: Demo Setup and Scan Execution (1:30 – 3:00)

**[Screen: DVWA login page — logging in with admin/password, navigating to Security page]**

> "Our target is DVWA on localhost, set to security level Medium. Medium enables some input filtering — basic blacklist protections, simple sanitization — which means our scanner will produce a mix of confirmed vulnerabilities and findings that look like vulnerabilities but are actually blocked by the filters. This is exactly what you face in real engagements — applications with partial defenses that produce noisy scan results."

**[Screen: DVWA Security page showing "Medium" selected in the dropdown]**

> "Confirm your security level is set to Medium. This matters for reproducibility — if someone follows along with a different security level, they'll get different results and some of the false positive examples won't match."

**[Screen: Huginn Scanner page — selecting Normal profile, entering http://localhost/dvwa/ as target, clicking Start Scan]**

> "I've already run a Normal profile scan against this target — the same configuration we used in Video 25. The scan completed with 16 findings across all severity levels. Let's look at the results."

```bash
# Pre-completed scan summary:
Target: http://localhost/dvwa/
Profile: Normal
Duration: 22 minutes 8 seconds
Findings: 16 total (3 High, 5 Medium, 5 Low, 3 Info)
Status: Completed
```

---

## SECTION 2: Results Panel Navigation (3:00 – 5:30)

**[Screen: Scan results overview panel — showing findings grouped by severity with color-coded badges (Red=High, Orange=Medium, Yellow=Low, Blue=Info)]**

> "The results panel organizes findings in three views — Summary, Detail, and Evidence. The summary view is what you see first: findings grouped by severity with color-coded badges. Red for High, orange for Medium, yellow for Low, blue for Informational. The number badges show count per category. This gives you an instant read on the target's security posture — three High findings means there's real exploitable risk here."

**[Screen: Clicking on the severity distribution chart — showing a bar graph comparing finding counts across severity levels]**

> "The severity distribution chart puts findings in visual context. A healthy application might show zero High, a couple of Medium, and mostly Low and Info findings. What we're seeing — three High severity items — indicates exploitable vulnerabilities that need immediate attention. In a client engagement, these go in the executive summary."

**[Screen: Switching to the findings list view — showing a sortable table with columns: Severity, Type, URL, Confidence, Evidence]**

> "Switch to the list view for actionable detail. Each finding has a severity rating, vulnerability type, the affected URL, a confidence score, and an evidence indicator showing whether artifacts were captured. The confidence score is critical — it ranges from 0 to 100 and tells you how certain the scanner is that this finding is real. High confidence means strong evidence. Low confidence means the scanner saw something suspicious but couldn't confirm exploitation."

```bash
# Results list columns:
| Severity | Type                  | URL                              | Confidence | Evidence |
|----------|-----------------------|----------------------------------|------------|----------|
| High     | SQL Injection         | /dvwa/vulnerabilities/sqli/      | 95%        | ✓        |
| High     | Command Injection     | /dvwa/vulnerabilities/exec/      | 88%        | ✓        |
| High     | XSS (Stored)          | /dvwa/vulnerabilities/xss_s/     | 92%        | ✓        |
| Medium   | XSS (Reflected)       | /dvwa/vulnerabilities/xss_r/     | 65%        | ✓        |
| Medium   | CSRF                  | /dvwa/vulnerabilities/csrf/      | 70%        | ✓        |
| Medium   | Missing CSP Header    | /dvwa/ (all pages)               | 100%       | ✓        |
| Medium   | Missing HSTS          | /dvwa/ (all pages)               | 100%       | ✓        |
| Medium   | File Inclusion        | /dvwa/vulnerabilities/fi/        | 60%        | ✓        |
| Low      | Directory Listing     | /dvwa/docs/                      | 100%       | ✓        |
| Low      | Cookie No HttpOnly    | /dvwa/ (PHPSESSID)               | 100%       | ✓        |
| Low      | Cookie No Secure Flag | /dvwa/ (PHPSESSID)               | 100%       | ✓        |
| Low      | Clickjacking          | /dvwa/ (missing X-Frame-Options) | 100%       | ✓        |
| Low      | Server Version Exposed| /dvwa/ (Apache header)           | 100%       | ✓        |
| Info     | PHP Version Detected  | /dvwa/ (X-Powered-By header)     | 100%       | —        |
| Info     | Technology: MySQL     | /dvwa/setup.php                  | 85%        | —        |
| Info     | Login Form Detected   | /dvwa/login.php                  | 100%       | —        |
```

**[Screen: Demonstrating column sorting — clicking "Confidence" to sort descending, then "Severity" to re-sort]**

> "Sort by confidence to surface the most certain findings first. Everything at 100% confidence is deterministic — the scanner verified it directly. For example, missing security headers are always 100% because the scanner just checks whether the header exists in the response. Items at 60-70% confidence need manual verification — the scanner saw indicators but couldn't fully confirm exploitation. We'll dig into those during false positive triage."

---

## SECTION 3: Evidence Review Workflow (5:30 – 8:30)

**[Screen: Clicking on the SQL Injection finding — expanding the detail panel showing Request, Response, and Payload tabs]**

> "Let's examine our highest-confidence finding — SQL Injection in the sqli module at 95% confidence. Click it to expand the evidence panel. You'll see three tabs: Request, Response, and Payload. This is the evidence that proves the vulnerability exists — or doesn't. Every finding you include in a client report needs evidence backing it up."

**[Screen: Request tab — showing the full HTTP request with the injected payload highlighted in the URL parameter]**

> "The Request tab shows exactly what the scanner sent. Here we can see a GET request to /dvwa/vulnerabilities/sqli/ with the id parameter set to a single quote followed by OR 1=1. The scanner injected this payload and captured the full request including headers, cookies, and session tokens. This is your proof of what was sent."

```
GET /dvwa/vulnerabilities/sqli/?id=1'+OR+'1'%3D'1'--+&Submit=Submit HTTP/1.1
Host: localhost
Cookie: PHPSESSID=abc123def456; security=medium
User-Agent: Huginn-Scanner/2.0
Accept: text/html,application/xhtml+xml
```

**[Screen: Response tab — showing the HTTP response with the database results highlighted, demonstrating successful injection]**

> "The Response tab shows what came back. Look at the highlighted section — the application returned multiple database rows when it should only return one. The injected OR 1=1 condition bypassed the WHERE clause and dumped all users. This is unambiguous evidence of SQL injection. The response also includes the HTTP status code, response headers, and the full content. For this finding, we can see the application returned a 200 OK with user data that shouldn't be accessible."

```
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 4832

<pre>
ID: 1' OR '1'='1'-- 
First name: admin
Surname: admin

ID: 1' OR '1'='1'-- 
First name: Gordon
Surname: Brown

ID: 1' OR '1'='1'-- 
First name: Hack
Surname: Me

ID: 1' OR '1'='1'-- 
First name: Pablo
Surname: Picasso

ID: 1' OR '1'='1'-- 
First name: Bob
Surname: Smith
</pre>
```

**[Screen: Payload tab — showing the specific payload used, its category (SQL Injection), and the mutation strategy]**

> "The Payload tab documents what was injected and why. It shows the raw payload, the injection category, whether this was a primary payload or a mutated variant, and the expected response pattern the scanner used to confirm the vulnerability. Here, the expected pattern was 'multiple rows returned where one expected' — a classic union-style confirmation technique. The evidence collector stores all of this with a unique vulnerability ID and timestamp for report traceability."

**[Screen: Clicking the Command Injection finding — showing evidence with the executed command and output]**

> "Let's check another one — Command Injection at 88% confidence. The scanner injected a pipe character followed by the id command into the IP parameter. The response shows the output of the id command — uid=33(www-data) — proving the injected command executed on the server. At Medium security level, DVWA blocks some injection characters like semicolons but allows pipes. The scanner adapted its payload accordingly."

```
# Request payload:
ip=127.0.0.1|id&Submit=Submit

# Response excerpt:
PING 127.0.0.1 (127.0.0.1): 56 data bytes
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## SECTION 4: False Positive Identification (8:30 – 11:30)

**[Screen: Clicking on the File Inclusion finding — showing 60% confidence with evidence that the attack was partially blocked]**

> "Now for the critical skill — identifying false positives. Look at the File Inclusion finding at 60% confidence. The scanner flagged this because it detected path traversal patterns in a parameter, but let's look at the evidence carefully."

**[Screen: Evidence panel for File Inclusion — showing the response returned an error page rather than file contents]**

> "The scanner sent a request with page=../../../../../../etc/passwd in the URL. At Medium security, DVWA strips the ../ sequences from the input. The response doesn't contain the contents of /etc/passwd — it shows a 'File not found' error. The scanner flagged this at 60% confidence because it detected the parameter accepts file paths, which is suspicious. But the actual exploitation failed. This is a false positive at this security level."

```
# Request:
GET /dvwa/vulnerabilities/fi/?page=....//....//....//etc/passwd HTTP/1.1

# Response:
ERROR: File not found.

# Analysis:
# The scanner identified file path input (correct observation)
# But the Medium security filter strips traversal sequences
# No file contents disclosed = NOT exploitable = FALSE POSITIVE
```

**[Screen: Demonstrating the false positive marking workflow — right-clicking the finding, selecting "Mark as False Positive" with a reason field]**

> "To mark a false positive, right-click the finding and select 'Mark as False Positive.' Enter your reasoning — in this case: 'Medium security level strips traversal sequences. Response shows error page, no file disclosure.' This annotation stays attached to the finding. If you rescan later, the scanner remembers your triage decision and won't re-alert on the same pattern unless something changes."

**[Screen: Looking at the XSS Reflected finding at 65% confidence — showing partial evidence]**

> "Let's look at another borderline case — Reflected XSS at 65% confidence. The scanner injected a script tag into the name parameter. At Medium security, DVWA replaces script tags with empty strings using str_replace. But the scanner detected that some characters were reflected — the closing tag survived the filter. This is technically a true positive, but not directly exploitable with this payload. The vulnerability exists because the filter is bypassable with alternative vectors like img onerror or svg onload. So this is a true positive with a caveat — it requires a different payload to exploit."

```
# Scanner payload:
name=<script>alert('XSS')</script>

# Response shows:
Hello alert('XSS')

# Analysis:
# <script> and </script> tags stripped (str_replace)
# BUT: Filter only removes <script> — not <img>, <svg>, <body>
# Exploitable with: <img src=x onerror=alert('XSS')>
# Verdict: TRUE POSITIVE (filter bypass possible)
```

**[Screen: Summary of triage decisions — showing 2 findings marked as false positive, 1 downgraded, 13 confirmed]**

> "After reviewing all 16 findings, our triage results: 13 confirmed true positives, 1 downgraded from Medium to Low because exploitation requires additional conditions, and 2 marked as false positives — the File Inclusion and one of the Info findings. A 12% false positive rate is typical for Normal profile scans against medium-security applications. In practice, you should expect 10-30% depending on the target's defense maturity."

---

## SECTION 5: Severity Assessment and CVSS Context (11:30 – 14:00)

**[Screen: Results analyzer panel — showing the risk score calculation breaking down severity weights and business impact]**

> "Raw severity from the scanner is a starting point, not the final answer. The results analyzer calculates a composite risk score by weighing severity, confidence, exploitability, and business impact. A High severity finding with 95% confidence and easy exploitability scores differently than a High finding at 65% confidence requiring complex conditions."

**[Screen: Detailed view of the SQL Injection finding showing CVSS breakdown — Attack Vector: Network, Complexity: Low, Privileges Required: Low, User Interaction: None]**

> "For our SQL injection finding, Huginn's results analyzer maps it to CVSS context. Attack vector is Network — it's remotely exploitable over HTTP. Attack complexity is Low — the injection works with a straightforward payload. Privileges required is Low — you need a DVWA login but it's default credentials. User interaction is None — no victim action required. This gives us a CVSS base score in the 8.0-9.0 range — solidly High, potentially Critical depending on the data accessible."

```bash
# Severity assessment for SQL Injection:
┌─────────────────────────────────────────────────────────────┐
│ CVSS 3.1 Contextual Assessment                              │
├─────────────────────────────────────────────────────────────┤
│ Attack Vector:     Network (AV:N)                           │
│ Attack Complexity: Low (AC:L)                               │
│ Privileges Req.:   Low (PR:L)                               │
│ User Interaction:  None (UI:N)                              │
│ Scope:            Unchanged (S:U)                           │
│ Confidentiality:  High (C:H) — full DB access              │
│ Integrity:        High (I:H) — can modify data             │
│ Availability:     Low (A:L) — can disrupt queries          │
├─────────────────────────────────────────────────────────────┤
│ Base Score: 8.6 (High)                                      │
│ Huginn Confidence: 95%                                      │
│ Exploitability: Confirmed                                   │
│ Remediation Effort: Medium (input parameterization)         │
└─────────────────────────────────────────────────────────────┘
```

**[Screen: Vulnerability correlator output — showing relationships between findings and attack chain mapping]**

> "The vulnerability correlator connects individual findings into attack chains. It identified that our SQL injection combined with the exposed server version and missing security headers creates an amplified risk. The correlation: SQL injection provides database access, the server version reveals the technology stack for targeted exploitation, and missing security headers like CSP mean any XSS finding has greater impact because there's no browser-side mitigation. The correlator assigns a correlation score that adjusts overall risk assessment upward when findings reinforce each other."

**[Screen: Risk score summary — showing individual findings plus correlation amplifiers combining into an overall engagement risk score]**

> "The final risk score accounts for individual vulnerabilities plus correlation amplifiers. Our scan scored 72 out of 100 — driven primarily by the three High findings and the attack chain correlation between SQL injection and XSS in the absence of security headers. This score helps you prioritize during the reporting phase — a 72 indicates significant risk requiring immediate remediation recommendations."

---

## SECTION 6: Result Filtering and Comparison (14:00 – 16:00)

**[Screen: Filter panel — showing dropdown filters for Severity, Type, Confidence range, and URL pattern]**

> "When scans produce dozens or hundreds of findings — which happens against larger applications — filtering becomes essential. The result filter supports criteria-based filtering by severity, type, confidence range, and URL pattern. Let's filter to show only High findings with confidence above 80%."

**[Screen: Applying filters — severity=High, confidence>=80 — results narrowing from 16 to 3 findings]**

> "Three findings remain. These are your confirmed, high-confidence, high-severity items — the ones that go at the top of your report. For OSCP and CEH exam purposes, these are the findings that demonstrate exploitation paths. In client engagements, these are the items your executive summary highlights."

```bash
# Filter configuration:
Severity: High
Confidence: >= 80%
Result: 3 findings (SQL Injection 95%, XSS Stored 92%, Command Injection 88%)
```

**[Screen: Scan comparison view — selecting current scan and a previous Light profile scan, showing differences]**

> "The result comparator lets you compare scans over time or across profiles. Here I'm comparing our Normal scan against a Light profile scan of the same target. The comparison shows which findings are new — Normal found 9 additional vulnerabilities that Light missed — which were removed, and which persist across both. This is powerful for demonstrating remediation progress to clients: scan before fix, scan after fix, compare the results."

**[Screen: Comparison summary showing new findings highlighted in green, unchanged in gray, removed in red]**

> "The comparator flags new findings in green, unchanged findings in gray, and removed findings in red. Across an engagement timeline, this shows your client their security posture improving as they address your recommendations. It also catches regression — if a finding that was fixed reappears in a later scan, it's immediately flagged."

---

## SECTION 7: Export to Findings (16:00 – 17:30)

**[Screen: Selecting confirmed findings — checking boxes next to each validated finding, then clicking "Export to Findings"]**

> "Once triage is complete, export confirmed findings to the Findings Manager for report generation. Select each validated finding — we're exporting our 13 confirmed true positives — and click 'Export to Findings.' This creates formal finding entries with all the evidence attached."

**[Screen: Export options dialog — showing format selection (Findings Manager, JSON, CSV) and included metadata checkboxes]**

> "The export dialog lets you choose the destination. 'Findings Manager' pushes directly into Huginn's findings system for report generation (covered in Video 50: Findings Management). JSON and CSV exports are useful for feeding into external tools or tracking spreadsheets. Check the metadata boxes to include evidence artifacts, timestamps, and triage notes in the export."

```bash
# Export configuration:
Destination: Findings Manager
Include Evidence: ✓ (requests, responses, payloads)
Include CVSS Context: ✓
Include Triage Notes: ✓
Include Correlation Data: ✓

Exported: 13 confirmed findings
Skipped: 2 false positives, 1 informational (no evidence)
```

**[Screen: Findings Manager showing the newly imported findings — organized by severity with evidence attached]**

> "In the Findings Manager, your exported findings appear with full context — severity, evidence artifacts, CVSS scores, triage notes, and correlation data. Each finding is ready for inclusion in your pentest report. The evidence chain from scan execution through triage to final reporting is complete and auditable."

---

## SECTION 8: Certification Tips and Practice (17:30 – 18:30)

**[Screen: Slide showing OSCP tip — "Evidence is everything: screenshot, request, response for each finding"]**

> "For OSCP — your exam report requires proof of exploitation for every finding you submit. The evidence workflow we just covered maps directly to what the OSCP examiners expect: the exact request you sent, the response proving exploitation, and the payload that worked. Practice capturing evidence cleanly during your HTB and THM work so it becomes automatic during the exam."

**[Screen: CEH tip — "Know the difference between automated findings and validated vulnerabilities"]**

> "For CEH — the exam tests your understanding of vulnerability assessment methodology, not just tool usage. You need to know why false positives occur, how to verify findings manually, and how severity assessment works in context. The triage workflow — checking confidence, reviewing evidence, confirming exploitation — is testable knowledge."

**[Screen: Practice resource list — DVWA (Medium/High), THM "Nessus", HTB "Shocker", HTB "Bashed"]**

> "Practice results interpretation on these targets. Run DVWA at both Medium and High security levels — High produces more false positives because more filters are active. THM's Nessus room teaches vulnerability scanning methodology. HTB Shocker and Bashed are web machines where scan results need careful interpretation to identify the actual exploitation path."

---

## OUTRO (18:30 – end)

**[Screen: Summary slide — Results Interpretation: Navigate panels → Review evidence → Triage false positives → Assess severity → Export findings | Next: Video 27 — AI-Powered Scanning]**

> "That's the complete results interpretation workflow — navigating scan results, reviewing evidence artifacts to confirm findings, identifying and marking false positives, assessing severity with CVSS context and correlation analysis, and exporting validated findings for your report. The discipline of evidence-backed triage is what makes your pentest reports credible and actionable. In the next video, we'll explore Huginn's Enterprise-tier AI-powered scanning features — Neural Network Analysis and ML Pattern Detection that take vulnerability discovery beyond traditional signature-based approaches. See you in Video 27."
