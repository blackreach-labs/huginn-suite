# VIDEO 50: Findings Management
### Adding, Categorizing, Scoring & Organizing Findings
**Suggested length:** 14–18 minutes
**License Tier:** Free
**Certification Relevance:** OSCP: Reporting | CEH: Scanning Networks (Reporting phase)

---

## INTRO (0:00 – 1:30)

**[Screen: Huginn splash screen with Section 9 title card "Reporting and Documentation"]**

> "Welcome to Section 9 — Reporting and Documentation. We've spent the entire series discovering vulnerabilities, exploiting weaknesses, and gathering evidence across dozens of tools and techniques. Now it's time to turn all of that into something your client can act on. In Video 26 (see Video 26: Results Interpretation), we learned how to review scan results, triage false positives, and export validated findings. Today we pick up exactly where that left off — taking those exported findings and organizing them into a structured findings database that drives professional report generation."

**[Screen: Slide showing the Reporting phase workflow — Scan Results → Findings Manager → Categorize & Score → Organize → Generate Reports]**

> "The Findings Manager is where raw vulnerability data becomes professional documentation. We'll cover four core activities: adding findings — both manually and by importing from scan results. Categorizing findings by severity, type, and affected asset. Scoring findings with CVSS context and business impact. And organizing your findings into engagement-ready groups for report generation. Everything we do here feeds directly into Video 51 where we generate the actual reports."

---

## SECTION 1: Accessing the Findings Manager (1:30 – 3:00)

**[Screen: Huginn main navigation — clicking the Report phase icon in the attack chain toolbar, then selecting "Findings" from the submenu]**

> "The Findings Manager lives in the Report phase of the attack chain. Click the Report icon in the top toolbar — the clipboard with a checkmark — and select 'Findings' from the dropdown. This opens the centralized findings dashboard where all your discovered vulnerabilities are tracked across the entire engagement."

**[Screen: Findings Manager dashboard — empty state for a fresh session, showing the "Add Finding" button and "Import from Scan" button prominently]**

> "If this is a fresh session, you'll see an empty dashboard with two primary actions: 'Add Finding' for manual entry and 'Import from Scan' for pulling in results from completed scans. Most of your findings will come through the import path — which is what we set up in Video 26 — but manual entry is essential for findings you discover through manual testing that the automated scanner didn't catch."

**[Screen: Findings Manager dashboard — pre-populated with 13 findings from our DVWA scan (imported from Video 26 results)]**

> "For this demo, I've already imported the 13 confirmed findings from our DVWA scan at Medium security level. You can see them listed here — sorted by severity with the familiar color-coded badges. These are the same findings we validated in Video 26. Let's walk through managing them."

```bash
# Findings Manager overview:
Session: DVWA Penetration Test
Target: http://localhost/dvwa/
Findings: 13 total
  Critical: 0
  High: 3 (SQL Injection, Command Injection, Stored XSS)
  Medium: 4 (Reflected XSS, CSRF, Missing CSP, Missing HSTS)
  Low: 4 (Dir Listing, No HttpOnly, No Secure Flag, Clickjacking)
  Info: 2 (PHP Version Exposed, MySQL Detected)
Status: All findings in "Confirmed" state
```

---

## SECTION 2: Adding Findings Manually (3:00 – 5:30)

**[Screen: Clicking "Add Finding" button — opening the manual finding entry form]**

> "Click 'Add Finding' to open the manual entry form. This is where you document vulnerabilities discovered through manual testing — things like logic flaws, authentication bypasses, or business logic issues that automated scanners can't detect. Let's add a finding we discovered during manual testing of DVWA's authentication mechanism."

**[Screen: Manual finding form — showing fields: Title, Description, Severity, Category, Affected URL, Evidence, CVSS Score, Remediation]**

> "The form has eight core fields. Title — a concise name for the finding. Description — what the vulnerability is and why it matters. Severity — Critical, High, Medium, Low, or Informational. Category — the vulnerability class like Injection, Authentication, or Configuration. Affected URL — exactly where the issue exists. Evidence — the proof. CVSS Score — the numeric risk rating. And Remediation — what the client should do to fix it."

**[Screen: Filling in the form — Title: "Weak Default Credentials", Description: "DVWA uses admin/password as default credentials...", Severity: High, Category: Authentication]**

> "I'm adding a finding for weak default credentials — something the scanner didn't flag because it doesn't know what 'default' means for DVWA specifically. Title: 'Weak Default Credentials.' Description: 'The application ships with admin/password as default credentials that grant full administrative access. These credentials are publicly documented and trivially guessable.' Severity: High — because it grants full access. Category: Authentication."

```bash
# Manual finding entry:
Title: Weak Default Credentials
Description: The application uses admin/password as default
  credentials providing full administrative access.
  These are publicly documented and trivially guessable.
Severity: High
Category: Authentication
Affected URL: http://localhost/dvwa/login.php
CVSS Base Score: 8.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)
Evidence: Login succeeded with admin:password on first attempt.
  No account lockout observed after 50 failed attempts.
Remediation: Enforce password change on first login. Implement
  account lockout after 5 failed attempts. Remove default
  credential documentation from public sources.
```

**[Screen: Clicking "Save Finding" — the new finding appears in the list with a "Manual" badge distinguishing it from scan-imported findings]**

> "Save the finding and it appears in your findings list with a 'Manual' badge. This badge helps you distinguish between scanner-discovered and manually-discovered findings during report generation. In a real engagement, manual findings often represent your highest-value discoveries — the things that prove a skilled tester goes beyond automated tools."

**[Screen: Adding a second manual finding — "No Account Lockout" with Medium severity and Brute Force category]**

> "Let's add one more — 'No Account Lockout.' During credential testing we observed the application allows unlimited login attempts with no rate limiting or lockout. This enables brute-force attacks. Severity Medium because it requires guessing valid credentials, but combined with the weak defaults finding, the risk compounds."

---

## SECTION 3: Importing Findings from Scan Results (5:30 – 7:30)

**[Screen: Clicking "Import from Scan" button — showing a dialog listing completed scans with date, profile, and finding count]**

> "The 'Import from Scan' workflow pulls validated findings directly from completed scans. This is the primary path — most findings come from your automated scanning. The dialog shows all completed scans in the current session with their date, profile used, and finding count. We already imported from our Normal profile scan, but let me show you the workflow for a second scan."

**[Screen: Import dialog showing two completed scans — "Normal Profile (13 findings)" already imported, "Light Profile (7 findings)" available for import]**

> "I ran a Light profile scan earlier for comparison purposes (see Video 24: Scanner Overview & Profiles). It found 7 findings — a subset of what Normal detected. Let's import these to demonstrate how Huginn handles duplicate findings across multiple scans."

**[Screen: Selecting the Light profile scan — import options showing: "Skip Duplicates", "Merge Evidence", "Import All"]**

> "When you select a scan for import, you get three deduplication options. 'Skip Duplicates' ignores any finding that matches an existing entry — same vulnerability type and URL. 'Merge Evidence' keeps existing findings but adds evidence from the new scan — useful for building stronger proof. 'Import All' creates separate entries for everything regardless of overlap. For most engagements, 'Skip Duplicates' or 'Merge Evidence' is what you want."

```bash
# Import deduplication:
Scan: Light Profile - 2024-01-15 09:30
Findings: 7 total

Import Mode: Skip Duplicates
  - Matching existing findings: 7 (all found in Normal scan too)
  - New findings to import: 0
  - Result: "No new findings to import — all 7 already exist"

Import Mode: Merge Evidence
  - Matching findings: 7
  - Evidence items added: 14 (request + response for each)
  - Result: "Merged 14 evidence items into 7 existing findings"
```

**[Screen: Selecting "Merge Evidence" and clicking Import — showing a progress bar and summary "Merged 14 evidence items into 7 existing findings"]**

> "I'll select 'Merge Evidence' so we get additional proof artifacts attached to our existing findings. The import merges 14 evidence items — the request and response from the Light profile scan — into the 7 matching findings. Now those findings have evidence from two different scan profiles, which strengthens your report by showing the vulnerability was consistently detected across multiple approaches."

---

## SECTION 4: Categorizing and Organizing Findings (7:30 – 10:00)

**[Screen: Findings list view — showing the Category column with values like "Injection", "Authentication", "Configuration", "Information Disclosure"]**

> "Every finding belongs to a category — the vulnerability class it falls into. Categories help you organize the report narrative and identify patterns. If a client has eight findings all in the 'Configuration' category, that tells a story about their hardening practices. Let's look at how categories are assigned and how to adjust them."

**[Screen: Right-clicking a finding — context menu showing "Edit Category" with dropdown options: Injection, Authentication, Cryptography, Configuration, Information Disclosure, Session Management, Input Validation, Custom...]**

> "Right-click any finding to access the category editor. Huginn pre-assigns categories based on vulnerability type — SQL injection gets 'Injection,' missing headers get 'Configuration' — but you can override these. The standard categories follow OWASP conventions: Injection, Authentication, Cryptography, Configuration, Information Disclosure, Session Management, and Input Validation. You can also create custom categories for findings that don't fit neatly into these groups."

**[Screen: Findings grouped by category — showing a collapsible tree view: Injection (2), Authentication (2), Configuration (4), Session Management (2), Information Disclosure (3), Input Validation (2)]**

> "Switch to the 'Group by Category' view to see your findings organized by class. This view is particularly useful during report writing because professional pentest reports typically present findings grouped by category rather than severity alone. You can see patterns at a glance — we have four configuration findings suggesting systematic hardening gaps, two injection findings showing input validation failures, and two authentication findings revealing access control weakness."

```bash
# Findings grouped by category:
Injection (2):
  ├── SQL Injection [High] — /dvwa/vulnerabilities/sqli/
  └── Command Injection [High] — /dvwa/vulnerabilities/exec/

Authentication (2):
  ├── Weak Default Credentials [High] — /dvwa/login.php
  └── No Account Lockout [Medium] — /dvwa/login.php

Configuration (4):
  ├── Missing CSP Header [Medium] — all pages
  ├── Missing HSTS [Medium] — all pages
  ├── Clickjacking (X-Frame-Options) [Low] — all pages
  └── Server Version Exposed [Low] — all pages

Session Management (2):
  ├── Cookie No HttpOnly [Low] — PHPSESSID
  └── Cookie No Secure Flag [Low] — PHPSESSID

Information Disclosure (3):
  ├── Directory Listing [Low] — /dvwa/docs/
  ├── PHP Version Detected [Info] — X-Powered-By
  └── MySQL Detected [Info] — setup.php

Input Validation (2):
  ├── Cross-Site Scripting (Stored) [High] — /dvwa/vulnerabilities/xss_s/
  └── Cross-Site Scripting (Reflected) [Medium] — /dvwa/vulnerabilities/xss_r/
```

**[Screen: Drag-and-drop reordering within a category — moving "Weak Default Credentials" above "No Account Lockout"]**

> "Within each category, you can reorder findings by dragging them. This controls the presentation order in your final report. I like to put the highest-impact finding first within each category — so our weak default credentials finding goes above the account lockout finding because it has direct, immediate exploitability."

**[Screen: Adding tags to findings — selecting multiple findings and applying tags "OWASP-A03", "Quick-Win", "Requires-Patching"]**

> "Tags add a secondary organization layer. Select multiple findings and apply tags like 'OWASP-A03' for injection category mapping, 'Quick-Win' for findings with simple remediation, or 'Requires-Patching' for items needing vendor updates. Tags help you filter findings for specific report sections — like pulling all quick-wins into a 'Low-Hanging Fruit' appendix."

---

## SECTION 5: CVSS Scoring and Risk Assessment (10:00 – 13:00)

**[Screen: Clicking on the SQL Injection finding — opening the detail panel with the CVSS scoring section expanded]**

> "Every finding needs a CVSS score — it's the industry standard language for communicating vulnerability severity. Huginn auto-calculates CVSS from scan data, but you should verify and adjust the scores based on your understanding of the target's context. Let's review and refine the score for our SQL injection finding."

**[Screen: CVSS calculator panel — showing the eight CVSS 3.1 base metrics as clickable selectors with the current values highlighted]**

> "The CVSS calculator shows all eight base metrics. Attack Vector — how the attacker reaches the vulnerable component. Attack Complexity — conditions beyond the attacker's control. Privileges Required — authentication level needed. User Interaction — whether a victim must take action. Scope — whether the vulnerability impacts beyond the vulnerable component. Confidentiality, Integrity, and Availability impact — what gets affected and how severely."

```bash
# CVSS 3.1 Base Score Calculator — SQL Injection:
┌─────────────────────────────────────────────────────────┐
│ Attack Vector (AV):        [Network] Local Adjacent Physical │
│ Attack Complexity (AC):    [Low] High                        │
│ Privileges Required (PR):  None [Low] High                   │
│ User Interaction (UI):     [None] Required                   │
│ Scope (S):                 [Unchanged] Changed               │
│ Confidentiality (C):       None Low [High]                   │
│ Integrity (I):             None Low [High]                   │
│ Availability (A):          None [Low] High                   │
├─────────────────────────────────────────────────────────┤
│ Base Score: 8.3 (High)                                       │
│ Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L      │
└─────────────────────────────────────────────────────────┘
```

**[Screen: Adjusting the Privileges Required metric from "Low" to "None" — score updating from 8.3 to 9.1]**

> "The scanner set Privileges Required to 'Low' because the user needs a DVWA login. But the default credentials are publicly known — admin/password. In context, this effectively means no authentication barrier. Changing PR to 'None' better reflects the real-world exploitability. The score jumps from 8.3 to 9.1 — now Critical severity. This contextual adjustment is why human review of automated scores matters. A scanner doesn't know the credentials are public defaults."

**[Screen: Security metrics engine panel — showing the engagement risk score calculation with individual finding scores and correlation amplifiers]**

> "The Security Metrics engine aggregates individual CVSS scores into an overall engagement risk score. It factors in finding density — how many findings exist relative to the target size — correlation between findings, and exploitability confirmation. Our engagement scores 76 out of 100, driven by the three Critical/High findings with confirmed exploitability. This number goes in your executive summary to give stakeholders a single-number risk assessment."

**[Screen: Risk breakdown visualization — pie chart showing Critical: 1, High: 3, Medium: 4, Low: 5, Info: 2]**

> "After our CVSS adjustment, the risk breakdown shows one Critical finding — the SQL injection with confirmed exploitation and effectively no auth barrier — three High findings, four Medium, five Low, and two Informational. This distribution tells the client they have significant exploitable risk requiring immediate attention on the Critical and High items, while the Medium and Low findings represent defense-in-depth improvements."

```bash
# Security Metrics Summary:
┌────────────────────────────────────────────────────────┐
│ Engagement Risk Score: 76/100 (High Risk)              │
├────────────────────────────────────────────────────────┤
│ Finding Distribution:                                   │
│   Critical: 1  ████░░░░░░░░░░░░░░░░  (7%)            │
│   High:     3  ████████████░░░░░░░░  (20%)            │
│   Medium:   4  ████████████████░░░░  (27%)            │
│   Low:      5  ████████████████████  (33%)            │
│   Info:     2  ████████░░░░░░░░░░░░  (13%)            │
├────────────────────────────────────────────────────────┤
│ Correlation Amplifiers:                                 │
│   SQLi + Weak Auth = Credential-less DB Access (+15%)  │
│   XSS + No CSP = Unrestricted Script Execution (+10%) │
│   Missing Headers (4) = Systematic Gap Pattern (+5%)   │
├────────────────────────────────────────────────────────┤
│ Remediation Priority:                                   │
│   Immediate: 4 findings (Critical + High)              │
│   Short-term: 4 findings (Medium)                      │
│   Long-term: 7 findings (Low + Info)                   │
└────────────────────────────────────────────────────────┘
```

---

## SECTION 6: Finding Status and Workflow Management (13:00 – 15:30)

**[Screen: Finding detail panel — showing the Status dropdown with options: New, Confirmed, Exploited, Reported, Remediated, Accepted Risk, False Positive]**

> "Every finding has a lifecycle status that tracks its progression through the engagement. 'New' means just imported and not yet reviewed. 'Confirmed' means you've verified it's real — either through evidence review or manual exploitation. 'Exploited' means you've achieved full exploitation and have proof of impact. 'Reported' means it's been included in a delivered report. 'Remediated' means the client fixed it and a rescan confirms. 'Accepted Risk' means the client acknowledges the risk but chooses not to fix it. 'False Positive' removes it from active reporting."

**[Screen: Batch status update — selecting all High severity findings, right-clicking and selecting "Mark as Exploited"]**

> "For our three High severity findings plus the Critical SQL injection, we confirmed exploitation during the vulnerability scanning videos. Let's batch-update them to 'Exploited' status. Select the findings, right-click, and choose 'Mark as Exploited.' This status drives report language — exploited findings get stronger language in the report about confirmed impact versus theoretical risk."

**[Screen: Evidence attachment workflow — clicking "Add Evidence" on the Weak Default Credentials finding, selecting a screenshot file]**

> "Each finding can have multiple evidence attachments — screenshots, request/response pairs, terminal output, or arbitrary files. For our manual findings, we should add evidence now. Click 'Add Evidence' and attach the proof. For the default credentials finding, I'll attach a screenshot of the successful login and the raw HTTP request showing the admin/password authentication."

```bash
# Finding status lifecycle:
New → Confirmed → Exploited → Reported → Remediated
                          ↓
                   Accepted Risk
         ↓
   False Positive (removed from reporting)

# Evidence types supported:
- HTTP Request/Response pairs (auto-captured from scanner)
- Screenshots (.png, .jpg)
- Terminal output (.txt)
- Proof-of-concept scripts (.py, .sh)
- Arbitrary file attachments
```

**[Screen: Findings timeline view — showing when each finding was first discovered, confirmed, and exploited with timestamps]**

> "The timeline view shows the chronological discovery and validation story for each finding. This is important for engagement reporting because it demonstrates your methodology — you discovered the vulnerability on day one, confirmed it on day two, and achieved exploitation on day three. Clients and auditors appreciate seeing a structured approach rather than a random dump of findings."

---

## SECTION 7: Certification Tips and Practice (15:30 – 16:30)

**[Screen: Slide showing OSCP tip — "Document every finding as you go — don't leave reporting to the last hour of the exam"]**

> "For OSCP — the exam gives you 24 hours to test and an additional 24 hours to report. Many candidates lose points not because they couldn't exploit the targets, but because their documentation was incomplete. Practice adding findings to Huginn as you work through HTB machines. When you document as you go, your report writes itself at the end."

**[Screen: CEH tip — "Know the CVSS metrics and how context changes the score"]**

> "For CEH — the exam tests CVSS knowledge directly. You need to understand why the same vulnerability might score differently depending on network position, authentication requirements, and scope. The scoring exercise we did — adjusting SQL injection from 8.3 to 9.1 based on default credentials context — is exactly the kind of reasoning CEH tests."

**[Screen: Practice recommendation — "Run DVWA at all security levels and build a complete findings database for each"]**

> "Practice target: run DVWA at Low, Medium, and High security levels. Build a complete findings database for each level. Notice how the same vulnerability types appear at Low but disappear at Medium or High — this teaches you about true positives versus false positives and how defenses reduce the finding count. Export your findings and use them for Video 51's report generation practice."

---

## OUTRO (16:30 – end)

**[Screen: Summary slide — Findings Management: Add (manual + import) → Categorize → Score (CVSS) → Organize (status + tags) → Ready for Reports | Next: Video 51 — Report Generation]**

> "That's findings management — adding findings manually and from scans, categorizing them by vulnerability class, scoring them with CVSS in proper context, and organizing them with statuses, tags, and evidence for professional reporting. Your findings database is now complete and ready for report generation. In the next video, we'll take these organized findings and produce finished reports in every format Huginn supports — JSON, CSV, XML, PDF, and HTML — including a complete walkthrough of generating a professional PDF pentest report. See you in Video 51."

