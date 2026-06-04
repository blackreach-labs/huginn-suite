# VIDEO 19: Breach Intelligence
### Credential Databases, Paste Monitoring & Exposure Assessment
**Suggested length:** 15–18 minutes
**License Tier:** Enterprise
**Certification Relevance:** OSCP: Information Gathering | CEH: Footprinting & Reconnaissance

---

## INTRO (0:00 – 1:45)

**[Screen: Huginn splash screen with Section 3 title card "OSINT and Intelligence Gathering"]**

> "In this video we cover Breach Intelligence — one of Huginn's Enterprise tier features. Breach intelligence allows you to query databases of known data breaches to determine whether email addresses, credentials, or other sensitive data associated with a target organization have been exposed in previous breaches. This is a critical step in penetration testing because breached credentials are one of the most common initial access vectors — if an employee's password was exposed in a third-party breach and they reuse that password on corporate systems, you have a viable entry point."

**[Screen: Slide showing the lifecycle — Breach occurs → Data surfaces on dark web → Aggregators index it → Security teams query for exposure → Remediation]**

> "This is entirely passive reconnaissance. We're querying breach aggregator APIs — not the dark web directly. Services like Have I Been Pwned, DeHashed, and specialized breach intelligence APIs have already collected and indexed breach data. We simply ask: has this email address or domain appeared in any known breaches? The answer tells us the organization's exposure level and which credentials might still be valid."

**[Screen: Enterprise tier badge prominently displayed — "This feature requires an Enterprise license ($299/month)"]**

> "Important note: Breach Intelligence is an Enterprise tier feature in Huginn. You'll need an active Enterprise license to access this module. If you're on the Free or Professional tier, you can still follow along to understand the methodology — and when you're ready to upgrade, everything shown here will be available immediately. Also note that some breach intelligence APIs require their own separate API keys and subscriptions, which we'll set up in this video (see Video 4: Licensing & Tiers)."

---

## SECTION 1: Breach Intelligence Sources (1:45 – 4:00)

**[Screen: Diagram showing Huginn's breach intelligence pipeline — target email/domain → query engine → multiple APIs (HIBP, DeHashed, Local DB, Dark Web Monitor) → aggregated results]**

> "Huginn's Breach Intelligence engine queries multiple sources in sequence, each providing different coverage and depth. Let's walk through what each source offers."

**[Screen: Source comparison table — HIBP (free API, breach names only), DeHashed (paid, includes partial credentials), Local DB (offline database, full credentials if available), Dark Web Monitor (real-time paste monitoring)]**

> "Have I Been Pwned — HIBP — is the first source. It tells you which breaches an email appeared in and what data types were exposed — passwords, phone numbers, addresses — but it doesn't provide the actual credentials. It's the safest and most widely used breach notification service. DeHashed goes deeper — it's a paid search engine for breach data that can return partial or full credentials, hashed passwords, and associated metadata. The Local DB source queries any offline breach databases you've imported. And the Dark Web Monitor checks paste sites and dark web forums for recent credential dumps."

**[Screen: Ethical guidelines callout — bold text: "Only query email addresses and domains you have written authorization to test"]**

> "A critical ethical point: you must only query email addresses belonging to organizations that have given you written authorization for the assessment. Never query personal email addresses without consent. Breach intelligence is powerful but sensitive — the data you uncover belongs to real people. Document your authorization scope clearly before running any breach queries."

---

## SECTION 2: API Key Setup (4:00 – 6:30)

**[Screen: Huginn Settings → API Keys configuration panel — showing fields for HIBP, DeHashed, and Shodan API keys]**

> "Before we can run breach queries, we need to configure API keys. Navigate to Settings from the sidebar, then click the API Keys tab. You'll see fields for each supported service. Let's set up Have I Been Pwned and DeHashed."

**[Screen: Browser showing haveibeenpwned.com/API/Key — the API key purchase page]**

> "For Have I Been Pwned, you need a paid API key. Navigate to haveibeenpwned.com/API/Key in your browser. The API key costs a small monthly fee — currently around three dollars and fifty cents per month — and gives you programmatic access to search any email address. Purchase the key and copy it."

```bash
# HIBP API Key Setup
1. Navigate to: https://haveibeenpwned.com/API/Key
2. Purchase an API key (≈$3.50/month)
3. Copy the key from your confirmation email
4. In Huginn: Settings → API Keys → HIBP API Key → Paste → Save
```

**[Screen: Pasting the HIBP API key into Huginn's settings field — green checkmark appears confirming valid key]**

> "Paste the key into Huginn's HIBP API Key field and click Save. Huginn validates the key immediately — you'll see a green checkmark if it's accepted. If you get a red indicator, double-check that you copied the full key without trailing spaces."

**[Screen: Browser showing dehashed.com/register — the registration page]**

> "DeHashed requires a separate subscription — it's a breach search engine with tiered pricing depending on your query volume. Create an account at dehashed.com, subscribe to a plan, then copy your API key from your account dashboard. This service provides deeper results including partial credential data."

```bash
# DeHashed API Key Setup
1. Navigate to: https://dehashed.com/register
2. Create account and subscribe to a plan
3. Copy API key from: Account → API Key
4. Copy API email from: Account → Email
5. In Huginn: Settings → API Keys → DeHashed API Key → Paste
6. In Huginn: Settings → API Keys → DeHashed Email → Paste → Save
```

**[Screen: DeHashed fields populated in Huginn settings — both API key and email fields showing green checkmarks]**

> "DeHashed requires both your API key and the email associated with your account. Fill in both fields. Once validated, you're ready to run breach intelligence queries using both sources."

---

## SECTION 3: Running a Breach Query (6:30 – 9:30)

**[Screen: Navigating to OSINT & Intelligence → Breach Intelligence tab — showing the search interface]**

> "Navigate to OSINT and Intelligence, then click the Breach Intelligence tab. The interface accepts two input types — a single email address or a domain name. Email searches check that specific address across all breach databases. Domain searches find all breached emails associated with that domain — which is typically what you want during an organizational assessment."

**[Screen: Breach Intelligence interface — target input field, search type selector (Email/Domain), source checkboxes, "Start Analysis" button]**

> "For our demonstration, I'm using test email addresses on my own domain. I've pre-created accounts that I've intentionally registered on services known to have been breached — purely for this demonstration. Never use real employee data for tutorial purposes."

```bash
Target: testuser@yourdomain.com
Search Type: Email
Sources: HIBP ✓, DeHashed ✓, Local DB ✓, Dark Web Monitor ✓
```

**[Screen: Clicking "Start Analysis" — progress indicator showing each source being queried in sequence]**

> "Click Start Analysis. The engine queries each source sequentially — HIBP first because it's fastest, then DeHashed, then the local database, and finally the dark web monitor. Watch the progress indicator as each phase completes."

```bash
[Breach Intel] ═══════════════════════════════════════════════════
[Breach Intel]   BREACH INTELLIGENCE REPORT
[Breach Intel]   Target: testuser@yourdomain.com
[Breach Intel] ═══════════════════════════════════════════════════

[Breach Intel] Phase 1/4: Have I Been Pwned
[Breach Intel] ─────────────────────────────────────────
[Breach Intel] Querying HIBP API...
[Breach Intel] EXPOSED in 3 breaches:
[Breach Intel]   ▸ LinkedIn (2012) — Emails, Passwords (SHA1)
[Breach Intel]   ▸ Adobe (2013) — Emails, Passwords (3DES), Password hints
[Breach Intel]   ▸ Collection #1 (2019) — Emails, Passwords (plaintext)
[Breach Intel] Data types exposed: email, password hash, password hint

[Breach Intel] Phase 2/4: DeHashed
[Breach Intel] ─────────────────────────────────────────
[Breach Intel] Querying DeHashed API...
[Breach Intel] Found 4 records:
[Breach Intel]   ▸ LinkedIn breach: hash=sha1:5baa61e4c9b93f3f...
[Breach Intel]   ▸ Adobe breach: hash=3des:2M+7Eh7... hint="pet name"
[Breach Intel]   ▸ Collection #1: password=p@ssw0rd123
[Breach Intel]   ▸ Pastebin dump (2020): email + IP address

[Breach Intel] Phase 3/4: Local Database
[Breach Intel] ─────────────────────────────────────────
[Breach Intel] Searching local breach database...
[Breach Intel] No records found in local DB

[Breach Intel] Phase 4/4: Dark Web Monitor
[Breach Intel] ─────────────────────────────────────────
[Breach Intel] Checking recent paste sites and forums...
[Breach Intel] 1 mention found:
[Breach Intel]   ▸ Paste site (2024-01-20): email listed in credential dump
```

**[Screen: Results panel populating with breach details — breach name, date, data types, severity indicators]**

> "The results show this email appeared in three major breaches. The LinkedIn breach from 2012 exposed a SHA-1 hashed password — those are trivially crackable today. Adobe's 2013 breach used weak 3DES encryption with password hints. And Collection 1 from 2019 contained the plaintext password directly. DeHashed confirmed the findings and provided additional detail — including a partial password from the Collection 1 breach. This is exactly the kind of intelligence that enables password spraying attacks during an authorized engagement."

---

## SECTION 4: Domain-Wide Exposure Assessment (9:30 – 11:30)

**[Screen: Switching search type to "Domain" — entering own domain]**

> "Now let's do a domain-wide search. This queries all sources for any email address associated with our domain. In a real engagement, this reveals how many employees have been exposed across all known breaches — giving you a credential exposure score for the entire organization."

```bash
Target: yourdomain.com
Search Type: Domain
Sources: HIBP ✓, DeHashed ✓
```

**[Screen: Domain search results — showing multiple email addresses with their breach exposure]**

> "The domain search returns aggregated results. Here we can see four test accounts on our domain that appeared across various breaches. The results are sorted by exposure severity — accounts appearing in more breaches or with plaintext passwords exposed rank higher."

```bash
[Breach Intel] ═══════════════════════════════════════════════════
[Breach Intel]   DOMAIN EXPOSURE REPORT: yourdomain.com
[Breach Intel] ═══════════════════════════════════════════════════

[Breach Intel] Accounts exposed: 4
[Breach Intel] Total breach appearances: 9
[Breach Intel] Unique breaches: 5

[Breach Intel] ▸ testuser@yourdomain.com — 3 breaches (HIGH risk)
[Breach Intel]   Plaintext password available (Collection #1)
[Breach Intel] ▸ admin.test@yourdomain.com — 3 breaches (HIGH risk)
[Breach Intel]   Password hash crackable (SHA-1)
[Breach Intel] ▸ dev.test@yourdomain.com — 2 breaches (MEDIUM risk)
[Breach Intel]   Only hashed credentials (bcrypt)
[Breach Intel] ▸ info@yourdomain.com — 1 breach (LOW risk)
[Breach Intel]   Email only, no credentials

[Breach Intel] ─────────────────────────────────────────
[Breach Intel] RISK SCORE: 72/100 (HIGH)
[Breach Intel] Recommendation: Immediate password reset for high-risk accounts
```

**[Screen: Risk assessment panel — showing a risk score gauge, exposure timeline, and recommendations]**

> "The risk assessment panel calculates an overall exposure score. Our domain scores 72 out of 100 — HIGH risk — primarily because plaintext passwords are available for one account and easily crackable hashes for another. The recommendations section suggests immediate password resets and multi-factor authentication enforcement. In an engagement report, this data quantifies the credential reuse risk to stakeholders."

---

## SECTION 5: Analyzing Breach Timelines (11:30 – 13:30)

**[Screen: Timeline visualization — horizontal chart showing breach events plotted chronologically for the domain]**

> "The timeline view shows when each breach occurred relative to the target's accounts. Older breaches — LinkedIn 2012, Adobe 2013 — have had years for the data to circulate. Passwords from these breaches are in every dictionary and cracking wordlist. Newer breaches pose a higher risk of credentials still being active because users may not have changed passwords since the breach was disclosed."

**[Screen: Highlighting the "Collection #1" breach (2019) with a warning indicator — "Plaintext credentials available"]**

> "Collection 1 from 2019 is particularly dangerous because it contained plaintext passwords — no cracking required. If an employee used that same password on their corporate account and hasn't changed it since 2019, that's a direct access path. During an authorized engagement, you'd add these credentials to your password spray list and test them against the target's authentication endpoints."

**[Screen: Correlation panel — showing password reuse indicators across breaches]**

> "The correlation panel identifies potential password reuse patterns. If the same hash appears in multiple breaches for the same email, the user likely hasn't changed their password between breaches. Huginn flags these as 'persistent credential' indicators — they're the highest-value targets for credential reuse attacks because the password has remained static for years."

---

## SECTION 6: Generating Reports and Recommendations (13:30 – 15:30)

**[Screen: Report generation panel — "Generate Breach Exposure Report" button with format options]**

> "From the breach intelligence results, you can generate a standalone exposure report. This is a deliverable you might provide to a client as part of the reconnaissance phase — it documents their credential exposure without requiring any active testing. Click 'Generate Breach Exposure Report' and select your format."

```bash
Report Options:
  Format: PDF (Executive) | JSON (Technical) | CSV (Raw Data)
  Include: Risk Score ✓, Recommendations ✓, Timeline ✓
  Redaction: Mask passwords ✓, Show only partial hashes ✓
```

**[Screen: PDF report preview — showing executive summary with risk score, breach timeline, and remediation recommendations]**

> "The PDF executive format is suitable for non-technical stakeholders. It includes the risk score, a breach timeline, the number of exposed accounts, and specific remediation recommendations — enforce MFA, require password changes, monitor for credential stuffing attacks. Notice that passwords are automatically redacted in the report — you never include plaintext credentials in client deliverables."

**[Screen: Export to Findings — showing breach data being added to the Findings module for the final engagement report]**

> "You can also export breach findings directly to Huginn's Findings module. Each exposed account becomes a finding with appropriate severity — Critical for plaintext password exposure, High for crackable hashes, Medium for hashed-only credentials, and Low for email-only exposure. These findings then appear in your final engagement report alongside vulnerability scan results and exploitation evidence."

**[Screen: Recommendations list — MFA enforcement, password rotation policy, dark web monitoring subscription, breach notification procedures]**

> "Huginn generates contextualized recommendations based on the exposure data. For high-risk accounts with plaintext credentials, it recommends immediate forced password resets. For medium-risk accounts, it suggests credential monitoring and proactive rotation policies. For the organization overall, it recommends dark web monitoring services and employee security awareness training focused on password reuse."

---

## SECTION 7: Certification Mapping and Practice (15:30 – 16:30)

**[Screen: Slide showing OSCP and CEH certification mapping for breach intelligence]**

> "Breach intelligence maps to the OSCP Information Gathering domain — specifically the passive information gathering objectives. While OSCP won't explicitly ask you to query breach databases, the credential intelligence you gather directly feeds into password attacks later in the engagement. For CEH, this falls under Module 2, Footprinting and Reconnaissance, covering OSINT techniques and credential discovery."

**[Screen: Practice resources — own email addresses with HIBP, breach reporting methodology documentation]**

> "For practice, check your own email addresses on Have I Been Pwned's website — the free web interface lets you check individual emails without an API key. Understand how the data is presented and think about how you'd use that intelligence offensively. When you're ready to use the full API programmatically through Huginn, the Enterprise tier gives you the automated workflow we demonstrated today."

**[Screen: Tips slide — "Document breach exposure in your reconnaissance notes; build targeted wordlists from discovered patterns"]**

> "An exam tip: even without automated breach intelligence tools, understanding that breach data exists and that credential reuse is common informs your approach to password attacks. On OSCP, if you find a username and common passwords aren't working, consider that the password might follow patterns seen in public breach data — company name plus year, season plus numbers, or other predictable formats."

---

## OUTRO (16:30 – end)

**[Screen: Summary slide — Breach Intelligence: HIBP Integration, DeHashed Queries, Domain Exposure Assessment, Risk Scoring, Report Generation | Enterprise Tier | Next: Video 20 — People/Employee OSINT]**

> "That's Breach Intelligence in Huginn. We configured API keys for Have I Been Pwned and DeHashed, queried breach databases for individual email exposure, performed a domain-wide exposure assessment revealing four compromised accounts, analyzed breach timelines for credential reuse indicators, and generated a client-ready exposure report. Remember — this is an Enterprise tier feature requiring both a Huginn Enterprise license and separate API subscriptions for HIBP and DeHashed. In the next video, we'll cover People and Employee OSINT — discovering employee names, roles, and email patterns for a target organization. See you there."
