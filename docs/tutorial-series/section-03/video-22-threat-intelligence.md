# VIDEO 22: Threat Intelligence
### IOC Feeds, APT Tracking & Threat Landscape Analysis
**Suggested length:** 15–18 minutes
**License Tier:** Enterprise
**Certification Relevance:** OSCP: Information Gathering | CEH: Footprinting & Reconnaissance

---

## INTRO (0:00 – 1:45)

**[Screen: Huginn splash screen with Section 3 title card "OSINT and Intelligence Gathering"]**

> "Welcome back to the Huginn tutorial series. In this video we're covering Threat Intelligence Integration — Huginn's Enterprise tier feature that connects to external intelligence platforms like Shodan and VirusTotal to assess the threat landscape around target infrastructure. Unlike the passive OSINT techniques we covered in previous videos, threat intelligence gives you contextual awareness — is this IP associated with known malware? Has this domain been flagged by security vendors? What services does Shodan see exposed on this address?"

**[Screen: Slide showing the threat intelligence ecosystem — Shodan, VirusTotal, AlienVault OTX, Abuse.ch, ThreatFox, MalwareBazaar icons connected to Huginn]**

> "Huginn integrates with six threat intelligence sources: Shodan for internet-wide service intelligence, VirusTotal for multi-engine malware and reputation analysis, AlienVault OTX for open threat exchange data, Abuse.ch for botnet and malware tracking, ThreatFox for IOC sharing, and MalwareBazaar for malware sample intelligence. This video requires API keys for Shodan and VirusTotal — we'll walk through obtaining and configuring those step by step."

**[Screen: Enterprise tier badge highlighted — "This feature requires an Enterprise license ($299/month)"]**

> "Important note — Threat Intelligence Integration is an Enterprise tier feature. You'll need an active Enterprise license plus API keys from the individual intelligence platforms. We'll demonstrate against our own IP addresses and domains — nothing belonging to third parties (see Video 17: Subdomain Discovery for how we set up our own infrastructure)."

---

## SECTION 1: API Key Setup — Shodan (1:45 – 4:00)

**[Screen: Browser navigating to shodan.io — account registration page]**

> "Let's start by setting up our API keys. First, Shodan. Navigate to shodan.io and create an account if you don't have one. Shodan offers a free tier with limited API queries, but for integration with Huginn you'll want at least a Membership plan for higher rate limits."

**[Screen: Shodan dashboard — navigating to Account → API Key page]**

> "Once logged in, click your profile icon in the top right, then go to Account. Your API key is displayed on the account overview page. It's a 32-character alphanumeric string. Copy this — we'll need it in a moment."

```bash
# Shodan API Key Location:
# Login → Profile → Account → API Key
# Format: aBcDeFgH1234567890iJkLmNoP (32 characters)
# Free tier: 100 queries/month
# Membership: Unlimited queries + additional features
```

**[Screen: Huginn application — navigating to Settings → API Keys configuration panel]**

> "In Huginn, go to Settings from the main menu, then find the API Keys section. You'll see fields for each supported intelligence platform. Paste your Shodan API key into the designated field. Huginn validates the key immediately — you'll see a green checkmark if it's accepted."

**[Screen: Settings panel showing the Shodan API key field with green validation checkmark]**

> "The validation check makes a single test query to confirm the key is valid and has sufficient permissions. If you see a red X, double-check that you copied the full key without extra spaces."

---

## SECTION 2: API Key Setup — VirusTotal (4:00 – 6:00)

**[Screen: Browser navigating to virustotal.com — sign up / login page]**

> "Next, VirusTotal. Navigate to virustotal.com and create a free account. VirusTotal's free API tier provides 4 requests per minute and 500 requests per day — sufficient for individual assessments. Premium plans offer higher limits and additional data."

**[Screen: VirusTotal dashboard — navigating to user menu → API key page]**

> "After logging in, click your avatar in the top right, select API key from the dropdown menu. You'll see your API key displayed — it's a 64-character hexadecimal string. Copy this."

```bash
# VirusTotal API Key Location:
# Login → Avatar → API key
# Format: 64-character hex string (a-f, 0-9)
# Free tier: 4 requests/minute, 500 requests/day
# Premium: Higher limits, additional endpoints
```

**[Screen: Huginn Settings → API Keys — pasting VirusTotal key into the designated field]**

> "Back in Huginn's API Keys settings, paste the VirusTotal key into its field. Again, you'll get immediate validation. With both keys configured, the Threat Intelligence module is ready to use."

**[Screen: Both API keys showing green validation checkmarks — "Ready" status indicator]**

> "Both keys validated successfully. The status indicator at the top of the Threat Intelligence module will now show 'Ready' instead of 'Configuration Required'. Let's move to the intelligence gathering interface."

---

## SECTION 3: Huginn Threat Intelligence Interface (6:00 – 7:30)

**[Screen: Navigating to OSINT & Intelligence → Threat Intelligence tab — interface overview]**

> "Navigate to OSINT and Intelligence, then select the Threat Intelligence tab. The interface has a target input that accepts IP addresses or domain names. Below that, you'll see toggles for each intelligence source — Shodan, VirusTotal, AlienVault OTX, Abuse.ch Feodo Tracker, ThreatFox, and MalwareBazaar."

**[Screen: Threat Intelligence page — highlighting the scan mode selector: "Quick Check", "Deep Analysis", "Full Threat Intel"]**

> "Three analysis modes are available. Quick Check runs a basic reputation lookup — fast but limited. Deep Analysis queries all enabled sources and correlates results. Full Threat Intel does everything Deep Analysis does plus cross-references findings with known threat actor TTPs and generates a risk assessment score. We'll use Full Threat Intel for our demonstration."

**[Screen: Showing the source toggles — all six enabled with green indicators showing API connectivity]**

> "All six sources are enabled and showing green connectivity indicators. Sources that don't require API keys — AlienVault OTX, Abuse.ch, ThreatFox, and MalwareBazaar — work out of the box. Shodan and VirusTotal require the keys we just configured."

---

## SECTION 4: IP Address Threat Intelligence (7:30 – 10:30)

**[Screen: Entering own cloud infrastructure IP address in the target field — selecting "Full Threat Intel" mode]**

> "Let's query our own infrastructure IP address. Enter the IP of our test EC2 instance and select Full Threat Intel. This will query all six sources and produce a comprehensive threat assessment."

**[Screen: Clicking "Analyze" — progress bars for each source advancing]**

> "Click Analyze. Watch the progress indicators — each source is queried in parallel. Shodan typically responds fastest since it's querying pre-indexed data. VirusTotal may take a few seconds as it aggregates results from dozens of security engines."

```bash
[THREAT] Full Threat Intel starting for: 203.0.113.42 (own infrastructure)
[THREAT] Querying 6 intelligence sources in parallel...

[SHODAN] Querying Shodan for 203.0.113.42...
[SHODAN] Results:
  → Organization: Amazon Web Services (AWS)
  → ASN: AS16509
  → Country: US (us-west-2)
  → Open ports: 22 (SSH), 80 (HTTP), 443 (HTTPS)
  → SSH: OpenSSH 8.9p1 Ubuntu-3ubuntu0.6
  → HTTP: nginx/1.24.0
  → HTTPS: nginx/1.24.0 (Let's Encrypt certificate)
  → Last seen: 2024-01-15
  → Vulnerabilities: None identified
  → Tags: cloud, self-signed (incorrect — actually Let's Encrypt)

[VIRUSTOTAL] Querying VirusTotal for 203.0.113.42...
[VIRUSTOTAL] Results:
  → Detection ratio: 0/94 (clean)
  → Community score: 0 (neutral — no reports)
  → Categories: None assigned
  → Last analysis: 2024-01-14
  → Associated domains: meridian-tech-demo.own-infra.local
  → HTTPS certificate: CN=meridian-tech-demo.own-infra.local (Let's Encrypt)
  → Whois: Amazon Technologies Inc.

[ALIENVAULT] Querying AlienVault OTX for 203.0.113.42...
[ALIENVAULT] Results:
  → Pulses: 0 (not mentioned in any threat pulse)
  → Reputation: No data
  → Related indicators: None

[ABUSE_CH] Checking Abuse.ch Feodo Tracker...
[ABUSE_CH] Results:
  → Not found in botnet C&C database
  → Not found in malware distribution database

[THREATFOX] Checking ThreatFox IOC database...
[THREATFOX] Results:
  → No IOCs associated with this IP

[MALWAREBAZAAR] Checking MalwareBazaar...
[MALWAREBAZAAR] Results:
  → No malware samples associated with this IP

[THREAT] Full Threat Intel complete for 203.0.113.42
[THREAT] Risk Score: 0/100 (Clean)
[THREAT] Summary: No threats detected across 6 intelligence sources
```

**[Screen: Results dashboard showing all six sources with results — risk score gauge at 0/100 (green)]**

> "Our own infrastructure comes back clean across all sources — as expected. Shodan reveals exactly what services we have exposed: SSH, HTTP, and HTTPS on an nginx server. It correctly identifies this as AWS infrastructure in us-west-2. VirusTotal confirms zero detections across 94 security engines. None of the threat feeds have our IP flagged. The aggregate risk score is 0 out of 100."

**[Screen: Expanding the Shodan results — showing detailed service banners and version information]**

> "Drill into the Shodan results to see the detailed service intelligence. Shodan captured our SSH banner revealing the exact OpenSSH version, the nginx version on both HTTP and HTTPS, and the Let's Encrypt certificate details. This is the same information an attacker would find — useful for understanding your own exposure. Notice how Shodan indexed our infrastructure even though we never asked it to — Shodan continuously scans the entire IPv4 space."

---

## SECTION 5: Domain Reputation Analysis (10:30 – 12:30)

**[Screen: Clearing the previous results — entering own domain name in the target field]**

> "Now let's check our domain. Clear the previous results and enter our demonstration domain. Domain queries focus on reputation analysis, DNS intelligence, and associated file submissions."

```bash
[THREAT] Full Threat Intel starting for: meridian-tech-demo.own-infra.local
[THREAT] Querying 6 intelligence sources...

[VIRUSTOTAL] Domain report for meridian-tech-demo.own-infra.local:
  → Detection ratio: 0/94 (clean)
  → Categories: uncategorized
  → DNS records: A → 203.0.113.42
  → Subdomains observed: www, mail, api (from passive DNS)
  → Last DNS resolution: 2024-01-15
  → HTTPS certificate: Valid (Let's Encrypt, expires 2024-04-15)
  → No communicating files (no malware samples contact this domain)
  → No downloaded files associated

[SHODAN] DNS fallback for meridian-tech-demo.own-infra.local:
  → Resolved to: 203.0.113.42
  → (IP results from previous query apply)

[ALIENVAULT] Domain report:
  → Passive DNS records: 3 subdomains observed
  → No malware associations
  → No threat pulses reference this domain

[ABUSE_CH] Domain check:
  → Not in malware domain blocklist
  → Not in phishing domain database

[THREATFOX] Domain IOC check:
  → No IOCs associated

[MALWAREBAZAAR] Domain association check:
  → No malware samples reference this domain

[THREAT] Full Threat Intel complete for meridian-tech-demo.own-infra.local
[THREAT] Risk Score: 0/100 (Clean)
[THREAT] Domain Age: 6 months | Reputation: Neutral (newly registered)
```

**[Screen: Domain results dashboard — showing DNS intelligence, certificate status, and reputation across engines]**

> "The domain comes back clean. VirusTotal shows zero detections, reveals passive DNS data including subdomains it's observed being resolved, and confirms our certificate validity. AlienVault's passive DNS corroborates the subdomain list. No threat feeds flag our domain. The one note is 'newly registered' — some security systems flag young domains as potentially suspicious, which is useful context."

**[Screen: Showing the "Passive DNS" tab within results — historical DNS resolution data]**

> "The Passive DNS tab shows historical resolution data collected by VirusTotal and AlienVault. This reveals what subdomains have been observed over time and what IP addresses they've pointed to. For our own infrastructure this is expected data, but when analyzing a target, passive DNS history can reveal infrastructure changes, old servers, and migration patterns."

---

## SECTION 6: Threat Feed Correlation and IOC Analysis (12:30 – 14:30)

**[Screen: Slide explaining threat feed types — "Botnet C&C lists", "Malware distribution", "Phishing domains", "IOC databases"]**

> "Let's discuss what the threat feeds actually contain. Abuse.ch's Feodo Tracker maintains a database of botnet command-and-control servers — primarily Emotet, Dridex, TrickBot, and QakBot infrastructure. ThreatFox aggregates Indicators of Compromise shared by the security community — IP addresses, domains, and URLs associated with specific malware families. MalwareBazaar tracks malware samples and the infrastructure they communicate with."

**[Screen: Huginn interface showing the "Feed Status" panel — all feeds showing online with last-updated timestamps]**

> "Huginn maintains a Feed Status panel showing the health of each intelligence source. You can see when each feed was last updated and whether the API endpoint is responding. If a feed goes offline, Huginn marks it with a warning and excludes it from aggregate scoring rather than failing the entire query."

```bash
[THREAT] Feed Status:
  → Shodan API: Online (last query: 2 minutes ago)
  → VirusTotal API: Online (last query: 2 minutes ago)
  → AlienVault OTX: Online (feed updated: 4 hours ago)
  → Abuse.ch Feodo: Online (feed updated: 1 hour ago)
  → ThreatFox: Online (feed updated: 30 minutes ago)
  → MalwareBazaar: Online (feed updated: 2 hours ago)
```

**[Screen: Showing a hypothetical example of what a POSITIVE hit looks like — using documentation/reference data, not a real malicious IP]**

> "For educational context, let me show you what a positive detection looks like. When an IP or domain IS found in threat feeds, the results turn red with detailed attribution — which malware family, when it was first reported, which feeds flagged it, and the confidence level. The risk score jumps proportionally. A hit on one feed might score 30 out of 100. Hits on multiple feeds compounds the score. A hit on Feodo Tracker plus VirusTotal detections would push into the 70-90 range."

**[Screen: Reference screenshot showing the risk score explanation — how scores are weighted across sources]**

> "Huginn's risk scoring weights sources differently. VirusTotal multi-engine consensus carries the highest weight because it aggregates 94 independent security vendors. Abuse.ch feeds are highly specific — if an IP appears there, it was confirmed as malicious infrastructure. AlienVault OTX community intelligence has moderate weight since it's community-contributed. Understanding these weights helps you assess the confidence level of any finding."

---

## SECTION 7: Certification Mapping and Practice (14:30 – 16:00)

**[Screen: Slide showing certification mapping — OSCP: Information Gathering, CEH: Footprinting & Reconnaissance (Module 2)]**

> "Threat intelligence maps to the OSCP Information Gathering domain — specifically understanding target infrastructure exposure and correlating findings with known vulnerabilities. For CEH, this falls under Module 2: Footprinting and Reconnaissance, covering OSINT sources, threat intelligence platforms, and IP reputation analysis."

**[Screen: Bullet list of exam-relevant skills — "Shodan query syntax", "VirusTotal interpretation", "IOC correlation", "Risk assessment"]**

> "For OSCP, knowing how to use Shodan to identify exposed services is directly tested — the exam gives you targets and expects you to enumerate everything available. Understanding what intelligence Shodan and similar platforms provide about target infrastructure helps prioritize your attack approach. For CEH, threat intelligence platforms and their data types are explicitly tested."

**[Screen: Practice suggestions — "Query your own infrastructure via Shodan", "Analyze known-malicious IOCs from threat reports", "Practice API integration setup"]**

> "For practice, start by querying your own public infrastructure through Shodan's web interface to understand what's exposed. Read published threat reports and practice correlating their IOCs through VirusTotal. The API setup process itself is worth practicing — many engagement tools require API key configuration, and being comfortable with that workflow saves time during real assessments."

---

## OUTRO (16:00 – end)

**[Screen: Summary slide — "Threat Intelligence: Shodan + VirusTotal API Setup, IP/Domain Reputation, Threat Feed Correlation, Risk Scoring | Next: Video 23 — Infrastructure OSINT"]**

> "That's Threat Intelligence Integration in Huginn. We walked through setting up Shodan and VirusTotal API keys, queried our own infrastructure to understand the intelligence available, analyzed domain reputation across six sources, and explained how threat feed correlation and risk scoring work. Remember — this is an Enterprise tier feature requiring both the license and individual API keys. In the next video, we'll cover Infrastructure OSINT — mapping cloud infrastructure, identifying hosting providers, and fingerprinting technology stacks using Huginn's Cloud Enumeration engine. See you there."
