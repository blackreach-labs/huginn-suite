# VIDEO 17: Subdomain Discovery
### Passive Enumeration, DNS Brute-Force & Wildcard Detection
**Suggested length:** 14–18 minutes
**License Tier:** Free
**Certification Relevance:** OSCP: Information Gathering | CEH: Footprinting & Reconnaissance

---

## INTRO (0:00 – 1:30)

**[Screen: Huginn splash screen with Section 3 title card "OSINT and Intelligence Gathering"]**

> "Welcome to Section 3 of the Huginn tutorial series — OSINT and Intelligence Gathering. In this section we shift from active enumeration to passive reconnaissance. The key difference: passive techniques gather information without sending a single packet to the target. Instead we query public data sources — search engines, certificate logs, DNS aggregators — that have already indexed the target's infrastructure."

**[Screen: Slide contrasting Active Recon (sends traffic to target) vs Passive Recon (queries third-party sources)]**

> "Subdomain discovery is the foundation of passive OSINT. Every subdomain an organization exposes — whether it's a dev server, staging environment, or forgotten API endpoint — represents a potential attack surface. In this video we'll use Huginn's Subdomain Discovery engine to passively enumerate subdomains using multiple data sources, then verify them with DNS resolution and wildcard detection. If you completed Video 5 on DNS Enumeration, you already know how brute-force subdomain discovery works — this time we're doing it without touching the target at all (see Video 5: DNS Enumeration)."

---

## SECTION 1: Passive vs Active Subdomain Discovery (1:30 – 3:30)

**[Screen: Diagram showing passive sources — CT Logs, Search Engines, DNS Aggregators, Wayback Machine — all pointing to a "results" node without connecting to the target server]**

> "Active subdomain enumeration — the brute-force approach from Video 5 — sends thousands of DNS queries directly to the target's nameservers. It works, but it's noisy. The target can see your queries in their logs. Passive enumeration takes a completely different approach. We query third-party databases that have already collected DNS data through web crawling, certificate issuance monitoring, and zone file aggregation."

**[Screen: List of passive data sources with logos — crt.sh, CertSpotter, VirusTotal, Wayback Machine, Censys]**

> "Huginn's Subdomain Discovery engine queries multiple sources in parallel. The free tier gives you access to crt.sh for Certificate Transparency logs, CertSpotter as a backup CT source, and the Wayback Machine for historical URL data. If you configure API keys, you can also query VirusTotal and Censys for additional coverage. Each source may find subdomains the others miss, so combining them gives the most complete picture."

**[Screen: Table comparing detection likelihood — CT Logs find certificates, Wayback finds historically crawled pages, VirusTotal finds DNS resolution history]**

> "Why do different sources find different results? CT Logs capture any subdomain that has had a certificate issued — even internal ones if the organization uses public CAs. The Wayback Machine finds pages that were once publicly accessible but may have since been taken down. VirusTotal aggregates DNS resolution data from its scanning network. The overlap between these sources is surprisingly small — typically 40 to 60 percent — which is why querying all of them matters."

---

## SECTION 2: Huginn OSINT Interface (3:30 – 5:30)

**[Screen: Huginn application — navigating from Home to OSINT & Intelligence → Subdomain Discovery tab]**

> "Open Huginn and navigate to the OSINT and Intelligence module from the sidebar. You'll see multiple tabs across the top — Subdomain Discovery, Certificate Transparency, Breach Intelligence, People Search, and more. Click the Subdomain Discovery tab."

**[Screen: Subdomain Discovery interface — target input field, source selection checkboxes, scan options panel]**

> "The interface has three areas. At the top, the target input field accepts a single domain name — no subdomains, no protocols, just the root domain. Below that is the source selection panel where you choose which passive sources to query. Each source has a checkbox and a status indicator showing whether it's available — green for ready, yellow for requires API key, red for unavailable."

**[Screen: Close-up on source selection — crt.sh (green), CertSpotter (green), Wayback Machine (green), VirusTotal (yellow — API key required), Censys (yellow — API key required)]**

> "By default, the three free sources — crt.sh, CertSpotter, and Wayback Machine — are enabled and ready to go. VirusTotal and Censys show yellow indicators because they require API keys. We'll set those up later. For now, the free sources alone can discover dozens or even hundreds of subdomains for most domains."

**[Screen: Scan options panel — showing "Resolve discovered subdomains" toggle, "Detect wildcards" toggle, thread count slider, timeout settings]**

> "Below the sources, the scan options panel lets you control post-discovery behavior. The 'Resolve discovered subdomains' toggle performs a DNS A-record lookup on every subdomain found, confirming which ones currently resolve to live IP addresses. The 'Detect wildcards' toggle identifies domains configured with wildcard DNS — where any subdomain resolves — so you can filter out false positives. Both are enabled by default, and I recommend leaving them on."

---

## SECTION 3: Running a Passive Scan (5:30 – 8:00)

**[Screen: Typing "yourdomain.com" in the target field — using own cloud infrastructure domain with 10+ subdomains pre-configured]**

> "For this demonstration, I'm using my own domain that I've configured with over ten subdomains specifically for this tutorial — mail, dev, staging, api, admin, vpn, test, docs, cdn, and blog. Since this is my infrastructure, I can verify the completeness of what the passive scan finds against what I know actually exists."

```bash
Target: yourdomain.com
Sources: crt.sh ✓, CertSpotter ✓, Wayback Machine ✓
Options: Resolve subdomains ✓, Detect wildcards ✓
```

**[Screen: Clicking "Start Scan" — progress indicator showing each source being queried sequentially]**

> "Click Start Scan. Watch the progress panel — it shows each source being queried in parallel. crt.sh typically responds fastest because it has a straightforward JSON API. CertSpotter may take a few seconds longer. The Wayback Machine is usually the slowest because it's searching through historical URL archives."

**[Screen: Real-time output terminal showing source-by-source results flowing in]**

> "Results flow in as each source completes. You can see the terminal output showing which source discovered each subdomain. Notice some subdomains appear from multiple sources — that's expected and the engine deduplicates automatically. The counter in the top-right shows unique subdomains discovered so far."

```bash
[Subdomain Engine] Starting passive enumeration for yourdomain.com
[Subdomain Engine] Querying crt.sh...
[crt.sh] Found: mail.yourdomain.com
[crt.sh] Found: dev.yourdomain.com
[crt.sh] Found: staging.yourdomain.com
[crt.sh] Found: api.yourdomain.com
[crt.sh] Found: admin.yourdomain.com
[crt.sh] Found: docs.yourdomain.com
[crt.sh] Found: cdn.yourdomain.com
[crt.sh] Source complete: 7 subdomains found

[Subdomain Engine] Querying CertSpotter...
[CertSpotter] Found: mail.yourdomain.com (duplicate)
[CertSpotter] Found: vpn.yourdomain.com
[CertSpotter] Found: api.yourdomain.com (duplicate)
[CertSpotter] Found: blog.yourdomain.com
[CertSpotter] Source complete: 2 new subdomains (4 total, 2 duplicates)

[Subdomain Engine] Querying Wayback Machine...
[Wayback] Found: test.yourdomain.com
[Wayback] Found: dev.yourdomain.com (duplicate)
[Wayback] Found: old.yourdomain.com
[Wayback] Source complete: 2 new subdomains (3 total, 1 duplicate)

[Subdomain Engine] Deduplication complete: 11 unique subdomains from 3 sources
```

---

## SECTION 4: DNS Resolution and Wildcard Detection (8:00 – 10:30)

**[Screen: Progress indicator shifting to "Resolving discovered subdomains..." phase]**

> "After all sources complete, the engine moves to DNS resolution. This step sends A-record queries for every discovered subdomain to confirm which ones are currently live. A subdomain that appeared in CT logs six months ago might no longer resolve if the server was decommissioned."

```bash
[DNS Resolver] Resolving 11 subdomains (50 concurrent workers)...
[DNS Resolver] mail.yourdomain.com → 203.0.113.10 ✓
[DNS Resolver] dev.yourdomain.com → 203.0.113.20 ✓
[DNS Resolver] staging.yourdomain.com → 203.0.113.25 ✓
[DNS Resolver] api.yourdomain.com → 203.0.113.30 ✓
[DNS Resolver] admin.yourdomain.com → 203.0.113.5 ✓
[DNS Resolver] vpn.yourdomain.com → 203.0.113.15 ✓
[DNS Resolver] test.yourdomain.com → 203.0.113.40 ✓
[DNS Resolver] docs.yourdomain.com → 203.0.113.50 ✓
[DNS Resolver] cdn.yourdomain.com → 198.51.100.77 ✓ (CDN IP)
[DNS Resolver] blog.yourdomain.com → 203.0.113.55 ✓
[DNS Resolver] old.yourdomain.com → NXDOMAIN ✗ (not resolving)
[DNS Resolver] Resolution complete: 10 live, 1 dead
```

**[Screen: Results table showing subdomain, IP address, status (Live/Dead), and source columns]**

> "Ten of our eleven subdomains resolve to live IP addresses. One — old.yourdomain.com — returns NXDOMAIN, meaning it no longer exists in DNS. The Wayback Machine found it because it existed historically, but it's since been removed. This is still valuable intelligence — it tells us the organization previously had that subdomain, and if we check web archives we might find what it hosted."

**[Screen: Wildcard detection output — testing random string subdomain to identify wildcard DNS]**

> "Next comes wildcard detection. The engine generates a random subdomain string — something like xk7q2m9z.yourdomain.com — and checks if it resolves. If it does, the domain has wildcard DNS configured, meaning any subdomain resolves to the same IP. In that case, all our results need to be filtered against that wildcard IP to remove false positives."

```bash
[Wildcard Detection] Testing random subdomain: xk7q2m9z.yourdomain.com
[Wildcard Detection] Result: NXDOMAIN — no wildcard detected
[Wildcard Detection] All 10 live subdomains are confirmed valid (no wildcard filtering needed)
```

> "No wildcard detected for our domain — all ten live results are genuine. If a wildcard had been found, the engine would automatically filter out any subdomain resolving to the wildcard IP, keeping only those with unique addresses."

---

## SECTION 5: Understanding the Results (10:30 – 12:30)

**[Screen: Results panel — Table View showing columns: Subdomain, IP Address, Source, First Seen, Status]**

> "Let's examine the results in detail. The table view shows each subdomain with its resolved IP address, the source that discovered it, the first-seen timestamp, and its live-or-dead status. You can sort by any column — sorting by IP address clusters hosts on the same subnet, which is useful for identifying server groups."

**[Screen: Highlighting the "Source" column showing color-coded badges — crt.sh (blue), CertSpotter (green), Wayback (orange)]**

> "The source column uses color-coded badges so you can quickly see where each subdomain came from. Subdomains found by multiple sources get stacked badges. This matters for confidence — a subdomain found by three sources independently is almost certainly real, while one found by only the Wayback Machine might be historical."

**[Screen: Statistics panel — pie chart showing source contribution: crt.sh 7, CertSpotter 2, Wayback 2]**

> "The statistics panel breaks down source contribution. In our scan, crt.sh found the most subdomains at seven, which is typical — CT logs are the richest passive source for most domains. CertSpotter contributed two unique finds, and the Wayback Machine added two more. Together they gave us 100% coverage of my known subdomains, except one that was removed before any certificate was issued for it."

**[Screen: Clicking on a single subdomain row to expand details — showing full DNS record, HTTP response code if applicable, and linked certificate data]**

> "Click any row to expand its detail panel. You'll see the full DNS resolution data, response TTL, and — if the subdomain came from a CT source — a link to the certificate that revealed it. This certificate link is valuable for the next video on Certificate Transparency where we'll dig deeper into certificate metadata."

---

## SECTION 6: Exporting and Integration (12:30 – 14:30)

**[Screen: Export button dropdown — JSON, CSV, and "Feed to Port Scanner" option]**

> "To export results, click the Export button. JSON and CSV formats are available for external processing. But the most powerful option is 'Feed to Port Scanner' — this takes all live subdomains and their resolved IPs and queues them as targets in the Port Scanning module. One click connects your passive OSINT directly into active reconnaissance."

```bash
Export Options:
  → JSON (full metadata, suitable for scripting)
  → CSV (spreadsheet-compatible, basic fields)
  → Feed to Port Scanner (auto-queue live hosts as scan targets)
```

**[Screen: Demonstrating the JSON export — showing structured output with all metadata fields]**

> "The JSON export includes full metadata — the domain, each subdomain with its IP, source, discovery timestamp, resolution status, and any associated certificate IDs. You can feed this into custom scripts or import it into other tools."

**[Screen: Showing results flowing into the Asset Inventory panel — discovered subdomains appearing as new assets]**

> "Discovered subdomains also automatically populate the Asset Inventory. Navigate to the Inventory page and you'll see each subdomain listed as an asset with its IP, discovery source, and a 'New' badge. As you scan these hosts further, their inventory cards accumulate findings from port scans, vulnerability scans, and other modules — building a complete picture of each asset over time."

---

## SECTION 7: Certification Mapping and Practice (14:30 – 16:00)

**[Screen: Slide showing OSCP and CEH certification mapping for subdomain discovery]**

> "Passive subdomain discovery maps directly to the OSCP Information Gathering domain. On the exam, you're given a scope that may include wildcards like *.target.com — finding all subdomains in scope is your first task. For CEH, this technique falls under Module 2, Footprinting and Reconnaissance, specifically the DNS footprinting and competitive intelligence objectives."

**[Screen: Slide listing practice targets — own domains with DNS configured, THM "Content Discovery" room]**

> "For practice, set up your own domain with multiple subdomains — even a cheap domain with free DNS will work. Configure ten or more subdomains and run the passive scan to see how quickly CT logs and other sources index them after certificate issuance. The TryHackMe 'Content Discovery' room also covers subdomain enumeration techniques in a guided format."

**[Screen: Tips slide — "Register subdomains and issue Let's Encrypt certs → wait 24h → verify CT log indexing"]**

> "A practical exam tip: when you discover subdomains during an OSCP engagement, immediately feed them into a port scan. The combination of passive subdomain discovery followed by targeted port scanning is one of the most efficient reconnaissance workflows. It maximizes coverage while minimizing your network footprint in the initial phases."

---

## OUTRO (16:00 – end)

**[Screen: Summary slide — Passive Subdomain Discovery: CT Logs, CertSpotter, Wayback Machine, DNS Resolution, Wildcard Detection | Next: Video 18 — Certificate Transparency]**

> "That's passive subdomain discovery in Huginn. We queried three public data sources without sending a single packet to the target, discovered eleven subdomains, resolved ten of them to live IP addresses, and confirmed no wildcard DNS was in play. In the next video, we'll go deeper into Certificate Transparency — examining certificate metadata, monitoring for new certificate issuances, and detecting expired certificates that signal potential takeover opportunities. See you there."
