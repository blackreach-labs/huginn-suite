# VIDEO 5: DNS Enumeration
### Zone Transfers, Record Types & Brute-Force Discovery
**Suggested length:** 14–18 minutes
**License Tier:** Free
**Certification Relevance:** OSCP: Information Gathering | CEH: Enumeration

---

## INTRO (0:00 – 1:30)

**[Screen: Huginn splash screen with Section 2 title card "Recon and Enumeration Tools"]**

> "Welcome back to the Huginn tutorial series. In this video we begin Section 2 — Recon and Enumeration — by tackling DNS enumeration. DNS is the backbone of the internet. Every domain name you type into a browser gets translated into an IP address through the Domain Name System, and for penetration testers, DNS records are a goldmine of intelligence. Misconfigurations like open zone transfers can expose an entire organization's internal network layout in seconds."

**[Screen: Slide showing DNS hierarchy diagram — root servers, TLDs, authoritative nameservers, resolvers]**

> "We'll cover how DNS works at a protocol level, walk through Huginn's DNS enumeration interface, configure different query types, attempt zone transfers, run subdomain brute-force discovery, and interpret the results. If you haven't seen Video 3 on UI Navigation, I recommend watching that first so you're familiar with navigating between Huginn's modules (see Video 3: Navigating the UI)."

---

## SECTION 1: DNS Protocol Fundamentals (1:30 – 4:00)

**[Screen: Animated diagram showing DNS resolution flow — client → recursive resolver → root → TLD → authoritative]**

> "Let's start with a quick refresher on how DNS works. When your machine wants to resolve a hostname, it sends a query to a recursive DNS resolver. That resolver checks its cache first — if it doesn't have the answer, it walks up the hierarchy. It asks a root nameserver which TLD server handles the domain, then asks that TLD server which authoritative nameserver holds the actual records."

**[Screen: Table of DNS record types — A, AAAA, MX, NS, TXT, SOA, CNAME, PTR, SRV]**

> "DNS supports multiple record types, and each reveals different information. A records map hostnames to IPv4 addresses. AAAA records do the same for IPv6. MX records tell us where mail is handled — often revealing internal server names. NS records identify authoritative nameservers. TXT records frequently contain SPF policies, DKIM keys, and domain verification tokens. SOA records expose administrative contact details and zone serial numbers. CNAME records show aliases, and SRV records can reveal specific services running on non-standard ports."

**[Screen: Diagram showing zone transfer — primary nameserver replicating full zone file to secondary]**

> "Zone transfers use the AXFR protocol. They're designed for primary nameservers to replicate their entire zone file to secondary nameservers. When a server is misconfigured and allows zone transfers to any requester, an attacker gets a complete dump of every record in the domain — subdomains, mail servers, internal hosts, everything. This is one of the first things we check during reconnaissance."

---

## SECTION 2: Huginn DNS Enumeration Interface (4:00 – 6:30)

**[Screen: Huginn application — navigating from Home to Recon & Enumeration → DNS Enumeration page]**

> "Let's open Huginn and navigate to the DNS Enumeration module. From the home screen, click Recon and Enumeration in the sidebar, then select DNS Enumeration. You'll see the dedicated DNS interface load with three main areas: the target configuration panel on the left, the controls in the center, and the results pane on the right."

**[Screen: DNS Enumeration page — highlighting the target input field and DNS server configuration]**

> "At the top, you have the target input field where you enter the domain you want to enumerate. Below that is the DNS server configuration — by default Huginn uses your system's DNS resolver, but you can specify a custom nameserver. This is useful when you want to query the target's authoritative nameserver directly, or use a specific public resolver like 8.8.8.8 or 1.1.1.1."

**[Screen: DNS Enumeration page — highlighting the record type checkboxes (A, AAAA, MX, NS, TXT, SOA, CNAME, PTR, SRV) and the "Select All" toggle]**

> "In the center panel, you'll see checkboxes for each DNS record type — A, AAAA, MX, NS, TXT, SOA, CNAME, PTR, and SRV. There's a Select All toggle that checks every type at once. Below that are the enumeration method options: Standard Query, Zone Transfer, and Brute-Force. Each method has its own configuration options that appear when selected."

**[Screen: DNS Enumeration page — showing the wordlist dropdown for brute-force and the output terminal below]**

> "When you select Brute-Force mode, a wordlist dropdown appears with pre-loaded subdomain wordlists — small, medium, and large. You can also load custom wordlists. The output terminal at the bottom shows real-time results as queries execute, and the results table on the right organizes discovered records by type."

---

## SECTION 3: Configuring a DNS Scan (6:30 – 8:30)

**[Screen: DNS Enumeration page — entering "scanme.nmap.org" in the target field]**

> "For our first demonstration, we'll enumerate scanme.nmap.org — the Nmap project's authorized scanning target. Type the domain into the target field. We'll leave the DNS server set to system default for now."

```bash
Target: scanme.nmap.org
DNS Server: System Default
```

**[Screen: Selecting record types — checking A, AAAA, MX, NS, TXT, SOA]**

> "Let's select multiple record types. I'll check A, AAAA, MX, NS, TXT, and SOA. This gives us a comprehensive picture of the domain's DNS configuration without being overly noisy."

**[Screen: Selecting "Standard Query" as the enumeration method]**

> "We'll start with a Standard Query — this simply resolves each selected record type for the target domain. It's the quietest option and gives us baseline information before we try more aggressive techniques."

**[Screen: Clicking the "Start Scan" button — progress indicator begins]**

> "Click Start Scan. Watch the output terminal — you'll see each query go out and results come back in real time. The progress bar at the top tracks completion across all selected record types."

---

## SECTION 4: Live Demo — Standard DNS Query (8:30 – 10:30)

**[Screen: Terminal output showing DNS query results populating in real time]**

> "Here come the results. The A record resolves scanme.nmap.org to 45.33.32.156. We can see the NS records pointing to ns1 and ns2 at nmap.org — confirming the authoritative nameservers. The SOA record shows the primary nameserver and the administrative email in the RNAME field."

```bash
[DNS] Querying A record for scanme.nmap.org...
[DNS] A: scanme.nmap.org → 45.33.32.156 (TTL: 3600)

[DNS] Querying AAAA record for scanme.nmap.org...
[DNS] AAAA: scanme.nmap.org → 2600:3c01::f03c:91ff:fe18:bb2f (TTL: 3600)

[DNS] Querying NS records for scanme.nmap.org...
[DNS] NS: nmap.org → ns1.linode.com (TTL: 86400)
[DNS] NS: nmap.org → ns2.linode.com (TTL: 86400)

[DNS] Querying MX records for scanme.nmap.org...
[DNS] No MX records found for scanme.nmap.org

[DNS] Querying TXT records for scanme.nmap.org...
[DNS] TXT: nmap.org → "v=spf1 include:_spf.google.com ~all" (TTL: 300)

[DNS] Querying SOA record for scanme.nmap.org...
[DNS] SOA: nmap.org → ns1.linode.com admin.nmap.org (Serial: 2024010101)
```

**[Screen: Results table populated with records — Type, Name, Value, TTL columns]**

> "The results table organizes everything clearly. Notice the TTL values — the A record has a 3600-second TTL, meaning it's cached for one hour. The NS records have a much higher TTL of 86400 seconds — that's 24 hours. No MX records found for scanme specifically, but the TXT record for the parent domain reveals they use Google Workspace for email via the SPF record."

**[Screen: Highlighting the tree view toggle — switching from table to hierarchical tree view]**

> "Switch to the tree view for a visual hierarchy. You can see the domain at the root with record types branching off beneath it. This is especially useful when you're enumerating multiple subdomains and need to see the relationship between them."

---

## SECTION 5: Zone Transfer Attempt (10:30 – 12:30)

**[Screen: Changing enumeration method to "Zone Transfer" — AXFR option selected]**

> "Now let's try a zone transfer. Change the enumeration method to Zone Transfer. This sends an AXFR request to each nameserver listed in the NS records for the domain. On most properly configured servers, this will be denied — but you always check because the payoff is enormous when it works."

```bash
[DNS] Attempting AXFR zone transfer against ns1.linode.com for nmap.org...
[DNS] Zone transfer DENIED — server refused the request
[DNS] Attempting AXFR zone transfer against ns2.linode.com for nmap.org...
[DNS] Zone transfer DENIED — server refused the request
[DNS] Zone transfer failed for all nameservers (2 attempted, 0 successful)
```

**[Screen: Terminal showing "Zone transfer DENIED" message]**

> "As expected, the Nmap project has their nameservers properly configured — zone transfers are restricted to authorized secondary servers only. This is the secure configuration. In a real engagement, you'd document this as a negative finding — confirming the target has proper DNS security controls."

**[Screen: Switching to THM "DNS in Detail" room — showing a successful zone transfer scenario]**

> "To see what a successful zone transfer looks like, let's switch to the TryHackMe DNS in Detail room where the lab server is intentionally misconfigured. When we run the same AXFR query against this target, watch what happens."

```bash
[DNS] Attempting AXFR zone transfer against ns1.target.thm for target.thm...
[DNS] Zone transfer SUCCESSFUL — 47 records received

[DNS] AXFR Results:
  admin.target.thm      A     10.10.10.5
  mail.target.thm       A     10.10.10.10
  vpn.target.thm        A     10.10.10.15
  dev.target.thm        A     10.10.10.20
  staging.target.thm    A     10.10.10.25
  internal.target.thm   A     192.168.1.100
  db01.target.thm       A     192.168.1.50
  dc01.target.thm       A     192.168.1.10
  ...
[DNS] Total records dumped: 47 (including 12 internal hosts)
```

**[Screen: Results table now showing dozens of records including internal IP addresses]**

> "There it is — a full zone dump. We've pulled 47 records including internal hosts on private IP ranges. Notice entries like dc01 — that's likely a domain controller. db01 suggests a database server. The internal.target.thm entry points to a 192.168.1.x address — that's RFC1918 space, meaning it's internal infrastructure that should never be exposed via public DNS. This single misconfiguration just gave us a complete network map."

---

## SECTION 6: Subdomain Brute-Force Discovery (12:30 – 15:00)

**[Screen: Changing enumeration method to "Brute-Force" — wordlist dropdown visible]**

> "The third technique is subdomain brute-force. This sends DNS queries for common subdomain names prepended to the target domain — things like mail, ftp, dev, staging, api, admin. Select Brute-Force as the method."

**[Screen: Wordlist dropdown showing options — "small (100 entries)", "medium (1000 entries)", "large (10000 entries)", "custom..."]**

> "Choose a wordlist. The small list has about 100 common subdomain names and runs quickly — good for a first pass. The medium list covers a thousand names for broader coverage. The large list is thorough but takes longer. For this demo, we'll use the medium list against our THM target."

```bash
[DNS] Starting subdomain brute-force against target.thm
[DNS] Wordlist: medium (1000 entries)
[DNS] Threads: 10
[DNS] Progress: 0/1000

[DNS] FOUND: www.target.thm → 10.10.10.2
[DNS] FOUND: mail.target.thm → 10.10.10.10
[DNS] FOUND: ftp.target.thm → 10.10.10.30
[DNS] FOUND: admin.target.thm → 10.10.10.5
[DNS] FOUND: dev.target.thm → 10.10.10.20
[DNS] FOUND: api.target.thm → 10.10.10.35
[DNS] NOT FOUND: test.target.thm (NXDOMAIN)
[DNS] NOT FOUND: portal.target.thm (NXDOMAIN)
[DNS] FOUND: vpn.target.thm → 10.10.10.15
...
[DNS] Brute-force complete: 1000 queries sent, 14 subdomains discovered
```

**[Screen: Progress bar advancing — showing discovered count incrementing]**

> "Watch the progress bar advance and the discovered count increment as valid subdomains are found. The tool sends parallel queries — you can see the thread count is set to 10 by default. Each valid response gets added to the results table immediately."

**[Screen: Results table showing discovered subdomains with IP addresses]**

> "After the brute-force completes, we've discovered 14 valid subdomains. Some of these overlap with what the zone transfer revealed, but brute-force works even when zone transfers are denied. It's noisier — generating many DNS queries — but it's effective and doesn't require any server misconfiguration to succeed."

---

## SECTION 7: Results Interpretation and Export (15:00 – 16:30)

**[Screen: Results panel — switching between Table View, Tree View, and Graph View]**

> "Let's review our results. The table view gives you sortable columns — Name, Type, Value, TTL, and timestamp. You can sort by record type to group all A records together, or by value to identify clusters of hosts on the same subnet. The tree view shows the domain hierarchy visually. The graph view maps relationships between records."

**[Screen: Highlighting the Export button — dropdown showing JSON, CSV options]**

> "To export results, click the Export button in the top-right corner of the results pane. You can export as JSON for programmatic processing or CSV for spreadsheet analysis. These results feed directly into other Huginn modules — discovered hosts automatically appear as potential targets for port scanning in the next step of your reconnaissance."

**[Screen: Showing exported JSON file briefly]**

> "The exported data includes full metadata — timestamps, TTL values, the nameserver that responded, and which method discovered each record. This audit trail is valuable for your final engagement report."

---

## SECTION 8: Certification Mapping and Practice (16:30 – 17:30)

**[Screen: Slide showing certification mapping — OSCP: Information Gathering domain, CEH: Enumeration phase]**

> "DNS enumeration maps directly to the OSCP Information Gathering domain and the CEH Enumeration phase. On the OSCP exam, you'll need to enumerate DNS records to discover additional hosts in scope. Zone transfer checks are a standard first step. For CEH, DNS enumeration falls under Module 4 — Enumeration — covering DNS zone transfer and DNS interrogation techniques."

**[Screen: Slide listing practice resources — THM "DNS in Detail", HTB machines with DNS exposure]**

> "For additional practice, the TryHackMe 'DNS in Detail' room walks through each concept step by step. On Hack The Box, machines like 'Cronos' and 'Bank' feature DNS enumeration as part of their intended attack path. Practice zone transfers, subdomain discovery, and correlating DNS records with other enumeration data."

---

## OUTRO (17:30 – end)

**[Screen: Summary slide — DNS Enumeration: Standard Queries, Zone Transfers, Brute-Force | Next: Video 6 — Port Scanning]**

> "That's DNS enumeration in Huginn. We covered standard record queries across multiple types, zone transfer attempts to check for AXFR misconfigurations, and subdomain brute-force discovery. In the next video, we'll move to port scanning — identifying which services are actually listening on the hosts we've discovered. See you there."
