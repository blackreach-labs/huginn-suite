# VIDEO 18: Certificate Transparency
### CT Log Monitoring, Domain Mapping & Expired Cert Detection
**Suggested length:** 13–17 minutes
**License Tier:** Free
**Certification Relevance:** OSCP: Information Gathering | CEH: Footprinting & Reconnaissance

---

## INTRO (0:00 – 1:30)

**[Screen: Huginn splash screen with Section 3 title card "OSINT and Intelligence Gathering"]**

> "In the previous video we used Certificate Transparency logs as one of several passive sources for subdomain discovery. In this video we go much deeper into Certificate Transparency itself — understanding how CT logs work, what intelligence you can extract from certificate metadata beyond just subdomain names, and how to monitor for new certificate issuances in real time. This is one of the most powerful passive reconnaissance techniques available because CT logs are public by design — every certificate authority is required to publish certificates to these logs before browsers will trust them."

**[Screen: Slide showing CT log ecosystem — Certificate Authorities submitting to CT Logs, browsers verifying SCTs, researchers querying logs]**

> "Certificate Transparency was created to detect misissued certificates — rogue CAs issuing certificates for domains they shouldn't. But from a penetration testing perspective, it gives us a free, constantly updated database of every SSL/TLS certificate ever issued for any domain. If a target issues a certificate for internal-dashboard.target.com, we'll see it in the CT logs within hours — even if that subdomain is never exposed to the public internet. This builds directly on Video 17's subdomain discovery techniques (see Video 17: Subdomain Discovery)."

---

## SECTION 1: How Certificate Transparency Works (1:30 – 3:30)

**[Screen: Animated diagram showing the CT log submission flow — CA issues cert → submits to CT logs → receives SCT → embeds SCT in certificate → browser verifies SCT]**

> "Here's how the system works. When a Certificate Authority issues a new certificate, it must submit that certificate to one or more CT logs — these are append-only public databases maintained by organizations like Google, Cloudflare, and DigiCert. The CT log returns a Signed Certificate Timestamp, or SCT, which the CA embeds in the certificate. When a browser connects to a site, it checks for a valid SCT — if one is missing, some browsers will warn the user or refuse the connection."

**[Screen: Table showing major CT log operators — Google (Argon, Xenon, Icarus), Cloudflare (Nimbus), DigiCert, Let's Encrypt (Oak)]**

> "There are dozens of CT logs operated by different organizations. Google operates several — Argon, Xenon, Icarus. Cloudflare runs Nimbus. DigiCert and Let's Encrypt operate their own logs. The important thing for us is that aggregator services like crt.sh and CertSpotter index across all these logs, giving us a single query point."

**[Screen: Slide showing what certificate metadata contains — Subject CN, Subject Alternative Names (SANs), Issuer, Validity Dates, Serial Number, Signature Algorithm]**

> "Each certificate in the log contains rich metadata. The Subject Common Name and Subject Alternative Names list every domain the certificate covers — this is how we find subdomains. The issuer tells us which CA the organization uses. Validity dates show when certificates were issued and when they expire. The signature algorithm reveals their cryptographic choices. All of this is intelligence we can collect without touching the target."

---

## SECTION 2: Huginn CT Interface (3:30 – 5:30)

**[Screen: Huginn application — navigating to OSINT & Intelligence → Certificate Transparency tab]**

> "Navigate to the OSINT module and click the Certificate Transparency tab. This interface is dedicated to certificate analysis — it goes beyond the basic subdomain extraction from Video 17 and provides full certificate metadata inspection, timeline visualization, and expiry monitoring."

**[Screen: Certificate Transparency interface — target domain input, search controls, results panel with tabs: Certificates, Subdomains, Timeline, Expired]**

> "The interface has the target domain input at the top with a search button. Below that, the results area has four tabs. The Certificates tab shows every certificate found with full metadata. The Subdomains tab extracts and deduplicates all domain names across all certificates — similar to what we saw in the subdomain discovery module. The Timeline tab visualizes certificate issuance history. And the Expired tab highlights certificates past their validity date."

**[Screen: Close-up on search options — "Include expired certificates" toggle, "Include pre-certificates" toggle, date range filter]**

> "The search options let you control what gets returned. 'Include expired certificates' is important — expired certs reveal historical infrastructure that may still be running with an invalid certificate. 'Include pre-certificates' shows certificates submitted to CT logs before final issuance — these are technically different from the final leaf certificate but contain the same domain information. The date range filter lets you focus on recent activity or look back historically."

---

## SECTION 3: Searching Certificate Logs (5:30 – 8:00)

**[Screen: Entering own domain in the target field — the same domain used in Video 17]**

> "Let's search for certificates issued for our demo domain — the same one we used in Video 17. I've issued multiple Let's Encrypt certificates for various subdomains specifically for this demonstration."

```bash
Target: yourdomain.com
Options: Include expired ✓, Include pre-certificates ✓
Date range: All time
```

**[Screen: Clicking "Search" — progress indicator showing crt.sh and CertSpotter being queried]**

> "Click Search. The engine queries crt.sh first — it's the most comprehensive free CT log aggregator — then CertSpotter as a secondary source. Both APIs are free and don't require authentication for basic queries."

```bash
[CT Search] Searching crt.sh for *.yourdomain.com...
[CT Search] Processing response: 23 certificates found

[CT Search] Certificate 1:
  Common Name: yourdomain.com
  SANs: yourdomain.com, www.yourdomain.com
  Issuer: Let's Encrypt Authority X3
  Valid: 2024-01-15 to 2024-04-14
  Status: ACTIVE

[CT Search] Certificate 2:
  Common Name: mail.yourdomain.com
  SANs: mail.yourdomain.com
  Issuer: Let's Encrypt Authority X3
  Valid: 2024-02-01 to 2024-05-01
  Status: ACTIVE

[CT Search] Certificate 3:
  Common Name: dev.yourdomain.com
  SANs: dev.yourdomain.com, staging.yourdomain.com
  Issuer: Let's Encrypt Authority X3
  Valid: 2024-01-20 to 2024-04-19
  Status: ACTIVE

[CT Search] Certificate 4:
  Common Name: api.yourdomain.com
  SANs: api.yourdomain.com, api-v2.yourdomain.com
  Issuer: Let's Encrypt Authority X3
  Valid: 2023-10-05 to 2024-01-03
  Status: EXPIRED

[CT Search] Searching CertSpotter...
[CT Search] CertSpotter: 18 certificates found (15 duplicates, 3 new)

[CT Search] Complete: 26 unique certificates, 14 unique subdomains extracted
```

**[Screen: Results populating in the Certificates tab — table with columns: CN, SANs, Issuer, Not Before, Not After, Status]**

> "Twenty-six unique certificates found across both sources. Notice Certificate 3 — it covers both dev.yourdomain.com and staging.yourdomain.com in its Subject Alternative Names. This is common with Let's Encrypt where organizations bundle related subdomains into a single certificate. Also notice Certificate 4 — it's expired, covering api.yourdomain.com and api-v2.yourdomain.com. That api-v2 subdomain didn't appear in our Video 17 scan because the certificate is expired and the current infrastructure might use a newer cert."

---

## SECTION 4: Extracting Intelligence from Metadata (8:00 – 10:30)

**[Screen: Subdomains tab — showing all extracted subdomains with their certificate count and first/last seen dates]**

> "Switch to the Subdomains tab. This view deduplicates all domain names found across all certificates and shows how many certificates reference each one, plus the first and last time that subdomain appeared in a certificate. A subdomain appearing in many certificates over a long period is stable infrastructure. One that appears once in an old expired cert might be decommissioned."

**[Screen: Highlighting a subdomain (api-v2.yourdomain.com) that only appears in an expired certificate]**

> "Here's api-v2.yourdomain.com — it only appears in one expired certificate from October 2023. This tells us the organization was developing or running an API v2 at that time. If we check whether that subdomain still resolves, we might find a forgotten endpoint. If it doesn't resolve but the DNS name is unclaimed, that's a potential subdomain takeover vector."

**[Screen: Certificate detail panel — clicking on a certificate to view full X.509 information]**

> "Click any certificate to expand its full details. You'll see the complete X.509 metadata including the signature algorithm — SHA256 with RSA in this case — the key size, the certificate serial number, and the full issuer chain. For security assessment, check the key size and algorithm. RSA 2048 is the minimum acceptable today. If you find certificates using SHA-1 signatures or RSA 1024, that's a finding worth noting in your report."

**[Screen: Showing issuer distribution — pie chart of CAs used across all certificates]**

> "The issuer distribution shows which Certificate Authorities the target uses. Our demo domain uses Let's Encrypt exclusively, which is common for automated certificate management. In a real engagement, if you see a mix of CAs — Let's Encrypt for some, DigiCert for others, maybe an internal CA for some — that reveals their certificate management practices and potential weak points. Internal CAs are especially interesting because they might have weaker validation policies."

---

## SECTION 5: Timeline Analysis and Monitoring (10:30 – 12:30)

**[Screen: Timeline tab — horizontal timeline visualization showing certificate issuance events plotted chronologically]**

> "The Timeline tab visualizes certificate activity over time. Each bar represents a certificate's validity period, positioned on the timeline by its issuance date and extending to its expiry. Clusters of certificate issuances often correlate with infrastructure changes — a burst of new certificates might indicate a migration, new service deployment, or certificate rotation event."

**[Screen: Timeline showing a gap where a certificate expired and wasn't renewed for 2 weeks — highlighted with a warning indicator]**

> "Look for gaps — periods where a certificate expired before its replacement was issued. In our demo data, api.yourdomain.com had a certificate expire on January 3rd and the replacement wasn't issued until January 15th. That 12-day gap could mean the service was down, running without TLS, or using an untrusted self-signed certificate. In a real engagement, these gaps are worth investigating."

**[Screen: Expired tab — showing certificates past their validity date with days-expired count]**

> "The Expired tab lists all certificates past their Not After date. This is reconnaissance gold for subdomain takeover assessments. If an expired certificate referenced a subdomain that now has a dangling CNAME record — pointing to a service the organization no longer controls — an attacker could potentially claim that service and receive traffic intended for the target's subdomain."

**[Screen: Monitoring setup panel — showing how to configure alerts for new certificate issuances]**

> "Huginn also supports continuous CT monitoring. In the settings panel, you can configure alerts that notify you whenever a new certificate is issued for a domain you're tracking. This is useful during long-term engagements — if the target deploys new infrastructure mid-assessment, you'll know about it within hours of the certificate being logged."

---

## SECTION 6: Practical Workflow (12:30 – 14:30)

**[Screen: Workflow diagram — CT Search → Extract Subdomains → Resolve DNS → Check for Expired/Dangling → Feed to Scanner]**

> "Let's tie this into a practical reconnaissance workflow. Start with a CT search to find all certificates. Extract subdomains and resolve them — some will be live, some dead. For live ones, feed them directly into port scanning. For dead ones — especially those from expired certificates — check whether the DNS records still exist. A CNAME record pointing to an unregistered cloud service is a takeover opportunity."

**[Screen: Demonstrating the workflow — selecting 3 live subdomains and clicking "Scan with Port Scanner"]**

> "From the Subdomains tab, select the hosts you want to investigate further and click 'Scan with Port Scanner.' This queues them as targets in the Port Scanning module. You're building an attack surface map without ever having sent reconnaissance traffic to the target directly — everything so far has been queries to public CT log aggregators."

```bash
[Workflow] Selected subdomains for port scanning:
  → api.yourdomain.com (203.0.113.30)
  → dev.yourdomain.com (203.0.113.20)
  → admin.yourdomain.com (203.0.113.5)
[Workflow] 3 targets queued in Port Scanner module
```

**[Screen: Showing how CT findings integrate with Asset Inventory — certificate data enriching asset records]**

> "Certificate data also enriches your Asset Inventory. Each asset card now shows its TLS certificate information — the issuer, expiry date, and any related certificates. This gives you a complete picture when you later arrive at the vulnerability assessment phase."

---

## SECTION 7: Certification Mapping and Practice (14:30 – 15:30)

**[Screen: Slide showing certification relevance — OSCP: Information Gathering, CEH: Footprinting & Reconnaissance]**

> "Certificate Transparency reconnaissance maps to the OSCP Information Gathering domain. While the OSCP exam doesn't explicitly test CT knowledge, the subdomain discovery it enables is directly applicable to finding in-scope hosts. For CEH, CT log analysis falls under Module 2 — Footprinting and Reconnaissance — specifically the DNS footprinting and competitive intelligence sections."

**[Screen: Practice resources — crt.sh manual searches, own domain with Let's Encrypt, THM "OSINT" rooms]**

> "For practice, issue Let's Encrypt certificates for your own subdomains and verify they appear in crt.sh within 24 hours. Try searching for certificates of large organizations on crt.sh directly — you'll be surprised how many internal-sounding subdomains are visible. The TryHackMe OSINT rooms also cover certificate transparency as part of their passive reconnaissance modules."

---

## OUTRO (15:30 – end)

**[Screen: Summary slide — Certificate Transparency: CT Log Searching, Metadata Extraction, Timeline Analysis, Expiry Monitoring | Next: Video 19 — Breach Intelligence]**

> "That's Certificate Transparency in Huginn. We searched public CT logs to discover 26 certificates and 14 unique subdomains, analyzed certificate metadata to understand the target's infrastructure and CA relationships, used timeline analysis to identify gaps and changes, and highlighted expired certificates as potential takeover vectors. In the next video, we'll explore Breach Intelligence — querying breach databases to assess credential exposure. That's an Enterprise tier feature, so I'll walk through the API setup and licensing requirements. See you there."
