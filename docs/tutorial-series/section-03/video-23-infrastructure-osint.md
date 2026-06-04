# VIDEO 23: Infrastructure OSINT
### IP History, Hosting Providers & Infrastructure Mapping
**Suggested length:** 14–18 minutes
**License Tier:** Free
**Certification Relevance:** OSCP: Information Gathering | CEH: Footprinting & Reconnaissance

---

## INTRO (0:00 – 1:30)

**[Screen: Huginn splash screen with Section 3 title card "OSINT and Intelligence Gathering"]**

> "Welcome back to the Huginn tutorial series. This is the final video in Section 3 — Infrastructure OSINT. We're going to map out the technical infrastructure behind a target organization using entirely passive techniques. That means identifying hosting providers, cloud platforms, IP ranges, technology stacks, CDN configurations, and DNS infrastructure — all without sending a single probe to the target. Huginn's Cloud Enumeration engine handles the discovery and correlation."

**[Screen: Slide showing infrastructure layers — "DNS → IP Ranges → ASN → Hosting Provider → Cloud Services → CDN → Technology Stack"]**

> "Infrastructure OSINT builds a map of what a target has deployed and where. In previous videos we found people and assessed threat intelligence. Now we're asking: what does their infrastructure actually look like? What cloud providers host it? What services are exposed? Are there misconfigured storage buckets or forgotten development servers? We'll demonstrate against our own AWS infrastructure — EC2 instances, S3 buckets, and Route53 DNS (see Video 17: Subdomain Discovery for domain-level reconnaissance)."

---

## SECTION 1: Infrastructure OSINT Methodology (1:30 – 3:30)

**[Screen: Slide titled "Infrastructure Mapping Workflow" — flowchart showing: Domain → DNS Records → IP Resolution → ASN/WHOIS → Cloud Provider ID → Service Enumeration → Technology Fingerprint]**

> "Infrastructure OSINT follows a layered approach. Start with a domain name and resolve its DNS records — these give you IP addresses. IP addresses reveal their ASN and WHOIS data, identifying the hosting provider or cloud platform. Once you know it's AWS, Azure, or GCP, you can check for cloud-specific resources — S3 buckets, Azure Blobs, metadata endpoints. Finally, technology fingerprinting identifies the software stack without actively probing."

**[Screen: Diagram showing passive data sources — "WHOIS databases", "BGP route tables", "DNS records", "Certificate Transparency", "Shodan cached data", "Public cloud registries"]**

> "All of this intelligence comes from passive sources. WHOIS databases and regional internet registries publish IP ownership. BGP route tables show how traffic flows through autonomous systems. DNS records are public by design. Certificate Transparency logs reveal what certificates have been issued. And cached scan data from services like Shodan provides historical port and service information without us scanning anything ourselves."

**[Screen: Slide emphasizing "Zero packets to target — all public data sources"]**

> "This is a key distinction from active scanning. In Video 6 we did port scanning — that sends packets directly to the target (see Video 6: Port Scanning). Infrastructure OSINT queries third-party databases about the target. The target never sees our queries. This makes it safe to perform before you have explicit authorization for active testing, as part of scoping discussions."

---

## SECTION 2: Huginn Cloud Enumeration Interface (3:30 – 5:30)

**[Screen: Huginn application — navigating to OSINT & Intelligence → Infrastructure OSINT tab]**

> "Navigate to OSINT and Intelligence, then select the Infrastructure OSINT tab. The Cloud Enumeration interface presents several scan types: S3 Bucket Discovery, Azure Blob Enumeration, Azure Tenant Information, Metadata API Check, and Full Cloud Enumeration."

**[Screen: Infrastructure OSINT page — highlighting target input, scan type selector, and wordlist configuration]**

> "The target input accepts a domain name, IP address, or organization name depending on the scan type. The scan type selector determines which enumeration modules run. For S3 and Azure Blob discovery, you'll see a wordlist configuration panel — these modules brute-force common bucket and container naming patterns against cloud storage APIs."

**[Screen: Showing the "Full Cloud Enumeration" option selected — all sub-modules listed with descriptions]**

> "Full Cloud Enumeration runs everything — S3 bucket discovery, Azure blob enumeration, Azure tenant lookup, and metadata API checks. It also performs ASN lookup, IP range identification, CDN detection, and technology fingerprinting. This is the most comprehensive option for mapping a target's cloud footprint."

**[Screen: Showing the proxy configuration option and delay slider for responsible scanning]**

> "Notice the proxy configuration option and the delay slider. Even though we're querying public APIs and not the target directly, some cloud enumeration generates requests to cloud provider APIs. The delay slider spaces these requests to stay within API rate limits. The proxy option routes queries through your configured proxy chain if stealth is desired."

---

## SECTION 3: Demo Environment — Own AWS Infrastructure (5:30 – 7:00)

**[Screen: AWS Console overview showing the test infrastructure — EC2 instances, S3 bucket, Route53 zones]**

> "For this demonstration, we've deployed dedicated AWS infrastructure. We have two EC2 instances — a web server and an API server — plus one S3 bucket that we've intentionally left with overly permissive settings to demonstrate what misconfiguration detection looks like. Route53 manages our DNS zones, and we have a CloudFront distribution in front of the web server."

```bash
Demo Infrastructure (Own AWS Account):
  EC2 Instances:
    → web-server-01: t3.micro, us-west-2, nginx + React frontend
    → api-server-01: t3.micro, us-west-2, Python Flask API
  S3 Bucket:
    → meridian-demo-assets (intentionally misconfigured — public listing enabled)
  Route53:
    → meridian-tech-demo.own-infra.local (primary zone)
    → Subdomains: www, api, mail, cdn
  CloudFront:
    → Distribution for www subdomain
  IP Range: 203.0.113.0/28 (documentation range for demo purposes)
```

**[Screen: Diagram showing the infrastructure layout — users → CloudFront → EC2 web server, API server, S3 bucket]**

> "This is a typical small-company cloud deployment. A CDN sits in front of the web tier, DNS routes traffic, and there's a storage bucket for static assets. The intentional misconfiguration on the S3 bucket simulates a common real-world finding — a developer enabling public access during development and forgetting to lock it down."

---

## SECTION 4: ASN and IP Range Discovery (7:00 – 9:00)

**[Screen: Selecting "Full Cloud Enumeration" — entering the demo domain — clicking "Start"]**

> "Let's run the full enumeration. Enter our demo domain and click Start. The first phase identifies the IP addresses associated with the domain and maps them to their Autonomous System."

```bash
[CLOUD] Full Cloud Enumeration starting for: meridian-tech-demo.own-infra.local
[CLOUD] Phase 1: DNS and IP Resolution...

[CLOUD] DNS Resolution:
  → meridian-tech-demo.own-infra.local → 203.0.113.42 (A record)
  → www.meridian-tech-demo.own-infra.local → d1234abcdef.cloudfront.net (CNAME → CloudFront)
  → api.meridian-tech-demo.own-infra.local → 203.0.113.43 (A record)
  → mail.meridian-tech-demo.own-infra.local → 203.0.113.42 (A record)

[CLOUD] Phase 2: ASN and WHOIS Lookup...

[CLOUD] IP: 203.0.113.42
  → ASN: AS16509 (Amazon.com, Inc.)
  → Organization: Amazon Web Services
  → Network: 203.0.113.0/24
  → Country: US
  → Registry: ARIN
  → Allocated: 2018-03-15

[CLOUD] IP: 203.0.113.43
  → ASN: AS16509 (Amazon.com, Inc.)
  → Same network block as primary

[CLOUD] CloudFront Distribution detected:
  → d1234abcdef.cloudfront.net
  → Edge locations: Global CDN
  → Origin: 203.0.113.42 (mapped back to primary)

[CLOUD] Infrastructure Summary:
  → Cloud Provider: AWS (confirmed via ASN + CloudFront)
  → Region: us-west-2 (inferred from IP allocation)
  → IP Range: 203.0.113.0/24 (organization allocation)
  → CDN: CloudFront (www subdomain)
  → 2 unique server IPs identified
```

**[Screen: Results showing ASN map visualization — the organization's IP space highlighted within the AWS network block]**

> "Phase one and two complete. We've confirmed this is AWS infrastructure — the ASN belongs to Amazon, and the CloudFront CNAME is a definitive AWS indicator. We've identified two server IPs and mapped the CDN configuration. The WHOIS data tells us the network block and when it was allocated. All from DNS queries and public registry data."

**[Screen: Expanding the WHOIS details panel — showing registration data and netblock information]**

> "The WHOIS details reveal the specific netblock assignment. For AWS, this isn't as useful as it would be for a company with their own IP allocation — but it confirms the hosting provider conclusively. For organizations that own their IP space, WHOIS reveals contact information, netblock size, and sometimes technical POCs."

---

## SECTION 5: S3 Bucket Discovery (9:00 – 11:30)

**[Screen: Phase 3 starting — S3 Bucket Discovery progress showing wordlist-based enumeration]**

> "Phase three checks for S3 buckets associated with the target. Huginn generates candidate bucket names based on the organization name, domain, and common naming patterns, then passively checks if those buckets exist and what permissions they have."

```bash
[CLOUD] Phase 3: S3 Bucket Discovery...
[CLOUD] Generating bucket name candidates from: meridian-tech-demo
[CLOUD] Wordlist: 50 common patterns (e.g., {name}-assets, {name}-backup,
        {name}-dev, {name}-prod, {name}-staging, {name}-uploads, {name}-data)

[CLOUD] Checking bucket: meridian-tech-demo-assets...
[S3] FOUND: meridian-demo-assets
  → Status: EXISTS
  → Public Listing: ENABLED (misconfiguration!)
  → Region: us-west-2
  → Objects visible: 143 files
  → Total size: ~2.3 GB
  → Notable contents:
    → /images/ (47 files — product images)
    → /documents/ (12 files — PDF documents)
    → /backups/ (3 files — database exports!)
    → /config/ (2 files — configuration files!)

[CLOUD] Checking bucket: meridian-tech-demo-backup...
[S3] NOT FOUND (NoSuchBucket)

[CLOUD] Checking bucket: meridian-tech-demo-dev...
[S3] NOT FOUND (NoSuchBucket)

[CLOUD] Checking bucket: meridian-demo-staging...
[S3] FOUND: meridian-demo-staging
  → Status: EXISTS
  → Public Listing: DISABLED (Access Denied — properly configured)
  → Note: Bucket exists but permissions are correctly restricted

[CLOUD] S3 Discovery complete: 2 buckets found, 1 with public listing enabled
[CLOUD] ALERT: meridian-demo-assets has public listing — potential data exposure
```

**[Screen: Results showing the S3 findings — the misconfigured bucket highlighted in red with file listing]**

> "Huginn found two S3 buckets. The first — meridian-demo-assets — has public listing enabled. This is our intentional misconfiguration. We can see 143 files including a 'backups' directory with database exports and a 'config' directory with configuration files. In a real engagement, this could expose credentials, customer data, or application secrets. The second bucket exists but has proper access controls — we know it's there but can't list its contents."

**[Screen: Expanding the public bucket listing — showing the directory structure and file names visible]**

> "The bucket listing shows exactly what's exposed. Notice the /backups directory containing what appear to be database exports — those could contain user credentials or sensitive business data. The /config directory might have API keys or database connection strings. This is one of the most common cloud misconfigurations we find in real engagements, and we detected it entirely passively."

**[Screen: Showing the risk assessment for the S3 finding — severity rating and recommended remediation]**

> "Huginn rates this as a High severity finding with clear remediation guidance — disable public access, enable bucket-level access logging, and review the exposed files for sensitive data. This finding alone could be the most critical issue in a reconnaissance report."

---

## SECTION 6: Technology Stack Fingerprinting (11:30 – 13:30)

**[Screen: Phase 4 — Technology fingerprinting from passive sources]**

> "The final phase performs technology stack fingerprinting using data already collected. This correlates DNS records, certificate information, HTTP headers from cached sources, and known cloud service patterns to identify what software runs on the infrastructure."

```bash
[CLOUD] Phase 4: Technology Fingerprinting (passive)...

[CLOUD] Certificate Analysis:
  → Issuer: Let's Encrypt (ACME automated)
  → Subject Alternative Names: 
    meridian-tech-demo.own-infra.local, 
    www.meridian-tech-demo.own-infra.local,
    api.meridian-tech-demo.own-infra.local
  → Key Type: RSA 2048-bit
  → Validity: 90 days (standard Let's Encrypt)

[CLOUD] CDN Analysis:
  → CloudFront distribution detected
  → Edge caching enabled
  → Origin: 203.0.113.42:443

[CLOUD] Cached Service Data (from passive sources):
  → Web server: nginx/1.24.0 (from Shodan cache)
  → Framework indicators: React (from JavaScript bundle paths in cached pages)
  → API: Python/Flask (from cached response headers)
  → SSL/TLS: TLSv1.2 and TLSv1.3 supported

[CLOUD] DNS-based Indicators:
  → MX: No mail server (using external email)
  → SPF record: includes google.com (Google Workspace)
  → No DMARC record (potential email spoofing risk)

[CLOUD] Infrastructure Profile:
  ┌─────────────────────────────────────┐
  │ Cloud: AWS (us-west-2)              │
  │ CDN: CloudFront                     │
  │ Web: nginx 1.24.0 + React          │
  │ API: Python Flask                   │
  │ TLS: Let's Encrypt (automated)     │
  │ Email: Google Workspace             │
  │ Storage: S3 (1 misconfigured)       │
  │ DNS: Route53                        │
  └─────────────────────────────────────┘

[CLOUD] Full Cloud Enumeration complete
[CLOUD] Total findings: 4 infrastructure components mapped, 1 misconfiguration detected
```

**[Screen: Results dashboard showing the complete infrastructure profile — visual diagram of all discovered components]**

> "The complete infrastructure profile shows everything we've discovered passively. AWS hosting in us-west-2, CloudFront CDN, nginx web server running a React frontend, Python Flask API backend, Let's Encrypt certificates, Google Workspace for email, and the misconfigured S3 bucket. All of this from DNS queries, certificate transparency, cached scan data, and cloud API checks."

**[Screen: Showing the CDN Origin Exposure check — testing if the origin server can be accessed directly bypassing CloudFront]**

> "Huginn also checks for CDN origin exposure. When a site uses CloudFront, the origin server might still accept direct connections — bypassing any WAF rules or rate limiting applied at the CDN layer. Our check identifies whether the origin IP responds to HTTP requests directly, which would be a security concern in production."

**[Screen: Showing the CSP Bypass plugin results — checking Content Security Policy for CDN-hosted resource bypass opportunities]**

> "The CSP Bypass plugin examines Content Security Policy headers cached from passive sources. If a CSP allows loading resources from broad CDN domains, there might be bypass opportunities. This is advanced analysis that feeds directly into web exploitation planning covered in Section 5."

---

## SECTION 7: Certification Mapping and Practice (13:30 – 15:30)

**[Screen: Slide showing certification mapping — OSCP: Information Gathering, CEH: Footprinting & Reconnaissance (Module 2)]**

> "Infrastructure OSINT maps to the OSCP Information Gathering domain — specifically identifying target infrastructure, hosting providers, and exposed services without active scanning. For CEH, this covers Module 2: Footprinting and Reconnaissance, including network footprinting, DNS footprinting, and cloud infrastructure enumeration."

**[Screen: Bullet list of exam-relevant skills — "ASN identification", "Cloud provider fingerprinting", "S3 bucket enumeration", "Infrastructure mapping from DNS"]**

> "For OSCP, the ability to map infrastructure before active scanning helps you prioritize targets efficiently during the limited exam time. Knowing it's AWS tells you to check for metadata endpoints, S3 buckets, and Lambda functions. For CEH, cloud infrastructure enumeration is explicitly tested — including identifying cloud providers from IP ranges and checking for storage misconfigurations."

**[Screen: Practice suggestions with specific resources]**

> "For practice, deploy your own cloud infrastructure and run these enumeration techniques against it. AWS free tier gives you enough resources. Check your own S3 bucket permissions — you might be surprised what's publicly accessible. TryHackMe has cloud-focused rooms that test these skills. The key takeaway is that passive infrastructure mapping gives you a complete picture before you ever send an active probe."

**[Screen: Slide showing "Section 3 Complete — 7 OSINT videos covering the full intelligence gathering workflow"]**

> "This also wraps up Section 3 — OSINT and Intelligence Gathering. Over seven videos we covered subdomain discovery, certificate transparency, breach intelligence, people OSINT, social media intelligence, threat intelligence with API integration, and now infrastructure mapping. Together these give you a complete passive reconnaissance toolkit."

---

## OUTRO (15:30 – end)

**[Screen: Summary slide — "Infrastructure OSINT: ASN/IP Mapping, S3 Bucket Discovery, Technology Fingerprinting, CDN Analysis | Next: Section 4 — Vulnerability Scanning (Video 24)"]**

> "That's Infrastructure OSINT in Huginn. We mapped cloud infrastructure through ASN and WHOIS lookups, discovered misconfigured S3 buckets through passive name enumeration, fingerprinted the technology stack from cached data and certificates, and built a complete infrastructure profile without sending a single packet to the target. In the next section, we move from passive reconnaissance into active vulnerability scanning — Video 24 covers the Huginn Scanner overview and scan profiles. The reconnaissance we've gathered in Sections 2 and 3 directly informs how we configure those scans. See you in Section 4."
