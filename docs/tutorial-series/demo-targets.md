# Demo Target Registry

## Overview

This document assigns specific demo targets to every video in the Huginn YouTube Tutorial Series (Videos 5–61). All targets are drawn exclusively from the approved target list and include configuration details sufficient for reproducibility.

## Approved Target List

| Target | Type | Authorization | Use Cases |
|--------|------|---------------|-----------|
| scanme.nmap.org | Public (authorized) | Nmap project authorized scanning target | Port scanning, HTTP fingerprinting, basic enumeration |
| HTB machines | Lab platform | Requires active HTB subscription | SMB, RPC, exploitation, post-exploitation, AD |
| THM rooms | Lab platform | Requires active THM subscription | Web exploits, network exploits, privilege escalation |
| DVWA | Self-hosted vulnerable app | Locally deployed, fully owned | Web application attacks (SQLi, XSS, SSTI, etc.) |
| Own cloud infrastructure | Self-owned | Personally owned AWS/cloud account | AWS deployment, infrastructure OSINT, stealth testing |

> **Important:** No video in this series demonstrates tools against unauthorized or non-consenting targets. All lab platforms require active subscriptions and are used within their terms of service.

---

## Section 2 — Recon and Enumeration Tools (Videos 5–16)

### Video 5: DNS Enumeration

| Field | Value |
|-------|-------|
| **Platform** | scanme.nmap.org + THM |
| **Target** | scanme.nmap.org (basic DNS), THM room "DNS in Detail" |
| **Configuration** | Default THM room configuration |
| **Expected Services** | DNS (port 53), HTTP (port 80) on scanme.nmap.org |
| **Security Level** | N/A (public target + guided lab) |
| **Notes** | Demonstrate zone transfer attempts against scanme.nmap.org; use THM room for successful zone transfer, brute-force, and multiple record type queries (A, AAAA, MX, NS, TXT, SOA, CNAME) |

### Video 6: Port Scanning

| Field | Value |
|-------|-------|
| **Platform** | scanme.nmap.org |
| **Target** | scanme.nmap.org (45.33.32.156) |
| **Configuration** | Default — no special setup required |
| **Expected Services** | SSH (22), HTTP (80), filtered ports for demonstration |
| **Security Level** | N/A (public authorized target) |
| **Notes** | Demonstrate TCP connect, SYN, UDP scan types; service version detection; OS fingerprinting; scan timing options. This target is explicitly authorized for scanning by the Nmap project. |

### Video 7: SMB Enumeration

| Field | Value |
|-------|-------|
| **Platform** | HTB |
| **Target** | HTB "Lame" (10.10.10.3) |
| **Configuration** | Default HTB machine spawn; no modifications needed |
| **Expected Services** | SMB/CIFS (ports 139, 445), FTP (21), SSH (22) |
| **Security Level** | Easy difficulty |
| **Notes** | Demonstrate null session enumeration, share listing, user enumeration, SMB version detection. Lame has Samba 3.0.20 with known misconfigurations ideal for demonstrating SMB enumeration techniques. |

### Video 8: SMTP Enumeration

| Field | Value |
|-------|-------|
| **Platform** | HTB |
| **Target** | HTB "Beep" (10.10.10.7) |
| **Configuration** | Default HTB machine spawn |
| **Expected Services** | SMTP (port 25), HTTP/HTTPS (80/443), SSH (22), POP3 (110), IMAP (143) |
| **Security Level** | Easy difficulty |
| **Notes** | Demonstrate VRFY, EXPN, and RCPT TO user enumeration techniques. Beep runs a full mail stack (Postfix) making it ideal for SMTP enumeration demonstrations. |

### Video 9: SNMP Enumeration

| Field | Value |
|-------|-------|
| **Platform** | HTB |
| **Target** | HTB "Mirai" (10.10.10.48) |
| **Configuration** | Default HTB machine spawn |
| **Expected Services** | SNMP (port 161/UDP), HTTP (80), SSH (22) |
| **Security Level** | Easy difficulty |
| **Notes** | Demonstrate community string guessing, SNMP walk, OID enumeration, system information extraction. Alternative: HTB "Conceal" for SNMPv3 demonstration if needed. |

### Video 10: HTTP/S Fingerprinting

| Field | Value |
|-------|-------|
| **Platform** | scanme.nmap.org |
| **Target** | scanme.nmap.org |
| **Configuration** | Default — no special setup required |
| **Expected Services** | HTTP (port 80), HTTPS (443 if available) |
| **Security Level** | N/A (public authorized target) |
| **Notes** | Demonstrate HTTP header analysis, web server identification (Apache), technology stack detection, SSL/TLS certificate inspection, response fingerprinting. |

### Video 11: API Enumeration

| Field | Value |
|-------|-------|
| **Platform** | THM |
| **Target** | THM room "OWASP API Security Top 10" |
| **Configuration** | Default THM room configuration; deploy the target machine |
| **Expected Services** | HTTP API endpoints (port 80/443), REST API with documented endpoints |
| **Security Level** | Medium difficulty |
| **Notes** | Demonstrate API endpoint discovery, method enumeration (GET/POST/PUT/DELETE), authentication testing, parameter fuzzing, and OpenAPI/Swagger detection. |

### Video 12: RPC Enumeration

| Field | Value |
|-------|-------|
| **Platform** | HTB |
| **Target** | HTB "Active" (10.10.10.100) |
| **Configuration** | Default HTB machine spawn |
| **Expected Services** | MSRPC (port 135), SMB (445), LDAP (389), Kerberos (88), DNS (53) |
| **Security Level** | Medium difficulty |
| **Notes** | Demonstrate RPC endpoint mapping, anonymous RPC enumeration, named pipe listing, and RPC-based user/group enumeration. Active is a Windows AD machine with rich RPC services. |

### Video 13: LDAP Enumeration

| Field | Value |
|-------|-------|
| **Platform** | HTB |
| **Target** | HTB "Cascade" (10.10.10.182) |
| **Configuration** | Default HTB machine spawn |
| **Expected Services** | LDAP (port 389), LDAPS (636), SMB (445), Kerberos (88), DNS (53) |
| **Security Level** | Medium difficulty |
| **Notes** | Demonstrate anonymous LDAP bind, base DN discovery, user/group enumeration, attribute extraction, and LDAP search filter construction. Cascade has rich AD/LDAP data suitable for enumeration. |

### Video 14: IKE/VPN Assessment

| Field | Value |
|-------|-------|
| **Platform** | HTB |
| **Target** | HTB "Conceal" (10.10.10.116) |
| **Configuration** | Default HTB machine spawn |
| **Expected Services** | IKE (port 500/UDP), IPsec NAT-T (4500/UDP), SNMP (161/UDP) |
| **Security Level** | Hard difficulty |
| **Notes** | Demonstrate IKE version detection, transform set enumeration, aggressive mode testing, and VPN endpoint identification. Conceal requires IPsec/IKE interaction making it the ideal target. |

### Video 15: Database Enumeration

| Field | Value |
|-------|-------|
| **Platform** | HTB |
| **Target** | HTB "Archetype" (10.10.10.27) |
| **Configuration** | Default HTB machine spawn (Starting Point machine) |
| **Expected Services** | MSSQL (port 1433), SMB (445), HTTP (varies) |
| **Security Level** | Very Easy (Starting Point) |
| **Notes** | Demonstrate database service detection, version fingerprinting, default credential testing, and database instance enumeration. Archetype exposes MSSQL with accessible credentials via SMB shares. |

### Video 16: AV/Firewall Detection

| Field | Value |
|-------|-------|
| **Platform** | THM |
| **Target** | THM room "Firewalls" |
| **Configuration** | Default THM room deployment |
| **Expected Services** | Various filtered/firewalled ports for detection demonstration |
| **Security Level** | Medium difficulty |
| **Notes** | Demonstrate firewall rule detection via port scan behavior analysis, WAF fingerprinting, IDS/IPS evasion indicator detection, and AV presence enumeration through service responses. |

---

## Section 3 — OSINT and Intelligence Gathering (Videos 17–23)

### Video 17: Subdomain Discovery

| Field | Value |
|-------|-------|
| **Platform** | Own cloud infrastructure |
| **Target** | Own domain with multiple subdomains configured |
| **Configuration** | Pre-configured DNS with 10+ subdomains (e.g., mail., dev., staging., api., admin., vpn., test., docs., cdn., blog.) |
| **Expected Services** | DNS resolution for all configured subdomains |
| **Security Level** | N/A (passive reconnaissance) |
| **Notes** | Demonstrate passive subdomain enumeration via certificate transparency logs, DNS brute-forcing, and search engine dorking against own infrastructure. No interaction with third-party targets. |

### Video 18: Certificate Transparency

| Field | Value |
|-------|-------|
| **Platform** | Own cloud infrastructure |
| **Target** | Own domain with SSL/TLS certificates |
| **Configuration** | Multiple Let's Encrypt certificates issued for various subdomains |
| **Expected Services** | HTTPS on primary domain and subdomains |
| **Security Level** | N/A (passive reconnaissance — CT logs are public) |
| **Notes** | Demonstrate CT log querying, certificate history analysis, subdomain discovery via certificate SANs, and certificate expiry monitoring. All queries target public CT logs about own domains. |

### Video 19: Breach Intelligence

| Field | Value |
|-------|-------|
| **Platform** | Own cloud infrastructure |
| **Target** | Test email addresses on own domain |
| **Configuration** | Pre-created test accounts (e.g., testuser@owndomain.com) with known breach database entries from historical data sets |
| **Expected Services** | N/A (API-based queries to breach databases) |
| **Security Level** | N/A (passive query) |
| **Notes** | Demonstrate breach database lookups, credential exposure analysis, and breach timeline correlation. Only query own email addresses. Requires API key setup (Have I Been Pwned API or similar). Enterprise tier feature. |

### Video 20: People/Employee OSINT

| Field | Value |
|-------|-------|
| **Platform** | Own cloud infrastructure |
| **Target** | Fictional company profile created for demonstration |
| **Configuration** | Pre-created LinkedIn-style profiles, company website with staff directory on own infrastructure |
| **Expected Services** | HTTP (own web server hosting fictional company site) |
| **Security Level** | N/A (passive reconnaissance) |
| **Notes** | Demonstrate employee enumeration, email pattern discovery, organizational chart construction, and role identification using own fictional company data. No real individuals targeted. |

### Video 21: Social Media Intelligence

| Field | Value |
|-------|-------|
| **Platform** | Own cloud infrastructure |
| **Target** | Own social media test accounts created for the demonstration |
| **Configuration** | Dedicated test profiles on major platforms with controlled content |
| **Expected Services** | N/A (API and web-based queries) |
| **Security Level** | N/A (passive reconnaissance) |
| **Notes** | Demonstrate username correlation across platforms, profile metadata extraction, and activity pattern analysis using own test accounts only. No real individuals targeted. |

### Video 22: Threat Intelligence Integration

| Field | Value |
|-------|-------|
| **Platform** | Own cloud infrastructure |
| **Target** | Own IP addresses and domains |
| **Configuration** | Shodan API key configured, VirusTotal API key configured, own cloud IPs registered |
| **Expected Services** | N/A (API-based threat intelligence queries) |
| **Security Level** | N/A (passive query) |
| **Notes** | Demonstrate Shodan integration for IP/service intelligence, VirusTotal lookups for domain reputation, and threat feed correlation. API key setup shown step-by-step. Enterprise tier feature. Requires Shodan and VirusTotal API keys. |

### Video 23: Infrastructure OSINT

| Field | Value |
|-------|-------|
| **Platform** | Own cloud infrastructure |
| **Target** | Own AWS infrastructure (EC2 instances, S3 buckets, DNS) |
| **Configuration** | Dedicated AWS account with: 2+ EC2 instances, 1 S3 bucket (intentionally misconfigured for demo), Route53 DNS zones, CloudFront distribution |
| **Expected Services** | HTTP (80/443), SSH (22) on EC2 instances; S3 endpoints; CloudFront endpoints |
| **Security Level** | N/A (own infrastructure) |
| **Notes** | Demonstrate cloud infrastructure mapping, IP range identification, ASN lookups, hosting provider detection, and technology stack fingerprinting. All targets are self-owned. |

---

## Section 4 — Vulnerability Scanning (Videos 24–27)

### Video 24: Scanner Overview and Profiles

| Field | Value |
|-------|-------|
| **Platform** | DVWA |
| **Target** | DVWA (localhost or local VM) |
| **Configuration** | DVWA Security Level: Low |
| **Expected Services** | HTTP (port 80), MySQL (3306), Apache/PHP stack |
| **Security Level** | Low |
| **Notes** | Demonstrate all four scan profiles (Light, Normal, Aggressive, Insane) against DVWA showing progressive depth. Start with Light for speed comparison, end with Insane for thoroughness. Clearly show detection risk differences between profiles. |

### Video 25: Scan Configuration and Target Setup

| Field | Value |
|-------|-------|
| **Platform** | THM |
| **Target** | THM room "Vulnversity" |
| **Configuration** | Default THM room deployment |
| **Expected Services** | HTTP (port 3333), SSH (22), various filtered ports |
| **Security Level** | Easy difficulty |
| **Notes** | Demonstrate scan target input methods (single IP, CIDR range, hostname), port range configuration, timing templates, credential-based scanning, and output format selection. |

### Video 26: Results Interpretation and Evidence Review

| Field | Value |
|-------|-------|
| **Platform** | DVWA |
| **Target** | DVWA (localhost or local VM) |
| **Configuration** | DVWA Security Level: Medium |
| **Expected Services** | HTTP (port 80), MySQL (3306), Apache/PHP stack |
| **Security Level** | Medium |
| **Notes** | Demonstrate scan results navigation, vulnerability severity assessment, evidence artifact review (screenshots, responses), false positive identification, and export to findings. Run a Normal profile scan and walk through every results panel. |

### Video 27: AI-Powered Scanning

| Field | Value |
|-------|-------|
| **Platform** | THM |
| **Target** | THM room "Overpass" |
| **Configuration** | Default THM room deployment |
| **Expected Services** | HTTP (port 80), SSH (22) |
| **Security Level** | Easy difficulty |
| **Notes** | Demonstrate Neural Network Analysis and ML Pattern Detection features using Insane profile. Show how AI identifies attack paths, correlates findings, and suggests exploitation routes. Enterprise tier feature. |

---

## Section 5 — Web Application Exploitation (Videos 28–35)

> **Safety Notice:** All videos in this section include explicit lab environment warnings and ethical testing disclaimers. Demonstrations use only self-hosted DVWA or authorized THM lab rooms.

### Video 28: SQL Injection

| Field | Value |
|-------|-------|
| **Platform** | DVWA |
| **Target** | DVWA SQL Injection module |
| **Configuration** | DVWA Security Level: Low (initial demo), then Medium (bypass demo) |
| **Expected Services** | HTTP (port 80), MySQL (3306) |
| **Security Level** | Low → Medium |
| **Notes** | Demonstrate in-band (UNION-based), blind (boolean-based and time-based) SQL injection. Show payload crafting, database enumeration, and data extraction. Start at Low for clear demonstration, escalate to Medium to show filter bypass techniques. |

### Video 29: Cross-Site Scripting (XSS)

| Field | Value |
|-------|-------|
| **Platform** | DVWA |
| **Target** | DVWA XSS (Reflected) and XSS (Stored) modules |
| **Configuration** | DVWA Security Level: Low (initial demo), then Medium (filter bypass) |
| **Expected Services** | HTTP (port 80) |
| **Security Level** | Low → Medium |
| **Notes** | Demonstrate reflected XSS, stored XSS, and DOM-based XSS. Show cookie theft payloads, session hijacking concepts, and filter evasion techniques. Both DVWA XSS modules used to show reflected vs stored variants. |

### Video 30: Server-Side Template Injection (SSTI)

| Field | Value |
|-------|-------|
| **Platform** | THM |
| **Target** | THM room "SSTI" |
| **Configuration** | Default THM room deployment |
| **Expected Services** | HTTP (port 80/5000), Python/Jinja2 or Node/Nunjucks application |
| **Security Level** | Medium difficulty |
| **Notes** | Demonstrate template engine detection, payload construction for Jinja2/Twig/Freemarker, RCE escalation from SSTI. Show identification methodology ({{7*7}} probing) and exploitation to command execution. |

### Video 31: Command Injection

| Field | Value |
|-------|-------|
| **Platform** | DVWA |
| **Target** | DVWA Command Injection module |
| **Configuration** | DVWA Security Level: Low (basic demo), then Medium (filter bypass) |
| **Expected Services** | HTTP (port 80) |
| **Security Level** | Low → Medium |
| **Notes** | Demonstrate OS command injection via ping utility, semicolon/pipe/ampersand injection, blind command injection detection, and out-of-band data exfiltration. Show payload obfuscation for Medium security level filters. |

### Video 32: Path Traversal

| Field | Value |
|-------|-------|
| **Platform** | DVWA |
| **Target** | DVWA File Inclusion module |
| **Configuration** | DVWA Security Level: Low (basic demo), then Medium (filter bypass) |
| **Expected Services** | HTTP (port 80) |
| **Security Level** | Low → Medium |
| **Notes** | Demonstrate directory traversal (../) to read /etc/passwd, LFI to RCE techniques (log poisoning, PHP wrappers), and filter bypass with encoding. DVWA's File Inclusion module covers both LFI and path traversal. |

### Video 33: Server-Side Request Forgery (SSRF)

| Field | Value |
|-------|-------|
| **Platform** | THM |
| **Target** | THM room "SSRF" |
| **Configuration** | Default THM room deployment |
| **Expected Services** | HTTP (port 80), internal services (metadata endpoint simulation) |
| **Security Level** | Medium difficulty |
| **Notes** | Demonstrate basic SSRF (internal port scanning), cloud metadata access (169.254.169.254), protocol smuggling, and blind SSRF detection with out-of-band callbacks. |

### Video 34: Deserialization Attacks

| Field | Value |
|-------|-------|
| **Platform** | THM |
| **Target** | THM room "Intro to Web Hacking" (Insecure Deserialization section) |
| **Configuration** | Default THM room deployment |
| **Expected Services** | HTTP (port 80), Java/PHP application with serialized object handling |
| **Security Level** | Medium difficulty |
| **Notes** | Demonstrate insecure deserialization in Java (ysoserial payloads) and PHP (object injection). Show serialized object identification, payload generation, and RCE achievement through deserialization. |

### Video 35: HTTP Interceptor

| Field | Value |
|-------|-------|
| **Platform** | DVWA |
| **Target** | DVWA (any module — Brute Force module recommended) |
| **Configuration** | DVWA Security Level: Medium |
| **Expected Services** | HTTP (port 80) |
| **Security Level** | Medium |
| **Notes** | Standalone video demonstrating HTTP Interceptor/Proxy system. Show request interception, header modification, parameter tampering, request replay, response inspection, and integration with other Huginn exploitation tools. Use DVWA Brute Force module to demonstrate credential interception and replay. |

---

## Section 6 — Network and OS Exploitation (Videos 36–40)

> **Safety Notice:** All videos in this section include explicit warnings confirming demonstrations use isolated lab environments only. No real-world systems are targeted.

### Video 36: SSH Brute-force and Vulnerability Scanning

| Field | Value |
|-------|-------|
| **Platform** | HTB |
| **Target** | HTB "Lame" (10.10.10.3) |
| **Configuration** | Default HTB machine spawn |
| **Expected Services** | SSH (port 22), FTP (21), SMB (139/445) |
| **Security Level** | Easy difficulty |
| **Notes** | Demonstrate SSH version detection, vulnerability identification (e.g., libssh auth bypass), credential brute-forcing with wordlists, and SSH key-based attack detection. Lame provides SSH plus additional services for context. Alternative: HTB "Shocker" for SSH + restricted shell scenarios. |

### Video 37: Database Attacks (MSSQL Client)

| Field | Value |
|-------|-------|
| **Platform** | HTB |
| **Target** | HTB "Archetype" (10.10.10.27) |
| **Configuration** | Default HTB machine spawn (Starting Point) |
| **Expected Services** | MSSQL (port 1433), SMB (445) |
| **Security Level** | Very Easy (Starting Point) |
| **Notes** | Demonstrate MSSQL client connection, xp_cmdshell enablement, SQL command execution, credential extraction from configuration files, and privilege escalation via database. Archetype is specifically designed for MSSQL attack demonstrations. |

### Video 38: RPC Relay and MITM Techniques

| Field | Value |
|-------|-------|
| **Platform** | HTB |
| **Target** | HTB "Active" (10.10.10.100) |
| **Configuration** | Default HTB machine spawn |
| **Expected Services** | MSRPC (135), SMB (445), LDAP (389), Kerberos (88) |
| **Security Level** | Medium difficulty |
| **Notes** | Demonstrate NTLM relay concepts, responder-style MITM interception, RPC-based relay attacks, and Kerberoasting via relay. Active's AD environment provides realistic relay attack scenarios. |

### Video 39: Exploit Database and CVE Matching

| Field | Value |
|-------|-------|
| **Platform** | HTB |
| **Target** | HTB "Blue" (10.10.10.40) |
| **Configuration** | Default HTB machine spawn |
| **Expected Services** | SMB (port 445), RPC (135), NetBIOS (139) |
| **Security Level** | Easy difficulty |
| **Notes** | Demonstrate CVE lookup (MS17-010/EternalBlue), exploit database searching, vulnerability-to-exploit matching, and exploit selection workflow. Blue is the canonical EternalBlue demonstration machine. Enterprise tier for Full Exploit Database; Professional tier for Basic access. |

### Video 40: Hacking Mode (Framework Integration)

| Field | Value |
|-------|-------|
| **Platform** | HTB |
| **Target** | HTB "Blue" (10.10.10.40) |
| **Configuration** | Default HTB machine spawn; Metasploit Framework installed locally |
| **Expected Services** | SMB (port 445) |
| **Security Level** | Easy difficulty |
| **Notes** | Demonstrate Metasploit/Empire framework integration, module selection, payload configuration, exploitation execution, and session establishment. Use EternalBlue (ms17_010_eternalblue) as the demonstration exploit. Professional tier (Basic Hacking Mode) and Enterprise tier (Advanced Hacking Mode) distinctions shown. |

---

## Section 7 — Stealth and Evasion (Videos 41–44)

### Video 41: Stealth Mode Configuration

| Field | Value |
|-------|-------|
| **Platform** | Own cloud infrastructure |
| **Target** | Own EC2 instance running IDS (Snort/Suricata) |
| **Configuration** | EC2 instance with Suricata IDS configured, network traffic capture enabled (tcpdump), baseline traffic rules established |
| **Expected Services** | HTTP (80), SSH (22), Suricata IDS monitoring all traffic |
| **Security Level** | N/A (own infrastructure) |
| **Notes** | Demonstrate measurable traffic differences between Normal, Polite, Sneaky, and Paranoid stealth levels. Show packet captures comparing timing, volume, and pattern for each level. Professional tier feature. |

### Video 42: ProxyChains Setup

| Field | Value |
|-------|-------|
| **Platform** | Own cloud infrastructure |
| **Target** | Own proxy servers (2–3 EC2 instances configured as SOCKS proxies) |
| **Configuration** | 3 EC2 instances: 1x HTTP proxy (Squid), 1x SOCKS4/5 proxy (Dante), 1x Tor relay node. ProxyChains configuration with all three. |
| **Expected Services** | SOCKS5 (1080), HTTP Proxy (3128), Tor SOCKS (9050) |
| **Security Level** | N/A (own infrastructure) |
| **Notes** | Demonstrate HTTP, SOCKS4, SOCKS5, and Tor proxy type configuration. Show strict, dynamic, and random chain modes. Verify IP rotation with each mode. Professional tier feature. |

### Video 43: Tor Integration

| Field | Value |
|-------|-------|
| **Platform** | Own cloud infrastructure |
| **Target** | Own EC2 instance as destination + Tor network for routing |
| **Configuration** | Tor service installed locally, own EC2 instance as verification endpoint (shows connecting IP) |
| **Expected Services** | Tor SOCKS (9050 local), HTTP (80 on destination EC2) |
| **Security Level** | N/A (own infrastructure) |
| **Notes** | Demonstrate Tor circuit setup, exit node selection awareness, traffic routing through Tor, and IP verification. Show integration with Huginn's stealth scanning features. Professional tier feature. |

### Video 44: AWS Infrastructure Deployment

| Field | Value |
|-------|-------|
| **Platform** | Own cloud infrastructure |
| **Target** | Own AWS account (fresh deployment) |
| **Configuration** | AWS credentials configured, VPC/subnet for proxy deployment, Security Groups allowing proxy traffic |
| **Expected Services** | EC2 API, deployed proxy/VPN servers on demand |
| **Security Level** | N/A (own infrastructure) |
| **Notes** | Demonstrate automated AWS proxy/VPN server deployment, infrastructure-as-code deployment, multi-region distribution, and teardown/cleanup procedures. Professional tier feature. Show cost awareness and resource cleanup. |

---

## Section 8 — Post-Exploitation and Privilege Escalation (Videos 45–49)

> **Safety Notice:** All videos in this section include explicit ethical guidelines, authorized-testing-only disclaimers, and confirm all demonstrations use isolated HTB/THM lab environments.

### Video 45: Session Management

| Field | Value |
|-------|-------|
| **Platform** | HTB |
| **Target** | HTB "Lame" (10.10.10.3) + HTB "Jerry" (10.10.10.95) |
| **Configuration** | Both machines spawned simultaneously for multi-session demonstration |
| **Expected Services** | Lame: SSH (22), SMB (445); Jerry: HTTP/Tomcat (8080) |
| **Security Level** | Easy difficulty (both) |
| **Notes** | Demonstrate multi-session support by establishing shells on two machines simultaneously. Show session types (reverse shell, bind shell, meterpreter), session switching, and session management. Enterprise tier feature (Post-Exploitation Framework). |

### Video 46: Credential Harvesting

| Field | Value |
|-------|-------|
| **Platform** | HTB |
| **Target** | HTB "Bastion" (10.10.10.134) |
| **Configuration** | Default HTB machine spawn |
| **Expected Services** | SSH (22), SMB (445), VHD files accessible via shares |
| **Security Level** | Easy difficulty |
| **Notes** | Demonstrate SAM dump extraction, LSA secrets retrieval, and offline credential extraction from VHD backups. Bastion specifically involves SAM database extraction from Windows backup VHD files. Enterprise tier feature. |

### Video 47: Persistence Techniques

| Field | Value |
|-------|-------|
| **Platform** | THM |
| **Target** | THM room "Windows Privilege Escalation" |
| **Configuration** | Default THM room deployment with Windows target |
| **Expected Services** | RDP (3389), SMB (445), WinRM (5985) |
| **Security Level** | Medium difficulty |
| **Notes** | Demonstrate registry run keys, scheduled task creation, service installation, and startup folder persistence on Windows. Show crontab persistence on Linux equivalent. Enterprise tier feature. Include explicit ethical reminder about only deploying persistence in authorized engagements. |

### Video 48: Lateral Movement

| Field | Value |
|-------|-------|
| **Platform** | HTB |
| **Target** | HTB "Forest" (10.10.10.161) |
| **Configuration** | Default HTB machine spawn |
| **Expected Services** | WinRM (5985), LDAP (389), Kerberos (88), SMB (445), RPC (135) |
| **Security Level** | Easy difficulty |
| **Notes** | Demonstrate PsExec, WMI execution, SMB-based lateral movement, and credential reuse across services. Forest provides an AD environment suitable for demonstrating movement between domain-joined contexts. Enterprise tier feature. |

### Video 49: Active Directory Enumeration

| Field | Value |
|-------|-------|
| **Platform** | HTB |
| **Target** | HTB "Active" (10.10.10.100) |
| **Configuration** | Default HTB machine spawn |
| **Expected Services** | LDAP (389), Kerberos (88), SMB (445), DNS (53), RPC (135) |
| **Security Level** | Medium difficulty |
| **Notes** | Demonstrate AD user/group enumeration, GPP password extraction, Kerberoasting, domain trust mapping, and BloodHound-style relationship mapping. Active is the canonical AD enumeration HTB machine with GPP credentials and Kerberoastable accounts. Enterprise tier feature. |

---

## Section 9 — Reporting and Documentation (Videos 50–54)

### Video 50: Findings Management

| Field | Value |
|-------|-------|
| **Platform** | DVWA |
| **Target** | DVWA (localhost) — using pre-collected scan data |
| **Configuration** | DVWA Security Level: Medium (scanned in prior videos); import previous scan results |
| **Expected Services** | HTTP (80), MySQL (3306) |
| **Security Level** | Medium |
| **Notes** | Demonstrate adding findings manually, importing from scan results, categorizing by severity (Critical/High/Medium/Low/Info), CVSS scoring, evidence attachment, and finding status management. Uses accumulated scan data from earlier sections. |

### Video 51: Standard Report Generation

| Field | Value |
|-------|-------|
| **Platform** | DVWA |
| **Target** | DVWA (localhost) — using findings from Video 50 |
| **Configuration** | Pre-populated findings database from previous demonstrations |
| **Expected Services** | N/A (report generation from stored data) |
| **Security Level** | N/A |
| **Notes** | Demonstrate report generation in all formats: JSON, CSV, XML, PDF, and HTML. Show complete workflow from raw scan results through findings curation to finished professional PDF report. Free tier feature (standard formats). |

### Video 52: Executive Summary Generation

| Field | Value |
|-------|-------|
| **Platform** | DVWA |
| **Target** | DVWA (localhost) — using accumulated engagement data |
| **Configuration** | Multiple scan sessions with findings across different severity levels |
| **Expected Services** | N/A (report generation from stored data) |
| **Security Level** | N/A |
| **Notes** | Demonstrate AI-generated executive summary, risk posture overview, remediation priority recommendations, and management-friendly output formatting. Show aggregation of findings from multiple scans into single engagement narrative. Enterprise tier feature. |

### Video 53: Compliance Reporting

| Field | Value |
|-------|-------|
| **Platform** | DVWA |
| **Target** | DVWA (localhost) — using accumulated engagement data |
| **Configuration** | Pre-populated findings mapped to compliance control families |
| **Expected Services** | N/A (report generation from stored data) |
| **Security Level** | N/A |
| **Notes** | Demonstrate NIST 800-53, ISO 27001, and PCI-DSS compliance report templates. Show how findings map to control families, gap analysis output, and compliance posture scoring. Enterprise tier feature. |

### Video 54: Scan Comparison and Trend Analysis

| Field | Value |
|-------|-------|
| **Platform** | DVWA |
| **Target** | DVWA (localhost) — with multiple historical scan sessions |
| **Configuration** | DVWA scanned at Low, then Medium security levels to show remediation progress |
| **Expected Services** | HTTP (80) |
| **Security Level** | Low → Medium (historical comparison) |
| **Notes** | Demonstrate scan-to-scan comparison, new/resolved finding detection, trend graphs over time, and remediation tracking. Use DVWA security level changes to simulate remediation between scans. Free tier feature (scan comparison). |

---

## Section 10 — Advanced Features and Workflows (Videos 55–61)

### Video 55: Guided Mode Walkthrough

| Field | Value |
|-------|-------|
| **Platform** | THM |
| **Target** | THM room "Vulnversity" |
| **Configuration** | Default THM room deployment |
| **Expected Services** | HTTP (port 3333), SSH (22) |
| **Security Level** | Easy difficulty |
| **Notes** | Demonstrate end-to-end Guided Mode methodology: Setup → Recon → Scan → Exploit → Report. Walk through each step with the guided workflow prompts. Vulnversity provides a straightforward path through all phases. Free tier feature. |

### Video 56: Runecraft Payload Builder

| Field | Value |
|-------|-------|
| **Platform** | THM |
| **Target** | THM room "Intro to Shells" |
| **Configuration** | Default THM room deployment; local listener configured |
| **Expected Services** | HTTP (80), various ports for reverse/bind shells |
| **Security Level** | Easy difficulty |
| **Notes** | Demonstrate custom payload generation (reverse shells, bind shells, web shells), encoding/obfuscation options, multi-format output (Python, PHP, Bash, PowerShell), and deployment to target. Include responsible disclosure reminder. Enterprise tier feature. |

### Video 57: Hash Cracking

| Field | Value |
|-------|-------|
| **Platform** | HTB |
| **Target** | HTB "Bastion" (10.10.10.134) — using extracted hashes |
| **Configuration** | Pre-extracted SAM hashes from Video 46 demonstration |
| **Expected Services** | N/A (local hash cracking — no network target needed) |
| **Security Level** | N/A |
| **Notes** | Demonstrate hash identification (NTLM, MD5, SHA-256, bcrypt), wordlist attacks, rule-based attacks, mask attacks, and hashcat/john integration. Use hashes extracted from the Bastion machine in Video 46. Professional tier feature. |

### Video 58: Local DNS Server

| Field | Value |
|-------|-------|
| **Platform** | Own cloud infrastructure |
| **Target** | Own local network + test domains |
| **Configuration** | Local DNS server setup with custom zone files, test domains pointing to lab machines |
| **Expected Services** | DNS (port 53 local), resolution of custom lab domains |
| **Security Level** | N/A (own infrastructure) |
| **Notes** | Demonstrate local DNS server deployment, custom zone configuration, DNS-based target management for lab environments, and integration with Huginn's scanning tools for hostname-based targeting. Professional tier feature. |

### Video 59: Automation and Scheduling

| Field | Value |
|-------|-------|
| **Platform** | DVWA |
| **Target** | DVWA (localhost) |
| **Configuration** | DVWA Security Level: Medium; scheduled scan profiles configured |
| **Expected Services** | HTTP (80) |
| **Security Level** | Medium |
| **Notes** | Demonstrate scan scheduling (daily/weekly/monthly), automated scan profiles, result comparison triggers, notification setup, and batch scanning workflows. Use DVWA as a persistent target for repeated automated scans. Professional tier feature. |

### Video 60: Multi-Target Campaigns

| Field | Value |
|-------|-------|
| **Platform** | THM + DVWA |
| **Target** | THM room "Vulnversity" + DVWA (localhost) simultaneously |
| **Configuration** | Both targets active; campaign configured with target groups |
| **Expected Services** | THM: HTTP (3333), SSH (22); DVWA: HTTP (80) |
| **Security Level** | Easy (THM) + Medium (DVWA) |
| **Notes** | Demonstrate multi-target campaign setup, target grouping, parallel scanning, consolidated results, and cross-target finding correlation. Show how a single engagement can span multiple targets with unified reporting. Enterprise tier feature. |

### Video 61: Plugin System

| Field | Value |
|-------|-------|
| **Platform** | DVWA |
| **Target** | DVWA (localhost) |
| **Configuration** | DVWA Security Level: Low; sample plugin installed |
| **Expected Services** | HTTP (80) |
| **Security Level** | Low |
| **Notes** | Demonstrate plugin architecture overview, installing/removing plugins, plugin configuration, creating a custom plugin (simple example), and community plugin marketplace concept. Use DVWA as the target for plugin-enhanced scanning demonstration. Enterprise tier feature. |

---

## Target Configuration Summary

### HTB Machines Used

| Machine | IP | Difficulty | Videos | Key Services |
|---------|-----|-----------|--------|-------------|
| Lame | 10.10.10.3 | Easy | 7, 36, 45 | SSH, FTP, SMB (Samba 3.0.20) |
| Beep | 10.10.10.7 | Easy | 8 | SMTP, HTTP/S, POP3, IMAP |
| Archetype | 10.10.10.27 | Very Easy | 15, 37 | MSSQL, SMB |
| Blue | 10.10.10.40 | Easy | 39, 40 | SMB (MS17-010) |
| Mirai | 10.10.10.48 | Easy | 9 | SNMP, HTTP, SSH |
| Jerry | 10.10.10.95 | Easy | 45 | Tomcat (8080) |
| Active | 10.10.10.100 | Medium | 12, 38, 49 | MSRPC, LDAP, Kerberos, SMB |
| Conceal | 10.10.10.116 | Hard | 14 | IKE (500/UDP), IPsec, SNMP |
| Bastion | 10.10.10.134 | Easy | 46, 57 | SSH, SMB (VHD backups) |
| Forest | 10.10.10.161 | Easy | 48 | WinRM, LDAP, Kerberos, SMB |
| Cascade | 10.10.10.182 | Medium | 13 | LDAP, SMB, Kerberos |

### THM Rooms Used

| Room | Videos | Key Topics |
|------|--------|-----------|
| DNS in Detail | 5 | DNS enumeration, zone transfers |
| OWASP API Security Top 10 | 11 | API endpoint discovery, method enumeration |
| Firewalls | 16 | Firewall detection, WAF fingerprinting |
| Vulnversity | 25, 55 | Web server scanning, guided mode walkthrough |
| Overpass | 27 | AI scanning demonstration |
| SSTI | 30 | Template injection (Jinja2, Twig) |
| SSRF | 33 | Server-side request forgery |
| Intro to Web Hacking | 34 | Insecure deserialization |
| Windows Privilege Escalation | 47 | Windows persistence techniques |
| Intro to Shells | 56 | Payload builder, reverse/bind shells |

### DVWA Modules Used

| Module | Security Level | Videos | Attack Type |
|--------|---------------|--------|-------------|
| SQL Injection | Low → Medium | 28 | In-band, blind SQLi |
| XSS (Reflected) | Low → Medium | 29 | Reflected XSS |
| XSS (Stored) | Low → Medium | 29 | Stored XSS |
| Command Injection | Low → Medium | 31 | OS command injection |
| File Inclusion | Low → Medium | 32 | LFI, path traversal |
| Brute Force | Medium | 35 | HTTP Interceptor demo |
| Full application | Low | 24 | Scanner profile overview |
| Full application | Medium | 26, 50, 51, 59 | Results review, findings, reports, automation |
| Full application | Low → Medium | 54 | Scan comparison (security level change = remediation) |
| Full application | Medium | 52, 53 | Executive summary, compliance reporting |
| Full application | Low | 61 | Plugin system demonstration |

### Own Cloud Infrastructure Requirements

| Component | Videos | Purpose |
|-----------|--------|---------|
| Domain with 10+ subdomains | 17, 18 | Subdomain discovery, certificate transparency |
| Test email accounts | 19 | Breach intelligence lookups |
| Fictional company website | 20 | People/employee OSINT |
| Social media test accounts | 21 | Social media intelligence |
| AWS EC2 instances (2–3) | 22, 23, 41, 42, 43, 44 | Threat intel, infra OSINT, stealth, proxies |
| AWS account with S3/Route53/CloudFront | 23 | Infrastructure OSINT |
| EC2 with Suricata IDS | 41 | Stealth mode traffic comparison |
| SOCKS/HTTP proxy instances | 42 | ProxyChains demonstration |
| Tor relay configuration | 42, 43 | Tor integration |
| Local DNS server | 58 | Custom DNS zone management |

---

## Target Preparation Checklist

Before recording, ensure the following are prepared:

- [ ] Active HTB VIP subscription (for simultaneous machine spawns)
- [ ] Active THM subscription (for room access)
- [ ] DVWA deployed locally (Docker recommended: `docker run -d -p 80:80 vulnerables/web-dvwa`)
- [ ] AWS account with budget alerts configured (stealth/deployment demos incur costs)
- [ ] Own domain registered with DNS control (Route53 or equivalent)
- [ ] Shodan API key obtained and configured
- [ ] VirusTotal API key obtained and configured
- [ ] Have I Been Pwned API key obtained (for breach intelligence)
- [ ] Metasploit Framework installed locally (for Hacking Mode integration)
- [ ] Tor service installed locally
- [ ] ProxyChains installed and configured
- [ ] Fictional company profiles and test accounts created
- [ ] Multiple DVWA scan sessions saved for reporting videos (50–54)

---

## Authorization and Ethics Statement

Every target used in this series falls into one of these authorized categories:

1. **scanme.nmap.org** — Explicitly authorized by the Nmap project for scanning demonstrations
2. **HTB machines** — Isolated lab instances spawned within a paid subscription, designed for offensive security practice
3. **THM rooms** — Isolated lab instances within a paid subscription, designed for learning
4. **DVWA** — Self-hosted, intentionally vulnerable application under full user control
5. **Own cloud infrastructure** — Personally owned and controlled cloud resources

No video in this series targets any system without explicit authorization. All demonstrations include verbal and written reminders about authorized testing requirements.
