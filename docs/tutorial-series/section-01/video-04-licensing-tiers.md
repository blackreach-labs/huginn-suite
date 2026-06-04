# VIDEO 4: Licensing & Tiers
### Free vs Professional vs Enterprise — What You Need for Your Operations
**Suggested length:** 10–13 minutes
**License Tier:** Free
**Certification Relevance:** OSCP, CEH, PNPT — full methodology coverage

---

## INTRO (0:00 – 1:00)

**[Screen: Huginn splash screen with Section 1 title card "Getting Started"]**

> "Welcome back. In this video we're covering Huginn's three license tiers — what each one unlocks, what operational capabilities sit behind each tier, and which one matches your specific workflow. Whether you're a freelance consultant, a red team operator, running a security consultancy, or building your skills for the field — there's a tier designed for where you are."

**[Screen: Slide showing three-tier structure — Free, Professional ($99/mo), Enterprise ($299/mo)]**

> "Huginn uses a three-tier model: Free, Professional at $99 per month, and Enterprise at $299 per month. Let's break down exactly what you get at each level and who should be running what."

---

## SECTION 1: Free Tier — Core Testing Capabilities (1:00 – 3:15)

**[Screen: Slide titled "Free Tier" with feature categories — Enumeration, Web Exploitation, Basic Reporting, OSINT]**

> "The Free tier provides the complete core testing workflow — all enumeration modules, all web exploitation tools, vulnerability scanning, and basic reporting. This is not a crippled demo. The Free tier is permanently free, fully functional across its covered areas, and capable of real assessment work."

**[Screen: Recon & Enumeration page — showing all 12 enumeration modules unlocked]**

> "Every enumeration module is included. DNS enumeration, port scanning, SMB, SMTP, SNMP, HTTP fingerprinting, API enumeration, RPC, LDAP, IKE/VPN assessment, database enumeration, and AV/firewall detection. All twelve modules, unrestricted. The entire Recon phase of the attack chain operates at full capability on the Free tier."

**[Screen: Web Exploits page — SQL Injection, XSS, SSTI, Command Injection, Path Traversal, SSRF, Deserialization, HTTP Interceptor]**

> "Web exploitation is fully included. SQL injection — in-band, blind, and second-order. Cross-site scripting. Server-side template injection. Command injection. Path traversal. SSRF. Insecure deserialization. And the HTTP interceptor for request manipulation and replay. Complete OWASP Top 10 testing methodology, no restrictions."

**[Screen: Findings page showing basic report export options: JSON, CSV, XML, PDF, HTML]**

> "Reporting includes findings management with CVSS scoring plus export to JSON, CSV, XML, PDF, and HTML. That's sufficient for engagement documentation, lab writeups, and evidence compilation. Executive summaries, compliance mapping, and trend analysis are higher-tier features."

**[Screen: OSINT modules available in Free — Subdomain Discovery, Certificate Transparency, People OSINT, Social Media, Infrastructure OSINT]**

> "Most OSINT modules are Free tier — subdomain discovery, certificate transparency, people and employee OSINT, social media intelligence, and infrastructure OSINT. Breach intelligence and threat intelligence feeds require Enterprise. The Free tier's generosity is deliberate — professional tooling should be accessible to operators evaluating the platform on real work, and to newcomers building their skills before entering the field."

---

## SECTION 2: Professional Tier — Operational Security ($99/month) (3:15 – 5:45)

**[Screen: Slide titled "Professional Tier — $99/month" with feature categories: Stealth & Evasion, Hash Cracking, Automation, AWS Deployment]**

> "The Professional tier at $99 per month adds operational security capabilities — stealth, evasion, proxy routing, hash cracking, automation, and cloud infrastructure deployment. These are the features that separate lab-style testing from real engagement operations where detection avoidance matters and operational efficiency is directly billable."

**[Screen: Stealth Mode settings — evasion levels, traffic patterns, timing controls, IDS avoidance]**

> "Stealth Mode gives you granular control over operational noise. Configure evasion levels that control packet timing, randomize source ports, fragment payloads, and adjust traffic patterns to avoid triggering IDS and SIEM signatures. On engagements where the client has active monitoring and detection testing is in scope, stealth parameters are non-negotiable."

**[Screen: ProxyChains and Tor configuration — multi-hop routing, circuit management, exit node selection]**

> "Proxy support includes ProxyChains integration for multi-hop SOCKS routing, native Tor integration with circuit management and exit node selection, and the AWS Infrastructure Deployment module that spins up proxy servers in your preferred region directly from Huginn. Operational security on external assessments demands proper traffic routing — Professional tier delivers it natively."

**[Screen: Hash Cracking module — dictionary attacks, rule-based cracking, rainbow tables]**

> "Hash cracking handles dictionary attacks with rule-based permutations and rainbow table lookups. When you capture hashes during an engagement — SAM dumps, NTDS extractions, database credential stores — crack them in the same tool without context-switching to Hashcat or John. Results feed directly back into your session data for credential reuse and lateral movement planning."

**[Screen: Automation & Scheduling panel — recurring scans, workflow chains, batch operations]**

> "Automation and scheduling enables recurring scans, chains multiple modules into automated workflows, and handles batch operations across scope. If you're on a retainer doing monthly assessments for the same client, configure your standard scan profile once and schedule it. Efficiency at scale."

**[Screen: Local DNS Server — port 5353, custom record configuration for lab and engagement use]**

> "The local DNS server on port 5353 lets you define custom DNS records — useful for DNS-based attack setups, traffic redirection during exploitation, and controlled lab environments. Lightweight, runs alongside Huginn, and configurable per-session."

---

## SECTION 3: Enterprise Tier — Full Platform ($299/month) (5:45 – 8:00)

**[Screen: Slide titled "Enterprise Tier — $299/month" with feature categories: AI Scanning, Post-Exploitation, Compliance, Multi-Target, Plugins]**

> "The Enterprise tier at $299 per month unlocks the complete platform — AI-powered scanning, the full post-exploitation framework, compliance reporting, multi-target campaign management, and the plugin system. This tier is built for teams, consultancies, and operators running advanced engagements at scale."

**[Screen: AI Scanner interface — neural network analysis, ML pattern detection, adaptive scanning strategies]**

> "AI-powered scanning uses machine learning models trained on vulnerability patterns to analyze your scan results, identify correlations across services that human review misses in large datasets, and recommend exploitation paths based on detected technology stacks. When it detects a WAF, it automatically adjusts to evasion-friendly testing strategies. On large-scope assessments with hundreds of hosts, AI augmentation catches what manual review can't cover in the available engagement window."

**[Screen: Post-Exploitation framework — session management, credential harvesting, persistence, lateral movement, AD enumeration]**

> "The post-exploitation framework covers everything after initial access. Multi-session management across multiple compromised hosts. Credential harvesting — SAM databases, LSA secrets, NTDS.dit extraction. Persistence modules for registry keys, scheduled tasks, and services. Lateral movement via PsExec, WMI, and SSH key abuse. Full Active Directory enumeration for domain-joined environments. This is your complete Elevate phase toolkit for real engagements."

**[Screen: Compliance Reporting — NIST 800-53, ISO 27001, PCI-DSS templates and mapping]**

> "Compliance reporting maps findings to industry frameworks — NIST 800-53, ISO 27001, PCI-DSS. Select your client's applicable framework and Huginn generates reports showing which controls your findings impact. Executive summary generation produces business-readable narratives for C-suite delivery. For consultancies with compliance-driven clients, this eliminates hours of manual report mapping per engagement."

**[Screen: Multi-Target Campaigns and Plugin System — parallel assessments, custom modules, API hooks]**

> "Multi-target campaign management runs parallel assessments across multiple hosts with aggregated results — essential for large-scope external assessments and internal network sweeps. The plugin system lets you extend Huginn with custom modules, integrate external APIs, build bespoke reporting templates, or add capabilities specific to your team's methodology. Enterprise is the extensible, scalable platform."

---

## SECTION 4: Feature Comparison Matrix (8:00 – 9:00)

**[Screen: Full-screen comparison table showing all three tiers with checkmarks]**

> "Here's the complete comparison at a glance. I'll leave this on screen — pause if you need to review the details."

**[Screen: Feature comparison table]**

| Feature Category | Free | Professional | Enterprise |
|-----------------|------|--------------|------------|
| All Enumeration Modules (12) | ✓ | ✓ | ✓ |
| Web Exploitation (8 modules) | ✓ | ✓ | ✓ |
| Basic Reporting (JSON/CSV/XML/PDF/HTML) | ✓ | ✓ | ✓ |
| Guided Workflow Mode | ✓ | ✓ | ✓ |
| OSINT (5 of 7 modules) | ✓ | ✓ | ✓ |
| Vulnerability Scanner (Basic) | ✓ | ✓ | ✓ |
| Stealth Mode & Evasion | ✗ | ✓ | ✓ |
| ProxyChains & Tor | ✗ | ✓ | ✓ |
| Hash Cracking | ✗ | ✓ | ✓ |
| Automation & Scheduling | ✗ | ✓ | ✓ |
| Local DNS Server (port 5353) | ✗ | ✓ | ✓ |
| AWS Infrastructure Deployment | ✗ | ✓ | ✓ |
| AI-Powered Scanning | ✗ | ✗ | ✓ |
| Post-Exploitation Framework | ✗ | ✗ | ✓ |
| Active Directory Enumeration | ✗ | ✗ | ✓ |
| Compliance Reporting (NIST/ISO/PCI) | ✗ | ✗ | ✓ |
| Executive Summary Generation | ✗ | ✗ | ✓ |
| Multi-Target Campaigns | ✗ | ✗ | ✓ |
| Plugin System | ✗ | ✗ | ✓ |
| Breach & Threat Intelligence | ✗ | ✗ | ✓ |

> "The tier progression is logical. Free provides the core testing workflow — complete and capable. Professional adds operational security for real engagements where stealth and efficiency matter. Enterprise adds advanced exploitation, AI augmentation, compliance reporting, and platform extensibility for teams operating at scale."

---

## SECTION 5: Activating a License (9:00 – 10:15)

**[Screen: Settings → License page — current tier shown as "Free" with activation options]**

> "Activation is straightforward. Open Settings, click the License tab. You'll see your current tier and two options — enter a license key if you've purchased, or start a 14-day trial of Professional or Enterprise."

**[Screen: License activation dialog — key entry field and Activate button]**

> "Paste your license key and click Activate. Huginn validates against the license server and unlocks the tier immediately. Keys are machine-bound — deactivate from this panel before migrating to a different workstation."

**[Screen: Trial activation — tier selection and email entry]**

> "For the trial, select Professional or Enterprise, enter your email, and you get full access for 14 days. No credit card required. After expiration, you revert to Free automatically — nothing breaks, session data is preserved, you simply lose access to tier-specific features until you activate."

```
License Activation:
1. Settings → License → Enter License Key
2. Paste key → Click Activate
3. Restart Huginn to apply

Trial Activation:
1. Settings → License → Start Trial
2. Select tier: Professional or Enterprise
3. Enter email → Start 14-Day Trial
4. Restart Huginn to apply
```

**[Screen: Post-activation — tier badge updates in title bar, expiry date shown in settings]**

> "After activation, the tier badge updates in the title bar and the settings page shows your expiration date. Monitor remaining time from the License panel."

---

## SECTION 6: Which Tier Fits Which Workflow (10:15 – 11:45)

**[Screen: Slide showing operator profiles matched to tiers — Solo Pentester→Professional, Consultancy/Team→Enterprise, Learning/Evaluating→Free]**

> "Let me make the recommendation direct. If you're a working penetration tester — solo consultant, freelancer, or employed pentester running real client engagements — Professional is your tier. Stealth mode, proxy routing, automation, and hash cracking are operational necessities on production assessments. At $99 per month, that's less than a single billable hour for most consultants."

**[Screen: Slide showing consultancy workflow — multi-target campaigns, compliance reports, team operations]**

> "If you're running a consultancy or internal red team — multiple assessors, parallel campaigns, compliance-driven reporting, or custom tooling needs — Enterprise at $299 per month. For a team billing tens of thousands per engagement, the efficiency gains pay for the license in the first day of every assessment."

**[Screen: Slide showing learning and evaluation use — Free tier with complete core workflow, lab platform compatibility]**

> "If you're entering the field, building your skills, or evaluating the platform before committing — the Free tier is genuinely capable. Full enumeration, full web exploitation, basic reporting, and guided workflow to teach you professional methodology. Run it against Hack The Box, TryHackMe, DVWA — learn on the same tool you'll use professionally. When your work demands stealth and automation, you'll know it's time to upgrade."

**[Screen: Pricing context — "$99/mo < 1 billable hour. $299/mo < 1 billable day."]**

> "Frame the pricing against professional revenue. A Professional license costs less than a single billable hour for most consultants. Enterprise costs less than a single day's revenue for a consultancy. Professional tooling at professional prices — and these are conservative relative to alternatives like Burp Suite Pro or Cobalt Strike licensing."

---

## OUTRO (11:45 – end)

**[Screen: End card with "Section 1 Complete — Next: Section 2, Video 5 — DNS Enumeration" and tier badge]**

> "That wraps Section 1 — Getting Started. You know what Huginn is, how to install it, how to navigate the interface efficiently, and which license tier matches your operational profile. Starting in the next video, we dive into the tools themselves. Section 2 covers Recon and Enumeration — beginning with DNS enumeration in Video 5. That's where hands-on operations begin. If you haven't created an engagement session yet, do that before the next video. See you in Section 2."
