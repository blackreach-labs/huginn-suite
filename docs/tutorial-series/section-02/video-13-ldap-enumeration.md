# VIDEO 13: LDAP Enumeration
### Directory Queries, User/Group Extraction & Base DN Discovery
**Suggested length:** 14–18 minutes
**License Tier:** Free
**Certification Relevance:** OSCP: Information Gathering | CEH: Enumeration

---

## INTRO (0:00 – 0:50)

**[Screen: Huginn splash screen with Section 2 badge, transitioning to Recon & Enumeration page]**

> "Welcome back to the Huginn tutorial series. In this video we're covering LDAP enumeration — querying directory services to extract users, groups, computers, and organizational structure from Active Directory environments. If you watched the RPC enumeration video (see Video 12: RPC Enumeration), you already saw how we can pull user data through SAMR. LDAP gives us a different — and often richer — view of the same information, with full attribute access and hierarchical structure. You'll need a target with port 389 or 636 open (see Video 6: Port Scanning) to follow along. Let's get into it."

---

## SECTION 1: Understanding LDAP (0:50 – 2:50)

**[Screen: Slide — "What is LDAP?" with diagram showing LDAP directory tree structure: DC=lab,DC=local → OU=Users, OU=Groups, OU=Computers]**

> "LDAP — Lightweight Directory Access Protocol — is the primary protocol for querying Active Directory. Think of it as a database query language for directory services. Active Directory stores everything as objects in a hierarchical tree: users, groups, computers, organizational units, group policies. LDAP lets you search, read, and in some cases modify these objects. It runs on port 389 for unencrypted connections and port 636 for LDAP over SSL."

**[Screen: Slide — "Key LDAP Concepts" with bullet points: Base DN, Search Filters, Attributes, Bind Types]**

> "There are four concepts you need to understand. First, the Base DN — Distinguished Name — is your starting point in the directory tree. Something like DC=lab,DC=local tells LDAP to search from the root of the lab.local domain. Second, search filters use a specific syntax to narrow results — objectClass=user finds all user objects, for instance. Third, attributes are the fields you want returned — sAMAccountName, memberOf, description, and so on. And fourth, bind type determines your authentication level — anonymous bind means no credentials, simple bind means username and password in plaintext, and SASL bind provides stronger authentication."

**[Screen: Slide — "Why LDAP Enumeration Matters" — showing data accessible: usernames, group memberships, password policies, service accounts, computer names]**

> "For penetration testing, LDAP enumeration is often the fastest way to get a complete picture of an Active Directory environment. A successful anonymous bind can reveal the entire user list, group memberships, computer accounts, password policies, and sometimes even passwords stored in description fields or custom attributes. Even without anonymous access, a single low-privilege credential gives you read access to almost everything in the directory."

---

## SECTION 2: Huginn's LDAP Scanner (2:50 – 5:20)

**[Screen: Huginn UI — Recon & Enumeration page, selecting LDAP scanner from service list]**

> "Huginn's LDAP scanner is designed for progressive enumeration. It starts with the least intrusive checks and escalates based on what access is available. The scanner lives in the Recon and Enumeration page alongside the other service scanners."

**[Screen: Huginn UI — LDAP scanner configuration panel showing target, port, SSL toggle, scan type dropdown, credentials section]**

> "The configuration panel gives you several options. Target IP and port are straightforward — 389 for standard LDAP, 636 for LDAPS. The SSL toggle switches between the two. Then you have the scan type selector with three modes: Basic Info queries the rootDSE for server metadata without authenticating, Anonymous Bind attempts full enumeration without credentials, and Authenticated Enum uses provided credentials for comprehensive data extraction."

**[Screen: Huginn UI — Advanced configuration: base DN override, search scope, attribute selection, result limit]**

> "In the advanced options you can override the base DN if you already know it, set the search scope — base, one-level, or subtree — choose which attributes to retrieve, and set a result limit to avoid overwhelming large directories. For most engagements you'll leave these at defaults and let Huginn discover the appropriate settings automatically."

**[Screen: Huginn UI — LDAP scan type descriptions in UI]**

> "Let me explain what each scan type does in detail. Basic Info is passive — it only reads the rootDSE, which is always anonymously accessible and reveals the server's supported LDAP versions, naming contexts, and supported controls. Anonymous Bind attempts to authenticate with empty credentials and then enumerate users, groups, and computers. Authenticated Enum does the same but with credentials you provide, which typically gives access to more attributes like password last set, account expiry, and group membership details."

---

## SECTION 3: Lab Setup — HTB Cascade (5:20 – 6:30)

**[Screen: Hack The Box platform — "Cascade" machine page showing Medium difficulty, Windows OS]**

> "Our demo target is HTB Cascade at 10.10.10.182. This is a medium-difficulty Windows machine with a rich Active Directory environment. It has LDAP on port 389, LDAPS on 636, and notably allows anonymous LDAP queries — making it ideal for demonstrating the full enumeration workflow. Connect to your HTB VPN and let's verify the target."

**[Screen: Terminal — VPN connection and port verification]**

```bash
# Connect to HTB VPN
sudo openvpn ~/htb-vpn.ovpn

# Verify LDAP ports are open
nmap -sT -p 389,636,445,88,53 10.10.10.182

# Expected output:
# PORT    STATE SERVICE
# 53/tcp  open  domain
# 88/tcp  open  kerberos-sec
# 389/tcp open  ldap
# 445/tcp open  microsoft-ds
# 636/tcp open  ldapssl
```

> "Ports 389 and 636 are both open, along with Kerberos and DNS — classic domain controller profile. We're ready to enumerate."

---

## SECTION 4: RootDSE and Base DN Discovery (6:30 – 8:45)

**[Screen: Huginn UI — Starting Basic Info scan against 10.10.10.182]**

> "We'll start with the Basic Info scan type. This queries the rootDSE — the root of the directory information tree. Every LDAP server exposes this anonymously. It's like asking the phone book for its table of contents before you start looking up names."

**[Screen: Huginn UI — RootDSE results populating: defaultNamingContext, supportedLDAPVersion, dnsHostName, serverName]**

> "Here's what came back. The defaultNamingContext is DC=cascade,DC=local — that's our base DN for subsequent searches. We can see the server supports LDAP version 3, the DNS hostname is CASC-DC1.cascade.local, and there are several naming contexts listed including the configuration and schema partitions. This single unauthenticated query just told us the domain name, the DC hostname, and where to point all our subsequent searches."

**[Screen: Terminal — manual rootDSE query for reference]**

```bash
# Manual rootDSE query using ldapsearch
ldapsearch -x -H ldap://10.10.10.182 -s base -b "" "(objectClass=*)" namingContexts defaultNamingContext dnsHostName

# Expected output:
# defaultNamingContext: DC=cascade,DC=local
# namingContexts: DC=cascade,DC=local
# namingContexts: CN=Configuration,DC=cascade,DC=local
# namingContexts: CN=Schema,CN=Configuration,DC=cascade,DC=local
# dnsHostName: CASC-DC1.cascade.local
```

> "The equivalent ldapsearch command queries the base object with an empty base DN. Huginn performs this same query using its built-in LDAP client — no external tools required. The -x flag means simple authentication and -s base means we only want the root object itself. This is always the first step in LDAP enumeration — you need the base DN before you can search for anything else."

---

## SECTION 5: Anonymous Bind and User Enumeration (8:45 – 12:00)

**[Screen: Huginn UI — Switching to Anonymous Bind scan type, initiating enumeration]**

> "Now let's try anonymous bind enumeration. Huginn will attempt to authenticate with empty credentials and then search for user, group, and computer objects under the base DN we just discovered."

**[Screen: Huginn UI — Anonymous bind succeeding, status indicator showing "Connected — Anonymous"]**

> "The anonymous bind succeeded. Not all servers allow this — it depends on the domain's security policy. On Cascade, anonymous queries are permitted, which means we can enumerate without any credentials at all. In a real engagement, this would be a significant finding worth noting in your report."

**[Screen: Huginn UI — User enumeration results populating: sAMAccountName, displayName, distinguishedName, memberOf for each user]**

> "User enumeration is running. Huginn searches for objects where objectClass equals user and objectCategory equals person — this gives us actual user accounts rather than system objects. For each user it retrieves the SAM account name, display name, distinguished name, group memberships, and available descriptive attributes. Look at this — we're getting a full user list: Administrator, CascGuest, arksvc, s.smith, r.thompson, j.wakefield, s.hickson, j.goodhand, and more."

**[Screen: Huginn UI — Detailed user view showing attributes: description, whenCreated, lastLogon, userAccountControl]**

> "Let's look at the detail level. For each user Huginn extracts as many attributes as the anonymous session allows. The userAccountControl field is particularly interesting — it tells us the account status. A value of 66048 means a normal account with password never expires. If you see 4260352, that's an account with Kerberos preauthentication not required — a prime target for AS-REP roasting."

**[Screen: Terminal — LDAP user enumeration commands]**

```bash
# Enumerate all users via anonymous LDAP bind
ldapsearch -x -H ldap://10.10.10.182 -b "DC=cascade,DC=local" "(&(objectClass=user)(objectCategory=person))" sAMAccountName memberOf description userAccountControl

# Search for users with specific attributes
ldapsearch -x -H ldap://10.10.10.182 -b "DC=cascade,DC=local" "(objectClass=user)" description | grep -i "pass\|pwd\|cred"

# Find accounts with Kerberos preauth disabled
ldapsearch -x -H ldap://10.10.10.182 -b "DC=cascade,DC=local" "(userAccountControl:1.2.840.113556.1.4.803:=4194304)" sAMAccountName
```

> "Here are the equivalent ldapsearch commands. The search filter syntax uses ampersand for AND operations and the colon notation for bitwise attribute matching. That last command searches for accounts where the DONT_REQUIRE_PREAUTH flag is set — those are AS-REP roastable. Huginn handles all this filter construction automatically."

**[Screen: Huginn UI — Highlighting a user with credentials in description field]**

> "And here's something critical — look at this user's description field. It contains what appears to be a Base64-encoded value in a custom attribute. On Cascade, this is actually how credentials are stored for certain service accounts. This is exactly why LDAP enumeration is so powerful — you get access to attributes that other enumeration methods miss entirely."

---

## SECTION 6: Group and Computer Enumeration (12:00 – 14:00)

**[Screen: Huginn UI — Group enumeration results: Domain Admins, IT staff, Remote Management Users, Audit Share, Data Share groups]**

> "Group enumeration gives us the organizational structure. Huginn queries for objectClass=group and retrieves group names, descriptions, and membership lists. On Cascade we see the standard AD groups — Domain Admins, Domain Users — plus custom groups like IT, Remote Management Users, Audit Share, and Data Share. These custom groups often reveal the application architecture and access hierarchy."

**[Screen: Huginn UI — Group membership detail view showing nested group members]**

> "The membership details are especially valuable. We can see which users belong to which groups. If we find that a user we've compromised belongs to 'Remote Management Users,' that tells us WinRM access is available. If they're in 'IT,' there might be additional shares or admin panels accessible. Huginn maps these relationships so you can quickly identify high-value targets."

**[Screen: Huginn UI — Computer enumeration results: CASC-DC1, workstations, servers]**

> "Computer enumeration reveals every domain-joined machine. Each computer object includes its DNS hostname, operating system version, and when it last authenticated. This gives you a network map without running a single port scan. You can see which machines are servers versus workstations, identify potentially unpatched systems by their OS version, and find machines that haven't authenticated recently — those might be offline or decommissioned."

**[Screen: Terminal — Group and computer enumeration commands]**

```bash
# Enumerate groups
ldapsearch -x -H ldap://10.10.10.182 -b "DC=cascade,DC=local" "(objectClass=group)" cn member description

# Enumerate computers
ldapsearch -x -H ldap://10.10.10.182 -b "DC=cascade,DC=local" "(objectClass=computer)" cn operatingSystem operatingSystemVersion dNSHostName lastLogonTimestamp

# Find service accounts (SPN set)
ldapsearch -x -H ldap://10.10.10.182 -b "DC=cascade,DC=local" "(servicePrincipalName=*)" sAMAccountName servicePrincipalName
```

> "Service account enumeration is another powerful sub-feature. By searching for objects with a servicePrincipalName attribute set, we can identify accounts that are Kerberoastable. Huginn's LDAP scanner has a dedicated service account finder that flags these automatically, highlighting accounts with SPNs that can be targeted for offline password cracking."

---

## SECTION 7: Results Interpretation and Findings (14:00 – 16:00)

**[Screen: Huginn UI — LDAP scan summary showing: server info, user count, group count, computer count, service accounts found, privileged users identified]**

> "Let's review the full picture. From a single anonymous LDAP session against Cascade, we've extracted: complete server configuration from the rootDSE, the full user list with attributes — and a potential credential in a custom field — group memberships revealing the organizational hierarchy, computer accounts showing the domain topology, and service accounts that are candidates for Kerberoasting."

**[Screen: Huginn UI — Privileged user identification showing members of Domain Admins and other high-value groups]**

> "Huginn automatically identifies privileged users by checking membership in sensitive groups — Domain Admins, Enterprise Admins, Schema Admins, Account Operators, and Backup Operators. This saves you from manually cross-referencing user and group data. On Cascade, we can see exactly who the domain admins are and start planning our attack path toward those accounts."

**[Screen: Huginn UI — Data export options and integration with session data]**

> "All LDAP enumeration results feed into Huginn's session data. The discovered users appear in your target's asset inventory. Group memberships inform the attack path visualization. And the data is exportable in structured formats — JSON for scripting, CSV for spreadsheets, or directly into your findings for reporting. This is recon data that stays useful throughout the entire engagement."

---

## SECTION 8: Certification Context (16:00 – 16:45)

**[Screen: Slide — OSCP and CEH relevance for LDAP enumeration]**

> "For OSCP, LDAP enumeration is critical during the Information Gathering phase. The exam regularly features AD environments where anonymous LDAP queries reveal user accounts or credentials in object attributes. Being able to quickly enumerate and identify high-value targets saves precious exam time. For CEH candidates, LDAP enumeration maps directly to the Enumeration domain — it's explicitly covered as a required skill. Practice on HTB machines like Cascade, Active, and Forest — each presents different LDAP access levels and findings to discover."

---

## OUTRO (16:45 – end)

> "That's LDAP enumeration in Huginn. We started with rootDSE discovery to find our base DN, performed anonymous bind enumeration to extract users, groups, and computers, identified service accounts and privileged users, and found sensitive data in object attributes. Combined with the RPC enumeration we covered previously (see Video 12: RPC Enumeration), you now have two powerful methods for extracting Active Directory information during recon. In our next video, we'll move to IKE and VPN assessment (see Video 14: IKE/VPN Assessment) — a completely different protocol targeting encrypted tunnel endpoints. See you there."

---
