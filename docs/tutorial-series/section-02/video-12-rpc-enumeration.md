# VIDEO 12: RPC Enumeration
### RPC Endpoint Mapping, Interface Discovery & NULL Sessions
**Suggested length:** 14–18 minutes
**License Tier:** Free
**Certification Relevance:** OSCP: Information Gathering | CEH: Enumeration

---

## INTRO (0:00 – 0:50)

**[Screen: Huginn splash screen with Section 2 badge, transitioning to Recon & Enumeration page]**

> "Welcome back to the Huginn tutorial series. Today we're tackling RPC enumeration — mapping Remote Procedure Call endpoints, discovering exposed interfaces, and extracting user and system information through anonymous and authenticated RPC sessions. RPC is one of those protocols that's everywhere on Windows networks but often overlooked during recon. If a target has ports 135, 139, or 445 open (see Video 6: Port Scanning), there's a good chance you can pull valuable data from it via RPC. Let's see how Huginn handles this."

---

## SECTION 1: Understanding RPC (0:50 – 2:45)

**[Screen: Slide — "What is RPC?" with diagram showing client-server RPC communication flow over named pipes and TCP]**

> "Remote Procedure Call is a protocol that allows a program on one machine to execute code on another machine as if it were local. On Windows systems, Microsoft's implementation — MSRPC — underpins a huge amount of functionality. Everything from file sharing to domain authentication uses RPC under the hood. The RPC Endpoint Mapper runs on TCP port 135 and acts as a directory service — it tells clients which port a particular RPC service is listening on."

**[Screen: Slide — "Key RPC Interfaces" listing SAMR, LSA, SVCCTL, DRSUAPI, LSARPC with descriptions]**

> "For penetration testing, the interesting RPC interfaces include SAMR for user and group enumeration, LSA for domain policy and trust information, SVCCTL for service management, and DRSUAPI for domain replication. These interfaces can often be queried anonymously or with low-privilege credentials to extract sensitive information. Named pipes — essentially inter-process communication channels exposed over SMB — provide another access path to these same services through ports 139 and 445."

---

## SECTION 2: Huginn's RPC Enumeration Tools (2:45 – 5:15)

**[Screen: Huginn UI — Recon & Enumeration page, selecting RPC scanner]**

> "Huginn has a comprehensive RPC enumeration suite built from multiple components. The RPC Enumerator handles connectivity testing and endpoint mapping. The RPC Enumeration Engine performs direct RPC calls against SAMR and LSA interfaces for user and policy information. And the Anonymous RPC Enum module specifically targets null session access — attempting enumeration without any credentials."

**[Screen: Huginn UI — RPC scanner configuration panel showing target IP, port selection, authentication options]**

> "The configuration panel lets you specify your target IP, choose which ports to probe — 135 for the endpoint mapper, 139 and 445 for named pipes — and optionally provide credentials. For anonymous enumeration, you leave the credentials blank. You can also select which enumeration modules to run: endpoint mapping, service enumeration, registry queries, SAMR users, LSA policy, or all of the above."

**[Screen: Huginn UI — Advanced options showing scan subtypes: enumeration, vulnerability assessment, comprehensive]**

> "Under advanced options you'll see scan subtypes. The enumeration subtype focuses on information gathering — mapping endpoints and extracting data. The vulnerability assessment subtype checks for known RPC vulnerabilities and misconfigurations. And comprehensive runs everything. For this demo we'll start with enumeration and then show the other modes."

---

## SECTION 3: Lab Setup — HTB Active (5:15 – 6:30)

**[Screen: Hack The Box platform — "Active" machine page showing Medium difficulty, Windows OS]**

> "Our target today is HTB Active, a medium-difficulty Windows Active Directory machine at 10.10.10.100. This is a domain controller with a full suite of RPC services exposed — perfect for demonstrating endpoint mapping, anonymous enumeration, and named pipe access. Make sure you have your HTB VPN connected."

**[Screen: Terminal — VPN connection and initial port scan confirmation]**

```bash
# Connect to HTB VPN
sudo openvpn ~/htb-vpn.ovpn

# Quick port check confirming RPC services
nmap -sT -p 135,139,445,389,88 10.10.10.100

# Expected output:
# PORT    STATE SERVICE
# 88/tcp  open  kerberos-sec
# 135/tcp open  msrpc
# 139/tcp open  netbios-ssn
# 389/tcp open  ldap
# 445/tcp open  microsoft-ds
```

> "We can see ports 135, 139, and 445 are all open — that's the RPC endpoint mapper, NetBIOS session service, and SMB. Kerberos and LDAP are also there, confirming this is a domain controller. All the ingredients we need for rich RPC enumeration."

---

## SECTION 4: RPC Endpoint Mapping (6:30 – 9:15)

**[Screen: Huginn UI — Starting RPC endpoint mapping scan against 10.10.10.100]**

> "Let's start with RPC endpoint mapping. This queries port 135 to get a list of all registered RPC services and the ports they're listening on. Think of it as a service directory for the entire system."

**[Screen: Huginn UI — Results populating with RPC endpoints, showing UUID, named pipe, and TCP port for each service]**

> "Huginn is connecting to the endpoint mapper and pulling back the registration table. Each entry shows the service UUID — a unique identifier for that RPC interface — the named pipe or TCP port it's bound to, and an annotation describing the service. You can see entries for the SAMR interface, LSA, the Service Control Manager, the Task Scheduler, and several others."

**[Screen: Terminal — equivalent rpcdump command for reference]**

```bash
# Manual RPC endpoint mapping (equivalent to what Huginn does internally)
# Using rpcdump from impacket
rpcdump.py 10.10.10.100

# Alternative: using rpcclient for named pipe enumeration
rpcclient -U "" -N 10.10.10.100 -c "lsaquery"
rpcclient -U "" -N 10.10.10.100 -c "enumdomusers"
rpcclient -U "" -N 10.10.10.100 -c "srvinfo"
```

> "For reference, this is similar to what rpcdump from the Impacket toolkit does. Huginn's implementation connects directly via TCP to port 135, sends an RPC bind request, and then queries the endpoint mapper using the DCE/RPC protocol. The advantage is you get structured, organized results right in the UI rather than parsing raw text output."

**[Screen: Huginn UI — Detailed endpoint view showing service name, UUID, protocol, binding info]**

> "Let's look at some key findings. We've got the SAMR interface bound to named pipe \\pipe\\samr — that's our path to user enumeration. The LSA interface is on \\pipe\\lsarpc — domain policy and trust information. SVCCTL is on \\pipe\\svcctl — service enumeration. And there are several DCOM interfaces on dynamic TCP ports. Each of these is a potential information source."

---

## SECTION 5: Anonymous RPC Enumeration (9:15 – 12:30)

**[Screen: Huginn UI — Switching to Anonymous RPC Enumeration module, initiating null session scan]**

> "Now for the real prize — anonymous enumeration. A null session means connecting with empty credentials. Many Windows systems, especially older domain controllers or those with relaxed policies, allow anonymous access to certain RPC interfaces. Let's see what Active gives us."

**[Screen: Huginn UI — Anonymous connection establishing, SAMR enumeration starting]**

> "Huginn's anonymous RPC module tries multiple access methods. First it attempts a direct RPC connection with null credentials. Then it tries SMB named pipes with a null session — connecting to IPC$ without authentication. If either succeeds, it starts querying interfaces."

**[Screen: Huginn UI — SAMR user enumeration results showing domain users with RIDs]**

> "We've got SAMR access. Huginn is enumerating domain users through the Security Account Manager interface. Each user comes back with their Relative Identifier — the RID — and their account name. We can see the Administrator account at RID 500, Guest at 501, krbtgt at 502, and several domain user accounts. This is the kind of information that directly feeds into password attacks or Kerberoasting later in your engagement."

**[Screen: Huginn UI — LSA policy query results showing domain name, SID, DNS info]**

> "The LSA policy query was also successful. We've extracted the domain name, the domain SID, and the DNS forest information. This tells us the exact domain structure — lab.local in this case — which is critical for Kerberos attacks and further AD enumeration. Huginn automatically performs the LSA OpenPolicy2 call and then queries for PolicyPrimaryDomainInformation to extract this."

**[Screen: Terminal — showing the RPC calls happening under the hood]**

```bash
# What Huginn is doing under the hood:
# 1. Connect to IPC$ with null session
smbclient //10.10.10.100/IPC$ -U "" -N

# 2. SAMR enumeration via null session
rpcclient -U "" -N 10.10.10.100 -c "enumdomusers"
# Output: user:[Administrator] rid:[0x1f4]
# Output: user:[Guest] rid:[0x1f5]
# Output: user:[krbtgt] rid:[0x1f6]
# Output: user:[SVC_TGS] rid:[0x459]

# 3. LSA policy query
rpcclient -U "" -N 10.10.10.100 -c "lsaquery"
# Output: Domain Name: ACTIVE
# Output: Domain Sid: S-1-5-21-405608879-3187717380-1996298813

# 4. Named pipe enumeration
rpcclient -U "" -N 10.10.10.100 -c "netshareenum"
```

> "Here's what those RPC calls look like from the command line. Huginn handles all of this internally using its RPC transport layer — building proper DCE/RPC PDUs, performing the three-way bind handshake, and parsing the NDR-encoded responses. You get the clean results without needing to memorize rpcclient syntax."

---

## SECTION 6: Named Pipe Enumeration (12:30 – 14:15)

**[Screen: Huginn UI — Named pipe discovery results]**

> "Named pipes are another important piece of the RPC picture. These are inter-process communication channels that services expose over SMB. By enumerating available named pipes, we can determine which services are accessible and potentially find unusual or custom pipes that indicate additional attack surface."

**[Screen: Huginn UI — List of discovered named pipes: samr, lsarpc, svcctl, netlogon, srvsvc, wkssvc, browser, epmapper]**

> "On Active, Huginn discovered the standard Windows named pipes — samr, lsarpc, svcctl, netlogon, srvsvc, and wkssvc. These correspond to the Security Account Manager, Local Security Authority, Service Control, Netlogon, Server Service, and Workstation Service respectively. Each of these is a potential interaction point."

**[Screen: Huginn UI — Service enumeration via SVCCTL named pipe]**

> "Through the SVCCTL pipe, Huginn can enumerate running services on the target. This works similarly to running sc query on the remote machine. The service list tells us what's installed and running — useful for identifying potential attack vectors or confirming the system's role. We can see Active Directory services, DNS Server, Kerberos Key Distribution Center — all confirming this is a domain controller."

**[Screen: Terminal — Named pipe interaction]**

```bash
# Enumerate named pipes via SMB
smbclient //10.10.10.100/IPC$ -U "" -N -c "ls"

# Query specific pipes
rpcclient -U "" -N 10.10.10.100 -c "getusername"
rpcclient -U "" -N 10.10.10.100 -c "querydispinfo"
rpcclient -U "" -N 10.10.10.100 -c "enumdomgroups"
```

> "Named pipe enumeration is especially valuable because different pipes may have different access controls. Even when SAMR is restricted, you might find that srvsvc or wkssvc allows anonymous queries that leak share names or logged-in users. Always enumerate all available pipes."

---

## SECTION 7: Results Interpretation and Next Steps (14:15 – 16:15)

**[Screen: Huginn UI — Complete RPC scan results summary with categorized findings]**

> "Let's review everything we pulled from this single target. Through RPC enumeration we've gathered: a complete list of registered RPC services and their bindings, domain user accounts with RIDs via SAMR, domain name and SID via LSA policy, available named pipes, and a running service inventory. All of this from anonymous access — no credentials required."

**[Screen: Huginn UI — RPC data summary view with graph visualization of discovered services]**

> "Huginn organizes these results into a structured format. The data summary shows totals — how many endpoints, how many users, how many services. The graph view lets you visualize the relationships between services. And all of this feeds into the broader session data, so when you move to exploitation later, you have this recon data at your fingertips."

**[Screen: Huginn UI — Security issues flagged: anonymous access enabled, sensitive interfaces exposed]**

> "The security assessment module has flagged several issues. Anonymous RPC access is enabled — that's often a misconfiguration. Sensitive interfaces like SAMR and LSA are queryable without authentication. And there are services with known vulnerability patterns. These findings go directly into your report and inform your next steps — whether that's password spraying the discovered users, attempting Kerberoasting against service accounts, or moving to full Active Directory enumeration."

---

## SECTION 8: Certification Context (16:15 – 17:00)

**[Screen: Slide — OSCP and CEH relevance for RPC enumeration]**

> "For OSCP preparation, RPC enumeration is part of the Information Gathering domain. The exam frequently features Windows targets where null session enumeration reveals user accounts that can be targeted with password attacks. Knowing how to extract this data quickly is a time-saver. For CEH, this falls under the Enumeration phase — specifically NetBIOS and LDAP enumeration objectives. Practice this on HTB machines like Active, Forest, and Cascade — all have rich RPC services for enumeration practice."

---

## OUTRO (17:00 – end)

> "That's RPC enumeration in Huginn. We mapped RPC endpoints, performed anonymous enumeration through SAMR and LSA interfaces, discovered named pipes, and extracted service inventories — all without credentials. In the next video, we'll cover LDAP enumeration (see Video 13: LDAP Enumeration), which builds on similar concepts but targets the directory service directly for user, group, and computer object extraction. See you there."

---
