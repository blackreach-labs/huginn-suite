# VIDEO 9: SNMP Enumeration
### Community Strings, MIB Walking & Information Disclosure
**Suggested length:** 14–18 minutes
**License Tier:** Free
**Certification Relevance:** OSCP: Information Gathering | CEH: Enumeration

---

## INTRO (0:00 – 0:50)

**[Screen: Huginn main dashboard with the Recon & Enumeration page open. SNMP scanner panel visible in the background.]**

> "Welcome back to the Huginn tutorial series. Today we're tackling SNMP enumeration — a protocol that was designed for network monitoring but frequently becomes an information goldmine for penetration testers. SNMP runs on UDP port 161 and if you can guess the community string — which is essentially a password — you can pull system descriptions, user lists, running processes, network interfaces, and installed software from a target. We'll walk through Huginn's SNMP scanner, demonstrate community string guessing, and perform a full MIB walk against HTB Mirai. Let's dive in."

---

## SECTION 1: Understanding SNMP (0:50 – 3:00)

**[Screen: Diagram showing SNMP architecture — Manager, Agent, MIB tree structure with OID examples.]**

> "SNMP — Simple Network Management Protocol — was built so administrators could monitor and manage network devices remotely. The architecture has three parts: a Manager that sends queries, an Agent running on the target device, and the MIB — Management Information Base — which is a hierarchical database of everything the agent knows about the device. Each piece of information has a unique Object Identifier, or OID, written as a dotted number like 1.3.6.1.2.1.1.1.0 for the system description."

**[Screen: Table showing SNMP versions — v1 (plaintext community), v2c (plaintext community + bulk operations), v3 (authentication + encryption).]**

> "There are three SNMP versions you'll encounter. Version 1 and 2c use community strings for authentication — these are transmitted in plaintext, making them easy to sniff or guess. The default community strings are 'public' for read access and 'private' for read-write. Version 3 adds proper authentication and encryption, but many devices still run v1 or v2c with default strings. For a pentester, finding a valid community string is like finding an unlocked door — suddenly you can read everything the device knows about itself."

**[Screen: Common OID tree diagram showing iso.org.dod.internet.mgmt.mib-2 branches — system, interfaces, ip, tcp, udp, snmp.]**

> "The MIB tree is organized under standard branches. Under mib-2, you'll find system information at 1.3.6.1.2.1.1, network interfaces at 1.3.6.1.2.1.2, IP routing at 1.3.6.1.2.1.4, and TCP connection tables at 1.3.6.1.2.1.6. Beyond the standard MIBs, vendors add their own extensions — Microsoft puts Windows user lists at 1.3.6.1.4.1.77.1.2.25, for example. Walking the entire tree can reveal far more than you'd expect from a monitoring protocol."

---

## SECTION 2: Huginn SNMP Scanner Interface (3:00 – 5:00)

**[Screen: Huginn Recon & Enumeration page → Service Scanners tab → SNMP selected from the protocol dropdown.]**

> "In Huginn, head to Recon and Enumeration, then Service Scanners, and select SNMP from the protocol dropdown. The SNMP enumeration panel appears with your target configuration options."

**[Screen: Close-up of SNMP configuration panel showing Target IP, SNMP Version dropdown (v1/v2c/v3), Scan Type dropdown, and Community Strings field.]**

> "The interface has four main fields. Target is your IP address — SNMP doesn't use hostnames for queries. The Version dropdown lets you select v1, v2c, or v3. Scan Type gives you options: Basic Info pulls just the system description, Users targets the user table, Network grabs interface information, and Full Enumeration walks everything. The Community Strings field accepts a comma-separated list of strings to test — Huginn defaults to 'public', 'private', and 'community', but you can add your own."

**[Screen: Scan Type dropdown expanded showing options: Basic Info, Users, Network, Full Enumeration.]**

> "For today's demo we'll use Full Enumeration to show everything SNMP can reveal. In a real engagement you might start with Basic Info for speed and only do a full walk if the community string works. Each scan type maps to specific OID branches — Full Enumeration walks the entire tree, which takes longer but gives you the complete picture."

---

## SECTION 3: Configuration Options (5:00 – 6:30)

**[Screen: SNMP panel configured — Target: 10.10.10.48, Version: 2c, Scan Type: Full Enumeration, Communities: public,private,community.]**

> "Let's configure for our target — HTB Mirai at 10.10.10.48. From our earlier port scan we know UDP 161 is open (see Video 6: Port Scanning). I'll set version to 2c since that's most common, scan type to Full Enumeration, and leave the default community strings. On a real engagement you'd add strings from wordlists like the ones in SecLists — strings like 'manager', 'admin', 'cisco', 'monitor' are surprisingly common on enterprise devices."

**[Screen: Advanced options panel showing Timeout, Retries, Max OIDs per request, and Output Format.]**

> "The advanced options let you tune performance. Timeout controls how long Huginn waits for each UDP response — important since UDP is connectionless and packets can drop silently. Retries sets how many times to resend before giving up. Max OIDs per request controls GETBULK sizing for v2c — higher values are faster but some devices choke on large requests. For lab environments the defaults work fine."

---

## SECTION 4: Live Demonstration — Community String Discovery (6:30 – 9:00)

**[Screen: Huginn SNMP scanner ready to run. Target: HTB "Mirai" (10.10.10.48). Start Scan button highlighted.]**

> "Let's start the scan. Huginn first tests each community string to find which ones the target accepts before performing the full enumeration."

```bash
# Community string testing
snmpget -v 2c -c public 10.10.10.48 1.3.6.1.2.1.1.1.0
# Response: SNMPv2-MIB::sysDescr.0 = STRING: Linux Mirai 4.9.0-6-686 #1 SMP Debian 4.9.82-1+deb9i2 i686

snmpget -v 2c -c private 10.10.10.48 1.3.6.1.2.1.1.1.0
# Timeout: No Response

snmpget -v 2c -c community 10.10.10.48 1.3.6.1.2.1.1.1.0
# Timeout: No Response
```

**[Screen: Huginn output showing "Valid community: public" in green, and "No response" for private and community in amber.]**

> "Huginn tests each community string by sending a GET request for the system description OID. The 'public' string works — we get back the full system description showing this is a Linux machine running Debian on a 4.9 kernel. The 'private' and 'community' strings time out, meaning they're not configured on this target. One valid string is all we need."

**[Screen: Huginn automatically proceeding to full enumeration with the valid 'public' community string.]**

> "With a valid community string confirmed, Huginn automatically proceeds to the full enumeration using that string. This is where things get interesting."

---

## SECTION 5: Live Demonstration — Full MIB Walk (9:00 – 13:00)

**[Screen: Huginn output panel showing system information being retrieved — sysDescr, sysObjectID, sysUpTime, sysContact, sysName, sysLocation.]**

> "The enumeration starts with system information. We can see the full system description — Linux Mirai running kernel 4.9.0 on Debian. The system name confirms the hostname. Uptime tells us how long since last reboot. This information alone helps us target our exploitation — we know the exact kernel version for privilege escalation research."

```bash
# System information
snmpwalk -v 2c -c public 10.10.10.48 1.3.6.1.2.1.1
# sysDescr.0 = STRING: Linux Mirai 4.9.0-6-686 #1 SMP Debian 4.9.82-1+deb9i2 i686
# sysObjectID.0 = OID: NET-SNMP-MIB::netSnmpAgentOIDs.10
# sysUpTime.0 = Timeticks: (215437) 0:35:54.37
# sysContact.0 = STRING: root
# sysName.0 = STRING: Mirai
# sysLocation.0 = STRING: Sitting on the Dock of the Bay

# Network interfaces
snmpwalk -v 2c -c public 10.10.10.48 1.3.6.1.2.1.2.2.1.2
# IF-MIB::ifDescr.1 = STRING: lo
# IF-MIB::ifDescr.2 = STRING: Intel Corporation 82545EM Gigabit Ethernet

# Interface IP addresses
snmpwalk -v 2c -c public 10.10.10.48 1.3.6.1.2.1.4.20.1.1
# IP-MIB::ipAdEntAddr.10.10.10.48 = IpAddress: 10.10.10.48
# IP-MIB::ipAdEntAddr.127.0.0.1 = IpAddress: 127.0.0.1

# Running processes
snmpwalk -v 2c -c public 10.10.10.48 1.3.6.1.2.1.25.4.2.1.2
# HOST-RESOURCES-MIB::hrSWRunName.1 = STRING: "systemd"
# HOST-RESOURCES-MIB::hrSWRunName.271 = STRING: "sshd"
# HOST-RESOURCES-MIB::hrSWRunName.289 = STRING: "apache2"
# HOST-RESOURCES-MIB::hrSWRunName.315 = STRING: "dnsmasq"
# HOST-RESOURCES-MIB::hrSWRunName.412 = STRING: "pihole-FTL"
```

**[Screen: Huginn results panel showing categorized output — System Info, Network Interfaces, Running Processes, all neatly organized.]**

> "Look at what we're getting from the MIB walk. Network interfaces reveal the adapter type and IP addresses — confirming 10.10.10.48 is the only routable address. The running processes table is extremely valuable — we can see sshd, apache2, dnsmasq, and pihole-FTL. That last one confirms this machine is running Pi-hole, which is consistent with the Mirai box's theme. Knowing exactly what services are running helps us plan our attack path without any additional port scanning or service detection."

**[Screen: Huginn displaying installed software table extracted from hrSWInstalledName OIDs.]**

> "Huginn also walks the installed software table when available. This can reveal package versions, installed applications, and sometimes even patch levels. On this target we can see the Debian packages installed, which helps us identify potential vulnerabilities tied to specific versions."

---

## SECTION 6: Results Interpretation (13:00 – 15:30)

**[Screen: Huginn results summary panel with tabs — Community Strings, System, Users, Network, Processes, Software.]**

> "Let's review the full results. Huginn organizes SNMP findings into tabbed categories. The Community Strings tab confirms which strings are valid — critical documentation for your report. The System tab shows the OS, kernel, hostname, and uptime. Network shows all interfaces with their IPs and MAC addresses. Processes lists every running service. And Software catalogs installed packages."

**[Screen: Highlighting specific findings — kernel version, running services, network configuration — with arrows pointing to exploitation implications.]**

> "From an attacker's perspective, here's what matters most. The kernel version 4.9.0-6 tells us to search for privilege escalation CVEs in that range. Running processes confirm attack surfaces — apache2 means web exploitation is viable, sshd means credential attacks are possible. Network configuration confirms there's no dual-homing or additional network segments. All of this from a single UDP protocol with a default community string."

**[Screen: Export dialog and integration with Huginn's asset database.]**

> "Export these results to feed into your engagement workflow. The findings integrate with Huginn's asset database — discovered services, OS details, and user information all populate the asset inventory automatically. You can also export as JSON for external tool consumption or generate a findings entry documenting the SNMP misconfiguration itself as a vulnerability."

---

## SECTION 7: OSCP Exam Tips and Practice (15:30 – 17:00)

**[Screen: Slide showing "OSCP Relevance: Information Gathering — Active Reconnaissance (UDP)" with tips.]**

> "For OSCP, SNMP enumeration is a high-value low-effort technique. The exam frequently includes machines with SNMP exposed on UDP 161. Key tip: always include a UDP scan in your initial reconnaissance — many candidates miss SNMP because they only do TCP scans. If you find port 161 open, immediately try the 'public' community string. The process list alone can reveal credentials hardcoded in command-line arguments, and the user list saves you from blind brute-forcing."

**[Screen: Practice recommendations — HTB "Mirai" for SNMP + IoT theme, HTB "Conceal" for SNMPv3 + IPsec challenge.]**

> "HTB Mirai is excellent for practicing basic SNMP enumeration — the community string is default and the information disclosure is significant. For a harder challenge, try HTB Conceal which uses SNMPv3 and requires you to extract IPsec credentials from SNMP data to establish a VPN tunnel. That's a real chain: SNMP enumeration leading directly to network access (see Video 6: Port Scanning for identifying UDP services)."

---

## OUTRO (17:00 – end)

> "That wraps up SNMP enumeration in Huginn. We covered the protocol architecture, walked through community string discovery, performed a full MIB walk revealing system info, network configuration, and running processes, and discussed how to leverage these findings in an engagement. The amount of information a single misconfigured SNMP service can leak is remarkable — always check for it. Next up is HTTP and HTTPS fingerprinting, where we'll identify web technologies, analyze security headers, and inspect TLS certificates. See you in the next video."
