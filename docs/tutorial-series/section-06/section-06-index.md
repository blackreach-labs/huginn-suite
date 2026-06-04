# Section 6: Network and OS Exploitation

## Overview

| Metric | Value |
|--------|-------|
| Attack Chain Phase | Exploit (Network/OS) |
| Videos | 5 (Videos 36–40) |
| License Tier | Mixed (Free/Professional/Enterprise) |
| Certification Relevance | OSCP: Network Exploitation, CEH: System Hacking |

---

## Video Listing

| # | Title | Subtitle | Tier | Playlist Order |
|---|-------|----------|------|----------------|
| 36 | SSH Brute-Force & Vulnerability Scanning | Credential Testing, Key-Based Auth & SSH Exploit Detection | Free | 36 |
| 37 | Database Attacks | MSSQL Client, Privilege Escalation & Data Exfiltration | Free | 37 |
| 38 | RPC Relay & MITM | NTLM Relay, Token Impersonation & Relay Attack Chains | Free (Scanning) / Professional (Exploitation) | 38 |
| 39 | Exploit Database | CVE Matching, Service-to-Exploit Mapping & Automated Execution | Enterprise | 39 |
| 40 | Hacking Mode | Metasploit/Empire Integration, Framework Automation & Payload Delivery | Professional (Basic) / Enterprise (Advanced) | 40 |

---

## Section Summary

Section 6 extends active exploitation beyond web applications into network protocols and operating system services — the Exploit (Network/OS) phase of the attack chain. These 5 videos demonstrate Huginn's capabilities for attacking SSH, databases, RPC services, and leveraging external exploit frameworks for comprehensive system compromise.

This section uses a **mixed tier** model spanning all three license levels: 2 videos cover Free-tier features, 1 video spans Free and Professional tiers, 1 video requires Enterprise, and 1 video spans Professional and Enterprise tiers.

All exploitation demonstrations in this section use **isolated lab environments only** (HTB machines, THM rooms). No real-world targets are used in any demonstration. Each video includes explicit safety warnings confirming authorized testing scope.

### Safety Disclaimer

> **⚠️ Important:** All exploitation techniques demonstrated in Section 6 are performed exclusively against intentionally vulnerable lab environments. These tools must only be used against systems you own or have explicit written authorization to test. Unauthorized access to computer systems is illegal. Always follow responsible disclosure practices.

### Prerequisites

- Video 1: What is Huginn? (Platform Overview)
- Video 2: Installation & Setup
- Video 3: Navigating the UI
- Video 6: Port Scanning (for service detection context)
- Video 7: SMB Enumeration (for network service context)
- Video 12: RPC Enumeration (for RPC Relay context)
- Video 15: Database Enumeration (for Database Attacks context)
- Section 4 completion recommended (vulnerability scan results inform exploitation targets)
- Section 5 completion recommended (web exploitation concepts carry over to network exploitation)

### What Comes Next

- Section 7: Stealth and Evasion (Videos 41–44) — configuring stealth capabilities before deeper post-exploitation operations

---

## License Tier Quick-Reference Table

| Video | Title | Required Tier |
|-------|-------|---------------|
| 36 | SSH Brute-Force & Vulnerability Scanning | Free |
| 37 | Database Attacks | Free |
| 38 | RPC Relay & MITM | Free (Scanning) / **Professional** (Exploitation) |
| 39 | Exploit Database | **Enterprise** |
| 40 | Hacking Mode | **Professional** (Basic) / **Enterprise** (Advanced) |

**Free tier features in this section:**

- **Video 36: SSH Brute-Force & Vulnerability Scanning** — Credential testing against SSH services, key-based authentication analysis, and SSH-specific vulnerability detection.
- **Video 37: Database Attacks** — MSSQL client connections, privilege escalation within database contexts, and data exfiltration techniques.
- **Video 38 (Scanning only): RPC Relay & MITM** — RPC service scanning and relay vulnerability detection are available in the Free tier.

**Professional tier features in this section:**

- **Video 38 (Exploitation): RPC Relay & MITM** — Active NTLM relay exploitation, token impersonation, and relay attack chain execution require a Professional license.
- **Video 40 (Basic): Hacking Mode** — Basic Metasploit/Empire integration and framework automation require a Professional license.

**Enterprise tier features in this section:**

- **Video 39: Exploit Database** — Full CVE matching, automated service-to-exploit mapping, and automated exploit execution require an Enterprise license.
- **Video 40 (Advanced): Hacking Mode** — Advanced payload delivery, multi-framework orchestration, and full exploitation automation require an Enterprise license.
