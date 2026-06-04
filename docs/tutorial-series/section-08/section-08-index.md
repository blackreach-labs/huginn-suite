# Section 8: Post-Exploitation and Privilege Escalation

## Overview

| Metric | Value |
|--------|-------|
| Attack Chain Phase | Elevate |
| Videos | 5 (Videos 45–49) |
| License Tier | Enterprise (all videos) |
| Certification Relevance | OSCP: Post-Exploitation, CEH: System Hacking |

---

## Video Listing

| # | Title | Subtitle | Tier | Playlist Order |
|---|-------|----------|------|----------------|
| 45 | Session Management | Multi-Session Support, Session Types & Host Tracking | Enterprise | 45 |
| 46 | Credential Harvesting | SAM Dumps, LSA Secrets, NTDS.dit Extraction & Mimikatz | Enterprise | 46 |
| 47 | Persistence Techniques | Registry, Scheduled Tasks, Services & Crontab Persistence | Enterprise | 47 |
| 48 | Lateral Movement | PsExec, WMI, SMB Execution & SSH Key Abuse | Enterprise | 48 |
| 49 | Active Directory Enumeration | Domain Mapping, Trust Relationships & AD Attack Paths | Enterprise | 49 |

---

## Section Summary

Section 8 covers post-exploitation and privilege escalation techniques using Huginn's Elevate phase modules. These 5 videos demonstrate how to maintain access, harvest credentials, establish persistence, move laterally through networks, and enumerate Active Directory environments after initial exploitation is achieved.

All tools in this section require the **Enterprise** tier, reflecting the advanced nature of post-exploitation capabilities. Each video includes explicit safety warnings confirming demonstrations use isolated lab environments only, with ethical guidelines and authorized-testing-only disclaimers present throughout.

This section follows the natural attack chain progression: once initial access is gained through exploitation (Section 6), these techniques allow testers to escalate privileges and expand their foothold within target environments.

### Safety Disclaimer

> **⚠️ Important:** All post-exploitation and privilege escalation techniques demonstrated in Section 8 are performed exclusively against intentionally vulnerable lab environments (HTB/THM machines with pre-established authorized access). These tools must only be used against systems you own or have explicit written authorization to test. Credential harvesting, persistence mechanisms, and lateral movement techniques carry significant legal risk if used without proper authorization. Unauthorized access to computer systems is illegal. Always follow responsible disclosure practices and ethical testing guidelines.

### Prerequisites

- Video 1: What is Huginn? (Platform Overview)
- Video 2: Installation & Setup
- Video 3: Navigating the UI
- Section 6: Network and OS Exploitation (Videos 36–40) — initial exploitation techniques required before post-exploitation
- Video 40: Hacking Mode — Metasploit/Empire integration for payload delivery and session establishment

### What Comes Next

- Section 9: Reporting and Documentation (Videos 50–54) — documenting findings, generating reports, and compliance mapping

---

## License Tier Quick-Reference Table

| Video | Title | Required Tier |
|-------|-------|---------------|
| 45 | Session Management | Enterprise |
| 46 | Credential Harvesting | Enterprise |
| 47 | Persistence Techniques | Enterprise |
| 48 | Lateral Movement | Enterprise |
| 49 | Active Directory Enumeration | Enterprise |

**All Section 8 tools require the Enterprise tier.** Post-exploitation capabilities including session management, credential harvesting, persistence mechanisms, lateral movement, and Active Directory enumeration are exclusively available to Enterprise-licensed users due to their advanced offensive nature.
