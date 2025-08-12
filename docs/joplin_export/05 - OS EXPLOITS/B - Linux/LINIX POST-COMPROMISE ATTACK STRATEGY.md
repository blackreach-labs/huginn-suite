---
title: LINIX POST-COMPROMISE ATTACK STRATEGY
updated: 2023-11-03 08:40:48Z
created: 2023-11-03 08:36:04Z
latitude: -33.86881970
longitude: 151.20929550
altitude: 0.0000
---

# POST-COMPROMISE ATTACK STRATEGY

### Copy files from Kali to target using HTTP

`python3 -m http.server 80`  
use wget or curl

### Copy files from Kali to target using FTP

`python3 -m pyftpdlib -p 21 --write`

### Copy files from target to Kali

`python3 /opt/impacket/examples/smbserver.py -smb2support myshare .`
linPEAS.sh 