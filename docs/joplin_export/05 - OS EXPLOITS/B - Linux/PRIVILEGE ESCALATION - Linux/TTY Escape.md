---
title: TTY Escape
updated: 2023-11-01 00:43:40Z
created: 2023-10-19 11:03:01Z
latitude: -33.86881970
longitude: 151.20929550
altitude: 0.0000
---

python3 -c 'import pty; pty.spawn("/bin/sh")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;