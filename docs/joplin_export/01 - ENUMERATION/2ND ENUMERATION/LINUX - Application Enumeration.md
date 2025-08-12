---
title: LINUX - Application Enumeration
updated: 2025-05-06 13:05:45Z
created: 2025-05-06 08:50:04Z
latitude: -33.86881970
longitude: 151.20929550
altitude: 0.0000
---

Search for version of all installed software and search for any exploits
`dpkg -l`

Search for any writable directory 
`find / -writable -type d 2>/dev/null`

Show mouted directories:
`cat /etc/fstab`
`lsblk` - search for anything that can be mounted
* * *

## Exploitation of device drivers and kernel modules
Gather list of kernel modules and drivers:
`lsmod`

Gather more information like **filename** and **version** on a specific module:
`/sbin/modinto <module>`

* * *
## setuid (SUID) / setgid (SGID)
Look for files that can be executed as other user
`find / -perm -u=s -type f 2>/dev/null`
