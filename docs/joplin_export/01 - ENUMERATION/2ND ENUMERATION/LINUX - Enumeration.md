---
title: LINUX - Enumeration
updated: 2025-05-06 13:25:08Z
created: 2025-05-06 12:52:06Z
latitude: -33.86881970
longitude: 151.20929550
altitude: 0.0000
---

## Enumerate USER
1. `history`
2. `sudo su -`
3. `whoami`
`id` 
4. Look for SUDO exploits
`sudo -l`
5. `cat /etc/passwd`
6. `cat /etc/shadow` 
7. `cat /etc/group`

## Enumerate OS
Find OS and architecture, core count
1. `uname -a`
2. `cat /proc/version`
3. `cat /etc/issue`

Get Privileges:
`id`

## Enumerate NETWORK
Check network settings, route settings, multi-homing
1. `ifconfig`
`ip a`
1. `ip route`
`netstat -r`
3. `arp -a`
Check open port and who machine is communicating with
5. `netatat -ano

### Check for interfaces, routes and open ports:
`ifconfig` OR `ip a`
`route` OR `routel`
`cat /etc/resolv.conf`

`ss -anp` 
-a : List all connections
-n : Disable hostname resolution
-p : List name of process

`netstat -ano`

### Firewall rules
`/etc/iptables`
`cat /etc/iptables/rules.v4`

`iptables-save`
`iptables-restore`

### Other commands
`cat /etc/passwd`
`hostname`
`cat /etc/issue`
`cat /etc/os-release`
`uname -a` - how kernel version and architecture

Show variables:
`enum`
*** 

### List system processes:
`ps aux` (look for processes running as root)
`watch -n 1 "ps aux | grep <keyword>`

***
## Password Hunting
1. `grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2>/dev/null`
`grep --color=auto -rnw '/' -ie "PASSWORD=" --color=always 2>/dev/null`

2. `locate password | more`
`locate passw | more`
`locate pwd | more`

Look for SSH keys:
1. `find / -name authorized_keys 2>/dev/null` 
`find / -name id_rsa 2>/dev/null`

* * *
Look for scheduled or automated tasks that are run by processes. Look for weak permissions
`ls -lah /etc/cron*`
`crontal -l` OR `sudo crontab -l`

* * *
### unix-privesc-check
https://pentestmonkey.net/tools/audit/unix-privesc-check
`./unix-privesc-check standard > output.txt`

## Automated Tools
* linPEAS.sh
* LinENUM.sh
* linux-exploit-suggester.sh
* linuxprivchecker.py

