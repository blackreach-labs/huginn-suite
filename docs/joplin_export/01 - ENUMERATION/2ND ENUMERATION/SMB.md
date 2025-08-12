---
title: SMB
updated: 2025-05-12 06:06:49Z
created: 2025-05-12 05:58:06Z
latitude: -33.86881970
longitude: 151.20929550
altitude: 0.0000
---

## smbmap
`smbmap -H <target>`

## crackmapexec
1. List share of user with username and password:
`crackmapexec smb <target> -u <user> -p <password> --shares`
2. List share of user using NTLM hash:
`crackmapexec smb <target> -u <user> -H <NTLM_HASH>`
3. Spay with password:
`crackmapexec smb <target> -u <textfile> -p <password> --shares`

## smbclient
Connect to SMB shares with username/password:
`smbclient //<target>/<share> -U domain.com/<user>%<password>`

Connect to SMB share with HASH:
`smbclient //<target>/<share> -U <user> --pw-nt-hash <HASH> -W domain.com`