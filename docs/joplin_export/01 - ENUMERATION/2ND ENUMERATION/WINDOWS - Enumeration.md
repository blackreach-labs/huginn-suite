---
title: WINDOWS - Enumeration
updated: 2025-05-06 12:52:39Z
created: 2025-04-29 07:03:37Z
latitude: -33.78668940
longitude: 150.95264980
altitude: 0.0000
---

# WINDOWS ENUMERATION

## Automated Tools

### Executables:
- winPEAS.exe
- Seatbelt.exe (compile)
- Watson.exe (compile)
- SharpUp.exe (compile)

### PowerShell:
- Sherlock.ps1
- PowerUp.ps1
- PowerView.ps1
- jaws-enum.ps1
- WinPEAS.ps1
- PowerSploit-Master

### Other:
- windows-exploit-suggester.py (local)
- Exploit Suggester (Metasploit)

### Meterpreter
meterpreter > run post/multi/recon/local\_exploit\_suggestor

### Windows-exploit-suggester.py

1.  Copy systeminfo of target to file **systeminfo\_target.txt** & Download [windows-exploit-suggester.py](https://github.com/Pwnistry/Windows-Exploit-Suggester-python3/blob/master/windows-exploit-suggester.py) file locally
    
2.  `sudo pip install xlrd --upgrade`
    
3.  `python2 get-pip.py`
    
4.  `python -m pip install --user xlrd==1.1.0`
    
5.  `python3 ./windows-exploit-suggester.py --update`
    
6.  Take note of database name
    
7.  `python3 ./windows-exploit-suggester.py --database <database_name> --systeminfo systeminfo_target.txt`
    

**NTUSER.DAT**: This is the main registry hive for the users residing in the user account profile folder and contains the most valuable forensics data.

**UsrClass.dat**: Just Like NTUSER.DAT, the UsrClass is another registry hive to obtained user-related information.

***
## PowerUp.ps1
`. .\PowerUp.ps1`
`Invoke-AllChecks`

## PowerView.ps1
#### Abusing Active Directory ACLs/ACEs

`Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.ActiveDirectoryRights -eq "GenericAll"}`  

* * *

Check Powershell history
`Get-History`
`(Get-PSReadlineOption).HistorySavePath`

Gather the following information:
- Username and hostname
- Group memberships of the current user
- Existing users and groups

`whoami /groups`
`net user` OR `Get-LocalUser`
`net localgroup` OR `Get-LocalGroup`
`Get-LocalGroupMember <group_name>`

- Operating system, version and architecture

`systeminfo`

- Network information 

`ipconfig /all`
`route print`
`netstat -ano`

- Installed applications

`Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select DisplayName`
`Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Select DisplayName"`

- Running processes

`Get-Process`
`systeminfo`

- Privileges

`whoami /priv`

## WinRM - Microsoft-HTTPAPI

1.  Once you have crerdentials, run **evil-winrm**  
    `evil-winrm -i <target> -u <user> -p <password>`

2. `powershell.exe -ExecutionPolicy Bypass`
3. `Import-Module .\powerview-dev.ps1`

4. 
```
Get-NetGPO
Get-NetDomain
Get-NetUser
Get-NetGroup
```