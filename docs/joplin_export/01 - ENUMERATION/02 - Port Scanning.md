---
title: 02 - Port Scanning
updated: 2025-05-12 03:02:49Z
created: 2025-04-14 12:55:36Z
latitude: -33.78668940
longitude: 150.95264980
altitude: 0.0000
---

## nmap 
(note: run as **sudo**)
* * *
**Sweeping Scans**
1. Perform a network sweeping scan first
`nmap -v -sn x.x.x.1-254 -oG ping-sweep.txt`
`grep Up ping-sweep.txt | cut -d " " -f2`
2. Sweeping scan for specific ports
`nmap -p 80 x.x.x.1-254 -oG web-sweep.txt`
`grep open web-sweep.txt | cut -d " " -f2`
3. Scan multiple IPs, probing for a shortlist of common ports
`nmap -sT -A --top-ports=20 x.x.x.1-254 -oG top-port-sweep.txt` 
* * *

**Targeted Scans**
1. Perform a SYN stealth scan
`nmap -sS <target>`
2. Run a TCP connect scan
`nmap -sT <target>`
3. Run a UDP scan
`nmap -sU <target>`
4. Run a UDP with TCP SYN scan
`nmap -sU -sS <target>`
5. Scan for OS type
`nmap -O <target> --osscan-guess`
6. Identiy services running on specific ports
`nmap -sV -sT -A <target>`

* * *
**NSE scripts**
1. Attempt to connect to HTTP service
`nmap --script http-headers <target>`

* * *
**Port Scanning from a Windows Machine**
1. Test for an open connection on a sepcific port and IP
`Test-NetConnection -Port 445 <target>`
2. Script to test on a range of ports 1 - 1024
`foreach ($port in 1..1024) {If (($a=Test-NetConnection <target> -Port $port -WarningAction SilentlyContinue).tcpTestSucceeded -eq $true){ "TCP port $port is open"}}`

3. Or use tcpclient:
`$target="192.168.1.1";1..1024|%{Start-Job -ScriptBlock{param($t,$p);try{$c=New-Object Net.Sockets.TcpClient;$a=$c.BeginConnect($t,$p,$null,$null);if($a.AsyncWaitHandle.WaitOne(100,$false)-and$c.Connected){"TCP port $p is open"};$c.Close()}catch{}} -ArgumentList $target,$_} | Wait-Job | Receive-Job`


* * * 
`proxychains nmap -sT --top-ports=100 -Pn <IP>`




