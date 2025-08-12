---
title: RECONNIASANCE
updated: 2023-11-29 02:33:09Z
created: 2023-09-28 23:29:39Z
latitude: -35.28093680
longitude: 149.13000920
altitude: 0.0000
---

# RECONNIASANCE

## Detect WebApplicationFirewalls (WAF)

## nmap

Quick win scan:  
`nmap -p21-25,135,139,445,80,443,8000-8081`

1.  Perform first scan  
    `nmap -PR -sn <network IP>`  
    For external scan  
    `sudo nmap -PE -sn <domainname/IP>`
2.  Scan for open ports  
    `nmap -p- --min-rate 1000 -iL <list of IP's>`  
    `nmap -T4 -p- --min-rate 1000 -A <target IP>`
3.  Scan for filtered ports  
    `sudo nmap -sA <target IP>`
4.  Next level port scanning  
    `nmap -iL <list of IP's -sV`
5.  Identify the OS  
    `nmap -iL <list of IP's -sV -O`
6.  Deep level scan on specific target  
    `nmap -T4 -A -p- <target IP>`
7.  Find NetBIOS name  
    `nmap -sU --script nbstat.nse -p 137 <target IP>`
8.  Firewall and IDS evasion & spoofing  
    `nmap -f -D decoy1,decoy2,ME -S <spoofed source IP> --proxies url1,[url2] --spoof-mac ADDR/PREFIX/VENDOR`
9.  To scan past firewall (on port 80)  
    `nmap -PA80 -sn <domainname>`

***

### Bypassing firewalls

USe different scan types:

- FIN
- Maimon
- Window
- SYN/FIN
- NULL  
    `sudo nmap <target IP> --spoof-mac 0`

* * *




	
   
