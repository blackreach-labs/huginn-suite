---
title: 01 - DNS Enumeration
updated: 2025-05-12 03:05:54Z
created: 2025-04-14 12:38:24Z
latitude: -33.78668940
longitude: 150.95264980
altitude: 0.0000
---

1. Enumerate hostnames with wordlist
`for ip in $(cat hostname_wordlist.txt); do host $ip.example.com; done`
2. Enumerate IP's with reverse lookups
`for ip in $(seq 1 254); do host x.x.x.$ip; done | grep -v "not found"`

* * *
**DNSRECON**
1. Run a standard scan:
`dnsrecon -d example.com -t std`
`dnsrecon -r 127.0.0.1/24 -n target -d example.com` 

2. Run a brute force on subdomains
`dnsrecon -d example.com -D subdomain_list.txt -t brt`

* * *
**DNSENUM**
1. run a scan on a domain
`dnsenum example.com`
`dnsenum --dnsserver <server>--private -r -t 5 --threads <value> -f /usr/share/dnsenum/dns.txt`

 * * * 
 **NSLOOKUP**
 * * *
 ## DNS zone transfer attack
 `dig axfr domain.com @<DNS IP>`
