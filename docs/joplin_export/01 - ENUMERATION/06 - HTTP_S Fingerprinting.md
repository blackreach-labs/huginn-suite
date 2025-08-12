---
title: 06 - HTTP/S Fingerprinting
updated: 2025-05-12 03:22:56Z
created: 2025-04-16 11:17:46Z
latitude: -33.78668940
longitude: 150.95264980
altitude: 0.0000
---

* * *
## HTTP/S

1. Scan web server using **nmap**
`nmap -p80,443 --script=vuln <target IP>`
`nmap -p80 --script=http-enum <target>`
2. Identify supported SSL/TLS versions & cipher suites:
`nmap --script ssl-enum-ciphers -p 443 <target>`

3. Enumerate sub-directories

### dirsearch

`dirsearch -u http://<target>`

* * *
## GoBuster
`gobuster dir -u <target> -w /usr/share/wordlists/dirb/common.txt -t 5`

`gobuster dir -u http://<target> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t20 -x aspx`

`gobuster dir -t 4 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -u http://<target> -x .php`

vhost
`gobuster vhost -w <wordlist> -u http://<target>:<port> --exclude-length 334`

* * *

## Debug Page Content

1. Start with a URL address
2. File extensions (which can be part of a URL) can reveal the application it was written in
3. Some extension like PHP are straightforward, but other are more cryptic and vary based on the frameworks in use. ***File extensions on webpages are becoming less common***, however since many languages & frameworks now support the concept of *routes* which allow developers to map a URI to a section of code. Applications leveraging *routes* use logic to determine what content is returned to the user - making URI extensions largely irrelevant.
Most context clues can be found in the source of the web page.
4. The Firefox debugger tool displays the pages resources and content, which may display:
- Javascript & Javascript Frameworks
- Hidden Input Fields
- Comments
- Client-Side controls within HTML

* * * 
## BurpSuite
1. Inspect **HTTP response headers** and **Sitemaps**
**Sitemap** files are used by searchengine bot to crawl and index site, including a list of what not to crawl (such as sensite pages or admin consoles). The **robots.txt** file includes the URL to exclude
2. Inspect **Server responses** for additional information

* * *
## Dirbuster
`dirb http://<target> -r`
`dirbuster&`  
Use wordlist:  
`/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt`

### ffuf

`ffuf -w wordlist.txt -w http://website.com/FUZZ -e .aspx,.html -mc 200,302`

### Subdomain busting

`ffuf -w /usr/share/seclists/Discovery/DNS/n0kovo_subdomains.txt -u http://cozyhosting.htb/ -H "HOST: FUZZ.cozyhosting.htb" -mc 200,301,403 -t 200` , then `-fw` to filter out the word count

* * *
Hints:
1. Look for hidden directories and files using gobuster/dirb/etc
2. Check for login pages
3. Check pages (including source) for application versions
4. check html pagesource for any info  
5. `nikto -h http://<target>`  
6. `dirbuster&`  
7. `dirb`  
8. `gobuster`  
9. Enumerate web pages looking for vulnerable software exploits
10. Check for XSS vulnerabilities  
11. Check for SQLi vulnerabilities  
12. Check for FileUpload vulnerabilities  
13. Once Logged in, check folder and files  
`/var/www/html`

# WEB-APPLICATION ENUMERATION

1.  Install **Go**
2.  Install **Assetfinder**
3.  Install **Amass** (OWASP)
4.  use `httpprobe` to find alive domains
5.  Screenshot with **GoWitness**
6.  Automate the process

## FUZZ for subdomains

`wfuzz -c -f sub-fighter -w /usr/share/seclists/Fuzzing/subdomains-top1million-5000.txt -u 'http://<website>' -H "Host: FUZZ.<website>"`  
Note: you can use `--hc/hl/hw/hh` to hide responses with the specified code/lines/words/chars

`gobuster vhost -w /usr/share/seclists/Fuzzing/subdomains-top1million-5000.txt -u http://<website> -v --append-domain`

## Access webpage from different world locations
`shotsherpa`

***
### Try to register or create an account.
1. If possible to login or register a new account, once logged in check browser **cookies**
2. Check if **HttpOnly** 