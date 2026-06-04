# VIDEO 15: Database Enumeration
### Service Discovery, Default Credentials & Schema Mapping
**Suggested length:** 14–18 minutes
**License Tier:** Free
**Certification Relevance:** OSCP: Information Gathering | CEH: Enumeration

---

## INTRO (0:00 – 1:30)

**[Screen: Huginn dashboard with Recon & Enumeration page open, Database Enumeration section highlighted]**

> "Welcome back to the Huginn tutorial series. Today we are covering database enumeration — the process of discovering database services on a target, fingerprinting their version, testing for default or weak credentials, and mapping the schema of accessible databases. Databases are high-value targets in any penetration test because they often contain credentials, personal data, and business-critical information. Finding an exposed database with default credentials is one of the fastest paths to compromise."

**[Screen: Slide showing common database ports — MSSQL 1433, MySQL 3306, PostgreSQL 5432, Oracle 1521, MariaDB 3306]**

> "If your port scan (see Video 6: Port Scanning) revealed any of these ports open, this video shows you how to take the next step. We will be working with HTB Archetype today, which exposes MSSQL on port 1433 with credentials accessible via an SMB share. Let's dive in."

---

## SECTION 1: Database Protocols and Service Identification (1:30 – 4:00)

**[Screen: Diagram showing the four major database protocols — TDS (MSSQL), MySQL Protocol, PostgreSQL Wire Protocol, Oracle TNS]**

> "Different database engines use different wire protocols. Microsoft SQL Server uses TDS — Tabular Data Stream — on port 1433. MySQL and MariaDB share a protocol on port 3306. PostgreSQL uses its own wire protocol on port 5432, and Oracle uses TNS on port 1521. Each protocol has a distinct handshake that allows us to fingerprint the service even before authentication."

**[Screen: TDS protocol packet structure diagram showing pre-login, login7, and SQL batch packet types]**

> "For MSSQL specifically, the TDS protocol starts with a pre-login packet exchange where the server reveals its version, encryption support level, and instance name. This happens before any credentials are exchanged — meaning we get version information for free just by connecting."

**[Screen: Table showing database version to vulnerability mapping — e.g., MSSQL 2016 SP1, MySQL 5.7, PostgreSQL 12]**

> "Version fingerprinting matters because specific database versions have known vulnerabilities. MSSQL 2016 without current patches may be vulnerable to privilege escalation. Older MySQL versions have known authentication bypasses. Knowing the exact version directs our next steps."

---

## SECTION 2: Huginn Database Enumeration Interface (4:00 – 7:00)

**[Screen: Huginn UI — navigating to Recon & Enumeration, then selecting the Database Enumeration service scanner]**

> "In Huginn, database enumeration lives in two places. For initial discovery and fingerprinting during reconnaissance, use the service scanner under Recon and Enumeration. For deeper interaction after you have credentials, the Database Attacks module provides a full interactive client. Today we start with discovery."

**[Screen: Database enumeration panel showing — target field, database type dropdown (MSSQL/MySQL/PostgreSQL/Oracle/MariaDB), port field, and connection options]**

> "The interface gives us a target field, a database type selector, and a port that auto-fills based on the selected type. MSSQL defaults to 1433, MySQL to 3306, PostgreSQL to 5432. You can override these for non-standard configurations."

**[Screen: Connection panel showing fields — hostname, port, database type, username, password, domain (for Windows auth), use Windows authentication toggle]**

> "The connection panel supports both SQL authentication and Windows integrated authentication. For MSSQL targets in a domain environment, Windows authentication via NTLM is common. Huginn's MSSQL client handles both the standard SQL auth login7 packet and NTLM challenge-response flows natively."

```bash
# Database ports to look for in your port scan results:
# MSSQL:      TCP 1433, UDP 1434 (Browser Service)
# MySQL:      TCP 3306
# PostgreSQL: TCP 5432
# Oracle:     TCP 1521, 1522-1529
# MariaDB:    TCP 3306
```

**[Screen: Enumeration tab showing quick query buttons — List Databases, List Tables, Get Version, List Users, Check Privileges]**

> "Once connected, the enumeration tab provides quick query buttons. List Databases shows all accessible databases. Get Version returns the exact version string. List Users reveals database accounts. Check Privileges shows what the current user can do — critically, whether xp_cmdshell or other dangerous stored procedures are available."

---

## SECTION 3: Live Demo — Enumerating HTB Archetype (7:00 – 12:30)

**[Screen: Terminal showing HTB VPN connection, target IP 10.10.10.27 confirmed via ping]**

> "Our target is HTB Archetype at 10.10.10.27. This is a Starting Point machine — Very Easy difficulty — but it perfectly demonstrates the database enumeration workflow. Let's confirm our port scan results first."

```bash
# Confirm database port is open
nmap -sV -p 1433,445 10.10.10.27
```

**[Screen: Nmap output showing port 1433 open (ms-sql-s Microsoft SQL Server 2017) and port 445 open (SMB)]**

> "Port 1433 is open running Microsoft SQL Server 2017. Port 445 is also open — and on Archetype, SMB shares contain a configuration file with database credentials. We covered SMB enumeration in Video 7 (see Video 7: SMB Enumeration). For this demo, let's assume we have already retrieved the credentials: username sql_svc with password M3g4c0rp123."

**[Screen: Huginn UI — entering 10.10.10.27 in target, selecting MSSQL, port 1433, entering credentials sql_svc / M3g4c0rp123]**

> "In Huginn, I will enter the target IP, select MSSQL as the database type, verify port 1433, and enter our discovered credentials. Let's test the connection first."

**[Screen: Connection test result showing "Connection successful — Microsoft SQL Server 2017 (RTM) — 14.0.1000.169"]**

> "Connection successful. We immediately get the full version string — SQL Server 2017 RTM build 14.0.1000.169. Now let's run the enumeration queries."

```bash
# Huginn executes these queries behind the scenes:
# Version:
SELECT @@version;

# List databases:
SELECT name FROM sys.databases;

# Current user and privileges:
SELECT SYSTEM_USER;
SELECT IS_SRVROLEMEMBER('sysadmin');

# List database users:
SELECT name, type_desc FROM sys.server_principals WHERE type IN ('S','U');
```

**[Screen: Results panel showing database list — master, tempdb, model, msdb, plus any custom databases]**

> "The database list shows the standard system databases plus any custom ones. Now let's check our privilege level."

**[Screen: Privilege check result showing IS_SRVROLEMEMBER('sysadmin') = 0, current user = sql_svc]**

> "We are not sysadmin yet — just a regular database user. But let's check what we can access. I will click List Tables on each database to map the schema."

**[Screen: Huginn executing schema mapping — showing tables, columns, and row counts across accessible databases]**

> "Schema mapping reveals the structure of every accessible database. We can see table names, column types, and row counts. This tells us where interesting data lives — credential tables, user tables, configuration tables."

```bash
# Schema enumeration queries:
SELECT TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.TABLES;
SELECT COLUMN_NAME, DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'users';

# Check for dangerous stored procedures:
SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';
SELECT * FROM sys.configurations WHERE name = 'show advanced options';
```

**[Screen: Results showing xp_cmdshell configuration — currently disabled but show advanced options available]**

> "Here is a critical finding — xp_cmdshell is disabled but show advanced options is available to our user. On Archetype, this means we could potentially enable xp_cmdshell and achieve command execution on the underlying operating system. That takes us from database access to full system compromise — but that is exploitation territory covered in Video 37 (see Video 37: Database Attacks). For enumeration, documenting this capability is the key finding."

---

## SECTION 4: Default Credential Testing (12:30 – 14:30)

**[Screen: Huginn UI — default credentials testing panel showing common MSSQL credential pairs]**

> "One of the most common findings in database enumeration is default credentials. Huginn includes a built-in list of common default credentials for each database type."

```bash
# Common MSSQL default credentials:
# sa : (blank)
# sa : sa
# sa : Password1
# sa : password
# sa : admin

# Common MySQL defaults:
# root : (blank)
# root : root
# root : mysql

# Common PostgreSQL defaults:
# postgres : postgres
# postgres : (blank)
```

**[Screen: Huginn running credential test against target, showing results — green checkmarks for successful logins, red X for failures]**

> "The credential tester cycles through common username-password combinations and reports which ones succeed. On a real engagement, finding default credentials on a production database is almost always a Critical severity finding. Even on development or staging databases, it indicates poor security hygiene that likely extends to other systems."

**[Screen: Results summary showing one successful login found with severity rating]**

> "Huginn automatically generates a finding when default credentials succeed, including the CVSS score, evidence of the successful authentication, and remediation recommendations — change the password, implement account lockout, and restrict network access to the database port."

---

## SECTION 5: Multi-Database Support (14:30 – 16:00)

**[Screen: Huginn database type selector showing all five supported types — MSSQL, MySQL, PostgreSQL, Oracle, MariaDB]**

> "While we demonstrated MSSQL today, Huginn's database enumeration component supports all five major database engines. The enumeration worker adapts its queries to each platform — using sys.databases for MSSQL, SHOW DATABASES for MySQL, and pg_catalog for PostgreSQL. The interface remains consistent regardless of the backend."

**[Screen: Side-by-side comparison showing equivalent enumeration queries across MSSQL, MySQL, and PostgreSQL]**

> "Each database type also has platform-specific checks. For MSSQL we check xp_cmdshell and linked servers. For MySQL we check FILE privilege and LOAD DATA INFILE capability. For PostgreSQL we check COPY TO/FROM PROGRAM. These are the dangerous functions that can escalate database access to operating system access."

```bash
# Platform-specific dangerous capability checks:
# MSSQL: xp_cmdshell, OPENROWSET, linked servers
# MySQL: LOAD DATA INFILE, INTO OUTFILE, UDF
# PostgreSQL: COPY TO/FROM PROGRAM, lo_export
# Oracle: Java stored procedures, UTL_FILE
```

**[Screen: Huginn quick query buttons updating based on selected database type]**

> "Notice how the quick query buttons adapt when you change the database type. The underlying queries change but the enumeration workflow remains the same — connect, enumerate databases, map schemas, check privileges, identify dangerous capabilities."

---

## OUTRO (16:00 – end)

> "That wraps up database enumeration in Huginn. We covered how to identify database services from port scan results, fingerprint versions via protocol handshakes, test for default credentials, map database schemas, and identify dangerous capabilities like xp_cmdshell. For OSCP preparation, database enumeration is a critical information gathering skill — knowing what databases are accessible and what privileges you have shapes your entire exploitation strategy. For further practice, HTB Archetype covers MSSQL, HTB Querier provides a more challenging MSSQL scenario, and THM rooms covering SQL fundamentals are excellent starting points. Next up, we cover AV and Firewall Detection (see Video 16: AV/Firewall Detection), where we learn to identify security products protecting our target. See you there."
