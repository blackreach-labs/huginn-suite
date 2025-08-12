---
title: 03 - SMB Enumeration
updated: 2025-05-12 05:56:21Z
created: 2025-04-15 13:06:59Z
latitude: -33.78668940
longitude: 150.95264980
altitude: 0.0000
---

**NetBIOS** (TCP_139) - An independent session layer protocol and service used for LAN  
**SMB** (TCP_445) - Can work without NetBIOS, but NetBIOS over TCP 

1. **Enumerate smb:**  
   `nmap --script=smb2-security-mode.nse -p139,445 <target IP>`
2. **Enumerate shares**  
   `nmap -p139,445 --script=smb-enum* <target IP>`
3. **Scan for vulnerablities**  
   `nmap --script-args=unsafe=1 --script=smb-vulns*.nse -p139,445 <target IP>`  
   `nmap --script=smb-proto* -p139,445 <target IP>`  
   `nmap --script=smb-os-discovery.nse -p139,445 <target IP>`
   **List mounts:**  
   `showmount --exports <target IP>`
4. **List shares:**  
   `smbclient -L \\\\<target ip>`  
   **Connect to share:**
5. `smbclient //<target ip>/<share>`  
   `smbclient \\\\<target IP>\\IPC$`  
   **Download from share:**
6. `smbget -R smb://<ip>/<share>`
7. Enumerate with **crackmapexec**  
   `crackmapexec smb <target IP> -u '' -p '' --users`  
   `crackmapexec smb <target IP> -u '' -p '' --groups`  
   `crackmapexec smb <target IP> -u '' -p '' --pass-pol`
8. `python3 /opt/impacket/GetNPUsers.py -dc-ip <targetIP> -request 'domain.com/'`  
   If any hashes found, crack then with:  
   `john --format=krb5asrep \ -w=/usr/share/wordlists/rockyou.txt hash.txt`
9. `python3 /opt/impacket/smbserver.py -smb2support myshare .`  
   Check for SMB not enforcing signing , see SMBrelay.
10. Connect a shell over SMB using psexec  
   `psexec.py administrator@<targetIP> # password: abc123!`

(**NBT**) is required for backward compatibility 

Both are usually enabled together, so enumeration often goes hand in hand  
* * *
Note: **nmap** scripts can be found at `/usr/share/nmap/scripts/smb*`

1. Scan IP range for NetBIOS and SMB:
`nmap -v -p 139,445 -oG smb.txt x.x.x.1-254`
2. Scan for SMB OS discovery:
`nmap -v -p 139,445 --script smb-os-discovery <target>`

* * *
1. Scan with **nbtscan**
`nbtscan -r x.x.x.0/24/`

* * *
1. Scan using a Windows client
`net view \\servername /all`


