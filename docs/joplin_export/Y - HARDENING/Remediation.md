---
title: REMEDIATION
updated: 2023-11-03 06:27:55Z
created: 2023-09-29 05:29:21Z
latitude: -35.28093680
longitude: 149.13000920
altitude: 0.0000
---

# REMEDIATION
1. Disable LLMNR (GPO > DNS client > Turn off multicast name resolution)
2. Disable use NetBIOS over TCP/IP in IP4 settings
3. Enable SMB signing on all devices
4. Disable NTLM authentication on network
5. Login with user account instead of admin unless needed
6. Restrict local administrators members
7. Use LAPS to have unique admin password on machines
8. Set GPO rule to block instead of allow
  * (Inbound) Core Networking - Dynamic Host Configuration Protocol for IPv6(DHCPV6-In)
  * (Inbound) Core Networking - Router Advertisement (ICMPv6-In)
  * (Outbound) Core Networking - Dynamic Host Configuration Protocol for IPv6 (DHCPV6-Out)
9. If WPAD is not used internally, disable it via Group Policy and by disabling the WinHttpAutoProxySvc service
10. Enable both LDAP signing and LDAP channel binding
11. Administrative users to the Protected Users group OR marking them as Account is sensite and cannot be delegated.
12. Disable Guest and Administrator accounts, limit who has local administrator
13. PAM , check-in/out sensative accounts when needed (TPAM / CyberArc)
14. Service account not running as domain admin, use strong passwords
15. Don't just use block-lists to prevent file uploads
