---
title: Capabilities
updated: 2023-10-15 10:04:13Z
created: 2023-10-14 13:29:56Z
latitude: -33.86881970
longitude: 151.20929550
altitude: 0.0000
---

1. In command prompt type: `getcap -r / 2>/dev/null`

**cap_sys_admin** – this capability provide almost complete access to the administrative privileges. You could add or modify system capabilities, mount or unmount file systems, modify kernel modules, set process priorities, and many more.
**cap_setuid** and **cap_setgid** – these two Linux capabilities allow the modification of user or group IDs and can allow privilege escalation if poorly assigned.
**cap_chown** – this capability allows modification of ownership of any file or directory.
**cap_dac_read_search** – this capability allows to bypass discretionary access controls to read and search any file or directory.
**cap_dac_override** – this capability allows to bypass discretionary access controls to override the file system permissions and access any files and directories.
Other than that, “**+ep**” is required along with the Linux capabilities set to be exploitable. “e” here means executable and “p” here means that SUID has been set on the binary. Together “+ep” indicates that a binary has both the executable permission and the SUID permission set. This allows the binary to be executed as a program and grants it the ability to run with elevated privileges.

**GTFObins** is a great resource for finding if an exploit is available for a binary set with capability.


